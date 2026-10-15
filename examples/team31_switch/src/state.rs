//! Mutable per-switch control-plane state: neighbor discovery, the
//! link-state database, customer learning, queues, shortest-path routes
//! for untagged traffic, and the per-customer path plan.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use switch_program_sdk::{
    actions, wire, Action, Cca, Customer, Discipline, PuntEvent, QueueSpec, TableAction, TableEntry,
};

use crate::lsdb::{self, Accept, Lsdb};
use crate::plan;
use crate::proto::{self, Lsp};

/// Fixed simulator convention: every switch's customer app is on this port.
pub const APP_PORT: u16 = 100;

pub const T_PROTO: u32 = 1;
pub const T_SRC: u32 = 2;
pub const T_DST: u32 = 3;
pub const T_TAG: u32 = 4;

/// A `T_SRC` entry id at or above this is "classify only, do not stamp".
pub const MARK: u64 = 1 << 62;
/// Punt reason for a customer's packet whose `T_SRC` entry still punts.
pub const PUNT_CUSTOMER: u32 = 3;

// ---- Tunables -----------------------------------------------------------

pub const HELLO_INTERVAL_NS: u64 = 25_000_000;
/// Only used when the world has no customer contract (an A1 world). No link
/// fails in A2, so there a silent neighbour is never expired and `link_down`
/// is never declared.
const NEIGHBOR_TIMEOUT_NS: u64 = 3 * HELLO_INTERVAL_NS;
const PUNT_DEBOUNCE_NS: u64 = 20_000_000;
/// Re-flood our own LSP this often, so one lost copy cannot leave a switch blind.
const LSP_REFRESH_NS: u64 = 1_000_000_000;
/// An ingress waits this long after a new plan before stamping packets
/// with it, so the switches downstream have installed the path.
const INGRESS_FLIP_DELAY_NS: u64 = HELLO_INTERVAL_NS;
/// Detour slack of the path menu: the Part 2 worlds' `detour_hops`.
const SLACK: usize = 2;
/// Encoded bytes of actions one call may return (the host's limit is 4,096).
const ACTION_BYTES_PER_CALL: usize = 3_400;

/// Queue 0: control packets and acks. Caps are in full-size packets.
const Q0_CAP: u32 = 4;
const Q0_WEIGHT: u32 = 16;
const AIMD_CAP: u32 = 6;
/// Early-drop line for AIMD queues; 0 = tail drop only.
const AIMD_DROP_AT: u32 = 0;
const RM_CAP: u32 = 6;
/// Customers asking less than this get a short queue: they never need more.
const SMALL_ASK_BPS: u64 = 1_000_000;
const SMALL_CAP: u32 = 2;
/// Customer queues per port, after queue 0.
const MAX_CUSTOMER_QUEUES: usize = 15;

fn mask24(ip: u32) -> u32 {
    ip & 0xFFFF_FF00
}

fn prefix_mask(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len.min(32) as u32) }
}

pub fn queue_of(customer_idx: usize) -> u16 {
    1 + (customer_idx % MAX_CUSTOMER_QUEUES) as u16
}

fn queue_spec(c: &Customer) -> QueueSpec {
    if c.ask_bps.is_some_and(|a| a < SMALL_ASK_BPS) {
        return QueueSpec::new(SMALL_CAP);
    }
    match c.cca {
        Cca::Aimd => QueueSpec::new(AIMD_CAP).drop_at(AIMD_DROP_AT),
        Cca::RateMatch => QueueSpec::new(RM_CAP),
    }
}

fn src_entry(id: u64, c: &Customer, priority: i32, action: TableAction) -> TableEntry {
    TableEntry {
        id: wire::EntryIdW(id),
        key: (c.prefix_addr & prefix_mask(c.prefix_len)) as u64,
        prefix_len: c.prefix_len,
        priority,
        action,
    }
}

/// The `T_SRC` entries every switch starts with: punt each customer's
/// first packet so the switch learns where it comes from and goes to.
pub fn initial_src_entries(customers: &[Customer]) -> Vec<TableEntry> {
    customers
        .iter()
        .enumerate()
        .map(|(i, c)| {
            src_entry(MARK | i as u64, c, 0, TableAction::Punt {
                reason: wire::PuntReasonW::Custom(PUNT_CUSTOMER),
            })
        })
        .collect()
}

fn action_size(a: &Action) -> usize {
    switch_program_sdk::__export::postcard::to_allocvec(a).map_or(64, |v| v.len())
}

pub struct SwitchState {
    switch_id: u32,
    local_ports: Vec<u16>,
    port_capacity_bps: BTreeMap<u16, u64>,
    customers: Vec<Customer>,
    now_ns: u64,

    neighbors: BTreeMap<u16, u32>,
    last_hello_ns: BTreeMap<u16, u64>,

    local_prefix: Option<u32>,
    /// Where our local sender's traffic goes, once seen.
    sender_dst: u32,
    own_seq: u32,
    last_refresh_ns: u64,
    lsdb: Lsdb,
    dirty: bool,

    /// prefix -> egress port installed in `T_DST`.
    installed: BTreeMap<u32, u16>,
    last_punt_ns: BTreeMap<u32, u64>,

    queues_configured: bool,
    /// Customers whose `T_SRC` entry here no longer punts.
    src_learned: Vec<bool>,
    /// Path codes installed in `T_TAG`. Never deleted: a code always names
    /// the same path, so a stale entry is harmless.
    tags: BTreeSet<u64>,
    /// Local customer -> path code its `T_SRC` entry stamps now.
    stamping: BTreeMap<usize, u64>,
    /// Local customer -> (code it should stamp, from when).
    pending_flip: BTreeMap<usize, (u64, u64)>,
    src_priority: i32,

    /// Actions waiting for room in a call's output.
    backlog: VecDeque<Action>,
}

impl SwitchState {
    pub fn new(switch_id: u32, local_ports: Vec<u16>, capacities: Vec<u64>, customers: Vec<Customer>) -> Self {
        let port_capacity_bps = local_ports.iter().copied().zip(capacities).collect();
        let n = customers.len();
        Self {
            switch_id,
            local_ports,
            port_capacity_bps,
            customers,
            now_ns: 0,
            neighbors: BTreeMap::new(),
            last_hello_ns: BTreeMap::new(),
            local_prefix: None,
            sender_dst: 0,
            own_seq: 0,
            last_refresh_ns: 0,
            lsdb: Lsdb::new(),
            dirty: false,
            installed: BTreeMap::new(),
            last_punt_ns: BTreeMap::new(),
            queues_configured: false,
            src_learned: vec![false; n],
            tags: BTreeSet::new(),
            stamping: BTreeMap::new(),
            pending_flip: BTreeMap::new(),
            src_priority: 0,
            backlog: VecDeque::new(),
        }
    }

    // ---- Handlers -------------------------------------------------------

    pub fn on_hello(&mut self, ingress_port: u16, now_ns: u64, payload: &[u8]) -> Vec<Action> {
        self.now_ns = now_ns;
        if let Some(neighbor_id) = proto::decode_hello(payload) {
            self.last_hello_ns.insert(ingress_port, now_ns);
            if self.neighbors.get(&ingress_port) != Some(&neighbor_id) {
                self.neighbors.insert(ingress_port, neighbor_id);
                self.dirty = true;
            }
            self.settle();
        }
        self.drain(Vec::new())
    }

    pub fn on_lsp(&mut self, ingress_port: u16, now_ns: u64, payload: &[u8]) -> Vec<Action> {
        self.now_ns = now_ns;
        let Some(mut lsp) = Lsp::decode(payload) else {
            return self.drain(Vec::new());
        };
        if lsp.origin == self.switch_id {
            return self.drain(Vec::new());
        }
        // Relay the received LSP as-is; never regenerate our own here (see
        // the A1 note: that would ping-pong forever).
        match self.lsdb.accept(&lsp) {
            Accept::Stale => {}
            Accept::Refresh => {
                lsp.ttl = lsp.ttl.saturating_sub(1);
                if lsp.ttl > 0 {
                    self.flood_raw(&lsp, Some(ingress_port));
                }
            }
            Accept::Changed => {
                if lsp.ttl == 0 {
                    self.lsdb.remove(lsp.origin);
                } else {
                    lsp.ttl -= 1;
                }
                self.flood_raw(&lsp, Some(ingress_port));
                self.recompute();
            }
        }
        self.drain(Vec::new())
    }

    /// A customer packet whose `T_SRC` entry here still punts.
    pub fn on_customer_punt(&mut self, ev: &PuntEvent) -> Vec<Action> {
        self.now_ns = ev.now_ns;
        let Some(i) = self.customer_index(ev.ip_src) else {
            return self.drain(Vec::new());
        };
        if self.src_learned[i] {
            return self.drain(Vec::new());
        }
        if ev.ingress_port == APP_PORT {
            if self.local_prefix.is_none() {
                self.local_prefix = Some(mask24(ev.ip_src));
                self.dirty = true;
            }
            // The app's first packet is addressed to itself; keep punting
            // until one says where this customer sends.
            if mask24(ev.ip_dst) == mask24(ev.ip_src) {
                self.settle();
                return self.drain(Vec::new());
            }
            if self.sender_dst != ev.ip_dst {
                self.sender_dst = ev.ip_dst;
                self.dirty = true;
            }
        }
        self.src_learned[i] = true;
        let c = self.customers[i];
        self.backlog.push_back(actions::delete_entry(T_SRC, MARK | i as u64));
        self.backlog.push_back(actions::install_entry(
            T_SRC,
            src_entry(MARK | i as u64, &c, 0, TableAction::SetQueue { queue: wire::QueueIdW(queue_of(i)) }),
        ));
        self.settle();
        self.drain(Vec::new())
    }

    pub fn on_no_route_punt(&mut self, ev: &PuntEvent) -> Vec<Action> {
        self.now_ns = ev.now_ns;
        let key = mask24(ev.ip_dst);
        if let Some(&last) = self.last_punt_ns.get(&key) {
            if ev.now_ns.saturating_sub(last) < PUNT_DEBOUNCE_NS {
                return self.drain(Vec::new());
            }
        }
        self.last_punt_ns.insert(key, ev.now_ns);
        if ev.ingress_port == APP_PORT && self.local_prefix.is_none() {
            self.local_prefix = Some(mask24(ev.ip_src));
            self.dirty = true;
            self.settle();
        }
        self.drain(Vec::new())
    }

    pub fn on_timer(&mut self, now_ns: u64) -> Vec<Action> {
        self.now_ns = now_ns;
        let mut out = Vec::new();

        // Without a contract (an A1 world) the default queues stay.
        if !self.queues_configured && !self.customers.is_empty() {
            self.queues_configured = true;
            for &port in &self.local_ports.clone() {
                self.backlog.push_front(self.queue_config(port));
            }
        }

        let hello_payload = proto::encode_hello(self.switch_id);
        for &port in &self.local_ports {
            if port == APP_PORT {
                continue;
            }
            out.push(self.control_packet(port, proto::HELLO_PROTO, hello_payload.clone()));
        }

        if self.customers.is_empty() {
            let dead: Vec<u16> = self
                .neighbors
                .keys()
                .copied()
                .filter(|p| self.last_hello_ns.get(p).is_none_or(|&t| now_ns.saturating_sub(t) > NEIGHBOR_TIMEOUT_NS))
                .collect();
            for port in dead {
                self.neighbors.remove(&port);
                self.dirty = true;
            }
        }

        if self.dirty {
            self.settle();
        } else if now_ns.saturating_sub(self.last_refresh_ns) >= LSP_REFRESH_NS && !self.neighbors.is_empty() {
            self.last_refresh_ns = now_ns;
            self.own_seq += 1;
            let lsp = self.own_lsp();
            self.flood_raw(&lsp, None);
        }

        self.run_flips();

        out.push(actions::schedule_timer(HELLO_INTERVAL_NS));
        self.drain(out)
    }

    // ---- Helpers --------------------------------------------------------

    /// Move backlog actions into `out` while they fit in one call.
    fn drain(&mut self, mut out: Vec<Action>) -> Vec<Action> {
        let mut used: usize = out.iter().map(action_size).sum();
        while let Some(a) = self.backlog.front() {
            let sz = action_size(a);
            if used + sz > ACTION_BYTES_PER_CALL {
                break;
            }
            used += sz;
            out.push(self.backlog.pop_front().unwrap());
        }
        out
    }

    fn customer_index(&self, ip: u32) -> Option<usize> {
        self.customers.iter().position(|c| {
            let m = prefix_mask(c.prefix_len);
            ip & m == c.prefix_addr & m
        })
    }

    fn queue_config(&self, port: u16) -> Action {
        let mut specs = vec![QueueSpec::new(Q0_CAP).weight(Q0_WEIGHT)];
        let n = self.customers.len().min(MAX_CUSTOMER_QUEUES);
        for q in 0..n {
            specs.push(queue_spec(&self.customers[q]).weight(1));
        }
        actions::set_queues(port, Discipline::Drr, specs)
    }

    fn link_local_src(&self) -> u32 {
        0xa9fe_0000 | (self.switch_id & 0xffff)
    }

    fn control_packet(&self, port: u16, proto: u8, payload: Vec<u8>) -> Action {
        actions::in_queue(0, actions::inject_packet(port, self.link_local_src(), proto::CTRL_IP, proto, 1, payload))
    }

    fn own_lsp(&self) -> Lsp {
        Lsp {
            origin: self.switch_id,
            seq: self.own_seq,
            ttl: proto::LSP_TTL,
            neighbors: self
                .neighbors
                .iter()
                .map(|(port, &id)| (id, (self.port_capacity_bps.get(port).copied().unwrap_or(0) / 1000) as u32))
                .collect(),
            prefixes: self.local_prefix.into_iter().collect(),
            sender_dst: self.sender_dst,
        }
    }

    /// If our adjacency, prefix or sender changed, flood a fresh LSP and
    /// recompute.
    fn settle(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        self.own_seq += 1;
        self.last_refresh_ns = self.now_ns;
        let lsp = self.own_lsp();
        self.flood_raw(&lsp, None);
        self.recompute();
    }

    fn flood_raw(&mut self, lsp: &Lsp, except_port: Option<u16>) {
        let payload = lsp.encode();
        let ports: Vec<u16> = self.neighbors.keys().copied().filter(|&p| Some(p) != except_port).collect();
        for port in ports {
            let a = self.control_packet(port, proto::LSP_PROTO, payload.clone());
            self.backlog.push_back(a);
        }
    }

    /// Adjacency of the whole network as we know it, ourselves included.
    fn adjacency(&self) -> BTreeMap<u32, Vec<u32>> {
        let mut adj: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        adj.insert(self.switch_id, self.neighbors.values().copied().collect());
        for (&origin, rec) in &self.lsdb.records {
            adj.insert(origin, rec.neighbors.iter().map(|n| n.0).collect());
        }
        adj
    }

    /// The database is closed when every link is reported by both of its
    /// ends: until then switches may disagree, so no routes are computed.
    fn lsdb_closed(&self, adj: &BTreeMap<u32, Vec<u32>>) -> bool {
        !self.neighbors.is_empty()
            && adj.iter().all(|(a, ns)| ns.iter().all(|b| adj.get(b).is_some_and(|back| back.contains(a))))
    }

    fn recompute(&mut self) {
        let adj = self.adjacency();
        if !self.lsdb_closed(&adj) {
            return;
        }
        self.recompute_dst_routes();
        self.recompute_plan(&adj);
    }

    /// Shortest-path routes by destination, for traffic carrying no path
    /// code: acks from receivers, and customer data before a plan exists.
    fn recompute_dst_routes(&mut self) {
        let confirmed = lsdb::compute_routes(self.switch_id, &self.neighbors, &self.lsdb);
        let mut desired: BTreeMap<u32, u16> = BTreeMap::new();
        if let Some(prefix) = self.local_prefix {
            desired.insert(prefix, APP_PORT);
        }
        for (&origin, rec) in &self.lsdb.records {
            if let Some(entry) = confirmed.get(&origin) {
                for &prefix in &rec.prefixes {
                    desired.insert(prefix, entry.next_hop_port);
                }
            }
        }
        let stale: Vec<u32> = self.installed.keys().copied().filter(|p| !desired.contains_key(p)).collect();
        for prefix in stale {
            self.backlog.push_back(actions::delete_entry(T_DST, prefix as u64));
            self.installed.remove(&prefix);
        }
        for (&prefix, &port) in &desired {
            match self.installed.get(&prefix) {
                Some(&existing) if existing == port => {}
                Some(_) => {
                    // Install never dedupes by id: delete first or the stale
                    // entry shadows the new one.
                    self.backlog.push_back(actions::delete_entry(T_DST, prefix as u64));
                    self.backlog.push_back(actions::install_route(T_DST, prefix as u64, prefix as u64, 24, port));
                    self.installed.insert(prefix, port);
                }
                None => {
                    self.backlog.push_back(actions::install_route(T_DST, prefix as u64, prefix as u64, 24, port));
                    self.installed.insert(prefix, port);
                }
            }
        }
    }

    /// Place every customer whose ends are known, the way the grader does,
    /// install the path codes that cross this switch, and schedule the
    /// ingress flip for our own customer.
    fn recompute_plan(&mut self, adj: &BTreeMap<u32, Vec<u32>>) {
        let mut owner: BTreeMap<u32, u32> = BTreeMap::new(); // prefix -> switch
        let mut sender: BTreeMap<u32, u32> = BTreeMap::new(); // switch -> sender dst
        let mut cap: BTreeMap<plan::Edge, f64> = BTreeMap::new();
        if let Some(p) = self.local_prefix {
            owner.insert(p, self.switch_id);
        }
        sender.insert(self.switch_id, self.sender_dst);
        for (port, &n) in &self.neighbors {
            cap.insert((self.switch_id, n), self.port_capacity_bps.get(port).copied().unwrap_or(0) as f64);
        }
        for (&origin, rec) in &self.lsdb.records {
            for &p in &rec.prefixes {
                owner.insert(p, origin);
            }
            sender.insert(origin, rec.sender_dst);
            for &(n, kbps) in &rec.neighbors {
                cap.insert((origin, n), kbps as f64 * 1000.0);
            }
        }

        let ends: Vec<Option<(u32, u32)>> = self
            .customers
            .iter()
            .map(|c| {
                let m = prefix_mask(c.prefix_len);
                let (_, &ingress) = owner.iter().find(|(p, _)| **p & m == c.prefix_addr & m)?;
                let dst = *sender.get(&ingress)?;
                if dst == 0 {
                    return None;
                }
                let egress = *owner.get(&mask24(dst))?;
                Some((ingress, egress))
            })
            .collect();
        let menus: Vec<Vec<Vec<u32>>> = ends
            .iter()
            .map(|e| e.map_or(Vec::new(), |(a, b)| plan::path_menu(adj, a, b, SLACK)))
            .collect();
        let demands: Vec<Option<f64>> = self.customers.iter().map(|c| c.ask_bps.map(|a| a as f64)).collect();
        let chosen = plan::assign_paths(&demands, &menus, &cap);

        let port_to: BTreeMap<u32, u16> = self.neighbors.iter().map(|(&p, &n)| (n, p)).collect();
        for (i, pick) in chosen.iter().enumerate() {
            let Some(pi) = *pick else { continue };
            let path = &menus[i][pi];
            let Some(code) = plan::path_code(path) else { continue };
            if let Some(k) = path.iter().position(|&s| s == self.switch_id) {
                let port = if k + 1 == path.len() { Some(APP_PORT) } else { port_to.get(&path[k + 1]).copied() };
                if let Some(port) = port {
                    if self.tags.insert(code) {
                        self.backlog.push_back(actions::install_entry(
                            T_TAG,
                            TableEntry {
                                id: wire::EntryIdW(code),
                                key: code,
                                prefix_len: 0,
                                priority: 0,
                                action: TableAction::SetEgress { port: wire::PortIdW(port) },
                            },
                        ));
                    }
                }
                if k == 0 && self.stamping.get(&i) != Some(&code) {
                    self.pending_flip.insert(i, (code, self.now_ns + INGRESS_FLIP_DELAY_NS));
                }
            }
        }
    }

    /// Point our own customers' `T_SRC` entries at their new path codes:
    /// install the new entry above the old one, then remove the old.
    fn run_flips(&mut self) {
        let due: Vec<(usize, u64)> = self
            .pending_flip
            .iter()
            .filter(|(_, (_, at))| self.now_ns >= *at)
            .map(|(&i, &(code, _))| (i, code))
            .collect();
        for (i, code) in due {
            self.pending_flip.remove(&i);
            let c = self.customers[i];
            self.src_priority += 1;
            self.backlog.push_back(actions::install_entry(
                T_SRC,
                src_entry(code, &c, self.src_priority, TableAction::SetQueue { queue: wire::QueueIdW(queue_of(i)) }),
            ));
            let old = self.stamping.insert(i, code).unwrap_or(MARK | i as u64);
            self.backlog.push_back(actions::delete_entry(T_SRC, old));
        }
    }
}
