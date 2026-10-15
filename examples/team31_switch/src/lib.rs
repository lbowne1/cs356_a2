//! # team31_switch — link-state routing with per-customer paths and fair queues
//!
//! Every switch runs this program. From Assignment 1 it keeps HELLO
//! discovery, LSP flooding and shortest-path routes by destination. For
//! Assignment 2 it adds:
//!
//! - **Fair queues.** Every port runs DRR over one queue per customer (equal
//!   weights, so each link is split max-min) plus queue 0 for control
//!   packets and acks.
//! - **Per-customer paths.** Every switch runs the grader's greedy
//!   placement over the same flooded topology. A customer's ingress stamps
//!   a *path code* into `custom0`; every switch on that path forwards by the
//!   code. A coded packet follows exactly its simple path or is dropped, so
//!   no customer packet can revisit a switch, even while plans change.
//! - **No link_down, ever.** No link fails in A2.

mod lsdb;
mod plan;
mod proto;
mod state;

use switch_program_sdk::*;

use state::{SwitchState, MARK, PUNT_CUSTOMER, T_DST, T_PROTO, T_SRC, T_TAG};

/// The data plane, 4 stages (the hardware pipeline depth):
/// - S0: punt our control protocols; TTL guard.
/// - S1: classify by source (sets the customer's queue). At the customer's
///   ingress the entry id is a path code (< MARK): stamp it into custom0.
/// - S2: untagged packets route by destination.
/// - S3: tagged packets route by path code; a miss drops (never a fallback
///   mid-path). Acks always go to queue 0.
pub fn data_plane() -> String {
    format!(
        "
        stage alu=8 mem=1
            load    r0, ip_proto
            table   t{T_PROTO}, r0 -> m0
            load    r1, ip_ttl
            const   r2, 1
            lt      r8, r2, r1
            bif     r8 -> 7
            drop
            sub     r3, r1, r2
            store   ip_ttl, r3
        stage alu=16 mem=1
            const   r0, 0
            storem  m1, r0
            load    r1, ip_src
            table   t{T_SRC}, r1 -> m1
            loadm   r2, m1
            const   r3, {MARK}
            lt      r4, r2, r3
            eq      r5, r2, r0
            const   r6, 1
            xor     r5, r5, r6
            and     r7, r4, r5
            eq      r9, r7, r0
            bif     r9 -> 14
            store   custom0, r2
            noop
        stage alu=8 mem=1
            load    r1, custom0
            const   r0, 0
            eq      r2, r1, r0
            const   r3, 1
            xor     r4, r2, r3
            bif     r4 -> 8
            load    r5, ip_dst
            table   t{T_DST}, r5 -> m2
            noop
        stage alu=16 mem=1
            load    r1, custom0
            const   r0, 0
            eq      r2, r1, r0
            bif     r2 -> 11
            storem  m3, r0
            table   t{T_TAG}, r1 -> m3
            loadm   r4, m3
            eq      r5, r4, r0
            eq      r6, r5, r0
            bif     r6 -> 11
            drop
            load    r7, kind
            const   r8, 4
            eq      r9, r7, r8
            eq      r10, r9, r0
            bif     r10 -> 17
            queue   0
            noop
        "
    )
}

pub struct Team31Switch {
    state: SwitchState,
}

impl SwitchProgram for Team31Switch {
    fn init(switch_id: u32, local_ports: Vec<u16>) -> (Self, ProgramSetup) {
        Self::init_with(InitInput { switch_id, local_ports, port_capacity_bps: Vec::new(), customers: Vec::new() })
    }

    fn init_with(input: InitInput) -> (Self, ProgramSetup) {
        let mut setup = ProgramSetup::new();
        setup.declare_table(T_PROTO, MatchKind::Exact, 8);
        setup.declare_table(T_SRC, MatchKind::Lpm, 128);
        setup.declare_table(T_DST, MatchKind::Lpm, 256);
        setup.declare_table(T_TAG, MatchKind::Exact, 1024);
        setup.set_program(text::parse_tiny_program(&data_plane()).unwrap());

        for (id, proto) in [(1, proto::HELLO_PROTO), (2, proto::LSP_PROTO)] {
            setup.add_entry(
                T_PROTO,
                TableEntry {
                    id: wire::EntryIdW(id),
                    key: proto as u64,
                    prefix_len: 8,
                    priority: 0,
                    action: TableAction::Punt { reason: PuntReason::Custom(id as u32) },
                },
            );
        }
        for e in state::initial_src_entries(&input.customers) {
            setup.add_entry(T_SRC, e);
        }

        let state = SwitchState::new(input.switch_id, input.local_ports, input.port_capacity_bps, input.customers);
        (Self { state }, setup)
    }

    fn on_punt(&mut self, ev: PuntEvent) -> Vec<Action> {
        match ev.reason {
            PuntReason::Custom(1) => self.state.on_hello(ev.ingress_port, ev.now_ns, &ev.payload),
            PuntReason::Custom(2) => self.state.on_lsp(ev.ingress_port, ev.now_ns, &ev.payload),
            PuntReason::Custom(PUNT_CUSTOMER) => self.state.on_customer_punt(&ev),
            PuntReason::NoRoute => self.state.on_no_route_punt(&ev),
            _ => Vec::new(),
        }
    }

    fn on_timer(&mut self, ev: TimerEvent) -> Vec<Action> {
        self.state.on_timer(ev.now_ns)
    }
}

switch_program!(Team31Switch);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_plane_parses_in_four_stages() {
        let p = text::parse_tiny_program(&data_plane()).unwrap();
        assert_eq!(p.stages.len(), 4);
        for s in &p.stages {
            assert!(s.instrs.len() <= 64);
        }
    }
}
