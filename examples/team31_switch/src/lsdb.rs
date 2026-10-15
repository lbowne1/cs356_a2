//! Link-state database and the forward-search shortest-path computation
//! (the Confirmed/Tentative realization of Dijkstra's algorithm).

use std::collections::BTreeMap;

use crate::proto::Lsp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspRecord {
    pub seq: u32,
    /// (neighbor switch, capacity of the link to it in kbit/s)
    pub neighbors: Vec<(u32, u32)>,
    pub prefixes: Vec<u32>,
    pub sender_dst: u32,
}

impl LspRecord {
    fn same_content(&self, other: &LspRecord) -> bool {
        self.neighbors == other.neighbors && self.prefixes == other.prefixes && self.sender_dst == other.sender_dst
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Accept {
    /// Old or duplicate copy: do not reflood.
    Stale,
    /// Newer sequence number, same content: reflood, nothing to recompute.
    Refresh,
    /// Newer and different: reflood and recompute.
    Changed,
}

/// Every other switch's most recent accepted LSP, keyed by origin.
#[derive(Debug, Default)]
pub struct Lsdb {
    pub records: BTreeMap<u32, LspRecord>,
}

impl Lsdb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(&mut self, lsp: &Lsp) -> Accept {
        let rec = LspRecord {
            seq: lsp.seq,
            neighbors: lsp.neighbors.clone(),
            prefixes: lsp.prefixes.clone(),
            sender_dst: lsp.sender_dst,
        };
        let verdict = match self.records.get(&lsp.origin) {
            Some(existing) if existing.seq >= lsp.seq => return Accept::Stale,
            Some(existing) if existing.same_content(&rec) => Accept::Refresh,
            _ => Accept::Changed,
        };
        self.records.insert(lsp.origin, rec);
        verdict
    }

    pub fn remove(&mut self, origin: u32) -> bool {
        self.records.remove(&origin).is_some()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    pub cost: u32,
    pub next_hop_port: u16,
}

/// Hop-count shortest paths rooted at `self_id`. Every link costs 1; the
/// second field of each LSP neighbor is a capacity, not a cost.
pub fn compute_routes(
    self_id: u32,
    my_neighbors: &BTreeMap<u16, u32>,
    lsdb: &Lsdb,
) -> BTreeMap<u32, RouteEntry> {
    let mut confirmed: BTreeMap<u32, RouteEntry> = BTreeMap::new();
    confirmed.insert(self_id, RouteEntry { cost: 0, next_hop_port: 0 });
    let mut tentative: BTreeMap<u32, RouteEntry> = BTreeMap::new();
    let mut frontier = self_id;

    loop {
        let base_cost = confirmed[&frontier].cost;
        let base_next_hop = confirmed[&frontier].next_hop_port;

        let offer = |nbr: u32, next_hop_port: u16, tentative: &mut BTreeMap<u32, RouteEntry>| {
            if nbr == self_id || confirmed.contains_key(&nbr) {
                return;
            }
            let total = base_cost + 1;
            if tentative.get(&nbr).map_or(true, |e| total < e.cost) {
                tentative.insert(nbr, RouteEntry { cost: total, next_hop_port });
            }
        };

        if frontier == self_id {
            for (&port, &nbr) in my_neighbors {
                offer(nbr, port, &mut tentative);
            }
        } else if let Some(rec) = lsdb.records.get(&frontier) {
            for &(nbr, _) in &rec.neighbors {
                offer(nbr, base_next_hop, &mut tentative);
            }
        }

        let next = tentative.iter().min_by_key(|(_, e)| e.cost).map(|(&k, _)| k);
        match next {
            None => break,
            Some(k) => {
                let entry = tentative.remove(&k).unwrap();
                confirmed.insert(k, entry);
                frontier = k;
            }
        }
    }

    confirmed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nbrs(pairs: &[(u16, u32)]) -> BTreeMap<u16, u32> {
        pairs.iter().copied().collect()
    }

    fn rec(neighbors: Vec<(u32, u32)>) -> LspRecord {
        LspRecord { seq: 1, neighbors, prefixes: vec![], sender_dst: 0 }
    }

    #[test]
    fn multi_hop_inherits_next_hop_from_first_hop() {
        let my_neighbors = nbrs(&[(1, 2)]);
        let mut lsdb = Lsdb::default();
        lsdb.records.insert(2, rec(vec![(3, 10_000)]));
        let routes = compute_routes(1, &my_neighbors, &lsdb);
        assert_eq!(routes[&3].cost, 2);
        assert_eq!(routes[&3].next_hop_port, 1);
    }

    #[test]
    fn capacity_is_not_a_cost() {
        // 1 -p1- 2 -(slow)- 3, and 1 -p2- 4 -(fast)- 5 -(fast)- 3: two hops beats three.
        let my_neighbors = nbrs(&[(1, 2), (2, 4)]);
        let mut lsdb = Lsdb::default();
        lsdb.records.insert(2, rec(vec![(3, 1)]));
        lsdb.records.insert(4, rec(vec![(5, 100_000)]));
        lsdb.records.insert(5, rec(vec![(3, 100_000)]));
        let routes = compute_routes(1, &my_neighbors, &lsdb);
        assert_eq!(routes[&3].next_hop_port, 1);
    }

    #[test]
    fn accept_tells_refresh_from_change() {
        let mut db = Lsdb::new();
        let mut lsp = Lsp { origin: 2, seq: 1, ttl: 15, neighbors: vec![(1, 10)], prefixes: vec![], sender_dst: 0 };
        assert_eq!(db.accept(&lsp), Accept::Changed);
        assert_eq!(db.accept(&lsp), Accept::Stale);
        lsp.seq = 2;
        assert_eq!(db.accept(&lsp), Accept::Refresh);
        lsp.seq = 3;
        lsp.sender_dst = 9;
        assert_eq!(db.accept(&lsp), Accept::Changed);
    }
}
