//! Traffic engineering: which path each customer takes.
//!
//! `path_menu` and `assign_paths` mirror the grader's reference placement
//! (`src/floors.rs` in the kit) so that, with the same topology and
//! contract, every switch places each customer exactly where the Part 2
//! fair share assumes it is.

use std::collections::{BTreeMap, BTreeSet};

pub type Edge = (u32, u32);

/// Every simple path from `from` to `to` no longer than the shortest plus
/// `slack` hops, as node sequences, shortest first and then by edge order.
pub fn path_menu(adj: &BTreeMap<u32, Vec<u32>>, from: u32, to: u32, slack: usize) -> Vec<Vec<u32>> {
    if from == to {
        return vec![vec![from]];
    }
    let mut dist: BTreeMap<u32, usize> = BTreeMap::new();
    let mut frontier = std::collections::VecDeque::from([to]);
    dist.insert(to, 0);
    while let Some(v) = frontier.pop_front() {
        let d = dist[&v];
        for &u in adj.get(&v).map(|v| v.as_slice()).unwrap_or(&[]) {
            if !dist.contains_key(&u) {
                dist.insert(u, d + 1);
                frontier.push_back(u);
            }
        }
    }
    let Some(&shortest) = dist.get(&from) else { return Vec::new() };
    let limit = shortest + slack;

    fn walk(
        adj: &BTreeMap<u32, Vec<u32>>,
        dist: &BTreeMap<u32, usize>,
        at: u32,
        to: u32,
        limit: usize,
        path: &mut Vec<Edge>,
        on_path: &mut BTreeSet<u32>,
        out: &mut Vec<Vec<Edge>>,
    ) {
        if at == to {
            out.push(path.clone());
            return;
        }
        let mut next: Vec<u32> = adj.get(&at).cloned().unwrap_or_default();
        next.sort_unstable();
        for u in next {
            if on_path.contains(&u) {
                continue;
            }
            let Some(&rest) = dist.get(&u) else { continue };
            if path.len() + 1 + rest > limit {
                continue;
            }
            on_path.insert(u);
            path.push((at, u));
            walk(adj, dist, u, to, limit, path, on_path, out);
            path.pop();
            on_path.remove(&u);
        }
    }

    let mut out: Vec<Vec<Edge>> = Vec::new();
    walk(adj, &dist, from, to, limit, &mut Vec::new(), &mut BTreeSet::from([from]), &mut out);
    out.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    out.into_iter()
        .map(|edges| {
            let mut nodes = vec![from];
            nodes.extend(edges.iter().map(|e| e.1));
            nodes
        })
        .collect()
}

fn edges_of(path: &[u32]) -> impl Iterator<Item = Edge> + '_ {
    path.windows(2).map(|w| (w[0], w[1]))
}

/// The grader's greedy placement: fewest choices first, then unlimited
/// (`None`) demands, then the biggest, then by index. Each customer takes
/// the path whose thinnest link, shared with everyone already placed on
/// it, leaves it the most; the shortest wins ties. Returns the index of
/// the chosen path in each menu (`None` for an empty menu).
pub fn assign_paths(demands: &[Option<f64>], menus: &[Vec<Vec<u32>>], cap: &BTreeMap<Edge, f64>) -> Vec<Option<usize>> {
    let n = demands.len();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&a, &b| {
        let choices = |i: usize| menus[i].len().max(1);
        let size = |i: usize| demands[i].unwrap_or(f64::INFINITY);
        choices(a)
            .cmp(&choices(b))
            .then_with(|| size(b).partial_cmp(&size(a)).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| a.cmp(&b))
    });
    let mut on_link: BTreeMap<Edge, usize> = BTreeMap::new();
    let mut chosen = vec![None; n];
    for i in order {
        if menus[i].is_empty() {
            continue;
        }
        let mut best: Option<(f64, usize)> = None;
        for (pi, p) in menus[i].iter().enumerate() {
            let room = edges_of(p)
                .map(|e| cap.get(&e).copied().unwrap_or(0.0) / (on_link.get(&e).copied().unwrap_or(0) + 1) as f64)
                .fold(f64::INFINITY, f64::min);
            if best.map_or(true, |(br, _)| room > br + 1e-9) {
                best = Some((room, pi));
            }
        }
        let pi = best.map(|b| b.1).unwrap_or(0);
        for e in edges_of(&menus[i][pi]) {
            *on_link.entry(e).or_insert(0) += 1;
        }
        chosen[i] = Some(pi);
    }
    chosen
}

/// Bits per hop in a path code.
const HOP_BITS: u32 = 5;

/// A number that names one switch sequence, the same at every switch
/// whatever it knows: a leading 1 then 5 bits per switch (id + 1). `None`
/// when the path does not fit (a switch id above 30, or more than 12
/// switches), so the code stays below 2^61.
pub fn path_code(path: &[u32]) -> Option<u64> {
    if path.len() > 12 {
        return None;
    }
    let mut code: u64 = 1;
    for &s in path {
        if s >= (1 << HOP_BITS) - 1 {
            return None;
        }
        code = (code << HOP_BITS) | (s as u64 + 1);
    }
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adj_of(links: &[(u32, u32)]) -> BTreeMap<u32, Vec<u32>> {
        let mut adj: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for &(a, b) in links {
            adj.entry(a).or_default().push(b);
            adj.entry(b).or_default().push(a);
        }
        adj
    }

    fn caps(links: &[(u32, u32, f64)]) -> BTreeMap<Edge, f64> {
        let mut m = BTreeMap::new();
        for &(a, b, c) in links {
            m.insert((a, b), c);
            m.insert((b, a), c);
        }
        m
    }

    #[test]
    fn menu_lists_detours_shortest_first() {
        // Square 0-1-3, 0-2-3 plus a tail 3-4.
        let adj = adj_of(&[(0, 1), (1, 3), (0, 2), (2, 3), (3, 4)]);
        assert_eq!(path_menu(&adj, 0, 3, 0), vec![vec![0, 1, 3], vec![0, 2, 3]]);
        assert_eq!(path_menu(&adj, 0, 3, 2).len(), 2);
        assert_eq!(path_menu(&adj, 0, 0, 2), vec![vec![0]]);
        assert!(path_menu(&adj, 0, 9, 2).is_empty());
    }

    #[test]
    fn greedy_sends_the_second_customer_down_the_detour() {
        // Thin direct link 0-1 (2 Mbit/s), fat detour 0-2-1 (10 Mbit/s).
        let adj = adj_of(&[(0, 1), (0, 2), (2, 1)]);
        let cap = caps(&[(0, 1, 2e6), (0, 2, 10e6), (2, 1, 10e6)]);
        let menu = path_menu(&adj, 0, 1, 2);
        assert_eq!(menu, vec![vec![0, 1], vec![0, 2, 1]]);
        let chosen = assign_paths(&[Some(1e6), None], &[menu.clone(), menu], &cap);
        // The unlimited customer goes first and takes the fat detour; the
        // other still finds 10/2 = 5 on the detour beats 2 on the thin link.
        assert_eq!(chosen[1], Some(1));
        assert_eq!(chosen[0], Some(1));
    }

    #[test]
    fn path_codes_are_unique_and_bounded() {
        let a = path_code(&[0, 1, 2]).unwrap();
        let b = path_code(&[0, 2, 1]).unwrap();
        let c = path_code(&[1, 2]).unwrap();
        assert!(a != b && a != c && b != c);
        assert!(path_code(&[30; 12]).unwrap() < 1 << 61);
        assert!(path_code(&[31]).is_none());
        assert!(path_code(&[0; 13]).is_none());
    }
}
