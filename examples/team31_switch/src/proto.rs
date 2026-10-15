//! Wire format for our own control-plane messages: HELLO (neighbor
//! discovery) and LSP (link-state advertisement).

pub const HELLO_PROTO: u8 = 89;
pub const LSP_PROTO: u8 = 90;

/// Destination nobody routes; used for all link-local control traffic.
pub const CTRL_IP: u32 = 0xe000_0005; // 224.0.0.5

/// Hops an LSP survives; a TTL of zero is the delete signal.
pub const LSP_TTL: u8 = 15;

pub fn encode_hello(switch_id: u32) -> Vec<u8> {
    switch_id.to_le_bytes().to_vec()
}

pub fn decode_hello(payload: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = payload.get(0..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// A link-state packet: the origin's neighbors with the capacity (kbit/s)
/// of the link to each, the prefixes it originates, and where its local
/// sender's traffic goes (0 when unknown or none).
#[derive(Debug, Clone)]
pub struct Lsp {
    pub origin: u32,
    pub seq: u32,
    pub ttl: u8,
    pub neighbors: Vec<(u32, u32)>,
    pub prefixes: Vec<u32>,
    pub sender_dst: u32,
}

impl Lsp {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(15 + self.neighbors.len() * 8 + self.prefixes.len() * 4);
        buf.extend_from_slice(&self.origin.to_le_bytes());
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.push(self.ttl);
        buf.push(self.neighbors.len() as u8);
        for (id, cap) in &self.neighbors {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&cap.to_le_bytes());
        }
        buf.push(self.prefixes.len() as u8);
        for p in &self.prefixes {
            buf.extend_from_slice(&p.to_le_bytes());
        }
        buf.extend_from_slice(&self.sender_dst.to_le_bytes());
        buf
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
        let mut cur = 0usize;
        let take4 = |payload: &[u8], cur: &mut usize| -> Option<u32> {
            let bytes: [u8; 4] = payload.get(*cur..*cur + 4)?.try_into().ok()?;
            *cur += 4;
            Some(u32::from_le_bytes(bytes))
        };

        let origin = take4(payload, &mut cur)?;
        let seq = take4(payload, &mut cur)?;
        let ttl = *payload.get(cur)?;
        cur += 1;

        let n_neighbors = *payload.get(cur)? as usize;
        cur += 1;
        let mut neighbors = Vec::with_capacity(n_neighbors);
        for _ in 0..n_neighbors {
            let id = take4(payload, &mut cur)?;
            let cap = take4(payload, &mut cur)?;
            neighbors.push((id, cap));
        }

        let n_prefixes = *payload.get(cur)? as usize;
        cur += 1;
        let mut prefixes = Vec::with_capacity(n_prefixes);
        for _ in 0..n_prefixes {
            prefixes.push(take4(payload, &mut cur)?);
        }
        let sender_dst = take4(payload, &mut cur)?;

        Some(Lsp { origin, seq, ttl, neighbors, prefixes, sender_dst })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips() {
        assert_eq!(decode_hello(&encode_hello(7)), Some(7));
    }

    #[test]
    fn lsp_round_trips() {
        let lsp = Lsp {
            origin: 3,
            seq: 42,
            ttl: 15,
            neighbors: vec![(1, 10_000), (2, 6_000)],
            prefixes: vec![0x0a000300],
            sender_dst: 0x0a000901,
        };
        let d = Lsp::decode(&lsp.encode()).unwrap();
        assert_eq!((d.origin, d.seq, d.ttl), (3, 42, 15));
        assert_eq!(d.neighbors, lsp.neighbors);
        assert_eq!(d.prefixes, lsp.prefixes);
        assert_eq!(d.sender_dst, lsp.sender_dst);
    }

    #[test]
    fn truncated_payload_decodes_to_none() {
        let lsp = Lsp { origin: 1, seq: 1, ttl: 1, neighbors: vec![], prefixes: vec![], sender_dst: 0 };
        let bytes = lsp.encode();
        assert!(Lsp::decode(&bytes[..bytes.len() - 1]).is_none());
        assert!(decode_hello(&[1, 2]).is_none());
    }
}
