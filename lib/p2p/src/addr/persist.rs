use crate::addr::addrman::{AddrEntry, Table};
use crate::constants::*;

pub const PEERS_MAGIC: [u8; 8] = *b"PLNEPEER";

pub const PEERS_VERSION: u16 = 1;

pub const PEERS_HEADER_BYTES: usize = 18;

pub const PEERS_REC_BYTES: usize = 35;

pub const PEERS_DIGEST_BYTES: usize = 32;

pub const PEERS_FILE_MAX: usize =
    PEERS_HEADER_BYTES + (ADDR_NEW_MAX + ADDR_TRIED_MAX) * PEERS_REC_BYTES + PEERS_DIGEST_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeersError {
    TooShort,
    TooLong,
    BadMagic,
    BadVersion(u16),
    ForeignChain([u8; 4]),
    BadLength,
    BadDigest,
    BadRecord,
}

impl PeersError {
    pub fn describe(&self) -> &'static str {
        match self {
            PeersError::TooShort => "peers.dat is shorter than its own header",
            PeersError::TooLong => "peers.dat is larger than a full address book could ever be",
            PeersError::BadMagic => "peers.dat does not start with the expected magic",
            PeersError::BadVersion(_) => "peers.dat was written by a different format version",
            PeersError::ForeignChain(_) => "peers.dat belongs to the other network",
            PeersError::BadLength => "peers.dat is truncated: fewer bytes than its count claims",
            PeersError::BadDigest => "peers.dat failed its checksum: truncated or altered",
            PeersError::BadRecord => "peers.dat holds a record this build cannot read",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerRec {
    pub ip: [u8; 16],
    pub port: u16,
    pub services: u32,
    pub last_seen: u64,
    pub table: Table,
    pub source_group: [u8; 4],
}

pub fn encode(entries: &[AddrEntry], chain_id: [u8; 4]) -> Vec<u8> {
    let n = entries.len().min(ADDR_NEW_MAX + ADDR_TRIED_MAX);
    let mut out = Vec::with_capacity(PEERS_HEADER_BYTES + n * PEERS_REC_BYTES + PEERS_DIGEST_BYTES);
    out.extend_from_slice(&PEERS_MAGIC);
    out.extend_from_slice(&PEERS_VERSION.to_le_bytes());
    out.extend_from_slice(&chain_id);
    out.extend_from_slice(&(n as u32).to_le_bytes());
    for e in entries.iter().take(n) {
        out.extend_from_slice(&e.ip);
        out.extend_from_slice(&e.port.to_le_bytes());
        out.extend_from_slice(&e.services.to_le_bytes());
        out.extend_from_slice(&e.last_seen.to_le_bytes());
        out.push(match e.table {
            Table::New => 0u8,
            Table::Tried => 1u8,
        });
        out.extend_from_slice(&e.source_group);
    }
    let digest = plaine_consensus::blake3::hash(&out);
    out.extend_from_slice(&digest);
    out
}

pub fn decode(buf: &[u8], chain_id: [u8; 4]) -> Result<Vec<PeerRec>, PeersError> {
    if buf.len() > PEERS_FILE_MAX {
        return Err(PeersError::TooLong);
    }
    if buf.len() < PEERS_HEADER_BYTES + PEERS_DIGEST_BYTES {
        return Err(PeersError::TooShort);
    }
    if buf[0..8] != PEERS_MAGIC {
        return Err(PeersError::BadMagic);
    }
    let version = u16::from_le_bytes([buf[8], buf[9]]);
    if version != PEERS_VERSION {
        return Err(PeersError::BadVersion(version));
    }
    let mut file_chain = [0u8; 4];
    file_chain.copy_from_slice(&buf[10..14]);
    if file_chain != chain_id {
        return Err(PeersError::ForeignChain(file_chain));
    }
    let count = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]) as usize;

    if count > ADDR_NEW_MAX + ADDR_TRIED_MAX {
        return Err(PeersError::TooLong);
    }
    let body = PEERS_HEADER_BYTES + count * PEERS_REC_BYTES;
    if buf.len() != body + PEERS_DIGEST_BYTES {
        return Err(PeersError::BadLength);
    }

    if plaine_consensus::blake3::hash(&buf[..body]) != buf[body..] {
        return Err(PeersError::BadDigest);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = PEERS_HEADER_BYTES + i * PEERS_REC_BYTES;
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&buf[o..o + 16]);
        let port = u16::from_le_bytes([buf[o + 16], buf[o + 17]]);
        let mut s = [0u8; 4];
        s.copy_from_slice(&buf[o + 18..o + 22]);
        let services = u32::from_le_bytes(s);
        let mut t = [0u8; 8];
        t.copy_from_slice(&buf[o + 22..o + 30]);
        let last_seen = u64::from_le_bytes(t);
        let table = match buf[o + 30] {
            0 => Table::New,
            1 => Table::Tried,
            _ => return Err(PeersError::BadRecord),
        };
        let mut source_group = [0u8; 4];
        source_group.copy_from_slice(&buf[o + 31..o + 35]);
        out.push(PeerRec {
            ip,
            port,
            services,
            last_seen,
            table,
            source_group,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(n: u8, table: Table) -> AddrEntry {
        AddrEntry {
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, n],
            port: 9256,
            services: 7,
            last_seen: 1_000_000,
            table,
            failures: 3,
            protocol_deaths: 1,
            from_seed: true,
            source_group: [1, 2, 3, 4],
            foreign_until: Some(crate::traits::Mono(999_999)),
            last_attempt: Some(crate::traits::Mono(12_345)),
        }
    }

    #[test]
    fn the_record_has_no_room_for_a_privilege_or_a_ban() {
        assert_eq!(
            PEERS_REC_BYTES,
            16 + 2 + 4 + 8 + 1 + 4,
            "ip + port + services + last_seen + table + source_group, and nothing else"
        );
        let e = rec(1, Table::Tried);
        let bytes = encode(&[e], CHAIN_ID);
        assert_eq!(
            bytes.len(),
            PEERS_HEADER_BYTES + PEERS_REC_BYTES + PEERS_DIGEST_BYTES
        );
        let back = decode(&bytes, CHAIN_ID).expect("round trip");

        let PeerRec {
            ip,
            port,
            services,
            last_seen,
            table,
            source_group,
        } = back[0];
        assert_eq!(
            (ip, port, services, last_seen, table, source_group),
            (
                e.ip,
                e.port,
                e.services,
                e.last_seen,
                e.table,
                e.source_group
            )
        );
    }

    #[test]
    fn a_book_round_trips_through_the_file() {
        let entries = vec![rec(1, Table::New), rec(2, Table::Tried)];
        let bytes = encode(&entries, CHAIN_ID);
        let back = decode(&bytes, CHAIN_ID).expect("round trip");
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].ip, entries[0].ip);
        assert_eq!(back[0].source_group, [1, 2, 3, 4]);
        assert_eq!(back[1].table, Table::Tried);
    }

    #[test]
    fn a_file_truncated_anywhere_is_refused_rather_than_half_read() {
        let entries: Vec<AddrEntry> = (1..=8).map(|i| rec(i, Table::New)).collect();
        let bytes = encode(&entries, CHAIN_ID);

        for cut in 0..bytes.len() {
            assert!(
                decode(&bytes[..cut], CHAIN_ID).is_err(),
                "prefix of {cut} bytes was accepted"
            );
        }
        assert!(
            decode(&bytes, CHAIN_ID).is_ok(),
            "the whole file must still load"
        );
    }

    #[test]
    fn one_flipped_bit_anywhere_is_caught_by_the_digest() {
        let entries: Vec<AddrEntry> = (1..=4).map(|i| rec(i, Table::New)).collect();
        let bytes = encode(&entries, CHAIN_ID);
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            assert!(
                decode(&b, CHAIN_ID).is_err(),
                "a flip at byte {i} was accepted"
            );
        }
    }

    #[test]
    fn a_file_from_the_other_network_is_refused() {
        let bytes = encode(&[rec(1, Table::New)], FOREIGN_CHAIN_ID);
        match decode(&bytes, CHAIN_ID) {
            Err(PeersError::ForeignChain(c)) => assert_eq!(c, FOREIGN_CHAIN_ID),
            other => panic!("expected ForeignChain, got {other:?}"),
        }
    }

    #[test]
    fn a_count_field_that_lies_cannot_make_the_reader_allocate() {
        let mut bytes = encode(&[rec(1, Table::New)], CHAIN_ID);
        bytes[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&bytes, CHAIN_ID), Err(PeersError::TooLong));

        let mut bytes = encode(&[rec(1, Table::New)], CHAIN_ID);
        bytes[14..18].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(decode(&bytes, CHAIN_ID), Err(PeersError::BadLength));
    }

    #[test]
    fn an_unknown_table_byte_is_refused_rather_than_defaulted() {
        let mut bytes = encode(&[rec(1, Table::New)], CHAIN_ID);
        bytes[PEERS_HEADER_BYTES + 30] = 9;

        let body = bytes.len() - PEERS_DIGEST_BYTES;
        let d = plaine_consensus::blake3::hash(&bytes[..body]);
        bytes[body..].copy_from_slice(&d);
        assert_eq!(decode(&bytes, CHAIN_ID), Err(PeersError::BadRecord));
    }

    #[test]
    fn the_file_cap_is_the_books_own_cap_and_a_bigger_file_is_never_parsed() {
        let big = vec![0u8; PEERS_FILE_MAX + 1];
        assert_eq!(decode(&big, CHAIN_ID), Err(PeersError::TooLong));
    }
}
