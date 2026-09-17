use crate::constants::{
    ADDRESS_PAYLOAD_BYTES, ANNOUNCEMENT_MAX_PAYLOAD_BYTES, ANNOUNCEMENT_MIN_PAYLOAD_BYTES,
    AUTHOR_NOTE_MAX_BYTES, AUTHOR_NOTE_RECORD_VERSION, BODY_COUNT_BYTES, BODY_MIN_RECORD_BYTES,
    BODY_TXLEN_BYTES, COINBASE_PREFIX_BYTES, HEADER_BYTES, MAX_BLOCK_BYTES, MAX_TXS_PER_BLOCK,
    MAX_TX_BYTES, TX_ANNOUNCEMENT_OVERHEAD_BYTES, TX_ANNOUNCEMENT_PREFIX_BYTES,
    TX_ANN_OFF_ENCODING, TX_ANN_OFF_FEE, TX_ANN_OFF_FROM_PUB, TX_ANN_OFF_LENGTH, TX_ANN_OFF_NONCE,
    TX_ANN_OFF_PAYLOAD, TX_CB_OFF_FEES, TX_CB_OFF_HEIGHT, TX_CB_OFF_NOTE, TX_CB_OFF_REWARD,
    TX_CB_OFF_TO, TX_TRANSFER_BYTES, TX_TRANSFER_BYTES_UNSIGNED, TX_TYPE_ANNOUNCEMENT,
    TX_TYPE_COINBASE, TX_TYPE_TRANSFER,
};
use crate::crypto;

pub use crate::constants::{AUTHOR_NOTE_HEADER_BYTES, HASH_BYTES, PUBKEY_BYTES, SIG_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    Truncated { need: usize, got: usize },
    TrailingBytes { extra: usize },
    WrongTxType { got: u8 },
    ReservedTxType { got: u8 },
    AuthorNoteVersion { got: u8 },
    AuthorNoteTooLong { len: usize },
    AnnouncementLength { len: usize },
    BodyTxCount { got: usize },
    BodyTxLen { got: usize },
    BodyTooLarge { got: usize },
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CodecError::Truncated { need, got } => {
                write!(f, "truncated: need {need} bytes, got {got}")
            }
            CodecError::TrailingBytes { extra } => {
                write!(f, "non-canonical: {extra} trailing byte(s)")
            }
            CodecError::WrongTxType { got } => write!(f, "wrong tx type byte 0x{got:02x}"),
            CodecError::ReservedTxType { got } => {
                write!(f, "reserved tx type 0x{got:02x} (0x03..=0xFF are rejected)")
            }
            CodecError::AuthorNoteVersion { got } => {
                write!(f, "author-note record_version 0x{got:02x}, expected 0x01")
            }
            CodecError::AuthorNoteTooLong { len } => {
                write!(f, "author-note length {len} exceeds 256")
            }
            CodecError::AnnouncementLength { len } => {
                write!(f, "announcement payload length {len} outside 1..=1024")
            }
            CodecError::BodyTxCount { got } => {
                write!(
                    f,
                    "block body declares {got} transactions (allowed 1..=4096)"
                )
            }
            CodecError::BodyTxLen { got } => {
                write!(
                    f,
                    "block body record declares {got} bytes (allowed 1..=8192)"
                )
            }
            CodecError::BodyTooLarge { got } => {
                write!(
                    f,
                    "block body of {got} bytes exceeds the block size limit with the header"
                )
            }
        }
    }
}

impl std::error::Error for CodecError {}

// Every fixed-size structure decodes through this. Rejecting trailing bytes
// keeps encode/decode a bijection: one valid byte string per tx, one txid.
fn require_exact(got: usize, need: usize) -> Result<(), CodecError> {
    if got < need {
        Err(CodecError::Truncated { need, got })
    } else if got > need {
        Err(CodecError::TrailingBytes { extra: got - need })
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub height: u64,
    pub prev_hash: [u8; HASH_BYTES],
    pub tx_root: [u8; HASH_BYTES],
    // reserved for a future commitment; consensus requires it to be all-zero.
    pub ext_root: [u8; HASH_BYTES],
    pub time: u64,
    pub bits: u32,
    pub author_note_len: u32,
    pub nonce: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut b = [0u8; HEADER_BYTES];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..12].copy_from_slice(&self.height.to_le_bytes());
        b[12..44].copy_from_slice(&self.prev_hash);
        b[44..76].copy_from_slice(&self.tx_root);
        b[76..108].copy_from_slice(&self.ext_root);
        b[108..116].copy_from_slice(&self.time.to_le_bytes());
        b[116..120].copy_from_slice(&self.bits.to_le_bytes());
        b[120..124].copy_from_slice(&self.author_note_len.to_le_bytes());
        b[124..132].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        require_exact(bytes.len(), HEADER_BYTES)?;
        let arr = |r: core::ops::Range<usize>| -> [u8; HASH_BYTES] {
            bytes[r].try_into().expect("range length is 32")
        };
        Ok(Header {
            version: u32::from_le_bytes(bytes[0..4].try_into().expect("4")),
            height: u64::from_le_bytes(bytes[4..12].try_into().expect("8")),
            prev_hash: arr(12..44),
            tx_root: arr(44..76),
            ext_root: arr(76..108),
            time: u64::from_le_bytes(bytes[108..116].try_into().expect("8")),
            bits: u32::from_le_bytes(bytes[116..120].try_into().expect("4")),
            author_note_len: u32::from_le_bytes(bytes[120..124].try_into().expect("4")),
            nonce: u64::from_le_bytes(bytes[124..132].try_into().expect("8")),
        })
    }

    pub fn hash(&self) -> [u8; HASH_BYTES] {
        crypto::header_hash(&self.encode())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferTx {
    pub from_pub: [u8; PUBKEY_BYTES],
    pub to: [u8; ADDRESS_PAYLOAD_BYTES],
    pub amount: u128,
    pub fee: u128,
    pub nonce: u64,
    pub sig: [u8; SIG_BYTES],
}

impl TransferTx {
    pub fn encode_unsigned(&self) -> [u8; TX_TRANSFER_BYTES_UNSIGNED] {
        let mut b = [0u8; TX_TRANSFER_BYTES_UNSIGNED];
        b[0] = TX_TYPE_TRANSFER;
        b[1..33].copy_from_slice(&self.from_pub);
        b[33..53].copy_from_slice(&self.to);
        b[53..69].copy_from_slice(&self.amount.to_le_bytes());
        b[69..85].copy_from_slice(&self.fee.to_le_bytes());
        b[85..93].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    pub fn encode(&self) -> [u8; TX_TRANSFER_BYTES] {
        let mut b = [0u8; TX_TRANSFER_BYTES];
        b[..TX_TRANSFER_BYTES_UNSIGNED].copy_from_slice(&self.encode_unsigned());
        b[TX_TRANSFER_BYTES_UNSIGNED..].copy_from_slice(&self.sig);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        require_exact(bytes.len(), TX_TRANSFER_BYTES)?;
        if bytes[0] != TX_TYPE_TRANSFER {
            return Err(CodecError::WrongTxType { got: bytes[0] });
        }
        Ok(TransferTx {
            from_pub: bytes[1..33].try_into().expect("32"),
            to: bytes[33..53].try_into().expect("20"),
            amount: u128::from_le_bytes(bytes[53..69].try_into().expect("16")),
            fee: u128::from_le_bytes(bytes[69..85].try_into().expect("16")),
            nonce: u64::from_le_bytes(bytes[85..93].try_into().expect("8")),
            sig: bytes[93..157].try_into().expect("64"),
        })
    }

    pub fn txid(&self) -> [u8; HASH_BYTES] {
        crypto::txid(&self.encode_unsigned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementTx {
    pub from_pub: [u8; PUBKEY_BYTES],
    pub fee: u128,
    pub nonce: u64,
    pub encoding: u8,
    pub payload: Vec<u8>,
    pub sig: [u8; SIG_BYTES],
}

impl AnnouncementTx {
    pub fn check_payload_len(&self) -> Result<u16, CodecError> {
        let len = self.payload.len();
        if !(ANNOUNCEMENT_MIN_PAYLOAD_BYTES..=ANNOUNCEMENT_MAX_PAYLOAD_BYTES).contains(&len) {
            return Err(CodecError::AnnouncementLength { len });
        }
        Ok(len as u16)
    }

    pub fn wire_len(&self) -> usize {
        TX_ANNOUNCEMENT_OVERHEAD_BYTES + self.payload.len()
    }

    pub fn encode_unsigned(&self) -> Result<Vec<u8>, CodecError> {
        let length = self.check_payload_len()?;
        let mut v = Vec::with_capacity(TX_ANNOUNCEMENT_PREFIX_BYTES + self.payload.len());
        v.push(TX_TYPE_ANNOUNCEMENT);
        v.extend_from_slice(&self.from_pub);
        v.extend_from_slice(&self.fee.to_le_bytes());
        v.extend_from_slice(&self.nonce.to_le_bytes());
        v.push(self.encoding);
        v.extend_from_slice(&length.to_le_bytes());
        v.extend_from_slice(&self.payload);
        debug_assert_eq!(v.len(), TX_ANNOUNCEMENT_PREFIX_BYTES + self.payload.len());
        Ok(v)
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut v = self.encode_unsigned()?;
        v.extend_from_slice(&self.sig);
        Ok(v)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let min = TX_ANNOUNCEMENT_OVERHEAD_BYTES + ANNOUNCEMENT_MIN_PAYLOAD_BYTES;
        if bytes.len() < min {
            return Err(CodecError::Truncated {
                need: min,
                got: bytes.len(),
            });
        }

        if bytes[0] != TX_TYPE_ANNOUNCEMENT {
            return Err(CodecError::WrongTxType { got: bytes[0] });
        }

        let length =
            u16::from_le_bytes([bytes[TX_ANN_OFF_LENGTH], bytes[TX_ANN_OFF_LENGTH + 1]]) as usize;
        if !(ANNOUNCEMENT_MIN_PAYLOAD_BYTES..=ANNOUNCEMENT_MAX_PAYLOAD_BYTES).contains(&length) {
            return Err(CodecError::AnnouncementLength { len: length });
        }

        require_exact(bytes.len(), TX_ANNOUNCEMENT_OVERHEAD_BYTES + length)?;

        let payload_end = TX_ANN_OFF_PAYLOAD + length;
        Ok(AnnouncementTx {
            from_pub: bytes[TX_ANN_OFF_FROM_PUB..TX_ANN_OFF_FROM_PUB + PUBKEY_BYTES]
                .try_into()
                .expect("32"),
            fee: u128::from_le_bytes(
                bytes[TX_ANN_OFF_FEE..TX_ANN_OFF_FEE + 16]
                    .try_into()
                    .expect("16"),
            ),
            nonce: u64::from_le_bytes(
                bytes[TX_ANN_OFF_NONCE..TX_ANN_OFF_NONCE + 8]
                    .try_into()
                    .expect("8"),
            ),
            encoding: bytes[TX_ANN_OFF_ENCODING],
            payload: bytes[TX_ANN_OFF_PAYLOAD..payload_end].to_vec(),
            sig: bytes[payload_end..payload_end + SIG_BYTES]
                .try_into()
                .expect("64"),
        })
    }

    pub fn txid(&self) -> Result<[u8; HASH_BYTES], CodecError> {
        Ok(crypto::txid(&self.encode_unsigned()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseTx {
    pub height: u64,
    pub to: [u8; ADDRESS_PAYLOAD_BYTES],
    pub reward: u128,
    pub fees: u128,
    pub note: AuthorNote,
}

impl CoinbaseTx {
    pub fn wire_len(&self) -> usize {
        COINBASE_PREFIX_BYTES + AUTHOR_NOTE_HEADER_BYTES + self.note.payload.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let note = self.note.encode()?;
        let mut v = Vec::with_capacity(COINBASE_PREFIX_BYTES + note.len());
        v.push(TX_TYPE_COINBASE);
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.to);
        v.extend_from_slice(&self.reward.to_le_bytes());
        v.extend_from_slice(&self.fees.to_le_bytes());
        v.extend_from_slice(&note);
        Ok(v)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let min = COINBASE_PREFIX_BYTES + AUTHOR_NOTE_HEADER_BYTES;
        if bytes.len() < min {
            return Err(CodecError::Truncated {
                need: min,
                got: bytes.len(),
            });
        }
        if bytes[0] != TX_TYPE_COINBASE {
            return Err(CodecError::WrongTxType { got: bytes[0] });
        }
        Ok(CoinbaseTx {
            height: u64::from_le_bytes(
                bytes[TX_CB_OFF_HEIGHT..TX_CB_OFF_HEIGHT + 8]
                    .try_into()
                    .expect("8"),
            ),
            to: bytes[TX_CB_OFF_TO..TX_CB_OFF_TO + ADDRESS_PAYLOAD_BYTES]
                .try_into()
                .expect("20"),
            reward: u128::from_le_bytes(
                bytes[TX_CB_OFF_REWARD..TX_CB_OFF_REWARD + 16]
                    .try_into()
                    .expect("16"),
            ),
            fees: u128::from_le_bytes(
                bytes[TX_CB_OFF_FEES..TX_CB_OFF_FEES + 16]
                    .try_into()
                    .expect("16"),
            ),
            note: AuthorNote::decode(&bytes[TX_CB_OFF_NOTE..])?,
        })
    }

    pub fn txid(&self) -> Result<[u8; HASH_BYTES], CodecError> {
        Ok(crypto::txid(&self.encode()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tx {
    Coinbase(CoinbaseTx),
    Transfer(TransferTx),
    Announcement(AnnouncementTx),
}

impl Tx {
    pub fn fee(&self) -> u128 {
        match self {
            Tx::Coinbase(_) => 0,
            Tx::Transfer(t) => t.fee,
            Tx::Announcement(a) => a.fee,
        }
    }

    pub fn type_byte(&self) -> u8 {
        match self {
            Tx::Coinbase(_) => TX_TYPE_COINBASE,
            Tx::Transfer(_) => TX_TYPE_TRANSFER,
            Tx::Announcement(_) => TX_TYPE_ANNOUNCEMENT,
        }
    }
}

pub fn decode_tx(bytes: &[u8]) -> Result<Tx, CodecError> {
    let first = *bytes
        .first()
        .ok_or(CodecError::Truncated { need: 1, got: 0 })?;
    match first {
        TX_TYPE_COINBASE => Ok(Tx::Coinbase(CoinbaseTx::decode(bytes)?)),
        TX_TYPE_TRANSFER => Ok(Tx::Transfer(TransferTx::decode(bytes)?)),
        TX_TYPE_ANNOUNCEMENT => Ok(Tx::Announcement(AnnouncementTx::decode(bytes)?)),
        // Rejected here, but the body envelope length-delimits them, so an old
        // node can still skip a type it does not know.
        got => Err(CodecError::ReservedTxType { got }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorNote {
    pub encoding: u8,
    pub payload: Vec<u8>,
}

impl AuthorNote {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.payload.len() > AUTHOR_NOTE_MAX_BYTES {
            return Err(CodecError::AuthorNoteTooLong {
                len: self.payload.len(),
            });
        }
        let mut v = Vec::with_capacity(AUTHOR_NOTE_HEADER_BYTES + self.payload.len());
        v.push(AUTHOR_NOTE_RECORD_VERSION);
        v.push(self.encoding);
        v.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.payload);
        Ok(v)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < AUTHOR_NOTE_HEADER_BYTES {
            return Err(CodecError::Truncated {
                need: AUTHOR_NOTE_HEADER_BYTES,
                got: bytes.len(),
            });
        }
        if bytes[0] != AUTHOR_NOTE_RECORD_VERSION {
            return Err(CodecError::AuthorNoteVersion { got: bytes[0] });
        }
        let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        if len > AUTHOR_NOTE_MAX_BYTES {
            return Err(CodecError::AuthorNoteTooLong { len });
        }
        require_exact(bytes.len(), AUTHOR_NOTE_HEADER_BYTES + len)?;
        Ok(AuthorNote {
            encoding: bytes[1],
            payload: bytes[AUTHOR_NOTE_HEADER_BYTES..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBody<'a> {
    raw: &'a [u8],
    spans: Vec<core::ops::Range<usize>>,
}

impl<'a> BlockBody<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, CodecError> {
        if raw.len() + HEADER_BYTES > MAX_BLOCK_BYTES {
            return Err(CodecError::BodyTooLarge { got: raw.len() });
        }
        if raw.len() < BODY_COUNT_BYTES {
            return Err(CodecError::Truncated {
                need: BODY_COUNT_BYTES,
                got: raw.len(),
            });
        }
        let count = u32::from_le_bytes(raw[0..BODY_COUNT_BYTES].try_into().expect("4")) as usize;

        if count == 0 || count > MAX_TXS_PER_BLOCK {
            return Err(CodecError::BodyTxCount { got: count });
        }

        // Gate before sizing `spans` from count: the smallest record is 5 bytes,
        // so a count this large in this few bytes can't be honest.
        let min_total = BODY_COUNT_BYTES + count * BODY_MIN_RECORD_BYTES;
        if min_total > raw.len() {
            return Err(CodecError::Truncated {
                need: min_total,
                got: raw.len(),
            });
        }

        let mut spans = Vec::with_capacity(count);
        let mut off = BODY_COUNT_BYTES;
        for _ in 0..count {
            let len_end = off
                .checked_add(BODY_TXLEN_BYTES)
                .ok_or(CodecError::BodyTooLarge { got: raw.len() })?;
            if len_end > raw.len() {
                return Err(CodecError::Truncated {
                    need: len_end,
                    got: raw.len(),
                });
            }
            let tx_len = u32::from_le_bytes(raw[off..len_end].try_into().expect("4")) as usize;
            if tx_len == 0 || tx_len > MAX_TX_BYTES {
                return Err(CodecError::BodyTxLen { got: tx_len });
            }
            let tx_end = len_end
                .checked_add(tx_len)
                .ok_or(CodecError::BodyTooLarge { got: raw.len() })?;
            if tx_end > raw.len() {
                return Err(CodecError::Truncated {
                    need: tx_end,
                    got: raw.len(),
                });
            }
            spans.push(len_end..tx_end);
            off = tx_end;
        }

        if off != raw.len() {
            return Err(CodecError::TrailingBytes {
                extra: raw.len() - off,
            });
        }
        Ok(BlockBody { raw, spans })
    }

    pub fn encode(txs: &[&[u8]]) -> Result<Vec<u8>, CodecError> {
        if txs.is_empty() || txs.len() > MAX_TXS_PER_BLOCK {
            return Err(CodecError::BodyTxCount { got: txs.len() });
        }
        let mut v = Vec::with_capacity(
            BODY_COUNT_BYTES
                + txs
                    .iter()
                    .map(|t| BODY_TXLEN_BYTES + t.len())
                    .sum::<usize>(),
        );
        v.extend_from_slice(&(txs.len() as u32).to_le_bytes());
        for tx in txs {
            if tx.is_empty() || tx.len() > MAX_TX_BYTES {
                return Err(CodecError::BodyTxLen { got: tx.len() });
            }
            v.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            v.extend_from_slice(tx);
        }
        if v.len() + HEADER_BYTES > MAX_BLOCK_BYTES {
            return Err(CodecError::BodyTooLarge { got: v.len() });
        }
        Ok(v)
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn encoded_len(&self) -> usize {
        self.raw.len()
    }

    pub fn tx_bytes(&self, i: usize) -> Option<&'a [u8]> {
        self.spans.get(i).map(|r| &self.raw[r.clone()])
    }

    pub fn decode_tx(&self, i: usize) -> Option<Result<Tx, CodecError>> {
        self.tx_bytes(i).map(decode_tx)
    }

    pub fn decode_all(&self) -> Result<Vec<Tx>, CodecError> {
        (0..self.len())
            .map(|i| decode_tx(self.tx_bytes(i).expect("i < len")))
            .collect()
    }

    pub fn leaves(&self) -> Vec<[u8; HASH_BYTES]> {
        (0..self.len())
            .map(|i| crypto::merkle_leaf(self.tx_bytes(i).expect("i < len")))
            .collect()
    }

    pub fn tx_root(&self) -> [u8; HASH_BYTES] {
        crate::merkle::merkle_root(&self.leaves())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn header_hand_built_vector_and_hash() {
        let h = Header {
            version: 0x2000_0000,
            height: 0x1122_3344_5566_7788,
            prev_hash: core::array::from_fn(|i| i as u8),
            tx_root: core::array::from_fn(|i| 0x20 + i as u8),
            ext_root: [0u8; 32],
            time: 1_700_000_000,
            bits: 0x1D00_FFFF,
            author_note_len: 33,
            nonce: 0xDEAD_BEEF_CAFE_BABE,
        };
        let expected_hex = concat!(
            "00000020",
            "8877665544332211",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00f1536500000000",
            "ffff001d",
            "21000000",
            "bebafecaefbeadde",
        );
        let enc = h.encode();
        assert_eq!(enc.len(), HEADER_BYTES);
        assert_eq!(crate::hex::encode(&enc), expected_hex);
        assert_eq!(Header::decode(&enc).unwrap(), h);

        assert_eq!(
            crate::hex::encode(&h.hash()),
            "4c033d24851bd65628b283a74b949caf4b327b6564da444ef53140661c2f133c",
        );
    }

    #[test]
    fn header_decode_rejects_wrong_lengths() {
        let bytes = [0u8; HEADER_BYTES];
        assert_eq!(
            Header::decode(&bytes[..HEADER_BYTES - 1]),
            Err(CodecError::Truncated {
                need: HEADER_BYTES,
                got: HEADER_BYTES - 1
            })
        );
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(
            Header::decode(&longer),
            Err(CodecError::TrailingBytes { extra: 1 })
        );
        assert_eq!(
            Header::decode(&[]),
            Err(CodecError::Truncated {
                need: HEADER_BYTES,
                got: 0
            })
        );
    }

    proptest! {
        #[test]
        fn header_roundtrip_random_bytes(bytes in prop::collection::vec(any::<u8>(), HEADER_BYTES)) {
            let h = Header::decode(&bytes).unwrap();
            let reencoded = h.encode();
            prop_assert_eq!(reencoded.as_slice(), bytes.as_slice());
        }

        #[test]
        fn header_roundtrip_random_fields(
            version in any::<u32>(),
            height in any::<u64>(),
            prev_hash in any::<[u8; 32]>(),
            tx_root in any::<[u8; 32]>(),
            ext_root in any::<[u8; 32]>(),
            time in any::<u64>(),
            bits in any::<u32>(),
            author_note_len in any::<u32>(),
            nonce in any::<u64>(),
        ) {
            let h = Header {
                version, height, prev_hash, tx_root, ext_root,
                time, bits, author_note_len, nonce,
            };
            prop_assert_eq!(Header::decode(&h.encode()).unwrap(), h);
        }
    }

    fn sample_tx() -> TransferTx {
        TransferTx {
            from_pub: [0xAB; 32],
            to: [0xCD; 20],
            amount: 1_000_000_000_000_000_000,
            fee: 1,
            nonce: 7,
            sig: [0xEF; 64],
        }
    }

    #[test]
    fn transfer_roundtrip_and_sizes() {
        let tx = sample_tx();
        let enc = tx.encode();
        assert_eq!(enc.len(), TX_TRANSFER_BYTES);
        assert_eq!(tx.encode_unsigned().len(), TX_TRANSFER_BYTES_UNSIGNED);

        assert_eq!(
            &enc[..TX_TRANSFER_BYTES_UNSIGNED],
            tx.encode_unsigned().as_slice()
        );
        assert_eq!(enc[0], TX_TYPE_TRANSFER);
        assert_eq!(TransferTx::decode(&enc).unwrap(), tx);
    }

    #[test]
    fn transfer_decode_rejects_wrong_lengths_and_trailing() {
        let enc = sample_tx().encode();
        assert_eq!(
            TransferTx::decode(&enc[..TX_TRANSFER_BYTES - 1]),
            Err(CodecError::Truncated {
                need: TX_TRANSFER_BYTES,
                got: TX_TRANSFER_BYTES - 1
            })
        );
        let mut longer = enc.to_vec();
        longer.push(0x00);
        assert_eq!(
            TransferTx::decode(&longer),
            Err(CodecError::TrailingBytes { extra: 1 })
        );
        assert_eq!(
            TransferTx::decode(&[]),
            Err(CodecError::Truncated {
                need: TX_TRANSFER_BYTES,
                got: 0
            })
        );
    }

    #[test]
    fn transfer_decode_rejects_wrong_type_byte() {
        let mut enc = sample_tx().encode();
        enc[0] = TX_TYPE_COINBASE;
        assert_eq!(
            TransferTx::decode(&enc),
            Err(CodecError::WrongTxType { got: 0x00 })
        );
        enc[0] = 0x02;
        assert_eq!(
            TransferTx::decode(&enc),
            Err(CodecError::WrongTxType { got: 0x02 })
        );
    }

    #[test]
    fn decode_tx_envelope_dispatch() {
        let enc = sample_tx().encode();
        assert_eq!(decode_tx(&enc).unwrap(), Tx::Transfer(sample_tx()));

        for t in [0x03u8, 0x7F, 0xFF] {
            let mut bad = enc.to_vec();
            bad[0] = t;
            assert_eq!(decode_tx(&bad), Err(CodecError::ReservedTxType { got: t }));
        }

        assert_eq!(
            decode_tx(&[TX_TYPE_COINBASE]),
            Err(CodecError::Truncated {
                need: COINBASE_PREFIX_BYTES + AUTHOR_NOTE_HEADER_BYTES,
                got: 1
            })
        );
        assert_eq!(
            decode_tx(&[]),
            Err(CodecError::Truncated { need: 1, got: 0 })
        );
    }

    proptest! {
        #[test]
        fn transfer_roundtrip_random_fields(
            from_pub in any::<[u8; 32]>(),
            to in any::<[u8; 20]>(),
            amount in any::<u128>(),
            fee in any::<u128>(),
            nonce in any::<u64>(),
            sig_a in any::<[u8; 32]>(),
            sig_b in any::<[u8; 32]>(),
        ) {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&sig_a);
            sig[32..].copy_from_slice(&sig_b);
            let tx = TransferTx { from_pub, to, amount, fee, nonce, sig };
            prop_assert_eq!(TransferTx::decode(&tx.encode()).unwrap(), tx);
        }
    }

    #[test]
    fn author_note_roundtrip() {
        for payload in [vec![], b"Plaine genesis".to_vec(), vec![0xFF; 256]] {
            let note = AuthorNote {
                encoding: 0x01,
                payload,
            };
            let enc = note.encode().unwrap();
            assert_eq!(enc[0], AUTHOR_NOTE_RECORD_VERSION);
            assert_eq!(AuthorNote::decode(&enc).unwrap(), note);
        }

        let odd = AuthorNote {
            encoding: 0xEE,
            payload: vec![1, 2, 3],
        };
        assert_eq!(AuthorNote::decode(&odd.encode().unwrap()).unwrap(), odd);
    }

    fn sample_announcement(payload: Vec<u8>) -> AnnouncementTx {
        AnnouncementTx {
            from_pub: core::array::from_fn(|i| i as u8),
            fee: 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10,
            nonce: 0xDEAD_BEEF_CAFE_BABE,
            encoding: 0xEE,
            payload,
            sig: [0x5A; SIG_BYTES],
        }
    }

    #[test]
    fn announcement_hand_built_vector() {
        let tx = sample_announcement(vec![0xAA, 0xBB, 0xCC]);
        let enc = tx.encode().unwrap();
        assert_eq!(enc.len(), 124 + 3);
        assert_eq!(tx.wire_len(), enc.len());

        let mut want = String::new();
        want.push_str("02");
        want.push_str("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        want.push_str("100f0e0d0c0b0a090807060504030201");
        want.push_str("bebafecaefbeadde");
        want.push_str("ee");
        want.push_str("0300");
        want.push_str("aabbcc");
        want.push_str(&"5a".repeat(64));
        assert_eq!(crate::hex::encode(&enc), want);

        assert_ne!(
            u128::from_be_bytes(enc[TX_ANN_OFF_FEE..TX_ANN_OFF_FEE + 16].try_into().unwrap()),
            tx.fee
        );
        assert_ne!(
            u64::from_be_bytes(
                enc[TX_ANN_OFF_NONCE..TX_ANN_OFF_NONCE + 8]
                    .try_into()
                    .unwrap()
            ),
            tx.nonce
        );

        assert_eq!(AnnouncementTx::decode(&enc).unwrap(), tx);

        assert_eq!(
            &enc[..TX_ANNOUNCEMENT_PREFIX_BYTES + 3],
            tx.encode_unsigned().unwrap()
        );
    }

    #[test]
    fn announcement_roundtrip_at_both_length_boundaries() {
        for n in [1usize, 2, 255, 256, 1023, 1024] {
            let tx = sample_announcement(vec![0x7F; n]);
            let enc = tx.encode().unwrap();
            assert_eq!(enc.len(), 124 + n);
            let back = AnnouncementTx::decode(&enc).unwrap();
            assert_eq!(back, tx);
            assert_eq!(back.encode().unwrap(), enc, "encode/decode is a bijection");
        }
    }

    #[test]
    fn announcement_rejects_length_zero_and_over_1024() {
        assert_eq!(
            sample_announcement(vec![]).encode(),
            Err(CodecError::AnnouncementLength { len: 0 })
        );
        assert_eq!(
            sample_announcement(vec![0; 1025]).encode(),
            Err(CodecError::AnnouncementLength { len: 1025 })
        );

        let mut wire = sample_announcement(vec![0x11]).encode().unwrap();
        wire[TX_ANN_OFF_LENGTH] = 0;
        wire[TX_ANN_OFF_LENGTH + 1] = 0;
        assert_eq!(
            AnnouncementTx::decode(&wire),
            Err(CodecError::AnnouncementLength { len: 0 })
        );

        let mut wire = sample_announcement(vec![0x11]).encode().unwrap();
        wire[TX_ANN_OFF_LENGTH..TX_ANN_OFF_LENGTH + 2].copy_from_slice(&1025u16.to_le_bytes());
        assert_eq!(
            AnnouncementTx::decode(&wire),
            Err(CodecError::AnnouncementLength { len: 1025 }),
            "range check must precede the total-size check"
        );

        wire[TX_ANN_OFF_LENGTH..TX_ANN_OFF_LENGTH + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            AnnouncementTx::decode(&wire),
            Err(CodecError::AnnouncementLength { len: 65535 })
        );
    }

    #[test]
    fn announcement_rejects_truncation_trailing_and_wrong_type() {
        let enc = sample_announcement(vec![0x11; 8]).encode().unwrap();

        assert_eq!(
            AnnouncementTx::decode(&enc[..enc.len() - 1]),
            Err(CodecError::Truncated {
                need: 132,
                got: 131
            })
        );

        let mut longer = enc.clone();
        longer.push(0);
        assert_eq!(
            AnnouncementTx::decode(&longer),
            Err(CodecError::TrailingBytes { extra: 1 })
        );

        assert_eq!(
            AnnouncementTx::decode(&[0x02; 124]),
            Err(CodecError::Truncated {
                need: 125,
                got: 124
            })
        );

        let mut bad = enc.clone();
        bad[0] = TX_TYPE_TRANSFER;
        assert_eq!(
            AnnouncementTx::decode(&bad),
            Err(CodecError::WrongTxType { got: 0x01 })
        );
    }

    #[test]
    fn announcement_txid_ignores_sig() {
        let tx = sample_announcement(vec![0x01, 0x02]);
        let mut resigned = tx.clone();
        resigned.sig = [0x00; SIG_BYTES];
        assert_eq!(tx.txid().unwrap(), resigned.txid().unwrap());

        assert_ne!(tx.txid().unwrap(), sample_tx().txid());

        assert_eq!(
            sample_announcement(vec![]).txid(),
            Err(CodecError::AnnouncementLength { len: 0 })
        );
    }

    fn sample_coinbase(note_len: usize) -> CoinbaseTx {
        CoinbaseTx {
            height: 0xDEAD_BEEF_CAFE_BABE,
            to: core::array::from_fn(|i| 0x40 + i as u8),
            reward: 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10,
            fees: 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00,
            note: AuthorNote {
                encoding: 0x02,
                payload: vec![0x33; note_len],
            },
        }
    }

    #[test]
    fn coinbase_hand_built_vector_and_roundtrip() {
        let cb = sample_coinbase(2);
        let enc = cb.encode().unwrap();
        assert_eq!(enc.len(), 65 + 2);
        assert_eq!(cb.wire_len(), enc.len());
        let mut want = String::new();
        want.push_str("00");
        want.push_str("bebafecaefbeadde");
        want.push_str("404142434445464748494a4b4c4d4e4f50515253");
        want.push_str("100f0e0d0c0b0a090807060504030201");
        want.push_str("00ffeeddccbbaa998877665544332211");
        want.push_str("01");
        want.push_str("02");
        want.push_str("0200");
        want.push_str("3333");
        assert_eq!(crate::hex::encode(&enc), want);
        assert_eq!(CoinbaseTx::decode(&enc).unwrap(), cb);

        for n in [0usize, 1, 256] {
            let cb = sample_coinbase(n);
            let enc = cb.encode().unwrap();
            assert_eq!(enc.len(), 65 + n);
            assert_eq!(CoinbaseTx::decode(&enc).unwrap(), cb);
        }
    }

    #[test]
    fn coinbase_rejects_malformed() {
        assert_eq!(
            sample_coinbase(257).encode(),
            Err(CodecError::AuthorNoteTooLong { len: 257 })
        );
        let mut wire = sample_coinbase(1).encode().unwrap();
        wire[TX_CB_OFF_NOTE + 2..TX_CB_OFF_NOTE + 4].copy_from_slice(&257u16.to_le_bytes());
        assert_eq!(
            CoinbaseTx::decode(&wire),
            Err(CodecError::AuthorNoteTooLong { len: 257 })
        );

        assert_eq!(
            CoinbaseTx::decode(&[0x00; 64]),
            Err(CodecError::Truncated { need: 65, got: 64 })
        );

        let mut longer = sample_coinbase(1).encode().unwrap();
        longer.push(0xFF);
        assert_eq!(
            CoinbaseTx::decode(&longer),
            Err(CodecError::TrailingBytes { extra: 1 })
        );

        let mut bad = sample_coinbase(0).encode().unwrap();
        bad[0] = TX_TYPE_TRANSFER;
        assert_eq!(
            CoinbaseTx::decode(&bad),
            Err(CodecError::WrongTxType { got: 0x01 })
        );

        let mut bad = sample_coinbase(0).encode().unwrap();
        bad[TX_CB_OFF_NOTE] = 0x02;
        assert_eq!(
            CoinbaseTx::decode(&bad),
            Err(CodecError::AuthorNoteVersion { got: 0x02 })
        );
    }

    #[test]
    fn every_integer_field_is_little_endian() {
        fn check(bytes: &[u8], off: usize, width: usize, field: &str) {
            assert_eq!(
                bytes[off], 0x01,
                "{field}: low byte must sit at offset {off}"
            );
            for (i, b) in bytes[off + 1..off + width].iter().enumerate() {
                assert_eq!(*b, 0, "{field}: byte {} must be zero", i + 1);
            }
        }

        let h = Header {
            version: 1,
            height: 1,
            prev_hash: [0; 32],
            tx_root: [0; 32],
            ext_root: [0; 32],
            time: 1,
            bits: 1,
            author_note_len: 1,
            nonce: 1,
        };
        let e = h.encode();
        check(&e, 0, 4, "header.version");
        check(&e, 4, 8, "header.height");
        check(&e, 108, 8, "header.time");
        check(&e, 116, 4, "header.bits");
        check(&e, 120, 4, "header.author_note_len");
        check(&e, 124, 8, "header.nonce");

        let t = TransferTx {
            from_pub: [0; 32],
            to: [0; 20],
            amount: 1,
            fee: 1,
            nonce: 1,
            sig: [0; 64],
        };
        let e = t.encode();
        check(&e, 53, 16, "transfer.amount");
        check(&e, 69, 16, "transfer.fee");
        check(&e, 85, 8, "transfer.nonce");

        let a = AnnouncementTx {
            from_pub: [0; 32],
            fee: 1,
            nonce: 1,
            encoding: 0,
            payload: vec![0; 1],
            sig: [0; 64],
        };
        let e = a.encode().unwrap();
        check(&e, TX_ANN_OFF_FEE, 16, "announcement.fee");
        check(&e, TX_ANN_OFF_NONCE, 8, "announcement.nonce");
        check(&e, TX_ANN_OFF_LENGTH, 2, "announcement.length");

        let c = CoinbaseTx {
            height: 1,
            to: [0; 20],
            reward: 1,
            fees: 1,
            note: AuthorNote {
                encoding: 0,
                payload: vec![0; 1],
            },
        };
        let e = c.encode().unwrap();
        check(&e, TX_CB_OFF_HEIGHT, 8, "coinbase.height");
        check(&e, TX_CB_OFF_REWARD, 16, "coinbase.reward");
        check(&e, TX_CB_OFF_FEES, 16, "coinbase.fees");
        check(&e, TX_CB_OFF_NOTE + 2, 2, "coinbase.note.length");

        let one = [TX_TYPE_TRANSFER; 1];
        let raw = BlockBody::encode(&[&one]).unwrap();
        check(&raw, 0, 4, "body.tx_count");
        check(&raw, 4, 4, "body.tx_len");
    }

    fn record(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    #[test]
    fn body_roundtrip_and_zero_copy() {
        let a = record(0x01, 7);
        let b = record(0x02, 13);
        let raw = BlockBody::encode(&[&a, &b]).unwrap();
        assert_eq!(raw.len(), 4 + 4 + 7 + 4 + 13);
        let body = BlockBody::parse(&raw).unwrap();
        assert_eq!(body.len(), 2);
        assert!(!body.is_empty());
        assert_eq!(body.encoded_len(), raw.len());

        assert_eq!(body.tx_bytes(0).unwrap(), a.as_slice());
        assert_eq!(body.tx_bytes(1).unwrap(), b.as_slice());
        assert!(body.tx_bytes(2).is_none());
        assert!(body.decode_tx(2).is_none());

        assert_eq!(body.tx_root(), crate::merkle::tx_root(&[&a, &b]));

        let mut raw2 = raw.clone();
        *raw2.last_mut().unwrap() ^= 0x01;
        assert_ne!(BlockBody::parse(&raw2).unwrap().tx_root(), body.tx_root());
    }

    #[test]
    fn body_at_maximum_transaction_count() {
        let one = record(0x01, 1);
        let refs: Vec<&[u8]> = (0..MAX_TXS_PER_BLOCK).map(|_| one.as_slice()).collect();
        let raw = BlockBody::encode(&refs).unwrap();
        let body = BlockBody::parse(&raw).unwrap();
        assert_eq!(body.len(), MAX_TXS_PER_BLOCK);
        assert_ne!(body.tx_root(), [0u8; 32]);

        let too_many: Vec<&[u8]> = (0..MAX_TXS_PER_BLOCK + 1).map(|_| one.as_slice()).collect();
        assert_eq!(
            BlockBody::encode(&too_many),
            Err(CodecError::BodyTxCount {
                got: MAX_TXS_PER_BLOCK + 1
            })
        );
    }

    #[test]
    fn body_rejects_bad_tx_count() {
        let raw = 0u32.to_le_bytes().to_vec();
        assert_eq!(
            BlockBody::parse(&raw),
            Err(CodecError::BodyTxCount { got: 0 })
        );

        let mut raw = (MAX_TXS_PER_BLOCK as u32 + 1).to_le_bytes().to_vec();
        raw.resize(100_000, 0);
        assert_eq!(
            BlockBody::parse(&raw),
            Err(CodecError::BodyTxCount {
                got: MAX_TXS_PER_BLOCK + 1
            })
        );

        assert_eq!(
            BlockBody::parse(&[0u8; 3]),
            Err(CodecError::Truncated { need: 4, got: 3 })
        );
    }

    #[test]
    fn body_plausibility_before_alloc() {
        let mut raw = (MAX_TXS_PER_BLOCK as u32).to_le_bytes().to_vec();
        raw.resize(10, 0);
        assert_eq!(
            BlockBody::parse(&raw),
            Err(CodecError::Truncated {
                need: 4 + 5 * MAX_TXS_PER_BLOCK,
                got: 10
            })
        );
    }

    #[test]
    fn body_rejects_bad_record_lengths() {
        let mut raw = 1u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.push(0xAA);
        assert_eq!(
            BlockBody::parse(&raw),
            Err(CodecError::BodyTxLen { got: 0 })
        );

        let mut raw = 1u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&((MAX_TX_BYTES + 1) as u32).to_le_bytes());
        raw.resize(4 + 4 + MAX_TX_BYTES + 1, 0x11);
        assert_eq!(
            BlockBody::parse(&raw),
            Err(CodecError::BodyTxLen {
                got: MAX_TX_BYTES + 1
            })
        );

        let mut raw = 1u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&100u32.to_le_bytes());
        raw.extend_from_slice(&[0x11; 50]);
        assert_eq!(
            BlockBody::parse(&raw),
            Err(CodecError::Truncated { need: 108, got: 58 })
        );

        let a = record(0x01, 4);
        let mut raw = BlockBody::encode(&[&a]).unwrap();
        raw.push(0x00);
        assert_eq!(
            BlockBody::parse(&raw),
            Err(CodecError::TrailingBytes { extra: 1 })
        );
    }

    #[test]
    fn body_size_limit_boundary() {
        let max_body = MAX_BLOCK_BYTES - HEADER_BYTES;

        let full = record(0x01, MAX_TX_BYTES);
        let used = 4 + 127 * (4 + MAX_TX_BYTES);
        let tail_len = max_body - used - 4;
        let tail = record(0x02, tail_len);
        let mut refs: Vec<&[u8]> = (0..127).map(|_| full.as_slice()).collect();
        refs.push(&tail);
        let raw = BlockBody::encode(&refs).unwrap();
        assert_eq!(raw.len(), max_body);
        assert_eq!(BlockBody::parse(&raw).unwrap().len(), 128);

        let mut over = raw.clone();
        over.push(0x00);
        assert_eq!(
            BlockBody::parse(&over),
            Err(CodecError::BodyTooLarge { got: max_body + 1 })
        );

        let mut refs2 = refs.clone();
        let extra = record(0x03, MAX_TX_BYTES);
        refs2.push(&extra);
        assert!(matches!(
            BlockBody::encode(&refs2),
            Err(CodecError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn unknown_tx_types_are_skippable_by_length() {
        let known = sample_tx().encode().to_vec();
        let unknown = record(0x7F, 33);
        let another = record(0xFF, 1);
        let raw = BlockBody::encode(&[&known, &unknown, &another]).unwrap();

        let body = BlockBody::parse(&raw).unwrap();
        assert_eq!(body.len(), 3);
        assert_eq!(body.tx_bytes(1).unwrap(), unknown.as_slice());
        assert_ne!(body.tx_root(), [0u8; 32]);
        assert_eq!(body.leaves().len(), 3);

        assert_eq!(
            body.decode_tx(0).unwrap().unwrap(),
            Tx::Transfer(sample_tx())
        );
        assert_eq!(
            body.decode_tx(1).unwrap(),
            Err(CodecError::ReservedTxType { got: 0x7F })
        );
        assert_eq!(
            body.decode_tx(2).unwrap(),
            Err(CodecError::ReservedTxType { got: 0xFF })
        );
        assert_eq!(
            body.decode_all(),
            Err(CodecError::ReservedTxType { got: 0x7F })
        );
    }

    #[test]
    fn body_rejects_a_padded_record() {
        let mut padded = sample_tx().encode().to_vec();
        padded.push(0x00);
        let raw = BlockBody::encode(&[&padded]).unwrap();
        let body = BlockBody::parse(&raw).unwrap();
        assert_eq!(body.len(), 1, "the envelope parses: length is explicit");
        assert_eq!(
            body.decode_all(),
            Err(CodecError::TrailingBytes { extra: 1 })
        );

        let canonical = sample_tx().encode().to_vec();
        assert_ne!(body.tx_root(), crate::merkle::tx_root(&[&canonical]));
    }

    #[test]
    fn author_note_rejects_malformed() {
        let too_long = AuthorNote {
            encoding: 0,
            payload: vec![0; 257],
        };
        assert_eq!(
            too_long.encode(),
            Err(CodecError::AuthorNoteTooLong { len: 257 })
        );
        let mut wire = vec![0x01, 0x00];
        wire.extend_from_slice(&257u16.to_le_bytes());
        wire.extend_from_slice(&[0; 257]);
        assert_eq!(
            AuthorNote::decode(&wire),
            Err(CodecError::AuthorNoteTooLong { len: 257 })
        );

        assert_eq!(
            AuthorNote::decode(&[0x02, 0x00, 0x00, 0x00]),
            Err(CodecError::AuthorNoteVersion { got: 0x02 })
        );

        assert_eq!(
            AuthorNote::decode(&[0x01, 0x00]),
            Err(CodecError::Truncated { need: 4, got: 2 })
        );
        let short = [0x01, 0x00, 0x05, 0x00, 0xAA, 0xBB];
        assert_eq!(
            AuthorNote::decode(&short),
            Err(CodecError::Truncated { need: 9, got: 6 })
        );

        let trailing = [0x01, 0x00, 0x01, 0x00, 0xAA, 0xBB];
        assert_eq!(
            AuthorNote::decode(&trailing),
            Err(CodecError::TrailingBytes { extra: 1 })
        );
    }
}
