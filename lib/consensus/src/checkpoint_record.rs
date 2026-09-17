use crate::rules::{self, CheckpointSig, SignedCheckpoint};

#[allow(unused_imports)]
use rules::Anchor;

pub const VERSION: u8 = 1;

pub const SIGS_MAX: usize = 15;

pub const MAX_BYTES: usize = 1 + 8 + 32 + 1 + SIGS_MAX * 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    Version(u8),
    Truncated { got: usize, want: usize },
    TooManySignatures(usize),
    TrailingBytes(usize),
}

impl RecordError {
    pub fn shape(self) -> &'static str {
        match self {
            RecordError::Version(_) => "unknown record version",
            RecordError::Truncated { .. } => "truncated",
            RecordError::TooManySignatures(_) => "too many signatures",
            RecordError::TrailingBytes(_) => "trailing bytes after the last signature",
        }
    }
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Version(v) => {
                write!(f, "anchor record version {v}, this build writes {VERSION}")
            }
            RecordError::Truncated { got, want } => {
                write!(
                    f,
                    "anchor record truncated: {got} bytes present, {want} needed"
                )
            }
            RecordError::TooManySignatures(n) => {
                write!(
                    f,
                    "anchor record carries {n} signatures, the cap is {SIGS_MAX}"
                )
            }
            RecordError::TrailingBytes(n) => {
                write!(f, "anchor record has {n} bytes after the last signature")
            }
        }
    }
}

pub fn encode(cp: &SignedCheckpoint) -> Vec<u8> {
    let n = cp.sigs.len().min(SIGS_MAX);
    let mut out = Vec::with_capacity(1 + 8 + 32 + 1 + n * 96);
    out.push(VERSION);
    out.extend_from_slice(&cp.height.to_le_bytes());
    out.extend_from_slice(&cp.hash);
    out.push(n as u8);
    for s in cp.sigs.iter().take(n) {
        out.extend_from_slice(&s.pubkey);
        out.extend_from_slice(&s.sig);
    }
    out
}

pub fn decode(raw: &[u8]) -> Result<SignedCheckpoint, RecordError> {
    const HEAD: usize = 1 + 8 + 32 + 1;
    if raw.len() < HEAD {
        return Err(RecordError::Truncated {
            got: raw.len(),
            want: HEAD,
        });
    }
    if raw[0] != VERSION {
        return Err(RecordError::Version(raw[0]));
    }
    let mut h = [0u8; 8];
    h.copy_from_slice(&raw[1..9]);
    let height = u64::from_le_bytes(h);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&raw[9..41]);
    let n = raw[41] as usize;
    // bound the count before sizing anything from it
    if n > SIGS_MAX {
        return Err(RecordError::TooManySignatures(n));
    }
    let want = HEAD + n * 96;
    if raw.len() < want {
        return Err(RecordError::Truncated {
            got: raw.len(),
            want,
        });
    }
    if raw.len() > want {
        return Err(RecordError::TrailingBytes(raw.len() - want));
    }
    let mut sigs = Vec::with_capacity(n);
    for i in 0..n {
        let at = HEAD + i * 96;
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&raw[at..at + 32]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&raw[at + 32..at + 96]);
        sigs.push(CheckpointSig { pubkey, sig });
    }
    Ok(SignedCheckpoint { height, hash, sigs })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(n: usize) -> SignedCheckpoint {
        SignedCheckpoint {
            height: 0x0102_0304_0506_0708,
            hash: [7u8; 32],
            sigs: (0..n)
                .map(|i| CheckpointSig {
                    pubkey: [i as u8; 32],
                    sig: [(i as u8).wrapping_add(0x80); 64],
                })
                .collect(),
        }
    }

    #[test]
    fn record_round_trips_at_every_sig_count() {
        for n in 0..=SIGS_MAX {
            let a = cp(n);
            let raw = encode(&a);
            assert_eq!(raw.len(), 42 + n * 96, "length is a function of n alone");
            assert!(raw.len() <= MAX_BYTES);
            let b = decode(&raw).expect("decodes");
            assert_eq!(a, b, "n = {n}");
            assert_eq!(encode(&b), raw, "re-encoding is byte-identical");
        }
    }

    #[test]
    fn pubkey_stored_verbatim_not_indexed() {
        let mut a = cp(1);
        a.sigs[0].pubkey = [0xAB; 32];
        let raw = encode(&a);
        assert_eq!(&raw[42..74], &[0xAB; 32], "the key is stored verbatim");
        assert_eq!(decode(&raw).unwrap().sigs[0].pubkey, [0xAB; 32]);
    }

    #[test]
    fn malformed_records_are_named() {
        let raw = encode(&cp(2));

        assert_eq!(
            decode(&[]),
            Err(RecordError::Truncated { got: 0, want: 42 })
        );
        assert_eq!(
            decode(&raw[..41]),
            Err(RecordError::Truncated { got: 41, want: 42 })
        );

        let mut wrong_version = raw.clone();
        wrong_version[0] = 2;
        assert_eq!(decode(&wrong_version), Err(RecordError::Version(2)));

        let mut lying = raw.clone();
        lying[41] = 3;
        assert_eq!(
            decode(&lying),
            Err(RecordError::Truncated {
                got: raw.len(),
                want: 42 + 3 * 96
            })
        );

        let mut too_many = raw.clone();
        too_many[41] = (SIGS_MAX + 1) as u8;
        assert_eq!(
            decode(&too_many),
            Err(RecordError::TooManySignatures(SIGS_MAX + 1))
        );

        let mut tail = raw.clone();
        tail.push(0);
        assert_eq!(decode(&tail), Err(RecordError::TrailingBytes(1)));
    }

    #[test]
    fn sig_count_bounded_before_alloc() {
        let mut raw = vec![VERSION];
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.extend_from_slice(&[1u8; 32]);
        raw.push(255);
        assert_eq!(decode(&raw), Err(RecordError::TooManySignatures(255)));
        assert_eq!(raw.len(), 42, "nothing read past the count byte");
    }
}
