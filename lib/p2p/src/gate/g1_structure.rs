use crate::constants::*;
use crate::gate::Rejection;
use crate::traits::{Hash32, HeaderRec};
use plaine_consensus::codec::Header;
use plaine_consensus::crypto::header_hash;

pub fn check_structure(
    raw: &[[u8; HEADER_BYTES]],
    expect_first_parent: Option<Hash32>,
) -> Result<Vec<HeaderRec>, Rejection> {
    if raw.is_empty() {
        return Err(Rejection::BadShape("empty HEADERS batch"));
    }
    if raw.len() > MAX_HEADERS_PER_MSG {
        return Err(Rejection::BadShape("HEADERS count over cap"));
    }
    let mut out: Vec<HeaderRec> = Vec::with_capacity(raw.len());
    for (i, bytes) in raw.iter().enumerate() {
        let Ok(h) = Header::decode(bytes) else {
            return Err(Rejection::BadShape("header failed structural decode"));
        };
        if h.ext_root != [0u8; 32] {
            return Err(Rejection::BadShape("ext_root is reserved and must be zero"));
        }
        if h.author_note_len as usize > AUTHOR_NOTE_MAX {
            return Err(Rejection::BadShape("author_note_len out of range"));
        }
        let hash = header_hash(bytes);
        let rec = HeaderRec {
            height: h.height,
            hash,
            prev_hash: h.prev_hash,
            time: h.time,
            bits: h.bits,
            target: [0u8; 32],
            raw: *bytes,
        };
        if i > 0 {
            let prev = &out[i - 1];
            if rec.height != prev.height + 1 {
                return Err(Rejection::NotContiguous);
            }
            if rec.prev_hash != prev.hash {
                return Err(Rejection::NotContiguous);
            }
        }
        out.push(rec);
    }
    // a batch whose head does not attach to the locator we sent is an answer
    // we never asked for, not merely a non-contiguous one.
    if let Some(parent) = expect_first_parent {
        if out[0].prev_hash != parent {
            return Err(Rejection::UnsolicitedAnswer);
        }
    }
    Ok(out)
}

const AUTHOR_NOTE_MAX: usize = plaine_consensus::constants::AUTHOR_NOTE_MAX_BYTES;
