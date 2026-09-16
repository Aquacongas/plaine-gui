use crate::constants::*;
use crate::gate::Rejection;
use crate::traits::{Hash32, HeaderRec};

pub trait BitsRule: Send + Sync + 'static {
    fn expected_bits(&self, parent: &HeaderRec) -> Option<u32>;

    fn expand(&self, bits: u32) -> Option<Hash32>;
}

#[derive(Clone, Copy, Debug)]
pub struct ContextParams {
    pub now_unix: u64,
    pub mtp: Option<u64>,
    pub fork_depth: u64,
    pub branch_contains_anchor: bool,
}

pub fn check_context<B: BitsRule + ?Sized>(
    rule: &B,
    parent: &HeaderRec,
    hdr: &mut HeaderRec,
    p: &ContextParams,
) -> Result<(), Rejection> {
    if hdr.prev_hash != parent.hash {
        return Err(Rejection::UnknownParent(hdr.prev_hash));
    }
    if hdr.height != parent.height + 1 {
        return Err(Rejection::NotContiguous);
    }

    if let Some(expected) = rule.expected_bits(parent) {
        if hdr.bits != expected {
            return Err(Rejection::BadBits {
                expected,
                got: hdr.bits,
            });
        }
    }
    let Some(target) = rule.expand(hdr.bits) else {
        return Err(Rejection::BadBits {
            expected: 0,
            got: hdr.bits,
        });
    };
    hdr.target = target;

    // time must be strictly past the median-time-past of the parent window.
    if let Some(mtp) = p.mtp {
        if hdr.time <= mtp {
            return Err(Rejection::TimePast);
        }
    }
    let limit = p.now_unix.saturating_add(MAX_FUTURE_DRIFT_SECS);
    if hdr.time > limit {
        return Err(Rejection::TimeFuture {
            by_secs: hdr.time as i64 - limit as i64,
        });
    }

    // A branch deeper than the reorg cap is refused unless it carries the signed
    // checkpoint anchor - the only thing allowed to rewrite that much history.
    if p.fork_depth > MAX_REORG_DEPTH && !p.branch_contains_anchor {
        return Err(Rejection::ReorgTooDeep {
            depth: p.fork_depth,
        });
    }
    Ok(())
}
