use plaine_consensus::asert::Target;
use plaine_consensus::codec::Header;
use plaine_consensus::constants::{
    AUTHOR_NOTE_MAX_BYTES, HEADER_BYTES, MAX_FUTURE_DRIFT_SECS, MEDIAN_TIME_SPAN, VERSION_BASE,
};
use plaine_consensus::rules::{self, Anchor};

use crate::error::Reject;
use crate::types::{ChainParams, Hash32, TipRef, Work};
use crate::work::expand_bits;

pub fn s1_fixed_fields(raw: &[u8], pow_limit: &Target) -> Result<Header, Reject> {
    if raw.len() != HEADER_BYTES {
        return Err(Reject::BadHeaderLength { got: raw.len() });
    }
    let h = Header::decode(raw).map_err(|_| Reject::BadHeaderLength { got: raw.len() })?;

    if h.ext_root != [0u8; 32] {
        return Err(Reject::ExtRootNotZero);
    }
    if h.author_note_len as usize > AUTHOR_NOTE_MAX_BYTES {
        return Err(Reject::AuthorNoteLen {
            got: h.author_note_len,
        });
    }

    if h.version & 0xE000_0000 != VERSION_BASE {
        return Err(Reject::BadVersion { got: h.version });
    }
    if expand_bits(h.bits, pow_limit).is_none() {
        return Err(Reject::BadBits { got: h.bits });
    }
    Ok(h)
}

pub fn s1b_checkpoint(
    checkpoints: &[(u64, Hash32)],
    height: u64,
    hash: &Hash32,
) -> Result<(), Reject> {
    rules::check_block_checkpoint(checkpoints, height, hash)
        .map_err(|_| Reject::CheckpointMismatch { height })
}

pub fn s2_height(child_height: u64, parent_height: u64) -> Result<(), Reject> {
    let expected = parent_height.saturating_add(1);
    if child_height != expected {
        return Err(Reject::HeightNotParentPlusOne {
            got: child_height,
            expected,
        });
    }
    Ok(())
}

pub fn s3_bits(got: u32, expected: u32) -> Result<(), Reject> {
    if got != expected {
        return Err(Reject::BitsNotAsert { got, expected });
    }
    Ok(())
}

pub fn s4_time(ancestor_times: &[u64], time: u64, now: u64) -> Result<(), Reject> {
    debug_assert!(ancestor_times.len() <= MEDIAN_TIME_SPAN);
    let mtp = rules::median_time_past(ancestor_times);
    rules::check_block_time(mtp, time, now).map_err(|e| match e {
        rules::RuleError::TimestampTooOld { mtp, time } => Reject::TimestampTooOld { mtp, time },
        _ => Reject::TimestampTooFarInFuture {
            time,
            limit: now.saturating_add(MAX_FUTURE_DRIFT_SECS),
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorReach {
    NotReached,
    Matches,
    Contradicts,
}

pub fn s5_fork_depth(
    tip: &TipRef,
    branch_base_height: u64,
    anchor: Option<&Anchor>,
    reach: AnchorReach,
    params: &ChainParams,
) -> Result<(), Reject> {
    let cap = params.max_reorg_depth;
    // Cap 0 disables the depth gate (regtest).
    if cap == 0 {
        return Ok(());
    }
    let depth = tip.height.saturating_sub(branch_base_height);
    if depth <= cap {
        return Ok(());
    }
    // Past the cap, only a signed anchor the branch doesn't contradict admits it.
    let exempt = anchor.is_some() && reach != AnchorReach::Contradicts;
    if exempt {
        return Ok(());
    }
    Err(Reject::ForkTooDeep { depth, cap })
}

pub fn s6_claimed_work(
    cand_work: &Work,
    cand_tip_hash: &Hash32,
    cand_tip_height: u64,
    depth: u64,
    tip: &TipRef,
) -> Result<(), Reject> {
    if *cand_work > tip.chainwork {
        return Ok(());
    }
    // Equal work wins only as a depth-1 same-height sibling with the lower hash.
    if *cand_work == tip.chainwork
        && depth == 1
        && cand_tip_height == tip.height
        && *cand_tip_hash < tip.hash
    {
        return Ok(());
    }
    Err(Reject::InsufficientClaimedWork)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChainParams;
    use plaine_consensus::rules::Work;

    fn base_header() -> Header {
        Header {
            version: VERSION_BASE,
            height: 1,
            prev_hash: [1u8; 32],
            tx_root: [2u8; 32],
            ext_root: [0u8; 32],
            time: 1_000_060,
            bits: ChainParams::default().genesis_bits,
            author_note_len: 0,
            nonce: 0,
        }
    }

    fn tip() -> TipRef {
        TipRef {
            height: 1_000,
            hash: [0x80; 32],
            time: 1_000_000,
            chainwork: Work::ONE,
        }
    }

    fn tip_at(height: u64) -> TipRef {
        TipRef { height, ..tip() }
    }

    #[test]
    fn s1_rejects_short_and_long_headers() {
        let p = ChainParams::default();
        assert!(matches!(
            s1_fixed_fields(&[0u8; 131], &p.pow_limit),
            Err(Reject::BadHeaderLength { got: 131 })
        ));
        assert!(matches!(
            s1_fixed_fields(&[0u8; 133], &p.pow_limit),
            Err(Reject::BadHeaderLength { got: 133 })
        ));
    }

    #[test]
    fn s1_rejects_nonzero_ext_root() {
        let p = ChainParams::default();
        let mut h = base_header();
        h.ext_root = [1u8; 32];
        assert_eq!(
            s1_fixed_fields(&h.encode(), &p.pow_limit),
            Err(Reject::ExtRootNotZero)
        );
    }

    #[test]
    fn s1_rejects_author_note_len_257() {
        let p = ChainParams::default();
        let mut h = base_header();
        h.author_note_len = 257;
        assert_eq!(
            s1_fixed_fields(&h.encode(), &p.pow_limit),
            Err(Reject::AuthorNoteLen { got: 257 })
        );
        h.author_note_len = 256;
        assert!(s1_fixed_fields(&h.encode(), &p.pow_limit).is_ok());
    }

    #[test]
    fn s1_rejects_wrong_version_top_bits() {
        let p = ChainParams::default();
        let mut h = base_header();
        h.version = 0x4000_0000;
        assert!(matches!(
            s1_fixed_fields(&h.encode(), &p.pow_limit),
            Err(Reject::BadVersion { .. })
        ));

        h.version = VERSION_BASE | 0x0000_0007;
        assert!(s1_fixed_fields(&h.encode(), &p.pow_limit).is_ok());
    }

    #[test]
    fn s1_rejects_bits_above_pow_limit_and_zero_bits() {
        let p = ChainParams::default();
        let mut h = base_header();
        h.bits = 0x2100_ffff;
        assert!(matches!(
            s1_fixed_fields(&h.encode(), &p.pow_limit),
            Err(Reject::BadBits { .. })
        ));
        h.bits = 0;
        assert!(matches!(
            s1_fixed_fields(&h.encode(), &p.pow_limit),
            Err(Reject::BadBits { .. })
        ));
    }

    #[test]
    fn s1b_rejects_wrong_hash_at_checkpointed_height() {
        let cps = [(5u64, [7u8; 32])];
        assert!(s1b_checkpoint(&cps, 5, &[7u8; 32]).is_ok());
        assert_eq!(
            s1b_checkpoint(&cps, 5, &[8u8; 32]),
            Err(Reject::CheckpointMismatch { height: 5 })
        );

        assert!(s1b_checkpoint(&cps, 6, &[8u8; 32]).is_ok());
    }

    #[test]
    fn s2_binds_height_to_the_parent() {
        assert!(s2_height(11, 10).is_ok());
        assert_eq!(
            s2_height(50, 10),
            Err(Reject::HeightNotParentPlusOne {
                got: 50,
                expected: 11
            })
        );
        assert_eq!(
            s2_height(10, 10),
            Err(Reject::HeightNotParentPlusOne {
                got: 10,
                expected: 11
            })
        );
    }

    #[test]
    fn s3_is_exact_equality() {
        assert!(s3_bits(0x1e00_ffff, 0x1e00_ffff).is_ok());
        assert_eq!(
            s3_bits(0x1e00_fffe, 0x1e00_ffff),
            Err(Reject::BitsNotAsert {
                got: 0x1e00_fffe,
                expected: 0x1e00_ffff
            })
        );
    }

    #[test]
    fn s4_enforces_mtp_and_drift() {
        let times: Vec<u64> = (0..11).map(|i| 1_000_000 + i * 60).collect();
        let mtp = 1_000_000 + 5 * 60;
        assert!(s4_time(&times, mtp + 1, 1_000_700).is_ok());
        assert_eq!(
            s4_time(&times, mtp, 1_000_700),
            Err(Reject::TimestampTooOld { mtp, time: mtp })
        );

        let now = 1_000_000u64;
        assert!(s4_time(&times, now + 600, now).is_ok());
        assert!(matches!(
            s4_time(&times, now + 601, now),
            Err(Reject::TimestampTooFarInFuture { .. })
        ));
    }

    #[test]
    fn s5_admits_at_cap_refuses_past() {
        let p = ChainParams::default();
        let cap = p.max_reorg_depth;

        let at_cap = tip_at(cap);
        assert!(s5_fork_depth(&at_cap, 0, None, AnchorReach::NotReached, &p).is_ok());

        let past_cap = tip_at(cap + 1);
        assert_eq!(
            s5_fork_depth(&past_cap, 0, None, AnchorReach::NotReached, &p),
            Err(Reject::ForkTooDeep {
                depth: cap + 1,
                cap
            })
        );
    }

    #[test]
    fn s5_does_not_self_disable_on_stale_tip() {
        let p = ChainParams::default();

        let t = tip_at(p.max_reorg_depth + 1);

        assert_eq!(
            s5_fork_depth(&t, 0, None, AnchorReach::NotReached, &p),
            Err(Reject::ForkTooDeep {
                depth: p.max_reorg_depth + 1,
                cap: p.max_reorg_depth
            }),
            "one block past the cap with no anchor must refuse"
        );

        assert_eq!(
            p.sync_window_secs,
            plaine_consensus::constants::SYNC_WINDOW_SECS
        );
    }

    #[test]
    fn s5_anchor_exemption_admits_partial() {
        let p = ChainParams::default();

        let depth = p.max_reorg_depth * 2;
        let t = tip_at(depth);
        let anchor = Anchor {
            height: depth / 2,
            hash: [9u8; 32],
        };

        assert!(s5_fork_depth(&t, 0, Some(&anchor), AnchorReach::NotReached, &p).is_ok());

        assert!(s5_fork_depth(&t, 0, Some(&anchor), AnchorReach::Matches, &p).is_ok());

        assert_eq!(
            s5_fork_depth(&t, 0, Some(&anchor), AnchorReach::Contradicts, &p),
            Err(Reject::ForkTooDeep {
                depth,
                cap: p.max_reorg_depth
            })
        );

        assert!(s5_fork_depth(&t, 0, None, AnchorReach::NotReached, &p).is_err());
    }

    #[test]
    fn s6_more_work_or_tie_break() {
        let t = tip();
        let above = t.height + 1;
        let more = t.chainwork.checked_add(&Work::ONE).unwrap();
        assert!(s6_claimed_work(&more, &[0xff; 32], above, 0, &t).is_ok());
        assert_eq!(
            s6_claimed_work(&Work::ZERO, &[0x00; 32], above, 1, &t),
            Err(Reject::InsufficientClaimedWork)
        );

        assert!(s6_claimed_work(&t.chainwork, &[0x7f; 32], t.height, 1, &t).is_ok());

        assert_eq!(
            s6_claimed_work(&t.chainwork, &[0x81; 32], t.height, 1, &t),
            Err(Reject::InsufficientClaimedWork)
        );

        assert_eq!(
            s6_claimed_work(&t.chainwork, &[0x7f; 32], t.height, 2, &t),
            Err(Reject::InsufficientClaimedWork)
        );
    }
}
