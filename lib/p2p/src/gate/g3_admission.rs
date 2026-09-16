use crate::gate::Rejection;
use crate::traits::{Hash32, Work};
use plaine_consensus::rules::tie_break_prefers_candidate;
use plaine_consensus::rules::HeaderInfo;

pub fn admit(
    cand_work: &Work,
    our_work: &Work,
    cand_tip: &Hash32,
    cand_height: u64,
    our_tip: &Hash32,
    our_height: u64,
    depth: u64,
) -> Result<(), Rejection> {
    if cand_work > our_work {
        return Ok(());
    }
    if cand_work < our_work {
        return Err(Rejection::LessWork);
    }

    let cand = HeaderInfo {
        height: cand_height,
        hash: *cand_tip,
        time: 0,
        target: [0u8; 32],
    };
    let ours = HeaderInfo {
        height: our_height,
        hash: *our_tip,
        time: 0,
        target: [0u8; 32],
    };
    if tie_break_prefers_candidate(depth, cand_work, our_work, &cand, &ours) {
        Ok(())
    } else {
        Err(Rejection::TieBreakLost)
    }
}
