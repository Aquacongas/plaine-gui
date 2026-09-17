use plaine_consensus::asert::Target;
use plaine_consensus::rules::{ChainView, HeaderInfo, Work};

use crate::index::HeaderIndex;
use crate::types::Hash32;
use crate::work::{expand_bits, target_to_be};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub fork_height: u64,
    pub rollback: Vec<u64>,
    pub apply: Vec<u32>,
    pub depth: u64,
}

pub fn select_best(index: &HeaderIndex) -> u32 {
    select_best_excluding(index, &[])
}

pub fn select_best_excluding(index: &HeaderIndex, skip: &[u32]) -> u32 {
    debug_assert!(
        skip.windows(2).all(|w| w[0] < w[1]),
        "select_best_excluding: skip must be sorted ascending and unique"
    );
    let mut best = index.tip_index();
    for i in index.indices() {
        if skip.binary_search(&i).is_ok() {
            continue;
        }
        let n = index.node(i);
        if n.invalid() || !n.pow_ok() {
            continue;
        }
        let b = index.node(best);
        // Most work wins; ties break on the lower hash for determinism.
        if n.cum_work > b.cum_work || (n.cum_work == b.cum_work && n.hash < b.hash) {
            best = i;
        }
    }
    best
}

pub fn plan_reorg(index: &HeaderIndex, best: u32) -> Option<Plan> {
    if best == index.tip_index() {
        return None;
    }
    let mut branch: Vec<u32> = Vec::new();
    let mut cur = best;
    loop {
        if index.is_canonical(cur) {
            break;
        }
        branch.push(cur);
        let prev = index.node(cur).prev;
        if prev == crate::index::NO_PARENT {
            break;
        }
        cur = prev;
    }
    branch.reverse();
    let fork_height = index.node(cur).height;
    let tip_height = index.tip_height();
    let rollback: Vec<u64> = ((fork_height + 1)..=tip_height).rev().collect();
    let depth = tip_height.saturating_sub(fork_height);
    Some(Plan {
        fork_height,
        rollback,
        apply: branch,
        depth,
    })
}

pub struct ArenaView<'a> {
    index: &'a HeaderIndex,
    pow_limit: Target,
}

impl<'a> ArenaView<'a> {
    pub fn new(index: &'a HeaderIndex, pow_limit: Target) -> ArenaView<'a> {
        ArenaView { index, pow_limit }
    }

    fn target_of(&self, bits: u32) -> Hash32 {
        let t = expand_bits(bits, &self.pow_limit)
            .expect("every arena header had its bits checked against this pow_limit before insert");
        target_to_be(&t)
    }
}

impl ChainView for ArenaView<'_> {
    fn len(&self) -> u64 {
        self.index.tip_height() + 1
    }

    fn header_at(&self, height: u64) -> Option<HeaderInfo> {
        let n = self.index.canonical_at(height)?;
        Some(HeaderInfo {
            height: n.height,
            hash: n.hash,
            time: n.time,
            target: self.target_of(n.bits),
        })
    }

    fn header_by_hash(&self, hash: &Hash32) -> Option<HeaderInfo> {
        let idx = self.index.index_of(hash)?;
        let n = self.index.node(idx);
        if !self.index.is_canonical(idx) {
            return None;
        }
        Some(HeaderInfo {
            height: n.height,
            hash: n.hash,
            time: n.time,
            target: self.target_of(n.bits),
        })
    }

    fn cumulative_work(&self) -> Work {
        self.index.tip().cum_work
    }
}
