use crate::constants::{
    CHECKPOINT_MSG_PREFIX, CHECKPOINT_SUNSET_HEIGHT, COINBASE_MATURITY, MAX_FUTURE_DRIFT_SECS,
    MAX_REORG_DEPTH, MEDIAN_TIME_SPAN,
};

pub type Hash32 = [u8; 32];

const ZERO_HASH: Hash32 = [0u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderInfo {
    pub height: u64,
    pub hash: Hash32,
    pub time: u64,
    pub target: Hash32,
}

pub trait ChainView {
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn header_at(&self, height: u64) -> Option<HeaderInfo>;

    fn header_by_hash(&self, hash: &Hash32) -> Option<HeaderInfo>;

    fn cumulative_work(&self) -> Work;

    fn tip(&self) -> HeaderInfo {
        self.header_at(self.len() - 1)
            .expect("ChainView contract: header_at(len-1) must exist")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Work(pub [u64; 8]);

impl Work {
    pub const ZERO: Work = Work([0; 8]);

    pub const ONE: Work = Work([1, 0, 0, 0, 0, 0, 0, 0]);

    fn two_pow_256() -> Work {
        let mut w = Work::ZERO;
        w.0[4] = 1;
        w
    }

    pub fn from_be256(bytes: &Hash32) -> Work {
        let mut w = Work::ZERO;
        for limb in 0..4 {
            let mut v = 0u64;
            for byte in 0..8 {
                v = (v << 8) | u64::from(bytes[limb * 8 + byte]);
            }

            w.0[3 - limb] = v;
        }
        w
    }

    pub fn checked_add(&self, rhs: &Work) -> Option<Work> {
        let mut out = Work::ZERO;
        let mut carry = 0u64;
        for i in 0..8 {
            let (s1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            out.0[i] = s2;
            carry = u64::from(c1) + u64::from(c2);
        }
        if carry != 0 {
            None
        } else {
            Some(out)
        }
    }

    pub fn checked_sub(&self, rhs: &Work) -> Option<Work> {
        let mut out = Work::ZERO;
        let mut borrow = 0u64;
        for i in 0..8 {
            let (d1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out.0[i] = d2;
            borrow = u64::from(b1) + u64::from(b2);
        }
        if borrow != 0 {
            None
        } else {
            Some(out)
        }
    }

    fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, i: usize) {
        self.0[i / 64] |= 1u64 << (i % 64);
    }

    fn shl1_or(&mut self, low: bool) {
        let mut carry = u64::from(low);
        for limb in self.0.iter_mut() {
            let next_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
        debug_assert_eq!(carry, 0, "shl1 overflow inside division");
    }

    fn div_floor(&self, den: &Work) -> Work {
        assert!(*den != Work::ZERO, "division by zero in work arithmetic");
        let mut quot = Work::ZERO;
        let mut rem = Work::ZERO;

        for i in (0..512).rev() {
            rem.shl1_or(self.bit(i));
            if rem >= *den {
                rem = rem
                    .checked_sub(den)
                    .expect("rem >= den, subtraction cannot underflow");
                quot.set_bit(i);
            }
        }
        quot
    }
}

impl Ord for Work {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..8).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        core::cmp::Ordering::Equal
    }
}

impl PartialOrd for Work {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Block work = 2^256 / (target + 1): the expected hashes to beat it. Chains
// compare by summed work, not by block count.
pub fn work_from_target(target_be: &Hash32) -> Work {
    let denom = Work::from_be256(target_be)
        .checked_add(&Work::ONE)
        .expect("target + 1 cannot overflow 512 bits");
    Work::two_pow_256().div_floor(&denom)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleError {
    EmptyCandidate,
    BadForkPoint,
    NonContiguousCandidate,
    ReorgTooDeep { depth: u64, cap: u64 },
    CheckpointShorteningAttack { height: u64 },
    CheckpointMismatch { height: u64 },
    InsufficientWork { depth: u64 },
    TimestampTooOld { mtp: u64, time: u64 },
    TimestampTooFarInFuture { time: u64, limit: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReorgVerdict {
    StrictlyMoreWork,
    TieBreak,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub height: u64,
    pub hash: Hash32,
}

pub fn candidate_meets_anchor(
    anchor: &Anchor,
    start_height: u64,
    candidate: &[HeaderInfo],
) -> bool {
    if anchor.height == 0 || anchor.hash == ZERO_HASH {
        return false;
    }
    if anchor.height < start_height {
        return false;
    }
    let idx = anchor.height - start_height;
    if idx >= candidate.len() as u64 {
        return false;
    }
    candidate[idx as usize].hash == anchor.hash
}

pub fn anchor_supersedes(current: Option<&Anchor>, candidate: &Anchor) -> bool {
    if candidate.height == 0 || candidate.hash == ZERO_HASH {
        return false;
    }
    match current {
        None => true,
        Some(cur) => candidate.height > cur.height,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointSig {
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub height: u64,
    pub hash: Hash32,
    pub sigs: Vec<CheckpointSig>,
}

pub fn checkpoint_message(height: u64, hash: &Hash32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CHECKPOINT_MSG_PREFIX.len() + 20 + 1 + 64);
    msg.extend_from_slice(CHECKPOINT_MSG_PREFIX);
    msg.extend_from_slice(height.to_string().as_bytes());
    msg.push(b'|');

    msg.extend_from_slice(crate::hex::encode(hash).as_bytes());
    msg
}

pub fn verify_checkpoint(
    cp: &SignedCheckpoint,
    authority_keys: &[[u8; 32]],
    threshold: usize,
) -> bool {
    if authority_keys.is_empty() || threshold == 0 || threshold > authority_keys.len() {
        return false;
    }

    if cp.sigs.len() > authority_keys.len() {
        return false;
    }
    if cp.hash == ZERO_HASH {
        return false;
    }
    if cp.height >= CHECKPOINT_SUNSET_HEIGHT {
        return false;
    }
    let msg = checkpoint_message(cp.height, &cp.hash);

    let mut key_tried = vec![false; authority_keys.len()];
    let mut valid = 0usize;
    for s in &cp.sigs {
        let Some(key_idx) = authority_keys.iter().position(|k| *k == s.pubkey) else {
            continue;
        };
        // one vote per authority key, even if the same key signs twice
        if key_tried[key_idx] {
            continue;
        }
        key_tried[key_idx] = true;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&s.pubkey) else {
            continue;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&s.sig);
        if vk.verify_strict(&msg, &sig).is_ok() {
            valid += 1;
            if valid >= threshold {
                return true;
            }
        }
    }
    false
}

pub fn check_block_checkpoint(
    checkpoints: &[(u64, Hash32)],
    height: u64,
    hash: &Hash32,
) -> Result<(), RuleError> {
    for (h, cp_hash) in checkpoints {
        if *h == height && cp_hash != hash {
            return Err(RuleError::CheckpointMismatch { height });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAdmission {
    Admit,
    GenesisImmutable,
    NotHeldYet,
    HashConflict,
}

pub fn checkpoint_admission<C: ChainView>(
    view: &C,
    height: u64,
    hash: &Hash32,
) -> CheckpointAdmission {
    if height == 0 {
        return CheckpointAdmission::GenesisImmutable;
    }
    if height >= view.len() {
        return CheckpointAdmission::NotHeldYet;
    }
    let held = view
        .header_at(height)
        .expect("ChainView contract: height < len");
    if held.hash == *hash {
        CheckpointAdmission::Admit
    } else {
        CheckpointAdmission::HashConflict
    }
}

// Equal work and height: the lower tip hash wins. Deterministic, so every node
// lands on the same tip rather than whichever it happened to see first.
pub fn tie_break_prefers_candidate(
    depth: u64,
    cand_work: &Work,
    our_work: &Work,
    cand_tip: &HeaderInfo,
    our_tip: &HeaderInfo,
) -> bool {
    depth == 1
        && cand_work == our_work
        && cand_tip.height == our_tip.height
        && cand_tip.hash < our_tip.hash
}

#[derive(Clone, Copy, Debug)]
pub struct ReorgParams<'a> {
    pub anchor: Option<&'a Anchor>,
    pub checkpoints: &'a [(u64, Hash32)],
    pub local_time: u64,
}

pub fn evaluate_reorg<C: ChainView>(
    view: &C,
    start_height: u64,
    candidate: &[HeaderInfo],
    params: &ReorgParams<'_>,
) -> Result<ReorgVerdict, RuleError> {
    evaluate_reorg_with_cap(view, start_height, candidate, params, MAX_REORG_DEPTH)
}

pub fn evaluate_reorg_with_cap<C: ChainView>(
    view: &C,
    start_height: u64,
    candidate: &[HeaderInfo],
    params: &ReorgParams<'_>,
    cap: u64,
) -> Result<ReorgVerdict, RuleError> {
    if candidate.is_empty() {
        return Err(RuleError::EmptyCandidate);
    }

    let chain_len = view.len();
    if start_height == 0 || start_height > chain_len {
        return Err(RuleError::BadForkPoint);
    }

    for (i, h) in candidate.iter().enumerate() {
        if h.height != start_height + i as u64 {
            return Err(RuleError::NonContiguousCandidate);
        }
    }

    let depth = chain_len - start_height;
    let our_tip = view.tip();

    // Past the cap a reorg is refused unless the candidate carries the last
    // signed anchor. The one escape hatch, and it never keys on the local clock
    // (see MAX_REORG_DEPTH).
    if cap > 0 && depth > cap {
        let anchored = params
            .anchor
            .is_some_and(|a| candidate_meets_anchor(a, start_height, candidate));
        if !anchored {
            return Err(RuleError::ReorgTooDeep { depth, cap });
        }
    }

    // Reject only a candidate that would drop a height we already checkpointed.
    // The blunt "reject any reorg past a checkpoint" wedges a node that lost its
    // blocks but kept its checkpoints.
    let our_tip_h = chain_len - 1;
    let new_tip_h = start_height + candidate.len() as u64 - 1;
    for &(h, _) in params.checkpoints {
        if h >= start_height && h <= our_tip_h && h > new_tip_h {
            return Err(RuleError::CheckpointShorteningAttack { height: h });
        }
    }

    for &(h, cp_hash) in params.checkpoints {
        if h >= start_height && h <= new_tip_h {
            let idx = (h - start_height) as usize;
            if candidate[idx].hash != cp_hash {
                return Err(RuleError::CheckpointMismatch { height: h });
            }
        }
    }

    let cum_work = view.cumulative_work();
    let mut discarded = Work::ZERO;
    for h in start_height..chain_len {
        let hd = view.header_at(h).expect("ChainView contract: height < len");
        discarded = discarded
            .checked_add(&work_from_target(&hd.target))
            .expect("work sum cannot overflow 512 bits");
    }
    let mut added = Work::ZERO;
    for hd in candidate {
        added = added
            .checked_add(&work_from_target(&hd.target))
            .expect("work sum cannot overflow 512 bits");
    }
    let cand_work = cum_work
        .checked_sub(&discarded)
        .expect("ChainView contract: cumulative work covers all blocks")
        .checked_add(&added)
        .expect("work sum cannot overflow 512 bits");

    if cand_work > cum_work {
        return Ok(ReorgVerdict::StrictlyMoreWork);
    }

    let cand_tip = candidate.last().expect("candidate verified non-empty");
    if tie_break_prefers_candidate(depth, &cand_work, &cum_work, cand_tip, &our_tip) {
        return Ok(ReorgVerdict::TieBreak);
    }
    Err(RuleError::InsufficientWork { depth })
}

pub fn median_time_past(times: &[u64]) -> u64 {
    assert!(
        !times.is_empty(),
        "median_time_past over empty ancestor set (genesis always exists)"
    );
    let window = &times[times.len().saturating_sub(MEDIAN_TIME_SPAN)..];
    let mut sorted = window.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

pub fn check_block_time(mtp: u64, time: u64, local_time: u64) -> Result<(), RuleError> {
    // Strictly above the MTP: the only floor on the timestamp.
    if time <= mtp {
        return Err(RuleError::TimestampTooOld { mtp, time });
    }
    let limit = local_time.saturating_add(MAX_FUTURE_DRIFT_SECS);
    if time > limit {
        return Err(RuleError::TimestampTooFarInFuture { time, limit });
    }
    Ok(())
}

pub fn coinbase_is_mature(coinbase_height: u64, spend_height: u64) -> bool {
    spend_height >= coinbase_height && spend_height - coinbase_height >= COINBASE_MATURITY
}

pub fn spendable_balance(balance: u128, immature: u128) -> u128 {
    balance.saturating_sub(immature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fake_hash(seed: u64, height: u64) -> Hash32 {
        let mut input = [0u8; 16];
        input[..8].copy_from_slice(&seed.to_le_bytes());
        input[8..].copy_from_slice(&height.to_le_bytes());
        crate::blake3::hash(&input)
    }

    fn pow2m1_target(m: usize) -> Hash32 {
        assert!((1..=256).contains(&m));
        let mut t = [0u8; 32];
        let full_bytes = m / 8;
        for i in 0..full_bytes {
            t[31 - i] = 0xff;
        }
        if m % 8 != 0 {
            t[31 - full_bytes] = (1u8 << (m % 8)) - 1;
        }
        t
    }

    const STD_M: usize = 255;

    const HEAVY_M: usize = 254;

    fn work_of_m(m: usize) -> Work {
        work_from_target(&pow2m1_target(m))
    }

    fn hdr(height: u64, seed: u64, m: usize) -> HeaderInfo {
        HeaderInfo {
            height,
            hash: fake_hash(seed, height),
            time: 1_000_000 + height * 60,
            target: pow2m1_target(m),
        }
    }

    struct MockChain {
        headers: Vec<HeaderInfo>,
    }

    impl MockChain {
        fn linear(n: u64, seed: u64) -> Self {
            MockChain {
                headers: (0..n).map(|h| hdr(h, seed, STD_M)).collect(),
            }
        }
    }

    impl ChainView for MockChain {
        fn len(&self) -> u64 {
            self.headers.len() as u64
        }
        fn header_at(&self, height: u64) -> Option<HeaderInfo> {
            self.headers.get(height as usize).copied()
        }
        fn header_by_hash(&self, hash: &Hash32) -> Option<HeaderInfo> {
            self.headers.iter().find(|h| h.hash == *hash).copied()
        }
        fn cumulative_work(&self) -> Work {
            let mut w = Work::ZERO;
            for h in &self.headers {
                w = w.checked_add(&work_from_target(&h.target)).unwrap();
            }
            w
        }
    }

    fn synced_params(view: &MockChain) -> ReorgParams<'static> {
        ReorgParams {
            anchor: None,
            checkpoints: &[],
            local_time: view.tip().time,
        }
    }

    fn branch(start: u64, n: u64, seed: u64, m: usize) -> Vec<HeaderInfo> {
        (0..n).map(|i| hdr(start + i, seed, m)).collect()
    }

    #[test]
    fn work_of_port_map_vectors() {
        assert_eq!(work_from_target(&[0u8; 32]), Work::two_pow_256());

        let mut two = Work::ZERO;
        two.0[0] = 2;
        assert_eq!(work_from_target(&pow2m1_target(255)), two);

        let mut t = [0u8; 32];
        t[0] = 0x80;
        assert_eq!(work_from_target(&t), Work::ONE);

        assert_eq!(work_from_target(&[0xffu8; 32]), Work::ONE);

        let mut one_t = [0u8; 32];
        one_t[31] = 1;
        let mut exp = Work::ZERO;
        exp.0[3] = 1u64 << 63;
        assert_eq!(work_from_target(&one_t), exp);
    }

    #[test]
    fn work_ordering_is_numeric() {
        assert!(work_of_m(HEAVY_M) > work_of_m(STD_M));
        assert!(Work::two_pow_256() > work_of_m(1));
        assert!(Work::ZERO < Work::ONE);
    }

    #[test]
    fn reject_empty_candidate() {
        let chain = MockChain::linear(5, 1);
        let p = synced_params(&chain);
        assert_eq!(
            evaluate_reorg(&chain, 1, &[], &p),
            Err(RuleError::EmptyCandidate)
        );
    }

    #[test]
    fn reject_fork_point_at_genesis_and_beyond_tip() {
        let chain = MockChain::linear(5, 1);
        let p = synced_params(&chain);

        let cand0 = branch(0, 2, 99, STD_M);
        assert_eq!(
            evaluate_reorg(&chain, 0, &cand0, &p),
            Err(RuleError::BadForkPoint)
        );

        let cand6 = branch(6, 2, 99, STD_M);
        assert_eq!(
            evaluate_reorg(&chain, 6, &cand6, &p),
            Err(RuleError::BadForkPoint)
        );
    }

    #[test]
    fn reject_non_contiguous_candidate() {
        let chain = MockChain::linear(5, 1);
        let p = synced_params(&chain);
        let mut cand = branch(3, 2, 99, STD_M);
        cand[1].height = 7;
        assert_eq!(
            evaluate_reorg(&chain, 3, &cand, &p),
            Err(RuleError::NonContiguousCandidate)
        );
    }

    #[test]
    fn depth_is_len_minus_start() {
        let chain = MockChain::linear(105, 1);
        let p = synced_params(&chain);
        let cand = branch(103, 3, 99, HEAVY_M);
        assert_eq!(
            evaluate_reorg_with_cap(&chain, 103, &cand, &p, 1),
            Err(RuleError::ReorgTooDeep { depth: 2, cap: 1 })
        );
    }

    #[test]
    fn pure_extension_passes() {
        let chain = MockChain::linear(5, 1);
        let p = synced_params(&chain);
        let cand = branch(5, 1, 99, STD_M);
        assert_eq!(
            evaluate_reorg(&chain, 5, &cand, &p),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );

        let junk = vec![HeaderInfo {
            height: 5,
            hash: fake_hash(98, 5),
            time: chain.tip().time + 60,
            target: [0xff; 32],
        }];
        assert_eq!(
            evaluate_reorg(&chain, 5, &junk, &p),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );
    }

    #[test]
    fn depth_cap_at_production_constant() {
        let cap = MAX_REORG_DEPTH;
        let tip = cap + 50;
        let chain = MockChain::linear(tip, 1);
        let p = synced_params(&chain);

        let too_deep_fork = tip - cap - 1;
        let deep = branch(too_deep_fork, tip + 60, tip - 51, HEAVY_M);
        assert_eq!(
            evaluate_reorg(&chain, too_deep_fork, &deep, &p),
            Err(RuleError::ReorgTooDeep {
                depth: cap + 1,
                cap: MAX_REORG_DEPTH
            })
        );

        let at_cap = branch(tip - cap, tip + 60, tip - 51, HEAVY_M);
        assert_eq!(
            evaluate_reorg(&chain, 50, &at_cap, &p),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );
    }

    #[test]
    fn depth_cap_never_lifts_on_stale_tip() {
        let cap = MAX_REORG_DEPTH;
        let len = cap * 2 + 50;
        let fork = len - cap - 1;
        let chain = MockChain::linear(len, 1);
        let deep = branch(fork, cap + 10, 99, HEAVY_M);
        let tip_time = chain.tip().time;

        let synced = ReorgParams {
            anchor: None,
            checkpoints: &[],
            local_time: tip_time,
        };
        assert!(matches!(
            evaluate_reorg(&chain, fork, &deep, &synced),
            Err(RuleError::ReorgTooDeep { .. })
        ));

        for lag in [60u64, 3_600, 86_400, 31_536_000] {
            let behind = ReorgParams {
                anchor: None,
                checkpoints: &[],
                local_time: tip_time + lag,
            };
            assert!(
                matches!(
                    evaluate_reorg(&chain, fork, &deep, &behind),
                    Err(RuleError::ReorgTooDeep { .. })
                ),
                "depth-{} reorg admitted with the tip looking {lag} s stale; the \
                 cap must not depend on the local clock",
                cap + 1
            );
        }

        let anchored_at = *deep.last().expect("non-empty branch");
        let anchor = Anchor {
            height: anchored_at.height,
            hash: anchored_at.hash,
        };
        let with_anchor = ReorgParams {
            anchor: Some(&anchor),
            checkpoints: &[],
            local_time: tip_time + 86_400,
        };
        assert_eq!(
            evaluate_reorg(&chain, fork, &deep, &with_anchor),
            Ok(ReorgVerdict::StrictlyMoreWork),
            "a deep candidate carrying the signed anchor must still be admitted"
        );
    }

    #[test]
    fn timestamp_acceptance_monotone_in_clock() {
        let mtp = 1_700_000_000u64;

        let time = mtp + 1;

        assert_eq!(check_block_time(mtp, time, time), Ok(()));

        for ahead in [1u64, 60, 600, 3_600, 86_400, 604_800, 31_536_000] {
            assert_eq!(
                check_block_time(mtp, time, time + ahead),
                Ok(()),
                "a header legal at its own timestamp became illegal {ahead} s later"
            );
        }

        let future = mtp + MAX_FUTURE_DRIFT_SECS + 10;
        assert!(check_block_time(mtp, future, mtp).is_err());
        assert_eq!(check_block_time(mtp, future, mtp + 10), Ok(()));
    }

    #[test]
    fn deep_recovery_anchor_vectors() {
        let base = 10u64;
        let chain = MockChain::linear(base + 3, 1);
        let start = base + 1;
        let cand = branch(start, 4, 99, HEAVY_M);
        let cand_tip = *cand.last().unwrap();
        let now = chain.tip().time;

        let p_none = ReorgParams {
            anchor: None,
            checkpoints: &[],
            local_time: now,
        };
        assert_eq!(
            evaluate_reorg_with_cap(&chain, start, &cand, &p_none, 1),
            Err(RuleError::ReorgTooDeep { depth: 2, cap: 1 })
        );

        let zero_anchor = Anchor {
            height: cand_tip.height,
            hash: ZERO_HASH,
        };
        let p_zero = ReorgParams {
            anchor: Some(&zero_anchor),
            checkpoints: &[],
            local_time: now,
        };
        assert_eq!(
            evaluate_reorg_with_cap(&chain, start, &cand, &p_zero, 1),
            Err(RuleError::ReorgTooDeep { depth: 2, cap: 1 })
        );

        let good_anchor = Anchor {
            height: cand_tip.height,
            hash: cand_tip.hash,
        };
        let p_good = ReorgParams {
            anchor: Some(&good_anchor),
            checkpoints: &[],
            local_time: now,
        };
        assert_eq!(
            evaluate_reorg_with_cap(&chain, start, &cand, &p_good, 1),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );

        let high_anchor = Anchor {
            height: cand_tip.height + 50,
            hash: fake_hash(7, 7),
        };
        let p_high = ReorgParams {
            anchor: Some(&high_anchor),
            checkpoints: &[],
            local_time: now,
        };
        assert_eq!(
            evaluate_reorg_with_cap(&chain, start, &cand, &p_high, 1),
            Err(RuleError::ReorgTooDeep { depth: 2, cap: 1 })
        );
    }

    #[test]
    fn candidate_meets_anchor_pure_vectors() {
        let cand = branch(1, 5, 42, STD_M);
        let t = cand[3];
        assert_eq!(t.height, 4);

        let ok = Anchor {
            height: t.height,
            hash: t.hash,
        };
        assert!(candidate_meets_anchor(&ok, 1, &cand));

        let wrong_hash = Anchor {
            height: t.height,
            hash: fake_hash(1234, 1),
        };
        assert!(!candidate_meets_anchor(&wrong_hash, 1, &cand));

        let zero_height = Anchor {
            height: 0,
            hash: t.hash,
        };
        assert!(!candidate_meets_anchor(&zero_height, 1, &cand));

        let below_range = Anchor {
            height: 0,
            hash: t.hash,
        };
        assert!(!candidate_meets_anchor(&below_range, 1, &cand));

        let beyond_range = Anchor {
            height: t.height + 100,
            hash: t.hash,
        };
        assert!(!candidate_meets_anchor(&beyond_range, 1, &cand));

        let empty_hash = Anchor {
            height: t.height,
            hash: ZERO_HASH,
        };
        assert!(!candidate_meets_anchor(&empty_hash, 1, &cand));
    }

    #[test]
    fn anchor_replacement_monotonic() {
        let h1 = fake_hash(1, 10);
        let h2 = fake_hash(2, 10);
        let h3 = fake_hash(3, 11);
        let a10 = Anchor {
            height: 10,
            hash: h1,
        };
        assert!(anchor_supersedes(None, &a10));
        let a10b = Anchor {
            height: 10,
            hash: h2,
        };
        assert!(!anchor_supersedes(Some(&a10), &a10b));
        let a11 = Anchor {
            height: 11,
            hash: h3,
        };
        assert!(anchor_supersedes(Some(&a10), &a11));
        let a9 = Anchor {
            height: 9,
            hash: h3,
        };
        assert!(!anchor_supersedes(Some(&a10), &a9));

        assert!(!anchor_supersedes(
            None,
            &Anchor {
                height: 0,
                hash: h1
            }
        ));
        assert!(!anchor_supersedes(
            None,
            &Anchor {
                height: 12,
                hash: ZERO_HASH
            }
        ));
    }

    fn coarse_prefix_predicate_rejects(checkpoints: &[(u64, Hash32)], start_height: u64) -> bool {
        checkpoints.iter().any(|&(h, _)| h >= start_height)
    }

    #[test]
    fn shortening_guard_wedge_regression() {
        let reference = branch(1, 4, 7, STD_M);
        let cp_block = reference[1];
        let checkpoints = [(2u64, cp_block.hash)];

        let fresh = MockChain::linear(1, 7);
        let p = ReorgParams {
            anchor: None,
            checkpoints: &checkpoints,
            local_time: fresh.tip().time,
        };

        assert_eq!(
            evaluate_reorg(&fresh, 1, &reference, &p),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );

        assert!(coarse_prefix_predicate_rejects(&checkpoints, 1));
    }

    #[test]
    fn shortening_guard_wrong_checkpoint_rejects_sync() {
        let reference = branch(1, 4, 7, STD_M);
        let checkpoints = [(2u64, ZERO_HASH)];
        let fresh = MockChain::linear(1, 7);
        let p = ReorgParams {
            anchor: None,
            checkpoints: &checkpoints,
            local_time: fresh.tip().time,
        };
        assert_eq!(
            evaluate_reorg(&fresh, 1, &reference, &p),
            Err(RuleError::CheckpointMismatch { height: 2 })
        );
    }

    #[test]
    fn shortening_guard_rejects_before_work() {
        let chain = MockChain::linear(11, 1);
        let cp5 = chain.header_at(5).unwrap().hash;
        let checkpoints = [(5u64, cp5)];
        let p = ReorgParams {
            anchor: None,
            checkpoints: &checkpoints,
            local_time: chain.tip().time,
        };
        let short_cand = branch(3, 2, 99, HEAVY_M);
        assert_eq!(
            evaluate_reorg(&chain, 3, &short_cand, &p),
            Err(RuleError::CheckpointShorteningAttack { height: 5 })
        );
    }

    #[test]
    fn shortening_guard_passes_at_checkpoint() {
        let chain = MockChain::linear(11, 1);
        let cp5 = chain.header_at(5).unwrap().hash;
        let checkpoints = [(5u64, cp5)];
        let p = ReorgParams {
            anchor: None,
            checkpoints: &checkpoints,
            local_time: chain.tip().time,
        };

        let mut good = branch(3, 5, 99, HEAVY_M);
        good[2].hash = cp5;
        assert_eq!(
            evaluate_reorg(&chain, 3, &good, &p),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );

        let bad = branch(3, 5, 98, HEAVY_M);
        assert_eq!(
            evaluate_reorg(&chain, 3, &bad, &p),
            Err(RuleError::CheckpointMismatch { height: 5 })
        );
    }

    #[test]
    fn block_level_checkpoint_match() {
        let chain = MockChain::linear(11, 1);
        let cp5 = chain.header_at(5).unwrap().hash;
        let checkpoints = [(5u64, cp5)];

        assert_eq!(check_block_checkpoint(&checkpoints, 5, &cp5), Ok(()));

        let wrong = fake_hash(1234, 5);
        assert_eq!(
            check_block_checkpoint(&checkpoints, 5, &wrong),
            Err(RuleError::CheckpointMismatch { height: 5 })
        );

        assert_eq!(check_block_checkpoint(&checkpoints, 6, &wrong), Ok(()));
    }

    #[test]
    fn checkpoint_message_exact_bytes() {
        let hash = [0xabu8; 32];
        let msg = checkpoint_message(2, &hash);
        let expected = format!("plaine-checkpoint-v1|2|{}", "ab".repeat(32));
        assert_eq!(msg, expected.as_bytes());
    }

    fn test_signer(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sign_checkpoint(sk: &SigningKey, height: u64, hash: &Hash32) -> CheckpointSig {
        let msg = checkpoint_message(height, hash);
        CheckpointSig {
            pubkey: sk.verifying_key().to_bytes(),
            sig: sk.sign(&msg).to_bytes(),
        }
    }

    #[test]
    fn checkpoint_verify_threshold_and_false_cases() {
        let (sk1, pk1) = test_signer(1);
        let (sk2, pk2) = test_signer(2);
        let (sk3, pk3) = test_signer(3);
        let (sk_rogue, _) = test_signer(9);
        let keys = [pk1, pk2, pk3];
        let hash = fake_hash(5, 100);

        let cp = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![sign_checkpoint(&sk1, 100, &hash)],
        };
        assert!(verify_checkpoint(&cp, &keys, 1));

        let cp2 = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![
                sign_checkpoint(&sk1, 100, &hash),
                sign_checkpoint(&sk3, 100, &hash),
            ],
        };
        assert!(verify_checkpoint(&cp2, &keys, 2));

        assert!(!verify_checkpoint(&cp, &keys, 2));

        let dup = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![
                sign_checkpoint(&sk1, 100, &hash),
                sign_checkpoint(&sk1, 100, &hash),
            ],
        };
        assert!(!verify_checkpoint(&dup, &keys, 2));

        assert!(!verify_checkpoint(&cp, &[], 1));

        assert!(!verify_checkpoint(&cp, &keys, 0));

        assert!(!verify_checkpoint(&cp2, &keys, 4));

        let zcp = SignedCheckpoint {
            height: 100,
            hash: ZERO_HASH,
            sigs: vec![sign_checkpoint(&sk1, 100, &ZERO_HASH)],
        };
        assert!(!verify_checkpoint(&zcp, &keys, 1));

        let rogue = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![sign_checkpoint(&sk_rogue, 100, &hash)],
        };
        assert!(!verify_checkpoint(&rogue, &keys, 1));

        let mut bad = sign_checkpoint(&sk2, 100, &hash);
        bad.sig[0] ^= 0xff;
        let corrupted = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![bad],
        };
        assert!(!verify_checkpoint(&corrupted, &keys, 1));

        let replay = SignedCheckpoint {
            height: 101,
            hash,
            sigs: vec![sign_checkpoint(&sk1, 100, &hash)],
        };
        assert!(!verify_checkpoint(&replay, &keys, 1));
    }

    #[test]
    fn checkpoint_sunset_is_unconditional() {
        let (sk1, pk1) = test_signer(1);
        let hash = fake_hash(6, CHECKPOINT_SUNSET_HEIGHT);
        let at_sunset = SignedCheckpoint {
            height: CHECKPOINT_SUNSET_HEIGHT,
            hash,
            sigs: vec![sign_checkpoint(&sk1, CHECKPOINT_SUNSET_HEIGHT, &hash)],
        };
        assert!(!verify_checkpoint(&at_sunset, &[pk1], 1));

        let h = CHECKPOINT_SUNSET_HEIGHT - 1;
        let hash2 = fake_hash(6, h);
        let before = SignedCheckpoint {
            height: h,
            hash: hash2,
            sigs: vec![sign_checkpoint(&sk1, h, &hash2)],
        };
        assert!(verify_checkpoint(&before, &[pk1], 1));
    }

    #[test]
    fn more_sigs_than_keys_refused() {
        let (sk1, pk1) = test_signer(1);
        let keys = [pk1];
        let hash = fake_hash(7, 100);
        let good = sign_checkpoint(&sk1, 100, &hash);

        let honest = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![good],
        };
        assert!(
            verify_checkpoint(&honest, &keys, 1),
            "the honest shape must survive the bound"
        );

        let mut junk = Vec::new();
        for i in 0..15u8 {
            junk.push(CheckpointSig {
                pubkey: pk1,
                sig: [i ^ 0xA5; 64],
            });
        }
        let flood = SignedCheckpoint {
            height: 100,
            hash,
            sigs: junk,
        };
        assert!(!verify_checkpoint(&flood, &keys, 1));

        let doubled = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![good, good],
        };
        assert!(!verify_checkpoint(&doubled, &keys, 1));
    }

    #[test]
    fn one_verify_attempt_per_key() {
        let (sk1, pk1) = test_signer(1);
        let (sk2, pk2) = test_signer(2);
        let keys = [pk1, pk2];
        let hash = fake_hash(8, 100);

        let shadowed = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![
                CheckpointSig {
                    pubkey: pk1,
                    sig: [0x11; 64],
                },
                sign_checkpoint(&sk1, 100, &hash),
            ],
        };
        assert!(!verify_checkpoint(&shadowed, &keys, 1));

        let other_key = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![
                CheckpointSig {
                    pubkey: pk1,
                    sig: [0x11; 64],
                },
                sign_checkpoint(&sk2, 100, &hash),
            ],
        };
        assert!(verify_checkpoint(&other_key, &keys, 1));
    }

    #[test]
    fn wire_cap_frame_is_cheap() {
        use std::time::Instant;
        let (_sk1, pk1) = test_signer(1);
        let keys = [pk1];
        let hash = fake_hash(9, 100);

        let one = SignedCheckpoint {
            height: 100,
            hash,
            sigs: vec![CheckpointSig {
                pubkey: pk1,
                sig: [0x5C; 64],
            }],
        };

        let flood = SignedCheckpoint {
            height: 100,
            hash,
            sigs: (0..15u8)
                .map(|i| CheckpointSig {
                    pubkey: pk1,
                    sig: [i ^ 0x5C; 64],
                })
                .collect(),
        };
        assert!(!verify_checkpoint(&one, &keys, 1));
        assert!(!verify_checkpoint(&flood, &keys, 1));

        const ROUNDS: u32 = 256;
        const TRIALS: u32 = 5;
        let measure = |cp: &SignedCheckpoint| {
            let mut best = u128::MAX;
            for _ in 0..TRIALS {
                let t = Instant::now();
                for _ in 0..ROUNDS {
                    std::hint::black_box(verify_checkpoint(std::hint::black_box(cp), &keys, 1));
                }
                best = best.min(t.elapsed().as_nanos());
            }
            best
        };
        let one_ns = measure(&one);
        let flood_ns = measure(&flood);

        println!(
            "verify_checkpoint: {ROUNDS} refused wire-cap frames in {flood_ns} ns; \
             {ROUNDS} single signature checks in {one_ns} ns = {} ns each",
            one_ns / ROUNDS as u128
        );

        assert!(
            one_ns > 100_000,
            "baseline too small to measure: {ROUNDS} checks took {one_ns} ns; raise ROUNDS"
        );
        assert!(
            flood_ns * 4 < one_ns,
            "refused 15-sig frame cost {flood_ns} ns vs {one_ns} ns for one check: the \
             work bound in verify_checkpoint is gone"
        );
    }

    #[test]
    fn checkpoint_admission_vectors() {
        let chain = MockChain::linear(5, 1);
        let any = fake_hash(50, 0);

        assert_eq!(
            checkpoint_admission(&chain, 0, &any),
            CheckpointAdmission::GenesisImmutable
        );

        assert_eq!(
            checkpoint_admission(&chain, 5, &any),
            CheckpointAdmission::NotHeldYet
        );

        assert_eq!(
            checkpoint_admission(&chain, 2, &any),
            CheckpointAdmission::HashConflict
        );

        let h2 = chain.header_at(2).unwrap().hash;
        assert_eq!(
            checkpoint_admission(&chain, 2, &h2),
            CheckpointAdmission::Admit
        );
        assert_eq!(
            checkpoint_admission(&chain, 2, &h2),
            CheckpointAdmission::Admit
        );
    }

    fn tie_fixture() -> (MockChain, HeaderInfo, MockChain, HeaderInfo) {
        let a = hdr(1, 100, STD_M);
        let b = hdr(1, 200, STD_M);
        assert_ne!(a.hash, b.hash);
        let (small, large) = if a.hash < b.hash { (a, b) } else { (b, a) };
        let mut holding_large = MockChain::linear(1, 1);
        holding_large.headers.push(large);
        let mut holding_small = MockChain::linear(1, 1);
        holding_small.headers.push(small);
        (holding_large, small, holding_small, large)
    }

    #[test]
    fn tie_break_depth1_lower_hash_wins() {
        let (holding_large, small, holding_small, large) = tie_fixture();

        let p1 = synced_params(&holding_large);
        assert_eq!(
            evaluate_reorg(&holding_large, 1, &[small], &p1),
            Ok(ReorgVerdict::TieBreak)
        );

        let p2 = synced_params(&holding_small);
        assert_eq!(
            evaluate_reorg(&holding_small, 1, &[large], &p2),
            Err(RuleError::InsufficientWork { depth: 1 })
        );
    }

    #[test]
    fn tie_break_depth2_rejected() {
        let chain = MockChain::linear(3, 1);
        let p = synced_params(&chain);

        for seed in 200..210 {
            let cand = branch(1, 2, seed, STD_M);
            assert_eq!(
                evaluate_reorg(&chain, 1, &cand, &p),
                Err(RuleError::InsufficientWork { depth: 2 }),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn tie_break_requires_same_tip_height() {
        let mut chain = MockChain::linear(1, 1);
        chain.headers.push(hdr(1, 5, HEAVY_M));
        let p = synced_params(&chain);
        for seed in 300..310 {
            let cand = branch(1, 2, seed, STD_M);
            assert_eq!(
                evaluate_reorg(&chain, 1, &cand, &p),
                Err(RuleError::InsufficientWork { depth: 1 }),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn tie_break_cannot_bypass_depth_cap_or_checkpoints() {
        let chain = MockChain::linear(4, 1);
        let p = synced_params(&chain);
        let cand = branch(1, 3, 400, STD_M);
        assert!(matches!(
            evaluate_reorg_with_cap(&chain, 1, &cand, &p, 1),
            Err(RuleError::ReorgTooDeep { depth: 3, cap: 1 })
        ));

        let (holding_large, small, _, _) = tie_fixture();
        let cp = [(1u64, holding_large.header_at(1).unwrap().hash)];
        let p_cp = ReorgParams {
            anchor: None,
            checkpoints: &cp,
            local_time: holding_large.tip().time,
        };
        assert_eq!(
            evaluate_reorg(&holding_large, 1, &[small], &p_cp),
            Err(RuleError::CheckpointMismatch { height: 1 })
        );
    }

    #[test]
    fn strict_work_equal_or_less_rejected() {
        let chain = MockChain::linear(5, 1);
        let p = synced_params(&chain);

        let equal = branch(3, 2, 500, STD_M);
        assert_eq!(
            evaluate_reorg(&chain, 3, &equal, &p),
            Err(RuleError::InsufficientWork { depth: 2 })
        );

        let lighter = branch(3, 1, 500, STD_M);
        assert_eq!(
            evaluate_reorg(&chain, 3, &lighter, &p),
            Err(RuleError::InsufficientWork { depth: 2 })
        );

        let heavier = branch(3, 2, 501, HEAVY_M);
        assert_eq!(
            evaluate_reorg(&chain, 3, &heavier, &p),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );
    }

    #[test]
    fn mtp_is_median_of_last_11_sorted() {
        assert_eq!(median_time_past(&[100]), 100);
        assert_eq!(median_time_past(&[100, 200]), 200);
        assert_eq!(median_time_past(&[300, 100, 200]), 200);

        let times: Vec<u64> = (0..12).map(|i| i * 10).collect();

        assert_eq!(median_time_past(&times), 60);

        assert_eq!(median_time_past(&[5, 90, 10, 80, 20]), 20);
    }

    #[test]
    fn block_time_must_strictly_exceed_mtp() {
        let mtp = 1_000;

        assert_eq!(
            check_block_time(mtp, 1_000, 2_000),
            Err(RuleError::TimestampTooOld {
                mtp: 1_000,
                time: 1_000
            })
        );
        assert_eq!(
            check_block_time(mtp, 999, 2_000),
            Err(RuleError::TimestampTooOld {
                mtp: 1_000,
                time: 999
            })
        );
        assert_eq!(check_block_time(mtp, 1_001, 2_000), Ok(()));
    }

    #[test]
    fn future_drift_boundary_600s() {
        let now = 10_000;

        assert_eq!(
            check_block_time(0, now + MAX_FUTURE_DRIFT_SECS, now),
            Ok(())
        );

        assert_eq!(
            check_block_time(0, now + MAX_FUTURE_DRIFT_SECS + 1, now),
            Err(RuleError::TimestampTooFarInFuture {
                time: now + MAX_FUTURE_DRIFT_SECS + 1,
                limit: now + MAX_FUTURE_DRIFT_SECS,
            })
        );
    }

    #[test]
    fn maturity_boundary_first_spend() {
        let h = 1_000;

        assert!(!coinbase_is_mature(h, h));
        assert!(!coinbase_is_mature(h, h + COINBASE_MATURITY - 1));

        assert!(coinbase_is_mature(h, h + COINBASE_MATURITY));
        assert!(coinbase_is_mature(h, h + COINBASE_MATURITY + 1));

        assert!(!coinbase_is_mature(h, h - 1));
    }

    #[test]
    fn spendable_balance_clamps_at_zero() {
        assert_eq!(spendable_balance(100, 30), 70);
        assert_eq!(spendable_balance(100, 100), 0);

        assert_eq!(spendable_balance(100, 150), 0);
    }

    #[test]
    fn maturity_exceeds_reorg_cap() {
        const { assert!(COINBASE_MATURITY > MAX_REORG_DEPTH) };

        const {
            assert!(
                COINBASE_MATURITY >= 2 * MAX_REORG_DEPTH,
                "SPEC 4/7.1: maturity must be at least twice the reorg cap"
            )
        };

        let h = 10u64;
        let first_spend_height = h + COINBASE_MATURITY;
        let chain = MockChain::linear(first_spend_height + 1, 1);
        let p = synced_params(&chain);

        let depth = chain.len() - h;
        assert_eq!(depth, COINBASE_MATURITY + 1);
        let attack = branch(h, depth + 5, 666, HEAVY_M);
        assert_eq!(
            evaluate_reorg(&chain, h, &attack, &p),
            Err(RuleError::ReorgTooDeep {
                depth,
                cap: MAX_REORG_DEPTH
            })
        );

        let shallow_start = h + (depth - MAX_REORG_DEPTH);
        let shallow = branch(shallow_start, 110, 667, HEAVY_M);
        assert_eq!(
            evaluate_reorg(&chain, shallow_start, &shallow, &p),
            Ok(ReorgVerdict::StrictlyMoreWork)
        );
    }
}
