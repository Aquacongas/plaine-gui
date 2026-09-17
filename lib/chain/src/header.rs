use std::collections::{HashMap, HashSet, VecDeque};

use plaine_consensus::constants::{BLOCK_TIME_SECS, HEADER_BYTES, MEDIAN_TIME_SPAN};
use plaine_consensus::rules::Anchor;

use crate::error::{BudgetClass, Condition, Permanence, Reject};
use crate::gates;
use crate::index::HeaderIndex;
use crate::traits::{PowVerifier, Store};
use crate::types::{
    Accepted, ChainParams, Hash32, HeaderRec, Solicitation, SourceId, TipRef, Work,
};
use crate::work::{anchor_height_for, expected_child_bits, WorkCache};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    pub rec: HeaderRec,
    pub cum_work: Work,
    pub branch_base_height: u64,
}

#[derive(Clone, Debug)]
pub struct NegativeCache {
    set: HashSet<Hash32>,
    ring: VecDeque<Hash32>,
    cap: usize,
}

impl NegativeCache {
    pub fn new(cap: usize) -> NegativeCache {
        NegativeCache {
            set: HashSet::new(),
            ring: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    pub fn contains(&self, h: &Hash32) -> bool {
        self.set.contains(h)
    }

    pub fn insert(&mut self, h: Hash32, p: Permanence) {
        // Cache permanent verdicts only. Transient ones (future drift, unknown
        // parent, fork-too-deep) can turn valid later, so caching would reject
        // the same header forever.
        if p != Permanence::Permanent || self.set.contains(&h) {
            return;
        }
        if self.ring.len() >= self.cap {
            if let Some(old) = self.ring.pop_front() {
                self.set.remove(&old);
            }
        }
        self.ring.push_back(h);
        self.set.insert(h);
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SourceState {
    pub staged: Vec<Staged>,
    staged_hashes: HashSet<Hash32>,
    tokens: u64,
    last_ms: u64,
    reserve_tokens: u64,
    reserve_last_ms: u64,
    primed: bool,
    pow_failures: u32,
    quota_epoch: u64,
    quota_ms: u64,
    dups: u32,
    dup_window_ms: u64,
}

impl SourceState {
    fn refill(&mut self, params: &ChainParams, cost_micros: u64, mono_ms: u64) {
        if !self.primed {
            self.primed = true;
            self.tokens = params.pow_budget_burst_micros;
            self.reserve_tokens = params.class_reserve_burst_micros(cost_micros);
            self.last_ms = mono_ms;
            self.reserve_last_ms = mono_ms;
            self.quota_ms = mono_ms;
            return;
        }
        let elapsed = mono_ms.saturating_sub(self.last_ms);
        if elapsed > 0 {
            let refill = elapsed.saturating_mul(params.pow_budget_micros)
                / params.pow_budget_window_ms.max(1);
            if refill > 0 {
                self.tokens = self
                    .tokens
                    .saturating_add(refill)
                    .min(params.pow_budget_burst_micros);
                self.last_ms = mono_ms;
            }
        }
        let elapsed = mono_ms.saturating_sub(self.reserve_last_ms);
        if elapsed > 0 {
            let refill = elapsed.saturating_mul(params.class_reserve_rate_micros_per_sec()) / 1_000;
            if refill > 0 {
                self.reserve_tokens = self
                    .reserve_tokens
                    .saturating_add(refill)
                    .min(params.class_reserve_burst_micros(cost_micros));
                self.reserve_last_ms = mono_ms;
            }
        }
    }

    fn roll_quota_epoch(&mut self, epoch: u64, params: &ChainParams, mono_ms: u64) {
        let stalled = mono_ms.saturating_sub(self.quota_ms)
            >= params.child_quota_window_secs.saturating_mul(1_000);
        if self.quota_epoch != epoch || stalled {
            self.quota_epoch = epoch;
            self.quota_ms = mono_ms;
            self.pow_failures = 0;
        }
    }

    fn budgets_full(&self, params: &ChainParams, cost_micros: u64) -> bool {
        self.pow_failures == 0
            && self.tokens >= params.pow_budget_burst_micros
            && self.reserve_tokens >= params.class_reserve_burst_micros(cost_micros)
    }

    fn owes_nothing(&self, params: &ChainParams, cost_micros: u64) -> bool {
        self.staged.is_empty() && self.budgets_full(params, cost_micros)
    }
}

#[derive(Clone, Debug)]
pub struct Ingest {
    pub neg: NegativeCache,
    sources: HashMap<SourceId, SourceState>,
    shared_tokens: u64,
    shared_last_ms: u64,
    shared_primed: bool,
}

impl Ingest {
    pub fn new(params: &ChainParams) -> Ingest {
        Ingest {
            neg: NegativeCache::new(params.negative_cache_entries),
            sources: HashMap::new(),
            shared_tokens: 0,
            shared_last_ms: 0,
            shared_primed: false,
        }
    }

    pub fn staged(&self, source: SourceId) -> usize {
        self.sources.get(&source).map_or(0, |s| s.staged.len())
    }

    pub fn tokens(&self, source: SourceId) -> u64 {
        self.sources.get(&source).map_or(0, |s| s.tokens)
    }

    pub fn reserve_tokens(&self, source: SourceId) -> u64 {
        self.sources.get(&source).map_or(0, |s| s.reserve_tokens)
    }

    pub fn shared_tokens(&self) -> u64 {
        self.shared_tokens
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn forget(&mut self, source: SourceId) {
        self.sources.remove(&source);
    }

    fn refill_shared(&mut self, params: &ChainParams, mono_ms: u64) {
        if !self.shared_primed {
            self.shared_primed = true;
            self.shared_tokens = params.class_shared_burst_micros();
            self.shared_last_ms = mono_ms;
            return;
        }
        let elapsed = mono_ms.saturating_sub(self.shared_last_ms);
        if elapsed == 0 {
            return;
        }
        let refill = elapsed.saturating_mul(params.class_shared_rate_micros_per_sec()) / 1_000;
        if refill > 0 {
            self.shared_tokens = self
                .shared_tokens
                .saturating_add(refill)
                .min(params.class_shared_burst_micros());
            self.shared_last_ms = mono_ms;
        }
    }

    fn touch(
        &mut self,
        source: SourceId,
        params: &ChainParams,
        cost_micros: u64,
        mono_ms: u64,
    ) -> Result<&mut SourceState, Reject> {
        if !self.sources.contains_key(&source) && self.sources.len() >= params.max_sources {
            // At the cap: evict a fully idle source before a parked one, and never
            // one that still owes budget.
            let mut idle: Option<SourceId> = None;
            let mut parked: Option<(usize, SourceId)> = None;
            for (id, s) in self.sources.iter_mut() {
                s.refill(params, cost_micros, mono_ms);
                if s.owes_nothing(params, cost_micros) {
                    if idle.is_none_or(|cur| *id < cur) {
                        idle = Some(*id);
                    }
                } else if s.budgets_full(params, cost_micros) {
                    let key = (s.staged.len(), *id);
                    if parked.is_none_or(|cur| key < cur) {
                        parked = Some(key);
                    }
                }
            }
            match idle.or(parked.map(|(_, id)| id)) {
                Some(id) => {
                    self.sources.remove(&id);
                }
                None => {
                    return Err(Reject::TooManySources {
                        source,
                        cap: params.max_sources,
                    })
                }
            }
        }
        let st = self.sources.entry(source).or_default();
        st.refill(params, cost_micros, mono_ms);
        Ok(st)
    }
}

pub struct IngestCtx<'a, S: Store + ?Sized, P: PowVerifier + ?Sized> {
    pub store: &'a S,
    pub pow: &'a P,
    pub checkpoints: &'a [(u64, Hash32)],
    pub anchor: Option<Anchor>,
    pub params: &'a ChainParams,
    pub now: u64,
    pub mono_ms: u64,
    pub tip: TipRef,
    pub genesis_time: u64,
    pub solicitation: Solicitation,
    pub tip_epoch: u64,
    pub side_capacity: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn submit_headers<S: Store + ?Sized, P: PowVerifier + ?Sized>(
    ing: &mut Ingest,
    index: &mut HeaderIndex,
    memo: &mut WorkCache,
    ctx: &IngestCtx<'_, S, P>,
    source: SourceId,
    raws: &[[u8; HEADER_BYTES]],
    connected_out: &mut Vec<HeaderRec>,
    observe: &mut dyn FnMut(Condition),
) -> Result<Accepted, Reject> {
    let params = ctx.params;
    let cost = ctx.pow.cost_micros();
    ing.refill_shared(params, ctx.mono_ms);
    let st = ing.touch(source, params, cost, ctx.mono_ms)?;
    st.roll_quota_epoch(ctx.tip_epoch, params, ctx.mono_ms);
    if ctx.mono_ms.saturating_sub(st.dup_window_ms) >= params.duplicate_window_secs * 1_000 {
        st.dup_window_ms = ctx.mono_ms;
        st.dups = 0;
    }

    let mut out = Accepted {
        verified_height: index.tip_height(),
        ..Default::default()
    };
    let mut batch_dups = 0u32;

    let mut staged_first: Option<(Hash32, u64)> = None;

    for raw in raws {
        let hash = plaine_consensus::crypto::header_hash(raw);
        let staged_here = ing
            .sources
            .get(&source)
            .is_some_and(|s| s.staged_hashes.contains(&hash));
        if staged_here
            || index.contains(&hash)
            || ing.neg.contains(&hash)
            || ctx.store.is_invalid(&hash)
        {
            if staged_here && out.first_held.is_none() {
                if let Some(h) = ing
                    .sources
                    .get(&source)
                    .and_then(|s| s.staged.iter().find(|x| x.rec.hash == hash))
                    .map(|x| x.rec.height)
                {
                    out.first_held = Some(crate::types::Held { hash, height: h });
                }
            }
            out.duplicates += 1;
            batch_dups += 1;
            let st = ing.sources.get_mut(&source).expect("inserted above");
            st.dups += 1;
            if st.dups > params.max_duplicates_per_window {
                observe(Condition::DuplicateFlood {
                    source,
                    count: st.dups,
                });
            }
            if batch_dups > params.max_duplicates_per_batch {
                observe(Condition::BudgetExhausted {
                    source,
                    class: BudgetClass::Duplicates,
                });
                break;
            }
            continue;
        }

        if ing.staged(source) >= params.max_staged_headers {
            out.connected += promote(
                ing,
                index,
                ctx,
                source,
                connected_out,
                observe,
                &mut out.first_rejection,
                &mut out.first_held,
            );
        }
        match stage_one(ing, index, memo, ctx, source, *raw, hash) {
            Ok(()) => {
                out.staged += 1;

                if staged_first.is_none() {
                    staged_first = ing
                        .sources
                        .get(&source)
                        .and_then(|s| s.staged.last())
                        .map(|x| (x.rec.hash, x.rec.height));
                }
            }
            Err(rej) => {
                out.rejected += 1;

                if out.first_rejection.is_none() {
                    let height = plaine_consensus::codec::Header::decode(raw)
                        .map(|h| h.height)
                        .unwrap_or(0);

                    let repair_from = match rej {
                        Reject::UnknownParent { .. } => height.saturating_sub(1),
                        _ => height,
                    };
                    out.first_rejection = Some(crate::types::Rejection {
                        hash,
                        height,
                        repair_from,
                        why: rej.why(),
                    });
                }
                ing.neg.insert(hash, rej.permanence());
            }
        }
    }

    let promoted = promote(
        ing,
        index,
        ctx,
        source,
        connected_out,
        observe,
        &mut out.first_rejection,
        &mut out.first_held,
    );
    out.connected += promoted;
    out.staged = ing.staged(source) as u32;

    if out.first_held.is_none() {
        if let Some((hash, height)) = staged_first {
            if ing
                .sources
                .get(&source)
                .is_some_and(|s| s.staged_hashes.contains(&hash))
            {
                out.first_held = Some(crate::types::Held { hash, height });
            }
        }
    }
    out.verified_height = index.tip_height().max(
        ing.sources
            .get(&source)
            .and_then(|s| s.staged.last().map(|x| x.rec.height))
            .unwrap_or(0),
    );
    Ok(out)
}

fn stage_one<S: Store + ?Sized, P: PowVerifier + ?Sized>(
    ing: &mut Ingest,
    index: &HeaderIndex,
    memo: &mut WorkCache,
    ctx: &IngestCtx<'_, S, P>,
    source: SourceId,
    raw: [u8; HEADER_BYTES],
    hash: Hash32,
) -> Result<(), Reject> {
    let params = ctx.params;

    let hdr = gates::s1_fixed_fields(&raw, &params.pow_limit)?;

    gates::s1b_checkpoint(ctx.checkpoints, hdr.height, &hash)?;

    let staged = ing
        .sources
        .get(&source)
        .map(|s| s.staged.as_slice())
        .unwrap_or(&[]);
    let parent = find_parent(index, staged, &hdr.prev_hash).ok_or(Reject::UnknownParent {
        prev: hdr.prev_hash,
    })?;

    gates::s2_height(hdr.height, parent.height)?;

    let (a_bits, a_height, a_parent_time) = resolve_anchor(index, staged, &parent, ctx)?;
    let expected = expected_child_bits(
        a_bits,
        a_height,
        a_parent_time,
        parent.height,
        parent.time,
        &params.pow_limit,
    )
    .map_err(|_| Reject::AsertAnchorUnavailable { height: a_height })?;
    gates::s3_bits(hdr.bits, expected)?;

    let times = ancestor_times(index, staged, &parent, MEDIAN_TIME_SPAN);
    gates::s4_time(&times, hdr.time, ctx.now)?;

    let reach = match ctx.anchor {
        None => gates::AnchorReach::NotReached,
        Some(a) => anchor_reach(index, staged, &parent, &a),
    };
    let child_base = child_branch_base(index, &parent);
    gates::s5_fork_depth(&ctx.tip, child_base, ctx.anchor.as_ref(), reach, params)?;

    let w = memo
        .work(hdr.bits, &params.pow_limit)
        .ok_or(Reject::BadBits { got: hdr.bits })?;
    let cum_work = parent
        .cum_work
        .checked_add(&w)
        .ok_or(Reject::ArithmeticOverflow)?;

    let st = ing.sources.entry(source).or_default();
    if st.staged.len() >= params.max_staged_headers {
        return Err(Reject::StagingFull { source });
    }
    st.staged.push(Staged {
        rec: HeaderRec {
            height: hdr.height,
            hash,
            prev_hash: hdr.prev_hash,
            time: hdr.time,
            bits: hdr.bits,
            raw,
        },
        cum_work,
        branch_base_height: child_base,
    });
    st.staged_hashes.insert(hash);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn promote<S: Store + ?Sized, P: PowVerifier + ?Sized>(
    ing: &mut Ingest,
    index: &mut HeaderIndex,
    ctx: &IngestCtx<'_, S, P>,
    source: SourceId,
    connected_out: &mut Vec<HeaderRec>,
    observe: &mut dyn FnMut(Condition),
    lost: &mut Option<crate::types::Rejection>,
    held: &mut Option<crate::types::Held>,
) -> u64 {
    let Some(st) = ing.sources.get(&source) else {
        return 0;
    };
    if st.staged.is_empty() {
        return 0;
    }

    // Heaviest staged head, lower hash breaks ties.
    let terminal = st
        .staged
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.cum_work
                .cmp(&b.cum_work)
                .then(b.rec.hash.cmp(&a.rec.hash))
        })
        .map(|(i, s)| (i, s.clone()))
        .expect("non-empty");
    let depth = ctx.tip.height.saturating_sub(terminal.1.branch_base_height);
    if gates::s6_claimed_work(
        &terminal.1.cum_work,
        &terminal.1.rec.hash,
        terminal.1.rec.height,
        depth,
        &ctx.tip,
    )
    .is_err()
    {
        if held.is_none() {
            if let Some(low) = st.staged.iter().min_by_key(|x| x.rec.height) {
                *held = Some(crate::types::Held {
                    hash: low.rec.hash,
                    height: low.rec.height,
                });
            }
        }
        return 0;
    }

    // Unsolicited children cost a per-source quota.
    if ctx.solicitation.charges_child_quota() {
        let st = ing.sources.get(&source).expect("checked");
        if st.pow_failures >= ctx.params.child_pow_failures_per_source {
            observe(Condition::BudgetExhausted {
                source,
                class: BudgetClass::ChildQuota,
            });
            return 0;
        }
    }

    let staged = ing
        .sources
        .get_mut(&source)
        .expect("checked")
        .staged
        .clone();
    let cost = ctx.pow.cost_micros();
    let charge = ctx.solicitation.charges_budget();
    let mut connected = 0u64;
    let mut consumed = 0usize;
    let mut failed = false;

    for s in &staged {
        if connected as usize >= ctx.side_capacity {
            observe(Condition::BudgetExhausted {
                source,
                class: BudgetClass::Staging,
            });
            break;
        }
        if charge && !spend_class_budget(ing, source, cost) {
            observe(Condition::BudgetExhausted {
                source,
                class: BudgetClass::Interpreter,
            });
            break;
        }
        if !ctx.pow.verify(&s.rec.raw) {
            if lost.is_none() {
                *lost = Some(crate::types::Rejection {
                    hash: s.rec.hash,
                    height: s.rec.height,
                    repair_from: s.rec.height,
                    why: Reject::PowInvalid { hash: s.rec.hash }.why(),
                });
            }
            ing.neg.insert(s.rec.hash, Permanence::Permanent);

            let st = ing.sources.get_mut(&source).expect("checked");
            st.pow_failures = st.pow_failures.saturating_add(1);
            consumed += 1;
            failed = true;
            break;
        }

        let Some(parent) = index.index_of(&s.rec.prev_hash) else {
            if lost.is_none() {
                *lost = Some(crate::types::Rejection {
                    hash: s.rec.hash,
                    height: s.rec.height,
                    repair_from: s.rec.height.saturating_sub(1),
                    why: "parent was not stored",
                });
            }
            consumed += 1;
            continue;
        };
        index.insert(&s.rec, parent, s.cum_work, true);
        connected_out.push(s.rec);
        connected += 1;
        consumed += 1;
    }

    let st = ing.sources.get_mut(&source).expect("checked");
    if failed {
        // A bad pow taints the whole staged run; drop all of it.
        for x in st.staged.drain(..) {
            st.staged_hashes.remove(&x.rec.hash);
        }
    } else {
        for x in st.staged.drain(..consumed.min(st.staged.len())) {
            st.staged_hashes.remove(&x.rec.hash);
        }
    }
    let _ = terminal.0;
    connected
}

fn spend_class_budget(ing: &mut Ingest, source: SourceId, cost: u64) -> bool {
    if !ing.sources.get(&source).is_some_and(|s| s.tokens >= cost) {
        return false;
    }

    // Shared class pool first, then the source's own reserve.
    let from_shared = ing.shared_tokens >= cost;
    if !from_shared
        && !ing
            .sources
            .get(&source)
            .is_some_and(|s| s.reserve_tokens >= cost)
    {
        return false;
    }
    if from_shared {
        ing.shared_tokens -= cost;
    }
    let st = ing.sources.get_mut(&source).expect("checked above");
    if !from_shared {
        st.reserve_tokens -= cost;
    }
    st.tokens -= cost;
    true
}

#[derive(Clone, Copy, Debug)]
struct Lite {
    height: u64,
    hash: Hash32,
    prev_hash: Hash32,
    time: u64,
    bits: u32,
    cum_work: Work,
    branch_base_height: u64,
    arena: Option<u32>,
}

fn find_parent(index: &HeaderIndex, staged: &[Staged], hash: &Hash32) -> Option<Lite> {
    if let Some(i) = index.index_of(hash) {
        let n = index.node(i);
        return Some(Lite {
            height: n.height,
            hash: n.hash,
            prev_hash: [0u8; 32],
            time: n.time,
            bits: n.bits,
            cum_work: n.cum_work,
            branch_base_height: n.branch_base_height,
            arena: Some(i),
        });
    }
    // TODO: linear scan of staged; staged_hashes answers membership but not the record.
    staged
        .iter()
        .rev()
        .find(|s| s.rec.hash == *hash)
        .map(|s| Lite {
            height: s.rec.height,
            hash: s.rec.hash,
            prev_hash: s.rec.prev_hash,
            time: s.rec.time,
            bits: s.rec.bits,
            cum_work: s.cum_work,
            branch_base_height: s.branch_base_height,
            arena: None,
        })
}

fn child_branch_base(index: &HeaderIndex, node: &Lite) -> u64 {
    match node.arena {
        Some(i) if index.is_canonical(i) => node.height,
        Some(_) => node.branch_base_height,
        None => node.branch_base_height,
    }
}

fn lite_parent(index: &HeaderIndex, staged: &[Staged], node: &Lite) -> Option<Lite> {
    if let Some(i) = node.arena {
        let p = index.node(i).prev;
        if p == crate::index::NO_PARENT {
            return None;
        }
        let n = index.node(p);
        return Some(Lite {
            height: n.height,
            hash: n.hash,
            prev_hash: [0u8; 32],
            time: n.time,
            bits: n.bits,
            cum_work: n.cum_work,
            branch_base_height: n.branch_base_height,
            arena: Some(p),
        });
    }
    find_parent(index, staged, &node.prev_hash)
}

fn ancestor_times(index: &HeaderIndex, staged: &[Staged], from: &Lite, span: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(span);
    let mut cur = *from;
    for _ in 0..span {
        out.push(cur.time);
        match lite_parent(index, staged, &cur) {
            Some(p) => cur = p,
            None => break,
        }
    }
    out.reverse();
    out
}

fn anchor_reach(
    index: &HeaderIndex,
    staged: &[Staged],
    from: &Lite,
    anchor: &Anchor,
) -> gates::AnchorReach {
    if from.height < anchor.height {
        return gates::AnchorReach::NotReached;
    }
    match ancestor_of(index, staged, from, anchor.height) {
        None => gates::AnchorReach::NotReached,
        Some(a) if a.hash == anchor.hash => gates::AnchorReach::Matches,
        Some(_) => gates::AnchorReach::Contradicts,
    }
}

fn ancestor_of(index: &HeaderIndex, staged: &[Staged], from: &Lite, height: u64) -> Option<Lite> {
    if height > from.height {
        return None;
    }
    if from.branch_base_height >= height {
        let n = *index.canonical_at(height)?;
        return Some(Lite {
            height: n.height,
            hash: n.hash,
            prev_hash: [0u8; 32],
            time: n.time,
            bits: n.bits,
            cum_work: n.cum_work,
            branch_base_height: n.branch_base_height,
            arena: index.index_of(&n.hash),
        });
    }
    let mut cur = *from;
    while cur.height > height {
        cur = lite_parent(index, staged, &cur)?;
    }
    if cur.height == height {
        Some(cur)
    } else {
        None
    }
}

fn resolve_anchor<S: Store + ?Sized, P: PowVerifier + ?Sized>(
    index: &HeaderIndex,
    staged: &[Staged],
    parent: &Lite,
    ctx: &IngestCtx<'_, S, P>,
) -> Result<(u32, u64, u64), Reject> {
    let ah = anchor_height_for(parent.height, ctx.params.asert_anchor_interval);
    let anchor = ancestor_of(index, staged, parent, ah)
        .ok_or(Reject::AsertAnchorUnavailable { height: ah })?;

    // Genesis has no parent; synthesize its parent time one block back to seed ASERT.
    let anchor_parent_time = if ah == 0 {
        ctx.genesis_time.saturating_sub(BLOCK_TIME_SECS)
    } else {
        ancestor_of(index, staged, parent, ah - 1)
            .ok_or(Reject::AsertAnchorUnavailable { height: ah })?
            .time
    };
    Ok((anchor.bits, anchor.height, anchor_parent_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_cache_refuses_transient_verdicts() {
        let mut c = NegativeCache::new(4);
        let a = [1u8; 32];
        c.insert(a, Reject::ExtRootNotZero.permanence());
        assert!(c.contains(&a));
        let b = [2u8; 32];
        c.insert(
            b,
            Reject::TimestampTooFarInFuture { time: 1, limit: 0 }.permanence(),
        );
        assert!(
            !c.contains(&b),
            "future drift is transient and must not be cached"
        );
        let d = [3u8; 32];
        c.insert(d, Reject::UnknownParent { prev: [0u8; 32] }.permanence());
        assert!(!c.contains(&d), "unknown parent must not be cached");
        let e = [4u8; 32];

        c.insert(e, Reject::ForkTooDeep { depth: 7, cap: 5 }.permanence());
        assert!(
            !c.contains(&e),
            "the fork-depth verdict is relative to a tip that may regress"
        );
    }

    #[test]
    fn negative_cache_evicts_at_capacity() {
        let mut c = NegativeCache::new(3);
        for i in 0..100u8 {
            let mut h = [0u8; 32];
            h[0] = i;
            c.insert(h, Permanence::Permanent);
            assert!(c.len() <= 3);
        }
        assert_eq!(c.len(), 3);
    }
}
