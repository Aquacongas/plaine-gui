use std::collections::HashMap;
use std::sync::Arc;

use plaine_consensus::constants::{
    HEADER_BYTES, MAX_BLOCK_BYTES, MAX_HEADERS_PER_MSG, MAX_TXS_PER_BLOCK,
};
use plaine_consensus::rules::{
    evaluate_reorg_with_cap, Anchor, HeaderInfo, ReorgParams, RuleError, SignedCheckpoint,
};

use crate::checkpoints::{CheckpointReport, Checkpoints};
use crate::error::{Condition, Reject};
use crate::forkchoice::{self, ArenaView};
use crate::header::{self, Ingest, IngestCtx};
use crate::index::HeaderIndex;
use crate::mempool::{self, Admitted, Ingress, Mempool};
use crate::reorg::{self, Base};
use crate::state::{CoinbaseLedger, Overlay};
use crate::traits::{Clock, Observer, PowVerifier, Sink, SinkError, Store};
use crate::types::{
    Accepted, Address, ChainParams, ChainStats, CommitBlock, DeepReorgCommit, Hash32, HeaderRec,
    Progress, ReorgCommit, SideHeaderRec, Solicitation, SourceId, TipRef, TxOrigin, Work,
};
use crate::work::{expand_bits, target_to_be, WorkCache};

pub struct ChainManager<S, K, P, C>
where
    S: Store + ?Sized,
    K: Sink + ?Sized,
    P: PowVerifier + ?Sized,
    C: Clock + ?Sized,
{
    store: Arc<S>,
    sink: Arc<K>,
    pow: Arc<P>,
    clock: Arc<C>,
    params: ChainParams,
    index: HeaderIndex,
    ingest: Ingest,
    memo: WorkCache,
    cps: Checkpoints,
    pool: Mempool,
    tx_ingress: Ingress,
    tip_epoch: u64,
    bodies: HashMap<Hash32, Vec<u8>>,
    side_raws: HashMap<Hash32, [u8; HEADER_BYTES]>,
    tip_ledger: CoinbaseLedger,
    observer: Option<Observer>,
    stats: ChainStats,
    halted: Option<&'static str>,
    genesis_time: u64,
    last_branch_failure: Option<Reject>,
    wanted_bodies: Vec<Hash32>,
}

// Cap the body wishlist so it can't grow without bound.
const WANTED_BODIES_CAP: usize = 512;

impl<S, K, P, C> ChainManager<S, K, P, C>
where
    S: Store + ?Sized,
    K: Sink + ?Sized,
    P: PowVerifier + ?Sized,
    C: Clock + ?Sized,
{
    pub fn new(
        store: Arc<S>,
        sink: Arc<K>,
        pow: Arc<P>,
        clock: Arc<C>,
        params: ChainParams,
        observer: Option<Observer>,
    ) -> Result<Self, Reject> {
        // Frozen consensus sizes. Fail at boot if a refactor moved them, not later.
        if HEADER_BYTES != 132 {
            return Err(Reject::BootInvariant {
                detail: "header is not 132 bytes",
            });
        }
        if MAX_BLOCK_BYTES != 1_048_576 || MAX_TXS_PER_BLOCK != 4_096 {
            return Err(Reject::BootInvariant {
                detail: "block limits moved",
            });
        }

        if !params.profile_is_consistent() {
            return Err(Reject::BootInvariant {
                detail: "ChainParams.profile does not match pow_limit",
            });
        }

        if !params.class_reserve_is_survivable(pow.cost_micros()) {
            return Err(Reject::BootInvariant {
                detail: "class reserve below one interpreter call per 30 s",
            });
        }

        if params.max_sources > params.max_peers {
            return Err(Reject::BootInvariant {
                detail: "max_sources exceeds max_peers: the class reserve over-commits",
            });
        }
        if params.class_aggregate_rate_micros_per_sec() > params.class_rate_micros_per_sec() {
            return Err(Reject::BootInvariant {
                detail: "shared + max_sources x reserve exceeds the class cap",
            });
        }
        let mut m = ChainManager {
            index: HeaderIndex::new(),
            ingest: Ingest::new(&params),
            memo: WorkCache::new(),
            cps: Checkpoints::new(),
            pool: Mempool::new(params.mempool.clone()),
            tx_ingress: Ingress::new(&params),
            tip_epoch: 0,
            bodies: HashMap::new(),
            side_raws: HashMap::new(),
            tip_ledger: CoinbaseLedger::new(),
            params,
            store,
            sink,
            pow,
            clock,
            observer,
            stats: ChainStats::default(),
            halted: None,
            genesis_time: 0,
            last_branch_failure: None,
            wanted_bodies: Vec::new(),
        };
        m.load_from_store()?;
        Ok(m)
    }

    fn load_from_store(&mut self) -> Result<(), Reject> {
        let tip = self.store.tip();
        let genesis = self.store.header_at(0).ok_or(Reject::BootInvariant {
            detail: "store holds no genesis",
        })?;
        self.genesis_time = genesis.time;
        let gw =
            self.memo
                .work(genesis.bits, &self.params.pow_limit)
                .ok_or(Reject::BootInvariant {
                    detail: "genesis bits are not a legal target",
                })?;
        self.index.insert_genesis(&genesis, gw);
        let mut cum = gw;
        let mut chain = vec![0u32];
        for h in 1..=tip.height {
            let Some(rec) = self.store.header_at(h) else {
                break;
            };
            let w =
                self.memo
                    .work(rec.bits, &self.params.pow_limit)
                    .ok_or(Reject::BootInvariant {
                        detail: "stored bits are not a legal target",
                    })?;
            cum = cum.checked_add(&w).ok_or(Reject::BootInvariant {
                detail: "chainwork overflow on load",
            })?;
            let parent = *chain.last().expect("genesis is in the chain");
            let idx = self.index.insert(&rec, parent, cum, true);
            self.index.set_have_body(idx);
            chain.push(idx);
        }
        self.index.set_canonical(&chain);
        self.rebuild_side_arena();
        self.tip_ledger = reorg::build_ledger(&*self.store, self.index.tip_height())?;
        Ok(())
    }

    fn rebuild_side_arena(&mut self) -> usize {
        let cap = self.params.max_side_headers;
        let rows = self.store.side_headers_from(0, cap);
        let mut restored = 0usize;
        for rec in rows {
            if restored >= cap {
                break;
            }

            if self.index.contains(&rec.hash) {
                continue;
            }
            let Some(parent) = self.index.index_of(&rec.prev_hash) else {
                continue;
            };
            let p = *self.index.node(parent);
            if p.height + 1 != rec.height {
                continue;
            }
            let Some(w) = self.memo.work(rec.bits, &self.params.pow_limit) else {
                continue;
            };
            let Some(cum) = p.cum_work.checked_add(&w) else {
                continue;
            };
            let idx = self.index.insert(&rec, parent, cum, true);

            if self.store.is_invalid(&rec.hash) {
                self.index.set_invalid_flag(idx);
            }

            restored += 1;
        }
        self.stats.side_headers_restored = restored as u64;
        restored
    }

    // A body can arrive for a header we pruned; pull it back from the store so the
    // body has a parent to attach to.
    fn readmit_persisted_header(&mut self, hash: &Hash32) -> Option<u32> {
        let rec = self.store.header_by_hash(hash)?;
        if rec.hash != *hash {
            return None;
        }
        let parent = self.index.index_of(&rec.prev_hash)?;
        let p = *self.index.node(parent);
        if p.height + 1 != rec.height {
            return None;
        }
        let w = self.memo.work(rec.bits, &self.params.pow_limit)?;
        let cum = p.cum_work.checked_add(&w)?;
        let idx = self.index.insert(&rec, parent, cum, true);
        if self.store.is_invalid(&rec.hash) {
            self.index.set_invalid_flag(idx);
        }
        self.stats.headers_readmitted += 1;
        Some(idx)
    }

    pub fn tip(&self) -> TipRef {
        let n = self.index.tip();
        TipRef {
            height: n.height,
            hash: n.hash,
            time: n.time,
            chainwork: n.cum_work,
        }
    }

    pub fn header_at(&self, height: u64) -> Option<HeaderRec> {
        self.index
            .canonical_at(height)
            .and_then(|n| self.rec_of(&n.hash))
    }

    pub fn header_by_hash(&self, hash: &Hash32) -> Option<HeaderRec> {
        self.rec_of(hash)
    }

    pub fn header_raw(&self, hash: &Hash32) -> Option<[u8; HEADER_BYTES]> {
        self.side_raws
            .get(hash)
            .copied()
            .or_else(|| self.store.header_by_hash(hash).map(|r| r.raw))
    }

    pub fn side_header_count(&self) -> usize {
        self.side_raws.len()
    }

    fn rec_of(&self, hash: &Hash32) -> Option<HeaderRec> {
        if let Some(r) = self.store.header_by_hash(hash) {
            return Some(r);
        }
        None
    }

    pub fn ancestor_at(&self, hash: &Hash32, height: u64) -> Option<Hash32> {
        let idx = self.index.index_of(hash)?;
        self.index
            .ancestor_at(idx, height)
            .map(|i| self.index.node(i).hash)
    }

    pub fn locator(&self) -> Vec<Hash32> {
        // Dense near the tip, then doubling stride: log(height) hashes pin the fork.
        let mut out = Vec::new();
        let mut h = self.index.tip_height() as i64;
        let mut step = 1i64;
        while h >= 0 {
            if let Some(n) = self.index.canonical_at(h as u64) {
                out.push(n.hash);
            }
            if out.len() > 10 {
                step *= 2;
            }
            h -= step;
        }
        if let Some(n) = self.index.canonical_at(0) {
            if out.last() != Some(&n.hash) {
                out.push(n.hash);
            }
        }
        out
    }

    pub fn headers_from(&self, from: u64, max: usize) -> Vec<[u8; HEADER_BYTES]> {
        self.store.headers_range(from, max.min(MAX_HEADERS_PER_MSG))
    }

    pub fn have_body(&self, hash: &Hash32) -> bool {
        self.bodies.contains_key(hash) || self.store.body_by_hash(hash).is_some()
    }

    pub fn body_bytes(&self, hash: &Hash32) -> Option<Vec<u8>> {
        self.bodies
            .get(hash)
            .cloned()
            .or_else(|| self.store.body_by_hash(hash))
    }

    pub fn anchor(&self) -> Option<Anchor> {
        self.cps.anchor().copied()
    }

    pub fn anchor_record(&self) -> Option<SignedCheckpoint> {
        self.cps.anchor_record().cloned()
    }

    pub fn checkpoints(&self) -> Vec<(u64, Hash32)> {
        self.cps.enforced().to_vec()
    }

    pub fn pow_verified_floor(&self) -> u64 {
        0
    }

    pub fn capacity(&self) -> usize {
        self.sink.capacity()
    }

    pub fn stats(&self) -> ChainStats {
        self.stats
    }

    pub fn mempool(&self) -> &Mempool {
        &self.pool
    }

    pub fn last_branch_failure(&self) -> Option<&Reject> {
        self.last_branch_failure.as_ref()
    }

    pub fn wanted_bodies(&self) -> &[Hash32] {
        &self.wanted_bodies
    }

    pub fn halted(&self) -> Option<&'static str> {
        self.halted
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn index(&self) -> &HeaderIndex {
        &self.index
    }

    pub fn branch_report(&self) -> BranchReport {
        let tip = self.index.tip_height();
        let best_idx = forkchoice::select_best(&self.index);
        let best_node = self.index.node(best_idx);
        let (fork_height, depth) = match forkchoice::plan_reorg(&self.index, best_idx) {
            None => (tip, 0),
            Some(p) => (p.fork_height, p.depth),
        };
        let verdict = match forkchoice::plan_reorg(&self.index, best_idx) {
            None => BranchVerdict::OnBest,
            Some(plan) => {
                let cap = self.params.max_reorg_depth;
                let anchored = self.cps.anchor().is_some_and(|a| {
                    plan.apply.iter().any(|&i| {
                        self.index.node(i).height == a.height && self.index.node(i).hash == a.hash
                    })
                });
                if cap > 0 && plan.depth > cap && !anchored {
                    BranchVerdict::Stranded { cap }
                } else {
                    let missing = plan
                        .apply
                        .iter()
                        .filter(|&&i| !self.have_body(&self.index.node(i).hash))
                        .count();
                    if missing > 0 {
                        BranchVerdict::NeedBodies { missing }
                    } else {
                        BranchVerdict::Adoptable
                    }
                }
            }
        };
        BranchReport {
            tip,
            best: best_node.height,
            best_hash: best_node.hash,
            fork_height,
            depth,
            verdict,
        }
    }

    pub fn submit_headers(
        &mut self,
        source: SourceId,
        raws: &[[u8; HEADER_BYTES]],
    ) -> Result<Accepted, Reject> {
        self.ingest_headers(source, raws, Solicitation::Unsolicited)
    }

    pub fn submit_headers_solicited(
        &mut self,
        source: SourceId,
        raws: &[[u8; HEADER_BYTES]],
    ) -> Result<Accepted, Reject> {
        self.ingest_headers(source, raws, Solicitation::SolicitedIbd)
    }

    pub fn submit_headers_solicited_steady(
        &mut self,
        source: SourceId,
        raws: &[[u8; HEADER_BYTES]],
    ) -> Result<Accepted, Reject> {
        self.ingest_headers(source, raws, Solicitation::SolicitedSteady)
    }

    pub fn forget_source(&mut self, source: SourceId) {
        self.ingest.forget(source);
        self.tx_ingress.forget(source);
    }

    pub fn source_count(&self) -> usize {
        self.ingest.source_count()
    }

    fn ingest_headers(
        &mut self,
        source: SourceId,
        raws: &[[u8; HEADER_BYTES]],
        solicitation: Solicitation,
    ) -> Result<Accepted, Reject> {
        if let Some(d) = self.halted {
            return Err(Reject::Halted { detail: d });
        }

        if raws.len() > MAX_HEADERS_PER_MSG {
            return Err(Reject::BatchTooLong {
                got: raws.len(),
                cap: MAX_HEADERS_PER_MSG,
            });
        }
        let mut conds: Vec<Condition> = Vec::new();
        let mut connected: Vec<HeaderRec> = Vec::new();
        let accepted = {
            let ctx = IngestCtx {
                store: &*self.store,
                pow: &*self.pow,
                checkpoints: self.cps.enforced(),
                anchor: self.cps.anchor().copied(),
                params: &self.params,
                now: self.clock.now_unix(),
                mono_ms: self.clock.mono_ms(),
                tip: {
                    let n = self.index.tip();
                    TipRef {
                        height: n.height,
                        hash: n.hash,
                        time: n.time,
                        chainwork: n.cum_work,
                    }
                },
                genesis_time: self.genesis_time,
                solicitation,
                tip_epoch: self.tip_epoch,
                side_capacity: self
                    .params
                    .max_side_headers
                    .saturating_sub(self.side_raws.len()),
            };
            let mut obs = |c: Condition| conds.push(c);
            header::submit_headers(
                &mut self.ingest,
                &mut self.index,
                &mut self.memo,
                &ctx,
                source,
                raws,
                &mut connected,
                &mut obs,
            )
        };
        for c in conds {
            self.emit(c);
        }
        let accepted = accepted?;
        self.stats.headers_connected += accepted.connected;

        for rec in connected {
            let cw = self
                .index
                .get(&rec.hash)
                .map(|n| n.cum_work)
                .unwrap_or_default();
            self.side_raws.insert(rec.hash, rec.raw);
            let _ = self
                .sink
                .store_side_header(&SideHeaderRec { rec, chainwork: cw });
        }
        Ok(accepted)
    }

    pub fn submit_block(&mut self, hash: &Hash32, body: Vec<u8>) -> Result<(), Reject> {
        if let Some(d) = self.halted {
            return Err(Reject::Halted { detail: d });
        }

        let idx = match self.index.index_of(hash) {
            Some(i) => i,
            None => self
                .readmit_persisted_header(hash)
                .ok_or(Reject::BodyNotAdmissible { hash: *hash })?,
        };
        let n = *self.index.node(idx);
        if !n.pow_ok() || n.invalid() {
            return Err(Reject::BodyNotAdmissible { hash: *hash });
        }
        if self.have_body(hash) {
            return Err(Reject::BodyAlreadyHeld { hash: *hash });
        }
        if body.len() + HEADER_BYTES > MAX_BLOCK_BYTES {
            return Err(Reject::BodyStructure {
                detail: "body over MAX_BLOCK_BYTES",
            });
        }
        self.bodies.insert(*hash, body);
        self.index.set_have_body(idx);
        Ok(())
    }

    pub fn advance(&mut self) -> Result<Progress, Reject> {
        if let Some(d) = self.halted {
            return Err(Reject::Halted { detail: d });
        }

        let mut refused: Vec<u32> = Vec::new();

        let mut first_refusal: Option<Reject> = None;

        let mut pending: Vec<Hash32> = Vec::new();
        loop {
            let best = forkchoice::select_best_excluding(&self.index, &refused);

            if refused.binary_search(&best).is_ok() {
                debug_assert!(false, "select_best_excluding returned a skipped index");
                return self.settle(pending, first_refusal);
            }
            let Some(plan) = forkchoice::plan_reorg(&self.index, best) else {
                return self.settle(pending, first_refusal);
            };

            let mut first_missing: Option<usize> = None;
            for (pos, &i) in plan.apply.iter().enumerate() {
                let h = self.index.node(i).hash;
                if self.have_body(&h) {
                    continue;
                }
                if first_missing.is_none() {
                    first_missing = Some(pos);
                }
                if pending.len() < WANTED_BODIES_CAP && !pending.contains(&h) {
                    pending.push(h);
                }
            }
            if let Some(pos) = first_missing {
                // Bodies missing from the first gap on: skip that suffix and let
                // fork choice fall back to the best branch we can apply. Gap hashes
                // are queued above.
                let before = refused.len();
                for &i in &plan.apply[pos..] {
                    skip_insert(&mut refused, i);
                }

                debug_assert!(
                    refused.len() > before,
                    "a bodyless skip that adds no new index cannot terminate"
                );
                continue;
            }
            match self.try_adopt(best, &plan) {
                Ok(p) => {
                    self.wanted_bodies = pending;
                    return Ok(p);
                }

                Err(Reject::BranchInvalid {
                    height,
                    hash,
                    cause,
                }) => {
                    // Poison a failing side branch and keep going. The same failure
                    // on our own canonical chain is corruption, so surface it.
                    let is_side = self
                        .index
                        .index_of(&hash)
                        .is_some_and(|i| !self.index.is_canonical(i));
                    if !is_side {
                        return Err(Reject::BranchInvalid {
                            height,
                            hash,
                            cause,
                        });
                    }
                    self.last_branch_failure = Some(Reject::BranchInvalid {
                        height,
                        hash,
                        cause,
                    });
                    self.invalidate(&hash);
                    continue;
                }

                Err(Reject::Rule(e)) => {
                    self.last_branch_failure = Some(Reject::Rule(e.clone()));
                    if first_refusal.is_none() {
                        first_refusal = Some(Reject::Rule(e));
                    }
                    debug_assert_ne!(
                        best,
                        self.index.tip_index(),
                        "the canonical tip is never a reorg plan"
                    );
                    skip_insert(&mut refused, best);
                    continue;
                }
                Err(e) => {
                    self.wanted_bodies = pending;
                    return Err(e);
                }
            }
        }
    }

    fn settle(
        &mut self,
        pending: Vec<Hash32>,
        first_refusal: Option<Reject>,
    ) -> Result<Progress, Reject> {
        self.wanted_bodies = pending;
        if !self.wanted_bodies.is_empty() {
            return Ok(Progress::NeedBodies(self.wanted_bodies.clone()));
        }
        match first_refusal {
            Some(e) => Err(e),
            None => Ok(Progress::NoChange),
        }
    }

    fn try_adopt(&mut self, best: u32, plan: &forkchoice::Plan) -> Result<Progress, Reject> {
        let now = self.clock.now_unix();
        let tip_height = self.index.tip_height();
        let start_height = plan.fork_height + 1;

        let candidate: Vec<HeaderInfo> = plan
            .apply
            .iter()
            .map(|&i| {
                let n = self.index.node(i);
                let t = expand_bits(n.bits, &self.params.pow_limit)
                    .ok_or(Reject::BadBits { got: n.bits })?;
                Ok(HeaderInfo {
                    height: n.height,
                    hash: n.hash,
                    time: n.time,
                    target: target_to_be(&t),
                })
            })
            .collect::<Result<_, Reject>>()?;
        let enforced = self.cps.enforced().to_vec();
        let anchor = self.cps.anchor().copied();
        let verdict = {
            let view = ArenaView::new(&self.index, self.params.pow_limit);

            evaluate_reorg_with_cap(
                &view,
                start_height,
                &candidate,
                &ReorgParams {
                    anchor: anchor.as_ref(),
                    checkpoints: &enforced,
                    local_time: now,
                },
                self.params.max_reorg_depth,
            )
        };
        if let Err(e) = verdict {
            if let RuleError::ReorgTooDeep { depth, cap: _ } = e {
                let their = candidate.last().map(|c| c.height).unwrap_or(0);
                self.emit(Condition::ReorgTooDeepRefused {
                    our_tip: tip_height,
                    their_tip: their,
                    depth,
                    fork_height: plan.fork_height,
                });
            }
            return Err(Reject::Rule(e));
        }

        let mut conds: Vec<Condition> = Vec::new();
        // Grab the rolled-back blocks' non-coinbase txs for reinjection after commit.
        let disconnected: Vec<(u64, Vec<Vec<u8>>)> = plan
            .rollback
            .iter()
            .map(|h| (*h, non_coinbase_bytes(&*self.store, *h)))
            .collect();

        let branch: Vec<(HeaderRec, Vec<u8>)> = plan
            .apply
            .iter()
            .map(|&i| {
                let n = self.index.node(i);

                let raw = self
                    .side_raws
                    .get(&n.hash)
                    .copied()
                    .or_else(|| self.store.header_by_hash(&n.hash).map(|r| r.raw))
                    .ok_or_else(|| Reject::BranchInvalid {
                        height: n.height,
                        hash: n.hash,
                        cause: Box::new(Reject::BodyNotAdmissible { hash: n.hash }),
                    })?;
                let body = self
                    .body_bytes(&n.hash)
                    .ok_or(Reject::BodyNotAdmissible { hash: n.hash })?;
                Ok((HeaderRec::from_raw(raw), body))
            })
            .collect::<Result<_, Reject>>()?;

        let branch_work: Vec<Work> = plan
            .apply
            .iter()
            .map(|&i| self.index.node(i).cum_work)
            .collect();

        let arena = &self.index;

        let outcome = {
            let mut overlay = Overlay::new(&*self.store, self.params.reorg_overlay_max_accounts);
            let mut ledger = CoinbaseLedger::new();
            let mut replayed: Vec<CommitBlock> = Vec::new();
            let mut obs = |c: Condition| conds.push(c);
            let chainwork_at = |h: u64| {
                arena
                    .canonical_at(h)
                    .map(|n| n.cum_work)
                    .unwrap_or_default()
            };
            reorg::rewind_to_fork(
                &*self.store,
                &mut overlay,
                &mut ledger,
                tip_height,
                plan.fork_height,
                &self.params,
                &chainwork_at,
                &mut replayed,
                &mut obs,
            )
            .and_then(|base| {
                let (mut commits, spent) = reorg::validate_branch(
                    &mut overlay,
                    &mut ledger,
                    &branch,
                    &|i| branch_work[i],
                    &self.params,
                    &mut obs,
                )?;
                if !replayed.is_empty() {
                    let mut all = replayed;
                    all.append(&mut commits);
                    commits = all;
                }
                Ok((commits, spent, base))
            })
        };
        for c in conds {
            self.emit(c);
        }
        let (commits, spent, base) = outcome?;
        self.stats.bodies_validated += branch.len() as u64;

        let applied = plan.apply.len() as u64;
        let rolled_back = plan.rollback.len() as u64;
        let result = match base {
            Base::DeepReplay { rewind_to } => self.sink.commit_deep_reorg(&DeepReorgCommit {
                rewind_to,
                apply: commits,
            }),
            // One block on the current tip: cheap single-block commit, no reorg write.
            Base::UndoWindow if plan.rollback.is_empty() && commits.len() == 1 => {
                self.sink.commit_block(&commits[0])
            }
            Base::UndoWindow => self.sink.commit_reorg(&ReorgCommit {
                rollback: plan.rollback.clone(),
                apply: commits,
            }),
        };
        match result {
            Ok(_) => {}
            Err(SinkError::Full) => return Err(Reject::Busy),
            Err(SinkError::Invalid(d)) => return Err(Reject::SinkRefused { detail: d }),
            Err(SinkError::Fatal(d)) => {
                self.halted = Some(d);
                self.emit(Condition::StorageFatal { detail: d });
                return Err(Reject::Halted { detail: d });
            }
        }

        let chain = self.index.ancestry(best);
        self.index.set_canonical(&chain);

        self.tip_epoch = self.tip_epoch.wrapping_add(1);
        for &i in &plan.apply {
            let h = self.index.node(i).hash;
            self.bodies.remove(&h);
            self.side_raws.remove(&h);
        }
        if rolled_back > 0 {
            self.stats.reorgs += 1;
        }
        if matches!(base, Base::DeepReplay { .. }) {
            self.stats.deep_reorgs += 1;
        }
        self.tip_ledger = reorg::build_ledger(&*self.store, self.index.tip_height())?;
        self.update_mempool(&spent, &disconnected);
        Ok(Progress::Advanced {
            tip: self.tip(),
            rolled_back,
            applied,
        })
    }

    pub fn submit_tx(&mut self, origin: TxOrigin, raw: Vec<u8>) -> Result<Admitted, Reject> {
        if let Some(d) = self.halted {
            return Err(Reject::Halted { detail: d });
        }
        let mut conds: Vec<Condition> = Vec::new();

        if let TxOrigin::Peer(source) = origin {
            let mono = self.clock.mono_ms();
            if let Err(e) = self.tx_ingress.admit(source, &self.params, mono) {
                self.emit(mempool::tx_ingress_exhausted(source));
                return Err(e);
            }
        }

        let now = self.clock.now_unix();
        let store = self.store.clone();
        let ledger = self.tip_ledger.clone();
        let height = self.index.tip_height() + 1;
        let author = self.params.author_pubkey;
        let network = self.params.network;
        let out = {
            let mut lookup = |a: &Address| {
                let ac = store.account(a);
                (ac, ledger.spendable(a, ac.balance, height))
            };
            let mut obs = |c: Condition| conds.push(c);
            self.pool
                .submit_verified(network, raw, &mut lookup, now, &author, &mut obs)
        };
        for c in conds {
            self.emit(c);
        }
        out
    }

    fn update_mempool(&mut self, spent: &[(Address, u64)], disconnected: &[(u64, Vec<Vec<u8>>)]) {
        let store = self.store.clone();
        let mut acct = |a: &Address| store.account(a);
        self.pool.on_block_connected(spent, &mut acct);
        if !disconnected.is_empty() {
            let now = self.clock.now_unix();
            let store = self.store.clone();
            let ledger = self.tip_ledger.clone();
            let height = self.index.tip_height() + 1;
            let mut conds: Vec<Condition> = Vec::new();
            {
                let mut lookup = |a: &Address| {
                    let ac = store.account(a);
                    (ac, ledger.spendable(a, ac.balance, height))
                };
                let mut obs = |c: Condition| conds.push(c);
                self.pool
                    .on_reorg_reinject(disconnected, now, &mut lookup, &mut obs);
            }
            for c in conds {
                self.emit(c);
            }
        }
        let store = self.store.clone();
        let mut acct = |a: &Address| store.account(a);
        self.pool.resplit_all(&mut acct);
    }

    pub fn block_template(&self) -> Vec<Vec<u8>> {
        self.pool.template(
            MAX_TXS_PER_BLOCK - 1,
            MAX_BLOCK_BYTES - HEADER_BYTES - 4_096,
        )
    }

    pub fn submit_checkpoint(&mut self, cp: &SignedCheckpoint) -> Result<CheckpointReport, Reject> {
        let mut conds: Vec<Condition> = Vec::new();
        let report = {
            let view = ArenaView::new(&self.index, self.params.pow_limit);
            let mut obs = |c: Condition| conds.push(c);
            self.cps.submit(cp, &view, &self.params, &mut obs)
        };
        for c in conds {
            self.emit(c);
        }

        if report.anchor_advanced {
            debug_assert_eq!(
                self.cps.anchor().map(|a| (a.height, a.hash)),
                Some((cp.height, cp.hash)),
                "anchor_advanced means this record became the anchor"
            );
            if let Err(e) = self.sink.put_anchor(cp) {
                self.emit(Condition::AnchorNotPersisted {
                    height: cp.height,
                    err: e,
                });
            }
        }
        Ok(report)
    }

    pub fn load_anchor(&mut self, cp: &SignedCheckpoint) -> bool {
        self.cps.load_anchor(cp, &self.params)
    }

    fn emit(&self, c: Condition) {
        if let Some(o) = &self.observer {
            o(c);
        }
    }

    pub fn invalidate(&mut self, hash: &Hash32) {
        if let Some(idx) = self.index.index_of(hash) {
            let poisoned = self.index.mark_invalid(idx);
            self.stats.invalidated += 1;
            self.stats.poisoned += poisoned;
            let _ = self.sink.mark_invalid(hash);
        }
    }
}

fn skip_insert(skip: &mut Vec<u32>, i: u32) {
    if let Err(pos) = skip.binary_search(&i) {
        skip.insert(pos, i);
    }
}

fn non_coinbase_bytes<S: Store + ?Sized>(store: &S, height: u64) -> Vec<Vec<u8>> {
    let Some(raw) = store.body_at(height) else {
        return Vec::new();
    };
    let Ok(body) = plaine_consensus::codec::BlockBody::parse(&raw) else {
        return Vec::new();
    };
    (1..body.len())
        .filter_map(|i| body.tx_bytes(i).map(|b| b.to_vec()))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchReport {
    pub tip: u64,
    pub best: u64,
    pub best_hash: Hash32,
    pub fork_height: u64,
    pub depth: u64,
    pub verdict: BranchVerdict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchVerdict {
    OnBest,

    NeedBodies { missing: usize },

    Stranded { cap: u64 },
    Adoptable,
}
