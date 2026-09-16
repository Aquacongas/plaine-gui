use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use plaine_chain::types::{Hash32, Progress, SourceId, TxOrigin};
use plaine_chain::{ChainManager, Reject};
use plaine_consensus::constants::{BLOCK_TIME_SECS, HEADER_BYTES};
use plaine_consensus::rules::SignedCheckpoint;

use crate::wire::clock::SysClock;
use crate::wire::pow::Interp;
use crate::wire::store::{CommitSink, NodeStore};
use crate::wire::tip::{TipCell, TipView};
use crate::wire::OnConsensusThread;

// sentinel source id for blocks we sealed ourselves - never collides with a
// source id p2p hands to a real peer.
pub const LOCAL_SOURCE: SourceId = u32::MAX;

pub type Manager = ChainManager<NodeStore, CommitSink, Interp, SysClock>;

pub enum Query {
    MempoolInfo(SyncSender<MempoolSnapshot>),
    BySender([u8; 20], SyncSender<Vec<Vec<u8>>>),
    Tx(Hash32, SyncSender<Option<Vec<u8>>>),
    Template([u8; 20], SyncSender<Option<TemplatePlan>>),
    Budgets(SyncSender<BudgetSnapshot>),
    Branch(SyncSender<plaine_chain::BranchReport>),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MempoolSnapshot {
    pub tx_count: usize,
    pub bytes: usize,
    pub executable: usize,
    pub queued: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectTally {
    pub already_held: u64,
    pub not_admissible: u64,
}

impl RejectTally {
    pub fn count(&mut self, e: &plaine_chain::error::Reject) {
        use plaine_chain::error::Reject;
        match e {
            Reject::BodyAlreadyHeld { .. } => {
                self.already_held = self.already_held.saturating_add(1)
            }
            Reject::BodyNotAdmissible { .. } => {
                self.not_admissible = self.not_admissible.saturating_add(1)
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BudgetSnapshot {
    pub pow_calls: u64,
    pub pow_cache_hits: u64,
    pub sources: usize,
    pub sources_cap: usize,
    pub headers_connected: u64,
    pub bodies_validated: u64,
    pub reorgs: u64,
    pub body_already_held: u64,
    pub body_not_admissible: u64,
}

#[derive(Clone, Debug)]
pub struct TemplatePlan {
    pub prefix: [u8; 124],
    pub height: u64,
    pub network_target: [u8; 32],
    pub body: Vec<u8>,
    pub parent: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealVerdict {
    Accepted,
    Obsolete,
    Rejected,
}

pub enum Cmd {
    Headers {
        source: SourceId,
        raws: Vec<[u8; HEADER_BYTES]>,
        solicitation: Solicit,
    },

    Block {
        hash: Hash32,
        bytes: Vec<u8>,
    },

    Tx {
        origin: TxOrigin,
        bytes: Vec<u8>,
        reply: Option<SyncSender<Result<Hash32, Reject>>>,
    },

    Checkpoint {
        cp: Box<SignedCheckpoint>,
        reply: SyncSender<CheckpointVerdict>,
    },

    Seal {
        header: [u8; HEADER_BYTES],
        body: Vec<u8>,
        reply: SyncSender<SealVerdict>,
    },
    Ask(Query),
    Tick,
    Stop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Solicit {
    #[allow(dead_code)]
    Unsolicited,
    Ibd,
    Steady,
}

fn report_headers(
    refusals: &std::sync::Mutex<Option<crate::wire::net::Break>>,
    holds: &std::sync::Mutex<Option<plaine_p2p::traits::Held>>,
    source: SourceId,
    a: &plaine_chain::Accepted,
) {
    crate::log::debug(
        "chain",
        format!(
            "headers from {source}: {} connected, {} duplicate, {} rejected, {} staged",
            a.connected, a.duplicates, a.rejected, a.staged
        ),
    );

    // A held header is staged but not connected. Tell p2p to drop it as delivered
    // and another peer can offer the branch again. The refusal below is a different
    // beast: it asks p2p to repair from the break, not just redeliver.
    if let Some(h) = a.first_held {
        crate::log::debug(
            "chain",
            format!(
                "header HELD from {source}: height {}, {} - staged, not connected. p2p is told to drop it as delivered, so another peer can offer the branch again.",
                h.height,
                plaine_consensus::hex::encode(&h.hash[..8])
            ),
        );

        crate::wire::net::ValidatorSink::hold(
            holds,
            plaine_p2p::traits::Held { hash: h.hash, height: h.height },
        );
    }
    let Some(rej) = a.first_rejection else { return };
    crate::log::warn(
        "chain",
        format!(
            "header REFUSED from {source}: height {}, {} - {}. p2p is told to repair \
             from height {}, dropping it as delivered and asking for it again.",
            rej.height,
            plaine_consensus::hex::encode(&rej.hash[..8]),
            rej.why,
            rej.repair_from
        ),
    );
    crate::wire::net::ValidatorSink::refuse(
        refusals,
        crate::wire::net::Break { height: rej.repair_from, why: rej.why },
    );
}

pub fn run(
    mut chain: Manager,
    mut rx: tokio::sync::mpsc::Receiver<Cmd>,
    tip: TipCell,
    interp: Arc<Interp>,
    clock: Arc<SysClock>,
    author_note: Vec<u8>,
    queued_bytes: Arc<std::sync::atomic::AtomicU64>,
    wanted_bodies: Arc<std::sync::Mutex<Arc<Vec<plaine_chain::types::Hash32>>>>,
    mempool_ids: Arc<std::sync::Mutex<Arc<Vec<plaine_chain::types::Hash32>>>>,
    anchor: AnchorCells,
    header_refusals: std::sync::Arc<std::sync::Mutex<Option<crate::wire::net::Break>>>,
    header_holds: std::sync::Arc<std::sync::Mutex<Option<plaine_p2p::traits::Held>>>,
    stranded: Arc<StrandedFlag>,
    on_tip: Box<dyn Fn(u64) + Send>,
) {
    let mut token = OnConsensusThread::claim();
    let mut rejects = RejectTally::default();
    publish(&chain, &tip, &interp, &wanted_bodies, &mempool_ids, &anchor);

    while let Some(cmd) = rx.blocking_recv() {
        let release = |n: usize| {
            queued_bytes.fetch_sub(
                (n as u64).min(queued_bytes.load(std::sync::atomic::Ordering::Relaxed)),
                std::sync::atomic::Ordering::Relaxed,
            );
        };
        let mut moved = false;
        match cmd {
            Cmd::Stop => break,
            Cmd::Tick => {}
            Cmd::Headers { source, raws, solicitation } => {
                release(raws.len() * HEADER_BYTES);
                let r = match solicitation {
                    Solicit::Unsolicited => chain.submit_headers(source, &raws),
                    Solicit::Ibd => chain.submit_headers_solicited(source, &raws),
                    Solicit::Steady => chain.submit_headers_solicited_steady(source, &raws),
                };
                match r {
                    Ok(a) => report_headers(&header_refusals, &header_holds, source, &a),
                    Err(e) => crate::log::debug("chain", format!("header batch refused: {e:?}")),
                }
            }
            Cmd::Block { hash, bytes } => {
                let n = bytes.len();
                release(n + HEADER_BYTES);
                match chain.submit_block(&hash, bytes) {
                    Ok(()) => crate::log::debug(
                        "chain",
                        format!("body {} accepted, {n} bytes", plaine_consensus::hex::encode(&hash[..8])),
                    ),
                    Err(e) => {
                        rejects.count(&e);
                        crate::log::debug("chain", format!("body refused: {e:?}"))
                    }
                }
            }
            Cmd::Tx { origin, bytes, reply } => {
                if reply.is_none() {
                    release(bytes.len());
                }
                let out = chain.submit_tx(origin, bytes);
                if let Some(r) = reply {
                    let _ = r.send(match out {
                        Ok(a) => Ok(a.txid),
                        Err(e) => Err(e),
                    });
                }
            }
            Cmd::Checkpoint { cp, reply } => {
                let r = chain.submit_checkpoint(&cp);

                let report = r.unwrap_or(plaine_chain::checkpoints::CheckpointReport {
                    outcome: plaine_chain::checkpoints::CheckpointOutcome::Unverified,
                    anchor_advanced: false,
                });
                let _ = reply.send(CheckpointVerdict {
                    report,
                    anchor: chain.anchor(),
                    enforced: chain.checkpoints().len(),
                });
            }
            Cmd::Seal { header, body, reply } => {
                let v = seal(&mut token, &mut chain, &header, body);
                let _ = reply.send(v);
                moved = v == SealVerdict::Accepted;
            }
            Cmd::Ask(q) => {
                answer(&mut token, &chain, &interp, &clock, &author_note, &stranded, &rejects, q);
                continue;
            }
        }

        match advance(&mut token, &mut chain) {
            Ok(Progress::Advanced { tip, rolled_back, applied }) => {
                moved = true;
                crate::log::debug(
                    "chain",
                    format!("advanced to {} (+{applied} -{rolled_back})", tip.height),
                );
            }
            Ok(Progress::NeedBodies(v)) => {
                crate::log::debug("chain", format!("need {} bodies", v.len()));
            }
            Ok(Progress::NoChange) => {}
            Err(Reject::Halted { detail }) => {
                crate::log::error("chain", format!("halted: {detail}. Restart to re-derive the tip from storage."));
            }
            Err(e) => crate::log::warn("chain", format!("advance: {e:?}")),
        }
        publish(&chain, &tip, &interp, &wanted_bodies, &mempool_ids, &anchor);
        if moved {
            on_tip(chain.tip().height);
        }
    }
    crate::log::info("shutdown", "validator drained");
}

#[derive(Debug, Default)]
pub struct StrandedFlag {
    at: std::sync::atomic::AtomicU64,
    now: std::sync::atomic::AtomicU64,
    our_tip: std::sync::atomic::AtomicU64,
    their_tip: std::sync::atomic::AtomicU64,
    depth: std::sync::atomic::AtomicU64,
    cap: std::sync::atomic::AtomicU64,
}

impl StrandedFlag {
    pub fn note(&self, unix_now: u64) {
        self.at.store(unix_now, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn note_with(&self, unix_now: u64, r: crate::health::TransportStranded) {
        use std::sync::atomic::Ordering::Relaxed;
        self.our_tip.store(r.our_tip, Relaxed);
        self.their_tip.store(r.their_tip, Relaxed);
        self.depth.store(r.depth, Relaxed);
        self.cap.store(r.cap, Relaxed);
        self.note(unix_now);
    }

    pub fn report(&self) -> Option<crate::health::TransportStranded> {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.recent() {
            return None;
        }
        Some(crate::health::TransportStranded {
            our_tip: self.our_tip.load(Relaxed),
            their_tip: self.their_tip.load(Relaxed),
            depth: self.depth.load(Relaxed),
            cap: self.cap.load(Relaxed),
        })
    }

    pub fn tick(&self, unix_now: u64) {
        self.now.store(unix_now, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn recent(&self) -> bool {
        let at = self.at.load(std::sync::atomic::Ordering::Relaxed);
        if at == 0 {
            return false;
        }
        self.now
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_sub(at)
            < STRANDED_TEMPLATE_HOLD_SECS
    }
}

// has to outlive several p2p audit intervals; miss one and a still-stranded node
// would resume mining its own dead branch.
const STRANDED_TEMPLATE_HOLD_SECS: u64 = 300;

// how far the body path may trail the header path before we stop building. it is
// a bound, not a direction - being ahead is fine, falling behind is not.
const TEMPLATE_LAG_MAX: u64 = 2;

// refuse to build on a branch we should not extend. Mining past a better branch we
// already hold just deepens the reorg needed to rejoin it.
fn refuse_template(
    report: &plaine_chain::BranchReport,
    transport_stranded: bool,
) -> Option<&'static str> {
    if transport_stranded {
        return Some("the transport refused a better branch as deeper than the reorg cap");
    }
    if matches!(report.verdict, plaine_chain::BranchVerdict::Stranded { .. }) {
        return Some("stranded past the reorg cap");
    }
    if report.best.saturating_sub(report.tip) > TEMPLATE_LAG_MAX {
        return Some("the body path has not kept up with the header path");
    }
    None
}

fn anchor_update(
    r: Result<plaine_chain::checkpoints::CheckpointReport, Reject>,
    anchor: Option<plaine_p2p::traits::Anchor>,
) -> plaine_p2p::traits::AnchorUpdate {
    use plaine_chain::checkpoints::CheckpointOutcome as O;
    use plaine_p2p::traits::AnchorUpdate as U;
    match r {
        Ok(r) if r.outcome == O::Unverified => U::Unverified,
        Ok(r) if r.anchor_advanced => match anchor {
            Some(a) => U::Advanced(a),
            None => U::Unchanged,
        },
        Ok(_) => U::Unchanged,
        Err(_) => U::Unverified,
    }
}

#[derive(Clone, Debug)]
pub struct CheckpointVerdict {
    pub report: plaine_chain::checkpoints::CheckpointReport,
    pub anchor: Option<plaine_p2p::traits::Anchor>,
    pub enforced: usize,
}

impl CheckpointVerdict {
    pub fn anchor_update(&self) -> plaine_p2p::traits::AnchorUpdate {
        anchor_update(Ok(self.report), self.anchor)
    }
}

pub type AnchorCells = (
    Arc<std::sync::Mutex<Option<plaine_p2p::traits::Anchor>>>,
    Arc<std::sync::Mutex<Arc<Vec<(u64, plaine_chain::types::Hash32)>>>>,
    Arc<std::sync::Mutex<Option<plaine_p2p::traits::SignedCheckpoint>>>,
);

fn advance(_t: &mut OnConsensusThread, chain: &mut Manager) -> Result<Progress, Reject> {
    chain.advance()
}

fn seal(
    t: &mut OnConsensusThread,
    chain: &mut Manager,
    header: &[u8; HEADER_BYTES],
    body: Vec<u8>,
) -> SealVerdict {
    let rec = plaine_chain::types::HeaderRec::from_raw(*header);
    // The tip moved under the miner while it sealed. The solved block builds on a
    // parent we have left behind - obsolete, not invalid.
    if rec.prev_hash != chain.tip().hash {
        return SealVerdict::Obsolete;
    }

    if chain.submit_headers_solicited(LOCAL_SOURCE, &[*header]).is_err() {
        return SealVerdict::Rejected;
    }
    if chain.submit_block(&rec.hash, body).is_err() {
        return SealVerdict::Rejected;
    }
    match advance(t, chain) {
        Ok(Progress::Advanced { .. }) => SealVerdict::Accepted,
        Ok(_) => SealVerdict::Rejected,
        Err(_) => SealVerdict::Rejected,
    }
}

fn publish_wanted(
    chain: &Manager,
    cell: &Arc<std::sync::Mutex<Arc<Vec<plaine_chain::types::Hash32>>>>,
) {
    let w = chain.wanted_bodies();
    let mut g = cell.lock().expect("wanted bodies");

    // nothing to publish and nothing published: skip the Arc swap. no point churning
    // a fresh allocation every tick on a quiet node.
    if w.is_empty() && g.is_empty() {
        return;
    }
    *g = Arc::new(w.to_vec());
}

fn publish_mempool(
    chain: &Manager,
    cell: &Arc<std::sync::Mutex<Arc<Vec<plaine_chain::types::Hash32>>>>,
) {
    let mut g = cell.lock().expect("mempool ids");
    if chain.mempool().executable_len() == 0 {
        if !g.is_empty() {
            *g = Arc::new(Vec::new());
        }
        return;
    }
    *g = Arc::new(chain.mempool().executable_ids());
}

fn publish(
    chain: &Manager,
    tip: &TipCell,
    interp: &Interp,
    wanted: &Arc<std::sync::Mutex<Arc<Vec<plaine_chain::types::Hash32>>>>,
    mempool_ids: &Arc<std::sync::Mutex<Arc<Vec<plaine_chain::types::Hash32>>>>,
    anchor: &AnchorCells,
) {
    publish_wanted(chain, wanted);
    publish_mempool(chain, mempool_ids);

    *anchor.0.lock().expect("anchor") = chain.anchor();

    *anchor.2.lock().expect("anchor record") = chain.anchor_record();
    {
        let cps = chain.checkpoints();
        let mut g = anchor.1.lock().expect("enforced");
        if !(cps.is_empty() && g.is_empty()) {
            *g = Arc::new(cps);
        }
    }
    let t = chain.tip();
    let mut chainwork = [0u8; 32];
    for i in 0..4 {
        let off = 24 - i * 8;
        chainwork[off..off + 8].copy_from_slice(&t.chainwork.0[i].to_be_bytes());
    }
    let prev = tip.get();
    let _ = interp;
    tip.publish(TipView {
        height: t.height,
        hash: t.hash,
        time: t.time,
        chainwork,
        epoch: if t.hash == prev.hash { prev.epoch } else { prev.epoch + 1 },
        mempool_txs: chain.mempool().len(),
        halted: chain.halted(),
    });
}

fn answer(
    t: &mut OnConsensusThread,
    chain: &Manager,
    interp: &Interp,
    clock: &SysClock,
    author_note: &[u8],
    stranded: &StrandedFlag,
    rejects: &RejectTally,
    q: Query,
) {
    match q {
        Query::MempoolInfo(r) => {
            let p = chain.mempool();
            let ex = p.executable_len();
            let _ = r.send(MempoolSnapshot {
                tx_count: p.len(),
                bytes: p.bytes(),
                executable: ex,
                queued: p.len().saturating_sub(ex),
            });
        }
        Query::BySender(addr, r) => {
            let _ = r.send(
                chain.mempool().sender_txs(&addr).into_iter().map(|t| t.bytes).collect(),
            );
        }
        Query::Tx(txid, r) => {
            let _ = r.send(chain.mempool().get(&txid).map(|t| t.bytes.clone()));
        }
        Query::Budgets(r) => {
            let s = chain.stats();
            let _ = r.send(BudgetSnapshot {
                pow_calls: interp.calls(),
                pow_cache_hits: interp.hits(),
                sources: chain.source_count(),
                sources_cap: chain.params().max_sources,
                headers_connected: s.headers_connected,
                bodies_validated: s.bodies_validated,
                reorgs: s.reorgs,
                body_already_held: rejects.already_held,
                body_not_admissible: rejects.not_admissible,
            });
        }
        Query::Branch(r) => {
            let _ = r.send(chain.branch_report());
        }
        Query::Template(recipient, r) => {
            let _ = r.send(build_template(t, chain, clock, author_note, &recipient, stranded));
        }
    }
}

fn build_template(
    _t: &mut OnConsensusThread,
    chain: &Manager,
    clock: &SysClock,
    author_note: &[u8],
    recipient: &[u8; 20],
    stranded: &StrandedFlag,
) -> Option<TemplatePlan> {
    use plaine_consensus::codec::{AuthorNote, BlockBody, CoinbaseTx, Header};
    use plaine_consensus::{emission, merkle};

    let report = chain.branch_report();
    if let Some(why) = refuse_template(&report, stranded.recent()) {
        // log the refusal once per tip, not on every template request.
        static SAID_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
        if SAID_AT.swap(report.tip, std::sync::atomic::Ordering::Relaxed) != report.tip {
            crate::log::warn(
                "chain",
                format!(
                    "not building templates at height {}: {why}. This node holds headers for a better branch at height {}. Mining now would extend a branch the network is not on, and every block deepens the reorg needed to rejoin. Miners are told the node is not ready.",
                    report.tip, report.best
                ),
            );
        }
        return None;
    }

    let tip = chain.tip();
    let height = tip.height + 1;

    let params = chain.params();
    let interval = params.asert_anchor_interval;
    let anchor_height = if interval == 0 { 0 } else { tip.height / interval * interval };
    let anchor = chain.header_at(anchor_height)?;
    let anchor_parent_time = if anchor_height == 0 {
        chain.header_at(0)?.time.saturating_sub(BLOCK_TIME_SECS)
    } else {
        chain.header_at(anchor_height - 1)?.time
    };
    let bits = plaine_consensus::asert::asert_next_bits(
        anchor.bits,
        anchor_height,
        anchor_parent_time,
        tip.height,
        tip.time,
        &params.pow_limit,
    )
    .ok()?;
    let target = plaine_consensus::asert::Target::from_compact(bits).ok()?;

    let mut times: Vec<u64> = Vec::with_capacity(11);
    let lo = tip.height.saturating_sub(10);
    for h in lo..=tip.height {
        if let Some(r) = chain.header_at(h) {
            times.push(r.time);
        }
    }
    // consensus rule is time > mtp. clamp up to mtp+1 even when the wall clock reads
    // lower - a template at or below mtp gets rejected.
    let mtp = plaine_consensus::rules::median_time_past(&times);
    let time = clock.unix().max(mtp + 1);

    let txs = chain.block_template();
    let mut fee_total: u128 = 0;
    for raw in &txs {
        let tx = plaine_consensus::codec::decode_tx(raw).ok()?;
        fee_total = fee_total.checked_add(tx.fee())?;
    }
    let note = AuthorNote {
        encoding: 0,
        payload: author_note.to_vec(),
    };
    let coinbase = CoinbaseTx {
        height,
        to: *recipient,
        reward: emission::block_reward(height),
        fees: fee_total,
        note,
    };
    let cb_bytes = coinbase.encode().ok()?;
    let mut all: Vec<&[u8]> = Vec::with_capacity(txs.len() + 1);
    all.push(cb_bytes.as_slice());
    for t in &txs {
        all.push(t.as_slice());
    }
    let body = BlockBody::encode(&all).ok()?;
    let tx_root = merkle::tx_root(&all);

    let header = Header {
        version: plaine_consensus::constants::VERSION_BASE,
        height,
        prev_hash: tip.hash,
        tx_root,
        ext_root: [0u8; 32],
        time,
        bits,
        author_note_len: author_note.len() as u32,
        nonce: 0,
    };
    let raw = header.encode();
    let mut prefix = [0u8; 124];
    prefix.copy_from_slice(&raw[..124]);
    Some(TemplatePlan {
        prefix,
        height,
        network_target: crate::wire::pow::target_be(&target),
        body,
        parent: tip.hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plaine_chain::types::Hash32;

    #[test]
    fn body_reject_tags_counted_separately() {
        use plaine_chain::error::Reject;
        let mut t = RejectTally::default();
        for _ in 0..2_104 {
            t.count(&Reject::BodyAlreadyHeld { hash: [0u8; 32] });
        }
        assert_eq!((t.already_held, t.not_admissible), (2_104, 0), "the measured healthy shape");

        let mut w = RejectTally::default();
        for _ in 0..85 {
            w.count(&Reject::BodyNotAdmissible { hash: [1u8; 32] });
        }
        assert_eq!((w.already_held, w.not_admissible), (0, 85), "the measured wedged shape");
    }

    #[test]
    fn unrelated_reject_moves_no_counter() {
        use plaine_chain::error::Reject;
        let mut t = RejectTally::default();
        t.count(&Reject::UnknownParent { prev: [2u8; 32] });
        assert_eq!((t.already_held, t.not_admissible), (0, 0));
    }

    #[allow(clippy::type_complexity)]
    fn rig() -> (
        Manager,
        TipCell,
        Arc<Interp>,
        Arc<std::sync::Mutex<Arc<Vec<Hash32>>>>,
        Arc<std::sync::Mutex<Arc<Vec<Hash32>>>>,
    ) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "plaine-validator-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let cfg = plaine_storage::StoreConfig::new(dir, plaine_storage::Network::Main);
        let (mut committer, reader) = crate::wire::store::tests::open_for_test(cfg);

        if reader.hdr_watermark() == 0 {
            let g = crate::genesis::for_network(crate::config::Network::Main).expect("genesis");
            committer
                .extend(&[plaine_storage::BlockToCommit {
                    header: &g.header_bytes,
                    hash: g.block_hash,
                    height: 0,
                    body: &g.body,
                    deltas: &[],
                    undo: &[],
                    issued_delta: plaine_consensus::emission::block_reward(0),
                    chainwork: [0u8; 32],
                    txids: None,
                }])
                .expect("genesis commit");
            committer.flush().expect("genesis flush");
        }
        let ring = crate::wire::store::new_ring();
        let store = Arc::new(NodeStore::new(reader.clone(), Arc::clone(&ring)));
        let sink = Arc::new(CommitSink::new(
            committer,
            reader,
            ring,
            crate::wire::rpcview::NoteIndex::new(),
        ));
        let interp = Arc::new(Interp::new().expect("interpreter"));
        let clock = Arc::new(SysClock::new());

        let d = plaine_chain::types::ChainParams::default();
        let params = plaine_chain::types::ChainParams {
            network: plaine_consensus::constants::Network::Main,
            genesis_bits: plaine_consensus::constants::GENESIS_BITS,
            ..d
        };
        let chain: Manager = plaine_chain::ChainManager::new(
            store,
            sink,
            Arc::clone(&interp),
            clock,
            params,
            None,
        )
        .expect("manager");
        (
            chain,
            TipCell::default(),
            interp,
            Arc::new(std::sync::Mutex::new(Arc::new(Vec::new()))),
            Arc::new(std::sync::Mutex::new(Arc::new(Vec::new()))),
        )
    }

    fn report(tip: u64, best: u64, verdict: plaine_chain::BranchVerdict)
        -> plaine_chain::BranchReport
    {
        plaine_chain::BranchReport {
            tip,
            best,
            best_hash: [0x5a; 32],
            fork_height: tip,
            depth: 0,
            verdict,
        }
    }

    #[test]
    fn replayed_checkpoint_not_an_advance() {
        use plaine_chain::checkpoints::{CheckpointOutcome as O, CheckpointReport};
        use plaine_p2p::traits::{Anchor, AnchorUpdate as U};
        let a = Anchor { height: 500, hash: [1u8; 32] };
        let rep = |outcome, advanced| CheckpointReport { outcome, anchor_advanced: advanced };

        assert_eq!(anchor_update(Ok(rep(O::AnchorNotSuperseded, false)), Some(a)), U::Unchanged);
        assert_eq!(anchor_update(Ok(rep(O::Admitted, false)), Some(a)), U::Unchanged);

        assert_eq!(anchor_update(Ok(rep(O::StoredAsAnchor, true)), Some(a)), U::Advanced(a));

        assert_eq!(anchor_update(Ok(rep(O::Unverified, false)), Some(a)), U::Unverified);
        assert_eq!(anchor_update(Ok(rep(O::Unverified, false)), None), U::Unverified);
    }

    #[test]
    fn held_better_branch_builds_no_template() {
        use plaine_chain::BranchVerdict as V;

        assert!(refuse_template(&report(1_686, 2_965, V::NeedBodies { missing: 1_279 }), false).is_some());
        assert!(refuse_template(&report(247, 4_239, V::Stranded { cap: 30 }), false).is_some());

        assert!(refuse_template(&report(247, 247, V::Stranded { cap: 30 }), false).is_some());

        assert!(refuse_template(&report(4_239, 4_239, V::OnBest), false).is_none());
        assert!(refuse_template(&report(100, 101, V::NeedBodies { missing: 1 }), false).is_none());
        assert!(refuse_template(&report(100, 102, V::NeedBodies { missing: 2 }), false).is_none());
        assert!(
            refuse_template(&report(100, 103, V::NeedBodies { missing: 3 }), false).is_some(),
            "the tolerance must be a bound, not a direction"
        );

        assert!(
            TEMPLATE_LAG_MAX * 10 < plaine_consensus::constants::MAX_REORG_DEPTH,
            "the template lag tolerance is within an order of magnitude of the reorg cap"
        );
    }

    #[test]
    fn transport_can_hold_templates_back() {
        use plaine_chain::BranchVerdict as V;

        let healthy = report(50, 50, V::OnBest);
        assert!(
            refuse_template(&healthy, false).is_none(),
            "the arena half must still pass a node that is genuinely on the best branch"
        );
        assert!(
            refuse_template(&healthy, true).is_some(),
            "transport refused a better branch for depth, so mining must be held back"
        );
    }

    #[test]
    fn stranded_report_expires() {
        let f = StrandedFlag::default();
        f.tick(1_000);
        assert!(!f.recent(), "an untouched flag must not hold templates back");
        f.note(1_000);
        assert!(f.recent());
        f.tick(1_000 + STRANDED_TEMPLATE_HOLD_SECS - 1);
        assert!(f.recent(), "it must outlive one p2p audit interval by a wide margin");
        f.tick(1_000 + STRANDED_TEMPLATE_HOLD_SECS + 1);
        assert!(!f.recent(), "a node that rejoined stayed idle for ever");
        assert!(
            STRANDED_TEMPLATE_HOLD_SECS > 4 * 60,
            "the hold must cover several re-emissions, or a single missed audit resumes mining"
        );
    }

    #[test]
    fn healthy_tip_gets_template() {
        let (chain, _tip, _interp, _w, _m) = rig();
        let clock = SysClock::new();
        let mut token = OnConsensusThread::claim();
        assert!(
            build_template(&mut token, &chain, &clock, &[], &[7u8; 20], &StrandedFlag::default())
                .is_some(),
            "a node at height 0 on the only branch it holds refused to build"
        );
        assert!(refuse_template(&chain.branch_report(), false).is_none());
    }

    #[test]
    fn publish_refreshes_transport_lists() {
        let (chain, tip, interp, wanted, mempool) = rig();
        let poison = [0xEEu8; 32];
        *wanted.lock().expect("cell") = Arc::new(vec![poison]);
        *mempool.lock().expect("cell") = Arc::new(vec![poison]);

        let cells: AnchorCells = (
            Arc::new(std::sync::Mutex::new(Some(plaine_p2p::traits::Anchor {
                height: 9_999,
                hash: poison,
            }))),
            Arc::new(std::sync::Mutex::new(Arc::new(vec![(9_999u64, poison)]))),

            Arc::new(std::sync::Mutex::new(Some(
                plaine_p2p::traits::SignedCheckpoint {
                    height: 9_999,
                    hash: poison,
                    sigs: Vec::new(),
                },
            ))),
        );

        publish(&chain, &tip, &interp, &wanted, &mempool, &cells);

        assert!(
            cells.0.lock().expect("anchor").is_none(),
            "the anchor cell was never republished"
        );
        assert!(
            cells.1.lock().expect("enforced").is_empty(),
            "the enforcement map was never republished"
        );
        assert!(
            cells.2.lock().expect("anchor record").is_none(),
            "the anchor record was never republished, so GETCHECKPOINT answers for the wrong chain"
        );

        assert!(
            !wanted.lock().expect("cell").contains(&poison),
            "the missing-body list was never republished, so the fetcher is asking for a \
             branch the chain has long since forgotten"
        );
        assert!(
            !mempool.lock().expect("cell").contains(&poison),
            "the relayable-id list was never republished, so we announce txs we no longer hold"
        );

        assert_eq!(tip.get().height, chain.tip().height);
    }

    fn refused(height: u64) -> plaine_chain::Accepted {
        plaine_chain::Accepted {
            connected: 0,
            duplicates: 0,
            rejected: 1,
            staged: 0,
            verified_height: 0,
            first_rejection: Some(plaine_chain::Rejection {
                hash: [9u8; 32],
                height,
                repair_from: height - 1,
                why: "the chain does not hold the parent",
            }),
            first_held: None,
        }
    }

    fn parked(height: u64, hash: [u8; 32]) -> plaine_chain::Accepted {
        plaine_chain::Accepted {
            connected: 0,
            duplicates: 0,
            rejected: 0,
            staged: 1,
            verified_height: 0,
            first_rejection: None,
            first_held: Some(plaine_chain::Held { hash, height }),
        }
    }

    #[test]
    fn refusal_handed_back_to_transport() {
        let cell = std::sync::Mutex::new(None);
        report_headers(&cell, &std::sync::Mutex::new(None), 7, &refused(42));
        assert_eq!(
            *cell.lock().expect("cell"),
            Some(crate::wire::net::Break {
                height: 41,
                why: "the chain does not hold the parent"
            }),
            "the chain refused a header we asked for and the transport was not told, so the branch can never be re-offered"
        );
    }

    #[test]
    fn unknown_parent_repaired_from_parent() {
        let cell = std::sync::Mutex::new(None);
        report_headers(&cell, &std::sync::Mutex::new(None), 7, &refused(42));
        assert_eq!(
            cell.lock().expect("cell").map(|b| b.height),
            Some(41),
            "the break was published at the child's height, not the parent's"
        );
    }

    #[test]
    fn connected_batch_publishes_nothing() {
        let cell = std::sync::Mutex::new(None);
        let ok = plaine_chain::Accepted { connected: 1, verified_height: 9, ..Default::default() };
        report_headers(&cell, &std::sync::Mutex::new(None), 7, &ok);
        assert_eq!(*cell.lock().expect("cell"), None);
    }

    #[test]
    fn parked_header_is_hold_not_break() {
        let breaks = std::sync::Mutex::new(None);
        let holds = std::sync::Mutex::new(None);
        report_headers(&breaks, &holds, 7, &parked(148, [7u8; 32]));
        assert_eq!(
            *holds.lock().expect("cell"),
            Some(plaine_p2p::traits::Held { hash: [7u8; 32], height: 148 })
        );
        assert_eq!(
            *breaks.lock().expect("cell"),
            None,
            "a parked header is not a refusal and must not be published as a break"
        );
    }

    #[test]
    fn batch_refuse_and_park_publishes_both() {
        let breaks = std::sync::Mutex::new(None);
        let holds = std::sync::Mutex::new(None);
        let mut a = refused(42);
        a.first_held = Some(plaine_chain::Held { hash: [3u8; 32], height: 40 });
        report_headers(&breaks, &holds, 7, &a);
        assert_eq!(breaks.lock().expect("cell").map(|b| b.height), Some(41));
        assert_eq!(holds.lock().expect("cell").map(|h| h.height), Some(40));
    }

    #[test]
    fn lowest_parked_header_reported() {
        let holds = std::sync::Mutex::new(None);
        let breaks = std::sync::Mutex::new(None);
        report_headers(&breaks, &holds, 7, &parked(90, [9u8; 32]));
        report_headers(&breaks, &holds, 7, &parked(50, [5u8; 32]));
        report_headers(&breaks, &holds, 7, &parked(70, [7u8; 32]));
        assert_eq!(holds.lock().expect("cell").map(|h| h.height), Some(50));
    }

    #[test]
    fn connected_batch_parks_nothing() {
        let holds = std::sync::Mutex::new(None);
        let ok = plaine_chain::Accepted { connected: 1, verified_height: 9, ..Default::default() };
        report_headers(&std::sync::Mutex::new(None), &holds, 7, &ok);
        assert_eq!(*holds.lock().expect("cell"), None);
    }
}
