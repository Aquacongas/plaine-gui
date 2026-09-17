pub mod body_track;
pub mod header_track;
pub mod recovery;
pub mod rotation;
pub mod staging;
pub mod stall;
pub mod tree;
pub mod tx_relay;

use crate::config::P2pConfig;
use crate::constants::*;
use crate::gate::g2_context::{check_context, BitsRule, ContextParams};
use crate::gate::{check_structure, Budgets, RejectCache, Rejection};
use crate::metrics::Metrics;
use crate::peer::inbox::PauseCause;
use crate::peer::score::{Offence, Verdict};
use crate::peer::Session;
use crate::sync::body_track::{BodyAction, BodyTrack};
use crate::sync::header_track::{HState, HeaderCtx, HeaderTrack, PeerClaim};
use crate::sync::recovery::{Audit, Quarantine, RecoveryGuard};
use crate::sync::staging::VerifyOutcome;
use crate::sync::tree::ForkTree;
use crate::sync::tx_relay::TxRelay;
use crate::traits::*;
use crate::wire::msg::Msg;
use plaine_consensus::constants::MEDIAN_TIME_SPAN;
use plaine_consensus::rules::median_time_past;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadReason {
    DialTimeout,
    HandshakeTimeout,
    PongTimeout,
    Protocol,
    Banned,
    LocalBackpressure,
    ForeignNetwork,
    SelfConnection,
    UselessPeer,
}

#[derive(Clone, Debug)]
pub enum Event {
    PeerReady {
        peer: PeerId,
        ip: [u8; 16],
        outbound: bool,
        height: u64,
        work: [u8; 32],
        tip: Hash32,
        services: u32,
    },

    PeerGone {
        peer: PeerId,
    },

    Headers {
        peer: PeerId,
        raw: Vec<[u8; HEADER_BYTES]>,
    },

    Body {
        peer: PeerId,
        hash: Hash32,
        height: u64,
        bytes: Vec<u8>,
    },

    NotFound {
        peer: PeerId,
        hash: Hash32,
    },

    Announced {
        peer: PeerId,
        blocks: Vec<Hash32>,
    },

    Paused {
        peer: PeerId,
        cause: PauseCause,
    },

    Unpaused {
        peer: PeerId,
    },

    Checkpoint {
        peer: PeerId,
        cp: SignedCheckpoint,
    },
    AnchorAdvanced,

    AnchorContradiction {
        height: u64,
        hash: Hash32,
    },

    AnnouncedTx {
        peer: PeerId,
        txids: Vec<Hash32>,
    },

    Tx {
        peer: PeerId,
        txid: Hash32,
        bytes: Vec<u8>,
    },

    NotFoundTx {
        peer: PeerId,
        txid: Hash32,
    },
    SinkFatal(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Send { peer: PeerId, msg: Msg },

    Disconnect { peer: PeerId, reason: DeadReason },

    Ban { peer: PeerId, ms: u64 },

    Score { peer: PeerId, offence: Offence },

    Dial { count: usize, widen: bool },

    Designate { peer: PeerId },

    Undesignate { peer: PeerId },

    WaiveCooldown { peer: PeerId },

    SyncCooldown { peer: PeerId, ms: u64 },

    QuarantineBranch { branch: Hash32 },
    RepublishTip,
    Say(Condition),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ForkWant {
    height: u64,
    asked: Option<(PeerId, Mono)>,
    attempts: u32,
    retry_at: Option<Mono>,
    gave_up_said: bool,
}

// Single owner of all sync state. Driven only through on_event/on_tick on one
// thread, so nothing here is shared or locked - the socket layer hands work in
// and takes Actions out. That is what keeps the hot path a plain &mut self.
pub struct SyncEngine<C: ChainView, S: BlockSink, V: PowVerifier, B: BitsRule> {
    chain: Arc<C>,
    sink: Arc<S>,
    pow: Arc<V>,
    bits: Arc<B>,
    cfg: P2pConfig,
    pub header: HeaderTrack,
    pub body: BodyTrack,
    pub tx: TxRelay,
    peers: BTreeMap<PeerId, Session>,
    reject: RejectCache,
    quarantine: Quarantine,
    guard: RecoveryGuard,
    budgets: Budgets,
    tree: ForkTree,
    // dedup memo of headers already seen; FIFO eviction keeps it bounded (entries
    // below the reorg cap are aged out, see forget_stale_known)
    known: HashMap<Hash32, HeaderRec>,
    known_order: VecDeque<Hash32>,
    // accepted by the chain but still in staging, not yet connected
    parked: Vec<(HeaderRec, Mono, [u8; 4])>,
    wanted: BTreeMap<u64, Hash32>,
    fork_wanted: BTreeMap<Hash32, ForkWant>,
    fork_said: bool,
    backlog_stuck: bool,
    no_supplier_said: Option<Mono>,
    probing: VecDeque<(Hash32, Mono)>,
    last_republish: Mono,
    last_refusal: Option<(u64, Mono)>,
    repair_watch: Option<(u64, u64, u32, &'static str)>,
    committed: Option<(Hash32, u64, PeerId, Mono)>,
    sink_suspended: bool,
    pub metrics: Metrics,
    conditions: Vec<Condition>,
    now_unix: u64,
    fatal: Option<&'static str>,
}

impl<C: ChainView, S: BlockSink, V: PowVerifier, B: BitsRule> SyncEngine<C, S, V, B> {
    pub fn new(
        chain: Arc<C>,
        sink: Arc<S>,
        pow: Arc<V>,
        bits: Arc<B>,
        cfg: P2pConfig,
        seed: u64,
        now: Mono,
    ) -> Self {
        let tip = chain.tip();
        SyncEngine {
            header: HeaderTrack::new(tip.height, tip.hash, seed, now),
            body: BodyTrack::new(tip.height),
            tx: TxRelay::new(),
            peers: BTreeMap::new(),
            reject: RejectCache::new(),
            quarantine: Quarantine::new(),
            guard: RecoveryGuard::new(),
            budgets: Budgets::new(now),
            tree: ForkTree::new(),
            known: HashMap::new(),
            known_order: VecDeque::new(),
            parked: Vec::new(),
            wanted: BTreeMap::new(),
            fork_wanted: BTreeMap::new(),
            fork_said: false,
            backlog_stuck: false,
            no_supplier_said: None,
            probing: VecDeque::new(),
            last_republish: now,
            last_refusal: None,
            repair_watch: None,
            committed: None,
            sink_suspended: false,
            metrics: Metrics::default(),
            conditions: Vec::new(),
            now_unix: tip.time,
            fatal: None,
            chain,
            sink,
            pow,
            bits,
            cfg,
        }
    }

    pub fn set_now_unix(&mut self, t: u64) {
        self.now_unix = t;
    }

    pub fn peers(&self) -> &BTreeMap<PeerId, Session> {
        &self.peers
    }

    pub fn peer_mut(&mut self, p: PeerId) -> Option<&mut Session> {
        self.peers.get_mut(&p)
    }

    pub fn drain_conditions(&mut self) -> Vec<Condition> {
        core::mem::take(&mut self.conditions)
    }

    pub fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    pub fn verified_height(&self) -> u64 {
        self.header.staging.verified_height()
    }

    pub fn fatal(&self) -> Option<&'static str> {
        self.fatal
    }

    pub fn quarantine(&self) -> &Quarantine {
        &self.quarantine
    }

    pub fn reject_cache(&self) -> &RejectCache {
        &self.reject
    }

    pub fn on_event(&mut self, ev: Event, now: Mono) -> Vec<Action> {
        let mut out = Vec::new();
        match ev {
            Event::PeerReady {
                peer,
                ip,
                outbound,
                height,
                work,
                tip,
                services,
            } => {
                let mut s = Session::new(peer, ip, outbound, now);
                s.state = crate::peer::PeerState::Ready;
                s.claimed_height = height;
                s.claimed_work = work;
                s.claimed_tip = tip;
                s.services = services;
                s.whitelisted = self.cfg.whitelist.contains(&ip);
                self.peers.insert(peer, s);
                self.header
                    .note_claim(peer, PeerClaim { height, work, tip }, now);
            }
            Event::PeerGone { peer } => {
                self.peers.remove(&peer);
                self.header.forget(peer);
                self.body.release_peer(peer, now);

                self.tx.on_peer_gone(peer);
            }
            Event::Headers { peer, raw } => self.on_headers(peer, raw, now, &mut out),
            Event::Body {
                peer,
                hash,
                height,
                bytes,
            } => {
                if self.fork_wanted.contains_key(&hash) {
                    if let Some(s) = self.peers.get_mut(&peer) {
                        s.record_body();
                        s.last_recv = now;
                    }
                    self.on_fork_body(hash, bytes);
                    return out;
                }
                let requested = self.body.on_body(hash, bytes, height, now);
                if let Some(s) = self.peers.get_mut(&peer) {
                    s.record_body();
                    s.last_recv = now;

                    s.claimed_height = s.claimed_height.max(height);
                    if !requested {
                        out.push(Action::Score {
                            peer,
                            offence: Offence::UnsolicitedBody,
                        });
                    }
                }
                self.body.clear_starvation(&hash);
                self.wanted.retain(|_, h| *h != hash);
            }
            Event::NotFound { peer, hash } => {
                if let Some(s) = self.peers.get_mut(&peer) {
                    s.last_recv = now;
                }

                if let Some(w) = self.fork_wanted.get_mut(&hash) {
                    w.asked = None;
                    w.attempts = w.attempts.saturating_add(1);
                }

                if self.body.on_notfound(&hash, peer, now) {
                    if let Some(s) = self.peers.get_mut(&peer) {
                        s.body_misses += 1;
                        if s.body_misses >= 3 {
                            s.body_slot_lost_until = Some(now.plus_ms(BODY_SLOT_LOST_MS));
                            s.body_misses = 0;
                        }
                    }
                }
            }
            Event::Announced { peer, blocks } => self.on_announced(peer, &blocks, now, &mut out),
            Event::Paused { peer, cause } => {
                if let Some(s) = self.peers.get_mut(&peer) {
                    s.pause(cause, now);
                }

                if cause.suspends_liveness_clocks() && self.header.sync_peer() == Some(peer) {
                    self.header.clock_mut().suspend(now);
                }
                if cause.peer_points() > 0 {
                    out.push(Action::Score {
                        peer,
                        offence: Offence::PeerOverran,
                    });
                }
            }
            Event::Unpaused { peer } => {
                if let Some(s) = self.peers.get_mut(&peer) {
                    s.unpause(now);
                }
                if self.header.sync_peer() == Some(peer) {
                    self.header.clock_mut().resume(now);

                    self.sink_suspended = false;
                }
            }
            Event::Checkpoint { peer, cp } => {
                let Some(s) = self.peers.get_mut(&peer) else {
                    return out;
                };
                s.last_recv = now;
                match s.admit_checkpoint(cp.height, cp.hash, now) {
                    crate::peer::session::CheckpointAdmit::Duplicate => return out,
                    crate::peer::session::CheckpointAdmit::OverRate => {
                        out.push(Action::Score {
                            peer,
                            offence: Offence::GetCheckpointAbuse,
                        });
                        return out;
                    }
                    crate::peer::session::CheckpointAdmit::Accept => {}
                }
                match self.sink.submit_checkpoint(cp) {
                    Ok(AnchorUpdate::Advanced(_)) => {
                        Audit::on_anchor_advanced(&mut self.quarantine, &mut self.reject);
                        self.header.end_episode();
                    }
                    Ok(AnchorUpdate::Unchanged) => {}
                    Ok(AnchorUpdate::Unverified) => {
                        out.push(Action::Score {
                            peer,
                            offence: Offence::CheckpointUnverified,
                        });
                    }
                    Ok(AnchorUpdate::Contradicts { height, hash }) => {
                        self.say(Condition::AnchorContradiction { height, hash });
                        self.header.begin_recovery(now);
                        if self.header.peer_furthest_ahead(&[]).is_none() {
                            self.say(Condition::AnchorChainUnavailable { height, hash });
                        }
                    }
                    Err(SinkError::Full) => {}

                    Err(SinkError::Invalid(_) | SinkError::RefusedAt { .. }) => {
                        out.push(Action::Score {
                            peer,
                            offence: Offence::CheckpointUnverified,
                        });
                    }
                    Err(SinkError::Fatal(m)) => {
                        self.fatal = Some(m);
                        self.say(Condition::SinkFatal(m));
                    }
                }
            }
            Event::AnchorAdvanced => {
                Audit::on_anchor_advanced(&mut self.quarantine, &mut self.reject);
                self.header.end_episode();
            }
            Event::AnchorContradiction { height, hash } => {
                self.say(Condition::AnchorContradiction { height, hash });

                self.header.begin_recovery(now);
                if self.header.peer_furthest_ahead(&[]).is_none() {
                    self.say(Condition::AnchorChainUnavailable { height, hash });
                }
            }
            Event::AnnouncedTx { peer, txids } => {
                if let Some(sess) = self.peers.get_mut(&peer) {
                    sess.last_recv = now;
                }
                self.tx.on_announced(peer, &txids, now, &mut out);
            }
            Event::Tx { peer, txid, bytes } => {
                if let Some(sess) = self.peers.get_mut(&peer) {
                    sess.last_recv = now;
                }

                if !self.tx.on_tx(peer, txid, now, &mut out) {
                    return out;
                }
                match self.sink.submit_tx(txid, bytes) {
                    Ok(()) => self.tx.on_accepted(txid),
                    Err(SinkError::Fatal(w)) => {
                        self.fatal = Some(w);
                        self.say(Condition::SinkFatal(w));
                    }

                    Err(_) => {}
                }
            }
            Event::NotFoundTx { peer, txid } => {
                if let Some(sess) = self.peers.get_mut(&peer) {
                    sess.last_recv = now;
                }

                self.tx.on_not_found(peer, txid);
            }
            Event::SinkFatal(msg) => {
                self.fatal = Some(msg);
                self.say(Condition::SinkFatal(msg));
            }
        }
        self.apply(&mut out, now);
        out
    }

    pub fn on_tick(&mut self, now: Mono) -> Vec<Action> {
        let mut out = Vec::new();

        if now.expired(self.last_republish, TIP_REPUBLISH_MS) {
            self.last_republish = now;
            out.push(Action::RepublishTip);
        }

        self.announce_tip(now, &mut out);

        let ready: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, s)| s.is_ready())
            .map(|(id, _)| *id)
            .collect();
        let chain = Arc::clone(&self.chain);
        self.tx
            .on_tick(now, &ready, || chain.mempool_txids(), &mut out);

        self.verify_pass(now, &mut out);

        self.audit_commit(now);

        let mut dead: Vec<(PeerId, DeadReason)> = Vec::new();
        for (id, s) in self.peers.iter() {
            if s.pong_expired(now) {
                dead.push((*id, DeadReason::PongTimeout));
            } else if s.pause_expired(now) {
                dead.push((*id, DeadReason::LocalBackpressure));
            } else if s.is_useless(now) {
                dead.push((*id, DeadReason::UselessPeer));
            }
        }
        for (id, reason) in dead {
            if reason == DeadReason::LocalBackpressure {
                Metrics::inc(&self.metrics.pause_max_disconnects);
            }
            self.peers.remove(&id);
            self.header.forget(id);
            self.body.release_peer(id, now);
            out.push(Action::Disconnect { peer: id, reason });
        }

        self.tick_parked(now, &mut out);

        {
            let ctx = HeaderCtx {
                peers: &self.peers,
                our_tip: self.chain.tip(),
                now_unix: self.now_unix,
                anchor: self.chain.anchor(),
                locator: self.chain.locator(),
            };
            let was = self.header.state();
            let acts = self.header.tick(&ctx, now);

            if was != HState::DeepRecovery && self.header.state() == HState::DeepRecovery {
                Metrics::inc(&self.metrics.deep_recoveries);
            }
            out.extend(acts);
        }

        {
            let ctx = HeaderCtx {
                peers: &self.peers,
                our_tip: self.chain.tip(),
                now_unix: self.now_unix,
                anchor: self.chain.anchor(),
                locator: self.chain.locator(),
            };
            let mut more = Vec::new();
            if self.header.state() == HState::HeaderSync {
                self.header.request_more(&ctx, now, &mut more);
            }
            out.extend(more);
        }

        self.tick_bodies(now, &mut out);

        Audit::tick(&mut self.quarantine, now);

        self.forget_stale_known();

        self.apply(&mut out, now);
        out
    }

    fn announce_tip(&mut self, now: Mono, out: &mut Vec<Action>) {
        let tip = self.chain.tip();
        if self.now_unix > tip.time.saturating_add(SYNC_WINDOW_SECS) {
            return;
        }

        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for id in ids {
            let Some(s) = self.peers.get_mut(&id) else {
                continue;
            };
            if !s.is_ready() {
                continue;
            }

            if s.announced_to_us == Some(tip.hash) {
                continue;
            }

            if s.announced_to_them == Some(tip.hash) {
                if s.inv_repeats == 0 {
                    continue;
                }
                match s.last_inv_sent {
                    Some(t) if !now.expired(t, TIP_REPUBLISH_MS) => continue,
                    _ => {}
                }
                s.inv_repeats -= 1;
            } else {
                if let Some(t) = s.last_inv_sent {
                    if !now.expired(t, TRICKLE_MS) {
                        continue;
                    }
                }

                s.inv_repeats = INV_REPEATS;
            }
            s.last_inv_sent = Some(now);
            s.announced_to_them = Some(tip.hash);
            Metrics::inc(&self.metrics.inv_out);
            out.push(Action::Send {
                peer: id,
                msg: Msg::Inv(vec![crate::wire::msg::InvItem {
                    kind: crate::wire::msg::InvKind::Block,
                    hash: tip.hash,
                }]),
            });
        }
    }

    // Only forget dedup entries below the reorg floor. Anything within the cap of
    // the tip could still come back on a competing branch, so it stays known.
    fn forget_stale_known(&mut self) {
        let floor = self.chain.tip().height.saturating_sub(MAX_REORG_DEPTH);
        if floor == 0 || self.known.is_empty() {
            return;
        }
        let doomed: Vec<Hash32> = self
            .known
            .iter()
            .filter(|(_, r)| r.height <= floor)
            .map(|(h, _)| *h)
            .collect();
        for h in doomed {
            self.known.remove(&h);
            self.known_order.retain(|x| *x != h);
        }
    }

    fn remember(&mut self, r: HeaderRec) {
        if self.known.insert(r.hash, r).is_none() {
            self.known_order.push_back(r.hash);
            while self.known_order.len() > KNOWN_HEADERS_MAX {
                if let Some(v) = self.known_order.pop_front() {
                    self.known.remove(&v);
                }
            }
        }
    }

    fn forget_known_from(&mut self, height: u64) {
        let doomed: Vec<Hash32> = self
            .known
            .iter()
            .filter(|(_, r)| r.height >= height)
            .map(|(h, _)| *h)
            .collect();
        for h in doomed {
            self.known.remove(&h);
            self.known_order.retain(|x| *x != h);
        }
    }

    pub fn known_len(&self) -> usize {
        self.known.len()
    }

    pub fn tree_len(&self) -> usize {
        self.tree.len()
    }

    pub fn deduplicates(&self, h: &Hash32) -> bool {
        self.known.contains_key(h) || self.tree.get(h).is_some()
    }

    pub fn wants_body_of(&self, h: &Hash32) -> bool {
        self.wanted.values().any(|x| x == h) || self.fork_wanted.contains_key(h)
    }

    fn on_announced(&mut self, peer: PeerId, blocks: &[Hash32], now: Mono, out: &mut Vec<Action>) {
        Metrics::inc(&self.metrics.inv_in);
        if blocks.is_empty() {
            return;
        }

        match self.peers.get_mut(&peer) {
            Some(s) => {
                s.last_recv = now;
                s.announced_to_us = blocks.last().copied();
            }
            None => return,
        }

        if !self.peers[&peer].probe_due(now) {
            Metrics::inc(&self.metrics.gate4_throttle);
            return;
        }

        if !self.budgets.probe_admits(now) {
            Metrics::inc(&self.metrics.gate4_throttle);
            return;
        }

        self.expire_probes(now);

        let mut novel: Option<Hash32> = None;
        let mut dups = 0u32;
        let mut seam_used = false;
        let our_tip = self.chain.tip().height;
        for h in blocks.iter().take(INV_BLOCKS_PER_MSG_MAX) {
            if self.reject.contains(h)
                || self.known.contains_key(h)
                || self.header.staging.contains(h)
                || self.tree.get(h).is_some()
                || self.quarantine.contains(h, now)
            {
                dups += 1;

                let in_tree = self.tree.get(h).map(|r| r.height);
                let height = self.known.get(h).map(|r| r.height).or(in_tree);
                if let (Some(height), Some(s)) = (height, self.peers.get_mut(&peer)) {
                    s.claimed_height = s.claimed_height.max(height);
                }

                if let Some(th) = in_tree {
                    if th <= our_tip {
                        continue;
                    }
                    self.header.note_claim(
                        peer,
                        PeerClaim {
                            height: th,
                            work: [0u8; 32],
                            tip: *h,
                        },
                        now,
                    );
                }
                continue;
            }
            if self.probing.iter().any(|(x, _)| x == h) {
                continue;
            }
            if !seam_used {
                seam_used = true;
                if let Some(r) = self.chain.header_by_hash(h) {
                    dups += 1;
                    if let Some(s) = self.peers.get_mut(&peer) {
                        s.claimed_height = s.claimed_height.max(r.height);
                    }
                    continue;
                }
            } else {
                break;
            }
            novel = Some(*h);
            break;
        }

        if dups > 0 {
            if let Some(s) = self.peers.get_mut(&peer) {
                for _ in 0..dups {
                    if s.note_dup_inv(now) {
                        out.push(Action::Score {
                            peer,
                            offence: Offence::DupInv,
                        });
                    }
                }
            }
        }

        let Some(h) = novel else {
            return;
        };

        self.budgets.probe_commit();
        self.probing.push_back((h, now));
        while self.probing.len() > INV_PROBE_INFLIGHT_MAX {
            self.probing.pop_front();
        }
        if let Some(s) = self.peers.get_mut(&peer) {
            s.note_probe(now);
        }
        Metrics::inc(&self.metrics.inv_probes);
        out.push(Action::Send {
            peer,
            msg: Msg::GetHeaders {
                locator: self.chain.locator(),
                stop: [0u8; 32],
            },
        });
    }

    fn say_refusal(&mut self, height: u64, why: &'static str, from: PeerId, now: Mono) {
        if let Some((h, at)) = self.last_refusal {
            if h == height && !now.expired(at, TRACKING_AUDIT_MS) {
                return;
            }
        }
        self.last_refusal = Some((height, now));
        self.say(Condition::HeaderRefusedByChain { height, why, from });
        self.watch_repair(height, why);
    }

    fn watch_repair(&mut self, height: u64, why: &'static str) {
        let tip = self.chain.tip().height;
        let repeats = repair_repeat(self.repair_watch, height, tip);
        self.repair_watch = Some((height, tip, repeats, why));
        if repeats >= REPAIR_STUCK_REPEATS {
            self.say(Condition::HeaderRepairStuck {
                height,
                why,
                repeats,
                our_tip: tip,
            });
        }
    }

    pub fn repair_stuck(&self) -> Option<(u64, &'static str, u32)> {
        match self.repair_watch {
            Some((h, t, n, why)) if n >= REPAIR_STUCK_REPEATS && t == self.chain.tip().height => {
                Some((h, why, n))
            }
            _ => None,
        }
    }

    fn note_committed(&mut self, hash: Hash32, height: u64, from: PeerId, now: Mono) {
        match self.committed {
            Some((_, h, _, _)) if h >= height => {}
            _ => self.committed = Some((hash, height, from, now)),
        }
    }

    fn audit_commit(&mut self, now: Mono) {
        let Some((hash, height, from, at)) = self.committed else {
            return;
        };
        if !now.expired(at, TRACKING_AUDIT_MS) {
            return;
        }
        if self.chain.header_by_hash(&hash).is_some() {
            self.committed = None;

            self.repair_watch = None;
            return;
        }
        self.committed = None;

        let floor = self.chain.tip().height.saturating_sub(MAX_REORG_DEPTH);
        let mut suspect: Vec<(u64, Hash32)> = self
            .known
            .iter()
            .filter(|(_, r)| r.height > floor)
            .map(|(h, r)| (r.height, *h))
            .collect();
        suspect.sort_unstable();
        suspect.truncate(WANTED_MAX);
        let height = suspect
            .iter()
            .find(|(_, h)| self.chain.header_by_hash(h).is_none())
            .map(|(x, _)| *x)
            .unwrap_or(height);
        Metrics::inc(&self.metrics.gate2_reject);
        self.forget_known_from(height);

        self.tree.truncate_from(height);

        self.say_refusal(
            height,
            "the chain does not hold a header this engine committed",
            from,
            now,
        );
    }

    fn repair_break(&mut self, height: u64, why: &'static str, from: PeerId, now: Mono) {
        self.forget_known_from(height);

        self.header.staging.truncate_from(height);
        self.tree.truncate_from(height);

        self.committed = None;
        self.say_refusal(height, why, from, now);
    }

    fn note_held(&mut self, held: Option<crate::traits::Held>) {
        let Some(h) = held else { return };
        Metrics::inc(&self.metrics.headers_held);

        self.known.remove(&h.hash);
        self.known_order.retain(|x| *x != h.hash);
        self.tree.forget(&h.hash);
        self.wanted.retain(|_, v| *v != h.hash);
        self.fork_wanted.remove(&h.hash);

        if self.committed.is_some_and(|(hash, ..)| hash == h.hash) {
            self.committed = None;
        }
    }

    fn expire_probes(&mut self, now: Mono) {
        while let Some((_, at)) = self.probing.front() {
            if now.expired(*at, INV_PROBE_INFLIGHT_TTL_MS) {
                self.probing.pop_front();
            } else {
                break;
            }
        }
    }

    fn try_probe(&mut self, peer: PeerId, is_sync: bool, now: Mono) -> bool {
        let Some(s) = self.peers.get(&peer) else {
            return false;
        };
        if !s.probe_due(now) {
            Metrics::inc(&self.metrics.gate4_throttle);
            return false;
        }
        if !is_sync {
            if !self.budgets.probe_admits(now) {
                Metrics::inc(&self.metrics.gate4_throttle);
                return false;
            }
            self.budgets.probe_commit();
        }
        if let Some(s) = self.peers.get_mut(&peer) {
            s.note_probe(now);
        }
        Metrics::inc(&self.metrics.inv_probes);
        true
    }

    fn on_headers(
        &mut self,
        peer: PeerId,
        raw: Vec<[u8; HEADER_BYTES]>,
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        let is_sync = self.header.sync_peer() == Some(peer);
        let mut solicited = false;
        if let Some(s) = self.peers.get_mut(&peer) {
            s.last_recv = now;

            solicited = s.take_solicited(now);
        }

        // Gates run cheapest-first: byte budget (g4) before we parse, structure
        // (g1) before dedup (g0), context (g2) last, on only what survives. A
        // flood should pay as little CPU as possible before it's dropped.
        let bytes = (raw.len() * HEADER_BYTES) as u64;
        if !self.budgets.admit_frame(bytes, is_sync, now) {
            Metrics::inc(&self.metrics.gate4_throttle);

            if is_sync {
                self.header.note_local_refusal(now);
            }
            return;
        }
        Metrics::add(&self.metrics.bytes_in, bytes);

        let mut raw = raw;
        if !is_sync && raw.len() > UNSOLICITED_HEADERS_MAX {
            if !solicited {
                out.push(Action::Score {
                    peer,
                    offence: Offence::UnsolicitedHeaders,
                });
                return;
            }
            raw.truncate(INV_HEADERS_ADMIT_MAX);
        }

        // a sync peer's next batch must continue exactly where staging left off;
        // anything else is an unsolicited answer, not a fork to explore.
        let expect = if is_sync && self.header.staging.staged_len() > 0 {
            Some(self.header.staging.staged_tip())
        } else {
            None
        };
        let recs = match check_structure(&raw, expect) {
            Ok(r) => r,
            Err(rej) => {
                Metrics::inc(&self.metrics.gate1_reject);
                self.charge(peer, &rej, now, out);
                return;
            }
        };

        if is_sync {
            self.header.note_answer();
        }

        if is_sync {
            if let Some(last) = recs.last() {
                let existing = PeerClaim {
                    height: last.height,
                    work: [0u8; 32],
                    tip: last.hash,
                };
                self.header.note_claim(peer, existing, now);
                if let Some(s) = self.peers.get_mut(&peer) {
                    s.claimed_height = s.claimed_height.max(last.height);
                    s.claimed_tip = last.hash;
                }
            }
        }

        let mut staged = 0u64;
        for mut rec in recs {
            if self.reject.contains(&rec.hash) {
                Metrics::inc(&self.metrics.gate0_dedup_hits);
                continue;
            }
            if self.known.contains_key(&rec.hash)
                || self.header.staging.contains(&rec.hash)
                || self.chain.header_by_hash(&rec.hash).is_some()
            {
                Metrics::inc(&self.metrics.gate0_dedup_hits);

                if !is_sync {
                    if let Some(s) = self.peers.get_mut(&peer) {
                        s.claimed_height = s.claimed_height.max(rec.height);
                    }
                    self.header.note_claim(
                        peer,
                        PeerClaim {
                            height: rec.height,
                            work: [0u8; 32],
                            tip: rec.hash,
                        },
                        now,
                    );
                }

                if rec.height > self.body.applied() && !self.chain.have_body(&rec.hash) {
                    self.want_body(rec.height, rec.hash);
                }
                continue;
            }
            if self.quarantine.contains(&rec.hash, now) {
                continue;
            }

            let Some(parent) = self.lookup(&rec.prev_hash) else {
                if self.try_probe(peer, is_sync, now) {
                    out.push(Action::Send {
                        peer,
                        msg: Msg::GetHeaders {
                            locator: self.chain.locator(),
                            stop: [0u8; 32],
                        },
                    });
                }
                break;
            };

            let mtp = self.mtp_for(&parent);
            let our_tip = self.chain.tip();
            let fork_depth = our_tip.height.saturating_sub(parent.height);
            let params = ContextParams {
                now_unix: self.now_unix,
                mtp,
                fork_depth,
                branch_contains_anchor: self.branch_has_anchor(&rec),
            };
            match check_context(&*self.bits, &parent, &mut rec, &params) {
                Ok(()) => {}
                Err(Rejection::TimeFuture { by_secs }) => {
                    // a future-dated header may just mean our own clock is behind,
                    // so we park it and retry later instead of scoring the peer.
                    let group = self.peers.get(&peer).map(|s| s.group).unwrap_or([0u8; 4]);
                    if self.parked.len() < TIME_PARK_MAX {
                        self.parked.push((rec, now, group));
                    }
                    let _ = by_secs;
                    break;
                }
                Err(rej) => {
                    if matches!(rej, Rejection::ReorgTooDeep { .. }) {
                        Metrics::inc(&self.metrics.gate2_reject);
                    }
                    if matches!(rej, Rejection::ReorgTooDeep { .. }) && is_sync {
                        self.header.begin_recovery(now);
                        self.guard.note_failure(now);
                        if self.guard.flapping(now) {
                            self.header.enter_quarantine(now, out);
                        }
                    }
                    if rej.is_permanent() {
                        self.reject.insert(rec.hash);
                    }
                    self.charge(peer, &rej, now, out);
                    break;
                }
            }

            if !is_sync {
                if !self.admit_announced(peer, rec, now, out) {
                    break;
                }
                continue;
            }

            if !self.header.staging.push(rec, peer) {
                break;
            }

            self.tree.insert(rec);
            staged += 1;
        }

        if let Some(s) = self.peers.get_mut(&peer) {
            s.record_delivery(staged, now);
            s.refresh_headers_only();
        }
        if is_sync {
            self.header.note_progress(staged, 0, now);
        }
    }

    fn admit_announced(
        &mut self,
        peer: PeerId,
        rec: HeaderRec,
        now: Mono,
        out: &mut Vec<Action>,
    ) -> bool {
        if let Some(held) = self.tree.get(&rec.hash).copied() {
            Metrics::inc(&self.metrics.gate0_dedup_hits);

            if held.height > self.chain.tip().height {
                self.header.note_claim(
                    peer,
                    PeerClaim {
                        height: held.height,
                        work: [0u8; 32],
                        tip: held.hash,
                    },
                    now,
                );
            }
            if let Some(s) = self.peers.get_mut(&peer) {
                s.claimed_height = s.claimed_height.max(held.height);
            }
            return true;
        }
        let cost = self.pow.cost_ms();
        let Some(s) = self.peers.get_mut(&peer) else {
            return false;
        };
        if !s.pow_budget.take(cost, now) {
            Metrics::inc(&self.metrics.gate4_throttle);
            return false;
        }

        if !self.budgets.admit_pow_announced(cost, now) {
            Metrics::inc(&self.metrics.gate4_throttle);
            return false;
        }
        self.header.staging.pow_calls += 1;
        if !self.pow.verify(&rec.raw) {
            self.reject.insert(rec.hash);
            out.push(Action::Score {
                peer,
                offence: Offence::BadPow,
            });
            return false;
        }

        self.header.note_claim(
            peer,
            PeerClaim {
                height: rec.height,
                work: [0u8; 32],
                tip: rec.hash,
            },
            now,
        );
        if let Some(s) = self.peers.get_mut(&peer) {
            s.claimed_height = s.claimed_height.max(rec.height);
            s.claimed_tip = rec.hash;
        }

        match self.sink.submit_headers(HeaderBatch {
            headers: vec![rec],
            source: peer,
            door: crate::traits::Door::Announced,
        }) {
            Ok(a) => self.note_held(a.held),
            Err(SinkError::Full) => return false,
            Err(SinkError::Invalid(why)) => {
                self.say_refusal(rec.height, why, peer, now);
                return false;
            }
            Err(SinkError::RefusedAt { height, why }) => {
                self.repair_break(height, why, peer, now);
                return false;
            }
            Err(SinkError::Fatal(w)) => {
                self.fatal = Some(w);
                self.say(Condition::SinkFatal(w));
                return false;
            }
        }
        self.tree.insert(rec);
        self.note_committed(rec.hash, rec.height, peer, now);

        if rec.height > self.body.applied() && !self.chain.have_body(&rec.hash) {
            self.want_body(rec.height, rec.hash);
        }
        true
    }

    fn verify_pass(&mut self, now: Mono, out: &mut Vec<Action>) {
        let anchor = self.chain.anchor();
        let mut verified = 0u64;
        let mut credited: BTreeMap<PeerId, (u64, u64)> = BTreeMap::new();
        let mut blocked = false;
        loop {
            if self.header.staging.staged_len() == 0 {
                break;
            }

            if !self.sink.capacity().admits(HEADER_BYTES as u64) {
                blocked = true;
                break;
            }

            let cost = self.pow.cost_ms();
            let costs = self
                .header
                .staging
                .front_costs_interpreter(anchor.as_ref(), self.cfg.verify_all_pow);
            if costs && !self.budgets.pow_affordable(cost, now) {
                break;
            }
            let before = self.header.staging.pow_calls;
            let outcome = self.header.staging.verify_step(
                &*self.pow,
                anchor.as_ref(),
                self.cfg.verify_all_pow,
            );
            let calls = self.header.staging.pow_calls - before;
            if calls > 0 {
                self.budgets.admit_pow(cost.saturating_mul(calls), now);
            }
            match outcome {
                VerifyOutcome::Idle => break,
                VerifyOutcome::Verified { rec: h, from }
                | VerifyOutcome::FastForwarded { rec: h, from } => {
                    let batch = HeaderBatch {
                        door: crate::traits::Door::Requested,
                        headers: vec![h],
                        source: from,
                    };
                    match self.sink.submit_headers(batch) {
                        Ok(a) => self.note_held(a.held),
                        Err(SinkError::Full) => {
                            blocked = true;
                            break;
                        }
                        Err(SinkError::Invalid(why)) => {
                            self.say_refusal(h.height, why, from, now);

                            self.header.note_local_refusal(now);

                            self.header.staging.truncate_from(h.height);
                            self.tree.truncate_from(h.height);
                            break;
                        }
                        Err(SinkError::RefusedAt { height, why }) => {
                            self.repair_break(height, why, from, now);

                            self.header.note_local_refusal(now);
                            break;
                        }
                        Err(SinkError::Fatal(m)) => {
                            self.fatal = Some(m);
                            self.say(Condition::SinkFatal(m));
                            break;
                        }
                    }

                    self.header.staging.commit_front();
                    self.remember(h);
                    self.note_committed(h.hash, h.height, from, now);
                    verified += 1;
                    let e = credited.entry(from).or_insert((0, 0));
                    e.0 += 1;
                    e.1 = e.1.max(h.height);
                    if !self.chain.have_body(&h.hash) && h.height > self.body.applied() {
                        self.want_body(h.height, h.hash);
                    }
                }
                VerifyOutcome::BadPow { rec: h, from } => {
                    self.reject.insert(h.hash);

                    self.header.staging.truncate_from(h.height);
                    self.tree.truncate_from(h.height);
                    self.forget_known_from(h.height);
                    out.push(Action::Score {
                        peer: from,
                        offence: Offence::BadPow,
                    });
                    break;
                }
                VerifyOutcome::AnchorMismatch { height, got, from } => {
                    self.reject.insert(got);
                    self.header.staging.truncate_from(height);
                    self.forget_known_from(height);
                    out.push(Action::Score {
                        peer: from,
                        offence: Offence::BadPow,
                    });
                    break;
                }
            }
        }

        self.set_sink_blocked(blocked, now);

        for (peer, (n, top)) in credited {
            if let Some(s) = self.peers.get_mut(&peer) {
                s.record_verified(n, now);
            }

            self.header.note_substantiated(peer, top);
        }
        if verified > 0 {
            Metrics::add(&self.metrics.headers_verified, verified);
            self.header.note_progress(0, verified, now);
        }
    }

    fn set_sink_blocked(&mut self, blocked: bool, now: Mono) {
        self.header.set_commit_bound(blocked);
        if blocked && !self.sink_suspended && !self.header.clock_mut().suspended() {
            self.sink_suspended = true;
            self.header.clock_mut().suspend(now);

            self.say(Condition::QueueOverflow {
                queue: "validate",
                policy: Policy::PauseReads,
            });
        } else if !blocked && self.sink_suspended {
            self.sink_suspended = false;
            self.header.clock_mut().resume(now);
        }
    }

    pub fn interpreter_calls(&self) -> u64 {
        self.header.staging.pow_calls
    }

    pub fn fast_forwarded(&self) -> u64 {
        self.header.staging.fast_forwarded
    }

    fn tick_bodies(&mut self, now: Mono, out: &mut Vec<Action>) {
        self.catch_up_to_the_chain();

        self.drain_bodies(now);

        let (suppliers, liveness_tier) = self.body_suppliers(true, now);

        self.refill_wanted();
        let wanted: Vec<(u64, Hash32)> = self.wanted.iter().map(|(h, x)| (*h, *x)).collect();

        let mut acts = self.body.schedule(&wanted, &suppliers, now);
        acts.extend(self.body.tick(&suppliers, now));

        for a in acts {
            match a {
                BodyAction::Request { peer, hashes } => {
                    Metrics::add(&self.metrics.body_requests, hashes.len() as u64);
                    if let Some(s) = self.peers.get_mut(&peer) {
                        s.bodies_requested_total =
                            s.bodies_requested_total.saturating_add(hashes.len() as u64);
                        s.refresh_headers_only();
                    }
                    let items = hashes
                        .into_iter()
                        .map(|h| crate::wire::msg::InvItem {
                            kind: crate::wire::msg::InvKind::Block,
                            hash: h,
                        })
                        .collect();
                    out.push(Action::Send {
                        peer,
                        msg: Msg::GetData(items),
                    });
                }
                BodyAction::DeadlineMiss { peer } => {
                    if self.header.sync_peer() != Some(peer) && !liveness_tier {
                        out.push(Action::Score {
                            peer,
                            offence: Offence::DeadlineMiss,
                        });
                    }
                    if let Some(s) = self.peers.get_mut(&peer) {
                        s.body_misses += 1;
                        if s.body_misses >= 3 {
                            s.body_slot_lost_until = Some(now.plus_ms(BODY_SLOT_LOST_MS));
                            s.body_misses = 0;
                        }
                    }
                }
                BodyAction::SlotLost { peer } => {
                    if let Some(s) = self.peers.get_mut(&peer) {
                        s.body_slot_lost_until = Some(now.plus_ms(BODY_SLOT_LOST_MS));
                    }
                }
                BodyAction::WidenSuppliers => {
                    out.push(Action::Dial {
                        count: 4,
                        widen: false,
                    });
                }
                BodyAction::Say(c) => self.say(c),
            }
        }

        let (fork_suppliers, _) = self.body_suppliers(false, now);
        self.refill_fork_wanted();

        let need = self.wanted.len() + self.fork_wanted.len();
        if fork_suppliers.is_empty() && need > 0 {
            let due = match self.no_supplier_said {
                Some(t) => now.expired(t, BODY_UNAVAILABLE_RETRY_MS),
                None => true,
            };
            if due {
                self.no_supplier_said = Some(now);
                let peers = self.peers.len();
                self.say(Condition::NoBodySupplier {
                    wanted: need,
                    peers,
                });
            }
        }

        self.schedule_fork_bodies(&fork_suppliers, now, out);
    }

    fn body_suppliers(&self, exclude_sync: bool, now: Mono) -> (Vec<body_track::Supplier>, bool) {
        let pick = |mut v: Vec<&Session>| -> Vec<body_track::Supplier> {
            v.sort_by_key(|s| std::cmp::Reverse((s.claimed_height, s.id)));
            v.iter()
                .take(BODY_SUPPLIERS)
                .map(|s| body_track::Supplier {
                    id: s.id,
                    horizon: s.claimed_height,
                })
                .collect()
        };
        if exclude_sync {
            let sync = self.header.sync_peer();

            let t1 = pick(
                self.peers
                    .values()
                    .filter(|s| Some(s.id) != sync && s.body_eligible(now))
                    .collect(),
            );
            if !t1.is_empty() {
                return (t1, false);
            }
        }
        let t2 = pick(
            self.peers
                .values()
                .filter(|s| s.body_eligible(now))
                .collect(),
        );
        if !t2.is_empty() {
            return (t2, false);
        }
        (
            pick(self.peers.values().filter(|s| s.is_ready()).collect()),
            true,
        )
    }

    fn catch_up_to_the_chain(&mut self) {
        for _ in 0..CHAIN_CATCHUP_MAX {
            let next = self.body.applied() + 1;
            let Some(rec) = self.chain.header_at(next) else {
                break;
            };
            if !self.chain.have_body(&rec.hash) {
                break;
            }
            if !self.body.note_chain_has(next) {
                break;
            }
        }
    }

    fn refill_fork_wanted(&mut self) {
        let applied = self.body.applied();
        let mut branch: Vec<(Hash32, u64)> = Vec::new();

        for hash in self.chain.wanted_bodies() {
            let Some(rec) = self.lookup(&hash) else {
                continue;
            };
            if self.chain.have_body(&hash) {
                continue;
            }
            if rec.height > applied {
                self.want_body(rec.height, rec.hash);
                continue;
            }
            if !branch.iter().any(|(h, _)| *h == hash) {
                branch.push((hash, rec.height));
            }
        }

        let start = self.wanted.values().next().copied();
        if let Some(start) = start {
            if let Some(mut cur) = self.lookup(&start) {
                let mut steps = 0usize;
                while steps < FORK_BODY_MAX {
                    steps += 1;
                    let Some(p) = self.lookup(&cur.prev_hash) else {
                        break;
                    };
                    if self.chain.have_body(&p.hash) {
                        break;
                    }
                    if !branch.iter().any(|(h, _)| *h == p.hash) {
                        branch.push((p.hash, p.height));
                    }
                    if p.height == 0 {
                        break;
                    }
                    cur = p;
                }
            }
        }
        if branch.is_empty() {
            self.fork_wanted.clear();
            self.fork_said = false;
            return;
        }

        branch.sort_unstable_by_key(|(h, height)| (*height, *h));
        branch.truncate(FORK_BODY_MAX);
        for (hash, height) in &branch {
            self.fork_wanted.entry(*hash).or_insert(ForkWant {
                height: *height,
                asked: None,
                attempts: 0,
                retry_at: None,
                gave_up_said: false,
            });
        }

        self.fork_wanted
            .retain(|h, _| branch.iter().any(|(b, _)| b == h));
        if !self.fork_said {
            self.fork_said = true;

            let our_tip = self.chain.tip().height;
            let lowest = branch.iter().map(|(_, h)| *h).min().unwrap_or(our_tip);
            let depth = our_tip.saturating_sub(lowest) + 1;
            self.say(Condition::ForkBodiesWanted {
                applied: our_tip,
                depth,
                missing: branch.len(),
            });
        }
    }

    fn schedule_fork_bodies(
        &mut self,
        suppliers: &[body_track::Supplier],
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        if self.fork_wanted.is_empty() || suppliers.is_empty() {
            return;
        }

        let mut gave_up: Vec<u64> = Vec::new();
        for w in self.fork_wanted.values_mut() {
            if let Some((_, at)) = w.asked {
                if now.expired(at, FORK_BODY_TIMEOUT_MS) {
                    w.asked = None;
                    w.attempts = w.attempts.saturating_add(1);
                }
            }
            if w.attempts >= FORK_BODY_ATTEMPTS {
                if !w.gave_up_said {
                    w.gave_up_said = true;
                    gave_up.push(w.height);
                }
                match w.retry_at {
                    None => w.retry_at = Some(now.plus_ms(BODY_UNAVAILABLE_RETRY_MS)),

                    Some(at) if now >= at => {
                        w.attempts = 0;
                        w.retry_at = None;

                        w.gave_up_said = false;
                    }
                    Some(_) => {}
                }
            }
        }
        for height in gave_up {
            self.say(Condition::BodyUnavailable { height });

            out.push(Action::Dial {
                count: 4,
                widen: false,
            });
        }
        let inflight = self
            .fork_wanted
            .values()
            .filter(|w| w.asked.is_some())
            .count();
        let mut slots = FORK_BODY_INFLIGHT.saturating_sub(inflight);
        if slots == 0 {
            return;
        }

        let mut todo: Vec<(Hash32, u64)> = self
            .fork_wanted
            .iter()
            .filter(|(_, w)| w.asked.is_none() && w.attempts < FORK_BODY_ATTEMPTS)
            .map(|(h, w)| (*h, w.height))
            .collect();
        todo.sort_by_key(|(_, h)| *h);
        let mut n = 0usize;
        for (hash, _) in todo {
            if slots == 0 {
                break;
            }

            let Some(w) = self.fork_wanted.get_mut(&hash) else {
                continue;
            };
            let peer = suppliers[(w.attempts as usize + n) % suppliers.len()].id;
            w.asked = Some((peer, now));
            out.push(Action::Send {
                peer,
                msg: Msg::GetData(vec![crate::wire::msg::InvItem {
                    kind: crate::wire::msg::InvKind::Block,
                    hash,
                }]),
            });
            Metrics::inc(&self.metrics.fork_body_requests);
            slots -= 1;
            n += 1;
        }
    }

    fn on_fork_body(&mut self, hash: Hash32, bytes: Vec<u8>) {
        match self.sink.submit_block(hash, bytes) {
            Ok(()) => {
                self.fork_wanted.remove(&hash);
                Metrics::inc(&self.metrics.fork_bodies_applied);
            }
            Err(SinkError::Full) => {
                if let Some(w) = self.fork_wanted.get_mut(&hash) {
                    w.asked = None;
                }
            }

            Err(SinkError::Invalid(_) | SinkError::RefusedAt { .. }) => {
                if let Some(w) = self.fork_wanted.get_mut(&hash) {
                    w.asked = None;
                    w.attempts = FORK_BODY_ATTEMPTS;
                }
            }
            Err(SinkError::Fatal(m)) => {
                self.fatal = Some(m);
                self.say(Condition::SinkFatal(m));
            }
        }
    }

    pub fn fork_wanted_len(&self) -> usize {
        self.fork_wanted.len()
    }

    pub fn fork_wanted_heights(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.fork_wanted.values().map(|w| w.height).collect();
        v.sort_unstable();
        v
    }

    fn drain_bodies(&mut self, now: Mono) {
        let sink = self.sink.clone();
        let mut fatal: Option<&'static str> = None;
        self.body.drain_applicable(
            |_h, hash, bytes| {
                if !sink.capacity().admits(bytes.len() as u64) {
                    return false;
                }
                match sink.submit_block(hash, bytes) {
                    Ok(()) => true,
                    Err(SinkError::Full) => false,
                    Err(SinkError::Invalid(_) | SinkError::RefusedAt { .. }) => true,
                    Err(SinkError::Fatal(m)) => {
                        fatal = Some(m);
                        false
                    }
                }
            },
            now,
        );
        if let Some(m) = fatal {
            self.fatal = Some(m);
            self.say(Condition::SinkFatal(m));
        }
        let applied = self.body.applied();
        self.wanted.retain(|h, _| *h > applied);
    }

    fn refill_wanted(&mut self) {
        if self.wanted.len() >= BODY_WINDOW_HASHES {
            return;
        }
        let applied = self.body.applied();
        let ceiling = (applied + WANTED_MAX as u64).min(self.verified_height());

        if ceiling <= applied {
            return;
        }

        if !self.refill_from_ancestry(applied, ceiling) {
            self.refill_from_canonical(applied, ceiling);
        }

        if self.wanted.is_empty() {
            if !self.backlog_stuck {
                self.backlog_stuck = true;
                let verified = self.verified_height();
                self.say(Condition::BodyBacklogUnreachable { applied, verified });
            }
        } else {
            self.backlog_stuck = false;
        }
    }

    fn refill_from_ancestry(&mut self, applied: u64, ceiling: u64) -> bool {
        let Some(mut cur) = self.lookup(&self.header.staging.verified_tip()) else {
            return false;
        };

        let mut steps = 0u64;
        while cur.height > ceiling {
            steps += 1;
            if steps > REFILL_WALK_MAX {
                return false;
            }
            let Some(next) = self.lookup(&cur.prev_hash) else {
                return false;
            };
            cur = next;
        }

        while cur.height > applied {
            if !self.wanted.contains_key(&cur.height) && !self.chain.have_body(&cur.hash) {
                self.wanted.insert(cur.height, cur.hash);
            }
            if cur.height == 0 {
                return true;
            }
            let Some(next) = self.lookup(&cur.prev_hash) else {
                return false;
            };
            cur = next;
        }
        true
    }

    fn refill_from_canonical(&mut self, applied: u64, ceiling: u64) {
        let mut h = applied + 1;
        while h <= ceiling && self.wanted.len() < WANTED_MAX {
            if !self.wanted.contains_key(&h) {
                if let Some(r) = self.chain.header_at(h) {
                    if !self.chain.have_body(&r.hash) {
                        self.wanted.insert(h, r.hash);
                    }
                }
            }
            h += 1;
        }
    }

    fn lookup(&self, h: &Hash32) -> Option<HeaderRec> {
        if let Some(r) = self.header.staging.get(h) {
            return Some(r);
        }
        if let Some(r) = self.known.get(h) {
            return Some(*r);
        }
        if let Some(r) = self.tree.get(h) {
            return Some(*r);
        }
        self.chain.header_by_hash(h)
    }

    fn mtp_for(&self, parent: &HeaderRec) -> Option<u64> {
        let mut times: Vec<u64> = Vec::with_capacity(MEDIAN_TIME_SPAN);
        let mut cur = *parent;
        loop {
            times.push(cur.time);

            if times.len() == MEDIAN_TIME_SPAN || cur.height == 0 {
                return Some(median_time_past(&times));
            }
            cur = self.lookup(&cur.prev_hash)?;
        }
    }

    fn branch_has_anchor(&self, rec: &HeaderRec) -> bool {
        match self.chain.anchor() {
            Some(a) => rec.height >= a.height && self.lookup(&a.hash).is_some(),
            None => false,
        }
    }

    fn say(&mut self, c: Condition) {
        Metrics::inc(&self.metrics.conditions);
        self.conditions.push(c);
    }

    fn charge(&mut self, peer: PeerId, rej: &Rejection, now: Mono, out: &mut Vec<Action>) {
        let Some(o) = rej.offence() else { return };

        if o == Offence::DisconnectedBatches {
            let chargeable = self
                .peers
                .get_mut(&peer)
                .map(|s| s.note_disconnected_batch(now))
                .unwrap_or(false);
            if !chargeable {
                return;
            }
        }
        out.push(Action::Score { peer, offence: o });
    }

    fn apply(&mut self, out: &mut Vec<Action>, now: Mono) {
        let mut extra = Vec::new();
        for a in out.iter() {
            match a {
                Action::Score { peer, offence } => {
                    let verdict = match self.peers.get_mut(peer) {
                        Some(s) => s.penalise(*offence, now),
                        None => Verdict::Keep,
                    };
                    match verdict {
                        Verdict::Keep => {}
                        Verdict::Ban => {
                            Metrics::inc(&self.metrics.bans);
                            extra.push(Action::Ban {
                                peer: *peer,
                                ms: BAN_TIME_MS,
                            });
                            extra.push(Action::Disconnect {
                                peer: *peer,
                                reason: DeadReason::Banned,
                            });
                        }
                        Verdict::BanShort => {
                            Metrics::inc(&self.metrics.bans);
                            extra.push(Action::Ban {
                                peer: *peer,
                                ms: BAN_PROTOCOL_MS,
                            });
                            extra.push(Action::Disconnect {
                                peer: *peer,
                                reason: DeadReason::Banned,
                            });
                        }
                    }
                }
                Action::Designate { peer } => {
                    Metrics::inc(&self.metrics.sync_designations);
                    for (id, s) in self.peers.iter_mut() {
                        s.role.sync_peer = id == peer;
                        if id == peer {
                            s.role.body_supplier = false;
                        }
                    }

                    self.body.release_peer(*peer, now);
                }
                Action::Send {
                    peer,
                    msg: Msg::GetCheckpoint,
                } => {
                    if let Some(s) = self.peers.get_mut(peer) {
                        s.last_getcheckpoint = Some(now);
                    }
                }
                Action::Undesignate { peer } => {
                    if let Some(s) = self.peers.get_mut(peer) {
                        s.role.sync_peer = false;
                    }
                }
                Action::WaiveCooldown { peer } => {
                    if let Some(s) = self.peers.get_mut(peer) {
                        s.sync_ineligible_until = None;
                    }
                }
                Action::SyncCooldown { peer, ms } => {
                    if let Some(s) = self.peers.get_mut(peer) {
                        s.sync_ineligible_until = Some(now.plus_ms(*ms));
                    }
                }
                Action::QuarantineBranch { branch } => {
                    Metrics::inc(&self.metrics.quarantines);
                    let peers: Vec<PeerId> = self.peers.keys().copied().collect();
                    self.quarantine.insert(*branch, peers, now);
                }
                Action::Say(c) => {
                    Metrics::inc(&self.metrics.conditions);

                    if let Condition::SyncRotation { kind, .. } = c {
                        match kind {
                            RotationKind::NoProgress
                            | RotationKind::BelowRateFloor
                            | RotationKind::LocateTimeout => {
                                Metrics::inc(&self.metrics.rotations_charged)
                            }
                            _ => Metrics::inc(&self.metrics.rotations_free),
                        }
                    }
                    self.conditions.push(c.clone());
                }
                _ => {}
            }
        }

        for a in extra.iter() {
            if let Action::Disconnect { peer, .. } = a {
                self.peers.remove(peer);
                self.header.forget(*peer);
                self.body.release_peer(*peer, now);
            }
        }
        out.extend(extra);
    }

    fn tick_parked(&mut self, now: Mono, out: &mut Vec<Action>) {
        let _ = out;

        self.parked
            .retain(|(_, at, _)| !now.expired(*at, TIME_PARK_TTL_MS));
        if self.parked.is_empty() {
            return;
        }

        let mut groups: Vec<[u8; 4]> = self.parked.iter().map(|(_, _, g)| *g).collect();
        groups.sort();
        groups.dedup();
        if groups.len() >= CLOCK_SKEW_GROUPS {
            let median = self
                .parked
                .iter()
                .map(|(h, _, _)| h.time as i64 - self.now_unix as i64)
                .max()
                .unwrap_or(0);
            self.say(Condition::ClockSkewSuspected {
                median_delta_secs: median,
            });
            self.parked.clear();
        }
    }

    pub fn want_body(&mut self, height: u64, hash: Hash32) {
        let applied = self.body.applied();
        if height <= applied || height > applied + WANTED_MAX as u64 {
            return;
        }
        if self.wanted.len() >= WANTED_MAX && !self.wanted.contains_key(&height) {
            match self.wanted.keys().next_back() {
                Some(top) if *top > height => {
                    let top = *top;
                    self.wanted.remove(&top);
                }
                _ => return,
            }
        }
        self.wanted.insert(height, hash);
    }

    pub fn wanted_span(&self) -> Option<(u64, u64)> {
        let lo = *self.wanted.keys().next()?;
        let hi = *self.wanted.keys().next_back()?;
        Some((lo, hi))
    }

    pub fn wanted_len(&self) -> usize {
        self.wanted.len()
    }
}

fn repair_repeat(prev: Option<(u64, u64, u32, &'static str)>, height: u64, tip: u64) -> u32 {
    match prev {
        Some((h, t, n, _)) if h == height && t == tip => n.saturating_add(1),
        _ => 1,
    }
}

#[cfg(test)]
mod repair_watch_tests {
    use super::repair_repeat;

    const WHY: &str = "the chain does not hold the parent";

    #[test]
    fn first_break_counts_one() {
        assert_eq!(repair_repeat(None, 414, 424), 1);
    }

    #[test]
    fn same_break_accumulates() {
        let mut w = None;
        for expect in 1..=5u32 {
            let n = repair_repeat(w, 414, 424);
            assert_eq!(n, expect, "the counter did not accumulate");
            w = Some((414, 424, n, WHY));
        }
    }

    #[test]
    fn walking_repair_no_wedge() {
        let w = Some((421u64, 424u64, 2u32, WHY));
        assert_eq!(
            repair_repeat(w, 420, 424),
            1,
            "the break moved from 421 to 420 - the walk is descending - and the \
             counter carried on as if nothing had changed"
        );
    }

    #[test]
    fn applying_node_no_wedge() {
        let w = Some((414u64, 424u64, 2u32, WHY));
        assert_eq!(
            repair_repeat(w, 414, 425),
            1,
            "our own tip moved from 424 to 425 - the node applied a block - and \
             the counter carried on as if it had not"
        );
    }

    #[test]
    fn count_saturates() {
        let w = Some((414u64, 424u64, u32::MAX, WHY));
        assert_eq!(repair_repeat(w, 414, 424), u32::MAX);
    }
}
