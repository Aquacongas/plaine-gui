use crate::constants::*;
use crate::peer::score::Offence;
use crate::sync::rotation::{Designation, Rotator};
use crate::sync::staging::Staging;
use crate::sync::stall::{ProgressClock, StallKind};
use crate::sync::{Action, DeadReason};
use crate::traits::{Anchor, Condition, Hash32, Mono, PeerId, RotationKind, TipSnapshot};
use crate::wire::msg::Msg;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HState {
    ColdStart,
    Probing,
    HeaderSync,
    Tracking,
    DeepRecovery,
    Quarantined,
}

#[derive(Clone, Debug)]
pub struct Episode {
    pub since: Mono,
    pub branch: Hash32,
    pub anchor_asked: Vec<PeerId>,
    pub anchor_since: Option<Mono>,
}

#[derive(Clone, Copy, Debug)]
pub struct PeerClaim {
    pub height: u64,
    pub work: [u8; 32],
    pub tip: Hash32,
}

#[derive(Clone, Copy, Debug)]
struct ClaimRec {
    claim: PeerClaim,
    at: Mono,
    substantiated_to: u64,
    failures: u32,
    demoted_at: Option<Mono>,
}

impl ClaimRec {
    fn effective_height(&self) -> u64 {
        if self.demoted_at.is_some() {
            self.substantiated_to
        } else {
            self.claim.height
        }
    }
}

pub struct HeaderCtx<'a> {
    pub peers: &'a BTreeMap<PeerId, crate::peer::Session>,
    pub our_tip: TipSnapshot,
    pub now_unix: u64,
    pub anchor: Option<Anchor>,
    pub locator: Vec<Hash32>,
}

#[derive(Debug)]
pub struct HeaderTrack {
    state: HState,
    since: Mono,
    sync_peer: Option<PeerId>,
    clock: ProgressClock,
    rotator: Rotator,
    pub staging: Staging,
    locate_sent: Option<Mono>,
    coldstart_attempt: u32,
    last_audit: Mono,
    last_catchup: Mono,
    flat_audits: u32,
    episode: Option<Episode>,
    quarantine_until: Option<Mono>,
    stranded_reported: Option<Mono>,
    claims: BTreeMap<PeerId, ClaimRec>,
    commit_bound: bool,
    ahead_masked: bool,
}

impl HeaderTrack {
    pub fn new(verified_height: u64, verified_tip: Hash32, seed: u64, now: Mono) -> HeaderTrack {
        HeaderTrack {
            state: HState::ColdStart,
            since: now,
            sync_peer: None,
            clock: ProgressClock::new(now),
            rotator: Rotator::new(),
            staging: Staging::new(verified_height, verified_tip, seed),
            locate_sent: None,
            coldstart_attempt: 0,
            last_audit: now,
            last_catchup: now,
            flat_audits: 0,
            episode: None,
            quarantine_until: None,
            stranded_reported: None,
            claims: BTreeMap::new(),
            commit_bound: false,
            ahead_masked: false,
        }
    }

    pub fn state(&self) -> HState {
        self.state
    }

    pub fn sync_peer(&self) -> Option<PeerId> {
        self.sync_peer
    }

    pub fn clock_mut(&mut self) -> &mut ProgressClock {
        &mut self.clock
    }

    pub fn rotations_charged(&self, now: Mono) -> u32 {
        self.rotator.charged_in_window(now)
    }

    pub fn note_claim(&mut self, peer: PeerId, claim: PeerClaim, now: Mono) {
        match self.claims.get_mut(&peer) {
            Some(existing) => {
                if claim.height <= existing.claim.height {
                    return;
                }

                if let Some(d) = existing.demoted_at {
                    if !now.expired(d, CLAIM_REARM_MS) {
                        return;
                    }
                    existing.demoted_at = None;
                    existing.failures = 0;
                }
                existing.claim = claim;
                existing.at = now;
            }
            None => {
                self.claims.insert(
                    peer,
                    ClaimRec {
                        claim,
                        at: now,
                        substantiated_to: 0,
                        failures: 0,
                        demoted_at: None,
                    },
                );
            }
        }
    }

    pub fn forget(&mut self, peer: PeerId) {
        self.claims.remove(&peer);
        if self.sync_peer == Some(peer) {
            self.sync_peer = None;
        }
    }

    pub fn best_claimed_height(&self) -> u64 {
        self.claims
            .values()
            .map(|c| c.effective_height())
            .max()
            .unwrap_or(0)
    }

    pub fn best_actionable_height(
        &self,
        peers: &BTreeMap<PeerId, crate::peer::Session>,
        now: Mono,
    ) -> u64 {
        self.claims
            .iter()
            .filter(|(p, _)| {
                peers
                    .get(p)
                    .map(|s| s.outbound && s.sync_eligible(now))
                    .unwrap_or(false)
            })
            .map(|(_, c)| c.effective_height())
            .max()
            .unwrap_or(0)
    }

    pub fn note_substantiated(&mut self, peer: PeerId, height: u64) {
        if let Some(c) = self.claims.get_mut(&peer) {
            if height > c.substantiated_to {
                c.substantiated_to = height;
            }
            c.failures = 0;
        }
    }

    pub fn note_unsubstantiated(&mut self, peer: PeerId, now: Mono, out: &mut Vec<Action>) {
        let Some(c) = self.claims.get_mut(&peer) else {
            return;
        };
        if c.demoted_at.is_some() {
            return;
        }
        c.failures = c.failures.saturating_add(1);
        if c.failures < CLAIM_ATTEMPTS {
            return;
        }
        c.demoted_at = Some(now);
        out.push(Action::Say(Condition::ClaimUnsubstantiated {
            peer,
            claimed: c.claim.height,
            proved: c.substantiated_to,
        }));
    }

    pub fn claim_height(&self, peer: PeerId) -> u64 {
        self.claims
            .get(&peer)
            .map(|c| c.effective_height())
            .unwrap_or(0)
    }

    pub fn claim_demoted(&self, peer: PeerId) -> bool {
        self.claims
            .get(&peer)
            .map(|c| c.demoted_at.is_some())
            .unwrap_or(false)
    }

    pub fn set_commit_bound(&mut self, bound: bool) {
        self.commit_bound = bound;
    }

    pub fn note_local_refusal(&mut self, now: Mono) {
        let _ = now;
        self.clock.note_local_refusal();
    }

    pub fn peer_furthest_ahead(&self, exclude: &[PeerId]) -> Option<PeerId> {
        self.claims
            .iter()
            .filter(|(p, _)| !exclude.contains(p))
            .max_by_key(|(_, c)| c.effective_height())
            .map(|(p, _)| *p)
    }

    pub fn in_ibd(&self, tip: &TipSnapshot, now_unix: u64) -> bool {
        let stale = now_unix > tip.time.saturating_add(SYNC_WINDOW_SECS);
        let deficit = self.best_claimed_height() > tip.height + IBD_WORK_DEFICIT_BLOCKS;
        stale || deficit
    }

    pub fn tick(&mut self, ctx: &HeaderCtx<'_>, now: Mono) -> Vec<Action> {
        let mut out = Vec::new();
        let ready: Vec<&crate::peer::Session> =
            ctx.peers.values().filter(|s| s.is_ready()).collect();

        if ready.is_empty() && self.state != HState::ColdStart {
            self.enter(HState::ColdStart, now);
            self.sync_peer = None;
        }

        match self.state {
            HState::ColdStart => self.tick_coldstart(&ready, now, &mut out),
            HState::Probing => self.tick_probing(ctx, &ready, now, &mut out),
            HState::HeaderSync => self.tick_headersync(ctx, &ready, now, &mut out),
            HState::Tracking => self.tick_tracking(ctx, &ready, now, &mut out),
            HState::DeepRecovery => self.tick_deep(ctx, now, &mut out),
            HState::Quarantined => self.tick_quarantined(now, &mut out),
        }
        out
    }

    fn enter(&mut self, s: HState, now: Mono) {
        self.state = s;
        self.since = now;
    }

    fn tick_coldstart(
        &mut self,
        ready: &[&crate::peer::Session],
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        if !ready.is_empty() {
            self.coldstart_attempt = 0;
            self.enter(HState::Probing, now);
            return;
        }
        let idx = (self.coldstart_attempt as usize).min(COLDSTART_BACKOFF_MS.len() - 1);
        let backoff = if self.coldstart_attempt == 0 {
            COLDSTART_DEADLINE_MS
        } else {
            COLDSTART_BACKOFF_MS[idx]
        };
        if now.expired(self.since, backoff) {
            self.coldstart_attempt = self.coldstart_attempt.saturating_add(1);
            self.since = now;

            out.push(Action::Dial {
                count: COLDSTART_DIAL_CONCURRENT,
                widen: self.coldstart_attempt > 0,
            });
            out.push(Action::Say(Condition::ColdStartRetry {
                attempt: self.coldstart_attempt,
                backoff_ms: backoff,
            }));
        }
    }

    fn tick_probing(
        &mut self,
        ctx: &HeaderCtx<'_>,
        ready: &[&crate::peer::Session],
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        let outbound_ready = ready.iter().filter(|s| s.outbound).count();

        if !now.expired(self.since, PROBE_WINDOW_MS) && outbound_ready < PROBE_PEERS {
            return;
        }
        if self.designate(ctx, ready, now, out) {
            self.enter(HState::HeaderSync, now);
        } else if self.best_actionable_height(ctx.peers, now) <= ctx.our_tip.height {
            self.enter(HState::Tracking, now);
            self.last_audit = now;
        }
    }

    fn designate(
        &mut self,
        ctx: &HeaderCtx<'_>,
        ready: &[&crate::peer::Session],
        now: Mono,
        out: &mut Vec<Action>,
    ) -> bool {
        let our_h = ctx.our_tip.height;
        let claims = &self.claims;
        let ahead = move |s: &crate::peer::Session| -> bool {
            claims
                .get(&s.id)
                .map(|c| c.effective_height() > our_h)
                .unwrap_or(false)
        };
        let refs: Vec<&crate::peer::Session> = ready.to_vec();
        match self.rotator.select(&refs, now, &ahead) {
            Designation::Peer(p) => {
                self.set_sync_peer(p, ctx, now, out);
                true
            }
            Designation::Waive(p) => {
                out.push(Action::Say(Condition::NoEligibleSyncPeer { waived: p }));
                out.push(Action::WaiveCooldown { peer: p });
                self.set_sync_peer(p, ctx, now, out);
                true
            }
            Designation::NoneYet => false,
        }
    }

    fn set_sync_peer(&mut self, p: PeerId, ctx: &HeaderCtx<'_>, now: Mono, out: &mut Vec<Action>) {
        let changed = self.sync_peer != Some(p);
        self.sync_peer = Some(p);
        if let Some(s) = ctx.peers.get(&p) {
            self.rotator.designate(s, now);
        }
        self.clock = ProgressClock::new(now);

        if changed {
            out.push(Action::Designate { peer: p });
        }
        self.send_getheaders(p, ctx, now, out);
    }

    fn send_getheaders(
        &mut self,
        p: PeerId,
        ctx: &HeaderCtx<'_>,
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        self.locate_sent = Some(now);

        let mut locator = Vec::with_capacity(LOCATOR_MAX);
        if self.staging.staged_len() > 0 {
            locator.push(self.staging.staged_tip());
        }
        locator.extend(ctx.locator.iter().copied());
        locator.truncate(LOCATOR_MAX);
        out.push(Action::Send {
            peer: p,
            msg: Msg::GetHeaders {
                locator,
                stop: [0u8; 32],
            },
        });
    }

    fn tick_headersync(
        &mut self,
        ctx: &HeaderCtx<'_>,
        ready: &[&crate::peer::Session],
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        let Some(p) = self.sync_peer else {
            self.enter(HState::Probing, now);
            return;
        };
        if !ctx.peers.get(&p).map(|s| s.is_ready()).unwrap_or(false) {
            self.say_rotation(p, RotationKind::DesigneeLost, out);
            self.rotate(None, ctx, ready, now, out, false);
            return;
        }

        self.clock
            .set_verify_bound(self.staging.staged_len() > 0 || self.commit_bound, now);

        if let Some(sent) = self.locate_sent {
            if now.expired(sent, LOCATE_TIMEOUT_MS) {
                out.push(Action::Score {
                    peer: p,
                    offence: Offence::DeadlineMiss,
                });
                self.say_rotation(p, RotationKind::LocateTimeout, out);

                self.note_unsubstantiated(p, now, out);
                self.rotator.charge(now);
                self.rotate(Some(p), ctx, ready, now, out, true);
                return;
            }
        }

        let ibd = self.in_ibd(&ctx.our_tip, ctx.now_unix);
        if let Some(kind) = self.clock.verdict(now, ibd) {
            if kind.peer_points() > 0 {
                out.push(Action::Score {
                    peer: p,
                    offence: Offence::DeadlineMiss,
                });

                self.note_unsubstantiated(p, now, out);
            }
            if let StallKind::LocalSuspendExceeded { suspended_ms } = kind {
                out.push(Action::Say(Condition::LocalStallRotation { suspended_ms }));
            }

            self.say_rotation(p, rotation_kind_of(kind), out);
            if kind.charges_budget() {
                self.rotator.charge(now);
            }
            self.rotate(Some(p), ctx, ready, now, out, kind.charges_budget());
            return;
        }

        if let Some(s) = ctx.peers.get(&p) {
            if self.rotator.probation_expired(s, now) {
                self.say_rotation(p, RotationKind::ProbationExpired, out);
                self.rotate(Some(p), ctx, ready, now, out, false);
                return;
            }
        }

        let claimed = self
            .claims
            .get(&p)
            .map(|c| c.effective_height())
            .unwrap_or(0);
        if self.staging.staged_len() == 0
            && self.staging.verified_height() >= claimed
            && self.locate_sent.is_none()
        {
            self.enter(HState::Tracking, now);
            self.last_audit = now;
        }
    }

    fn rotate(
        &mut self,
        from: Option<PeerId>,
        ctx: &HeaderCtx<'_>,
        ready: &[&crate::peer::Session],
        now: Mono,
        out: &mut Vec<Action>,
        charged: bool,
    ) {
        if let Some(p) = from {
            out.push(Action::Undesignate { peer: p });
            if charged {
                out.push(Action::SyncCooldown {
                    peer: p,
                    ms: SYNC_COOLDOWN_MS,
                });
            }
        }
        self.sync_peer = None;
        self.locate_sent = None;

        if charged && !self.rotator.budget_available(now) {
            out.push(Action::Say(Condition::RotationBudgetExhausted));
            out.push(Action::Dial {
                count: 4,
                widen: false,
            });
            self.enter(HState::Probing, now);
            return;
        }

        let ready_excl: Vec<&crate::peer::Session> = ready
            .iter()
            .filter(|s| Some(s.id) != from)
            .copied()
            .collect();
        if !self.designate(ctx, &ready_excl, now, out) {
            self.enter(HState::Probing, now);
        }
    }

    fn tick_tracking(
        &mut self,
        ctx: &HeaderCtx<'_>,
        ready: &[&crate::peer::Session],
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        let have = self.staging.verified_height().max(ctx.our_tip.height);
        if now.expired(self.last_catchup, PROBE_WINDOW_MS)
            && self.best_actionable_height(ctx.peers, now) > have
        {
            self.last_catchup = now;
            if self.designate(ctx, ready, now, out) {
                self.enter(HState::HeaderSync, now);
                return;
            }
        }

        if !now.expired(self.last_audit, TRACKING_AUDIT_MS) {
            return;
        }
        self.last_audit = now;

        let best = self.best_actionable_height(ctx.peers, now);
        let behind = best > ctx.our_tip.height;

        let raw = self.best_claimed_height();
        self.ahead_masked = !behind && raw > ctx.our_tip.height;
        if self.ahead_masked {
            out.push(Action::Say(Condition::AheadPeersAllIneligible {
                claimed: raw,
                ours: ctx.our_tip.height,
            }));

            if self.designate(ctx, ready, now, out) {
                self.enter(HState::HeaderSync, now);
            }
            return;
        }

        if !behind {
            self.flat_audits = 0;
            return;
        }

        if self.parked_branch().is_some() {
            self.begin_recovery(now);
            return;
        }

        if self.designate(ctx, ready, now, out) {
            self.flat_audits = 0;
            self.enter(HState::HeaderSync, now);
            return;
        }
        self.flat_audits += 1;
        if self.flat_audits >= STALL_CONFIRM_AUDITS {
            self.flat_audits = 0;
            self.begin_recovery(now);
        }
    }

    fn parked_branch(&self) -> Option<Hash32> {
        self.episode.as_ref().map(|e| e.branch)
    }

    pub fn begin_recovery(&mut self, now: Mono) {
        let branch = self
            .claims
            .values()
            .max_by_key(|c| c.effective_height())
            .map(|c| c.claim.tip)
            .unwrap_or([0u8; 32]);

        self.episode = Some(Episode {
            since: now,
            branch,
            anchor_asked: Vec::new(),
            anchor_since: None,
        });
        self.enter(HState::DeepRecovery, now);
    }

    fn tick_deep(&mut self, ctx: &HeaderCtx<'_>, now: Mono, out: &mut Vec<Action>) {
        let Some(ep) = self.episode.clone() else {
            self.enter(HState::Probing, now);
            return;
        };

        {
            let due = match ep.anchor_since {
                None => true,
                Some(t) => now.expired(t, ANCHOR_PULL_MS),
            };
            if due && ep.anchor_asked.len() < ANCHOR_PULL_PEERS {
                let mut excluded = ep.anchor_asked.clone();
                for (id, s) in ctx.peers.iter() {
                    if let Some(t) = s.last_getcheckpoint {
                        if !now.expired(t, GETCHECKPOINT_INTERVAL_MS) {
                            excluded.push(*id);
                        }
                    }
                }
                if let Some(p) = self.peer_furthest_ahead(&excluded) {
                    let mut e = ep.clone();
                    e.anchor_asked.push(p);
                    e.anchor_since = Some(now);
                    self.episode = Some(e);
                    out.push(Action::Send {
                        peer: p,
                        msg: Msg::GetCheckpoint,
                    });
                    return;
                }
            }

            let due_report = match self.stranded_reported {
                None => true,
                Some(t) => now.expired(t, TRACKING_AUDIT_MS),
            };
            if due_report {
                self.stranded_reported = Some(now);
                out.push(Action::Say(Condition::StrandedBeyondReorgCap {
                    our_tip: ctx.our_tip.height,
                    their_tip: self.best_claimed_height(),
                    depth: self
                        .best_claimed_height()
                        .saturating_sub(ctx.our_tip.height),
                }));
            }
        }

        if now.expired(ep.since, DEEP_RECOVERY_DEADLINE_MS) {
            out.push(Action::QuarantineBranch { branch: ep.branch });
            out.push(Action::Dial {
                count: 4,
                widen: false,
            });
            self.episode = None;
            self.enter(HState::Probing, now);
        }
    }

    pub fn enter_quarantine(&mut self, now: Mono, out: &mut Vec<Action>) {
        let branch = self.episode.as_ref().map(|e| e.branch).unwrap_or([0u8; 32]);
        out.push(Action::Say(Condition::DeepRecoveryFlapping { branch }));
        self.quarantine_until = Some(now.plus_ms(QUARANTINE_MS));
        self.episode = None;
        self.enter(HState::Quarantined, now);
    }

    fn tick_quarantined(&mut self, now: Mono, out: &mut Vec<Action>) {
        let _ = out;
        if let Some(t) = self.quarantine_until {
            if now >= t {
                self.quarantine_until = None;
                self.enter(HState::Probing, now);
            }
        } else {
            self.enter(HState::Probing, now);
        }
    }

    pub fn end_episode(&mut self) {
        self.episode = None;
        self.stranded_reported = None;
    }

    pub fn note_answer(&mut self) {
        self.locate_sent = None;
    }

    pub fn note_progress(&mut self, staged: u64, verified: u64, now: Mono) {
        let n = if self.clock.verify_bound() {
            verified
        } else {
            staged
        };
        self.clock.progress(n, now);
        self.rotator.note_grant_headers(staged);
        if staged > 0 || verified > 0 {
            self.locate_sent = None;
        }
    }

    pub fn request_more(&mut self, ctx: &HeaderCtx<'_>, now: Mono, out: &mut Vec<Action>) {
        let Some(p) = self.sync_peer else {
            return;
        };
        if !self.staging.can_stage() {
            return;
        }

        if self.locate_sent.is_some() {
            return;
        }
        self.locate_sent = Some(now);
        out.push(Action::Send {
            peer: p,
            msg: Msg::GetHeaders {
                locator: vec![self.staging.staged_tip()],
                stop: [0u8; 32],
            },
        });
        let _ = ctx;
    }

    pub fn to_tracking(&mut self, now: Mono) {
        self.enter(HState::Tracking, now);
        self.last_audit = now;
    }

    pub fn dead_reason(&self) -> DeadReason {
        DeadReason::Protocol
    }

    fn say_rotation(&self, peer: PeerId, kind: RotationKind, out: &mut Vec<Action>) {
        out.push(Action::Say(Condition::SyncRotation { peer, kind }));
    }
}

fn rotation_kind_of(k: StallKind) -> RotationKind {
    match k {
        StallKind::NoProgress => RotationKind::NoProgress,
        StallKind::BelowRateFloor { .. } => RotationKind::BelowRateFloor,
        StallKind::LocalSuspendExceeded { .. } => RotationKind::LocalSuspendExceeded,
        StallKind::LocalReadRefused { .. } => RotationKind::LocalReadRefused,
    }
}
