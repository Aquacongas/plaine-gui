use crate::constants::*;
use crate::peer::inbox::{Inbox, PauseCause};
use crate::peer::score::{Offence, Score, Verdict};
use crate::traits::{Hash32, Mono, PeerId};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAdmit {
    Accept,
    Duplicate,
    OverRate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Dialing,
    Handshaking,
    Ready,
    Paused,
    Draining,
    Dead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PeerRole {
    pub sync_peer: bool,
    pub body_supplier: bool,
    pub feeler: bool,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: PeerId,
    pub ip: [u8; 16],
    pub group: [u8; 4],
    pub outbound: bool,
    pub whitelisted: bool,
    pub state: PeerState,
    pub role: PeerRole,
    pub connected_at: Mono,
    pub last_recv: Mono,
    pub ping_sent: Option<Mono>,
    pub claimed_height: u64,
    pub claimed_work: [u8; 32],
    pub claimed_tip: Hash32,
    pub services: u32,
    pub score: Score,
    pub inbox: Inbox,
    pub pow_budget: crate::gate::g4_budget::PeerPowBudget,
    pub verified_delivered: u64,
    pub delivery_window_start: Mono,
    pub headers_delivered_total: u64,
    pub bodies_delivered_total: u64,
    pub bodies_requested_total: u64,
    pub body_misses: u32,
    pub sync_ineligible_until: Option<Mono>,
    pub body_slot_lost_until: Option<Mono>,
    pub headers_only: bool,
    pub last_penalised: Option<Mono>,
    pub last_getcheckpoint: Option<Mono>,
    pub last_getcheckpoint_in: Option<Mono>,
    pub checkpoints_in: u32,
    pub checkpoint_window: Option<Mono>,
    pub checkpoint_seen: VecDeque<(u64, Hash32)>,
    pub last_probe: Option<Mono>,
    pub solicited_until: Option<Mono>,
    pub disc_batches: u32,
    pub disc_batches_since: Mono,
    pub dup_inv: u32,
    pub dup_inv_since: Mono,
    pub announced_to_us: Option<Hash32>,
    pub announced_to_them: Option<Hash32>,
    pub last_inv_sent: Option<Mono>,
    pub inv_repeats: u8,
}

impl Session {
    pub fn new(id: PeerId, ip: [u8; 16], outbound: bool, now: Mono) -> Session {
        Session {
            id,
            ip,
            group: group_of(&ip),
            outbound,
            whitelisted: false,
            state: PeerState::Handshaking,
            role: PeerRole::default(),
            connected_at: now,
            last_recv: now,
            ping_sent: None,
            claimed_height: 0,
            claimed_work: [0u8; 32],
            claimed_tip: [0u8; 32],
            services: 0,
            score: Score::new(now),
            inbox: Inbox::new(),
            pow_budget: crate::gate::g4_budget::PeerPowBudget::new(now),
            verified_delivered: 0,
            delivery_window_start: now,
            headers_delivered_total: 0,
            bodies_delivered_total: 0,
            bodies_requested_total: 0,
            body_misses: 0,
            sync_ineligible_until: None,
            body_slot_lost_until: None,
            headers_only: false,
            last_penalised: None,
            last_getcheckpoint: None,
            last_getcheckpoint_in: None,
            checkpoints_in: 0,
            checkpoint_window: None,
            checkpoint_seen: VecDeque::new(),
            last_probe: None,
            solicited_until: None,
            disc_batches: 0,
            disc_batches_since: now,
            dup_inv: 0,
            dup_inv_since: now,
            announced_to_us: None,
            announced_to_them: None,
            last_inv_sent: None,
            inv_repeats: 0,
        }
    }

    pub fn probe_due(&self, now: Mono) -> bool {
        match self.last_probe {
            Some(t) => now.expired(t, INV_PROBE_INTERVAL_MS),
            None => true,
        }
    }

    pub fn note_probe(&mut self, now: Mono) {
        self.last_probe = Some(now);
        self.solicited_until = Some(now.plus_ms(LOCATE_TIMEOUT_MS));
    }

    pub fn take_solicited(&mut self, now: Mono) -> bool {
        match self.solicited_until.take() {
            Some(t) => now < t,
            None => false,
        }
    }

    pub fn note_disconnected_batch(&mut self, now: Mono) -> bool {
        if now.expired(self.disc_batches_since, DISCONNECTED_BATCH_WINDOW_MS) {
            self.disc_batches_since = now;
            self.disc_batches = 0;
        }
        self.disc_batches = self.disc_batches.saturating_add(1);
        self.disc_batches > DISCONNECTED_BATCH_FREE
    }

    pub fn note_dup_inv(&mut self, now: Mono) -> bool {
        if now.expired(self.dup_inv_since, DUP_INV_WINDOW_MS) {
            self.dup_inv_since = now;
            self.dup_inv = 0;
        }
        self.dup_inv = self.dup_inv.saturating_add(1);
        self.dup_inv > DUP_INV_FREE && (self.dup_inv - DUP_INV_FREE) % DUP_INV_PER_POINT == 0
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state, PeerState::Ready | PeerState::Paused)
    }

    pub fn penalise(&mut self, o: Offence, now: Mono) -> Verdict {
        if o.points() > 0 {
            self.last_penalised = Some(now);
        }
        if self.whitelisted {
            let _ = self.score.apply(o, now);
            return Verdict::Keep;
        }
        self.score.apply(o, now)
    }

    pub fn sync_eligible(&self, now: Mono) -> bool {
        self.is_ready()
            && !self.score.sync_disqualified()
            && match self.sync_ineligible_until {
                Some(t) => now >= t,
                None => true,
            }
    }

    pub fn body_eligible(&self, now: Mono) -> bool {
        self.is_ready()
            && !self.headers_only
            && match self.body_slot_lost_until {
                Some(t) => now >= t,
                None => true,
            }
    }

    pub fn delivery_rate(&self, now: Mono) -> Option<u64> {
        if self.verified_delivered == 0 {
            return None;
        }
        let elapsed = now.since(self.delivery_window_start).max(1);
        Some(self.verified_delivered.saturating_mul(1000) / elapsed)
    }

    pub fn record_delivery(&mut self, headers: u64, now: Mono) {
        self.roll_delivery_window(now);
        self.headers_delivered_total = self.headers_delivered_total.saturating_add(headers);
    }

    pub fn record_verified(&mut self, headers: u64, now: Mono) {
        self.roll_delivery_window(now);
        self.verified_delivered = self.verified_delivered.saturating_add(headers);
    }

    fn roll_delivery_window(&mut self, now: Mono) {
        if now.since(self.delivery_window_start) > DELIVERY_RATE_WINDOW_MS {
            self.delivery_window_start = now;
            self.verified_delivered = 0;
        }
    }

    pub fn record_body(&mut self) {
        self.bodies_delivered_total = self.bodies_delivered_total.saturating_add(1);
        self.body_misses = 0;
        self.headers_only = false;
    }

    pub fn refresh_headers_only(&mut self) {
        if self.bodies_delivered_total == 0
            && self.bodies_requested_total >= u64::from(BODY_ATTEMPTS)
            && self.headers_delivered_total >= HEADERS_ONLY_THRESHOLD
        {
            self.headers_only = true;
        }
    }

    pub fn pong_expired(&self, now: Mono) -> bool {
        if self.inbox.pause_cause().is_some() {
            return false;
        }
        match self.ping_sent {
            Some(t) => now.expired(t, PONG_TIMEOUT_MS),
            None => false,
        }
    }

    pub fn pause_expired(&self, now: Mono) -> bool {
        self.inbox.pause_expired(now)
    }

    pub fn is_useless(&self, now: Mono) -> bool {
        self.outbound
            && !self.whitelisted
            && !self.sync_eligible(now)
            && !self.body_eligible(now)
            && now.expired(self.last_recv, USELESS_PEER_MS)
    }

    pub fn pause(&mut self, cause: PauseCause, now: Mono) {
        if cause == PauseCause::IngestBudget && self.role.sync_peer {
            return;
        }
        self.inbox.pause(cause, now);
        self.state = PeerState::Paused;
    }

    pub fn unpause(&mut self, now: Mono) {
        self.inbox.unpause(now);
        if self.state == PeerState::Paused {
            self.state = PeerState::Ready;
        }
    }

    pub fn admit_checkpoint(&mut self, height: u64, hash: Hash32, now: Mono) -> CheckpointAdmit {
        if self
            .checkpoint_seen
            .iter()
            .any(|(h, x)| *h == height && *x == hash)
        {
            return CheckpointAdmit::Duplicate;
        }
        let fresh = match self.checkpoint_window {
            None => true,
            Some(t) => now.expired(t, CHECKPOINT_RATE_WINDOW_MS),
        };
        if fresh {
            self.checkpoint_window = Some(now);
            self.checkpoints_in = 0;
        }
        if self.checkpoints_in >= CHECKPOINT_RATE_PER_10MIN {
            return CheckpointAdmit::OverRate;
        }
        self.checkpoints_in += 1;

        self.checkpoint_seen.push_back((height, hash));
        while self.checkpoint_seen.len() > CHECKPOINT_DEDUP_MAX {
            self.checkpoint_seen.pop_front();
        }
        CheckpointAdmit::Accept
    }

    pub fn admit_getcheckpoint(&mut self, now: Mono) -> bool {
        match self.last_getcheckpoint_in {
            Some(t) if !now.expired(t, GETCHECKPOINT_INTERVAL_MS) => false,
            _ => {
                self.last_getcheckpoint_in = Some(now);
                true
            }
        }
    }
}

pub fn group_of(ip: &[u8; 16]) -> [u8; 4] {
    let is_v4_mapped = ip[..10].iter().all(|b| *b == 0) && ip[10] == 0xff && ip[11] == 0xff;
    if is_v4_mapped {
        [ip[12], ip[13], 0, 0]
    } else {
        [ip[0], ip[1], ip[2], ip[3]]
    }
}
