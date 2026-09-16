use crate::constants::*;
use crate::traits::Mono;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offence {
    BadPow,
    BadBits,
    BadTimePast,
    Malformed,
    BadSignature,
    PreHello,
    UnknownCmd,
    NotFoundAnnouncedBlock,
    RepeatOneShot,
    DisconnectedBatches,
    UnsolicitedBody,
    UnsolicitedHeaders,
    GetCheckpointAbuse,
    CheckpointUnverified,
    ReorgTooDeepRepeat,
    DeadlineMiss,
    DupInv,
    PeerOverran,
    LessWork,
    TieBreakLost,
    ReorgTooDeep,
    NotYetValid,
    LocalBackpressure,
    NotFoundTx,
}

impl Offence {
    // tiers: 100 = provably invalid data (instant-ish ban), 20 = protocol abuse,
    // 10 = wasted work, 5/1 = mild. the 0-point group is our own decision or
    // local backpressure, not the peer's fault, so it is reported but never scored.
    pub const fn points(self) -> u32 {
        match self {
            Offence::BadPow
            | Offence::BadBits
            | Offence::BadTimePast
            | Offence::Malformed
            | Offence::BadSignature
            | Offence::PreHello => 100,

            Offence::UnknownCmd
            | Offence::NotFoundAnnouncedBlock
            | Offence::RepeatOneShot
            | Offence::UnsolicitedHeaders
            | Offence::GetCheckpointAbuse => 20,

            Offence::DisconnectedBatches
            | Offence::UnsolicitedBody
            | Offence::CheckpointUnverified
            | Offence::ReorgTooDeepRepeat => 10,
            Offence::DeadlineMiss | Offence::PeerOverran => 5,
            Offence::DupInv => 1,

            Offence::LessWork
            | Offence::TieBreakLost
            | Offence::ReorgTooDeep
            | Offence::NotYetValid
            | Offence::LocalBackpressure
            | Offence::NotFoundTx => 0,
        }
    }

    pub const fn is_immediate_protocol_ban(self) -> bool {
        matches!(self, Offence::PreHello)
    }

    // Once a peer feeds us bad pow/bits/signature it is never a sync source again
    // this session - even after the score decays back down.
    pub const fn is_session_sync_disqualifying(self) -> bool {
        matches!(self, Offence::BadPow | Offence::BadBits | Offence::BadSignature)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Keep,
    Ban,
    BanShort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Score {
    // score is kept in thousandths so decay can interpolate within a half-life.
    milli: u64,
    at: Mono,
    sync_disqualified: bool,
}

impl Score {
    pub fn new(now: Mono) -> Score {
        Score {
            milli: 0,
            at: now,
            sync_disqualified: false,
        }
    }

    pub fn value(&self, now: Mono) -> u32 {
        (self.decayed_milli(now) / 1000) as u32
    }

    pub fn sync_disqualified(&self) -> bool {
        self.sync_disqualified
    }

    fn decayed_milli(&self, now: Mono) -> u64 {
        let elapsed = now.since(self.at);
        if self.milli == 0 {
            return 0;
        }
        let halves = elapsed / SCORE_HALF_LIFE_MS;

        // guard the shift: >> 64 on a u64 is UB (and past 63 halvings it's zero)
        let mut v = if halves >= 63 { 0 } else { self.milli >> halves };

        let rem = elapsed % SCORE_HALF_LIFE_MS;
        if v > 0 && rem > 0 {
            let drop = v / 2 * rem / SCORE_HALF_LIFE_MS;
            v = v.saturating_sub(drop);
        }
        v
    }

    pub fn apply(&mut self, o: Offence, now: Mono) -> Verdict {
        self.milli = self.decayed_milli(now);
        self.at = now;
        if o.is_session_sync_disqualifying() {
            self.sync_disqualified = true;
        }
        self.milli = self
            .milli
            .saturating_add(u64::from(o.points()).saturating_mul(1000));
        if o.is_immediate_protocol_ban() {
            return Verdict::BanShort;
        }
        if self.milli / 1000 >= u64::from(BAN_SCORE) {
            Verdict::Ban
        } else {
            Verdict::Keep
        }
    }
}
