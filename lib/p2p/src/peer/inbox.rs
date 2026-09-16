use crate::constants::*;
use crate::traits::Mono;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseCause {
    LocalInbox,
    ValidateQueue,
    CommitStall,
    IngestBudget,
    PeerOverran,
}

impl PauseCause {
    pub const fn is_local(self) -> bool {
        matches!(
            self,
            PauseCause::LocalInbox | PauseCause::ValidateQueue | PauseCause::CommitStall
        )
    }

    pub const fn suspends_liveness_clocks(self) -> bool {
        self.is_local()
    }

    pub const fn peer_points(self) -> u32 {
        match self {
            PauseCause::PeerOverran => 5,
            _ => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Inbox {
    used: u64,
    cap: u64,
    paused: Option<(PauseCause, Mono)>,
    paused_total_ms: u64,
}

impl Inbox {
    pub fn new() -> Inbox {
        Inbox {
            used: 0,
            cap: INBOX_BYTES,
            paused: None,
            paused_total_ms: 0,
        }
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn pause_cause(&self) -> Option<PauseCause> {
        self.paused.map(|(c, _)| c)
    }

    pub fn accept(&mut self, n: u64, now: Mono) -> bool {
        if self.used + n > self.cap {
            self.pause(PauseCause::LocalInbox, now);
            return false;
        }
        self.used += n;
        if self.used == self.cap {
            self.pause(PauseCause::LocalInbox, now);
        }
        true
    }

    pub fn consume(&mut self, n: u64, now: Mono) {
        self.used = self.used.saturating_sub(n);
        if self.used * 2 < self.cap {
            if let Some((PauseCause::LocalInbox, _)) = self.paused {
                self.unpause(now);
            }
        }
    }

    pub fn pause(&mut self, cause: PauseCause, now: Mono) {
        match self.paused {
            Some((_, since)) => self.paused = Some((cause, since)),
            None => self.paused = Some((cause, now)),
        }
    }

    pub fn unpause(&mut self, now: Mono) {
        if let Some((_, since)) = self.paused.take() {
            self.paused_total_ms = self.paused_total_ms.saturating_add(now.since(since));
        }
    }

    pub fn paused_for(&self, now: Mono) -> u64 {
        match self.paused {
            Some((_, since)) => now.since(since),
            None => 0,
        }
    }

    pub fn paused_total_ms(&self, now: Mono) -> u64 {
        self.paused_total_ms + self.paused_for(now)
    }

    pub fn pause_expired(&self, now: Mono) -> bool {
        self.paused_for(now) >= PAUSE_MAX_MS
    }
}

impl Default for Inbox {
    fn default() -> Inbox {
        Inbox::new()
    }
}
