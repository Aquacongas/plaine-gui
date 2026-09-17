use crate::constants::*;
use crate::traits::Mono;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StallKind {
    NoProgress,
    BelowRateFloor { per_10s: u64 },
    LocalSuspendExceeded { suspended_ms: u64 },
    LocalReadRefused { refusals: u64 },
}

impl StallKind {
    pub const fn charges_budget(self) -> bool {
        matches!(
            self,
            StallKind::NoProgress | StallKind::BelowRateFloor { .. }
        )
    }

    pub const fn peer_points(self) -> u32 {
        match self {
            StallKind::LocalSuspendExceeded { .. } | StallKind::LocalReadRefused { .. } => 0,
            _ => 5,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProgressClock {
    last_progress: Mono,
    window_start: Mono,
    in_window: u64,
    suspended_since: Option<Mono>,
    suspended_total_ms: u64,
    verify_bound: bool,
    local_refusals: u64,
}

impl ProgressClock {
    pub fn new(now: Mono) -> ProgressClock {
        ProgressClock {
            last_progress: now,
            window_start: now,
            in_window: 0,
            suspended_since: None,
            suspended_total_ms: 0,
            verify_bound: false,
            local_refusals: 0,
        }
    }

    pub fn note_local_refusal(&mut self) {
        self.local_refusals = self.local_refusals.saturating_add(1);
    }

    pub fn progress(&mut self, n: u64, now: Mono) {
        if n == 0 {
            return;
        }
        self.local_refusals = 0;
        self.last_progress = now;
        if now.since(self.window_start) > SYNC_RATE_WINDOW_MS {
            self.window_start = now;
            self.in_window = 0;
        }
        self.in_window = self.in_window.saturating_add(n);
    }

    pub fn set_verify_bound(&mut self, bound: bool, now: Mono) {
        if bound != self.verify_bound {
            self.verify_bound = bound;
            self.last_progress = now;
            self.window_start = now;
            self.in_window = 0;
        }
    }

    pub fn verify_bound(&self) -> bool {
        self.verify_bound
    }

    pub fn suspend(&mut self, now: Mono) {
        if self.suspended_since.is_none() {
            self.suspended_since = Some(now);
        }
    }

    pub fn resume(&mut self, now: Mono) {
        if let Some(since) = self.suspended_since.take() {
            let d = now.since(since);
            self.suspended_total_ms = self.suspended_total_ms.saturating_add(d);
            self.last_progress = now;
            self.window_start = now;
            self.in_window = 0;
        }
    }

    pub fn suspended(&self) -> bool {
        self.suspended_since.is_some()
    }

    pub fn suspended_total(&self, now: Mono) -> u64 {
        self.suspended_total_ms + self.suspended_since.map(|s| now.since(s)).unwrap_or(0)
    }

    pub fn verdict(&self, now: Mono, ibd: bool) -> Option<StallKind> {
        let susp = self.suspended_total(now);
        if susp >= SYNC_SUSPEND_MAX_MS {
            return Some(StallKind::LocalSuspendExceeded { suspended_ms: susp });
        }

        if self.suspended_since.is_some() {
            return None;
        }

        if self.verify_bound {
            return None;
        }
        if now.expired(self.last_progress, STALL_TIMEOUT_MS) {
            return Some(self.attribute(StallKind::NoProgress));
        }
        let floor = if ibd {
            SYNC_MIN_RATE_IBD_PER_10S
        } else {
            SYNC_MIN_RATE_TRACKING_PER_10S
        };
        if floor == 0 {
            return None;
        }
        let elapsed = now.since(self.window_start);
        if elapsed < SYNC_RATE_WINDOW_MS {
            return None;
        }
        let per_10s = self.in_window.saturating_mul(10_000) / elapsed.max(1);
        if per_10s < floor {
            return Some(self.attribute(StallKind::BelowRateFloor { per_10s }));
        }
        None
    }

    fn attribute(&self, k: StallKind) -> StallKind {
        if self.local_refusals > 0 {
            StallKind::LocalReadRefused {
                refusals: self.local_refusals,
            }
        } else {
            k
        }
    }
}
