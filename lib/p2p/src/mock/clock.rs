use crate::traits::{Clock, Mono};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct MockClock {
    mono_ms: AtomicU64,
    unix: AtomicU64,
}

impl MockClock {
    pub fn new(unix: u64) -> MockClock {
        MockClock {
            mono_ms: AtomicU64::new(0),
            unix: AtomicU64::new(unix),
        }
    }

    pub fn advance(&self, ms: u64) {
        self.mono_ms.fetch_add(ms, Ordering::Relaxed);
        self.unix.fetch_add(ms / 1000, Ordering::Relaxed);
    }

    pub fn advance_mono(&self, ms: u64) {
        self.mono_ms.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn set_unix(&self, t: u64) {
        self.unix.store(t, Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn now_unix(&self) -> u64 {
        self.unix.load(Ordering::Relaxed)
    }
    fn mono(&self) -> Mono {
        Mono(self.mono_ms.load(Ordering::Relaxed))
    }
}
