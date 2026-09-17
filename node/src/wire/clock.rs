use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct SysClock {
    start: Instant,
}

impl Default for SysClock {
    fn default() -> Self {
        SysClock::new()
    }
}

impl SysClock {
    pub fn new() -> SysClock {
        SysClock {
            start: Instant::now(),
        }
    }

    pub fn unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    // monotonic ms since process start, not since the epoch. for timeouts and
    // cadence, where a wall-clock jump must not matter.
    pub fn ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl plaine_chain::traits::Clock for SysClock {
    fn now_unix(&self) -> u64 {
        self.unix()
    }
    fn mono_ms(&self) -> u64 {
        self.ms()
    }
}

impl plaine_p2p::traits::Clock for SysClock {
    fn now_unix(&self) -> u64 {
        self.unix()
    }
    fn mono(&self) -> plaine_p2p::traits::Mono {
        plaine_p2p::traits::Mono(self.ms())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mono_clock_starts_low_and_monotone() {
        let c = SysClock::new();
        let a = c.ms();
        let b = c.ms();
        assert!(b >= a);
        assert!(a < 1_000, "the origin is process start, not the epoch");
    }

    #[test]
    fn wall_clock_is_plausible() {
        assert!(SysClock::new().unix() > 1_577_836_800);
    }
}
