use crate::constants::*;
use crate::traits::Mono;

#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    level: u64,
    capacity: u64,
    per_sec: u64,
    last: Mono,
}

impl TokenBucket {
    pub fn new(capacity: u64, per_sec: u64, now: Mono) -> TokenBucket {
        TokenBucket {
            level: capacity,
            capacity,
            per_sec,
            last: now,
        }
    }

    pub fn with_burst(capacity: u64, initial: u64, per_sec: u64, now: Mono) -> TokenBucket {
        TokenBucket {
            level: initial,
            capacity,
            per_sec,
            last: now,
        }
    }

    fn refill(&mut self, now: Mono) {
        let ms = now.since(self.last);
        if ms == 0 {
            return;
        }
        self.last = now;
        let add = self.per_sec.saturating_mul(ms) / 1000;
        self.level = (self.level + add).min(self.capacity);
    }

    pub fn take(&mut self, n: u64, now: Mono) -> bool {
        self.refill(now);
        if self.level >= n {
            self.level -= n;
            true
        } else {
            false
        }
    }

    pub fn admits(&mut self, n: u64, now: Mono) -> bool {
        self.refill(now);
        self.level >= n
    }

    pub fn commit(&mut self, n: u64) {
        self.level = self.level.saturating_sub(n);
    }

    pub fn level(&mut self, now: Mono) -> u64 {
        self.refill(now);
        self.level
    }
}

#[derive(Debug)]
pub struct Budgets {
    read_global: TokenBucket,
    ingest_global: TokenBucket,
    // carved out of the global ingest budget so a designated sync peer always
    // has bytes even when the rest of the network is flooding us.
    sync_reserve: TokenBucket,
    pow_pool: TokenBucket,
    probe_pool: TokenBucket,
}

impl Budgets {
    pub fn new(now: Mono) -> Budgets {
        Budgets {
            // initial burst is one second of global plus the reserve, so the
            // very first read at startup is never rejected for an empty bucket.
            read_global: TokenBucket::with_burst(
                READ_GLOBAL_BYTES_PER_SEC,
                READ_GLOBAL_BYTES_PER_SEC + SYNC_PEER_RESERVE_BYTES_PER_SEC,
                READ_GLOBAL_BYTES_PER_SEC,
                now,
            ),
            ingest_global: TokenBucket::new(
                INGEST_GLOBAL_BYTES_PER_SEC - SYNC_PEER_RESERVE_BYTES_PER_SEC,
                INGEST_GLOBAL_BYTES_PER_SEC - SYNC_PEER_RESERVE_BYTES_PER_SEC,
                now,
            ),
            sync_reserve: TokenBucket::new(
                SYNC_PEER_RESERVE_BYTES_PER_SEC,
                SYNC_PEER_RESERVE_BYTES_PER_SEC,
                now,
            ),
            pow_pool: TokenBucket::new(POW_POOL_MS_PER_SEC, POW_POOL_MS_PER_SEC, now),

            probe_pool: TokenBucket::new(
                INV_PROBE_GLOBAL_BURST,
                INV_PROBE_GLOBAL_PER_SEC,
                now,
            ),
        }
    }

    pub fn probe_admits(&mut self, now: Mono) -> bool {
        self.probe_pool.admits(1, now)
    }

    pub fn probe_commit(&mut self) {
        self.probe_pool.commit(1);
    }

    pub fn probe_level(&mut self, now: Mono) -> u64 {
        self.probe_pool.level(now)
    }

    // announced headers may spend the pow pool but must leave the reserve intact
    // (else an announcement flood starves real IBD of CPU)
    pub fn admit_pow_announced(&mut self, ms: u64, now: Mono) -> bool {
        if self.pow_pool.level(now) < POW_ANNOUNCE_RESERVE_MS.saturating_add(ms) {
            return false;
        }
        self.pow_pool.take(ms, now)
    }

    pub fn admit_ingest(&mut self, bytes: u64, is_sync_peer: bool, now: Mono) -> bool {
        // sync peer draws from its reserve first, then falls back to the shared pool.
        if is_sync_peer && self.sync_reserve.take(bytes, now) {
            return true;
        }
        self.ingest_global.take(bytes, now)
    }

    pub fn admit_frame(&mut self, bytes: u64, is_sync_peer: bool, now: Mono) -> bool {
        if is_sync_peer && self.sync_reserve.admits(bytes, now) {
            self.sync_reserve.commit(bytes);
            return true;
        }

        if !self.read_global.admits(bytes, now) || !self.ingest_global.admits(bytes, now) {
            return false;
        }
        self.ingest_global.commit(bytes);
        self.read_global.commit(bytes);
        true
    }

    pub fn admit_read(&mut self, bytes: u64, now: Mono) -> bool {
        self.read_global.take(bytes, now)
    }

    pub fn admit_pow(&mut self, ms: u64, now: Mono) -> bool {
        self.pow_pool.take(ms, now)
    }

    pub fn pow_affordable(&mut self, ms: u64, now: Mono) -> bool {
        self.pow_pool.admits(ms, now)
    }

    pub fn pow_level(&mut self, now: Mono) -> u64 {
        self.pow_pool.level(now)
    }

    pub fn read_level(&mut self, now: Mono) -> u64 {
        self.read_global.level(now)
    }

    pub fn ingest_level(&mut self, now: Mono) -> u64 {
        self.ingest_global.level(now)
    }

    pub fn reserve_level(&mut self, now: Mono) -> u64 {
        self.sync_reserve.level(now)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PeerPowBudget {
    bucket: TokenBucket,
}

impl PeerPowBudget {
    pub fn new(now: Mono) -> PeerPowBudget {
        PeerPowBudget {
            bucket: TokenBucket::new(
                POW_BUDGET_BURST_MS,
                POW_BUDGET_MS_PER_WINDOW * 1000 / POW_BUDGET_WINDOW_MS,
                now,
            ),
        }
    }

    pub fn take(&mut self, ms: u64, now: Mono) -> bool {
        self.bucket.take(ms, now)
    }
}
