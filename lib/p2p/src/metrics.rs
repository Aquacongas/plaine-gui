use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    pub frames_in: AtomicU64,
    pub frames_bad: AtomicU64,
    pub bytes_in: AtomicU64,
    pub headers_verified: AtomicU64,
    pub pow_calls: AtomicU64,
    pub gate0_dedup_hits: AtomicU64,
    pub gate1_reject: AtomicU64,
    pub gate2_reject: AtomicU64,
    pub gate3_reject: AtomicU64,
    pub gate4_throttle: AtomicU64,
    pub sync_designations: AtomicU64,
    pub rotations_charged: AtomicU64,
    pub rotations_free: AtomicU64,
    pub body_requests: AtomicU64,
    pub fork_body_requests: AtomicU64,
    pub fork_bodies_applied: AtomicU64,
    pub hol_escalations: AtomicU64,
    pub deep_recoveries: AtomicU64,
    pub quarantines: AtomicU64,
    pub bans: AtomicU64,
    pub pause_max_disconnects: AtomicU64,
    pub conditions: AtomicU64,
    pub inv_in: AtomicU64,
    pub inv_probes: AtomicU64,
    pub inv_out: AtomicU64,
    pub headers_held: AtomicU64,
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            frames_in: Self::get(&self.frames_in),
            frames_bad: Self::get(&self.frames_bad),
            bytes_in: Self::get(&self.bytes_in),
            headers_verified: Self::get(&self.headers_verified),
            pow_calls: Self::get(&self.pow_calls),
            gate0_dedup_hits: Self::get(&self.gate0_dedup_hits),
            gate3_reject: Self::get(&self.gate3_reject),
            sync_designations: Self::get(&self.sync_designations),
            rotations_charged: Self::get(&self.rotations_charged),
            rotations_free: Self::get(&self.rotations_free),
            body_requests: Self::get(&self.body_requests),
            hol_escalations: Self::get(&self.hol_escalations),
            deep_recoveries: Self::get(&self.deep_recoveries),
            quarantines: Self::get(&self.quarantines),
            bans: Self::get(&self.bans),
            pause_max_disconnects: Self::get(&self.pause_max_disconnects),
            conditions: Self::get(&self.conditions),
            inv_in: Self::get(&self.inv_in),
            inv_probes: Self::get(&self.inv_probes),
            inv_out: Self::get(&self.inv_out),
            headers_held: Self::get(&self.headers_held),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    #[allow(missing_docs)]
    pub frames_in: u64,
    #[allow(missing_docs)]
    pub frames_bad: u64,
    #[allow(missing_docs)]
    pub bytes_in: u64,
    #[allow(missing_docs)]
    pub headers_verified: u64,
    #[allow(missing_docs)]
    pub pow_calls: u64,
    #[allow(missing_docs)]
    pub gate0_dedup_hits: u64,
    #[allow(missing_docs)]
    pub gate3_reject: u64,
    #[allow(missing_docs)]
    pub sync_designations: u64,
    #[allow(missing_docs)]
    pub rotations_charged: u64,
    #[allow(missing_docs)]
    pub rotations_free: u64,
    #[allow(missing_docs)]
    pub body_requests: u64,
    #[allow(missing_docs)]
    pub hol_escalations: u64,
    #[allow(missing_docs)]
    pub deep_recoveries: u64,
    #[allow(missing_docs)]
    pub quarantines: u64,
    #[allow(missing_docs)]
    pub bans: u64,
    #[allow(missing_docs)]
    pub pause_max_disconnects: u64,
    #[allow(missing_docs)]
    pub conditions: u64,
    #[allow(missing_docs)]
    pub inv_in: u64,
    #[allow(missing_docs)]
    pub inv_probes: u64,
    #[allow(missing_docs)]
    pub inv_out: u64,
    #[allow(missing_docs)]
    pub headers_held: u64,
}
