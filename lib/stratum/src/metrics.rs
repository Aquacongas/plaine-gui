use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    pub accepted: AtomicU64,
    pub refused_banned: AtomicU64,
    pub refused_per_ip: AtomicU64,
    pub refused_rate: AtomicU64,
    pub refused_full: AtomicU64,
    pub subscribes: AtomicU64,
    pub authorizes_ok: AtomicU64,
    pub authorizes_bad: AtomicU64,
    pub notifies: AtomicU64,
    pub set_targets: AtomicU64,
    pub retargets: AtomicU64,
    pub shares_submitted: AtomicU64,
    pub shares_verified: AtomicU64,
    pub shares_accepted: AtomicU64,
    pub shares_accepted_difficulty: AtomicU64,
    pub blocks_found: AtomicU64,
    pub rej_unknown_job: AtomicU64,
    pub rej_stale: AtomicU64,
    pub rej_stale_credited: AtomicU64,
    pub rej_duplicate: AtomicU64,
    pub rej_low_difficulty: AtomicU64,
    pub rej_out_of_slice: AtomicU64,
    pub rej_throttled: AtomicU64,
    pub rej_server_busy: AtomicU64,
    pub rej_unauthorized: AtomicU64,
    pub bad_json: AtomicU64,
    pub closed_slow_client: AtomicU64,
    pub closed_idle: AtomicU64,
    pub closed_auth_timeout: AtomicU64,
    pub closed_line_flood: AtomicU64,
    pub closed_slice_revoked: AtomicU64,
    pub keepalives: AtomicU64,
    pub bans: AtomicU64,
    pub verify_internal_errors: AtomicU64,
}

impl Metrics {
    #[inline]
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    // must equal the number of rows in snapshot() below; the array type ties them
    // together so adding a counter without a row fails to compile.
    pub const COUNT: usize = 34;

    pub fn snapshot(&self) -> [(&'static str, u64); Metrics::COUNT] {
        [
            ("accepted", Self::get(&self.accepted)),
            ("refused_banned", Self::get(&self.refused_banned)),
            ("refused_per_ip", Self::get(&self.refused_per_ip)),
            ("refused_rate", Self::get(&self.refused_rate)),
            ("refused_full", Self::get(&self.refused_full)),
            ("subscribes", Self::get(&self.subscribes)),
            ("authorizes_ok", Self::get(&self.authorizes_ok)),
            ("authorizes_bad", Self::get(&self.authorizes_bad)),
            ("notifies", Self::get(&self.notifies)),
            ("set_targets", Self::get(&self.set_targets)),
            ("retargets", Self::get(&self.retargets)),
            ("shares_submitted", Self::get(&self.shares_submitted)),
            ("shares_verified", Self::get(&self.shares_verified)),
            ("shares_accepted", Self::get(&self.shares_accepted)),
            ("shares_accepted_difficulty", Self::get(&self.shares_accepted_difficulty)),
            ("blocks_found", Self::get(&self.blocks_found)),
            ("rej_unknown_job", Self::get(&self.rej_unknown_job)),
            ("rej_stale", Self::get(&self.rej_stale)),
            ("rej_stale_credited", Self::get(&self.rej_stale_credited)),
            ("rej_duplicate", Self::get(&self.rej_duplicate)),
            ("rej_low_difficulty", Self::get(&self.rej_low_difficulty)),
            ("rej_out_of_slice", Self::get(&self.rej_out_of_slice)),
            ("rej_throttled", Self::get(&self.rej_throttled)),
            ("rej_server_busy", Self::get(&self.rej_server_busy)),
            ("rej_unauthorized", Self::get(&self.rej_unauthorized)),
            ("bad_json", Self::get(&self.bad_json)),
            ("closed_slow_client", Self::get(&self.closed_slow_client)),
            ("closed_idle", Self::get(&self.closed_idle)),
            ("closed_auth_timeout", Self::get(&self.closed_auth_timeout)),
            ("closed_line_flood", Self::get(&self.closed_line_flood)),
            ("closed_slice_revoked", Self::get(&self.closed_slice_revoked)),
            ("keepalives", Self::get(&self.keepalives)),
            ("bans", Self::get(&self.bans)),
            ("verify_internal_errors", Self::get(&self.verify_internal_errors)),
        ]
    }
}
