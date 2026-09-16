use core::time::Duration;

// pre-auth we owe an unknown peer nothing, so keep the line short; a subscribed
// miner gets more room for a long worker/rig label. worst-case per-conn memory
// tracks this, see budget.rs.
pub const MAX_LINE_PRE_AUTH: usize = 2 * 1024;

pub const MAX_LINE_POST_AUTH: usize = 8 * 1024;

pub const READ_BUF_INITIAL: usize = 2 * 1024;

pub const OUT_BUF_CAP: usize = 4 * 1024;

pub const JSON_MAX_DEPTH: u32 = 3;

pub const JSON_MAX_MEMBERS: usize = 8;

pub const JSON_MAX_ELEMENTS: usize = 8;

pub const JSON_MAX_STRING_BYTES: usize = 512;

pub const JSON_MAX_NUMBER_DIGITS: usize = 20;

pub const JSON_MAX_VALUES: usize = 64;

// Nonce layout is [E1 | X]: the top 24 bits pick the per-connection slice, the
// low 40 are the miner's to roll. Must match the miner's split (see nonce.rs).
pub const E1_BITS: u32 = 24;

pub const X_BITS: u32 = 64 - E1_BITS;

pub const E1_SPACE: u32 = 1 << E1_BITS;

pub const MINER_ROLLABLE_BYTES: u64 = (X_BITS / 8) as u64;

pub const JOB_PREFIX_BYTES: usize = plaine_consensus::constants::HEADER_BYTES - 8;

pub const JOB_SLOTS: usize = 4;

pub const DEDUP_PER_JOB: usize = 256;

pub const TEMPLATE_REFRESH: Duration = Duration::from_secs(15);

pub const NEW_TIP_NOTIFY_BUDGET: Duration = Duration::from_millis(100);

pub const STALE_CREDIT_GRACE: Duration = Duration::from_secs(5);

// target: one share every 20 s per connection. the whole vardiff loop aims here.
pub const VARDIFF_SETPOINT_SECS: f64 = 20.0;

// floor difficulty, and the hard minimum a storm floor may never dip below.
pub const MIN_DIFF: u64 = 8_192;

// where a first-seen address starts before vardiff or the cache has an opinion.
pub const START_DIFF: u64 = 60_000;

pub const DIFF_CACHE_ENTRIES: usize = 65_536;

pub const DIFF_CACHE_TTL: Duration = Duration::from_secs(24 * 3600);

pub const RETARGET_GATE_SHARES: u32 = 20;

pub const RETARGET_GATE_SECS: f64 = 120.0;

pub const WARMUP_GATE_SHARES: u32 = 5;

pub const WARMUP_SHARES: u32 = 30;

pub const VARDIFF_DEAD_ZONE: f64 = 1.5;

pub const VARDIFF_MATURE_ZONE: f64 = 1.15;

pub const VARDIFF_MATURE_SHARES: u32 = 60;

pub const VARDIFF_MAX_STEP: f64 = 4.0;

pub const VARDIFF_FAST_ESCAPE: f64 = 1.7;

pub const VARDIFF_TICK: Duration = Duration::from_secs(2);

pub const SILENCE_SLACK: f64 = 4.0;

pub const DIFF_LADDER: [f64; 10] = [1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0];

pub const DSPS_TAU: [f64; 3] = [60.0, 300.0, 3600.0];

pub const RECONNECT_STORM_PER_MIN: u32 = 4;

pub const RECONNECT_STORM_WINDOW: Duration = Duration::from_secs(300);

pub const ADMIT_IN_FLIGHT: usize = 1;

pub const ADMIT_QUEUED: usize = 1;

pub const SHARE_VERIFY_SECS_WORST: f64 = 0.003;

pub const SHARE_VERIFY_SECS_BEST: f64 = 0.0013;

pub const SUBMIT_RATE_PER_SEC: f64 = 3.0;

pub const SUBMIT_BURST: f64 = 10.0;

pub const LINE_RATE_PER_SEC: f64 = 20.0;

pub const LINE_BURST: f64 = 60.0;

pub const DIFF_CACHE_MIN_SHARES: u64 = 4;

// score at which an ip is banned. paired with the decay below: 100 points and
// 1 point per 6 s means a maxed-out score drains in 10 minutes.
pub const BAN_THRESHOLD: u32 = 100;

pub const BAN_DECAY_SECS: u64 = 6;

pub const BAN_BASE: Duration = Duration::from_secs(600);

pub const BAN_LADDER_FACTOR: u64 = 4;

pub const BAN_MAX: Duration = Duration::from_secs(86_400);

pub const BAN_TABLE_ENTRIES: usize = 65_536;

pub const SOFT_SCORE_CAP: u32 = 25;

pub const IDLE_EVICT: Duration = Duration::from_secs(30 * 60);

pub const AUTH_DEADLINE: Duration = Duration::from_secs(10);

pub const READ_DEADLINE: Duration = Duration::from_secs(600);

pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub const GARBAGE_THROTTLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Solo,
    Pool,
}

#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub max_connections: usize,
    pub max_per_ip: usize,
    pub new_conns_per_ip_per_min: u32,
    pub global_accept_per_sec: u32,
}

impl Caps {
    // pool faces the open internet: many conns, generous per-ip, but a hard
    // global accept rate. solo is one operator's own rigs, so everything is tighter.
    pub const POOL: Caps = Caps {
        max_connections: 16_384,
        max_per_ip: 64,
        new_conns_per_ip_per_min: 6,
        global_accept_per_sec: 500,
    };

    pub const SOLO: Caps = Caps {
        max_connections: 256,
        max_per_ip: 16,
        new_conns_per_ip_per_min: 6,
        global_accept_per_sec: 50,
    };

    pub const fn for_mode(mode: Mode) -> Caps {
        match mode {
            Mode::Solo => Caps::SOLO,
            Mode::Pool => Caps::POOL,
        }
    }
}

// operator-tunable banning. a zero threshold disables banning without touching
// `enabled` (see penalise), and zero table_entries/throttle_ms mean "off" too.
#[derive(Debug, Clone, Copy)]
pub struct BanPolicy {
    pub enabled: bool,
    pub threshold: u32,
    pub soft_cap: u32,
    pub decay_secs: u64,
    pub base_secs: u64,
    pub ladder_factor: u64,
    pub max_secs: u64,
    pub table_entries: usize,
    pub throttle_ms: u64,
}

impl BanPolicy {
    pub const DEFAULT: BanPolicy = BanPolicy {
        enabled: true,
        threshold: BAN_THRESHOLD,
        soft_cap: SOFT_SCORE_CAP,
        decay_secs: BAN_DECAY_SECS,
        base_secs: 600,
        ladder_factor: BAN_LADDER_FACTOR,
        max_secs: 86_400,
        table_entries: BAN_TABLE_ENTRIES,
        throttle_ms: 60_000,
    };
}

impl Default for BanPolicy {
    fn default() -> BanPolicy {
        BanPolicy::DEFAULT
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DiffPolicy {
    pub start_diff: u64,
    pub min_diff: u64,
    pub cache_entries: usize,
    pub cache_ttl_ms: u64,
    pub storm_enabled: bool,
    pub storm_per_min: u32,
    pub storm_window_ms: u64,
}

impl DiffPolicy {
    pub const DEFAULT: DiffPolicy = DiffPolicy {
        start_diff: START_DIFF,
        min_diff: MIN_DIFF,
        cache_entries: DIFF_CACHE_ENTRIES,
        cache_ttl_ms: 24 * 3600 * 1000,
        storm_enabled: true,
        storm_per_min: RECONNECT_STORM_PER_MIN,
        storm_window_ms: 300_000,
    };
}

impl Default for DiffPolicy {
    fn default() -> DiffPolicy {
        DiffPolicy::DEFAULT
    }
}

pub const LADDER_MAX: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct Cadence {
    pub warmup_shares: u32,
    pub warmup_gate_shares: u32,
    pub retarget_gate_shares: u32,
    pub retarget_gate_secs: f64,
    pub mature_shares: u32,
    pub max_step: f64,
    pub dead_zone: f64,
    pub mature_zone: f64,
    pub fast_escape: f64,
    pub silence_slack: f64,
    pub tau: [f64; 3],
    pub ladder: [f64; LADDER_MAX],
    pub ladder_len: usize,
}

impl Cadence {
    // vardiff timing. ladder is the set of rungs difficulty may snap to, and
    // ladder_len says how many of the 16 slots are live, which keeps the struct
    // Copy and const-sized instead of dragging a Vec around.
    pub const DEFAULT: Cadence = Cadence {
        warmup_shares: WARMUP_SHARES,
        warmup_gate_shares: WARMUP_GATE_SHARES,
        retarget_gate_shares: RETARGET_GATE_SHARES,
        retarget_gate_secs: RETARGET_GATE_SECS,
        mature_shares: VARDIFF_MATURE_SHARES,
        max_step: VARDIFF_MAX_STEP,
        dead_zone: VARDIFF_DEAD_ZONE,
        mature_zone: VARDIFF_MATURE_ZONE,
        fast_escape: VARDIFF_FAST_ESCAPE,
        silence_slack: SILENCE_SLACK,
        tau: DSPS_TAU,
        // TODO: these rungs are a hand-copy of DIFF_LADDER above; the two have to
        // be edited in lockstep until a const can be spliced into a [f64; 16].
        ladder: [
            1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        ],
        ladder_len: 10,
    };
}

impl Default for Cadence {
    fn default() -> Cadence {
        Cadence::DEFAULT
    }
}

// per-connection token buckets. a disabled bucket, or a rate of 0, becomes an
// unlimited bucket in build_bucket rather than one that refuses everything.
#[derive(Debug, Clone, Copy)]
pub struct RatePolicy {
    pub submit_enabled: bool,
    pub submit_per_sec: f64,
    pub submit_burst: f64,
    pub line_enabled: bool,
    pub line_per_sec: f64,
    pub line_burst: f64,
}

impl RatePolicy {
    pub const DEFAULT: RatePolicy = RatePolicy {
        submit_enabled: true,
        submit_per_sec: SUBMIT_RATE_PER_SEC,
        submit_burst: SUBMIT_BURST,
        line_enabled: true,
        line_per_sec: LINE_RATE_PER_SEC,
        line_burst: LINE_BURST,
    };
}

impl Default for RatePolicy {
    fn default() -> RatePolicy {
        RatePolicy::DEFAULT
    }
}

pub const SOLO_MAX_CONNECTIONS_CEILING: usize = 8_192;

pub const SOLO_TEMPLATE_LRU: usize = 64;

pub const MAX_RIG_LABEL: usize = 32;

pub use plaine_consensus::constants::{PORT_STRATUM as PORT_SOLO, PORT_STRATUM_TLS as PORT_POOL};
