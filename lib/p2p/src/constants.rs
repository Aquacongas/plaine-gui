use plaine_consensus::constants as spec;

pub const PORT_P2P: u16 = spec::PORT_P2P;

pub const MAGIC_MAIN: [u8; 4] = spec::MAGIC_MAIN;

pub const FOREIGN_MAGIC: [u8; 4] = [0x2C, 0xA9, 0x1F, 0x84];

pub const FRAME_HEADER_BYTES: usize = 10;

pub const PROTO_VER: u16 = 1;

pub const MIN_PROTO: u16 = 1;

pub const MAX_P2P_MSG_BYTES: usize = spec::MAX_P2P_MSG_BYTES;

pub const HEADER_BYTES: usize = spec::HEADER_BYTES;

pub const CHAIN_ID: [u8; 4] = spec::CHAIN_ID;

pub const FOREIGN_CHAIN_ID: [u8; 4] = *b"XXXX";

pub const ARENA_MAX: usize = 64 * 1024;

pub const CAP_HELLO: usize = 103 + UA_MAX;

pub const CAP_HELLO_ACK: usize = 0;

pub const CAP_PING: usize = 8;

pub const CAP_PONG: usize = 8;

pub const CAP_GETADDR: usize = 0;

pub const CAP_ADDR: usize = 4 + ADDR_MSG_MAX * ADDR_REC_BYTES;

pub const CAP_INV: usize = 4 + INV_MAX * INV_ITEM_BYTES;

pub const CAP_GETHEADERS: usize = 4 + LOCATOR_MAX * 32 + 32;

pub const CAP_HEADERS: usize = 4 + spec::MAX_HEADERS_PER_MSG * HEADER_BYTES;

pub const CAP_BLOCK: usize = spec::MAX_BLOCK_BYTES;

pub const CAP_TX: usize = spec::MAX_TX_BYTES;

pub const CAP_MEMPOOL: usize = 16;

pub const CAP_FEEFILTER: usize = 16;

pub const CAP_CHECKPOINT: usize = 8 + 32 + 1 + CHECKPOINT_SIGS_MAX * 65;

pub const CAP_GETCHECKPOINT: usize = 0;

pub const LOCATOR_MAX: usize = 64;

pub const INV_MAX: usize = 4096;

pub const INV_ITEM_BYTES: usize = 33;

pub const ADDR_MSG_MAX: usize = 512;

pub const ADDR_REC_BYTES: usize = 30;

pub const UA_MAX: usize = 64;

pub const CHECKPOINT_SIGS_MAX: usize = 15;

pub const MAX_HEADERS_PER_MSG: usize = spec::MAX_HEADERS_PER_MSG;

pub const UNSOLICITED_HEADERS_MAX: usize = 8;

pub const INV_BLOCKS_PER_MSG_MAX: usize = UNSOLICITED_HEADERS_MAX;

pub const INV_HEADERS_ADMIT_MAX: usize = UNSOLICITED_HEADERS_MAX;

pub const INV_PROBE_INTERVAL_MS: u64 = 2_500;

pub const INV_PROBE_GLOBAL_PER_SEC: u64 = 16;

pub const INV_PROBE_GLOBAL_BURST: u64 = 64;

pub const INV_PROBE_INFLIGHT_MAX: usize = INV_PROBE_GLOBAL_BURST as usize;

pub const INV_PROBE_INFLIGHT_TTL_MS: u64 = 1_000;

pub const DUP_INV_FREE: u32 = 100;

pub const DUP_INV_PER_POINT: u32 = 100;

pub const DUP_INV_WINDOW_MS: u64 = 600_000;

pub const DISCONNECTED_BATCH_FREE: u32 = 2;

pub const DISCONNECTED_BATCH_WINDOW_MS: u64 = 600_000;

pub const HANDSHAKE_QUIET_MS: u64 = 250;

pub const SERVICE_FULL_RELAY: u32 = 1 << 0;

pub const SERVICE_ARCHIVE: u32 = 1 << 1;

pub const SERVICE_ENCRYPT_V2: u32 = 1 << 2;

pub const SERVICE_MBZ_MASK: u32 = !(SERVICE_FULL_RELAY | SERVICE_ARCHIVE | SERVICE_ENCRYPT_V2);

pub const MAX_PEERS: usize = spec::MAX_PEERS;

pub const MAX_OUTBOUND: usize = 16;

pub const MAX_INBOUND: usize = 96;

pub const WHITELIST_RESERVE: usize = 16;

pub const FEELER_SLOTS: usize = 2;

pub const INBOUND_PER_IP: usize = 4;

pub const INBOUND_PER_GROUP: usize = 16;

pub const ACCEPT_RATE_PER_SEC: u32 = 8;

pub const ACCEPT_BURST: u32 = 32;

pub const RECONNECT_PER_IP_PER_MIN: u32 = 6;

pub const OUTBOUND_PER_GROUP: usize = 2;

pub const COLDSTART_DIAL_CONCURRENT: usize = 32;

pub const OUTBOUND_TARGET: usize = MAX_OUTBOUND - FEELER_SLOTS;

pub const CONN_MANAGER_TICK_MS: u64 = 5_000;

pub const DIAL_RETRY_MS: u64 = 30_000;

pub const OUTBOUND_PER_GROUP_WIDENED: usize = MAX_OUTBOUND;

pub const FD_PEERS: u64 = MAX_PEERS as u64;

pub const FD_INBOUND_HANDSHAKE: u64 =
    ACCEPT_BURST as u64 + ACCEPT_RATE_PER_SEC as u64 * HANDSHAKE_TIMEOUT_MS / 1_000;

pub const FD_TRANSIENT_DIALS: u64 = COLDSTART_DIAL_CONCURRENT as u64;

pub const FD_LISTENERS: u64 = 2;

pub const FD_RPC: u64 = 128;

pub const FD_STORAGE: u64 = 256;

pub const FD_SERVICE: u64 = 32;

pub const FD_TOTAL: u64 = FD_PEERS
    + FD_INBOUND_HANDSHAKE
    + FD_TRANSIENT_DIALS
    + FD_LISTENERS
    + FD_RPC
    + FD_STORAGE
    + FD_SERVICE;

pub const FD_CEILING: u64 = 800;

pub const TICK_MS: u64 = 250;

pub const WRITE_STALL_MS: u64 = PONG_TIMEOUT_MS;

pub const SHUTDOWN_DRAIN_MS: u64 = 2_000;

pub const ACCEPT_ERROR_BACKOFF_MS: u64 = 50;

pub const ENGINE_QUEUE_ITEMS: usize = 1_024;

pub const SERVE_THREADS: usize = 2;

pub const SERVE_QUEUE_ITEMS: usize = 64;

pub const NET_INLINE_BUDGET_NS: u64 = 100_000;

pub const CONNECT_TIMEOUT_MS: u64 = 5_000;

pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

pub const PING_INTERVAL_MS: u64 = 120_000;

pub const PONG_TIMEOUT_MS: u64 = 60_000;

pub const PAUSE_MAX_MS: u64 = 300_000;

pub const PROBE_WINDOW_MS: u64 = 3_000;

pub const PROBE_PEERS: usize = 4;

pub const LOCATE_TIMEOUT_MS: u64 = 15_000;

pub const STALL_TIMEOUT_MS: u64 = 30_000;

pub const SYNC_RATE_WINDOW_MS: u64 = 30_000;

pub const SYNC_MIN_RATE_IBD_PER_10S: u64 = 2_000;

pub const SYNC_MIN_RATE_TRACKING_PER_10S: u64 = 0;

pub const SYNC_COOLDOWN_MS: u64 = 600_000;

pub const CLAIM_ATTEMPTS: u32 = 3;

pub const CLAIM_REARM_MS: u64 = SYNC_COOLDOWN_MS;

pub const LONELY_WAIVER_MS: u64 = 120_000;

pub const SYNC_ELIGIBILITY_FLOOR_MS: u64 = 30_000;

pub const PROBE_GRANT_HEADERS: u64 = 4_096;

pub const PROBE_GRANT_MS: u64 = 30_000;

pub const DELIVERY_RATE_WINDOW_MS: u64 = 60_000;

pub const ROTATION_BUDGET: u32 = 4;

pub const ROTATION_WINDOW_MS: u64 = 300_000;

pub const PRESYNC_LEAD_HEADERS: u64 = 65_536;

pub const PRESYNC_LEAD_BYTES: u64 = PRESYNC_LEAD_HEADERS * HEADER_BYTES as u64;

pub const FF_SAMPLE_RATE: u64 = 128;

pub const BODY_TIMEOUT_MS: u64 = 20_000;

pub const BODY_INFLIGHT_TAIL_MS: u64 = 60_000;

pub const BODY_ATTEMPTS: u32 = 3;

pub const HOL_TIMEOUT_MS: u64 = 30_000;

pub const HOL_PARALLEL: usize = 3;

pub const HOL_WINDOW_FREEZE: u64 = 64;

pub const BODY_STARVE_WIDEN_MS: u64 = 120_000;

pub const BODY_STARVE_REPORT_MS: u64 = 600_000;

pub const BODY_UNAVAILABLE_RETRY_MS: u64 = 60_000;

pub const BODY_SLOT_LOST_MS: u64 = 600_000;

pub const BODY_SUPPLIERS: usize = 8;

pub const BODY_WINDOW_HASHES: usize = 128;

pub const BODY_WINDOW_BYTES: u64 = 48 * 1024 * 1024;

pub const BODY_INFLIGHT_PER_PEER_MAX: u64 = 16;

pub const READY_AHEAD_BLOCKS: usize = 16;

pub const READY_AHEAD_BYTES: u64 = 16 * 1024 * 1024;

pub const HEADERS_ONLY_THRESHOLD: u64 = 1_000;

pub const WANTED_MAX: usize = BODY_WINDOW_HASHES * 4;

pub const WANTED_BYTES: u64 = WANTED_MAX as u64 * 40;

pub const CHAIN_CATCHUP_MAX: usize = 64;

pub const FORK_BODY_MAX: usize = MAX_REORG_DEPTH as usize;

pub const FORK_BODY_INFLIGHT: usize = 4;

pub const FORK_BODY_TIMEOUT_MS: u64 = BODY_TIMEOUT_MS;

pub const FORK_BODY_ATTEMPTS: u32 = BODY_ATTEMPTS;

pub const FORK_BODY_BYTES: u64 = FORK_BODY_MAX as u64 * 40;

pub const REFILL_WALK_MAX: u64 = PRESYNC_LEAD_HEADERS;

pub const TRACKING_AUDIT_MS: u64 = 60_000;

pub const STALL_CONFIRM_AUDITS: u32 = 3;

pub const REPAIR_STUCK_REPEATS: u32 = 3;

pub const ANCHOR_PULL_MS: u64 = 10_000;

pub const ANCHOR_PULL_PEERS: usize = 3;

pub const DEEP_RECOVERY_DEADLINE_MS: u64 = 900_000;

pub const RECOVERY_FLAP_LIMIT: u32 = 3;

pub const RECOVERY_FLAP_WINDOW_MS: u64 = 3_600_000;

pub const QUARANTINE_MS: u64 = 1_800_000;

pub const QUARANTINE_MAX: usize = 256;

pub const COLDSTART_DEADLINE_MS: u64 = 60_000;

pub const COLDSTART_BACKOFF_MS: [u64; 5] = [60_000, 120_000, 240_000, 480_000, 600_000];

pub const TIP_REPUBLISH_MS: u64 = 5_000;

pub const SYNC_SUSPEND_MAX_MS: u64 = 300_000;

// cap on future-dated headers we hold rather than reject; bounds the memory a
// peer with a fast clock can make us spend.
pub const TIME_PARK_MAX: usize = 128;

pub const TIME_PARK_TTL_MS: u64 = 900_000;

pub const CLOCK_SKEW_GROUPS: usize = 3;

pub const REJECT_CACHE_MAX: usize = 65_536;

pub const BANLIST_MAX: usize = 65_536;

// one 100-point offence (bad pow/bits/sig/malformed) is enough to hit this.
pub const BAN_SCORE: u32 = 100;

pub const BAN_TIME_MS: u64 = 24 * 3_600_000;

pub const BAN_PROTOCOL_MS: u64 = 3_600_000;

// score halves every 10 minutes, so a peer that stops misbehaving recovers.
pub const SCORE_HALF_LIFE_MS: u64 = 600_000;

pub const FOREIGN_NETWORK_MS: u64 = 24 * 3_600_000;

pub const POW_BUDGET_MS_PER_WINDOW: u64 = 100;

pub const POW_BUDGET_WINDOW_MS: u64 = 10_000;

pub const POW_BUDGET_BURST_MS: u64 = 300;

pub const POW_POOL_MS_PER_SEC: u64 =
    VERIFY_WORKERS_REFERENCE * 1_000 * (100 - VERIFY_BANDWIDTH_HAIRCUT_PCT) / 100;

pub const POW_ANNOUNCE_RESERVE_MS: u64 =
    SYNC_MIN_RATE_IBD_PER_10S / 10 * HEADER_VERIFY_US_MAX / 1_000;

pub const INGEST_GLOBAL_BYTES_PER_SEC: u64 = 16 * 1024 * 1024;

pub const READ_GLOBAL_BYTES_PER_SEC: u64 = 32 * 1024 * 1024;

pub const READ_PEER_BYTES_PER_SEC: u64 = 2 * 1024 * 1024;

pub const SYNC_PEER_RESERVE_BYTES_PER_SEC: u64 = READ_PEER_BYTES_PER_SEC;

pub const SERVE_RATE_PEER_BYTES_PER_SEC: u64 = 4 * 1024 * 1024;

pub const SERVE_RATE_GLOBAL_BYTES_PER_SEC: u64 = 32 * 1024 * 1024;

pub const GETHEADERS_RATE_MONOTONE_PER_SEC: u32 = 16;

pub const GETHEADERS_RATE_SCAN_PER_10S: u32 = 4;

pub const CHECKPOINT_RATE_PER_10MIN: u32 = 4;

pub const GETCHECKPOINT_INTERVAL_MS: u64 = 600_000;

pub const CHECKPOINT_RATE_WINDOW_MS: u64 = 600_000;

pub const CHECKPOINT_DEDUP_MAX: usize = 16;

pub const GETCHECKPOINT_PER_CONN: u32 = 1;

pub const GETCHECKPOINT_ABUSE_MAX: u32 = 4;

pub const FORK_TIPS_MAX: usize = 8;

pub const FORK_HEADERS_MAX: usize = 800;

pub const KNOWN_HEADERS_MAX: usize = PRESYNC_LEAD_HEADERS as usize + FORK_HEADERS_MAX;

pub const KNOWN_HEADERS_BYTES: u64 = KNOWN_HEADERS_MAX as u64 * (32 + HEADER_BYTES as u64 + 8);

pub const MAX_REORG_DEPTH: u64 = spec::MAX_REORG_DEPTH;

pub const SYNC_WINDOW_SECS: u64 = spec::SYNC_WINDOW_SECS;

pub const CHECKPOINT_SUNSET_HEIGHT: u64 = spec::CHECKPOINT_SUNSET_HEIGHT;

pub const MAX_FUTURE_DRIFT_SECS: u64 = spec::MAX_FUTURE_DRIFT_SECS;

pub const IBD_WORK_DEFICIT_BLOCKS: u64 = 20;

pub const INBOX_BYTES: u64 = 2 * 1024 * 1024;

pub const INBOX_POOL_BYTES: u64 = 64 * 1024 * 1024;

pub const VALIDATE_Q_ITEMS: u64 = 16;

pub const VALIDATE_Q_BYTES: u64 = 16 * 1024 * 1024;

pub const TX_Q_ITEMS: u64 = 8_192;

pub const TX_Q_BYTES: u64 = 8 * 1024 * 1024;

pub const OUTBOX_BYTES: u64 = 32 * 1024 * 1024;

pub const OUTBOX_SOFT_BYTES: u64 = 24 * 1024 * 1024;

pub const OUTBOX_POOL_BYTES: u64 = 256 * 1024 * 1024;

pub const ANONS_OUTBOX_ITEMS: u64 = 4_096;

pub const REORG_PREFETCH_BYTES: u64 = 32 * 1024 * 1024;

pub const ORPHAN_BODIES_ITEMS: u64 = 8;

pub const ORPHAN_BODIES_BYTES: u64 = 8 * 1024 * 1024;

pub const ORPHAN_BODIES_TTL_MS: u64 = 120_000;

pub const KNOWN_TX_PER_PEER: usize = 16_384;

pub const SEEN_TX_GLOBAL: usize = 65_536;

pub const TRICKLE_MS: u64 = 500;

pub const INV_REPEATS: u8 = 3;

pub const TX_POLL_MS: u64 = 1_000;

pub const INV_TX_PER_MSG: usize = 64;

pub const INV_TXS_PER_MSG_MAX: usize = 512;

pub const TX_INFLIGHT_PER_PEER: usize = 32;

pub const TX_INFLIGHT_MAX: usize = 512;

pub const TX_REQUEST_TIMEOUT_MS: u64 = 60_000;

pub const TX_ANNOUNCE_QUEUE_MAX: usize = 4_096;

pub const ADDR_NEW_MAX: usize = 4_096;

pub const ADDR_TRIED_MAX: usize = 1_024;

pub const SELF_ADDR_MS: u64 = 24 * 3_600_000;

pub const SELF_ADDR_JITTER_MS: u64 = 4 * 3_600_000;

pub const FEELER_INTERVAL_MS: u64 = 120_000;

// a tried address falls back to new after this many plain dial failures.
pub const DEMOTE_AFTER_FAILURES: u32 = 8;

// protocol-level deaths demote faster than mere unreachability.
pub const DEMOTE_AFTER_PROTOCOL_DEATHS: u32 = 3;

pub const SEED_DEMOTION_ADDR_COUNT: usize = 64;

pub const USELESS_PEER_MS: u64 = 1_800_000;

pub const ADDR_PER_SOURCE_GROUP_MAX: usize = ADDR_NEW_MAX / 16;

pub const ADDR_UNSOLICITED_MAX: usize = 10;

pub const GETADDR_PER_CONN: u32 = 1;

pub const GETADDR_ABUSE_MAX: u32 = 5;

pub const ADDR_MAX_AGE_SECS: u64 = 7 * 86_400;

pub const ADDR_FRESH_SECS: u64 = 3 * 3_600;

pub const ADDR_SAMPLE_PROBES: usize = 2 * ADDR_MSG_MAX;

pub const ADDR_RECS_PER_CONN: usize = ADDR_MSG_MAX + 64;

pub const HEADER_VERIFY_US_MIN: u64 = 1_300;

pub const HEADER_VERIFY_US_MAX: u64 = 3_000;

pub const VERIFY_WORKERS_REFERENCE: u64 = 2;

pub const VERIFY_BANDWIDTH_HAIRCUT_PCT: u64 = 15;

pub const GATE_NS_PER_HEADER: u64 = 2_200;

const _: () = assert!(CAP_HELLO == 167, "HELLO cap is 103 + 64");
const _: () = assert!(CAP_GETHEADERS == 2_084, "4 + 64*32 + 32");
const _: () = assert!(CAP_HEADERS == 264_004, "4 + 2000*132");
const _: () = assert!(CAP_CHECKPOINT == 1_016, "8 + 32 + 1 + 15*65");
const _: () = assert!(CAP_INV == 135_172, "4 + 4096*33");
const _: () = assert!(CAP_ADDR == 15_364, "4 + 512*30");
const _: () = assert!(
    CAP_BLOCK <= MAX_P2P_MSG_BYTES && CAP_HEADERS <= MAX_P2P_MSG_BYTES,
    "every per-command cap must sit under SPEC 10's 8 MiB frame ceiling"
);
const _: () = assert!(
    MAX_OUTBOUND + MAX_INBOUND + WHITELIST_RESERVE == MAX_PEERS,
    "16 + 96 + 16 = 128 = SPEC MAX_PEERS"
);
const _: () = assert!(FD_TOTAL < FD_CEILING, "the FD budget must add up");
const _: () = assert!(
    OUTBOUND_TARGET > 0 && OUTBOUND_TARGET + FEELER_SLOTS == MAX_OUTBOUND,
    "the standing outbound target is MAX_OUTBOUND minus the feeler slots; if either moves, re-derive this"
);
const _: () = assert!(
    OUTBOUND_PER_GROUP <= OUTBOUND_PER_GROUP_WIDENED && OUTBOUND_PER_GROUP_WIDENED <= MAX_OUTBOUND,
    "widening relaxes the /16 diversity rule and never the count"
);
const _: () = assert!(
    CONN_MANAGER_TICK_MS >= TICK_MS && DIAL_RETRY_MS >= CONN_MANAGER_TICK_MS,
    "the maintenance pass must be coarser than the tick that drives it, and the per-address floor coarser than the pass, or the pass is the connect storm"
);
const _: () = assert!(
    DIAL_RETRY_MS >= CONNECT_TIMEOUT_MS + HANDSHAKE_TIMEOUT_MS,
    "an address must not be re-dialled while the previous attempt to it can still be in flight"
);
const _: () = assert!(
    CHECKPOINT_DEDUP_MAX as u32 >= CHECKPOINT_RATE_PER_10MIN,
    "the dedup ring must cover at least one full rate window, or a peer inside its own rate could push its earliest record out of the ring and re-send it free"
);
const _: () = assert!(
    FORK_BODY_MAX as u64 <= MAX_REORG_DEPTH,
    "the competing-branch body list must never reach past the depth `plaine-chain` will refuse: a body beyond the cap is one we have already decided not to apply"
);
const _: () = assert!(
    FORK_BODY_INFLIGHT > 0 && FORK_BODY_INFLIGHT <= FORK_BODY_MAX,
    "competing-branch bodies bypass the ready buffer, so this number times the block size is their whole memory bound; zero would be a list that never drains"
);
const _: () = assert!(
    ADDR_PER_SOURCE_GROUP_MAX > 0 && ADDR_PER_SOURCE_GROUP_MAX * 16 <= ADDR_NEW_MAX,
    "no single source /16 may be entitled to more than a sixteenth of `new`; if this ever reaches ADDR_NEW_MAX the quota has stopped bounding anything"
);
const _: () = assert!(
    ADDR_UNSOLICITED_MAX < ADDR_MSG_MAX && ADDR_UNSOLICITED_MAX < ADDR_PER_SOURCE_GROUP_MAX,
    "an ADDR nobody asked for must be strictly cheaper than one we asked for, or 'ask once per connection' buys nothing"
);
const _: () = assert!(
    ADDR_RECS_PER_CONN >= ADDR_MSG_MAX,
    "one connection must be able to deliver the answer we asked it for"
);
const _: () = assert!(
    ADDR_FRESH_SECS < ADDR_MAX_AGE_SECS,
    "fresh is the ordering half, max age the admission half"
);
const _: () = assert!(
    FD_INBOUND_HANDSHAKE == 112,
    "FD_INBOUND_HANDSHAKE is ACCEPT_BURST + ACCEPT_RATE x HANDSHAKE_TIMEOUT, \
     i.e. the peak half-open inbound count, not the rate alone"
);
const _: () = assert!(
    TICK_MS * 4 <= TRICKLE_MS * 2 && TICK_MS * 20 <= LOCATE_TIMEOUT_MS,
    "the tick must be fine enough to be jitter against every deadline it drives"
);
const _: () = assert!(
    SYNC_PEER_RESERVE_BYTES_PER_SEC <= INGEST_GLOBAL_BYTES_PER_SEC,
    "the sync reserve is carved out of the global ingest budget"
);
const _: () = assert!(
    SYNC_PEER_RESERVE_BYTES_PER_SEC == READ_PEER_BYTES_PER_SEC,
    "a reserve larger than one peer's read cap is permanently unusable"
);
const _: () = assert!(
    PRESYNC_LEAD_BYTES == 8_650_752,
    "PRESYNC_LEAD is sized to fill the 11 staging window exactly"
);
const _: () = assert!(
    POW_POOL_MS_PER_SEC * 1_000 / HEADER_VERIFY_US_MAX >= SYNC_MIN_RATE_IBD_PER_10S / 10,
    "the interpreter pool must admit at least the header rate the rate floor \
     demands of a sync peer, or the node throttles itself below the bar it \
     enforces on others"
);
const _: () = assert!(
    (5_200_000 - CHECKPOINT_SUNSET_HEIGHT) * HEADER_VERIFY_US_MAX
        / 1_000
        / POW_POOL_MS_PER_SEC
        / 60
        <= 138,
    "the enforced interpreter pool must keep the header phase inside the \
     60-138 min the crate's own budget test asserts"
);
const _: () = assert!(
    BODY_WINDOW_BYTES < INBOX_POOL_BYTES,
    "the in-flight body window must not over-commit the inbox pool"
);
const _: () = assert!(
    ARENA_MAX < CAP_BLOCK,
    "arenas must not be able to grow to a full block, or 128 peers pin 128 MiB"
);
const _: () = assert!(
    PAUSE_MAX_MS > PONG_TIMEOUT_MS,
    "a paused socket must outlive an ordinary pong window, but not forever"
);
const _: () = assert!(
    INV_BLOCKS_PER_MSG_MAX == UNSOLICITED_HEADERS_MAX
        && INV_HEADERS_ADMIT_MAX == UNSOLICITED_HEADERS_MAX,
    "the items examined from one INV and the headers its answer may admit are \
     the same number, so they must not drift"
);
const _: () = assert!(
    INV_PROBE_INTERVAL_MS * POW_BUDGET_MS_PER_WINDOW / POW_BUDGET_WINDOW_MS
        >= INV_HEADERS_ADMIT_MAX as u64 * HEADER_VERIFY_US_MAX / 1_000,
    "the cheap per-peer probe gate (one integer compare) must bind before the \
     expensive one (a per-peer interpreter bucket that has already paid for a \
     decode): one probe's answer costs 24 ms and the interval must grant at \
     least that much of the peer's own allowance"
);
const _: () = assert!(
    POW_ANNOUNCE_RESERVE_MS == SYNC_MIN_RATE_IBD_PER_10S / 10 * HEADER_VERIFY_US_MAX / 1_000
        && POW_ANNOUNCE_RESERVE_MS < POW_POOL_MS_PER_SEC,
    "the announcement floor is exactly our own IBD need at the rate floor we \
     enforce on our sync peer, and it must leave the pool usable"
);
const _: () = assert!(
    MAX_PEERS as u64 * (POW_BUDGET_MS_PER_WINDOW * 1_000 / POW_BUDGET_WINDOW_MS)
        + POW_ANNOUNCE_RESERVE_MS
        > POW_POOL_MS_PER_SEC,
    "the enforced per-peer announcement allowance summed over the whole peer \
     set (128 x 10 ms/s) plus our own IBD need oversubscribes the interpreter \
     pool at the worst-case 3 ms/header. If this stops holding, the floor is \
     dead weight; re-derive it, don't delete it"
);
const _: () = assert!(
    INV_PROBE_GLOBAL_BURST >= INV_PROBE_GLOBAL_PER_SEC
        && INV_PROBE_INFLIGHT_MAX == INV_PROBE_GLOBAL_BURST as usize,
    "the outstanding-probe set is sized to the probe burst, because that is the \
     most that can be outstanding at once"
);
const _: () = assert!(
    INV_PROBE_INFLIGHT_TTL_MS < LOCATE_TIMEOUT_MS,
    "the outstanding-probe TTL is ~2x an intercontinental RTT, not the locate \
     window: the set is attacker-writable, so its worst case is a block \
     delayed by the TTL, not a block suppressed"
);
