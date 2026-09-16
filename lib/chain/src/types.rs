use plaine_consensus::constants::Network;
use plaine_consensus::asert::Target;
use plaine_consensus::constants::{
    ASERT_ANCHOR_INTERVAL, BLOCK_TIME_SECS, HEADER_BYTES, MAX_MEMPOOL_NONCE_GAP, MAX_MEMPOOL_TXS,
    MAX_MEMPOOL_TXS_PER_SENDER, MAX_REORG_DEPTH, SYNC_WINDOW_SECS,
};

pub use plaine_consensus::codec::Header;
pub use plaine_consensus::rules::{Anchor, SignedCheckpoint, Work};

pub type Hash32 = [u8; 32];

pub type Address = [u8; 20];

pub type SourceId = u32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
}

impl Account {
    pub fn is_absent(&self) -> bool {
        self.balance == 0 && self.nonce == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipRef {
    pub height: u64,
    pub hash: Hash32,
    pub time: u64,
    pub chainwork: Work,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRec {
    pub height: u64,
    pub hash: Hash32,
    pub prev_hash: Hash32,
    pub time: u64,
    pub bits: u32,
    pub raw: [u8; HEADER_BYTES],
}

impl HeaderRec {
    pub fn from_raw(raw: [u8; HEADER_BYTES]) -> HeaderRec {
        let h = Header::decode(&raw).expect("132 bytes always decode structurally");
        HeaderRec {
            height: h.height,
            hash: plaine_consensus::crypto::header_hash(&raw),
            prev_hash: h.prev_hash,
            time: h.time,
            bits: h.bits,
            raw,
        }
    }

    pub fn header(&self) -> Header {
        Header::decode(&self.raw).expect("132 bytes always decode structurally")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideHeaderRec {
    pub rec: HeaderRec,
    pub chainwork: Work,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UndoRec {
    pub addr: Address,
    pub prev_balance: u128,
    pub prev_nonce: u64,
    pub existed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateDelta {
    pub addr: Address,
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBlock {
    pub header_raw: [u8; HEADER_BYTES],
    pub hash: Hash32,
    pub height: u64,
    pub body: Vec<u8>,
    pub deltas: Vec<StateDelta>,
    pub undo: Vec<UndoRec>,
    pub issued_delta: u128,
    pub chainwork: Work,
    pub txids: Vec<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgCommit {
    pub rollback: Vec<u64>,
    pub apply: Vec<CommitBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeepReorgCommit {
    pub rewind_to: u64,
    pub apply: Vec<CommitBlock>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub tip: TipRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    OurStore,
    Untrusted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolParams {
    pub max_txs: usize,
    pub max_bytes: usize,
    pub max_nonce_gap: u64,
    pub max_txs_per_sender: usize,
    pub ttl_secs: u64,
    pub relay_fee_floor: u128,
    pub ingress_per_source: u32,
    pub ingress_global: u32,
    pub reorg_reinject_cap: usize,
}

pub const TX_COST_MILLI: u64 = 1_000;

impl MempoolParams {
    // One tx per nonce across the gap window, capped by the per-sender limit.
    pub fn effective_per_sender(&self) -> usize {
        (self.max_nonce_gap as usize + 1).min(self.max_txs_per_sender)
    }

    pub fn ingress_source_rate_milli(&self) -> u64 {
        (self.ingress_per_source as u64).saturating_mul(TX_COST_MILLI)
    }

    pub fn ingress_source_burst_milli(&self) -> u64 {
        self.ingress_source_rate_milli()
    }

    pub fn ingress_shared_rate_milli(&self) -> u64 {
        (self.ingress_global as u64).saturating_mul(TX_COST_MILLI) / 2
    }

    pub fn ingress_shared_burst_milli(&self) -> u64 {
        self.ingress_shared_rate_milli()
    }

    pub fn ingress_reserve_rate_milli(&self, max_peers: usize) -> u64 {
        self.ingress_shared_rate_milli() / max_peers.max(1) as u64
    }

    pub fn ingress_reserve_burst_milli(&self) -> u64 {
        2 * TX_COST_MILLI
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxOrigin {
    Local,
    Peer(SourceId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Solicitation {
    Unsolicited,
    SolicitedIbd,
    SolicitedSteady,
}

impl Solicitation {
    pub fn charges_budget(&self) -> bool {
        !matches!(self, Solicitation::SolicitedIbd)
    }

    pub fn charges_child_quota(&self) -> bool {
        matches!(self, Solicitation::Unsolicited)
    }
}

impl Default for MempoolParams {
    fn default() -> Self {
        MempoolParams {
            max_txs: MAX_MEMPOOL_TXS,
            max_bytes: 12 * 1024 * 1024,
            max_nonce_gap: MAX_MEMPOOL_NONCE_GAP,
            max_txs_per_sender: MAX_MEMPOOL_TXS_PER_SENDER,
            ttl_secs: 24 * 3600,
            // the consensus floor (1 mile); the fee market sets the real floor.
            relay_fee_floor: 1,
            ingress_per_source: 100,
            ingress_global: 2_000,
            reorg_reinject_cap: 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Real,
    Regtest,
}

#[derive(Clone, Debug)]
pub struct ChainParams {
    pub profile: Profile,
    pub network: Network,
    pub pow_limit: Target,
    pub genesis_bits: u32,
    pub asert_anchor_interval: u64,
    pub author_pubkey: [u8; 32],
    pub authority_keys: Vec<[u8; 32]>,
    pub checkpoint_threshold: usize,
    pub max_reorg_depth: u64,
    pub sync_window_secs: u64,
    pub pow_budget_micros: u64,
    pub pow_budget_window_ms: u64,
    pub pow_budget_burst_micros: u64,
    pub max_duplicates_per_batch: u32,
    pub max_duplicates_per_window: u32,
    pub duplicate_window_secs: u64,
    pub max_peers: usize,
    pub cpu_pool_threads: usize,
    pub child_pow_failures_per_source: u32,
    pub child_quota_window_secs: u64,
    pub max_sources: usize,
    pub max_side_headers: usize,
    pub max_staged_headers: usize,
    pub negative_cache_entries: usize,
    pub reorg_overlay_max_accounts: usize,
    pub mempool: MempoolParams,
}

impl ChainParams {
    pub fn default_pow_limit() -> Target {
        Target([u64::MAX, u64::MAX, u64::MAX, 0x0000_FFFF_FFFF_FFFF])
    }

    pub const REGTEST_BITS: u32 = 0x207F_FFFF;

    pub fn regtest_pow_limit() -> Target {
        Target::from_compact(ChainParams::REGTEST_BITS)
            .expect("0x207FFFFF is a valid compact encoding")
    }

    pub fn regtest(author_pubkey: [u8; 32]) -> ChainParams {
        let pow_limit = ChainParams::regtest_pow_limit();
        ChainParams {
            profile: Profile::Regtest,
            genesis_bits: ChainParams::REGTEST_BITS,
            pow_limit,
            author_pubkey,

            ..ChainParams::default()
        }
    }

    pub fn profile_is_consistent(&self) -> bool {
        match self.profile {
            Profile::Real => self.pow_limit == ChainParams::default_pow_limit(),
            Profile::Regtest => self.pow_limit == ChainParams::regtest_pow_limit(),
        }
    }

    pub fn class_rate_micros_per_sec(&self) -> u64 {
        250_000u64.saturating_mul(self.cpu_pool_threads as u64)
    }

    pub fn class_shared_rate_micros_per_sec(&self) -> u64 {
        self.class_rate_micros_per_sec() / 2
    }

    pub fn class_shared_burst_micros(&self) -> u64 {
        self.class_shared_rate_micros_per_sec()
    }

    pub fn class_reserve_rate_micros_per_sec(&self) -> u64 {
        self.class_shared_rate_micros_per_sec() / self.max_peers.max(1) as u64
    }

    pub fn class_reserve_burst_micros(&self, cost_micros: u64) -> u64 {
        cost_micros.saturating_mul(2)
    }

    // Every peer's reserve must refill one interpreter call per 30s or honest
    // peers starve.
    pub fn class_reserve_is_survivable(&self, cost_micros: u64) -> bool {
        self.class_reserve_rate_micros_per_sec().saturating_mul(30) >= cost_micros
    }

    pub fn class_aggregate_rate_micros_per_sec(&self) -> u64 {
        self.class_shared_rate_micros_per_sec().saturating_add(
            self.class_reserve_rate_micros_per_sec()
                .saturating_mul(self.max_sources as u64),
        )
    }
}

impl Default for ChainParams {
    fn default() -> Self {
        let pow_limit = ChainParams::default_pow_limit();
        ChainParams {
            profile: Profile::Real,
            network: Network::Main,
            genesis_bits: pow_limit.to_compact(),
            pow_limit,
            asert_anchor_interval: ASERT_ANCHOR_INTERVAL,
            author_pubkey: [0u8; 32],
            authority_keys: Vec::new(),
            checkpoint_threshold: 1,
            max_reorg_depth: MAX_REORG_DEPTH,
            sync_window_secs: SYNC_WINDOW_SECS,
            pow_budget_micros: 100_000,
            pow_budget_window_ms: 10_000,
            pow_budget_burst_micros: 300_000,
            max_duplicates_per_batch: 256,
            max_duplicates_per_window: 1_024,
            duplicate_window_secs: 60,
            max_peers: 128,
            cpu_pool_threads: 2,
            child_pow_failures_per_source: 1,
            child_quota_window_secs: 2 * BLOCK_TIME_SECS,
            max_sources: 128,
            max_side_headers: 16_384,
            max_staged_headers: 256,
            negative_cache_entries: 65_536,
            reorg_overlay_max_accounts: 714_000,
            mempool: MempoolParams::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub hash: Hash32,
    pub height: u64,
    pub repair_from: u64,
    pub why: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub hash: Hash32,
    pub height: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accepted {
    pub connected: u64,
    pub duplicates: u32,
    pub rejected: u32,
    pub staged: u32,
    pub verified_height: u64,
    pub first_rejection: Option<Rejection>,
    pub first_held: Option<Held>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    NoChange,
    NeedBodies(Vec<Hash32>),

    Advanced {
        tip: TipRef,
        rolled_back: u64,
        applied: u64,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainStats {
    pub headers_connected: u64,
    pub bodies_validated: u64,
    pub reorgs: u64,
    pub invalidated: u64,
    pub poisoned: u64,
    pub deep_reorgs: u64,
    pub side_headers_restored: u64,
    pub headers_readmitted: u64,
}
