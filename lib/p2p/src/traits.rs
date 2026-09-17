use crate::constants::HEADER_BYTES;

pub type Hash32 = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Mono(pub u64);

impl Mono {
    pub const ZERO: Mono = Mono(0);

    pub fn plus_ms(self, ms: u64) -> Mono {
        Mono(self.0.saturating_add(ms))
    }

    pub fn since(self, earlier: Mono) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    pub fn expired(self, start: Mono, deadline_ms: u64) -> bool {
        self.since(start) >= deadline_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TipSnapshot {
    pub height: u64,
    pub hash: Hash32,
    pub cum_work: [u8; 32],
    pub time: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRec {
    pub height: u64,
    pub hash: Hash32,
    pub prev_hash: Hash32,
    pub time: u64,
    pub bits: u32,
    pub target: Hash32,
    pub raw: [u8; HEADER_BYTES],
}

pub type Anchor = plaine_consensus::rules::Anchor;

pub type SignedCheckpoint = plaine_consensus::rules::SignedCheckpoint;

pub type CheckpointSig = plaine_consensus::rules::CheckpointSig;

pub type Work = plaine_consensus::rules::Work;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Door {
    Requested,
    Announced,
}

#[derive(Clone, Debug)]
pub struct HeaderBatch {
    pub headers: Vec<HeaderRec>,
    pub source: PeerId,
    pub door: Door,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub hash: Hash32,
    pub height: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accepted {
    pub connected: u64,
    pub verified_height: u64,
    pub held: Option<Held>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SinkError {
    Full,
    Invalid(&'static str),

    RefusedAt { height: u64, why: &'static str },
    Fatal(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SinkCapacity {
    pub blocks: u64,
    pub bytes: u64,
}

impl SinkCapacity {
    pub fn admits(&self, bytes: u64) -> bool {
        self.blocks > 0 && self.bytes >= bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorUpdate {
    Advanced(Anchor),
    Unchanged,
    Unverified,
    Contradicts { height: u64, hash: Hash32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PeerId(pub u64);

pub trait ChainView: Send + Sync + 'static {
    fn tip(&self) -> TipSnapshot;

    fn header_at(&self, height: u64) -> Option<HeaderRec>;

    fn header_by_hash(&self, h: &Hash32) -> Option<HeaderRec>;

    fn ancestor_at(&self, tip: &Hash32, height: u64) -> Option<Hash32>;

    fn locator(&self) -> Vec<Hash32>;

    fn headers_from(&self, loc: &[Hash32], stop: &Hash32, max: usize) -> Vec<[u8; HEADER_BYTES]>;

    fn have_body(&self, h: &Hash32) -> bool;

    fn body_bytes(&self, h: &Hash32) -> Option<Vec<u8>>;

    fn anchor(&self) -> Option<Anchor>;

    fn anchor_record(&self) -> Option<SignedCheckpoint> {
        None
    }

    fn checkpoints(&self) -> Vec<(u64, Hash32)>;

    fn pow_verified_floor(&self) -> u64;

    fn wanted_bodies(&self) -> Vec<Hash32> {
        Vec::new()
    }

    fn mempool_txids(&self) -> Vec<Hash32> {
        Vec::new()
    }

    fn tx_bytes(&self, txid: &Hash32) -> Option<Vec<u8>> {
        let _ = txid;
        None
    }
}

pub trait BlockSink: Send + Sync + 'static {
    fn submit_headers(&self, b: HeaderBatch) -> Result<Accepted, SinkError>;

    fn submit_block(&self, hash: Hash32, bytes: Vec<u8>) -> Result<(), SinkError>;

    fn submit_tx(&self, txid: Hash32, bytes: Vec<u8>) -> Result<(), SinkError>;

    fn submit_checkpoint(&self, cp: SignedCheckpoint) -> Result<AnchorUpdate, SinkError>;

    fn capacity(&self) -> SinkCapacity;
}

pub trait Clock: Send + Sync + 'static {
    fn now_unix(&self) -> u64;

    fn mono(&self) -> Mono;
}

pub trait PowVerifier: Send + Sync + 'static {
    fn verify(&self, hdr: &[u8; HEADER_BYTES]) -> bool;

    fn cost_ms(&self) -> u64;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    ColdStartRetry {
        attempt: u32,
        backoff_ms: u64,
    },
    NoEligibleSyncPeer {
        waived: PeerId,
    },
    RotationBudgetExhausted,
    LocalStallRotation {
        suspended_ms: u64,
    },

    StrandedBeyondReorgCap {
        our_tip: u64,
        their_tip: u64,
        depth: u64,
    },
    DeepRecoveryFlapping {
        branch: Hash32,
    },
    BodyUnavailable {
        height: u64,
    },

    BodiesUnappliable {
        applied: u64,
        ready: usize,
        missing: u64,
    },

    NoBodySupplier {
        wanted: usize,
        peers: usize,
    },
    ClockSkewSuspected {
        median_delta_secs: i64,
    },
    AnchorContradiction {
        height: u64,
        hash: Hash32,
    },
    AnchorChainUnavailable {
        height: u64,
        hash: Hash32,
    },
    SinkFatal(&'static str),
    QueueOverflow {
        queue: &'static str,
        policy: Policy,
    },

    ClaimUnsubstantiated {
        peer: PeerId,
        claimed: u64,
        proved: u64,
    },

    AheadPeersAllIneligible {
        claimed: u64,
        ours: u64,
    },

    HeaderRefusedByChain {
        height: u64,
        why: &'static str,
        from: PeerId,
    },

    HeaderRepairStuck {
        height: u64,
        why: &'static str,
        repeats: u32,
        our_tip: u64,
    },

    SyncRotation {
        peer: PeerId,
        kind: RotationKind,
    },

    BodyBacklogUnreachable {
        applied: u64,
        verified: u64,
    },

    ForkBodiesWanted {
        applied: u64,
        depth: u64,
        missing: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationKind {
    LocateTimeout,
    NoProgress,
    BelowRateFloor,
    LocalSuspendExceeded,
    LocalReadRefused,
    ProbationExpired,
    DesigneeLost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    PauseReads,
    DropNewest,
    RefuseServe,
    Disconnect,
    DropLargestOutbox,
    EvictOldest,
    StreamApply,
    ThrottleRequests,
}

pub type Sink = Box<dyn Fn(Condition) + Send + Sync>;
