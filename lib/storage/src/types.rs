use plaine_consensus::constants::HEADER_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TipRef {
    pub hash: [u8; 32],
    pub height: u64,
    pub chainwork: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
}

impl Account {
    // A zeroed account is never stored. The state table holds live rows only, so
    // an absent key and a zero balance/nonce are one and the same.
    #[inline]
    pub fn is_absent(&self) -> bool {
        self.balance == 0 && self.nonce == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDelta {
    pub addr: [u8; 20],
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UndoRec {
    pub addr: [u8; 20],
    pub prev_balance: u128,
    pub prev_nonce: u64,
    pub existed: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct BlockToCommit<'a> {
    pub header: &'a [u8; HEADER_BYTES],
    pub hash: [u8; 32],
    pub height: u64,
    pub body: &'a [u8],
    pub deltas: &'a [StateDelta],
    pub undo: &'a [UndoRec],
    pub issued_delta: u128,
    pub chainwork: [u8; 32],
    pub txids: Option<&'a [[u8; 32]]>,
}

#[derive(Debug, Clone, Copy)]
pub struct ReorgPlan<'a> {
    pub fork_height: u64,
    pub rollback: &'a [u64],
    pub apply: &'a [BlockToCommit<'a>],
}

#[derive(Debug, Clone, Copy)]
pub struct DeepReorgPlan<'a> {
    pub fork_height: u64,
    pub rewind_to: u64,
    pub replay: &'a [BlockToCommit<'a>],
    pub apply: &'a [BlockToCommit<'a>],
}

// A monotonic ladder - a side header only climbs these rungs as more of it gets
// checked, never back down. NOTE: the discriminants are on disk; do not renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderStatus {
    ValidHeader = 1,
    PowOk = 2,
    BodyOk = 3,
    Connected = 4,
}

impl HeaderStatus {
    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Self::ValidHeader),
            2 => Some(Self::PowOk),
            3 => Some(Self::BodyOk),
            4 => Some(Self::Connected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SideHeader {
    pub header: [u8; HEADER_BYTES],
    pub height: u64,
    pub status: HeaderStatus,
}

#[derive(Debug, Clone, Copy)]
pub struct CommitReceipt {
    pub seq: u64,
    pub tip: TipRef,
    pub durable: bool,
    pub bytes_written: u64,
    pub micros: u64,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct OpenReport {
    pub tip: TipRef,
    pub headers_truncated_to: Option<u64>,
    pub bodies_truncated_to: Option<u64>,
    pub hdr_scratch_discarded: u64,
    pub body_scratch_discarded: u64,
    pub hdr_undo_replayed: Option<(u64, u32)>,
    pub index_rebuilt: bool,
    pub bidx_rebuilt_segments: Vec<u32>,
    pub segments_unlinked: u32,
    pub open_micros: u64,
    pub ibd_batch_blocks: u32,
    pub integrity: crate::integrity::IntegrityReport,
    pub anchor_floor: u64,
    pub anchors_verified: u32,
    pub anchors_minted: u32,
    pub anchors_dropped: u32,
    pub anchor_floor_raised: Option<(u64, u64)>,
    pub unverifiable_body_ranges: Vec<(u64, u64, crate::integrity::UnverifiableCause)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallPoint {
    AfterHeaderWrite,
    AfterBodyWrite,
    BeforeRedbCommit,
    AfterRedbCommit,
    ReorgAfterUndoWritten,
    ReorgMidHeaderOverwrite,
    ReorgBeforeStateCommit,
    AfterSegmentSeal,
    PruneAfterFloorCommitted,
    PruneMidUnlink,
    BeforeBoundaryCommit,
    AfterBoundaryCommit,
}
