use crate::types::{Address, Hash32, SourceId};
use plaine_consensus::rules::RuleError;
use plaine_consensus::tx::TxError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permanence {
    Permanent,
    Transient,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    BadHeaderLength { got: usize },
    ExtRootNotZero,
    AuthorNoteLen { got: u32 },
    BadVersion { got: u32 },
    BadBits { got: u32 },
    CheckpointMismatch { height: u64 },
    UnknownParent { prev: Hash32 },
    HeightNotParentPlusOne { got: u64, expected: u64 },
    BitsNotAsert { got: u32, expected: u32 },
    AsertAnchorUnavailable { height: u64 },
    TimestampTooOld { mtp: u64, time: u64 },
    TimestampTooFarInFuture { time: u64, limit: u64 },
    ForkTooDeep { depth: u64, cap: u64 },
    InsufficientClaimedWork,
    PowInvalid { hash: Hash32 },
    BudgetExhausted { source: SourceId },
    DuplicateFlood { source: SourceId, count: u32 },
    StagingFull { source: SourceId },
    BatchTooLong { got: usize, cap: usize },
    TooManySources { source: SourceId, cap: usize },
    BodyNotAdmissible { hash: Hash32 },
    BodyAlreadyHeld { hash: Hash32 },
    BodyStructure { detail: &'static str },
    TxRootMismatch,
    Tx { index: usize, err: TxError },
    BadTransferSignature { index: usize },
    FeeBelowFloor { index: usize },
    BadNonce { index: usize, expected: u64, got: u64 },
    InsufficientBalance { index: usize, need: u128, have: u128 },
    ArithmeticOverflow,
    Rule(RuleError),
    BranchInvalid { height: u64, hash: Hash32, cause: Box<Reject> },
    ResyncRequired { fork_height: u64, replay_floor: u64 },
    Busy,
    SinkRefused { detail: &'static str },
    Halted { detail: &'static str },
    BootInvariant { detail: &'static str },
    TxKnown,
    TxStale { next: u64, got: u64 },
    NonceGapTooLarge { next: u64, got: u64 },
    TxTypeNotRelayable { type_byte: u8 },
    BelowRelayFloor { fee: u128, floor: u128 },
    ReplacementUnderpriced { need: u128, got: u128 },
    PoolFull,
    SenderCap { cap: usize },
    TxDecode,
    TxTooLarge { got: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitTag {
    Malformed,
    TooLarge,
    FeeBelowFloor,
    BadSignature,
    NotAuthorKey,
    NonceOutOfRange,
    InsufficientFunds,
    Duplicate,
    ReplacementUnderpriced,
    PoolFull,
    NotReady,
}

impl Reject {
    pub fn submit_tag(&self) -> SubmitTag {
        use plaine_consensus::tx::TxError as T;
        match self {
            Reject::TxDecode
            | Reject::TxTypeNotRelayable { .. }
            | Reject::BadHeaderLength { .. }
            | Reject::ExtRootNotZero
            | Reject::AuthorNoteLen { .. }
            | Reject::BadVersion { .. }
            | Reject::BadBits { .. }
            | Reject::BodyStructure { .. }
            | Reject::TxRootMismatch
            | Reject::BodyNotAdmissible { .. }
            | Reject::BodyAlreadyHeld { .. }
            | Reject::ArithmeticOverflow => SubmitTag::Malformed,
            Reject::TxTooLarge { .. } => SubmitTag::TooLarge,
            Reject::BelowRelayFloor { .. } | Reject::FeeBelowFloor { .. } => {
                SubmitTag::FeeBelowFloor
            }
            Reject::BadTransferSignature { .. } => SubmitTag::BadSignature,
            Reject::TxStale { .. } | Reject::NonceGapTooLarge { .. } | Reject::BadNonce { .. } => {
                SubmitTag::NonceOutOfRange
            }
            Reject::InsufficientBalance { .. } => SubmitTag::InsufficientFunds,
            Reject::TxKnown => SubmitTag::Duplicate,
            Reject::ReplacementUnderpriced { .. } => SubmitTag::ReplacementUnderpriced,
            Reject::PoolFull | Reject::SenderCap { .. } | Reject::StagingFull { .. } => {
                SubmitTag::PoolFull
            }

            Reject::Tx { err, .. } => match err {
                T::NotAuthorKey => SubmitTag::NotAuthorKey,
                T::BadSignature => SubmitTag::BadSignature,
                T::FeeBelowFloor { .. } => SubmitTag::FeeBelowFloor,
                T::BadNonce { .. } => SubmitTag::NonceOutOfRange,
                T::InsufficientBalance { .. } => SubmitTag::InsufficientFunds,
                T::AnnouncementLength { .. }
                | T::AmountOverflow
                | T::FeeSumOverflow
                | T::RecordDoesNotDecode { .. }
                | T::MissingCoinbase
                | T::MisplacedCoinbase { .. }
                | T::CoinbaseHeightMismatch { .. }
                | T::CoinbaseRewardMismatch { .. }
                | T::CoinbaseFeesMismatch { .. }
                | T::AuthorNoteLenMismatch { .. }
                | T::AuthorNoteTooLong { .. } => SubmitTag::Malformed,
            },

            Reject::Busy
            | Reject::Halted { .. }
            | Reject::SinkRefused { .. }
            | Reject::BootInvariant { .. }
            | Reject::BudgetExhausted { .. }
            | Reject::DuplicateFlood { .. }
            | Reject::BatchTooLong { .. }
            | Reject::TooManySources { .. }
            | Reject::CheckpointMismatch { .. }
            | Reject::UnknownParent { .. }
            | Reject::HeightNotParentPlusOne { .. }
            | Reject::BitsNotAsert { .. }
            | Reject::AsertAnchorUnavailable { .. }
            | Reject::TimestampTooOld { .. }
            | Reject::TimestampTooFarInFuture { .. }
            | Reject::ForkTooDeep { .. }
            | Reject::InsufficientClaimedWork
            | Reject::PowInvalid { .. }
            | Reject::Rule(_)
            | Reject::BranchInvalid { .. }
            | Reject::ResyncRequired { .. } => SubmitTag::NotReady,
        }
    }

    pub fn why(&self) -> &'static str {
        match self {
            Reject::BadHeaderLength { .. } => "header is not 132 bytes",
            Reject::ExtRootNotZero => "ext_root is not zero",
            Reject::AuthorNoteLen { .. } => "author_note_len out of range",
            Reject::BadVersion { .. } => "version bits are not 001",
            Reject::BadBits { .. } => "bits do not expand to a legal target",
            Reject::CheckpointMismatch { .. } => "checkpoint mismatch at this height",
            Reject::UnknownParent { .. } => "the chain does not hold the parent",
            Reject::HeightNotParentPlusOne { .. } => "height is not parent + 1",
            Reject::BitsNotAsert { .. } => "bits are not ASERT(parent)",
            Reject::AsertAnchorUnavailable { .. } => "the ASERT anchor is unreachable",
            Reject::TimestampTooOld { .. } => "timestamp at or below the median time past",
            Reject::TimestampTooFarInFuture { .. } => "timestamp too far in the future",
            Reject::ForkTooDeep { .. } => "the branch forks deeper than the reorg cap",
            Reject::InsufficientClaimedWork => "the branch claims no more work than our tip",
            Reject::PowInvalid { .. } => "proof of work is invalid",
            Reject::BudgetExhausted { .. } => "this source has spent its ingest budget",
            Reject::DuplicateFlood { .. } => "this source is replaying known headers",
            Reject::StagingFull { .. } => "this source's staging buffer is full",
            Reject::BatchTooLong { .. } => "the batch is longer than MAX_HEADERS_PER_MSG",
            Reject::TooManySources { .. } => "the per-source table is full",
            Reject::BodyNotAdmissible { .. } => "no PoW-verified header for this body",
            Reject::BodyAlreadyHeld { .. } => "this body is already held",
            Reject::BodyStructure { .. } => "the body does not parse",
            Reject::TxRootMismatch => "the body's merkle root is not the header's tx_root",
            Reject::Tx { .. } => "a transaction rule failed",
            Reject::BadTransferSignature { .. } => "a transfer signature failed",
            Reject::FeeBelowFloor { .. } => "a fee is below the consensus floor",
            Reject::BadNonce { .. } => "a transaction nonce is wrong",
            Reject::InsufficientBalance { .. } => "a sender cannot cover the outlay",
            Reject::ArithmeticOverflow => "arithmetic overflow",
            Reject::Rule(_) => "the authoritative predicate refused the branch",
            Reject::BranchInvalid { .. } => "a candidate block failed body validation",
            Reject::ResyncRequired { .. } => "the fork point is below the replay floor",
            Reject::Busy => "storage is busy",
            Reject::SinkRefused { .. } => "storage refused the write",
            Reject::Halted { .. } => "the manager is halted",
            Reject::BootInvariant { .. } => "a boot invariant failed",
            Reject::TxKnown => "already in the pool",
            Reject::TxStale { .. } => "nonce below the sender's next",
            Reject::NonceGapTooLarge { .. } => "nonce gap too large",
            Reject::TxTypeNotRelayable { .. } => "this transaction type is never relayed",
            Reject::BelowRelayFloor { .. } => "below the operator relay floor",
            Reject::ReplacementUnderpriced { .. } => "replacement underpriced",
            Reject::PoolFull => "the mempool is full",
            Reject::SenderCap { .. } => "this sender holds the per-sender cap",
            Reject::TxDecode => "the transaction does not decode",
            Reject::TxTooLarge { .. } => "the transaction is too large",
        }
    }

    // Permanent only for verdicts a header can never satisfy. Clock- or
    // tip-relative ones stay transient so they aren't cached.
    pub fn permanence(&self) -> Permanence {
        match self {
            Reject::BadHeaderLength { .. }
            | Reject::ExtRootNotZero
            | Reject::AuthorNoteLen { .. }
            | Reject::BadVersion { .. }
            | Reject::BadBits { .. }
            | Reject::CheckpointMismatch { .. }
            | Reject::HeightNotParentPlusOne { .. }
            | Reject::BitsNotAsert { .. }
            | Reject::TimestampTooOld { .. }
            | Reject::PowInvalid { .. } => Permanence::Permanent,
            _ => Permanence::Transient,
        }
    }
}

impl From<RuleError> for Reject {
    fn from(e: RuleError) -> Reject {
        Reject::Rule(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    ReorgTooDeepRefused { our_tip: u64, their_tip: u64, depth: u64, fork_height: u64 },
    ReorgOverlayExhausted { accounts: usize },
    ResyncRequired { fork_height: u64, replay_floor: u64 },
    AnchorContradiction { height: u64, hash: Hash32 },
    AnchorNotPersisted { height: u64, err: crate::traits::SinkError },
    BranchInvalidAt { height: u64, hash: Hash32 },
    DeepReplay { from: u64, to: u64, blocks: u64 },
    MempoolEvicted { count: usize, reason: EvictReason },
    BudgetExhausted { source: SourceId, class: BudgetClass },
    DuplicateFlood { source: SourceId, count: u32 },
    StorageFatal { detail: &'static str },
    ImmatureSpendDropped { addr: Address },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictReason {
    Expired,
    QueuedLowFee,
    ExecutableTail,
    Confirmed,
    ReorgInvalid,
    ReorgOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetClass {
    Interpreter,
    Duplicates,
    Staging,
    TxIngress,
    ChildQuota,
    HeaderClass,
}
