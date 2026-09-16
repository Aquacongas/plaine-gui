pub mod g0_dedup;
pub mod g1_structure;
pub mod g2_context;
pub mod g3_admission;
pub mod g4_budget;

pub use g0_dedup::{AuditPass, RejectCache};
pub use g1_structure::check_structure;
pub use g2_context::{check_context, BitsRule, ContextParams};
pub use g3_admission::admit;
pub use g4_budget::{Budgets, TokenBucket};

use crate::peer::score::Offence;
use crate::traits::Hash32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    Duplicate,
    KnownRejected,
    BadShape(&'static str),
    NotContiguous,
    UnsolicitedAnswer,
    UnknownParent(Hash32),
    BadBits { expected: u32, got: u32 },
    TimePast,
    TimeFuture { by_secs: i64 },
    ReorgTooDeep { depth: u64 },
    LessWork,
    TieBreakLost,
    Quarantined,
    BudgetExhausted,
    BadPow,
}

impl Rejection {
    // a rejection only scores the peer when the peer could have known better.
    // dups, unknown-parent and budget/quarantine are our own bookkeeping, so
    // they map to None and cost the sender nothing.
    pub fn offence(&self) -> Option<Offence> {
        match self {
            Rejection::Duplicate
            | Rejection::KnownRejected
            | Rejection::UnknownParent(_)
            | Rejection::BudgetExhausted
            | Rejection::Quarantined => None,
            Rejection::LessWork => Some(Offence::LessWork),
            Rejection::TieBreakLost => Some(Offence::TieBreakLost),
            Rejection::ReorgTooDeep { .. } => Some(Offence::ReorgTooDeep),
            Rejection::TimeFuture { .. } => Some(Offence::NotYetValid),
            Rejection::BadShape(_) | Rejection::NotContiguous => Some(Offence::Malformed),
            Rejection::UnsolicitedAnswer => Some(Offence::DisconnectedBatches),
            Rejection::BadBits { .. } => Some(Offence::BadBits),
            Rejection::TimePast => Some(Offence::BadTimePast),
            Rejection::BadPow => Some(Offence::BadPow),
        }
    }

    // Permanent rejections cache forever - the header can never become valid.
    // Transient ones (unknown parent, budget) must not stick.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Rejection::BadShape(_)
                | Rejection::NotContiguous
                | Rejection::BadBits { .. }
                | Rejection::TimePast
                | Rejection::BadPow
        )
    }
}
