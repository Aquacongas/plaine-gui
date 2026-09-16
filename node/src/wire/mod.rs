pub mod clock;
pub mod jobs;
pub mod net;
pub mod pow;
pub mod rpcview;
pub mod store;
pub mod tip;

// Zero-sized, !Send token that pins consensus work to one thread. The raw-pointer
// PhantomData is what removes Send: holding one is a compile-time promise the
// caller is on the consensus thread, not merely a convention.
pub struct OnConsensusThread(core::marker::PhantomData<*const ()>);

impl OnConsensusThread {
    pub(crate) fn claim() -> OnConsensusThread {
        OnConsensusThread(core::marker::PhantomData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SendProbe<T>(core::marker::PhantomData<T>);
    trait ProbeFallback {
        const IS_SEND: bool = false;
    }
    impl<T> ProbeFallback for SendProbe<T> {}
    impl<T: Send> SendProbe<T> {
        const IS_SEND: bool = true;
    }

    struct SyncProbe<T>(core::marker::PhantomData<T>);
    trait SyncFallback {
        const IS_SYNC: bool = false;
    }
    impl<T> SyncFallback for SyncProbe<T> {}
    impl<T: Sync> SyncProbe<T> {
        const IS_SYNC: bool = true;
    }

    #[test]
    fn u64_reports_send_and_sync() {
        assert!(SendProbe::<u64>::IS_SEND, "u64 is Send; the probe is broken");
        assert!(SyncProbe::<u64>::IS_SYNC, "u64 is Sync; the probe is broken");
        assert!(!SendProbe::<*const ()>::IS_SEND, "a raw pointer is not Send; the probe is broken");
    }

    #[test]
    fn consensus_token_is_not_send() {
        assert!(
            !SendProbe::<OnConsensusThread>::IS_SEND,
            "OnConsensusThread became Send: consensus work could move to a reactor \
             thread. Restore the PhantomData<*const ()> field."
        );
    }

    #[test]
    fn consensus_token_is_not_sync() {
        assert!(
            !SyncProbe::<OnConsensusThread>::IS_SYNC,
            "OnConsensusThread became Sync, so a reference to it can be shared across threads"
        );
    }

    #[test]
    fn token_is_zero_sized() {
        assert_eq!(core::mem::size_of::<OnConsensusThread>(), 0);
    }
}
