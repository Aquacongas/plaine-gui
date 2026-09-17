use crate::error::Condition;
use crate::types::{
    Account, Address, CommitBlock, DeepReorgCommit, Hash32, HeaderRec, Receipt, ReorgCommit,
    SideHeaderRec, SideHeaderRec as _SideHeaderRec, SignedCheckpoint, TipRef, UndoRec,
};
use plaine_consensus::constants::HEADER_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkError {
    Full,
    Invalid(&'static str),
    Fatal(&'static str),
}

pub trait Store: Send + Sync {
    fn tip(&self) -> TipRef;

    fn header_at(&self, height: u64) -> Option<HeaderRec>;

    fn header_by_hash(&self, h: &Hash32) -> Option<HeaderRec>;

    fn hash_at(&self, height: u64) -> Option<Hash32>;

    fn body_at(&self, height: u64) -> Option<Vec<u8>>;

    fn body_by_hash(&self, h: &Hash32) -> Option<Vec<u8>>;

    fn account(&self, addr: &Address) -> Account;

    fn accounts(&self, addrs: &[Address]) -> Vec<Account> {
        addrs.iter().map(|a| self.account(a)).collect()
    }

    fn undo_at(&self, height: u64) -> Option<Vec<UndoRec>>;

    fn undo_floor(&self) -> u64;

    fn replay_floor(&self) -> u64;

    fn checkpoint_at_or_below(&self, height: u64) -> Option<u64>;

    fn state_snapshot(&self, height: u64) -> Option<Vec<(Address, Account)>>;

    fn issued(&self) -> u128;

    fn is_invalid(&self, h: &Hash32) -> bool;

    fn headers_range(&self, from: u64, max: usize) -> Vec<[u8; HEADER_BYTES]>;

    fn side_headers_from(&self, from: u64, max: usize) -> Vec<HeaderRec> {
        let _ = (from, max);
        Vec::new()
    }
}

pub trait Sink: Send + Sync {
    fn capacity(&self) -> usize {
        usize::MAX
    }

    fn commit_block(&self, b: &CommitBlock) -> Result<Receipt, SinkError>;

    fn commit_reorg(&self, p: &ReorgCommit) -> Result<Receipt, SinkError>;

    fn commit_deep_reorg(&self, p: &DeepReorgCommit) -> Result<Receipt, SinkError>;

    fn store_side_header(&self, h: &SideHeaderRec) -> Result<(), SinkError>;

    fn mark_invalid(&self, h: &Hash32) -> Result<(), SinkError>;

    fn put_anchor(&self, cp: &SignedCheckpoint) -> Result<(), SinkError>;
}

pub trait PowVerifier: Send + Sync {
    fn verify(&self, hdr: &[u8; HEADER_BYTES]) -> bool;

    fn cost_micros(&self) -> u64;
}

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;

    fn mono_ms(&self) -> u64;
}

pub type Observer = Box<dyn Fn(Condition) + Send + Sync>;

#[allow(dead_code)]
fn _assert_owned_return_shapes(_: &_SideHeaderRec) {}
