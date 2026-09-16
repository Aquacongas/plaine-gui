use crate::constants::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdClass {
    Peer,
    InboundHandshake,
    TransientDial,
    Listener,
}

impl FdClass {
    pub const fn cap(self) -> u64 {
        match self {
            FdClass::Peer => FD_PEERS,
            FdClass::InboundHandshake => FD_INBOUND_HANDSHAKE,
            FdClass::TransientDial => FD_TRANSIENT_DIALS,
            FdClass::Listener => FD_LISTENERS,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            FdClass::Peer => "fd:peer",
            FdClass::InboundHandshake => "fd:inbound-handshake",
            FdClass::TransientDial => "fd:transient-dial",
            FdClass::Listener => "fd:listener",
        }
    }
}

#[derive(Debug, Default)]
pub struct FdBudget {
    peer: AtomicU64,
    inbound_handshake: AtomicU64,
    transient_dial: AtomicU64,
    listener: AtomicU64,
}

impl FdBudget {
    pub fn new() -> Arc<FdBudget> {
        Arc::new(FdBudget::default())
    }

    fn cell(&self, c: FdClass) -> &AtomicU64 {
        match c {
            FdClass::Peer => &self.peer,
            FdClass::InboundHandshake => &self.inbound_handshake,
            FdClass::TransientDial => &self.transient_dial,
            FdClass::Listener => &self.listener,
        }
    }

    pub fn acquire(self: &Arc<Self>, class: FdClass) -> Option<FdLease> {
        let cap = class.cap();
        let cell = self.cell(class);
        cell.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            if n < cap {
                Some(n + 1)
            } else {
                None
            }
        })
        .ok()?;
        Some(FdLease {
            budget: Arc::clone(self),
            class,
        })
    }

    pub fn open(&self, class: FdClass) -> u64 {
        self.cell(class).load(Ordering::Acquire)
    }

    pub fn total_open(&self) -> u64 {
        self.peer.load(Ordering::Acquire)
            + self.inbound_handshake.load(Ordering::Acquire)
            + self.transient_dial.load(Ordering::Acquire)
            + self.listener.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct FdLease {
    budget: Arc<FdBudget>,
    class: FdClass,
}

impl FdLease {
    pub fn class(&self) -> FdClass {
        self.class
    }

    pub fn promote(&mut self, to: FdClass) -> bool {
        if to == self.class {
            return true;
        }
        let cap = to.cap();
        let ok = self
            .budget
            .cell(to)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < cap {
                    Some(n + 1)
                } else {
                    None
                }
            })
            .is_ok();
        if ok {
            self.budget.cell(self.class).fetch_sub(1, Ordering::AcqRel);
            self.class = to;
        }
        ok
    }
}

impl Drop for FdLease {
    fn drop(&mut self) {
        self.budget.cell(self.class).fetch_sub(1, Ordering::AcqRel);
    }
}
