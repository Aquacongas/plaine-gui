use crate::constants::*;
use crate::peer::score::Offence;
use crate::sync::Action;
use crate::traits::{Hash32, Mono, PeerId};
use crate::wire::msg::{InvItem, InvKind, Msg};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Copy, Debug)]
struct InFlight {
    peer: PeerId,
    since: Mono,
}

#[derive(Debug, Default)]
struct IdSet {
    set: HashSet<Hash32>,
    order: VecDeque<Hash32>,
    cap: usize,
}

impl IdSet {
    fn with_cap(cap: usize) -> IdSet {
        IdSet {
            set: HashSet::new(),
            order: VecDeque::new(),
            cap,
        }
    }
    fn contains(&self, h: &Hash32) -> bool {
        self.set.contains(h)
    }

    fn insert(&mut self, h: Hash32) -> bool {
        if !self.set.insert(h) {
            return false;
        }
        self.order.push_back(h);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
    fn len(&self) -> usize {
        self.set.len()
    }
}

#[derive(Debug)]
pub struct TxRelay {
    seen: IdSet,
    known: HashMap<PeerId, IdSet>,
    inflight: HashMap<Hash32, InFlight>,
    pending: VecDeque<Hash32>,
    last_poll: Mono,
    pub ingested: u64,
    pub announced: u64,
    pub requested: u64,
    pub timed_out: u64,
    pub unsolicited: u64,
}

impl Default for TxRelay {
    fn default() -> TxRelay {
        TxRelay::new()
    }
}

impl TxRelay {
    pub fn new() -> TxRelay {
        TxRelay {
            seen: IdSet::with_cap(SEEN_TX_GLOBAL),
            known: HashMap::new(),
            inflight: HashMap::new(),
            pending: VecDeque::new(),
            last_poll: Mono::ZERO,
            ingested: 0,
            announced: 0,
            requested: 0,
            timed_out: 0,
            unsolicited: 0,
        }
    }

    pub fn seen_len(&self) -> usize {
        self.seen.len()
    }

    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_requested_from(&self, txid: &Hash32, peer: PeerId) -> bool {
        matches!(self.inflight.get(txid), Some(f) if f.peer == peer)
    }

    fn peer_inflight(&self, peer: PeerId) -> usize {
        self.inflight.values().filter(|f| f.peer == peer).count()
    }

    fn note_known(&mut self, peer: PeerId, txid: Hash32) {
        self.known
            .entry(peer)
            .or_insert_with(|| IdSet::with_cap(KNOWN_TX_PER_PEER))
            .insert(txid);
    }

    fn peer_knows(&self, peer: PeerId, txid: &Hash32) -> bool {
        matches!(self.known.get(&peer), Some(s) if s.contains(txid))
    }

    fn queue_announce(&mut self, txid: Hash32) {
        if self.pending.iter().any(|h| *h == txid) {
            return;
        }
        self.pending.push_back(txid);
        while self.pending.len() > TX_ANNOUNCE_QUEUE_MAX {
            self.pending.pop_front();
        }
    }

    pub fn on_peer_gone(&mut self, peer: PeerId) {
        self.known.remove(&peer);
        self.inflight.retain(|_, f| f.peer != peer);
    }

    pub fn on_announced(
        &mut self,
        peer: PeerId,
        txids: &[Hash32],
        now: Mono,
        out: &mut Vec<Action>,
    ) {
        let mut want: Vec<InvItem> = Vec::new();
        for id in txids.iter().take(INV_TXS_PER_MSG_MAX) {
            self.note_known(peer, *id);
            if self.seen.contains(id) || self.inflight.contains_key(id) {
                continue;
            }
            if self.inflight.len() >= TX_INFLIGHT_MAX
                || self.peer_inflight(peer) + want.len() >= TX_INFLIGHT_PER_PEER
            {
                break;
            }
            want.push(InvItem {
                kind: InvKind::Tx,
                hash: *id,
            });
        }
        if want.is_empty() {
            return;
        }
        for it in &want {
            self.inflight.insert(it.hash, InFlight { peer, since: now });
        }
        self.requested += want.len() as u64;
        out.push(Action::Send {
            peer,
            msg: Msg::GetData(want),
        });
    }

    pub fn on_tx(&mut self, peer: PeerId, txid: Hash32, now: Mono, out: &mut Vec<Action>) -> bool {
        let _ = now;
        self.note_known(peer, txid);
        match self.inflight.get(&txid) {
            Some(f) if f.peer == peer => {
                self.inflight.remove(&txid);
            }
            _ => {
                self.unsolicited += 1;
                out.push(Action::Score {
                    peer,
                    offence: Offence::UnsolicitedBody,
                });
                return false;
            }
        }
        if !self.seen.insert(txid) {
            return false;
        }
        true
    }

    pub fn on_accepted(&mut self, txid: Hash32) {
        self.ingested += 1;
        self.queue_announce(txid);
    }

    pub fn on_not_found(&mut self, peer: PeerId, txid: Hash32) {
        if matches!(self.inflight.get(&txid), Some(f) if f.peer == peer) {
            self.inflight.remove(&txid);
        }
    }

    pub fn on_tick<F: FnMut() -> Vec<Hash32>>(
        &mut self,
        now: Mono,
        ready: &[PeerId],
        mut mempool: F,
        out: &mut Vec<Action>,
    ) {
        let stale: Vec<(Hash32, PeerId)> = self
            .inflight
            .iter()
            .filter(|(_, f)| now.expired(f.since, TX_REQUEST_TIMEOUT_MS))
            .map(|(h, f)| (*h, f.peer))
            .collect();
        for (h, peer) in stale {
            self.inflight.remove(&h);
            self.timed_out += 1;
            out.push(Action::Score {
                peer,
                offence: Offence::DeadlineMiss,
            });
        }

        if now.expired(self.last_poll, TX_POLL_MS) {
            self.last_poll = now;
            for id in mempool() {
                if self.seen.insert(id) {
                    self.queue_announce(id);
                }
            }
        }

        if self.pending.is_empty() || ready.is_empty() {
            return;
        }
        let batch: Vec<Hash32> = self.pending.iter().take(INV_TX_PER_MSG).copied().collect();
        let mut delivered_to_someone = false;
        for peer in ready {
            let items: Vec<InvItem> = batch
                .iter()
                .filter(|h| !self.peer_knows(*peer, h))
                .map(|h| InvItem {
                    kind: InvKind::Tx,
                    hash: *h,
                })
                .collect();
            if items.is_empty() {
                continue;
            }
            for it in &items {
                self.note_known(*peer, it.hash);
            }
            delivered_to_someone = true;
            out.push(Action::Send {
                peer: *peer,
                msg: Msg::Inv(items),
            });
        }
        if delivered_to_someone {
            self.announced += batch.len() as u64;
        }

        for _ in 0..batch.len() {
            self.pending.pop_front();
        }
    }
}
