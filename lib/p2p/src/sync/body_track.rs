use crate::constants::*;
use crate::traits::{Condition, Hash32, Mono, PeerId};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BState {
    Idle,
    Windowing,
    Applying,
    Starved,
}

#[derive(Clone, Debug)]
pub struct InFlight {
    pub hash: Hash32,
    pub height: u64,
    pub peer: PeerId,
    pub since: Mono,
    pub tried: Vec<PeerId>,
    pub attempts: u32,
    pub escalated: bool,
    pub refused: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Supplier {
    pub id: PeerId,
    pub horizon: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyAction {
    Request { peer: PeerId, hashes: Vec<Hash32> },
    DeadlineMiss { peer: PeerId },
    SlotLost { peer: PeerId },
    WidenSuppliers,
    Say(Condition),
}

#[derive(Debug)]
pub struct BodyTrack {
    state: BState,
    applied: u64,
    inflight: Vec<InFlight>,
    ready: BTreeMap<u64, (Hash32, Vec<u8>)>,
    ready_bytes: u64,
    ewma_bytes: u64,
    hol_since: Option<Mono>,
    starved_since: Option<Mono>,
    unappliable_since: Option<Mono>,
    last_unappliable: Option<Mono>,
    last_report: Option<Mono>,
    starved: Vec<Hash32>,
    tail: VecDeque<(Hash32, Mono)>,
    pub requests_issued: u64,
}

impl BodyTrack {
    pub fn new(applied: u64) -> BodyTrack {
        BodyTrack {
            state: BState::Idle,
            applied,
            inflight: Vec::new(),
            ready: BTreeMap::new(),
            ready_bytes: 0,
            ewma_bytes: 20 * 1024,
            hol_since: None,
            starved_since: None,
            unappliable_since: None,
            last_unappliable: None,
            last_report: None,
            starved: Vec::new(),
            tail: VecDeque::new(),
            requests_issued: 0,
        }
    }

    pub fn state(&self) -> BState {
        self.state
    }

    pub fn applied(&self) -> u64 {
        self.applied
    }

    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    pub fn inflight_bytes(&self) -> u64 {
        self.inflight.len() as u64 * self.ewma_bytes
    }

    pub fn per_peer_inflight(&self) -> u64 {
        (INBOX_BYTES / self.ewma_bytes.max(1)).clamp(1, BODY_INFLIGHT_PER_PEER_MAX)
    }

    pub fn window_admits(&self) -> bool {
        self.inflight.len() < BODY_WINDOW_HASHES
            && self.inflight_bytes() + self.ewma_bytes <= BODY_WINDOW_BYTES
    }

    pub fn is_inflight(&self, hash: &Hash32) -> bool {
        self.inflight.iter().any(|f| f.hash == *hash)
    }

    pub fn schedule(
        &mut self,
        wanted: &[(u64, Hash32)],
        suppliers: &[Supplier],
        now: Mono,
    ) -> Vec<BodyAction> {
        let mut out = Vec::new();
        if suppliers.is_empty() || wanted.is_empty() {
            return out;
        }
        let per_peer = self.per_peer_inflight();
        let mut assigned: BTreeMap<PeerId, Vec<Hash32>> = BTreeMap::new();
        let mut cursor = 0usize;

        if self.ready_full() {
            return out;
        }

        let hol_ceiling = if self.hol_since.is_some() {
            self.applied + HOL_WINDOW_FREEZE
        } else {
            u64::MAX
        };
        let ceiling = hol_ceiling.min(self.applied + READY_AHEAD_BLOCKS as u64);

        for (height, hash) in wanted {
            if *height > ceiling {
                break;
            }
            if !self.window_admits() {
                break;
            }
            if self.is_inflight(hash) || self.ready.contains_key(height) {
                continue;
            }

            let mut placed = false;
            for pass in 0..2u8 {
                for _ in 0..suppliers.len() {
                    let s = suppliers[cursor % suppliers.len()];
                    cursor += 1;
                    if pass == 0 && s.horizon < *height {
                        continue;
                    }

                    let n = self.inflight.iter().filter(|f| f.peer == s.id).count() as u64;
                    if n < per_peer {
                        assigned.entry(s.id).or_default().push(*hash);
                        self.inflight.push(InFlight {
                            hash: *hash,
                            height: *height,
                            peer: s.id,
                            since: now,
                            tried: vec![s.id],
                            attempts: 0,
                            escalated: false,
                            refused: false,
                        });
                        placed = true;
                        break;
                    }
                }
                if placed {
                    break;
                }
            }
            if !placed {
                break;
            }
        }
        for (peer, hashes) in assigned {
            self.requests_issued += hashes.len() as u64;
            out.push(BodyAction::Request { peer, hashes });
        }
        if !self.inflight.is_empty() {
            self.state = BState::Windowing;
        }
        out
    }

    pub fn on_body(&mut self, hash: Hash32, bytes: Vec<u8>, height: u64, now: Mono) -> bool {
        let known = match self.inflight.iter().position(|f| f.hash == hash) {
            Some(i) => {
                self.inflight.remove(i);
                true
            }

            None => self.take_from_tail(&hash, now),
        };
        if height <= self.applied || height > self.applied + READY_AHEAD_BLOCKS as u64 {
            return known;
        }

        let n = bytes.len() as u64;
        self.ewma_bytes = (self.ewma_bytes * 7 + n) / 8;
        if !self.ready.contains_key(&height) {
            self.ready_bytes += n;
            self.ready.insert(height, (hash, bytes));
        }
        known
    }

    pub fn drain_applicable<F: FnMut(u64, Hash32, Vec<u8>) -> bool>(
        &mut self,
        mut apply: F,
        now: Mono,
    ) {
        loop {
            let next = self.applied + 1;
            let Some((hash, bytes)) = self.ready.remove(&next) else {
                break;
            };
            let n = bytes.len() as u64;
            if !apply(next, hash, bytes.clone()) {
                self.ready.insert(next, (hash, bytes));
                break;
            }
            self.ready_bytes = self.ready_bytes.saturating_sub(n);
            self.applied = next;
            self.hol_since = None;
        }

        let stale: Vec<u64> = self
            .ready
            .range(..=self.applied)
            .map(|(h, _)| *h)
            .collect();
        for h in stale {
            if let Some((_, b)) = self.ready.remove(&h) {
                self.ready_bytes = self.ready_bytes.saturating_sub(b.len() as u64);
            }
        }

        if !self.ready.is_empty() && !self.ready.contains_key(&(self.applied + 1)) {
            if self.hol_since.is_none() {
                self.hol_since = Some(now);
            }
        } else if self.ready.contains_key(&(self.applied + 1)) {
            self.hol_since = None;
        }
        if self.inflight.is_empty() && self.ready.is_empty() {
            self.state = BState::Idle;
        } else if !self.ready.is_empty() {
            self.state = BState::Applying;
        }
    }

    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    pub fn note_chain_has(&mut self, height: u64) -> bool {
        if height <= self.applied {
            return false;
        }
        self.applied = height;
        true
    }

    pub fn ready_full(&self) -> bool {
        self.ready.len() >= READY_AHEAD_BLOCKS || self.ready_bytes >= READY_AHEAD_BYTES
    }

    pub fn tick(&mut self, suppliers: &[Supplier], now: Mono) -> Vec<BodyAction> {
        let mut out = Vec::new();

        let mut retry: Vec<(usize, Hash32)> = Vec::new();
        for (i, f) in self.inflight.iter().enumerate() {
            if now.expired(f.since, BODY_TIMEOUT_MS) {
                retry.push((i, f.hash));
            }
        }
        for (i, _) in retry.iter().rev() {
            let f = &mut self.inflight[*i];
            if f.refused {
                f.refused = false;
            } else {
                out.push(BodyAction::DeadlineMiss { peer: f.peer });
            }
            f.attempts = f.attempts.saturating_add(1);

            let next = suppliers
                .iter()
                .find(|s| !f.tried.contains(&s.id) && s.horizon >= f.height)
                .or_else(|| suppliers.iter().find(|s| !f.tried.contains(&s.id)))
                .map(|s| s.id);
            match next {
                Some(p) => {
                    f.peer = p;
                    f.since = now;
                    f.tried.push(p);
                    self.requests_issued += 1;
                    out.push(BodyAction::Request {
                        peer: p,
                        hashes: vec![f.hash],
                    });
                }
                None if f.attempts >= BODY_ATTEMPTS => {
                    let h = f.hash;
                    self.inflight.remove(*i);

                    self.remember_requested(h, now);
                    if !self.starved.contains(&h) {
                        self.starved.push(h);
                    }
                    if self.starved_since.is_none() {
                        self.starved_since = Some(now);
                    }
                    self.state = BState::Starved;
                }
                None => {
                    f.since = now;
                    let p = f.peer;
                    self.requests_issued += 1;
                    out.push(BodyAction::Request {
                        peer: p,
                        hashes: vec![f.hash],
                    });
                }
            }
        }

        if let Some(since) = self.hol_since {
            if now.expired(since, HOL_TIMEOUT_MS) {
                let want = self.applied + 1;
                if let Some(f) = self.inflight.iter_mut().find(|f| f.height == want) {
                    if !f.escalated {
                        f.escalated = true;

                        let mut peers: Vec<PeerId> = suppliers
                            .iter()
                            .filter(|s| s.horizon >= f.height)
                            .take(HOL_PARALLEL)
                            .map(|s| s.id)
                            .collect();
                        if peers.is_empty() {
                            peers = suppliers
                                .iter()
                                .take(HOL_PARALLEL)
                                .map(|s| s.id)
                                .collect();
                        }
                        for p in peers {
                            self.requests_issued += 1;
                            out.push(BodyAction::Request {
                                peer: p,
                                hashes: vec![f.hash],
                            });
                        }
                        f.since = now;
                    }
                }
            }
        }

        let head = self.applied + 1;
        if !self.ready.is_empty()
            && !self.ready.contains_key(&head)
            && !self.inflight.iter().any(|f| f.height == head)
        {
            if self.unappliable_since.is_none() {
                self.unappliable_since = Some(now);
            }
        } else {
            self.unappliable_since = None;
            self.last_unappliable = None;
        }
        if let Some(since) = self.unappliable_since {
            if now.expired(since, HOL_TIMEOUT_MS) {
                let due = match self.last_unappliable {
                    Some(t) => now.expired(t, BODY_UNAVAILABLE_RETRY_MS),
                    None => true,
                };
                if due {
                    self.last_unappliable = Some(now);
                    out.push(BodyAction::Say(Condition::BodiesUnappliable {
                        applied: self.applied,
                        ready: self.ready.len(),
                        missing: head,
                    }));

                    out.push(BodyAction::WidenSuppliers);
                }
            }
        }

        if let Some(since) = self.starved_since {
            let el = now.since(since);
            if (BODY_STARVE_WIDEN_MS..BODY_STARVE_REPORT_MS).contains(&el) {
                out.push(BodyAction::WidenSuppliers);
            }
            if el >= BODY_STARVE_REPORT_MS {
                let due = match self.last_report {
                    Some(t) => now.expired(t, BODY_UNAVAILABLE_RETRY_MS),
                    None => true,
                };
                if due {
                    self.last_report = Some(now);

                    out.push(BodyAction::Say(Condition::BodyUnavailable {
                        height: self.applied + 1,
                    }));
                }
            }
        }
        out
    }

    pub fn on_notfound(&mut self, hash: &Hash32, from: PeerId, now: Mono) -> bool {
        match self
            .inflight
            .iter_mut()
            .find(|f| f.hash == *hash && f.peer == from)
        {
            Some(f) => {
                f.refused = true;

                f.since = Mono(now.0.saturating_sub(BODY_TIMEOUT_MS));
                true
            }
            None => false,
        }
    }

    pub fn release_peer(&mut self, peer: PeerId, now: Mono) {
        let released: Vec<Hash32> = self
            .inflight
            .iter()
            .filter(|f| f.peer == peer)
            .map(|f| f.hash)
            .collect();
        self.inflight.retain(|f| f.peer != peer);
        for h in released {
            self.remember_requested(h, now);
        }
    }

    fn remember_requested(&mut self, hash: Hash32, now: Mono) {
        if self.tail.iter().any(|(h, _)| *h == hash) {
            return;
        }
        self.tail.push_back((hash, now));
        while self.tail.len() > BODY_WINDOW_HASHES * 2 {
            self.tail.pop_front();
        }
    }

    fn take_from_tail(&mut self, hash: &Hash32, now: Mono) -> bool {
        match self
            .tail
            .iter()
            .position(|(h, t)| h == hash && !now.expired(*t, BODY_INFLIGHT_TAIL_MS))
        {
            Some(i) => {
                self.tail.remove(i);
                true
            }
            None => false,
        }
    }

    pub fn starved_hashes(&self) -> &[Hash32] {
        &self.starved
    }

    pub fn clear_starvation(&mut self, hash: &Hash32) {
        self.starved.retain(|h| h != hash);
        if self.starved.is_empty() {
            self.starved_since = None;
            self.last_report = None;
            if self.state == BState::Starved {
                self.state = BState::Windowing;
            }
        }
    }
}
