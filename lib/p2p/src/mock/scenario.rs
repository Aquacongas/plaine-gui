use crate::config::P2pConfig;
use crate::constants::*;
use crate::mock::chain::{build_chain, MockBits, MockChain, MockPow};
use crate::sync::{Action, Event, SyncEngine};
use crate::traits::*;
use crate::wire::msg::{InvKind, Msg};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behaviour {
    Honest,

    Slow { every_ms: u64 },
    Silent,

    Trickle { n: usize },
    Lying,

    Flapping { up_ms: u64, down_ms: u64 },
    HeadersOnly,

    WithholdsBelow { height: u64 },

    RepeatsFirstBatch { n: usize },

    AnswersOnce { n: u64 },
}

#[derive(Clone, Debug)]
pub struct MockPeer {
    pub id: PeerId,
    pub ip: [u8; 16],
    pub behaviour: Behaviour,
    pub chain: Vec<HeaderRec>,
    pub claimed_height: u64,
    pub connected: bool,
    pub last_answer: Mono,
    pub flap_at: Mono,
    pub getdata_seen: Vec<Hash32>,
    pub getheaders_seen: u64,
    pub headers_served: u64,
    pub inv_seen: u64,
    pub notfound_sent: u64,
}

impl MockPeer {
    fn ip_for(n: u64) -> [u8; 16] {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12] = 10;

        ip[13] = n as u8;
        ip[14] = (n >> 8) as u8;
        ip[15] = 1;
        ip
    }
}

pub struct Sim {
    pub engine: SyncEngine<MockChain, MockChain, MockPow, MockBits>,
    pub chain: Arc<MockChain>,
    pub pow: Arc<MockPow>,
    peers: Vec<MockPeer>,
    now: Mono,
    now_unix: u64,
    base_time: u64,
    pin_tip: bool,
    next_id: u64,
    pub actions: Vec<Action>,
    pub getdata_count: HashMap<Hash32, u64>,
}

impl Sim {
    pub fn new(local_blocks: u64, base_time: u64) -> Sim {
        Sim::with_pow_cost(local_blocks, base_time, 0)
    }

    pub fn with_pow_cost(local_blocks: u64, base_time: u64, cost_ms: u64) -> Sim {
        let chain = Arc::new(MockChain::linear(local_blocks, base_time, 1));
        let pow = Arc::new(MockPow::with_cost(cost_ms));
        let bits = Arc::new(MockBits);
        let cfg = P2pConfig::isolated();
        let now = Mono(0);
        let tip = chain.tip();
        let engine = SyncEngine::new(
            chain.clone(),
            chain.clone(),
            pow.clone(),
            bits,
            cfg,
            0xC0FFEE,
            now,
        );
        Sim {
            engine,
            chain,
            pow,
            peers: Vec::new(),
            now,
            now_unix: tip.time,
            base_time,
            pin_tip: false,
            next_id: 1,
            actions: Vec::new(),
            getdata_count: HashMap::new(),
        }
    }

    pub fn now(&self) -> Mono {
        self.now
    }

    pub fn set_now_unix(&mut self, t: u64) {
        self.now_unix = t;
        self.engine.set_now_unix(t);
    }

    pub fn extension(&mut self, n: u64) -> Vec<HeaderRec> {
        let tip = self.chain.tip();
        let out = build_chain(tip.height + 1, n, tip.hash, self.base_time, 1);
        self.cover(&out);
        out
    }

    pub fn extension_with_a_repeated_second(&mut self, n: u64, repeat_at: u64) -> Vec<HeaderRec> {
        let tip = self.chain.tip();
        let out = crate::mock::chain::build_chain_repeating_a_second(
            tip.height + 1,
            n,
            tip.hash,
            self.base_time,
            1,
            repeat_at,
        );
        self.cover(&out);
        out
    }

    pub fn fork(&mut self, depth: u64, n: u64, salt: u64) -> Vec<HeaderRec> {
        let tip = self.chain.tip();
        let fork_h = tip.height.saturating_sub(depth);
        let parent = self
            .chain
            .header_at(fork_h)
            .map(|h| h.hash)
            .unwrap_or([0u8; 32]);
        let out = build_chain(fork_h + 1, n, parent, self.base_time, salt);
        self.cover(&out);
        out
    }

    fn cover(&mut self, hs: &[HeaderRec]) {
        if let Some(last) = hs.last() {
            if last.time > self.now_unix {
                self.set_now_unix(last.time);
            }
        }
    }

    pub fn add_peer(&mut self, behaviour: Behaviour, chain: Vec<HeaderRec>) -> PeerId {
        let id = PeerId(self.next_id);
        self.next_id += 1;
        let claimed = chain.last().map(|h| h.height).unwrap_or(0);
        self.peers.push(MockPeer {
            id,
            ip: MockPeer::ip_for(id.0),
            behaviour,
            chain,
            claimed_height: claimed,
            connected: false,
            last_answer: self.now,
            flap_at: self.now,
            getdata_seen: Vec::new(),
            getheaders_seen: 0,
            headers_served: 0,
            inv_seen: 0,
            notfound_sent: 0,
        });
        id
    }

    pub fn grow_peer(&mut self, id: PeerId, chain: Vec<HeaderRec>) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
            p.chain = chain;
        }
    }

    pub fn announce(&mut self, id: PeerId, blocks: Vec<Hash32>) {
        self.engine_event(Event::Announced { peer: id, blocks });
    }

    pub fn announce_tip(&mut self, id: PeerId) {
        let h = self
            .peers
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.chain.last())
            .map(|h| h.hash);
        if let Some(h) = h {
            self.announce(id, vec![h]);
        }
    }

    pub fn inv_seen(&self, id: PeerId) -> u64 {
        self.peers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.inv_seen)
            .unwrap_or(0)
    }

    pub fn getdata_seen(&self, id: PeerId) -> u64 {
        self.peers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.getdata_seen.len() as u64)
            .unwrap_or(0)
    }

    pub fn notfound_sent(&self, id: PeerId) -> u64 {
        self.peers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.notfound_sent)
            .unwrap_or(0)
    }

    pub fn getheaders_total(&self) -> u64 {
        self.peers.iter().map(|p| p.getheaders_seen).sum()
    }

    pub fn add_liar(&mut self, forged: Vec<HeaderRec>, claim_height: u64) -> PeerId {
        self.pow.poison_all(&forged);
        let id = self.add_peer(Behaviour::Lying, forged);
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
            p.claimed_height = claim_height;
        }
        id
    }

    pub fn connect(&mut self, id: PeerId) {
        let (ip, height, tip) = {
            let p = self
                .peers
                .iter_mut()
                .find(|p| p.id == id)
                .expect("unknown peer");
            p.connected = true;
            (
                p.ip,
                p.claimed_height,
                p.chain.last().map(|h| h.hash).unwrap_or([0u8; 32]),
            )
        };
        let mut work = [0u8; 32];
        work[..8].copy_from_slice(&height.to_le_bytes());
        let acts = self.engine.on_event(
            Event::PeerReady {
                peer: id,
                ip,
                outbound: true,
                height,
                work,
                tip,
                services: SERVICE_FULL_RELAY | SERVICE_ARCHIVE,
            },
            self.now,
        );
        self.actions.extend(acts);
    }

    pub fn set_behaviour(&mut self, id: PeerId, b: Behaviour) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
            p.behaviour = b;
        }
    }

    pub fn kill(&mut self, id: PeerId) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
            p.connected = false;
        }
        let acts = self.engine.on_event(Event::PeerGone { peer: id }, self.now);
        self.actions.extend(acts);
    }

    pub fn connected(&self, id: PeerId) -> bool {
        self.peers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.connected)
            .unwrap_or(false)
    }

    pub fn getheaders_seen(&self, id: PeerId) -> u64 {
        self.peers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.getheaders_seen)
            .unwrap_or(0)
    }

    pub fn step(&mut self, ms: u64) {
        self.now = self.now.plus_ms(ms);
        self.now_unix += ms / 1000;
        self.engine.set_now_unix(self.now_unix);
        if self.pin_tip {
            self.chain.set_tip_time(Some(self.now_unix));
        }

        let flaps: Vec<(PeerId, bool)> = self
            .peers
            .iter_mut()
            .filter_map(|p| match p.behaviour {
                Behaviour::Flapping { up_ms, down_ms } => {
                    let due = if p.connected { up_ms } else { down_ms };
                    if self.now.since(p.flap_at) >= due {
                        p.flap_at = self.now;
                        Some((p.id, !p.connected))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();
        for (id, up) in flaps {
            if up {
                self.connect(id);
            } else {
                self.kill(id);
            }
        }

        let acts = self.engine.on_tick(self.now);
        self.dispatch(acts);
    }

    pub fn run(&mut self, total_ms: u64, step_ms: u64) {
        let mut t = 0;
        while t < total_ms {
            self.step(step_ms);
            t += step_ms;
        }
    }

    fn dispatch(&mut self, acts: Vec<Action>) {
        self.actions.extend(acts.clone());
        let mut events: Vec<Event> = Vec::new();
        for a in acts {
            match a {
                Action::Send { peer, msg } => {
                    if let Msg::GetData(items) = &msg {
                        for it in items {
                            if it.kind == InvKind::Block {
                                *self.getdata_count.entry(it.hash).or_insert(0) += 1;
                            }
                        }
                    }
                    if let Some(ev) = self.answer(peer, &msg) {
                        events.extend(ev);
                    }
                }
                Action::Disconnect { peer, .. } => {
                    if let Some(p) = self.peers.iter_mut().find(|p| p.id == peer) {
                        p.connected = false;
                    }
                }
                _ => {}
            }
        }
        for ev in events {
            let more = self.engine.on_event(ev, self.now);
            self.actions.extend(more.clone());

            for a in more {
                if let Action::Disconnect { peer, .. } = a {
                    if let Some(p) = self.peers.iter_mut().find(|p| p.id == peer) {
                        p.connected = false;
                    }
                }
            }
        }
    }

    fn answer(&mut self, id: PeerId, msg: &Msg) -> Option<Vec<Event>> {
        let now = self.now;
        let p = self.peers.iter_mut().find(|p| p.id == id)?;
        if !p.connected {
            return None;
        }
        match p.behaviour {
            Behaviour::Silent => {
                if let Msg::GetHeaders { .. } = msg {
                    p.getheaders_seen += 1;
                }
                return None;
            }
            Behaviour::Slow { every_ms } => {
                if now.since(p.last_answer) < every_ms {
                    return None;
                }
                p.last_answer = now;
            }
            _ => {}
        }

        match msg {
            Msg::GetHeaders { locator, .. } => {
                p.getheaders_seen += 1;
                let start = match p.behaviour {
                    Behaviour::RepeatsFirstBatch { .. } => 0,
                    _ => locator
                        .iter()
                        .filter_map(|h| p.chain.iter().position(|x| x.hash == *h))
                        .max()
                        .map(|i| i + 1)
                        .unwrap_or(0),
                };
                let take = match p.behaviour {
                    Behaviour::Trickle { n } => n,
                    Behaviour::RepeatsFirstBatch { n } => n,
                    Behaviour::AnswersOnce { n } => {
                        (n.saturating_sub(p.headers_served) as usize).min(MAX_HEADERS_PER_MSG)
                    }
                    _ => MAX_HEADERS_PER_MSG,
                };
                if take == 0 {
                    return None;
                }
                let raw: Vec<[u8; HEADER_BYTES]> = p
                    .chain
                    .iter()
                    .skip(start)
                    .take(take)
                    .map(|h| h.raw)
                    .collect();
                if raw.is_empty() {
                    return None;
                }
                p.headers_served += raw.len() as u64;
                Some(vec![Event::Headers { peer: id, raw }])
            }
            Msg::Inv(_) => {
                p.inv_seen += 1;
                None
            }
            Msg::GetData(items) => {
                if let Behaviour::WithholdsBelow { height } = p.behaviour {
                    let mut out = Vec::new();
                    for it in items {
                        if it.kind != InvKind::Block {
                            continue;
                        }
                        p.getdata_seen.push(it.hash);
                        match p.chain.iter().find(|h| h.hash == it.hash) {
                            Some(h) if h.height > height => out.push(Event::Body {
                                peer: id,
                                hash: it.hash,
                                height: h.height,
                                bytes: vec![7u8; 256],
                            }),
                            _ => {
                                p.notfound_sent += 1;
                                out.push(Event::NotFound {
                                    peer: id,
                                    hash: it.hash,
                                });
                            }
                        }
                    }
                    return Some(out);
                }
                if p.behaviour == Behaviour::HeadersOnly {
                    p.notfound_sent += items.len() as u64;
                    return Some(
                        items
                            .iter()
                            .map(|it| Event::NotFound {
                                peer: id,
                                hash: it.hash,
                            })
                            .collect(),
                    );
                }
                let mut out = Vec::new();
                for it in items {
                    if it.kind != InvKind::Block {
                        continue;
                    }
                    p.getdata_seen.push(it.hash);
                    if let Some(h) = p.chain.iter().find(|h| h.hash == it.hash) {
                        out.push(Event::Body {
                            peer: id,
                            hash: it.hash,
                            height: h.height,
                            bytes: vec![7u8; 256],
                        });
                    } else {
                        p.notfound_sent += 1;
                        out.push(Event::NotFound {
                            peer: id,
                            hash: it.hash,
                        });
                    }
                }
                Some(out)
            }
            Msg::GetCheckpoint => None,
            _ => None,
        }
    }

    pub fn now_unix_for_test(&self) -> u64 {
        self.now_unix
    }

    pub fn pin_tip_time_to_now(&mut self) {
        self.chain.set_tip_time(Some(self.now_unix));
        self.pin_tip = true;
    }

    pub fn engine_event(&mut self, ev: Event) {
        let acts = self.engine.on_event(ev, self.now);
        self.dispatch(acts);
    }

    pub fn headers_served_total(&self) -> u64 {
        self.peers.iter().map(|p| p.headers_served).sum()
    }

    pub fn sync_peer(&self) -> Option<PeerId> {
        self.engine.header.sync_peer()
    }

    pub fn getdata_for(&self, hash: &Hash32) -> u64 {
        self.peers
            .iter()
            .map(|p| p.getdata_seen.iter().filter(|h| *h == hash).count() as u64)
            .sum()
    }

    pub fn getdata_total(&self) -> u64 {
        self.peers.iter().map(|p| p.getdata_seen.len() as u64).sum()
    }

    pub fn said<F: Fn(&Condition) -> bool>(&self, f: F) -> bool {
        self.engine.conditions().iter().any(f)
    }
}
