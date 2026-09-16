pub mod fd;
pub mod host;
pub mod serve;

use crate::constants::HEADER_BYTES;
use crate::gate::g2_context::BitsRule;
use crate::sync::{Action, Event, SyncEngine};
use crate::traits::*;
use std::collections::VecDeque;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::mpsc;
use tokio::sync::OwnedSemaphorePermit;

pub trait Driver: Send + 'static {
    fn on_event(&mut self, ev: Event, now: Mono) -> Vec<Action>;

    fn on_tick(&mut self, now: Mono) -> Vec<Action>;

    fn drain_conditions(&mut self) -> Vec<Condition>;

    fn set_now_unix(&mut self, t: u64);

    fn peer_stats(&self, _now: Mono) -> Vec<(PeerId, u64, u32)> {
        Vec::new()
    }
}

impl<C: ChainView, S: BlockSink, V: PowVerifier, B: BitsRule> Driver for SyncEngine<C, S, V, B> {
    fn on_event(&mut self, ev: Event, now: Mono) -> Vec<Action> {
        SyncEngine::on_event(self, ev, now)
    }
    fn on_tick(&mut self, now: Mono) -> Vec<Action> {
        SyncEngine::on_tick(self, now)
    }
    fn drain_conditions(&mut self) -> Vec<Condition> {
        SyncEngine::drain_conditions(self)
    }
    fn set_now_unix(&mut self, t: u64) {
        SyncEngine::set_now_unix(self, t)
    }
    fn peer_stats(&self, now: Mono) -> Vec<(PeerId, u64, u32)> {
        SyncEngine::peers(self)
            .iter()
            .map(|(id, s)| (*id, s.claimed_height, s.score.value(now)))
            .collect()
    }
}

pub trait NetOut: Send + Sync + 'static {
    fn dispatch(&self, a: Action);

    fn say(&self, c: Condition);

    fn publish_tip(&self, t: TipSnapshot);

    fn note_peer_stats(&self, stats: &[(PeerId, u64, u32)]) {
        let _ = stats;
    }
}

#[derive(Debug, Default)]
pub struct Credit {
    pub peer: Option<OwnedSemaphorePermit>,
    pub pool: Option<OwnedSemaphorePermit>,
}

pub enum ToEngine {
    Event(Event, Credit),
    Tick(Mono),
    Shutdown,
}

impl ToEngine {
    fn is_control(&self) -> bool {
        match self {
            ToEngine::Tick(_) | ToEngine::Shutdown => true,
            ToEngine::Event(e, _) => matches!(
                e,
                Event::PeerReady { .. }
                    | Event::PeerGone { .. }
                    | Event::Paused { .. }
                    | Event::Unpaused { .. }
                    | Event::Checkpoint { .. }
                    | Event::AnchorAdvanced
                    | Event::AnchorContradiction { .. }
                    | Event::SinkFatal(_)
            ),
        }
    }
}

pub struct EngineThread;

impl EngineThread {
    pub fn spawn<D: Driver, C: ChainView>(
        mut driver: D,
        chain: Arc<C>,
        rx: mpsc::Receiver<ToEngine>,
        out: Arc<dyn NetOut>,
        clock: Arc<dyn Clock>,
    ) -> JoinHandle<D> {
        std::thread::Builder::new()
            .name("p2p-engine".to_string())
            .spawn(move || {
                out.publish_tip(chain.tip());
                EngineThread::run(&mut driver, &chain, rx, &out, &clock);
                driver
            })
            .expect("spawn p2p-engine")
    }

    fn run<D: Driver, C: ChainView>(
        driver: &mut D,
        chain: &Arc<C>,
        mut rx: mpsc::Receiver<ToEngine>,
        out: &Arc<dyn NetOut>,
        clock: &Arc<dyn Clock>,
    ) {
        let mut control: VecDeque<ToEngine> = VecDeque::new();
        let mut bulk: VecDeque<ToEngine> = VecDeque::new();
        loop {
            let Some(first) = rx.blocking_recv() else {
                return;
            };
            if first.is_control() {
                control.push_back(first);
            } else {
                bulk.push_back(first);
            }
            while let Ok(m) = rx.try_recv() {
                if m.is_control() {
                    control.push_back(m);
                } else {
                    bulk.push_back(m);
                }
            }

            let mut tick: Option<Mono> = None;
            let mut stop = false;
            let mut acts: Vec<Action> = Vec::new();

            while let Some(m) = control.pop_front() {
                match m {
                    ToEngine::Tick(t) => tick = Some(tick.map_or(t, |p: Mono| p.max(t))),
                    ToEngine::Shutdown => stop = true,
                    ToEngine::Event(e, credit) => {
                        driver.set_now_unix(clock.now_unix());
                        acts.extend(driver.on_event(e, clock.mono()));

                        drop(credit);
                    }
                }
            }
            let ticked = tick.is_some();
            if let Some(t) = tick {
                driver.set_now_unix(clock.now_unix());
                acts.extend(driver.on_tick(t));
            }
            while let Some(m) = bulk.pop_front() {
                if let ToEngine::Event(e, credit) = m {
                    driver.set_now_unix(clock.now_unix());
                    acts.extend(driver.on_event(e, clock.mono()));
                    drop(credit);
                }
            }

            let mut republish = false;
            for a in acts {
                if matches!(a, Action::RepublishTip) {
                    republish = true;
                }
                out.dispatch(a);
            }
            for c in driver.drain_conditions() {
                out.say(c);
            }

            if ticked {
                out.note_peer_stats(&driver.peer_stats(clock.mono()));
            }
            if republish {
                out.publish_tip(chain.tip());
            }
            if stop {
                return;
            }
        }
    }
}

pub fn tx_ident(bytes: &[u8]) -> Option<Hash32> {
    use plaine_consensus::codec::Tx;
    match plaine_consensus::codec::decode_tx(bytes).ok()? {
        Tx::Coinbase(_) => None,
        Tx::Transfer(t) => Some(t.txid()),
        Tx::Announcement(a) => a.txid().ok(),
    }
}

pub fn block_ident(bytes: &[u8]) -> Option<(Hash32, u64)> {
    if bytes.len() < HEADER_BYTES {
        return None;
    }
    let mut raw = [0u8; HEADER_BYTES];
    raw.copy_from_slice(&bytes[..HEADER_BYTES]);
    let h = plaine_consensus::codec::Header::decode(&raw).ok()?;
    Some((plaine_consensus::crypto::header_hash(&raw), h.height))
}
