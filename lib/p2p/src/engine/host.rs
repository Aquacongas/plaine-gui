use crate::config::P2pConfig;
use crate::constants::*;
use crate::engine::fd::FdBudget;
use crate::engine::serve::ServePool;
use crate::engine::{Driver, EngineThread, NetOut, ToEngine};
use crate::net::node::{self, DialReq, Net};
use crate::net::sock;
use crate::sync::Action;
use crate::traits::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickMode {
    Auto,
    Manual,
}

#[derive(Clone, Debug)]
pub struct NetOptions {
    pub listen: SocketAddr,
    pub ticks: TickMode,
    pub workers: usize,
}

impl Default for NetOptions {
    fn default() -> NetOptions {
        NetOptions {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            ticks: TickMode::Manual,
            workers: 4,
        }
    }
}

pub struct NetNode<D: Driver> {
    rt: Option<tokio::runtime::Runtime>,
    net: Arc<Net>,
    engine: Option<std::thread::JoinHandle<D>>,
    alive_rx: Option<mpsc::Receiver<()>>,
    local: SocketAddr,
}

impl<D: Driver> NetNode<D> {
    pub fn start<C: ChainView>(
        driver: D,
        chain: Arc<C>,
        cfg: P2pConfig,
        clock: Arc<dyn Clock>,
        opts: NetOptions,
    ) -> std::io::Result<NetNode<D>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(opts.workers)
            .enable_all()
            .thread_name("p2p-net")
            .build()?;

        let fd = FdBudget::new();
        let (to_engine, engine_rx) = mpsc::channel::<ToEngine>(ENGINE_QUEUE_ITEMS);
        let (dials, dial_rx) = mpsc::channel::<DialReq>(256);
        let (shutdown, _) = watch::channel(false);
        let (alive_tx, alive_rx) = mpsc::channel::<()>(1);
        let (tip_tx, tip) = crate::tip::channel(chain.tip());

        let net = node::new_net(
            cfg,
            Arc::clone(&clock),
            Arc::clone(&fd),
            ServePool::spawn(Arc::clone(&chain)),
            to_engine,
            dials,
            shutdown,
            alive_tx,
            tip_tx,
            tip,
        );

        let out: Arc<dyn NetOut> = Arc::clone(&net) as Arc<dyn NetOut>;
        let engine = EngineThread::spawn(driver, chain, engine_rx, out, clock);

        let (listener, lease) = rt.block_on(sock::bind(opts.listen, &fd))?;
        let local = listener.local_addr()?;

        net.set_local(local);

        rt.spawn(node::accept_loop(listener, lease, Arc::clone(&net)));
        rt.spawn(node::dial_loop(dial_rx, Arc::clone(&net)));
        if opts.ticks == TickMode::Auto {
            rt.spawn(node::tick_loop(Arc::clone(&net)));
        }

        Ok(NetNode {
            rt: Some(rt),
            net,
            engine: Some(engine),
            alive_rx: Some(alive_rx),
            local,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn net(&self) -> &Arc<Net> {
        &self.net
    }

    pub fn fd(&self) -> &Arc<FdBudget> {
        &self.net.fd
    }

    pub fn tip(&self) -> TipSnapshot {
        self.net.tip.tip()
    }

    pub fn peer_count(&self) -> usize {
        self.net.peer_count()
    }

    pub fn dial(&self, addr: SocketAddr) {
        self.net.add_address(addr);
    }

    pub fn learn(&self, addr: SocketAddr) {
        self.net.learn_address(addr);
    }

    pub fn outbound_count(&self) -> usize {
        self.net.outbound_count()
    }

    pub fn inbound_count(&self) -> usize {
        self.net.inbound_count()
    }

    pub fn peer_rows(&self) -> Vec<crate::net::node::PeerRow> {
        self.net.peer_rows()
    }

    pub fn tick(&self) {
        self.net.tick();
    }

    pub fn actions(&self) -> Vec<Action> {
        self.net.journal.lock().expect("journal").snapshot()
    }

    pub fn conditions(&self) -> Vec<Condition> {
        self.net.conditions.lock().expect("conditions").snapshot()
    }

    pub fn actions_since(&self, cursor: u64) -> (Vec<Action>, u64, u64) {
        self.net.journal.lock().expect("journal").since(cursor)
    }

    pub fn conditions_since(&self, cursor: u64) -> (Vec<Condition>, u64, u64) {
        self.net
            .conditions
            .lock()
            .expect("conditions")
            .since(cursor)
    }

    pub fn shutdown(mut self) -> D {
        let _ = self.net.shutdown.send(true);
        let _ = self.net.to_engine.try_send(ToEngine::Shutdown);
        let engine = self.engine.take().expect("engine handle");
        let driver = engine.join().expect("p2p-engine panicked");

        let rt = self.rt.take().expect("runtime");
        let alive_rx = self.alive_rx.take().expect("alive");
        rt.block_on(node::drain(Arc::clone(&self.net), alive_rx));
        rt.shutdown_timeout(std::time::Duration::from_millis(SHUTDOWN_DRAIN_MS));
        self.net.serve.shutdown();
        driver
    }
}
