use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use plaine_chain::traits::Store;
use plaine_rpc::{RpcConfig, RpcServer, Shutdown};

use crate::config::{self, Overrides};
use crate::health;
use crate::node;
use crate::paths::{self, Paths};
use crate::wire::store::NodeStore;
use crate::wire::tip::TipCell;

#[derive(Debug, Clone)]
pub struct DirectChainInfo {
    pub network: String,
    pub version: String,
    pub height: u64,
    pub tip_hash: String,
    pub chainwork: String,
    pub tip_time: u64,
    pub tip_age_secs: u64,
    pub sync: String,
    pub txindex: bool,
    pub pruned: bool,
    pub prune_horizon_height: u64,
    pub peers: u64,
    pub best_known_height: u64,
}

#[derive(Debug, Clone)]
pub struct DirectAccountInfo {
    pub balance: String,
    pub nonce: u64,
    pub pending_nonce: u64,
    pub immature: String,
    pub spendable: String,
}

#[derive(Debug, Clone)]
pub struct DirectFeeSuggest {
    pub blocks_sampled: u64,
    pub p10_mile: String,
    pub p50_mile: String,
    pub p90_mile: String,
    pub relay_floor_mile: String,
}

#[derive(Debug, Clone)]
pub struct DirectMempoolTx {
    pub txid: String,
}

#[derive(Clone)]
pub struct DirectApi {
    chain: Arc<dyn plaine_rpc::views::ChainView>,
    mempool: Arc<dyn plaine_rpc::views::MempoolView>,
    net: Arc<dyn plaine_rpc::views::NetView>,
}

impl DirectApi {
    pub fn chain_info(&self) -> DirectChainInfo {
        let c = self.chain.info();

        DirectChainInfo {
            network: c.network.as_str().to_string(),

            version: c.version,

            height: c.height,

            tip_hash: plaine_consensus::hex::encode(&c.tip_hash),

            chainwork: plaine_consensus::hex::encode(&c.chainwork),

            tip_time: c.tip_time,

            tip_age_secs: c.tip_age_secs,

            sync: c.sync.as_str().to_string(),

            txindex: c.txindex,

            pruned: c.pruned,

            prune_horizon_height: c.prune_horizon_height,

            peers: self.net.peers().len() as u64,

            best_known_height: c.best_known_height.unwrap_or(c.height),
        }
    }

    pub fn account(&self, address: &str) -> Result<DirectAccountInfo, String> {
        let payload =
            plaine_consensus::crypto::decode_address(address).map_err(|e| e.to_string())?;

        let a = self.chain.account(&payload);

        Ok(DirectAccountInfo {
            balance: a.balance.to_string(),

            nonce: a.nonce,

            pending_nonce: a.pending_nonce,

            immature: a.immature.to_string(),

            spendable: a.balance.saturating_sub(a.immature).to_string(),
        })
    }

    pub fn fee_suggest(&self) -> DirectFeeSuggest {
        let f = self.mempool.fee_suggest();

        DirectFeeSuggest {
            blocks_sampled: f.blocks_sampled,

            p10_mile: f.p10_mile.to_string(),

            p50_mile: f.p50_mile.to_string(),

            p90_mile: f.p90_mile.to_string(),

            relay_floor_mile: f.relay_floor_mile.to_string(),
        }
    }

    pub fn mempool_by_sender(&self, address: &str) -> Result<Vec<DirectMempoolTx>, String> {
        let payload =
            plaine_consensus::crypto::decode_address(address).map_err(|e| e.to_string())?;

        Ok(self
            .mempool
            .by_sender(&payload)
            .into_iter()
            .map(|tx| DirectMempoolTx {
                txid: plaine_consensus::hex::encode(&tx.txid),
            })
            .collect())
    }

    pub fn tx_send_raw(&self, raw_hex: &str) -> Result<String, String> {
        let hex = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);

        if hex.len() > plaine_consensus::constants::MAX_TX_BYTES * 2 {
            return Err("transaction exceeds MAX_TX_BYTES".into());
        }

        let raw = plaine_consensus::hex::decode(hex)
            .map_err(|e| format!("invalid transaction hex: {e}"))?;

        let txid = self.mempool.submit(&raw).map_err(|e| e.human())?;

        Ok(plaine_consensus::hex::encode(&txid))
    }
}

#[derive(Clone)]
pub struct HistoryReader {
    store: Arc<NodeStore>,
    tip: TipCell,
}

impl HistoryReader {
    pub fn tip_height(&self) -> u64 {
        self.tip.get().height
    }

    pub fn prune_floor(&self) -> u64 {
        self.store.reader().prune_floor()
    }

    pub fn block_raw(&self, height: u64) -> Result<Vec<u8>, String> {
        let header = self
            .store
            .header_at(height)
            .ok_or_else(|| format!("header {height} is not available"))?;

        let body = self
            .store
            .body_at_verified(height)
            .ok_or_else(|| format!("body {height} is not available"))?;

        let mut raw = Vec::with_capacity(header.raw.len() + body.len());

        raw.extend_from_slice(&header.raw);

        raw.extend_from_slice(&body);

        Ok(raw)
    }
}

pub struct EmbeddedNode {
    shutdown: Shutdown,
    thread: Option<thread::JoinHandle<()>>,
    history: HistoryReader,
    direct: DirectApi,
}

impl EmbeddedNode {
    pub fn start_default() -> Result<Self, String> {
        let shutdown = Shutdown::new();
        let thread_shutdown = shutdown.clone();

        let (ready_tx, ready_rx) =
            mpsc::sync_channel::<Result<(HistoryReader, DirectApi), String>>(1);

        let handle = thread::Builder::new()
            .name("plaine-embedded-node".into())
            .spawn(move || {
                if let Err(e) = run_embedded(thread_shutdown, ready_tx.clone()) {
                    let _ = ready_tx.send(Err(e));
                }
            })
            .map_err(|e| format!("cannot spawn node thread: {e}"))?;

        match ready_rx.recv() {
            Ok(Ok((history, direct))) => Ok(Self {
                shutdown,
                thread: Some(handle),
                history,
                direct,
            }),

            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }

            Err(e) => {
                let _ = handle.join();

                Err(format!("node startup thread closed unexpectedly: {e}"))
            }
        }
    }

    pub fn history_reader(&self) -> HistoryReader {
        self.history.clone()
    }

    pub fn direct_api(&self) -> DirectApi {
        self.direct.clone()
    }

    pub fn shutdown(&mut self) {
        self.shutdown.trigger();

        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EmbeddedNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn load_config() -> Result<(config::Config, Paths), String> {
    let bootstrap_dir = paths::default_data_dir();

    let bootstrap_paths = Paths::resolve(&bootstrap_dir, None);

    let overrides = Overrides {
        network: None,
        data_dir: None,
        log_level: None,
    };

    let cfg = match std::fs::read_to_string(&bootstrap_paths.config_file) {
        Ok(src) => {
            let path_text = bootstrap_paths.config_file.display().to_string();

            config::load(&path_text, &src, &overrides).map_err(|e| e.to_string())?
        }

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => config::defaults(&overrides),

        Err(e) => {
            return Err(format!(
                "cannot read {}: {e}",
                bootstrap_paths.config_file.display()
            ));
        }
    };

    let paths = Paths::resolve(&cfg.data_dir, None);

    Ok((cfg, paths))
}

fn run_embedded(
    shutdown: Shutdown,
    ready: mpsc::SyncSender<Result<(HistoryReader, DirectApi), String>>,
) -> Result<(), String> {
    let (cfg, paths) = load_config()?;

    std::fs::create_dir_all(&paths.chain_dir)
        .map_err(|e| format!("cannot create {}: {e}", paths.chain_dir.display()))?;

    let node = node::start(&cfg, &paths).map_err(|e| format!("cannot start Plaine node: {e}"))?;

    let history = HistoryReader {
        store: Arc::clone(&node.store),

        tip: node.tip.clone(),
    };

    let views = node.rpc_views(&cfg);

    let direct = DirectApi {
        chain: Arc::clone(&views.chain),

        mempool: Arc::clone(&views.mempool),

        net: Arc::clone(&views.net),
    };

    let rpc_cfg = RpcConfig {
        bind: cfg.rpc_listen,

        token: cfg.rpc_token.clone(),

        ..RpcConfig::loopback(cfg.rpc_listen.port())
    };

    let server = match RpcServer::bind(rpc_cfg, views, shutdown.clone()) {
        Ok(server) => server,

        Err(e) => {
            node.shutdown();

            return Err(format!("cannot start embedded RPC: {e}"));
        }
    };

    let server = Arc::new(server);

    let rpc_thread = {
        let server = server.clone();

        thread::Builder::new()
            .name("plaine-embedded-rpc".into())
            .spawn(move || {
                server.serve();
            })
            .map_err(|e| format!("cannot spawn RPC thread: {e}"))?
    };

    let _ = ready.send(Ok((history, direct)));

    let started = Instant::now();

    let mut tracker = health::Tracker::new(node.tip.height(), 0);

    let mut next_beat = Duration::from_secs(0);

    let mut sweeper = plaine_storage::sweep::HeaderSweeper::default();

    while !shutdown.is_triggered() {
        node.refresh();

        let elapsed = started.elapsed().as_secs();

        tracker.note_height(node.tip.height(), elapsed);

        if started.elapsed() >= next_beat {
            let verdict = node.beat(&mut tracker, elapsed);

            node.sweep_headers(&mut sweeper);

            next_beat =
                started.elapsed() + Duration::from_secs(health::heartbeat_interval(verdict.status));
        }

        thread::sleep(Duration::from_millis(200));
    }

    shutdown.trigger();

    let _ = rpc_thread.join();

    node.shutdown();

    Ok(())
}
