use crate::addr::addrman::Ingest;
use crate::addr::AddrMan;
use crate::config::P2pConfig;
use crate::constants::*;
use crate::engine::fd::{FdBudget, FdClass, FdLease};
use crate::engine::serve::ServePool;
use crate::engine::{NetOut, ToEngine};
use crate::gate::g4_budget::TokenBucket;
use crate::net::conn;
use crate::net::limits::{ip_bytes, BanSet, ConnLimits, Refusal};
use crate::net::sock;
use crate::peer::session::group_of;
use crate::sync::{Action, DeadReason};
use crate::tip::{TipPublisher, TipReader};
use crate::traits::*;
use crate::wire::codec::encode;
use crate::wire::frame::encode_frame;
use crate::wire::msg::Msg;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch, Semaphore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Control,
    Bulk,
}

#[derive(Debug, Default)]
pub struct PeerStat {
    pub best_height: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub misbehaviour: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct PeerRow {
    pub id: PeerId,
    pub ip: [u8; 16],
    pub port: u16,
    pub outbound: bool,
    pub services: u32,
    pub user_agent: String,
    pub best_height: u64,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
    pub misbehaviour: u32,
    pub connected_ms: u64,
}

#[derive(Debug)]
pub struct Wire {
    pub ip: [u8; 16],
    pub port: u16,
    pub user_agent: String,
    pub services: u32,
    pub since: Mono,
    pub stat: Arc<PeerStat>,
    pub outbound: bool,
    pub control: mpsc::Sender<Vec<u8>>,
    pub bulk: mpsc::Sender<Vec<u8>>,
    pub outbox_bytes: Arc<AtomicU64>,
    pub kill: watch::Sender<bool>,
}

#[derive(Clone, Copy, Debug)]
pub enum DialReq {
    Explicit(SocketAddr),

    Reach {
        count: usize,
        widen: bool,
    },
}

pub struct Net {
    pub cfg: P2pConfig,
    pub clock: Arc<dyn Clock>,
    pub fd: Arc<FdBudget>,
    pub to_engine: mpsc::Sender<ToEngine>,
    pub serve: ServePool,
    pub tip: TipReader,
    tip_tx: TipPublisher,
    pub nonce: u64,
    pub peers: Mutex<BTreeMap<PeerId, Wire>>,
    pub limits: Mutex<ConnLimits>,
    pub bans: Mutex<BanSet>,
    pub read_global: Mutex<TokenBucket>,
    pub inbox_pool: Arc<Semaphore>,
    pub outbox_pool: AtomicU64,
    pub sync_peer: AtomicU64,
    pub(crate) next_id: AtomicU64,
    pub inbound: AtomicUsize,
    pub outbound: AtomicUsize,
    pub dialing: AtomicUsize,
    pub shutdown: watch::Sender<bool>,
    pub dials: mpsc::Sender<DialReq>,
    pub book: Mutex<VecDeque<SocketAddr>>,
    pub addrs: Mutex<AddrMan>,
    pub(crate) rng: Mutex<crate::rng::Rng>,
    pub(crate) local: Mutex<Option<([u8; 16], u16)>>,
    pub addrs_learned: AtomicU64,
    pub addrs_restored: AtomicU64,
    pub addrs_filtered: AtomicU64,
    pub addrs_over_quota: AtomicU64,
    pub getaddr_answered: AtomicU64,
    pub getaddr_repeats: AtomicU64,
    last_maintain: AtomicU64,
    pub journal: Mutex<Ring<Action>>,
    pub conditions: Mutex<Ring<Condition>>,
    pub alive: Mutex<Option<mpsc::Sender<()>>>,
}

const JOURNAL_MAX: usize = 4096;

#[derive(Debug)]
// bounded journal with a monotone sequence: readers hold a cursor and `since`
// tells them what is new plus how many entries were evicted before they read.
pub struct Ring<T> {
    items: VecDeque<T>,
    // total entries ever dropped off the front; the base of the sequence.
    dropped: u64,
}

impl<T> Default for Ring<T> {
    fn default() -> Self {
        Ring { items: VecDeque::new(), dropped: 0 }
    }
}

impl<T: Clone> Ring<T> {
    pub fn push(&mut self, v: T, cap: usize) {
        self.items.push_back(v);
        while self.items.len() > cap {
            self.items.pop_front();
            self.dropped += 1;
        }
    }

    pub fn seq(&self) -> u64 {
        self.dropped + self.items.len() as u64
    }

    pub fn since(&self, cursor: u64) -> (Vec<T>, u64, u64) {
        let missed = self.dropped.saturating_sub(cursor);
        let skip = cursor.saturating_sub(self.dropped) as usize;
        let out = self.items.iter().skip(skip).cloned().collect();
        (out, self.seq(), missed)
    }

    pub fn snapshot(&self) -> Vec<T> {
        self.items.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// per-connection nonce echoed in the handshake; seeing our own back is how we
// detect a self-dial regardless of the address it came in on.
fn fresh_nonce() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut r = crate::rng::Rng::new(
        t ^ ((std::process::id() as u64) << 32) ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
    );
    r.next_u64() ^ n.rotate_left(41)
}

impl Net {
    pub fn new_id(&self) -> PeerId {
        PeerId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    pub fn is_sync_peer(&self, id: PeerId) -> bool {
        self.sync_peer.load(Ordering::Relaxed) == id.0
    }

    pub fn charge_read_global(&self, bytes: u64) -> u64 {
        let now = self.clock.mono();
        let mut b = self.read_global.lock().expect("read_global");
        if b.take(bytes, now) {
            return 0;
        }
        let level = b.level(now);
        bytes.saturating_sub(level) * 1000 / READ_GLOBAL_BYTES_PER_SEC + 1
    }

    pub fn enqueue(&self, id: PeerId, msg: &Msg, tier: Tier) -> bool {
        let bytes = encode_frame(&self.cfg.magic, msg.cmd(), &encode(msg));
        let n = bytes.len() as u64;
        let g = self.peers.lock().expect("peers");
        let Some(w) = g.get(&id) else {
            return false;
        };
        let queued = w.outbox_bytes.load(Ordering::Relaxed);
        if tier == Tier::Bulk {
            if queued + n > OUTBOX_BYTES || self.outbox_pool.load(Ordering::Relaxed) + n
                > OUTBOX_POOL_BYTES
            {
                let _ = w.kill.send(true);
                return false;
            }
            if queued + n > OUTBOX_SOFT_BYTES {
                return false;
            }
        }
        w.outbox_bytes.fetch_add(n, Ordering::Relaxed);
        self.outbox_pool.fetch_add(n, Ordering::Relaxed);
        let tx = match tier {
            Tier::Control => &w.control,
            Tier::Bulk => &w.bulk,
        };
        match tx.try_send(bytes) {
            Ok(()) => true,
            Err(e) => {
                let dropped = match e {
                    mpsc::error::TrySendError::Full(b) => b,
                    mpsc::error::TrySendError::Closed(b) => b,
                };
                w.outbox_bytes
                    .fetch_sub(dropped.len() as u64, Ordering::Relaxed);
                self.outbox_pool
                    .fetch_sub(dropped.len() as u64, Ordering::Relaxed);
                if tier == Tier::Control {
                    let _ = w.kill.send(true);
                }
                false
            }
        }
    }

    pub fn kill(&self, id: PeerId) {
        if let Some(w) = self.peers.lock().expect("peers").get(&id) {
            let _ = w.kill.send(true);
        }
    }

    pub fn kill_all(&self) {
        for w in self.peers.lock().expect("peers").values() {
            let _ = w.kill.send(true);
        }
    }

    pub fn learn_address(&self, addr: SocketAddr) {
        self.book.lock().expect("book").push_back(addr);
        self.addrs
            .lock()
            .expect("addrs")
            .add(ip_bytes(&addr), addr.port(), false, self.clock.now_unix());
    }

    pub fn add_address(&self, addr: SocketAddr) {
        self.book.lock().expect("book").push_back(addr);

        self.addrs
            .lock()
            .expect("addrs")
            .add(ip_bytes(&addr), addr.port(), true, self.clock.now_unix());
        let _ = self.dials.try_send(DialReq::Explicit(addr));
    }

    pub fn set_local(&self, addr: SocketAddr) {
        *self.local.lock().expect("local") = Some((ip_bytes(&addr), addr.port()));
    }

    fn is_self(&self, ip: &[u8; 16], port: u16) -> bool {
        match *self.local.lock().expect("local") {
            Some((lip, lport)) => lip == *ip && (port == lport || port == self.cfg.port),
            None => false,
        }
    }

    pub fn addr_sample(&self) -> Vec<Msg> {
        let now_unix = self.clock.now_unix();
        let mut rng = self.rng.lock().expect("rng");
        let picked = self.addrs.lock().expect("addrs").sample(
            ADDR_MSG_MAX,
            now_unix,
            &mut rng,
            self.cfg.accept_local_addrs,
        );
        let recs: Vec<crate::wire::msg::AddrRec> = picked
            .iter()
            .map(|e| crate::wire::msg::AddrRec {
                time: e.last_seen,
                services: e.services,
                ip: e.ip,
                port: e.port,
            })
            .collect();
        vec![Msg::Addr(recs)]
    }

    pub fn ingest_addrs(&self, recs: &[crate::wire::msg::AddrRec], from: &[u8; 16], limit: usize) -> usize {
        let now_unix = self.clock.now_unix();
        let source = group_of(from);
        let allow_local = self.cfg.accept_local_addrs;
        let mut added = 0usize;
        let mut filtered = 0u64;
        let mut over = 0u64;
        let mut am = self.addrs.lock().expect("addrs");
        for r in recs.iter().take(limit) {
            if self.is_self(&r.ip, r.port) {
                filtered += 1;
                continue;
            }
            match am.add_from_peer(
                r.ip,
                r.port,
                r.services,
                r.time,
                source,
                now_unix,
                allow_local,
            ) {
                Ingest::Added => added += 1,
                Ingest::Filtered => filtered += 1,
                Ingest::OverQuota => over += 1,
                Ingest::Refreshed | Ingest::TableFull | Ingest::TooOld => {}
            }
        }
        drop(am);
        self.addrs_learned
            .fetch_add(added as u64, Ordering::Relaxed);
        self.addrs_filtered.fetch_add(filtered, Ordering::Relaxed);
        self.addrs_over_quota.fetch_add(over, Ordering::Relaxed);
        added
    }

    pub fn note_peer_address(&self, ip: &[u8; 16], listen_port: u16, services: u32) {
        if self.is_self(ip, listen_port) {
            return;
        }
        let now_unix = self.clock.now_unix();
        let source = group_of(ip);
        let allow_local = self.cfg.accept_local_addrs;
        let out = self.addrs.lock().expect("addrs").add_from_peer(
            *ip,
            listen_port,
            services,
            now_unix,
            source,
            now_unix,
            allow_local,
        );
        match out {
            Ingest::Added => {
                self.addrs_learned.fetch_add(1, Ordering::Relaxed);
            }
            Ingest::Filtered => {
                self.addrs_filtered.fetch_add(1, Ordering::Relaxed);
            }
            Ingest::OverQuota => {
                self.addrs_over_quota.fetch_add(1, Ordering::Relaxed);
            }
            Ingest::Refreshed | Ingest::TableFull | Ingest::TooOld => {}
        }
    }

    pub fn addr_count(&self) -> usize {
        self.addrs.lock().expect("addrs").len()
    }

    pub fn addr_snapshot(&self) -> Vec<u8> {
        crate::addr::persist::encode(
            self.addrs.lock().expect("addrs").entries(),
            self.cfg.chain_id,
        )
    }

    pub fn load_addrs(
        &self,
        bytes: &[u8],
    ) -> Result<crate::addr::RestoreStats, crate::addr::PeersError> {
        let mut recs = crate::addr::persist::decode(bytes, self.cfg.chain_id)?;

        recs.retain(|r| !self.is_self(&r.ip, r.port));
        let mut rng = self.rng.lock().expect("rng");
        let st = self.addrs.lock().expect("addrs").restore(
            &recs,
            self.clock.now_unix(),
            self.cfg.accept_local_addrs,
            &mut rng,
        );
        drop(rng);
        self.addrs_restored.fetch_add(st.loaded, Ordering::Relaxed);
        Ok(st)
    }

    pub fn tick(&self) {
        let _ = self.to_engine.try_send(ToEngine::Tick(self.clock.mono()));
        self.maintain_outbound();
    }

    pub fn maintain_outbound(&self) {
        let now = self.clock.mono();
        let last = Mono(self.last_maintain.load(Ordering::Relaxed));
        if !now.expired(last, CONN_MANAGER_TICK_MS) {
            return;
        }
        self.last_maintain.store(now.0, Ordering::Relaxed);

        self.addrs
            .lock()
            .expect("addrs")
            .reap_expired(self.clock.now_unix());
        let established = self.outbound.load(Ordering::Relaxed);
        let inflight = self.dialing.load(Ordering::Relaxed);
        if established + inflight >= OUTBOUND_TARGET {
            return;
        }

        let widen = established == 0;
        let _ = self.dials.try_send(DialReq::Reach {
            count: OUTBOUND_TARGET - established - inflight,
            widen,
        });
    }

    pub fn peer_count(&self) -> usize {
        self.peers.lock().expect("peers").len()
    }

    pub fn outbound_count(&self) -> usize {
        self.outbound.load(Ordering::Relaxed)
    }

    pub fn inbound_count(&self) -> usize {
        self.inbound.load(Ordering::Relaxed)
    }

    pub fn peer_rows(&self) -> Vec<PeerRow> {
        let now = self.clock.mono();
        self.peers
            .lock()
            .expect("peers")
            .iter()
            .map(|(id, w)| PeerRow {
                id: *id,
                ip: w.ip,
                port: w.port,
                outbound: w.outbound,
                services: w.services,
                user_agent: w.user_agent.clone(),
                best_height: w.stat.best_height.load(Ordering::Relaxed),
                bytes_recv: w.stat.bytes_recv.load(Ordering::Relaxed),
                bytes_sent: w.stat.bytes_sent.load(Ordering::Relaxed),
                misbehaviour: w.stat.misbehaviour.load(Ordering::Relaxed) as u32,
                connected_ms: now.since(w.since),
            })
            .collect()
    }

    pub fn alive_token(&self) -> Option<mpsc::Sender<()>> {
        self.alive.lock().expect("alive").clone()
    }
}

impl NetOut for Net {
    fn dispatch(&self, a: Action) {
        {
            self.journal.lock().expect("journal").push(a.clone(), JOURNAL_MAX);
        }
        match a {
            Action::Send { peer, msg } => {
                self.enqueue(peer, &msg, Tier::Control);
            }
            Action::Disconnect { peer, .. } => self.kill(peer),
            Action::Ban { peer, ms } => {
                let ip = self
                    .peers
                    .lock()
                    .expect("peers")
                    .get(&peer)
                    .map(|w| w.ip);
                if let Some(ip) = ip {
                    let now = self.clock.mono();
                    self.bans.lock().expect("bans").ban(ip, ms, now);
                }
                self.kill(peer);
            }
            Action::Designate { peer } => {
                self.sync_peer.store(peer.0, Ordering::Relaxed);
            }
            Action::Undesignate { peer } => {
                let _ = self.sync_peer.compare_exchange(
                    peer.0,
                    0,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            Action::Dial { count, widen } => {
                let _ = self.dials.try_send(DialReq::Reach { count, widen });
            }

            _ => {}
        }
    }

    fn say(&self, c: Condition) {
        self.conditions.lock().expect("conditions").push(c, JOURNAL_MAX);
    }

    fn publish_tip(&self, t: TipSnapshot) {
        self.tip_tx.publish(t);
    }

    fn note_peer_stats(&self, stats: &[(PeerId, u64, u32)]) {
        let g = self.peers.lock().expect("peers");
        for (id, h, score) in stats {
            if let Some(w) = g.get(id) {
                w.stat.best_height.store(*h, Ordering::Relaxed);
                w.stat.misbehaviour.store(u64::from(*score), Ordering::Relaxed);
            }
        }
    }
}

pub(crate) async fn accept_loop(listener: tokio::net::TcpListener, lease: FdLease, net: Arc<Net>) {
    let mut stop = net.shutdown.subscribe();
    loop {
        let r = tokio::select! {
            _ = stop.changed() => break,
            r = sock::accept(&listener) => r,
        };
        let (stream, addr) = match r {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(
                    ACCEPT_ERROR_BACKOFF_MS,
                ))
                .await;
                continue;
            }
        };
        let ip = ip_bytes(&addr);
        let now = net.clock.mono();

        if net.bans.lock().expect("bans").banned(&ip, now) {
            drop(stream);
            continue;
        }
        if net.inbound.load(Ordering::Relaxed) >= MAX_INBOUND {
            let _ = Refusal::NoSlot;
            drop(stream);
            continue;
        }
        if net
            .limits
            .lock()
            .expect("limits")
            .admit_inbound(ip, now)
            .is_err()
        {
            drop(stream);
            continue;
        }
        let Some(lease) = net.fd.acquire(FdClass::InboundHandshake) else {
            let _ = Refusal::NoDescriptor;
            net.limits.lock().expect("limits").release_inbound(ip);
            drop(stream);
            continue;
        };
        let net2 = Arc::clone(&net);

        tokio::spawn(async move {
            conn::run(stream, ip, 0, false, lease, net2).await;
        });
    }
    drop(listener);
    drop(lease);
}

pub(crate) async fn dial_loop(mut rx: mpsc::Receiver<DialReq>, net: Arc<Net>) {
    let mut stop = net.shutdown.subscribe();
    loop {
        let req = tokio::select! {
            _ = stop.changed() => break,
            r = rx.recv() => match r { Some(r) => r, None => break },
        };
        let (addrs, widen): (Vec<SocketAddr>, bool) = match req {
            DialReq::Explicit(a) => (vec![a], false),
            DialReq::Reach { count, widen } => {
                let established = net.outbound.load(Ordering::Relaxed);
                let inflight = net.dialing.load(Ordering::Relaxed);
                let target = (established + count).min(MAX_OUTBOUND);
                let needed = target.saturating_sub(established + inflight);
                let needed = needed.min(COLDSTART_DIAL_CONCURRENT);
                if needed == 0 {
                    continue;
                }

                let connected: Vec<([u8; 16], u16)> = net
                    .peers
                    .lock()
                    .expect("peers")
                    .values()
                    .filter(|w| w.outbound)
                    .map(|w| (w.ip, w.port))
                    .collect();
                let now = net.clock.mono();

                let picked = net.addrs.lock().expect("addrs").select_dial_filtered(
                    needed,
                    &connected,
                    now,
                    widen,
                    net.cfg.accept_local_addrs,
                );
                (
                    picked
                        .into_iter()
                        .map(|(ip, port)| SocketAddr::from((unmap(&ip), port)))
                        .collect(),
                    widen,
                )
            }
        };
        for a in addrs {
            if net.cfg.isolated && !net.book.lock().expect("book").contains(&a) {
                continue;
            }
            if net.outbound.load(Ordering::Relaxed) + net.dialing.load(Ordering::Relaxed)
                >= MAX_OUTBOUND
            {
                break;
            }
            let ip = ip_bytes(&a);
            if net.bans.lock().expect("bans").banned(&ip, net.clock.mono()) {
                continue;
            }
            if net
                .limits
                .lock()
                .expect("limits")
                .admit_outbound(ip, widen)
                .is_err()
            {
                continue;
            }
            let Some(lease) = net.fd.acquire(FdClass::TransientDial) else {
                net.limits.lock().expect("limits").release_outbound(ip);
                continue;
            };

            {
                let now = net.clock.mono();
                net.addrs.lock().expect("addrs").note_attempt(&ip, a.port(), now);
            }
            net.dialing.fetch_add(1, Ordering::Relaxed);
            let net2 = Arc::clone(&net);
            let port = a.port();
            tokio::spawn(async move {
                match sock::connect(a, CONNECT_TIMEOUT_MS, lease).await {
                    Ok((stream, lease)) => {
                        net2.dialing.fetch_sub(1, Ordering::Relaxed);
                        conn::run(stream, ip, port, true, lease, Arc::clone(&net2)).await;
                        net2.limits.lock().expect("limits").release_outbound(ip);
                    }
                    Err(_) => {
                        net2.dialing.fetch_sub(1, Ordering::Relaxed);
                        net2.limits.lock().expect("limits").release_outbound(ip);

                        net2.addrs.lock().expect("addrs").on_failure(&ip, port, false);
                        let _ = DeadReason::DialTimeout;
                    }
                }
            });
        }
    }
}

fn unmap(ip: &[u8; 16]) -> std::net::IpAddr {
    let v4_mapped = ip[..10].iter().all(|b| *b == 0) && ip[10] == 0xff && ip[11] == 0xff;
    if v4_mapped {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(*ip))
    }
}

pub(crate) async fn tick_loop(net: Arc<Net>) {
    let mut stop = net.shutdown.subscribe();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(TICK_MS)) => {}
        }

        net.tick();
    }
}

pub fn group(ip: &[u8; 16]) -> [u8; 4] {
    group_of(ip)
}

pub async fn drain(net: Arc<Net>, mut alive_rx: mpsc::Receiver<()>) {
    tokio::time::sleep(std::time::Duration::from_millis(SHUTDOWN_DRAIN_MS.min(50))).await;
    net.kill_all();
    *net.alive.lock().expect("alive") = None;
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(SHUTDOWN_DRAIN_MS),
        alive_rx.recv(),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn new_net(
    cfg: P2pConfig,
    clock: Arc<dyn Clock>,
    fd: Arc<FdBudget>,
    serve: ServePool,
    to_engine: mpsc::Sender<ToEngine>,
    dials: mpsc::Sender<DialReq>,
    shutdown: watch::Sender<bool>,
    alive_tx: mpsc::Sender<()>,
    tip_tx: TipPublisher,
    tip: TipReader,
) -> Arc<Net> {
    let now = clock.mono();
    Arc::new(Net {
        nonce: fresh_nonce(),
        serve,
        cfg,
        clock,
        fd,
        to_engine,
        tip,
        tip_tx,
        peers: Mutex::new(BTreeMap::new()),
        limits: Mutex::new(ConnLimits::new(now)),
        bans: Mutex::new(BanSet::new()),
        read_global: Mutex::new(TokenBucket::new(
            READ_GLOBAL_BYTES_PER_SEC,
            READ_GLOBAL_BYTES_PER_SEC,
            now,
        )),
        inbox_pool: Arc::new(Semaphore::new(INBOX_POOL_BYTES as usize)),
        outbox_pool: AtomicU64::new(0),
        sync_peer: AtomicU64::new(0),
        next_id: AtomicU64::new(1),
        inbound: AtomicUsize::new(0),
        outbound: AtomicUsize::new(0),
        dialing: AtomicUsize::new(0),
        shutdown,
        dials,
        book: Mutex::new(VecDeque::new()),
        addrs: Mutex::new(AddrMan::new()),
        rng: Mutex::new(crate::rng::Rng::new(fresh_nonce())),
        local: Mutex::new(None),
        addrs_learned: AtomicU64::new(0),
        addrs_restored: AtomicU64::new(0),
        addrs_filtered: AtomicU64::new(0),
        addrs_over_quota: AtomicU64::new(0),
        getaddr_answered: AtomicU64::new(0),
        getaddr_repeats: AtomicU64::new(0),
        last_maintain: AtomicU64::new(now.0),
        journal: Mutex::new(Ring::default()),
        conditions: Mutex::new(Ring::default()),
        alive: Mutex::new(Some(alive_tx)),
    })
}
