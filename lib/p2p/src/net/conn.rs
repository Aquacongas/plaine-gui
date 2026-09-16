use crate::constants::*;
use crate::engine::fd::{FdClass, FdLease};
use crate::engine::serve::ServeJob;
use crate::engine::{block_ident, tx_ident, Credit, ToEngine};
use crate::gate::g4_budget::TokenBucket;
use crate::net::node::{Net, Tier, Wire};
use crate::net::sock;
use crate::peer::inbox::PauseCause;
use crate::peer::{HandshakeOutcome, HelloCheck};
use crate::sync::Event;
use crate::traits::PeerId;
use crate::wire::codec::decode;
use crate::wire::frame::{FrameReader, ReadArena, WireError};
use crate::wire::msg::{Hello, InvKind, Msg};
use crate::wire::Cmd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};

const READ_CHUNK: usize = ARENA_MAX;

const OUTBOX_ITEMS: usize = 256;

struct Ctx {
    net: Arc<Net>,
    id: PeerId,
    inbox: Arc<Semaphore>,
    kill: watch::Receiver<bool>,
    stat: Arc<crate::net::node::PeerStat>,
    ip: [u8; 16],
    getaddrs_in: AtomicU32,
    getaddr_sent: AtomicBool,
    addr_recs_in: AtomicUsize,
    getcheckpoints_in: AtomicU32,
}

pub(crate) async fn run(
    mut stream: TcpStream,
    ip: [u8; 16],
    dialed_port: u16,
    outbound: bool,
    mut lease: FdLease,
    net: Arc<Net>,
) {
    let _alive = net.alive_token();
    sock::tune(&stream);

    let hs = tokio::time::timeout(
        std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
        handshake(&mut stream, &net),
    )
    .await;
    let Ok(Some((hello, reader, carried))) = hs else {
        if !outbound {
            net.limits.lock().expect("limits").release_inbound(ip);
        } else {
            net.addrs
                .lock()
                .expect("addrs")
                .on_failure(&ip, dialed_port, true);
        }
        drop(lease);
        return;
    };

    if !lease.promote(FdClass::Peer) {
        if !outbound {
            net.limits.lock().expect("limits").release_inbound(ip);
        }
        drop(lease);
        return;
    }

    let port = if outbound { dialed_port } else { hello.listen_port };
    if outbound {
        net.addrs
            .lock()
            .expect("addrs")
            .on_handshake_ok(&ip, dialed_port, hello.services);
    }
    let stat = Arc::new(crate::net::node::PeerStat::default());
    let id = net.new_id();
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<Vec<u8>>(OUTBOX_ITEMS);
    let (bulk_tx, bulk_rx) = mpsc::channel::<Vec<u8>>(OUTBOX_ITEMS);
    let (kill_tx, kill_rx) = watch::channel(false);
    let outbox_bytes = Arc::new(AtomicU64::new(0));

    let inbox = Arc::new(Semaphore::new(INBOX_BYTES as usize));

    net.peers.lock().expect("peers").insert(
        id,
        Wire {
            ip,
            port,
            user_agent: String::from_utf8_lossy(&hello.user_agent).into_owned(),
            services: hello.services,
            since: net.clock.mono(),
            stat: Arc::clone(&stat),
            outbound,
            control: ctrl_tx,
            bulk: bulk_tx,
            outbox_bytes: Arc::clone(&outbox_bytes),
            kill: kill_tx.clone(),
        },
    );
    if outbound {
        net.outbound.fetch_add(1, Ordering::Relaxed);
    } else {
        net.inbound.fetch_add(1, Ordering::Relaxed);
    }

    let _ = net
        .to_engine
        .send(ToEngine::Event(
            Event::PeerReady {
                peer: id,
                ip,
                outbound,
                height: hello.height,
                work: hello.cum_work,
                tip: hello.tip_hash,
                services: hello.services,
            },
            Credit::default(),
        ))
        .await;

    if outbound {
        net.enqueue(id, &Msg::GetAddr, Tier::Control);
    } else {
        net.note_peer_address(&ip, hello.listen_port, hello.services);
    }

    let (rh, wh) = stream.into_split();
    let outbox_bytes_w = Arc::clone(&outbox_bytes);
    let net_w = Arc::clone(&net);
    let stat_w = Arc::clone(&stat);
    let ctx = Ctx {
        net: Arc::clone(&net),
        id,
        inbox: Arc::clone(&inbox),
        kill: kill_rx.clone(),
        stat: Arc::clone(&stat),
        ip,
        getaddrs_in: AtomicU32::new(0),
        getaddr_sent: AtomicBool::new(outbound),
        addr_recs_in: AtomicUsize::new(0),
        getcheckpoints_in: AtomicU32::new(0),
    };

    let quiet_from = net.clock.mono();
    let quiet_wall = std::time::Instant::now();
    let mut quiet_kill = kill_rx.clone();
    let writer = tokio::spawn(async move {
        loop {
            if net_w.clock.mono().since(quiet_from) >= HANDSHAKE_QUIET_MS
                || quiet_wall.elapsed().as_millis() as u64 >= HANDSHAKE_QUIET_MS
            {
                break;
            }
            tokio::select! {
                _ = quiet_kill.changed() => return,

                _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}
            }
        }
        write_loop(wh, ctrl_rx, bulk_rx, outbox_bytes_w, net_w, kill_rx, stat_w).await
    });
    read_loop(rh, reader, carried, ctx).await;

    let _ = kill_tx.send(true);
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(SHUTDOWN_DRAIN_MS),
        writer,
    )
    .await;
    net.peers.lock().expect("peers").remove(&id);
    if outbound {
        net.outbound.fetch_sub(1, Ordering::Relaxed);
    } else {
        net.inbound.fetch_sub(1, Ordering::Relaxed);
        net.limits.lock().expect("limits").release_inbound(ip);
    }
    net.outbox_pool
        .fetch_sub(outbox_bytes.load(Ordering::Relaxed), Ordering::Relaxed);
    let _ = net
        .to_engine
        .send(ToEngine::Event(
            Event::PeerGone { peer: id },
            Credit::default(),
        ))
        .await;
    drop(lease);
}

#[allow(clippy::type_complexity)]
async fn handshake(
    stream: &mut TcpStream,
    net: &Arc<Net>,
) -> Option<(Hello, FrameReader, Vec<(Cmd, Vec<u8>)>)> {
    let tip = net.tip.tip();
    let ours = Msg::Hello(Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: net.cfg.chain_id,
        services: net.cfg.services,
        nonce: net.nonce,
        time: net.clock.now_unix(),
        height: tip.height,
        tip_hash: tip.hash,
        cum_work: tip.cum_work,
        listen_port: net.cfg.port,
        user_agent: net.cfg.user_agent.clone(),
    });
    let bytes = crate::wire::frame::encode_frame(
        &net.cfg.magic,
        ours.cmd(),
        &crate::wire::codec::encode(&ours),
    );
    stream.write_all(&bytes).await.ok()?;

    let check = HelloCheck {
        chain_id: net.cfg.chain_id,
        our_nonce: net.nonce,
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        now_unix: net.clock.now_unix(),
    };
    let mut reader = FrameReader::new(net.cfg.magic);
    let mut buf = vec![0u8; 1024];
    let mut read_total = 0usize;
    let cap = 2 * (FRAME_HEADER_BYTES + CAP_HELLO) + FRAME_HEADER_BYTES;
    let mut theirs: Option<Hello> = None;
    let mut acked = false;

    let mut carried: Vec<(Cmd, Vec<u8>)> = Vec::new();
    loop {
        if let (Some(h), true) = (theirs.as_ref(), acked) {
            return Some((h.clone(), reader, carried));
        }
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        read_total += n;
        if read_total > cap {
            return None;
        }
        for (cmd, payload) in reader.push(&buf[..n]).ok()? {
            if theirs.is_some() && acked {
                carried.push((cmd, payload));
                continue;
            }
            match decode(cmd, &payload).ok()? {
                Msg::Hello(h) => {
                    if check.judge(&h) != HandshakeOutcome::Accept {
                        return None;
                    }
                    let ack = crate::wire::frame::encode_frame(&net.cfg.magic, Cmd::HelloAck, &[]);
                    stream.write_all(&ack).await.ok()?;
                    theirs = Some(h);
                }
                Msg::HelloAck => acked = true,
                _ => return None,
            }
        }
    }
}

fn merge_in(held: &mut Option<OwnedSemaphorePermit>, add: OwnedSemaphorePermit) {
    match held {
        Some(p) => p.merge(add),
        None => *held = Some(add),
    }
}

fn split_off(held: &mut Option<OwnedSemaphorePermit>, n: usize) -> Option<OwnedSemaphorePermit> {
    let have = held.as_ref()?.num_permits();
    let take = n.min(have);
    if take == 0 {
        return None;
    }
    if take == have {
        return held.take();
    }
    held.as_mut()?.split(take)
}

async fn credit_for(
    sem: &Arc<Semaphore>,
    n: usize,
    cause: PauseCause,
    ctx: &Ctx,
    kill: &mut watch::Receiver<bool>,
) -> Option<OwnedSemaphorePermit> {
    let want = n as u32;
    if let Ok(p) = Arc::clone(sem).try_acquire_many_owned(want) {
        return Some(p);
    }
    let _ = ctx
        .net
        .to_engine
        .send(ToEngine::Event(
            Event::Paused {
                peer: ctx.id,
                cause,
            },
            Credit::default(),
        ))
        .await;
    let p = tokio::select! {
        _ = kill.changed() => return None,
        p = Arc::clone(sem).acquire_many_owned(want) => p.ok()?,
    };
    let _ = ctx
        .net
        .to_engine
        .send(ToEngine::Event(
            Event::Unpaused { peer: ctx.id },
            Credit::default(),
        ))
        .await;
    Some(p)
}

async fn read_loop(
    mut half: OwnedReadHalf,
    mut reader: FrameReader,
    carried: Vec<(Cmd, Vec<u8>)>,
    ctx: Ctx,
) {
    let mut kill = ctx.kill.clone();

    for (cmd, payload) in carried {
        if !on_frame(&ctx, cmd, payload, Credit::default()).await {
            return;
        }
    }
    let mut arena = ReadArena::new();
    let mut peer_rate = TokenBucket::new(
        READ_PEER_BYTES_PER_SEC,
        READ_PEER_BYTES_PER_SEC,
        ctx.net.clock.mono(),
    );
    let mut held_peer: Option<OwnedSemaphorePermit> = None;
    let mut held_pool: Option<OwnedSemaphorePermit> = None;

    loop {
        let mut buf = arena.take(READ_CHUNK);
        let n = tokio::select! {
            _ = kill.changed() => break,
            r = half.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
        };
        ctx.stat.bytes_recv.fetch_add(n as u64, Ordering::Relaxed);

        loop {
            let now = ctx.net.clock.mono();
            if peer_rate.take(n as u64, now) {
                break;
            }
            let level = peer_rate.level(now);
            let wait = (n as u64).saturating_sub(level) * 1000 / READ_PEER_BYTES_PER_SEC + 1;
            tokio::select! {
                _ = kill.changed() => return,
                _ = tokio::time::sleep(std::time::Duration::from_millis(wait.min(1000))) => {}
            }
        }

        match credit_for(&ctx.inbox, n, PauseCause::LocalInbox, &ctx, &mut kill).await {
            Some(p) => merge_in(&mut held_peer, p),
            None => break,
        }
        if !ctx.net.is_sync_peer(ctx.id) {
            let pool = Arc::clone(&ctx.net.inbox_pool);
            match credit_for(&pool, n, PauseCause::IngestBudget, &ctx, &mut kill).await {
                Some(p) => merge_in(&mut held_pool, p),
                None => break,
            }
        }

        let frames = match reader.push(&buf[..n]) {
            Ok(f) => f,
            Err(e) => {
                wire_fault(&ctx, e);
                break;
            }
        };
        arena.give(buf);

        let mut fatal = false;
        for (cmd, payload) in frames {
            let consumed = FRAME_HEADER_BYTES + payload.len();
            let credit = Credit {
                peer: split_off(&mut held_peer, consumed),
                pool: split_off(&mut held_pool, consumed),
            };
            if !on_frame(&ctx, cmd, payload, credit).await {
                fatal = true;
                break;
            }
        }
        if fatal {
            break;
        }
    }
}

fn wire_fault(ctx: &Ctx, e: WireError) {
    if !e.is_silent_drop() {
        ban_peer(ctx, BAN_PROTOCOL_MS);
    }
}

fn ban_peer(ctx: &Ctx, ms: u64) {
    let ip = ctx
        .net
        .peers
        .lock()
        .expect("peers")
        .get(&ctx.id)
        .map(|w| w.ip);
    if let Some(ip) = ip {
        let now = ctx.net.clock.mono();
        ctx.net.bans.lock().expect("bans").ban(ip, ms, now);
    }
}

async fn on_frame(ctx: &Ctx, cmd: Cmd, payload: Vec<u8>, credit: Credit) -> bool {
    if !cmd.carries_headers() {
        let wait = ctx.net.charge_read_global((FRAME_HEADER_BYTES + payload.len()) as u64);
        if wait > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(wait.min(1000))).await;
        }
    }
    let msg = match decode(cmd, &payload) {
        Ok(m) => m,
        Err(e) => {
            wire_fault(ctx, e);
            return false;
        }
    };
    match msg {
        Msg::Ping(n) => {
            ctx.net.enqueue(ctx.id, &Msg::Pong(n), Tier::Control);
        }
        Msg::Pong(_) => {}
        Msg::GetAddr => {
            let n = ctx.getaddrs_in.fetch_add(1, Ordering::Relaxed) + 1;
            if n > GETADDR_PER_CONN {
                ctx.net.getaddr_repeats.fetch_add(1, Ordering::Relaxed);

                if n > GETADDR_PER_CONN + GETADDR_ABUSE_MAX {
                    ban_peer(ctx, BAN_TIME_MS);
                    return false;
                }
                return true;
            }
            for m in ctx.net.addr_sample() {
                ctx.net.enqueue(ctx.id, &m, Tier::Control);
            }
            ctx.net.getaddr_answered.fetch_add(1, Ordering::Relaxed);
        }
        Msg::Addr(recs) => {
            let solicited = ctx.getaddr_sent.swap(false, Ordering::Relaxed);
            let limit = if solicited {
                ADDR_MSG_MAX
            } else {
                ADDR_UNSOLICITED_MAX
            };

            let used = ctx.addr_recs_in.load(Ordering::Relaxed);
            let room = ADDR_RECS_PER_CONN.saturating_sub(used);
            let take = limit.min(room);
            if take > 0 {
                ctx.addr_recs_in
                    .store(used + take.min(recs.len()), Ordering::Relaxed);
                ctx.net.ingest_addrs(&recs, &ctx.ip, take);
            }
        }
        Msg::FeeFilter(_) | Msg::Mempool => {}
        Msg::Tx(bytes) => {
            let Some(txid) = tx_ident(&bytes) else {
                return false;
            };
            return send_event(
                ctx,
                Event::Tx {
                    peer: ctx.id,
                    txid,
                    bytes,
                },
                credit,
            )
            .await;
        }

        Msg::Hello(_) | Msg::HelloAck => return false,

        Msg::GetHeaders { locator, stop } => {
            let net = Arc::clone(&ctx.net);
            let id = ctx.id;
            let ok = ctx.net.serve.submit(ServeJob::Headers {
                locator,
                stop,
                reply: Box::new(move |m| {
                    net.enqueue(id, &m, Tier::Bulk);
                }),
            });

            let _ = ok;
        }
        Msg::GetData(items) => {
            for it in items.into_iter().take(INV_MAX) {
                let net = Arc::clone(&ctx.net);
                let id = ctx.id;
                let hash = it.hash;

                let job = match it.kind {
                    InvKind::Block => ServeJob::Body {
                        hash,
                        reply: Box::new(move |m| {
                            net.enqueue(id, &m, Tier::Bulk);
                        }),
                    },
                    InvKind::Tx => ServeJob::Tx {
                        txid: hash,
                        reply: Box::new(move |m| {
                            net.enqueue(id, &m, Tier::Bulk);
                        }),
                    },
                };
                if !ctx.net.serve.submit(job) {
                    ctx.net
                        .enqueue(ctx.id, &Msg::NotFound(vec![it]), Tier::Control);
                }
            }
        }

        Msg::Headers(raw) => {
            return send_event(
                ctx,
                Event::Headers {
                    peer: ctx.id,
                    raw,
                },
                credit,
            )
            .await
        }
        Msg::Block(bytes) => {
            let Some((hash, height)) = block_ident(&bytes) else {
                return false;
            };
            return send_event(
                ctx,
                Event::Body {
                    peer: ctx.id,
                    hash,
                    height,
                    bytes,
                },
                credit,
            )
            .await;
        }
        Msg::NotFound(items) => {
            for it in items {
                let ev = match it.kind {
                    InvKind::Block => Event::NotFound {
                        peer: ctx.id,
                        hash: it.hash,
                    },
                    InvKind::Tx => Event::NotFoundTx {
                        peer: ctx.id,
                        txid: it.hash,
                    },
                };
                if !send_event(ctx, ev, Credit::default()).await {
                    return false;
                }
            }
        }

        Msg::Inv(items) => {
            let blocks: Vec<[u8; 32]> = items
                .iter()
                .filter(|i| i.kind == InvKind::Block)
                .take(INV_BLOCKS_PER_MSG_MAX)
                .map(|i| i.hash)
                .collect();

            let txids: Vec<[u8; 32]> = items
                .iter()
                .filter(|i| i.kind == InvKind::Tx)
                .take(INV_TXS_PER_MSG_MAX)
                .map(|i| i.hash)
                .collect();
            if !txids.is_empty()
                && !send_event(
                    ctx,
                    Event::AnnouncedTx {
                        peer: ctx.id,
                        txids,
                    },
                    Credit::default(),
                )
                .await
            {
                return false;
            }
            if blocks.is_empty() {
                return true;
            }
            return send_event(
                ctx,
                Event::Announced {
                    peer: ctx.id,
                    blocks,
                },
                credit,
            )
            .await;
        }

        Msg::Checkpoint(c) => {
            let keys = &ctx.net.cfg.authority_keys;
            let sigs: Vec<crate::traits::CheckpointSig> = c
                .sigs
                .iter()
                .filter_map(|(id, sig)| {
                    keys.get(*id as usize).map(|pk| crate::traits::CheckpointSig {
                        pubkey: *pk,
                        sig: *sig,
                    })
                })
                .collect();
            return send_event(
                ctx,
                Event::Checkpoint {
                    peer: ctx.id,
                    cp: crate::traits::SignedCheckpoint {
                        height: c.height,
                        hash: c.hash,
                        sigs,
                    },
                },
                credit,
            )
            .await;
        }
        Msg::GetCheckpoint => {
            let n = ctx.getcheckpoints_in.fetch_add(1, Ordering::Relaxed) + 1;
            if n > GETCHECKPOINT_PER_CONN {
                if n > GETCHECKPOINT_PER_CONN + GETCHECKPOINT_ABUSE_MAX {
                    ban_peer(ctx, BAN_TIME_MS);
                    return false;
                }

                return true;
            }
            let net = Arc::clone(&ctx.net);
            let id = ctx.id;
            let keys = ctx.net.cfg.authority_keys.clone();

            let _ = ctx.net.serve.submit(ServeJob::Checkpoint {
                keys,
                reply: Box::new(move |m| {
                    net.enqueue(id, &m, Tier::Control);
                }),
            });
        }
    }
    true
}

async fn send_event(ctx: &Ctx, ev: Event, credit: Credit) -> bool {
    ctx.net
        .to_engine
        .send(ToEngine::Event(ev, credit))
        .await
        .is_ok()
}

#[allow(clippy::too_many_arguments)]
async fn write_loop(
    mut half: OwnedWriteHalf,
    mut control: mpsc::Receiver<Vec<u8>>,
    mut bulk: mpsc::Receiver<Vec<u8>>,
    outbox_bytes: Arc<AtomicU64>,
    net: Arc<Net>,
    mut kill: watch::Receiver<bool>,
    stat: Arc<crate::net::node::PeerStat>,
) {
    let mut ping_nonce: u64 = 1;
    loop {
        let frame = tokio::select! {
            biased;
            _ = kill.changed() => break,
            Some(b) = control.recv() => b,
            Some(b) = bulk.recv() => b,
            _ = tokio::time::sleep(std::time::Duration::from_millis(PING_INTERVAL_MS)) => {
                ping_nonce = ping_nonce.wrapping_add(1);
                crate::wire::frame::encode_frame(
                    &net.cfg.magic,
                    Cmd::Ping,
                    &crate::wire::codec::encode(&Msg::Ping(ping_nonce)),
                )
            }
            else => break,
        };
        let n = frame.len() as u64;

        let r = tokio::time::timeout(
            std::time::Duration::from_millis(WRITE_STALL_MS),
            half.write_all(&frame),
        )
        .await;
        outbox_bytes.fetch_sub(n.min(outbox_bytes.load(Ordering::Relaxed)), Ordering::Relaxed);
        net.outbox_pool
            .fetch_sub(n.min(net.outbox_pool.load(Ordering::Relaxed)), Ordering::Relaxed);
        if !matches!(r, Ok(Ok(()))) {
            break;
        }
        stat.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }
    let _ = half.shutdown().await;
}
