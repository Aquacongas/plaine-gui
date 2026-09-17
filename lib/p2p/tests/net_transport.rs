use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::*;
use plaine_p2p::engine::fd::{FdBudget, FdClass};
use plaine_p2p::mock::{MockBits, MockChain, MockClock, MockPow};
use plaine_p2p::net::{NetNode, NetOptions, TickMode};
use plaine_p2p::peer::Offence;
use plaine_p2p::sync::{Action, SyncEngine};
use plaine_p2p::traits::{ChainView, Clock, PeerId};
use plaine_p2p::wire::codec::{decode, encode};
use plaine_p2p::wire::frame::{encode_frame, FrameReader};
use plaine_p2p::wire::msg::{Hello, Msg};
use plaine_p2p::wire::Cmd;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

type Engine = SyncEngine<MockChain, MockChain, MockPow, MockBits>;

struct Node {
    node: NetNode<Engine>,
    chain: Arc<MockChain>,
    clock: Arc<MockClock>,
    fd: Arc<FdBudget>,
}

const BASE_TIME: u64 = 1_800_000_000;

fn node_with(blocks: u64, unix: u64) -> Node {
    node_with_keys(blocks, unix, Vec::new())
}

fn node_with_keys(blocks: u64, unix: u64, keys: Vec<[u8; 32]>) -> Node {
    let chain = Arc::new(MockChain::linear(blocks, BASE_TIME, 1));
    let pow = Arc::new(MockPow::all_valid());
    let bits = Arc::new(MockBits);
    let clock = Arc::new(MockClock::new(unix));
    let mut cfg = P2pConfig::isolated();
    cfg.authority_keys = keys;
    let engine = SyncEngine::new(
        Arc::clone(&chain),
        Arc::clone(&chain),
        pow,
        bits,
        cfg.clone(),
        0xC0FFEE,
        clock.mono(),
    );
    let node = NetNode::start(
        engine,
        Arc::clone(&chain),
        cfg,
        Arc::clone(&clock) as Arc<dyn Clock>,
        NetOptions {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            ticks: TickMode::Manual,
            workers: 2,
        },
    )
    .expect("start node");
    let fd = Arc::clone(node.fd());
    Node {
        node,
        chain,
        clock,
        fd,
    }
}

fn seed_real_bodies(chain: &MockChain) {
    for h in chain.headers() {
        let mut b = h.raw.to_vec();
        b.extend_from_slice(&0u32.to_le_bytes());
        let _ = plaine_p2p::traits::BlockSink::submit_block(chain, h.hash, b);
    }
}

impl Node {
    fn step(&self, ms: u64) {
        self.clock.advance(ms);
        self.node.tick();
    }
}

fn step_all(nodes: &[&Node], ms: u64, real_ms: u64) {
    for n in nodes {
        n.step(ms);
    }
    std::thread::sleep(Duration::from_millis(real_ms));
}

struct Raw {
    s: TcpStream,
    r: FrameReader,
    pending: std::collections::VecDeque<Msg>,
}

impl Raw {
    fn connect(addr: SocketAddr) -> std::io::Result<Raw> {
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        s.set_read_timeout(Some(Duration::from_millis(400)))?;
        s.set_nodelay(true)?;
        Ok(Raw {
            s,
            r: FrameReader::new(MAGIC_MAIN),
            pending: std::collections::VecDeque::new(),
        })
    }

    fn hello(height: u64, nonce: u64) -> Msg {
        Msg::Hello(Hello {
            proto_ver: PROTO_VER,
            min_proto: MIN_PROTO,
            chain_id: CHAIN_ID,
            services: SERVICE_FULL_RELAY,
            nonce,
            time: BASE_TIME,
            height,
            tip_hash: [7u8; 32],
            cum_work: [0u8; 32],
            listen_port: 0,
            user_agent: b"raw/1".to_vec(),
        })
    }

    fn send(&mut self, m: &Msg) -> std::io::Result<()> {
        let b = encode_frame(&MAGIC_MAIN, m.cmd(), &encode(m));
        self.s.write_all(&b)
    }

    fn send_one_byte_at_a_time(&mut self, m: &Msg) -> std::io::Result<()> {
        let b = encode_frame(&MAGIC_MAIN, m.cmd(), &encode(m));
        for i in 0..b.len() {
            self.s.write_all(&b[i..i + 1])?;
            self.s.flush()?;
            std::thread::sleep(Duration::from_micros(50));
        }
        Ok(())
    }

    fn wait_for<F: Fn(&Msg) -> bool>(&mut self, want: F, ms: u64) -> Option<Msg> {
        let deadline = Instant::now() + Duration::from_millis(ms);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if let Some(i) = self.pending.iter().position(&want) {
                return self.pending.remove(i);
            }
            if Instant::now() >= deadline {
                return None;
            }
            match self.s.read(&mut buf) {
                Ok(0) => return None,
                Ok(n) => {
                    for (cmd, payload) in self.r.push(&buf[..n]).ok()? {
                        if let Ok(m) = decode(cmd, &payload) {
                            self.pending.push_back(m);
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    fn handshake(&mut self, height: u64, nonce: u64) -> bool {
        if self.send(&Raw::hello(height, nonce)).is_err() {
            return false;
        }
        if self
            .wait_for(|m| matches!(m, Msg::Hello(_)), 2_000)
            .is_none()
        {
            return false;
        }
        if self.send(&Msg::HelloAck).is_err() {
            return false;
        }
        self.wait_for(|m| matches!(m, Msg::HelloAck), 2_000)
            .is_some()
    }
}

#[test]
fn two_nodes_sync_to_same_tip() {
    let unix = BASE_TIME + 200 * 60;
    let a = node_with(201, unix);
    let b = node_with(1, unix);
    seed_real_bodies(&a.chain);
    assert_eq!(a.chain.tip().height, 200);
    assert_eq!(b.chain.tip().height, 0);

    assert_eq!(
        a.chain.header_at(0).unwrap().hash,
        b.chain.header_at(0).unwrap().hash
    );

    b.node.dial(a.node.local_addr());

    let mut converged = false;
    for _ in 0..400 {
        step_all(&[&a, &b], 250, 5);
        if b.chain.tip().height == 200 {
            converged = true;
            break;
        }
    }
    assert!(
        converged,
        "B reached height {} of A's 200 over real TCP; conditions: {:?}",
        b.chain.tip().height,
        b.node.conditions()
    );
    assert_eq!(
        a.chain.tip().hash,
        b.chain.tip().hash,
        "same height, different tip - the headers that crossed the socket were \
         not the headers A holds"
    );

    assert_eq!(a.node.peer_count(), 1);
    assert_eq!(b.node.peer_count(), 1);

    let fda = Arc::clone(&a.fd);
    let fdb = Arc::clone(&b.fd);
    a.node.shutdown();
    b.node.shutdown();
    assert_eq!(fda.total_open(), 0, "A leaked descriptors");
    assert_eq!(fdb.total_open(), 0, "B leaked descriptors");
}

#[test]
fn byte_at_a_time_still_decodes() {
    let unix = BASE_TIME + 200 * 60;
    let a = node_with(201, unix);
    let mut raw = Raw::connect(a.node.local_addr()).expect("connect");

    raw.send_one_byte_at_a_time(&Raw::hello(0, 0xABCD))
        .expect("hello");
    assert!(
        raw.wait_for(|m| matches!(m, Msg::Hello(_)), 3_000)
            .is_some(),
        "no HELLO came back from a peer that trickled its own"
    );
    raw.send_one_byte_at_a_time(&Msg::HelloAck).expect("ack");
    assert!(
        raw.wait_for(|m| matches!(m, Msg::HelloAck), 3_000)
            .is_some(),
        "no HELLO_ACK"
    );

    raw.send_one_byte_at_a_time(&Msg::Ping(0x5A5A_5A5A))
        .expect("ping");
    let pong = raw.wait_for(|m| matches!(m, Msg::Pong(_)), 3_000);
    assert_eq!(pong, Some(Msg::Pong(0x5A5A_5A5A)));

    let loc = vec![a.chain.header_at(0).unwrap().hash];
    raw.send_one_byte_at_a_time(&Msg::GetHeaders {
        locator: loc,
        stop: [0u8; 32],
    })
    .expect("getheaders");
    let mut got = None;
    for _ in 0..40 {
        a.step(250);
        if let Some(m) = raw.wait_for(|m| matches!(m, Msg::Headers(_)), 200) {
            got = Some(m);
            break;
        }
    }
    match got {
        Some(Msg::Headers(v)) => {
            assert_eq!(v.len(), 200, "wrong header count over a trickled request");
            assert_eq!(v[0], a.chain.header_at(1).unwrap().raw);
        }
        other => panic!("expected HEADERS, got {other:?}"),
    }
    a.node.shutdown();
}

#[test]
fn connection_cap_holds() {
    let unix = BASE_TIME + 200 * 60;
    let a = node_with(201, unix);
    let addr = a.node.local_addr();

    let mut honest = Raw::connect(addr).expect("connect honest");
    assert!(honest.handshake(0, 0x1111), "honest handshake failed");

    let mut held: Vec<TcpStream> = Vec::new();
    let mut peak_fd = 0u64;
    for i in 0..200 {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            held.push(s);
        }
        if i % 20 == 0 {
            a.step(50);
            std::thread::sleep(Duration::from_millis(2));
        }
        peak_fd = peak_fd.max(a.fd.total_open());
    }
    a.step(250);
    std::thread::sleep(Duration::from_millis(50));
    peak_fd = peak_fd.max(a.fd.total_open());

    assert!(
        peak_fd <= FD_PEERS + FD_INBOUND_HANDSHAKE + FD_LISTENERS,
        "the descriptor ledger reached {peak_fd}, above its own budget rows"
    );
    assert!(
        a.node.peer_count() <= INBOUND_PER_IP,
        "{} peers established from one IP, above INBOUND_PER_IP = {}",
        a.node.peer_count(),
        INBOUND_PER_IP
    );

    honest.send(&Msg::Ping(0x99)).expect("ping under load");
    assert_eq!(
        honest.wait_for(|m| matches!(m, Msg::Pong(_)), 3_000),
        Some(Msg::Pong(0x99)),
        "the node stopped answering PING at the cap"
    );
    honest
        .send(&Msg::GetHeaders {
            locator: vec![a.chain.header_at(0).unwrap().hash],
            stop: [0u8; 32],
        })
        .expect("getheaders under load");
    let mut served = false;
    for _ in 0..40 {
        a.step(250);
        if honest
            .wait_for(|m| matches!(m, Msg::Headers(_)), 200)
            .is_some()
        {
            served = true;
            break;
        }
    }
    assert!(served, "the node stopped serving at the cap");

    drop(held);
    let fd = Arc::clone(&a.fd);
    a.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn slowloris_spares_descriptors() {
    let unix = BASE_TIME + 60;
    let a = node_with(2, unix);
    let addr = a.node.local_addr();

    let mut silent: Vec<TcpStream> = Vec::new();
    let mut peak_handshake = 0u64;
    for i in 0..200 {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            silent.push(s);
        }
        peak_handshake = peak_handshake.max(a.fd.open(FdClass::InboundHandshake));
        if i % 25 == 0 {
            a.step(50);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    a.step(250);
    std::thread::sleep(Duration::from_millis(50));
    peak_handshake = peak_handshake.max(a.fd.open(FdClass::InboundHandshake));

    assert!(
        peak_handshake <= FD_INBOUND_HANDSHAKE,
        "{peak_handshake} half-open inbound sockets against a row of {FD_INBOUND_HANDSHAKE}"
    );
    assert!(
        peak_handshake <= INBOUND_PER_IP as u64,
        "the per-IP filter did not absorb a single-source slowloris: {peak_handshake} \
         descriptors held, above INBOUND_PER_IP = {INBOUND_PER_IP}. That filter runs \
         only because accept() is called before the lease is taken."
    );
    assert_eq!(
        a.node.peer_count(),
        0,
        "a peer that never sent a byte became a peer"
    );

    drop(silent);
    a.step(250);
    std::thread::sleep(Duration::from_millis(80));
    let mut honest = Raw::connect(addr).expect("connect after the flood");
    assert!(
        honest.handshake(0, 0x2222),
        "the node stopped handshaking after a slowloris flood"
    );

    let fd = Arc::clone(&a.fd);
    a.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn descriptor_row_is_a_bound() {
    let fd = FdBudget::new();
    let mut leases = Vec::new();
    for _ in 0..FD_INBOUND_HANDSHAKE {
        leases.push(
            fd.acquire(FdClass::InboundHandshake)
                .expect("under the cap"),
        );
    }
    assert!(fd.acquire(FdClass::InboundHandshake).is_none());
    assert_eq!(fd.open(FdClass::InboundHandshake), FD_INBOUND_HANDSHAKE);

    let mut one = leases.pop().expect("a lease");
    assert!(one.promote(FdClass::Peer));
    assert_eq!(one.class(), FdClass::Peer);
    assert_eq!(fd.open(FdClass::Peer), 1);
    assert_eq!(fd.open(FdClass::InboundHandshake), FD_INBOUND_HANDSHAKE - 1);
    drop(one);
    drop(leases);
    assert_eq!(fd.total_open(), 0, "Drop did not return the descriptors");
}

#[test]
fn paused_peer_not_dead() {
    let unix = BASE_TIME + 200 * 60;
    let a = node_with(201, unix);
    let b = node_with(1, unix);
    seed_real_bodies(&a.chain);

    b.chain.freeze_sink(true);
    b.node.dial(a.node.local_addr());

    let mut stalled = false;
    for _ in 0..400 {
        step_all(&[&a, &b], 250, 2);
        if b.node.peer_count() == 1 && !b.node.conditions().is_empty() {
            stalled = true;
            break;
        }
    }
    assert!(
        stalled,
        "nothing stalled, so nothing is being paused: peers={} cond={:?}",
        b.node.peer_count(),
        b.node.conditions()
    );

    for _ in 0..960 {
        step_all(&[&a, &b], 250, 0);
    }

    assert_eq!(
        b.node.peer_count(),
        1,
        "the socket died while we were the ones not reading"
    );
    let acts = b.node.actions();
    assert!(
        !acts.iter().any(|x| matches!(x, Action::Disconnect { .. })),
        "the peer was disconnected for our own backpressure: {:?}",
        acts.iter()
            .filter(|x| matches!(x, Action::Disconnect { .. }))
            .collect::<Vec<_>>()
    );
    assert!(
        !acts.iter().any(|x| matches!(x, Action::Ban { .. })),
        "the peer was banned for our own frozen validate queue"
    );

    for x in &acts {
        if let Action::Score { offence, .. } = x {
            assert!(
                !matches!(
                    offence,
                    Offence::PeerOverran
                        | Offence::Malformed
                        | Offence::BadPow
                        | Offence::UnsolicitedHeaders
                        | Offence::DisconnectedBatches
                ),
                "our own stall was charged to the peer as {offence:?}"
            );
        }
    }

    assert!(
        b.node.conditions().iter().any(|c| matches!(
            c,
            plaine_p2p::traits::Condition::QueueOverflow {
                queue: "validate",
                policy: plaine_p2p::traits::Policy::PauseReads,
            }
        )),
        "a local commit stall produced no named condition: {:?}",
        b.node.conditions()
    );

    b.chain.freeze_sink(false);
    let mut recovered = false;
    for _ in 0..800 {
        step_all(&[&a, &b], 250, 2);
        if b.chain.tip().height == 200 {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "sync did not resume after the stall cleared; reached {}",
        b.chain.tip().height
    );

    let fda = Arc::clone(&a.fd);
    let fdb = Arc::clone(&b.fd);
    a.node.shutdown();
    let engine = b.node.shutdown();

    let now = b.clock.mono();
    for (id, s) in engine.peers() {
        assert!(
            s.score.value(now) < 20,
            "peer {:?} carries {} points for our stall, heading for a ban",
            id,
            s.score.value(now)
        );
        assert!(
            !s.score.sync_disqualified(),
            "peer {:?} was sync-disqualified for our stall",
            id
        );
        let _ = PeerId(id.0);
    }
    assert_eq!(fda.total_open(), 0);
    assert_eq!(fdb.total_open(), 0);
}

#[test]
fn frame_reader_bounds_memory() {
    let mut r = FrameReader::new(MAGIC_MAIN);
    let block = encode_frame(&MAGIC_MAIN, Cmd::Block, &vec![0u8; CAP_BLOCK]);
    let mut bytes = block.clone();
    bytes.push(MAGIC_MAIN[0]);
    let out = r.push(&bytes).expect("a legal block");
    assert_eq!(out.len(), 1);
    assert_eq!(r.buffered(), 1, "the partial header should still be held");
    assert!(
        r.retained() <= ARENA_MAX,
        "the reader is retaining {} bytes after one 1 MiB BLOCK plus one byte, \
         above ARENA_MAX = {} - 128 peers would pin {} MiB",
        r.retained(),
        ARENA_MAX,
        r.retained() * MAX_PEERS / (1024 * 1024)
    );

    let mut rest = block[1..].to_vec();
    rest.extend_from_slice(&encode_frame(&MAGIC_MAIN, Cmd::Ping, &7u64.to_le_bytes()));
    let out = r.push(&rest).expect("still framing");
    assert_eq!(out.len(), 2);
    assert!(r.retained() <= ARENA_MAX);
}

#[test]
fn two_nodes_propagate_over_tcp() {
    let unix = BASE_TIME + 10 * 60;
    let a = node_with(1, unix);
    let b = node_with(1, unix);

    a.chain.applied_tip(true);
    b.chain.applied_tip(true);
    b.node.dial(a.node.local_addr());

    for _ in 0..40 {
        step_all(&[&a, &b], 250, 5);
    }
    assert_eq!(a.node.peer_count(), 1, "the pair never handshook");
    assert_eq!(b.chain.tip().height, 0);
    assert_eq!(a.chain.tip().height, 0);

    let genesis = a.chain.header_at(0).expect("genesis").hash;
    let grown = plaine_p2p::mock::build_chain(1, 10, genesis, BASE_TIME, 1);
    a.chain.extend(&grown, true);
    seed_real_bodies(&a.chain);

    let mut converged = false;
    for _ in 0..400 {
        step_all(&[&a, &b], 250, 5);
        if b.chain.tip().height == 10 {
            converged = true;
            break;
        }
    }
    assert!(
        converged,
        "B reached height {} of A's 10 after the announce (full INV->GETHEADERS->HEADERS->designate path): {:?}",
        b.chain.tip().height,
        b.node.conditions()
    );
    assert_eq!(
        a.chain.tip().hash,
        b.chain.tip().hash,
        "same height, different tip"
    );

    let fda = Arc::clone(&a.fd);
    let fdb = Arc::clone(&b.fd);
    a.node.shutdown();
    b.node.shutdown();
    assert_eq!(fda.total_open(), 0, "A leaked descriptors");
    assert_eq!(fdb.total_open(), 0, "B leaked descriptors");
}

#[test]
fn getcheckpoint_answered_over_socket() {
    let key = [0xA7u8; 32];
    let n = node_with_keys(20, BASE_TIME + 20 * 60, vec![key]);
    let record = plaine_p2p::traits::SignedCheckpoint {
        height: 12,
        hash: [0x5C; 32],
        sigs: vec![plaine_p2p::traits::CheckpointSig {
            pubkey: key,
            sig: [0x9E; 64],
        }],
    };
    n.chain.set_anchor_record(Some(record.clone()));

    let mut c = Raw::connect(n.node.local_addr()).expect("connect");
    assert!(c.handshake(20, 0xAAAA), "handshake");
    c.send(&Msg::GetCheckpoint).expect("send");

    let got = c
        .wait_for(|m| matches!(m, Msg::Checkpoint(_)), 3_000)
        .expect("a GETCHECKPOINT must be answered now that the record exists");
    let Msg::Checkpoint(cp) = got else {
        unreachable!()
    };
    assert_eq!(cp.height, record.height);
    assert_eq!(cp.hash, record.hash);

    assert_eq!(cp.sigs, vec![(0u8, [0x9E; 64])]);
}

#[test]
fn no_record_answers_nothing() {
    let n = node_with(20, BASE_TIME + 20 * 60);
    let mut c = Raw::connect(n.node.local_addr()).expect("connect");
    assert!(c.handshake(20, 0xBBBB), "handshake");
    c.send(&Msg::GetCheckpoint).expect("send");
    assert!(
        c.wait_for(|m| matches!(m, Msg::Checkpoint(_)), 700)
            .is_none(),
        "an unsigned or absent anchor must never reach the wire"
    );

    c.send(&Msg::Ping(77)).expect("send");
    assert!(
        c.wait_for(|m| matches!(m, Msg::Pong(77)), 3_000).is_some(),
        "asking for an anchor we do not have must not cost the connection"
    );
}

#[test]
fn unknown_key_not_served() {
    let n = node_with_keys(20, BASE_TIME + 20 * 60, vec![[0xA7u8; 32]]);
    n.chain
        .set_anchor_record(Some(plaine_p2p::traits::SignedCheckpoint {
            height: 12,
            hash: [0x5C; 32],
            sigs: vec![plaine_p2p::traits::CheckpointSig {
                pubkey: [0x11u8; 32],
                sig: [0x9E; 64],
            }],
        }));
    let mut c = Raw::connect(n.node.local_addr()).expect("connect");
    assert!(c.handshake(20, 0xCCCC), "handshake");
    c.send(&Msg::GetCheckpoint).expect("send");
    assert!(
        c.wait_for(|m| matches!(m, Msg::Checkpoint(_)), 700)
            .is_none(),
        "a frame whose signatures we had to drop is one the asker will refuse after paying"
    );
}

#[test]
fn getcheckpoint_ladder_serves_then_bans() {
    let key = [0xA7u8; 32];
    let n = node_with_keys(20, BASE_TIME + 20 * 60, vec![key]);
    n.chain
        .set_anchor_record(Some(plaine_p2p::traits::SignedCheckpoint {
            height: 12,
            hash: [0x5C; 32],
            sigs: vec![plaine_p2p::traits::CheckpointSig {
                pubkey: key,
                sig: [0x9E; 64],
            }],
        }));
    let mut c = Raw::connect(n.node.local_addr()).expect("connect");
    assert!(c.handshake(20, 0xDDDD), "handshake");

    for i in 0..GETCHECKPOINT_PER_CONN {
        c.send(&Msg::GetCheckpoint).expect("send");
        assert!(
            c.wait_for(|m| matches!(m, Msg::Checkpoint(_)), 3_000)
                .is_some(),
            "request {i} inside the allowance went unanswered"
        );
    }

    c.send(&Msg::GetCheckpoint).expect("send");
    assert!(
        c.wait_for(|m| matches!(m, Msg::Checkpoint(_)), 700)
            .is_none(),
        "the allowance is not enforced: an unlimited answer is the serve cost the limit exists for"
    );
    c.send(&Msg::Ping(9)).expect("send");
    assert!(
        c.wait_for(|m| matches!(m, Msg::Pong(9)), 3_000).is_some(),
        "one over is not a ban"
    );

    for _ in 0..GETCHECKPOINT_ABUSE_MAX + 2 {
        let _ = c.send(&Msg::GetCheckpoint);
    }
    let mut dead = false;
    for _ in 0..40 {
        if c.send(&Msg::Ping(1)).is_err()
            || c.wait_for(|m| matches!(m, Msg::Pong(1)), 100).is_none()
        {
            dead = true;
            break;
        }
    }
    assert!(
        dead,
        "a GETCHECKPOINT flood past the abuse threshold must cost the connection"
    );
}
