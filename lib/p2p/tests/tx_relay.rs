use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::*;
use plaine_p2p::engine::fd::FdBudget;
use plaine_p2p::mock::{MockBits, MockChain, MockClock, MockPow};
use plaine_p2p::net::{NetNode, NetOptions, TickMode};
use plaine_p2p::peer::Offence;
use plaine_p2p::sync::{Action, SyncEngine};
use plaine_p2p::traits::{Clock, Hash32, Mono, PeerId};
use plaine_p2p::wire::codec::{decode, encode};
use plaine_p2p::wire::frame::{encode_frame, FrameReader};
use plaine_p2p::wire::msg::{Hello, InvItem, InvKind, Msg};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

type Engine = SyncEngine<MockChain, MockChain, MockPow, MockBits>;

const BASE_TIME: u64 = 1_800_000_000;

fn a_tx(n: u64) -> (Hash32, Vec<u8>) {
    use plaine_consensus::codec::TransferTx;
    let mut from = [0u8; 32];
    from[..8].copy_from_slice(&n.to_le_bytes());
    from[31] = 1;
    let t = TransferTx {
        from_pub: from,
        to: [7u8; 20],
        amount: 1_000 + n as u128,
        fee: 1_000_000,
        nonce: n,
        sig: [0u8; 64],
    };
    (t.txid(), t.encode().to_vec())
}

struct Node {
    node: NetNode<Engine>,
    chain: Arc<MockChain>,
    clock: Arc<MockClock>,
    fd: Arc<FdBudget>,
    addr: SocketAddr,
}

fn node() -> Node {
    let unix = BASE_TIME + 10 * 60;
    let chain = Arc::new(MockChain::linear(1, BASE_TIME, 1));
    let pow = Arc::new(MockPow::all_valid());
    let bits = Arc::new(MockBits);
    let clock = Arc::new(MockClock::new(unix));
    let cfg = P2pConfig::isolated();
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
    let addr = node.local_addr();
    Node {
        node,
        chain,
        clock,
        fd,
        addr,
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

fn settle(nodes: &[&Node], rounds: usize, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..rounds {
        step_all(nodes, TICK_MS, 4);
        if done() {
            return true;
        }
    }
    false
}

fn fds(nodes: &[&Node]) -> Vec<Arc<FdBudget>> {
    nodes.iter().map(|n| Arc::clone(&n.fd)).collect()
}

fn no_leak(fds: Vec<Arc<FdBudget>>) {
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

struct Raw {
    s: TcpStream,
    r: FrameReader,
    pending: std::collections::VecDeque<Msg>,
}

impl Raw {
    fn connect(addr: SocketAddr) -> std::io::Result<Raw> {
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        s.set_read_timeout(Some(Duration::from_millis(100)))?;
        s.set_nodelay(true)?;
        Ok(Raw {
            s,
            r: FrameReader::new(MAGIC_MAIN),
            pending: std::collections::VecDeque::new(),
        })
    }

    fn send(&mut self, m: &Msg) -> std::io::Result<()> {
        let b = encode_frame(&MAGIC_MAIN, m.cmd(), &encode(m));
        self.s.write_all(&b)
    }

    fn wait_for<F: Fn(&Msg) -> bool>(&mut self, want: F, ms: u64) -> Option<Msg> {
        let deadline = Instant::now() + Duration::from_millis(ms);
        let mut buf = vec![0u8; 256 * 1024];
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

    fn handshake(&mut self, nonce: u64) -> bool {
        let ours = Msg::Hello(Hello {
            proto_ver: PROTO_VER,
            min_proto: MIN_PROTO,
            chain_id: CHAIN_ID,
            services: SERVICE_FULL_RELAY,
            nonce,
            time: BASE_TIME,
            height: 0,
            tip_hash: [0u8; 32],
            cum_work: [0u8; 32],
            listen_port: 0,
            user_agent: b"raw/1".to_vec(),
        });
        if self.send(&ours).is_err() {
            return false;
        }
        if self
            .wait_for(|m| matches!(m, Msg::Hello(_)), 10_000)
            .is_none()
        {
            return false;
        }
        if self.send(&Msg::HelloAck).is_err() {
            return false;
        }
        self.wait_for(|m| matches!(m, Msg::HelloAck), 10_000)
            .is_some()
    }
}

#[test]
fn tx_reaches_peer_mempool() {
    let a = node();
    let b = node();
    let (txid, bytes) = a_tx(1);
    a.chain.add_local_tx(txid, bytes);
    b.node.dial(a.addr);

    let all: Vec<&Node> = vec![&a, &b];
    assert!(
        settle(&all, 400, || b.chain.has_tx(&txid)),
        "B never received the transaction. A holds {} in its mempool and the \
         two are connected; before this run `INV` was only ever built with \
         `InvKind::Block`, a tx-only `INV` was discarded before it became an \
         event, `GETDATA` for a transaction was silently ignored, and \
         `Msg::Tx(_) => {{}}` at the wire.",
        a.chain.mempool_ids().len()
    );

    let f = fds(&all);
    a.node.shutdown();
    b.node.shutdown();
    no_leak(f);
}

#[test]
fn relayed_tx_relayed_onward() {
    let a = node();
    let b = node();
    let c = node();
    let (txid, bytes) = a_tx(2);
    a.chain.add_local_tx(txid, bytes);

    b.node.dial(a.addr);
    c.node.dial(b.addr);

    let all: Vec<&Node> = vec![&a, &b, &c];
    assert!(
        settle(&all, 600, || c.chain.has_tx(&txid)),
        "the transaction reached B={} but not C, which is connected only to B. \
         A node must relay what it RECEIVED, not only what it originated - \
         otherwise every transaction dies one hop from its wallet.",
        b.chain.has_tx(&txid)
    );

    let f = fds(&all);
    a.node.shutdown();
    b.node.shutdown();
    c.node.shutdown();
    no_leak(f);
}

#[test]
fn no_mempool_relays_nothing() {
    let a = node();
    let b = node();
    a.chain.set_relayable(false);
    let (txid, bytes) = a_tx(3);
    a.chain.add_local_tx(txid, bytes);
    b.node.dial(a.addr);

    let all: Vec<&Node> = vec![&a, &b];
    assert!(
        settle(&all, 200, || a.node.outbound_count() + b.node.outbound_count() > 0),
        "the pair never connected"
    );

    for _ in 0..200 {
        step_all(&all, TICK_MS, 2);
    }
    assert!(
        !b.chain.has_tx(&txid),
        "the transaction reached B through some path other than the mempool \
         seam, so the seam is not what the tests above are proving"
    );
    assert!(a.chain.has_tx(&txid), "the fixture lost its own transaction");

    let f = fds(&all);
    a.node.shutdown();
    b.node.shutdown();
    no_leak(f);
}

#[test]
fn unknown_tx_answers_notfound() {
    let n = node();
    let mut raw = Raw::connect(n.addr).expect("connect");
    assert!(raw.handshake(0xBEEF01), "handshake");
    let (txid, _) = a_tx(9);
    raw.send(&Msg::GetData(vec![InvItem {
        kind: InvKind::Tx,
        hash: txid,
    }]))
    .expect("getdata");
    let answer = raw.wait_for(
        |m| matches!(m, Msg::NotFound(v) if v.iter().any(|i| i.kind == InvKind::Tx)),
        10_000,
    );
    assert!(
        answer.is_some(),
        "a GETDATA for a transaction was met with silence, the way the \
         driver used to answer"
    );
    let f = fds(&[&n]);
    n.node.shutdown();
    no_leak(f);
}

use plaine_p2p::sync::tx_relay::TxRelay;

fn ids(n: usize) -> Vec<Hash32> {
    (0..n as u64).map(|i| a_tx(1_000 + i).0).collect()
}

fn sends(out: &[Action]) -> Vec<&Msg> {
    out.iter()
        .filter_map(|a| match a {
            Action::Send { msg, .. } => Some(msg),
            _ => None,
        })
        .collect()
}

fn scored(out: &[Action]) -> Vec<Offence> {
    out.iter()
        .filter_map(|a| match a {
            Action::Score { offence, .. } => Some(*offence),
            _ => None,
        })
        .collect()
}

#[test]
fn inv_flood_bounded_per_peer() {
    let mut r = TxRelay::new();
    let mut out = Vec::new();
    let flood = ids(10_000);
    r.on_announced(PeerId(1), &flood, Mono(1_000), &mut out);
    let requested: usize = sends(&out)
        .iter()
        .map(|m| match m {
            Msg::GetData(v) => v.len(),
            _ => 0,
        })
        .sum();
    assert!(
        requested <= TX_INFLIGHT_PER_PEER,
        "one peer opened {requested} outstanding requests against a bound of {}",
        TX_INFLIGHT_PER_PEER
    );
    assert!(
        requested > 0,
        "the bound became a refusal: a peer with something to offer got nothing \
         asked of it"
    );
    assert!(
        scored(&out).is_empty(),
        "a peer with more to offer than we have room for was SCORED. That is a \
         busy network, not an attacker, and banning for it bans the healthiest \
         peers first."
    );
}

#[test]
fn silent_announcer_releases_slots() {
    let mut r = TxRelay::new();
    let mut out = Vec::new();
    let some = ids(4);
    r.on_announced(PeerId(1), &some, Mono(1_000), &mut out);
    assert_eq!(r.inflight_len(), 4);

    let mut out2 = Vec::new();
    r.on_announced(PeerId(2), &some, Mono(2_000), &mut out2);
    assert!(
        sends(&out2).is_empty(),
        "the same transaction was requested from two peers at once"
    );

    let mut out3 = Vec::new();
    let later = Mono(1_000).plus_ms(TX_REQUEST_TIMEOUT_MS + 1);
    r.on_tick(later, &[PeerId(2)], Vec::new, &mut out3);
    assert_eq!(
        r.inflight_len(),
        0,
        "the slots were never released: one announcement removes {} \
         transactions from circulation forever, for the price of one frame",
        TX_INFLIGHT_PER_PEER
    );
    assert!(
        scored(&out3).iter().all(|o| *o == Offence::DeadlineMiss),
        "a missed transaction deadline was charged as something other than a \
         deadline miss"
    );
    assert_eq!(scored(&out3).len(), 4, "the missed deadlines were not charged");

    let mut out4 = Vec::new();
    r.on_announced(PeerId(2), &some, later, &mut out4);
    assert!(
        !sends(&out4).is_empty(),
        "after the deadline the transaction was still unrequestable, so the \
         release is cosmetic"
    );
}

#[test]
fn unrequested_tx_scored() {
    let mut r = TxRelay::new();
    let mut out = Vec::new();
    let (txid, _) = a_tx(77);
    let admit = r.on_tx(PeerId(1), txid, Mono(1_000), &mut out);
    assert!(!admit, "a transaction nobody asked for was passed to the sink");
    assert_eq!(scored(&out), vec![Offence::UnsolicitedBody]);
}

#[test]
fn reflood_is_free() {
    let mut r = TxRelay::new();
    let (txid, _) = a_tx(55);
    let mut out = Vec::new();
    r.on_announced(PeerId(1), &[txid], Mono(1_000), &mut out);
    assert!(r.on_tx(PeerId(1), txid, Mono(1_100), &mut out));
    r.on_accepted(txid);

    for p in 2..20u64 {
        let mut o = Vec::new();
        r.on_announced(PeerId(p), &[txid], Mono(2_000), &mut o);
        assert!(
            sends(&o).is_empty(),
            "peer {p} made us re-request a transaction we already hold"
        );
        assert!(scored(&o).is_empty(), "a duplicate announcement was scored");
    }
}

#[test]
fn tx_not_announced_to_source() {
    let mut r = TxRelay::new();
    let (txid, _) = a_tx(66);
    let mut out = Vec::new();
    r.on_announced(PeerId(1), &[txid], Mono(1_000), &mut out);
    assert!(r.on_tx(PeerId(1), txid, Mono(1_100), &mut out));
    r.on_accepted(txid);

    let mut o = Vec::new();
    r.on_tick(Mono(2_000), &[PeerId(1), PeerId(2)], Vec::new, &mut o);
    for a in &o {
        if let Action::Send { peer, msg: Msg::Inv(v) } = a {
            assert!(
                !(*peer == PeerId(1) && v.iter().any(|i| i.hash == txid)),
                "the transaction was announced back to the peer that sent it"
            );
        }
    }

    let to_two = o.iter().any(|a| {
        matches!(a, Action::Send { peer, msg: Msg::Inv(v) }
            if *peer == PeerId(2) && v.iter().any(|i| i.hash == txid))
    });
    assert!(to_two, "the transaction was not relayed onward at all");
}

#[test]
fn disconnect_releases_slots() {
    let mut r = TxRelay::new();
    let mut out = Vec::new();
    let some = ids(8);
    r.on_announced(PeerId(1), &some, Mono(1_000), &mut out);
    assert_eq!(r.inflight_len(), 8);
    r.on_peer_gone(PeerId(1));
    assert_eq!(
        r.inflight_len(),
        0,
        "a peer that announces and disconnects removes those transactions from \
         circulation for {} ms, for the price of one connection, repeatable",
        TX_REQUEST_TIMEOUT_MS
    );
}

#[test]
fn notfound_releases_slot() {
    let mut r = TxRelay::new();
    let mut out = Vec::new();
    let (txid, _) = a_tx(88);
    r.on_announced(PeerId(1), &[txid], Mono(1_000), &mut out);
    assert_eq!(r.inflight_len(), 1);
    r.on_not_found(PeerId(1), txid);
    assert_eq!(r.inflight_len(), 0);

    r.on_announced(PeerId(1), &[txid], Mono(2_000), &mut out);
    r.on_not_found(PeerId(2), txid);
    assert_eq!(
        r.inflight_len(),
        1,
        "a third party released somebody else's request slot"
    );
}

#[test]
fn global_inflight_bound_holds() {
    let mut r = TxRelay::new();
    let per_peer = ids(TX_INFLIGHT_PER_PEER * 2);
    for p in 1..=64u64 {
        let mut out = Vec::new();
        r.on_announced(PeerId(p), &per_peer, Mono(1_000), &mut out);
    }
    assert!(
        r.inflight_len() <= TX_INFLIGHT_MAX,
        "{} requests outstanding against a global bound of {}",
        r.inflight_len(),
        TX_INFLIGHT_MAX
    );
}

#[test]
fn a_coinbase_is_refused_at_the_wire() {
    use plaine_consensus::codec::{AuthorNote, CoinbaseTx};
    let cb = CoinbaseTx {
        height: 5,
        to: [3u8; 20],
        reward: 1,
        fees: 0,
        note: AuthorNote {
            encoding: 0,
            payload: Vec::new(),
        },
    };
    let bytes = cb.encode().expect("encode coinbase");
    assert!(
        plaine_p2p::engine::tx_ident(&bytes).is_none(),
        "a bare coinbase was accepted as a relayable transaction. It exists \
         only inside a block, has no signature and no fee, and accepting one \
         here hands the embedder a record it must then know to reject."
    );

    let (txid, raw) = a_tx(4);
    assert_eq!(plaine_p2p::engine::tx_ident(&raw), Some(txid));

    let mut tampered = raw.clone();
    tampered[90] ^= 0xff;
    assert_ne!(plaine_p2p::engine::tx_ident(&tampered), Some(txid));
}

#[test]
fn decided_tx_not_repeated() {
    let mut r = TxRelay::new();
    let (txid, _) = a_tx(4242);

    let mut out = Vec::new();
    r.on_announced(PeerId(1), &[txid], Mono(1_000), &mut out);
    assert_eq!(r.inflight_len(), 1, "the fixture never requested it");

    let mut out2 = Vec::new();
    r.on_tick(Mono(2_000), &[], || vec![txid], &mut out2);
    assert_eq!(r.seen_len(), 1, "the poll did not mark it seen");
    let queued_after_poll = r.pending_len();
    assert_eq!(queued_after_poll, 1, "the poll did not queue it for announcement");

    let mut out3 = Vec::new();
    let admit = r.on_tx(PeerId(1), txid, Mono(3_000), &mut out3);
    assert!(
        !admit,
        "a transaction the node had already decided about was handed to the \
         sink a second time"
    );
    assert!(
        scored(&out3).is_empty(),
        "the peer was scored for delivering exactly what we asked it for"
    );
    r.on_accepted(txid);
    assert_eq!(
        r.pending_len(),
        queued_after_poll,
        "the same transaction was queued for announcement twice, so every peer \
         is told again and answers with a GETDATA we then serve"
    );
}

#[test]
fn notfound_releases_tx_slot() {
    use plaine_p2p::mock::Sim;
    use plaine_p2p::sync::Event;

    let mut sim = Sim::new(1, BASE_TIME);
    let (txid, _) = a_tx(31337);
    let peer = PeerId(7);

    let acts = sim.engine.on_event(
        Event::PeerReady {
            peer,
            ip: [9u8; 16],
            outbound: true,
            height: 0,
            work: [0u8; 32],
            tip: [0u8; 32],
            services: SERVICE_FULL_RELAY,
        },
        Mono(1_000),
    );
    let _ = acts;
    let acts = sim.engine.on_event(
        Event::AnnouncedTx {
            peer,
            txids: vec![txid],
        },
        Mono(1_100),
    );
    assert!(
        acts.iter().any(|a| matches!(a, Action::Send {
            msg: Msg::GetData(v), ..
        } if v.iter().any(|i| i.kind == InvKind::Tx && i.hash == txid))),
        "the engine did not turn a transaction announcement into a GETDATA"
    );
    assert_eq!(sim.engine.tx.inflight_len(), 1, "no slot was taken");

    let acts = sim.engine.on_event(Event::NotFoundTx { peer, txid }, Mono(1_200));
    assert_eq!(
        sim.engine.tx.inflight_len(),
        0,
        "the engine ignored a NOTFOUND for a transaction, so the slot is held \
         for the full {} ms and the honest answer is punished exactly like \
         silence",
        TX_REQUEST_TIMEOUT_MS
    );
    assert!(
        !acts.iter().any(|a| matches!(a, Action::Score { .. })),
        "a NOTFOUND on a transaction was scored; the rule says always zero"
    );
}
