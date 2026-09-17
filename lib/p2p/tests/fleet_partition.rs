use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::*;
use plaine_p2p::engine::fd::FdBudget;
use plaine_p2p::mock::{MockBits, MockChain, MockClock, MockPow};
use plaine_p2p::net::{NetNode, NetOptions, TickMode};
use plaine_p2p::sync::SyncEngine;
use plaine_p2p::traits::{ChainView, Clock};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

type Engine = SyncEngine<MockChain, MockChain, MockPow, MockBits>;

const BASE_TIME: u64 = 1_800_000_000;

struct Node {
    node: NetNode<Engine>,
    chain: Arc<MockChain>,
    pow: Arc<MockPow>,
    clock: Arc<MockClock>,
    fd: Arc<FdBudget>,
    addr: SocketAddr,
}

fn node_on(listen: SocketAddr, blocks: u64, unix: u64) -> Node {
    let chain = Arc::new(MockChain::linear(blocks, BASE_TIME, 1));
    let pow = Arc::new(MockPow::all_valid());
    let bits = Arc::new(MockBits);
    let pow_for_engine = Arc::clone(&pow);
    let clock = Arc::new(MockClock::new(unix));
    let cfg = P2pConfig::isolated();
    let engine = SyncEngine::new(
        Arc::clone(&chain),
        Arc::clone(&chain),
        pow_for_engine,
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
            listen,
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
        pow,
        clock,
        fd,
        addr,
    }
}

fn node_at(blocks: u64, unix: u64) -> Node {
    node_on(SocketAddr::from(([127, 0, 0, 1], 0)), blocks, unix)
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
    fn height(&self) -> u64 {
        self.chain.tip().height
    }
    fn outbound(&self) -> usize {
        self.node
            .net()
            .peers
            .lock()
            .expect("peers")
            .values()
            .filter(|w| w.outbound)
            .count()
    }
    fn inbound(&self) -> usize {
        self.node
            .net()
            .peers
            .lock()
            .expect("peers")
            .values()
            .filter(|w| !w.outbound)
            .count()
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

fn shape(nodes: &[&Node]) -> String {
    nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            format!(
                "n{i}: h={} in={} out={}",
                n.height(),
                n.inbound(),
                n.outbound()
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

#[test]
fn inbound_only_miner_propagates() {
    let unix = BASE_TIME + 10 * 60;
    let hub = node_at(1, unix);
    let edges: Vec<Node> = (0..4).map(|_| node_at(1, unix)).collect();
    for e in &edges {
        e.node.dial(hub.addr);
    }
    let mut all: Vec<&Node> = vec![&hub];
    all.extend(edges.iter());

    assert!(
        settle(&all, 200, || hub.inbound() == 4),
        "the mesh never formed: {}",
        shape(&all)
    );
    assert_eq!(hub.outbound(), 0, "the hub must dial nobody in this shape");

    let genesis = hub.chain.header_at(0).expect("genesis").hash;
    let grown = plaine_p2p::mock::build_chain(1, 5, genesis, BASE_TIME, 1);
    hub.chain.extend(&grown, true);
    seed_real_bodies(&hub.chain);
    assert_eq!(hub.height(), 5);

    let ok = settle(&all, 600, || edges.iter().all(|e| e.height() == 5));
    assert!(
        ok,
        "the hub mined 5 blocks and its peers are all inbound. {}",
        shape(&all)
    );
    for e in &edges {
        assert_eq!(
            e.chain.tip().hash,
            hub.chain.tip().hash,
            "same height, different tip"
        );
    }

    let fds: Vec<Arc<FdBudget>> = all.iter().map(|n| Arc::clone(&n.fd)).collect();
    hub.node.shutdown();
    for e in edges {
        e.node.shutdown();
    }
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn dead_outbound_redialled() {
    let unix = BASE_TIME + 10 * 60;
    let a = node_at(1, unix);
    let b = node_at(1, unix);
    let core = node_at(1, unix);
    core.node.dial(a.addr);
    core.node.dial(b.addr);

    let all: Vec<&Node> = vec![&a, &b, &core];
    assert!(
        settle(&all, 200, || core.outbound() == 2),
        "core never reached two outbound peers: {}",
        shape(&all)
    );
    let a_addr = a.addr;

    a.node.shutdown();
    let rest: Vec<&Node> = vec![&b, &core];
    assert!(
        settle(&rest, 100, || core.outbound() == 1),
        "core never noticed A leaving: {}",
        shape(&rest)
    );
    assert!(
        core.node.peer_count() > 0,
        "core must not be cold for this test to mean anything"
    );

    let a2 = node_on(a_addr, 1, unix);
    let all2: Vec<&Node> = vec![&a2, &b, &core];
    let ok = settle(&all2, 1200, || core.outbound() == 2);
    assert!(
        ok,
        "core never re-dialled the restarted peer. It still holds B, so it is \
         never cold, and before the connection manager existed `Action::Dial` \
         was emitted only from S0. {}",
        shape(&all2)
    );

    let fds: Vec<Arc<FdBudget>> = all2.iter().map(|n| Arc::clone(&n.fd)).collect();
    a2.node.shutdown();
    b.node.shutdown();
    core.node.shutdown();
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn restart_no_partition() {
    let unix = BASE_TIME + 10 * 60;
    let mut nodes: Vec<Node> = (0..5).map(|_| node_at(1, unix)).collect();

    for i in 0..5 {
        let next = nodes[(i + 1) % 5].addr;
        nodes[i].node.dial(next);
    }
    let refs: Vec<&Node> = nodes.iter().collect();
    assert!(
        settle(&refs, 300, || refs.iter().all(|n| n.node.peer_count() == 2)),
        "the ring never formed: {}",
        shape(&refs)
    );

    let genesis = nodes[0].chain.header_at(0).expect("genesis").hash;
    let grown = plaine_p2p::mock::build_chain(1, 4, genesis, BASE_TIME, 1);
    nodes[0].chain.extend(&grown, true);
    seed_real_bodies(&nodes[0].chain);

    let mut rounds = 0usize;
    let ok = settle(&refs, 1_200, || {
        rounds += 1;
        refs.iter().all(|n| n.height() == 4)
    });
    assert!(
        ok,
        "the ring did not converge before the restart: {}",
        shape(&refs)
    );
    let virtual_ms = rounds * TICK_MS as usize;
    assert!(
        virtual_ms <= 60_000,
        "the ring took {virtual_ms} ms of virtual time to carry one block four hops; one hop must cost far less than the 60 s block time"
    );

    let addr2 = nodes[2].addr;
    let old = std::mem::replace(&mut nodes[2], node_at(1, unix));
    old.node.shutdown();
    nodes[2] = node_on(addr2, 1, unix);

    let succ = nodes[3].addr;
    nodes[2].node.dial(succ);
    let refs: Vec<&Node> = nodes.iter().collect();

    assert!(
        settle(&refs, 1200, || nodes[2].node.peer_count() >= 1
            && refs.iter().all(|n| n.node.peer_count() >= 1)),
        "the mesh did not heal after the restart: {}",
        shape(&refs)
    );

    let tip4 = nodes[0].chain.tip().hash;
    let grown = plaine_p2p::mock::build_chain(5, 5, tip4, BASE_TIME, 1);
    nodes[0].chain.extend(&grown, true);
    seed_real_bodies(&nodes[0].chain);
    let refs: Vec<&Node> = nodes.iter().collect();
    let ok = settle(&refs, 1600, || refs.iter().all(|n| n.height() == 9));

    for (i, n) in refs.iter().enumerate() {
        let calls = n.pow.calls();
        assert!(
            calls <= 4 * 9,
            "n{i} ran the interpreter {calls} times for 9 distinct headers"
        );
    }
    assert!(
        ok,
        "a single peer restart partitioned the mesh - this is the fleet run, in \
         process. {}",
        shape(&refs)
    );

    let fds: Vec<Arc<FdBudget>> = refs.iter().map(|n| Arc::clone(&n.fd)).collect();
    for n in nodes {
        n.node.shutdown();
    }
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn no_outbound_widens_group_rule() {
    let unix = BASE_TIME + 10 * 60;
    let alone = node_at(1, unix);
    let edges: Vec<Node> = (0..5).map(|_| node_at(1, unix)).collect();

    edges[0].node.dial(alone.addr);
    edges[1].node.dial(alone.addr);

    for e in edges.iter().skip(2) {
        alone.node.learn(e.addr);
    }
    let mut all: Vec<&Node> = vec![&alone];
    all.extend(edges.iter());

    assert!(
        settle(&all, 300, || alone.inbound() == 2),
        "the fixture shape never formed: {}",
        shape(&all)
    );
    assert_eq!(alone.outbound(), 0, "the fixture dialled something");

    let ok = settle(&all, 900, || alone.outbound() > OUTBOUND_PER_GROUP);
    assert!(
        ok,
        "the node holds {} inbound and {} outbound with three learned addresses in one /16; `OUTBOUND_PER_GROUP` is {}, so the widened dial is its only escape. {}",
        alone.inbound(),
        alone.outbound(),
        OUTBOUND_PER_GROUP,
        shape(&all)
    );

    let fds: Vec<Arc<FdBudget>> = all.iter().map(|n| Arc::clone(&n.fd)).collect();
    alone.node.shutdown();
    for e in edges {
        e.node.shutdown();
    }
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn maintenance_no_duplicate_socket() {
    let unix = BASE_TIME + 10 * 60;
    let a = node_at(1, unix);
    let b = node_at(1, unix);
    a.node.dial(b.addr);
    let all: Vec<&Node> = vec![&a, &b];
    assert!(
        settle(&all, 200, || a.outbound() == 1 && b.inbound() == 1),
        "the pair never handshook: {}",
        shape(&all)
    );

    let rounds = (DIAL_RETRY_MS * 3 / TICK_MS) as usize;
    for _ in 0..rounds {
        step_all(&all, TICK_MS, 1);
        assert_eq!(
            a.outbound(),
            1,
            "a second outbound socket to the same peer: {}",
            shape(&all)
        );
        assert_eq!(b.inbound(), 1, "the far end accepted a duplicate");
    }

    let fda = Arc::clone(&a.fd);
    let fdb = Arc::clone(&b.fd);
    a.node.shutdown();
    b.node.shutdown();
    assert_eq!(fda.total_open(), 0);
    assert_eq!(fdb.total_open(), 0);
}

#[test]
fn peer_rows_carry_metadata() {
    let unix = BASE_TIME + 200 * 60;
    let a = node_at(201, unix);
    let b = node_at(1, unix);
    seed_real_bodies(&a.chain);
    b.node.dial(a.addr);

    let all: Vec<&Node> = vec![&a, &b];
    assert!(
        settle(&all, 600, || b.height() == 200),
        "B never synced: {}",
        shape(&all)
    );

    let rows = b.node.peer_rows();
    assert_eq!(rows.len(), 1, "one peer expected");
    let r = &rows[0];
    assert!(r.outbound, "B dialled A");
    assert_eq!(
        r.best_height, 200,
        "the peer's height is the one number the watchtower reads a peer for, \
         and it was 0 for every peer of every node on the fleet"
    );
    assert!(
        r.bytes_recv > 0 && r.bytes_sent > 0,
        "byte counters stayed at zero"
    );
    assert!(
        !r.user_agent.is_empty(),
        "the user agent is decoded by the handshake and was dropped on the floor"
    );
    assert_eq!(r.misbehaviour, 0, "an honest sync earned an offence");
    assert_eq!(r.port, a.addr.port(), "the port must be the one we dialled");

    let fda = Arc::clone(&a.fd);
    let fdb = Arc::clone(&b.fd);
    a.node.shutdown();
    b.node.shutdown();
    assert_eq!(fda.total_open(), 0);
    assert_eq!(fdb.total_open(), 0);
}

#[test]
fn one_dial_per_retry_interval() {
    use plaine_p2p::addr::AddrMan;
    use plaine_p2p::traits::Mono;

    let mut am = AddrMan::new();
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12] = 10;
    ip[13] = 44;
    ip[14] = 0;
    ip[15] = 11;
    am.add(ip, 9256, true, 0);

    let t0 = Mono(1_000_000);
    assert_eq!(
        am.select_dial(4, &[], t0, false).len(),
        1,
        "never tried, must be offered"
    );
    am.note_attempt(&ip, 9256, t0);

    let mid = t0.plus_ms(DIAL_RETRY_MS - 1);
    assert!(
        am.select_dial(4, &[], mid, false).is_empty(),
        "the address was re-offered {} ms after the last attempt; the floor is \
         {} ms, and a connection manager that ticks every {} ms would otherwise \
         hammer a peer that is down",
        DIAL_RETRY_MS - 1,
        DIAL_RETRY_MS,
        CONN_MANAGER_TICK_MS
    );

    assert!(
        am.select_dial(4, &[], mid, true).is_empty(),
        "widening relaxed the per-address retry floor"
    );

    let after = t0.plus_ms(DIAL_RETRY_MS + 1);
    assert_eq!(
        am.select_dial(4, &[], after, false).len(),
        1,
        "the address was never offered again - a floor is not a ban"
    );
}

#[test]
fn dialler_promotes_and_demotes() {
    use plaine_p2p::addr::Table;

    let unix = BASE_TIME + 10 * 60;
    let a = node_at(1, unix);
    let b = node_at(1, unix);
    let b_ip = plaine_p2p::net::ip_bytes(&b.addr);
    let b_port = b.addr.port();
    a.node.dial(b.addr);

    let all: Vec<&Node> = vec![&a, &b];
    assert!(
        settle(&all, 200, || a.outbound() == 1),
        "the pair never handshook: {}",
        shape(&all)
    );
    assert_eq!(
        a.node
            .net()
            .addrs
            .lock()
            .expect("addrs")
            .get(&b_ip, b_port)
            .map(|e| e.table),
        Some(Table::Tried),
        "a completed handshake did not promote the address"
    );

    b.node.shutdown();
    let alone: Vec<&Node> = vec![&a];

    let rounds = ((DEMOTE_AFTER_FAILURES as u64 + 4) * DIAL_RETRY_MS * 2 / TICK_MS) as usize;
    let demoted = settle(&alone, rounds, || {
        a.node
            .net()
            .addrs
            .lock()
            .expect("addrs")
            .get(&b_ip, b_port)
            .map(|e| e.table)
            == Some(Table::New)
    });
    assert!(
        demoted,
        "after {DEMOTE_AFTER_FAILURES} failed dials the address is still in \
         `tried`, so it keeps being preferred over addresses that work"
    );
    assert!(
        a.node
            .net()
            .addrs
            .lock()
            .expect("addrs")
            .get(&b_ip, b_port)
            .is_some(),
        "the address was deleted, not demoted. One that failed during an \
         outage is not a bad address."
    );

    let fda = Arc::clone(&a.fd);
    a.node.shutdown();
    assert_eq!(fda.total_open(), 0);
}

#[test]
fn inbound_spares_outbound_budget() {
    let unix = BASE_TIME + 10 * 60;
    let h = node_at(1, unix);
    let e: Vec<Node> = (0..4).map(|_| node_at(1, unix)).collect();

    e[0].node.dial(h.addr);
    e[1].node.dial(h.addr);

    h.node.dial(e[2].addr);

    h.node.learn(e[3].addr);

    let mut all: Vec<&Node> = vec![&h];
    all.extend(e.iter());
    assert!(
        settle(&all, 300, || h.inbound() == 2 && h.outbound() == 1),
        "the fixture shape never formed: {}",
        shape(&all)
    );

    let ok = settle(&all, 600, || h.outbound() == 2);
    assert!(
        ok,
        "the hub holds {} inbound and {} outbound and never opened its second \
         outbound connection. `OUTBOUND_PER_GROUP` is {}, and the two inbound \
         peers are not connections it opened. {}",
        h.inbound(),
        h.outbound(),
        OUTBOUND_PER_GROUP,
        shape(&all)
    );

    let fds: Vec<Arc<FdBudget>> = all.iter().map(|n| Arc::clone(&n.fd)).collect();
    h.node.shutdown();
    for n in e {
        n.node.shutdown();
    }
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn inbound_only_acquires_outbound() {
    let unix = BASE_TIME + 10 * 60;
    let miner = node_at(1, unix);
    let victim = node_at(1, unix);

    miner.node.dial(victim.addr);

    victim.node.learn(miner.addr);

    let all: Vec<&Node> = vec![&miner, &victim];
    assert!(
        settle(&all, 300, || victim.inbound() == 1),
        "the fixture shape never formed: {}",
        shape(&all)
    );

    let genesis = miner.chain.header_at(0).expect("genesis").hash;
    let grown = plaine_p2p::mock::build_chain(1, 5, genesis, BASE_TIME, 1);
    miner.chain.extend(&grown, true);
    seed_real_bodies(&miner.chain);

    assert!(
        settle(&all, 1_200, || victim.outbound() >= 1),
        "the victim never dialled anybody: {} inbound, {} outbound. {}",
        victim.inbound(),
        victim.outbound(),
        shape(&all)
    );
    let ok = settle(&all, 1_200, || victim.height() == 5);
    assert!(
        ok,
        "victim stuck at height {} against the miner's 5, with {} inbound and {} outbound peers {}",
        victim.height(),
        victim.inbound(),
        victim.outbound(),
        shape(&all)
    );
    assert_eq!(victim.chain.tip().hash, miner.chain.tip().hash);

    let fds: Vec<Arc<FdBudget>> = all.iter().map(|n| Arc::clone(&n.fd)).collect();
    miner.node.shutdown();
    victim.node.shutdown();
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn long_chain_syncs_to_end() {
    const N: u64 = WANTED_MAX as u64 * 2 + 100;
    let unix = BASE_TIME + (N + 1) * 60;
    let a = node_at(N + 1, unix);
    let b = node_at(1, unix);
    seed_real_bodies(&a.chain);
    assert_eq!(a.height(), N);

    b.chain.strict_canonical(true);

    b.node.dial(a.addr);
    let all: Vec<&Node> = vec![&a, &b];
    let ok = settle(&all, 4_000, || b.height() == N);
    assert!(
        ok,
        "B reached height {} of A's {N}. `WANTED_MAX` is {}, and a node that \
         stops within one of it is a node whose body window cannot slide. {}",
        b.height(),
        WANTED_MAX,
        shape(&all)
    );
    assert_eq!(b.chain.tip().hash, a.chain.tip().hash);

    let ok = settle(&all, 4_000, || b.chain.accepted_blocks() >= N);
    assert!(
        ok,
        "B applied {} blocks of A's {N} while holding every header; WANTED_MAX is {}, the body window stopped sliding at its own size. {}",
        b.chain.accepted_blocks(),
        WANTED_MAX,
        shape(&all)
    );

    let fda = Arc::clone(&a.fd);
    let fdb = Arc::clone(&b.fd);
    a.node.shutdown();
    b.node.shutdown();
    assert_eq!(fda.total_open(), 0);
    assert_eq!(fdb.total_open(), 0);
}
