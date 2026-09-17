use plaine_p2p::addr::addrman::Ingest;
use plaine_p2p::addr::{AddrMan, Table};
use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::*;
use plaine_p2p::engine::fd::FdBudget;
use plaine_p2p::mock::{MockBits, MockChain, MockClock, MockPow};
use plaine_p2p::net::{ip_bytes, NetNode, NetOptions, TickMode};
use plaine_p2p::rng::Rng;
use plaine_p2p::sync::SyncEngine;
use plaine_p2p::traits::{Clock, Mono};
use plaine_p2p::wire::codec::{decode, encode};
use plaine_p2p::wire::frame::{encode_frame, FrameReader};
use plaine_p2p::wire::msg::{AddrRec, Hello, Msg};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

type Engine = SyncEngine<MockChain, MockChain, MockPow, MockBits>;

const BASE_TIME: u64 = 1_800_000_000;

fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[10] = 0xff;
    o[11] = 0xff;
    o[12] = a;
    o[13] = b;
    o[14] = c;
    o[15] = d;
    o
}

fn grp(a: u8, b: u8) -> [u8; 4] {
    [a, b, 0, 0]
}

struct Node {
    node: NetNode<Engine>,
    clock: Arc<MockClock>,
    fd: Arc<FdBudget>,
    addr: SocketAddr,
    chain: Arc<MockChain>,
}

fn gossip_cfg() -> P2pConfig {
    P2pConfig {
        isolated: false,
        accept_local_addrs: true,
        ..P2pConfig::default()
    }
}

fn node_on(listen: SocketAddr, cfg: P2pConfig) -> Node {
    let unix = BASE_TIME + 10 * 60;
    let chain = Arc::new(MockChain::linear(1, BASE_TIME, 1));
    let pow = Arc::new(MockPow::all_valid());
    let bits = Arc::new(MockBits);
    let clock = Arc::new(MockClock::new(unix));
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
        clock,
        fd,
        addr,
        chain,
    }
}

fn node() -> Node {
    node_on(SocketAddr::from(([127, 0, 0, 1], 0)), gossip_cfg())
}

impl Node {
    fn step(&self, ms: u64) {
        self.clock.advance(ms);
        self.node.tick();
    }
    fn outbound(&self) -> usize {
        self.node.outbound_count()
    }
    fn knows(&self, a: &SocketAddr) -> bool {
        self.node
            .net()
            .addrs
            .lock()
            .expect("addrs")
            .get(&ip_bytes(a), a.port())
            .is_some()
    }
    fn connected_to(&self, a: &SocketAddr) -> bool {
        let ip = ip_bytes(a);
        self.node
            .net()
            .peers
            .lock()
            .expect("peers")
            .values()
            .any(|w| w.outbound && w.ip == ip && w.port == a.port())
    }
}

fn assert_book_is_loopback(n: &Node) {
    let am = n.node.net().addrs.lock().expect("addrs");
    for e in am.entries() {
        assert_eq!(
            e.ip[12], 127,
            "a socket test leaked {}.{}.{}.{} into the loopback book",
            e.ip[12], e.ip[13], e.ip[14], e.ip[15]
        );
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

    fn send_together(&mut self, a: &Msg, b: &Msg) -> std::io::Result<()> {
        let mut buf = encode_frame(&MAGIC_MAIN, a.cmd(), &encode(a));
        buf.extend_from_slice(&encode_frame(&MAGIC_MAIN, b.cmd(), &encode(b)));
        self.s.write_all(&buf)
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

    fn handshake(&mut self, nonce: u64, listen_port: u16) -> Option<Hello> {
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
            listen_port,
            user_agent: b"raw/1".to_vec(),
        });
        self.send(&ours).ok()?;
        let theirs = self.wait_for(|m| matches!(m, Msg::Hello(_)), 10_000)?;
        self.send(&Msg::HelloAck).ok()?;
        self.wait_for(|m| matches!(m, Msg::HelloAck), 10_000)?;
        match theirs {
            Msg::Hello(h) => Some(h),
            _ => None,
        }
    }

    fn handshake_claiming(&mut self, chain_id: [u8; 4], nonce: u64) -> (Option<Hello>, bool) {
        let ours = Msg::Hello(Hello {
            proto_ver: PROTO_VER,
            min_proto: MIN_PROTO,
            chain_id,
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
            return (None, false);
        }
        let theirs = match self.wait_for(|m| matches!(m, Msg::Hello(_)), 4_000) {
            Some(Msg::Hello(h)) => Some(h),
            _ => None,
        };
        let _ = self.send(&Msg::HelloAck);
        let acked = self
            .wait_for(|m| matches!(m, Msg::HelloAck), 4_000)
            .is_some();
        (theirs, acked)
    }
}

#[test]
fn flood_cannot_evict_honest_addr() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;

    let mut honest: Vec<([u8; 16], u16)> = Vec::new();
    for s in 0..4u8 {
        let honest_src = grp(198, 51 + s);
        for i in 0..100u32 {
            let ip = v4(51, s, (i & 0xff) as u8, 7);
            assert_eq!(
                am.add_from_peer(ip, 9256, 1, now, honest_src, now, false),
                Ingest::Added
            );
            honest.push((ip, 9256));
        }
    }

    let attacker_src = grp(203, 0);
    let mut accepted = 0usize;
    for i in 0..20_000u32 {
        let ip = v4(
            100 + (i >> 12) as u8 % 60,
            (i >> 4) as u8,
            (i & 0xf) as u8,
            9,
        );
        if am.add_from_peer(ip, 9256, 1, now, attacker_src, now, false) == Ingest::Added {
            accepted += 1;
        }
    }

    for (ip, port) in &honest {
        assert!(
            am.get(ip, *port).is_some(),
            "honest address evicted by a flood from distinct /16s; source group is attacker-chosen"
        );
    }
    assert!(
        accepted <= ADDR_PER_SOURCE_GROUP_MAX,
        "one source /16 placed {} entries against a quota of {}",
        accepted,
        ADDR_PER_SOURCE_GROUP_MAX
    );
    assert!(am.counters_consistent(), "counters drifted under the flood");
}

#[test]
fn peers_in_one_group_share_quota() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    let src = grp(203, 0);
    let mut accepted = 0usize;
    for peer in 0..4u32 {
        for i in 0..2_000u32 {
            let ip = v4(70 + peer as u8, (i >> 8) as u8, (i & 0xff) as u8, 3);
            if am.add_from_peer(ip, 9256, 1, now, src, now, false) == Ingest::Added {
                accepted += 1;
            }
        }
    }
    assert_eq!(
        accepted, ADDR_PER_SOURCE_GROUP_MAX,
        "four sources inside one /16 got {} entries; the quota key is the /16, \
         so they must share it - otherwise `INBOUND_PER_IP = 4` multiplies it",
        accepted
    );
}

#[test]
fn distinct_source_groups_get_distinct_quotas() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    for s in 0..3u8 {
        let src = grp(203, s);
        for i in 0..(ADDR_PER_SOURCE_GROUP_MAX as u32 + 50) {
            let ip = v4(80 + s, (i >> 8) as u8, (i & 0xff) as u8, 3);
            let _ = am.add_from_peer(ip, 9256, 1, now, src, now, false);
        }
        assert_eq!(
            am.count_new_from(src),
            ADDR_PER_SOURCE_GROUP_MAX,
            "source group {} did not get its own quota",
            s
        );
    }
}

#[test]
fn full_book_refuses_until_aged() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;

    let mut placed = 0u32;
    'outer: for s in 0..64u32 {
        let src = grp(10, s as u8);
        for i in 0..ADDR_PER_SOURCE_GROUP_MAX as u32 {
            let ip = v4(
                30 + (s >> 4) as u8,
                (s & 0xf) as u8,
                (i >> 8) as u8,
                (i & 0xff) as u8,
            );
            if am.add_from_peer(ip, 9256, 1, now, src, now, false) != Ingest::Added {
                break;
            }
            placed += 1;
            if am.count(Table::New) >= ADDR_NEW_MAX {
                break 'outer;
            }
        }
    }
    assert_eq!(
        am.count(Table::New),
        ADDR_NEW_MAX,
        "fixture did not fill (placed {placed})"
    );

    let fresh_src = grp(11, 1);
    assert_eq!(
        am.add_from_peer(v4(60, 1, 1, 1), 9256, 1, now, fresh_src, now, false),
        Ingest::TableFull,
        "a full book must refuse a peer-supplied address, never evict for it; \
         eviction on the peer path is what the flood attack needs"
    );

    let later = now + ADDR_MAX_AGE_SECS + 86_400;
    let reaped = am.reap_expired(later);
    assert!(
        reaped > 0,
        "nothing aged out after {} days",
        (later - now) / 86_400
    );
    assert_eq!(
        am.add_from_peer(v4(60, 1, 1, 1), 9256, 1, later, fresh_src, later, false),
        Ingest::Added,
        "the book stayed full after aging made room"
    );
    assert!(am.counters_consistent());
}

#[test]
fn aging_never_reaps_an_operator_seed() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    am.add(v4(51, 1, 1, 1), 9256, true, now);
    am.add_from_peer(v4(51, 2, 2, 2), 9256, 1, now, grp(203, 0), now, false);
    am.reap_expired(now + ADDR_MAX_AGE_SECS * 2);
    assert!(
        am.get(&v4(51, 1, 1, 1), 9256).is_some(),
        "the seed was reaped"
    );
    assert!(
        am.get(&v4(51, 2, 2, 2), 9256).is_none(),
        "a stale gossiped address survived"
    );
}

#[test]
fn future_clamped_ancient_refused() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    let src = grp(203, 0);
    assert_eq!(
        am.add_from_peer(
            v4(51, 1, 1, 1),
            9256,
            1,
            now + 10 * 365 * 86_400,
            src,
            now,
            false
        ),
        Ingest::Added
    );
    assert_eq!(
        am.get(&v4(51, 1, 1, 1), 9256).expect("entry").last_seen,
        now,
        "a claimed `time` ten years in the future was stored as claimed"
    );
    assert_eq!(
        am.add_from_peer(
            v4(51, 2, 2, 2),
            9256,
            1,
            now - ADDR_MAX_AGE_SECS - 1,
            src,
            now,
            false
        ),
        Ingest::TooOld,
        "the 7-day window is not enforced on ingest"
    );
}

#[test]
fn tried_bounded_by_demotion() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    let n = ADDR_TRIED_MAX + 200;
    for i in 0..n as u32 {
        let ip = v4(51, (i >> 8) as u8, (i & 0xff) as u8, 1);
        am.add(ip, 9256, true, now);
        am.note_attempt(&ip, 9256, Mono(1_000 + i as u64));
        am.on_handshake_ok(&ip, 9256, 1);
    }
    assert_eq!(
        am.count(Table::Tried),
        ADDR_TRIED_MAX,
        "`tried` grew past its declared bound"
    );
    assert_eq!(
        am.len(),
        n,
        "an address was deleted to hold the bound, not demoted. One that \
         answered a handshake once should survive a bad week."
    );
    assert!(am.counters_consistent());
}

#[test]
fn counters_match_recount() {
    let mut am = AddrMan::new();
    let mut rng = Rng::new(0xA11CE);
    let now = 1_800_000_000u64;
    for step in 0..6_000u32 {
        let ip = v4(
            (rng.below(200) + 20) as u8,
            rng.below(255) as u8,
            rng.below(255) as u8,
            rng.below(255) as u8,
        );
        let port = 9000 + rng.below(8) as u16;
        match rng.below(7) {
            0 => {
                am.add(ip, port, true, now);
            }
            1 => {
                am.add_from_peer(ip, port, 1, now, grp(203, rng.below(4) as u8), now, false);
            }
            2 => {
                am.on_handshake_ok(&ip, port, 1);
            }
            3 => {
                am.on_failure(&ip, port, rng.below(2) == 0);
            }
            4 => {
                am.note_attempt(&ip, port, Mono(step as u64 * 10));
            }
            5 => {
                am.mark_foreign(&ip, port, Mono(step as u64 * 10));
            }
            _ => {
                am.reap_expired(now + rng.below(ADDR_MAX_AGE_SECS * 3));
            }
        }
        assert!(
            am.counters_consistent(),
            "counters drifted at step {step}: len={} new={} tried={}",
            am.len(),
            am.count(Table::New),
            am.count(Table::Tried)
        );
    }
}

#[test]
fn unroutable_never_booked() {
    let cases: &[([u8; 16], &str)] = &[
        (v4(0, 0, 0, 0), "unspecified"),
        (v4(0, 1, 2, 3), "0.0.0.0/8 this network"),
        (v4(127, 0, 0, 1), "loopback"),
        (v4(10, 44, 0, 1), "RFC1918 10/8 - the fleet's own mesh"),
        (v4(172, 16, 5, 5), "RFC1918 172.16/12"),
        (v4(172, 31, 5, 5), "RFC1918 172.31/12, the top of the range"),
        (v4(192, 168, 1, 1), "RFC1918 192.168/16"),
        (
            v4(169, 254, 169, 254),
            "link-local - the cloud metadata address",
        ),
        (v4(100, 64, 0, 1), "CGNAT 100.64/10"),
        (v4(100, 127, 255, 1), "CGNAT top of range"),
        (v4(192, 0, 0, 1), "192.0.0/24 IETF protocol assignments"),
        (v4(192, 0, 2, 1), "192.0.2/24 documentation"),
        (v4(198, 51, 100, 1), "198.51.100/24 documentation"),
        (v4(203, 0, 113, 1), "203.0.113/24 documentation"),
        (v4(192, 88, 99, 1), "192.88.99/24 deprecated 6to4 anycast"),
        (v4(198, 18, 0, 1), "198.18/15 benchmarking"),
        (v4(198, 19, 0, 1), "198.19/15 benchmarking"),
        (v4(224, 0, 0, 1), "multicast"),
        (v4(240, 0, 0, 1), "240/4 reserved"),
        (v4(255, 255, 255, 255), "broadcast"),
        ([0u8; 16], "v6 unspecified"),
        (
            {
                let mut a = [0u8; 16];
                a[15] = 1;
                a
            },
            "v6 loopback",
        ),
        (
            {
                let mut a = [0u8; 16];
                a[0] = 0xfd;
                a[15] = 1;
                a
            },
            "fc00::/7 unique local",
        ),
        (
            {
                let mut a = [0u8; 16];
                a[0] = 0xfe;
                a[1] = 0x80;
                a[15] = 1;
                a
            },
            "fe80::/10 link local",
        ),
        (
            {
                let mut a = [0u8; 16];
                a[0] = 0x20;
                a[1] = 0x01;
                a[2] = 0x0d;
                a[3] = 0xb8;
                a[15] = 1;
                a
            },
            "2001:db8::/32 documentation",
        ),
        (
            {
                let mut a = [0u8; 16];
                a[0] = 0x00;
                a[1] = 0x64;
                a[2] = 0xff;
                a[3] = 0x9b;
                a[15] = 1;
                a
            },
            "64:ff9b::/96 NAT64 - a translator, not a peer",
        ),
        (
            {
                let mut a = [0u8; 16];
                a[0] = 0xff;
                a[15] = 1;
                a
            },
            "v6 multicast",
        ),
    ];
    let now = 1_800_000_000u64;
    for (ip, why) in cases {
        let mut am = AddrMan::new();
        assert_eq!(
            am.add_from_peer(*ip, 9256, 1, now, grp(203, 0), now, false),
            Ingest::Filtered,
            "{why} was accepted from a peer"
        );
    }

    let mut am = AddrMan::new();
    assert_eq!(
        am.add_from_peer(v4(51, 1, 1, 1), 0, 1, now, grp(203, 0), now, false),
        Ingest::Filtered,
        "port 0 was accepted; it is an explicit request not to \
         be announced"
    );
    assert_eq!(
        am.add_from_peer(v4(51, 1, 1, 1), 0, 1, now, grp(203, 0), now, true),
        Ingest::Filtered,
        "`accept_local_addrs` overruled a peer's own request not to be announced"
    );

    assert_eq!(
        am.add_from_peer(v4(51, 1, 1, 1), 9256, 1, now, grp(203, 0), now, false),
        Ingest::Added,
        "the filter refuses a globally routable address too"
    );
}

#[test]
fn getaddr_hides_private_addrs() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;

    for i in 11..=15u8 {
        am.add(v4(10, 44, 0, i), 9256, true, now);
    }
    am.add(v4(127, 0, 0, 1), 9256, true, now);
    am.add(v4(51, 12, 13, 14), 9256, true, now);
    let mut rng = Rng::new(1);
    let out = am.sample(ADDR_MSG_MAX, now, &mut rng, false);
    assert_eq!(
        out.len(),
        1,
        "GETADDR answer carried {} records; the operator exemption governs dialling, not what we publish",
        out.len()
    );
    assert_eq!(out[0].ip, v4(51, 12, 13, 14));
}

#[test]
fn foreign_addr_not_gossiped() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    am.add(v4(51, 1, 1, 1), 9256, true, now);
    am.add(v4(51, 2, 2, 2), 9256, true, now);
    am.mark_foreign(&v4(51, 2, 2, 2), 9256, Mono(0));
    let mut rng = Rng::new(1);
    let out = am.sample(ADDR_MSG_MAX, now, &mut rng, false);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ip, v4(51, 1, 1, 1));
}

#[test]
fn getaddr_is_sampled_not_ordered() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    let n = ADDR_MSG_MAX * 3;
    for i in 0..n as u32 {
        am.add(v4(51, (i >> 8) as u8, (i & 0xff) as u8, 1), 9256, true, now);
    }
    let mut r1 = Rng::new(1);
    let mut r2 = Rng::new(2);
    let a = am.sample(ADDR_MSG_MAX, now, &mut r1, false);
    let b = am.sample(ADDR_MSG_MAX, now, &mut r2, false);
    assert_eq!(a.len(), ADDR_MSG_MAX);
    assert_eq!(b.len(), ADDR_MSG_MAX);
    assert_ne!(
        a.iter().map(|e| e.ip).collect::<Vec<_>>(),
        b.iter().map(|e| e.ip).collect::<Vec<_>>(),
        "two answers were byte-identical: the sample is deterministic, so it \
         leaks the order this node learned the network in and relays the same \
         512 addresses every time"
    );

    let mut seen = std::collections::HashSet::new();
    for s in 0..40u64 {
        let mut r = Rng::new(s * 7717 + 3);
        for e in am.sample(ADDR_MSG_MAX, now, &mut r, false) {
            seen.insert(e.ip);
        }
    }
    assert!(
        seen.len() > ADDR_MSG_MAX,
        "40 draws yielded only {} of {} distinct: sampler is serving a prefix, not sampling",
        seen.len(),
        n
    );
}

#[test]
fn answer_excludes_stale() {
    let mut am = AddrMan::new();
    let now = 1_800_000_000u64;
    am.add(v4(51, 1, 1, 1), 9256, true, now - ADDR_MAX_AGE_SECS - 60);
    am.add(v4(51, 2, 2, 2), 9256, true, now - ADDR_FRESH_SECS);
    let mut rng = Rng::new(1);
    let out = am.sample(ADDR_MSG_MAX, now, &mut rng, false);
    assert_eq!(out.len(), 1, "an address older than 7 days was published");
    assert_eq!(out[0].ip, v4(51, 2, 2, 2));
}

#[test]
fn one_seed_reaches_unknown_peers() {
    let mesh: Vec<Node> = (0..4).map(|_| node()).collect();
    for i in 0..mesh.len() {
        for j in 0..mesh.len() {
            if i != j {
                mesh[i].node.dial(mesh[j].addr);
            }
        }
    }

    let fresh = node();
    fresh.node.dial(mesh[0].addr);

    let mut all: Vec<&Node> = mesh.iter().collect();
    all.push(&fresh);

    assert!(
        settle(&all, 400, || fresh.outbound() >= 1),
        "the fresh node never reached its seed"
    );

    let unseen: Vec<SocketAddr> = mesh[1..].iter().map(|n| n.addr).collect();
    let learned = settle(&all, 1_200, || unseen.iter().all(|a| fresh.knows(a)));
    assert!(
        learned,
        "node knows {} addrs after one seed; seed holds {} (empty-ADDR regression)",
        fresh.node.net().addr_count(),
        mesh[0].node.net().addr_count()
    );

    let connected = settle(&all, 1_200, || {
        unseen.iter().filter(|a| fresh.connected_to(a)).count() >= 1
    });
    assert!(
        connected,
        "node learned {} addrs but dialled none; healing a partition needs an outbound to an unnamed peer",
        fresh.node.net().addr_count()
    );
    assert!(
        fresh
            .node
            .net()
            .addrs_learned
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0,
        "no address was counted as learned from the wire"
    );

    drop(all);
    let fds: Vec<Arc<FdBudget>> = mesh
        .iter()
        .map(|n| Arc::clone(&n.fd))
        .chain(std::iter::once(Arc::clone(&fresh.fd)))
        .collect();
    fresh.node.shutdown();
    for m in mesh {
        m.node.shutdown();
    }
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn network_survives_seed_loss() {
    let mesh: Vec<Node> = (0..3).map(|_| node()).collect();
    for i in 0..mesh.len() {
        for j in 0..mesh.len() {
            if i != j {
                mesh[i].node.dial(mesh[j].addr);
            }
        }
    }
    let fresh = node();
    fresh.node.dial(mesh[0].addr);

    let mut all: Vec<&Node> = mesh.iter().collect();
    all.push(&fresh);
    let unseen: Vec<SocketAddr> = mesh[1..].iter().map(|n| n.addr).collect();
    assert!(
        settle(&all, 1_600, || unseen
            .iter()
            .filter(|a| fresh.connected_to(a))
            .count()
            >= 1),
        "the fresh node never reached past its seed"
    );

    let seed_addr = mesh[0].addr;
    let mut mesh = mesh;
    let seed = mesh.remove(0);
    let seed_fd = Arc::clone(&seed.fd);
    seed.node.shutdown();
    assert_eq!(seed_fd.total_open(), 0);

    let mut rest: Vec<&Node> = mesh.iter().collect();
    rest.push(&fresh);

    let rounds = (DIAL_RETRY_MS * 2 / TICK_MS) as usize;
    let alive = settle(&rest, rounds, || {
        fresh.outbound() >= 1 && !fresh.connected_to(&seed_addr)
    });
    assert!(
        alive,
        "seed gone, node holds {} outbound peers",
        fresh.outbound()
    );

    drop(rest);
    let fds: Vec<Arc<FdBudget>> = mesh
        .iter()
        .map(|n| Arc::clone(&n.fd))
        .chain(std::iter::once(Arc::clone(&fresh.fd)))
        .collect();
    fresh.node.shutdown();
    for m in mesh {
        m.node.shutdown();
    }
    for f in fds {
        assert_eq!(f.total_open(), 0, "descriptors leaked");
    }
}

#[test]
fn getaddr_once_then_banned() {
    let n = node();

    for i in 1..=20u8 {
        n.node.learn(SocketAddr::from(([127, 9, 0, i], 9256)));
    }
    assert_book_is_loopback(&n);
    let mut raw = Raw::connect(n.addr).expect("connect");
    assert!(raw.handshake(0xBEEF, 40_000).is_some(), "handshake failed");

    raw.send(&Msg::GetAddr).expect("getaddr");
    let first = raw.wait_for(|m| matches!(m, Msg::Addr(_)), 10_000);
    let Some(Msg::Addr(recs)) = first else {
        panic!("the first GETADDR was not answered at all");
    };
    assert!(
        !recs.is_empty(),
        "first GETADDR answered with an empty ADDR (v1 regression)"
    );

    raw.send(&Msg::GetAddr).expect("getaddr 2");
    assert!(
        raw.wait_for(|m| matches!(m, Msg::Addr(_)), 2_000).is_none(),
        "a second GETADDR on the same connection was answered; 4.3 allows one"
    );

    for _ in 0..(GETADDR_ABUSE_MAX + 2) {
        let _ = raw.send(&Msg::GetAddr);
    }
    let closed = {
        let deadline = Instant::now() + Duration::from_millis(10_000);
        let mut buf = [0u8; 1024];

        loop {
            match raw.s.read(&mut buf) {
                Ok(0) => break true,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break true,
                Ok(_) => {}
            }
            if Instant::now() >= deadline {
                break false;
            }
        }
    };
    assert!(
        closed,
        "a peer sent {} GETADDRs down one connection and was still connected",
        GETADDR_ABUSE_MAX + 3
    );
    assert!(
        !n.node.net().bans.lock().expect("bans").is_empty(),
        "the abuse ladder closed the socket without banning; 9 prices the \
         repeat at 20 points and bans at 100, and 5 repeats is that ladder"
    );

    let fd = Arc::clone(&n.fd);
    n.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn unsolicited_addr_capped() {
    let n = node();
    let before = n.node.net().addr_count();
    let mut raw = Raw::connect(n.addr).expect("connect");
    assert!(raw.handshake(0xBEE1, 40_001).is_some());

    let recs: Vec<AddrRec> = (0..200u32)
        .map(|i| AddrRec {
            time: BASE_TIME,
            services: 1,
            ip: v4(127, 9, (i >> 8) as u8, (i & 0xff) as u8),
            port: 9256,
        })
        .collect();
    raw.send(&Msg::Addr(recs)).expect("addr");

    for _ in 0..40 {
        n.step(TICK_MS);
        std::thread::sleep(Duration::from_millis(4));
    }
    let learned = n.node.net().addr_count() - before;

    assert!(
        learned <= ADDR_UNSOLICITED_MAX + 1,
        "inbound peer pushed 200 unasked addrs, {} landed; cap is {}",
        learned,
        ADDR_UNSOLICITED_MAX
    );
    assert!(
        learned >= ADDR_UNSOLICITED_MAX,
        "only {} of an unsolicited ADDR landed; the cap is a cap, not a refusal",
        learned
    );

    let fd = Arc::clone(&n.fd);
    n.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn inbound_booked_at_advertised_port() {
    let n = node();
    let mut raw = Raw::connect(n.addr).expect("connect");
    assert!(raw.handshake(0xBEE2, 41_234).is_some());
    for _ in 0..20 {
        n.step(TICK_MS);
        std::thread::sleep(Duration::from_millis(4));
    }
    let known = n
        .node
        .net()
        .addrs
        .lock()
        .expect("addrs")
        .get(
            &ip_bytes(&SocketAddr::from(([127, 0, 0, 1], 41_234))),
            41_234,
        )
        .is_some();
    assert!(
        known,
        "inbound peer advertising listen_port=41234 did not enter the book"
    );

    let n2 = node();
    let mut raw2 = Raw::connect(n2.addr).expect("connect");
    assert!(raw2.handshake(0xBEE3, 0).is_some());
    for _ in 0..20 {
        n2.step(TICK_MS);
        std::thread::sleep(Duration::from_millis(4));
    }
    assert_eq!(
        n2.node.net().addr_count(),
        0,
        "a peer that said `listen_port = 0` was put in the book anyway"
    );

    for x in [n, n2] {
        let fd = Arc::clone(&x.fd);
        x.node.shutdown();
        assert_eq!(fd.total_open(), 0);
    }
}

#[test]
fn node_refuses_own_addr() {
    let n = node();
    let me = n.addr;
    let mut raw = Raw::connect(n.addr).expect("connect");
    assert!(raw.handshake(0xBEE4, 40_002).is_some());
    raw.send(&Msg::Addr(vec![AddrRec {
        time: BASE_TIME,
        services: 1,
        ip: ip_bytes(&me),
        port: me.port(),
    }]))
    .expect("addr");
    for _ in 0..30 {
        n.step(TICK_MS);
        std::thread::sleep(Duration::from_millis(4));
    }
    assert!(
        n.node
            .net()
            .addrs
            .lock()
            .expect("addrs")
            .get(&ip_bytes(&me), me.port())
            .is_none(),
        "node booked its own listening address from a peer (wastes a dial before the HELLO nonce catches it)"
    );
    let fd = Arc::clone(&n.fd);
    n.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn pipelined_request_not_dropped() {
    let n = node();
    for i in 1..=5u8 {
        n.node.learn(SocketAddr::from(([127, 9, 0, i], 9256)));
    }
    assert_book_is_loopback(&n);

    let mut raw = Raw::connect(n.addr).expect("connect");
    raw.send(&Msg::Hello(Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: CHAIN_ID,
        services: SERVICE_FULL_RELAY,
        nonce: 0xB00C,
        time: BASE_TIME,
        height: 0,
        tip_hash: [0u8; 32],
        cum_work: [0u8; 32],
        listen_port: 40_100,
        user_agent: b"raw/1".to_vec(),
    }))
    .expect("hello");
    assert!(
        raw.wait_for(|m| matches!(m, Msg::Hello(_)), 10_000)
            .is_some(),
        "no HELLO from the node"
    );

    raw.send_together(&Msg::HelloAck, &Msg::GetAddr)
        .expect("ack+getaddr");

    let answered = raw.wait_for(|m| matches!(m, Msg::Addr(_)), 10_000);
    assert!(
        answered.is_some(),
        "closed the connection on a peer that pipelined its first request behind HELLO_ACK (a post-handshake frame wrongly scored as PreHello)"
    );
    let fd = Arc::clone(&n.fd);
    n.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn gossip_cost_bounded() {
    let now = 1_800_000_000u64;
    let mut am = AddrMan::new();

    'fill: for s in 0..64u32 {
        let src = grp(20, s as u8);
        for i in 0..ADDR_PER_SOURCE_GROUP_MAX as u32 {
            let ip = v4(
                40 + (s >> 4) as u8,
                (s & 0xf) as u8,
                (i >> 8) as u8,
                (i & 0xff) as u8,
            );
            if am.add_from_peer(ip, 9256, 1, now, src, now, false) != Ingest::Added {
                continue 'fill;
            }
            if am.count(Table::New) >= ADDR_NEW_MAX {
                break 'fill;
            }
        }
    }
    assert_eq!(am.count(Table::New), ADDR_NEW_MAX, "fixture did not fill");

    let reps = 200u32;

    let recs512: Vec<AddrRec> = (0..ADDR_MSG_MAX as u32)
        .map(|i| AddrRec {
            time: now,
            services: 1,
            ip: v4(200, (i >> 8) as u8, (i & 0xff) as u8, 9),
            port: 9256,
        })
        .collect();
    let m = Msg::Addr(recs512);
    let t = Instant::now();
    for _ in 0..reps {
        let f = encode_frame(&MAGIC_MAIN, m.cmd(), &encode(&m));
        assert_eq!(f.len(), FRAME_HEADER_BYTES + CAP_ADDR);
    }
    let base_ns = (t.elapsed().as_nanos() as u64 / reps as u64).max(1);

    let mut rng = Rng::new(9);
    let t = Instant::now();
    for _ in 0..reps {
        let out = am.sample(ADDR_MSG_MAX, now, &mut rng, false);
        assert_eq!(out.len(), ADDR_MSG_MAX);
    }
    let sample_ns = t.elapsed().as_nanos() as u64 / reps as u64;

    let addrs: Vec<([u8; 16], u16)> = (0..ADDR_MSG_MAX as u32)
        .map(|i| (v4(200, (i >> 8) as u8, (i & 0xff) as u8, 9), 9256u16))
        .collect();
    let src = grp(203, 9);
    let t = Instant::now();
    for _ in 0..reps {
        for (ip, port) in &addrs {
            let _ = am.add_from_peer(*ip, *port, 1, now, src, now, false);
        }
    }
    let ingest_ns = t.elapsed().as_nanos() as u64 / reps as u64;

    println!(
        "baseline(encode 512 ADDR) {base_ns} ns | sample {sample_ns} ns = {}x |          ingest(512) {ingest_ns} ns = {}x",
        sample_ns / base_ns,
        ingest_ns / base_ns
    );
    assert!(
        sample_ns < base_ns * 12,
        "GETADDR sampling costs {}x the encode; a full-book walk would blow this",
        sample_ns / base_ns
    );
    assert!(
        ingest_ns < base_ns * 60,
        "ADDR ingest costs {}x the encode; a linear lookup per record would blow this",
        ingest_ns / base_ns
    );
}

#[test]
fn maintenance_reaps_stale() {
    let n = node();
    let now_unix = n.node.net().clock.now_unix();
    {
        let mut am = n.node.net().addrs.lock().expect("addrs");

        am.add(
            v4(127, 9, 0, 1),
            9256,
            false,
            now_unix - ADDR_MAX_AGE_SECS - 3_600,
        );
        am.add(v4(127, 9, 0, 2), 9256, false, now_unix);
        assert_eq!(am.len(), 2, "fixture");
    }
    assert_book_is_loopback(&n);

    let rounds = (CONN_MANAGER_TICK_MS * 2 / TICK_MS) as usize;
    let reaped = settle(&[&n], rounds, || {
        n.node
            .net()
            .addrs
            .lock()
            .expect("addrs")
            .get(&v4(127, 9, 0, 1), 9256)
            .is_none()
    });
    assert!(
        reaped,
        "address {} days stale survived {} maintenance passes; nothing else frees a `new` slot",
        (ADDR_MAX_AGE_SECS + 3_600) / 86_400,
        rounds as u64 * TICK_MS / CONN_MANAGER_TICK_MS
    );
    assert!(
        n.node
            .net()
            .addrs
            .lock()
            .expect("addrs")
            .get(&v4(127, 9, 0, 2), 9256)
            .is_some(),
        "the reaper took a fresh address too"
    );

    let fd = Arc::clone(&n.fd);
    n.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn chain_id_judged_against_config() {
    let node = node_on(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        P2pConfig {
            chain_id: FOREIGN_CHAIN_ID,
            ..gossip_cfg()
        },
    );

    let mut probe = Raw::connect(node.addr).expect("connect");
    let (theirs, acked_wrong) = probe.handshake_claiming(CHAIN_ID, 0xA1);
    let theirs = theirs.expect("the node must send its own HELLO before judging ours");
    assert_eq!(
        theirs.chain_id, FOREIGN_CHAIN_ID,
        "a node configured for {:?} announced {:?}",
        FOREIGN_CHAIN_ID, theirs.chain_id
    );

    assert!(
        !acked_wrong,
        "a node on {:?} completed a handshake with a peer claiming {:?}",
        FOREIGN_CHAIN_ID, CHAIN_ID
    );
    drop(probe);
    for _ in 0..20 {
        node.step(TICK_MS);
    }
    assert_eq!(node.node.peer_count(), 0, "the foreign peer became a peer");

    let mut ok = Raw::connect(node.addr).expect("connect");
    let (theirs2, acked_right) = ok.handshake_claiming(FOREIGN_CHAIN_ID, 0xA2);
    assert_eq!(theirs2.expect("hello").chain_id, FOREIGN_CHAIN_ID);
    assert!(
        acked_right,
        "the node refused a peer claiming its own chain id, so (2) proves nothing"
    );

    drop(ok);
    let fd = Arc::clone(&node.fd);
    node.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn own_addr_not_reloaded() {
    let node = node_on(SocketAddr::from(([127, 0, 0, 1], 0)), gossip_cfg());
    let me = node.addr;
    let other = SocketAddr::from(([127, 0, 0, 9], 9256));

    let recs = vec![
        plaine_p2p::addr::PeerRec {
            ip: ip_bytes(&me),
            port: me.port(),
            services: 0,
            last_seen: node.clock.now_unix(),
            table: plaine_p2p::addr::Table::Tried,
            source_group: [10, 0, 0, 0],
        },
        plaine_p2p::addr::PeerRec {
            ip: ip_bytes(&other),
            port: other.port(),
            services: 0,
            last_seen: node.clock.now_unix(),
            table: plaine_p2p::addr::Table::New,
            source_group: [10, 0, 0, 0],
        },
    ];

    let mut donor = plaine_p2p::addr::AddrMan::new();
    donor.restore(
        &recs,
        node.clock.now_unix(),
        true,
        &mut plaine_p2p::rng::Rng::new(1),
    );
    assert_eq!(donor.len(), 2, "the donor book did not build");
    let bytes = plaine_p2p::addr::persist::encode(donor.entries(), gossip_cfg().chain_id);

    let st = node
        .node
        .net()
        .load_addrs(&bytes)
        .expect("our own file decodes");
    assert_eq!(st.loaded, 1, "the reload took {} records, not 1", st.loaded);
    assert!(
        !node.knows(&me),
        "the node reloaded its own listening address out of peers.dat"
    );
    assert!(
        node.knows(&other),
        "the reload dropped the address that was not ours"
    );
    assert_book_is_loopback(&node);

    let fd = Arc::clone(&node.fd);
    node.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn checkpoint_unknown_key_unsigned() {
    let n = node_on(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        P2pConfig {
            authority_keys: vec![[0xA1u8; 32]],
            ..gossip_cfg()
        },
    );
    let mut raw = Raw::connect(n.addr).expect("connect");
    assert!(raw.handshake(0xC0DE, 0).is_some(), "handshake failed");

    raw.send(&Msg::Checkpoint(plaine_p2p::wire::msg::CheckpointMsg {
        height: 4_100,
        hash: [0x11; 32],
        sigs: vec![(0u8, [0x22; 64])],
    }))
    .expect("send");
    assert!(
        settle(&[&n], 200, || n.chain.checkpoints_seen() >= 1),
        "the CHECKPOINT never reached the sink at all"
    );
    assert_eq!(
        n.chain.checkpoint_sigs(),
        1,
        "a signature by a key we hold was dropped"
    );

    raw.send(&Msg::Checkpoint(plaine_p2p::wire::msg::CheckpointMsg {
        height: 4_200,
        hash: [0x33; 32],
        sigs: vec![(7u8, [0x44; 64])],
    }))
    .expect("send");
    assert!(
        settle(&[&n], 200, || n.chain.checkpoints_seen() >= 2),
        "the second CHECKPOINT never reached the sink"
    );
    assert_eq!(
        n.chain.checkpoint_sigs(),
        0,
        "a signature by key_id 7 against a one-key configuration was carried through, so \
         `sigs.len()` is a number the sender picks"
    );

    drop(raw);
    let fd = Arc::clone(&n.fd);
    n.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}

#[test]
fn getcheckpoint_flood_disconnects() {
    let n = node();
    let mut raw = Raw::connect(n.addr).expect("connect");
    assert!(raw.handshake(0xC0DF, 0).is_some(), "handshake failed");
    for _ in 0..(GETCHECKPOINT_PER_CONN + GETCHECKPOINT_ABUSE_MAX + 2) {
        let _ = raw.send(&Msg::GetCheckpoint);
    }
    let closed = {
        let deadline = Instant::now() + Duration::from_millis(10_000);
        let mut buf = [0u8; 1024];

        loop {
            match raw.s.read(&mut buf) {
                Ok(0) => break true,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break true,
                Ok(_) => {}
            }
            if Instant::now() >= deadline {
                break false;
            }
        }
    };
    assert!(
        closed,
        "{} GETCHECKPOINTs down one socket cost the sender nothing",
        GETCHECKPOINT_PER_CONN + GETCHECKPOINT_ABUSE_MAX + 2
    );
    let fd = Arc::clone(&n.fd);
    n.node.shutdown();
    assert_eq!(fd.total_open(), 0);
}
