use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::*;
use plaine_p2p::mock::{Behaviour, MockBits, MockChain, MockClock, MockPow, Sim};
use plaine_p2p::net::{NetNode, NetOptions, TickMode};
use plaine_p2p::peer::score::Offence;
use plaine_p2p::peer::session::Session;
use plaine_p2p::sync::body_track::{BodyAction, BodyTrack, Supplier};
use plaine_p2p::sync::{Action, SyncEngine};
use plaine_p2p::traits::{Clock, Hash32, Mono, PeerId};
use plaine_p2p::wire::codec::{decode, encode};
use plaine_p2p::wire::frame::{encode_frame, FrameReader};
use plaine_p2p::wire::msg::{Hello, Msg};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

const T0: u64 = 1_800_000_000;

fn h(n: u8) -> Hash32 {
    let mut x = [0u8; 32];
    x[0] = n;
    x
}

#[test]
fn hello_ack_alone_in_burst() {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let clock = Arc::new(MockClock::new(T0));
    let chain = Arc::new(MockChain::linear(1, T0, 1));
    let cfg = P2pConfig {
        isolated: false,
        accept_local_addrs: true,
        ..P2pConfig::default()
    };
    let engine = SyncEngine::new(
        Arc::clone(&chain),
        Arc::clone(&chain),
        Arc::new(MockPow::all_valid()),
        Arc::new(MockBits),
        cfg.clone(),
        0xF00D,
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
    .expect("start");
    node.dial(addr);

    let (mut s, _) = listener.accept().expect("accept");
    s.set_nodelay(true).expect("nodelay");
    s.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");

    let ours = Msg::Hello(Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: CHAIN_ID,
        services: SERVICE_FULL_RELAY,
        nonce: 0x1234_5678_9abc_def0,
        time: T0,
        height: 0,
        tip_hash: [0u8; 32],
        cum_work: [0u8; 32],
        listen_port: addr.port(),
        user_agent: b"raw/1".to_vec(),
    });
    s.write_all(&encode_frame(
        &cfg_magic(),
        ours.cmd(),
        &encode(&ours),
    ))
    .expect("hello");

    let mut fr = FrameReader::new(cfg_magic());
    let mut buf = vec![0u8; 8192];
    let mut acked_at: Option<Instant> = None;
    let mut after_ack: Vec<Msg> = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(HANDSHAKE_QUIET_MS * 8 + 2_000);

    while Instant::now() < deadline {
        node.tick();
        let n = match s.read(&mut buf) {
            Ok(0) => panic!(
                "the node closed the connection during the handshake - this rig \
                 is the honest acceptor, so a close here is a fixture fault"
            ),
            Ok(n) => n,
            Err(_) => continue,
        };
        for (cmd, payload) in fr.push(&buf[..n]).expect("frames") {
            let m = decode(cmd, &payload).expect("decode");
            match (&m, acked_at) {
                (Msg::HelloAck, None) => {
                    acked_at = Some(Instant::now());

                    s.write_all(&encode_frame(&cfg_magic(), Msg::HelloAck.cmd(), &[]))
                        .expect("ack");
                }
                (_, Some(_)) => after_ack.push(m),
                _ => {}
            }
        }
        if acked_at.is_some() && !after_ack.is_empty() {
            break;
        }
    }

    let acked = acked_at.expect("the node never sent HELLO_ACK");
    let quiet = Duration::from_millis(HANDSHAKE_QUIET_MS / 2);
    let gap = acked.elapsed();

    node.shutdown();

    assert!(
        after_ack.is_empty() || gap >= quiet,
        "the node put {:?} on the wire {:?} after its own HELLO_ACK. Anything \
         inside one RTT of the ack lands in the same read on the far side, and \
         every peer running a release older than this one answers a second \
         frame in that read with Offence::PreHello and closes the socket. \
         Measured against the live fleet, that cost 100% of connections and a \
         fresh node obtained zero peers.",
        after_ack.first(),
        gap
    );
}

fn cfg_magic() -> [u8; 4] {
    P2pConfig::default().magic
}

#[test]
fn released_slot_body_still_requested() {
    let now = Mono(10_000);
    let mut b = BodyTrack::new(0);
    let peer = PeerId(1);
    let wanted = [(1u64, h(1))];
    let acts = b.schedule(&wanted, &[Supplier { id: peer, horizon: 10 }], now);
    assert!(
        matches!(acts.first(), Some(BodyAction::Request { .. })),
        "fixture: nothing was requested, so this test cannot see the defence"
    );
    assert!(b.is_inflight(&h(1)), "fixture: the hash is not in flight");

    b.release_peer(peer, now);
    assert!(
        !b.is_inflight(&h(1)),
        "releasing the slot must still free the hash for another supplier - \
         that is what the release is for, and keeping the record would trade \
         one defect for a stall"
    );

    let known = b.on_body(h(1), vec![0u8; 8], 1, now);
    assert!(
        known,
        "a body we requested was reported unrequested right after the request was released; the caller scores that as UnsolicitedBody and bans an honest seed"
    );
}

#[test]
fn tail_forgives_only_requested() {
    let now = Mono(10_000);
    let mut b = BodyTrack::new(0);
    assert!(
        !b.on_body(h(9), vec![0u8; 8], 1, now),
        "a hash never requested must stay unrequested, or the score table has \
         no unsolicited-body rule at all"
    );

    let mut b = BodyTrack::new(0);
    let peer = PeerId(1);
    b.schedule(&[(1u64, h(1))], &[Supplier { id: peer, horizon: 10 }], now);
    b.release_peer(peer, now);
    let late = Mono(now.0 + BODY_INFLIGHT_TAIL_MS + 1);
    assert!(
        !b.on_body(h(1), vec![0u8; 8], 1, late),
        "the tail must expire: an unbounded one is an unbounded exemption, and \
         the rule says sixty seconds"
    );
}

#[test]
fn honest_ibd_scores_nothing() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(WANTED_MAX as u64 * 3);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(600_000, 250);

    let designations = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Designate { .. }))
        .count();
    let offences: Vec<Offence> = sim
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::Score { offence, .. } => Some(*offence),
            _ => None,
        })
        .filter(|o| o.points() > 0)
        .collect();

    assert!(
        sim.engine.body.applied() > WANTED_MAX as u64,
        "fixture: the body track only reached {}, so this run never had a \
         window's worth of bodies in flight and proves nothing",
        sim.engine.body.applied()
    );
    assert!(
        designations >= 1,
        "fixture: nobody was ever designated, so the release path never ran"
    );
    assert!(
        offences.is_empty(),
        "an honest peer that served this node its entire chain was charged {:?}. \
         Against the live fleet one such peer finished a single IBD on 84 of the \
         100 points that ban it, with no attacker anywhere on the network.",
        offences
    );
}

#[test]
fn no_repeat_designation() {
    let mut sim = Sim::new(1, T0);
    let tall = sim.extension(WANTED_MAX as u64 * 3);
    let short: Vec<_> = tall.iter().take(16).cloned().collect();
    let p = sim.add_peer(Behaviour::Honest, short);
    sim.connect(p);
    sim.run(20_000, 250);
    let q = sim.add_peer(Behaviour::Honest, tall);
    sim.connect(q);
    sim.run(600_000, 250);

    let designated: Vec<PeerId> = sim
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::Designate { peer } => Some(*peer),
            _ => None,
        })
        .collect();
    assert!(
        designated.len() >= 2,
        "fixture: only {} designation(s), so the catch-up clause never fired and a repeat could not have been observed either way",
        designated.len()
    );
    for w in designated.windows(2) {
        assert_ne!(
            w[0], w[1],
            "peer {:?} was designated twice in a row out of {} designations. \
             The role flags the action sets are already set, so the repeat \
             changes nothing except calling BodyTrack::release_peer again.",
            w[0],
            designated.len()
        );
    }
}

#[test]
fn third_disconnected_batch_costs() {
    let now = Mono(1_000_000);
    let mut s = Session::new(PeerId(1), [0u8; 16], true, now);

    assert!(
        !s.note_disconnected_batch(now),
        "the first non-linking batch during IBD is an answer to a locator we \
         replaced while it was in flight - our race, not the peer's fault"
    );
    assert!(!s.note_disconnected_batch(now), "nor is the second");
    assert!(
        s.note_disconnected_batch(now),
        "the third within ten minutes is chargeable. A rule that \
         never charges is not a rate limit, it is a deletion."
    );

    let later = Mono(now.0 + DISCONNECTED_BATCH_WINDOW_MS + 1);
    assert!(
        !s.note_disconnected_batch(later),
        "the count must reset after DISCONNECTED_BATCH_WINDOW_MS, or three \
         batches spread over a day ban a peer that did nothing wrong"
    );
}

#[test]
fn disconnected_batch_priced() {
    assert_eq!(
        Offence::DisconnectedBatches.points(),
        10,
        "disconnected header batches = 10"
    );
    assert_eq!(
        Offence::UnsolicitedHeaders.points(),
        20,
        "unsolicited HEADERS count>8 = 20"
    );
    assert_eq!(
        plaine_p2p::gate::Rejection::UnsolicitedAnswer.offence(),
        Some(Offence::DisconnectedBatches),
        "G1's UnsolicitedAnswer IS a disconnected batch. Mapping it to \
         UnsolicitedHeaders charged twenty points on the first one and left \
         DisconnectedBatches a variant nothing could ever emit."
    );
}

#[test]
fn first_disconnected_batch_free() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(4_000);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);

    for _ in 0..400 {
        sim.step(50);
        if sim.engine.header.staging.staged_len() > 0 && sim.sync_peer() == Some(p) {
            break;
        }
    }
    assert!(
        sim.engine.header.staging.staged_len() > 0,
        "fixture: staging is empty, so G1 applies no linkage check and no batch \
         can be disconnected"
    );
    assert_eq!(
        sim.sync_peer(),
        Some(p),
        "fixture: the batch must come from the designated peer or the other \
         arm of `on_headers` runs instead"
    );

    let bogus: Vec<[u8; HEADER_BYTES]> = sim.fork(1_000, 4, 77).iter().map(|h| h.raw).collect();
    let before = sim.actions.len();
    for _ in 0..2 {
        sim.engine_event(plaine_p2p::sync::Event::Headers {
            peer: p,
            raw: bogus.clone(),
        });
    }
    let scored: Vec<Offence> = sim.actions[before..]
        .iter()
        .filter_map(|a| match a {
            Action::Score { peer, offence } if *peer == p => Some(*offence),
            _ => None,
        })
        .collect();
    assert!(
        scored.is_empty(),
        "first two disconnected batches cost the peer {:?}; a designation refresh races the in-flight answer, so batch one is our fault, not the peer's",
        scored
    );

    sim.engine_event(plaine_p2p::sync::Event::Headers {
        peer: p,
        raw: bogus,
    });
    let scored: Vec<Offence> = sim.actions[before..]
        .iter()
        .filter_map(|a| match a {
            Action::Score { peer, offence } if *peer == p => Some(*offence),
            _ => None,
        })
        .collect();
    assert_eq!(
        scored,
        vec![Offence::DisconnectedBatches],
        "the third must be charged, and charged as a disconnected batch. A \
         rule that never charges is not a rate limit, it is a deletion."
    );
}
