use plaine_p2p::constants::*;
use plaine_p2p::gate::{admit, Rejection};
use plaine_p2p::mock::{Behaviour, Rng, Sim};
use plaine_p2p::peer::inbox::{Inbox, PauseCause};
use plaine_p2p::peer::score::{Offence, Score, Verdict};
use plaine_p2p::peer::{HandshakeOutcome, HelloCheck, Session};
use plaine_p2p::sync::header_track::HState;
use plaine_p2p::sync::{Action, DeadReason, Event};
use plaine_p2p::traits::*;
use plaine_p2p::wire::msg::Hello;

const T0: u64 = 1_800_000_000;

#[test]
fn silent_sync_peer_no_stall() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(500);
    let silent = sim.add_peer(Behaviour::Silent, chain.clone());
    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(silent);
    sim.connect(honest);

    sim.run(5_000, 1_000);
    assert_eq!(
        sim.sync_peer(),
        Some(silent),
        "test precondition: the silent peer must be designated first"
    );
    assert_eq!(
        sim.engine.verified_height(),
        0,
        "the silent peer served nothing"
    );

    sim.run(60_000, 1_000);
    assert_eq!(
        sim.engine.verified_height(),
        500,
        "sync did not recover from a silent designated peer within 60 s"
    );
    assert_ne!(
        sim.sync_peer(),
        Some(silent),
        "the silent peer was not rotated out"
    );
}

#[test]
fn trickle_peer_is_rotated_by_the_rate_floor() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(500);
    let trickle = sim.add_peer(Behaviour::Trickle { n: 1 }, chain.clone());
    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(trickle);
    sim.connect(honest);

    sim.run(4_000, 1_000);
    assert_eq!(sim.sync_peer(), Some(trickle), "test precondition");

    sim.run(SYNC_RATE_WINDOW_MS + 10_000, 1_000);
    assert_ne!(
        sim.sync_peer(),
        Some(trickle),
        "a peer delivering 10 headers per 10 s stayed designated"
    );
    let s = sim.engine.peers().get(&trickle);
    if let Some(s) = s {
        assert!(
            !s.sync_eligible(sim.now()),
            "the trickling peer was not made sync-ineligible"
        );
    }

    sim.run(120_000, 1_000);
    assert_eq!(
        sim.engine.verified_height(),
        500,
        "sync did not complete after rotating away from the trickle"
    );
}

#[test]
fn staging_survives_rotation() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(4_000);
    let mut ids = Vec::new();
    for _ in 0..5 {
        ids.push(sim.add_peer(Behaviour::Honest, chain.clone()));
    }
    for id in &ids {
        sim.connect(*id);
    }

    let mut last_verified = 0u64;
    for _ in 0..5 {
        sim.run(6_000, 1_000);
        let v = sim.engine.verified_height();
        assert!(
            v >= last_verified,
            "verified height went backwards across a rotation: {} -> {}",
            last_verified,
            v
        );
        last_verified = v;

        if let Some(p) = sim.sync_peer() {
            sim.kill(p);
        }
    }
    sim.run(60_000, 1_000);
    assert_eq!(sim.engine.verified_height(), 4_000);
    assert!(
        sim.headers_served_total() < 4_000 + 5 * MAX_HEADERS_PER_MSG as u64,
        "{} headers were served for a 4,000-header chain across 5 rotations - \
         staging is being discarded",
        sim.headers_served_total()
    );
}

#[test]
fn liveness_survives_peer_loss() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(2_000);
    let a = sim.add_peer(Behaviour::Honest, chain.clone());
    let b = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(a);
    sim.connect(b);
    sim.run(5_000, 1_000);
    let mid = sim.engine.verified_height();
    assert!(mid > 0, "sync never started");

    sim.kill(a);
    sim.kill(b);
    sim.run(120_000, 1_000);

    assert_eq!(sim.engine.header.state(), HState::ColdStart);
    assert!(
        sim.said(|c| matches!(c, Condition::ColdStartRetry { .. })),
        "cold start did not announce itself"
    );
    assert_eq!(
        sim.engine.verified_height(),
        mid,
        "the verified prefix was discarded when the peers left"
    );

    let c = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(c);
    sim.run(120_000, 1_000);
    assert_eq!(
        sim.engine.verified_height(),
        2_000,
        "sync did not resume after a peer returned"
    );
}

#[test]
fn liveness_invariant_no_named_peer() {
    for seed in 0..24u64 {
        let mut rng = Rng::new(seed * 7919 + 1);
        let mut sim = Sim::new(1, T0);
        let chain = sim.extension(1_000);
        let mut ids = Vec::new();
        for _ in 0..4 {
            ids.push(sim.add_peer(Behaviour::Honest, chain.clone()));
        }
        for id in &ids {
            sim.connect(*id);
        }

        for _ in 0..6 {
            sim.run(1_000 + rng.below(4_000), 500);
            let victim = ids[rng.below(ids.len() as u64) as usize];
            sim.kill(victim);
        }
        for id in &ids {
            sim.connect(*id);
        }
        sim.run(300_000, 1_000);
        assert_eq!(
            sim.engine.verified_height(),
            1_000,
            "schedule seed {} left the engine short of the tip",
            seed
        );
    }
}

#[test]
fn flapping_peers_do_not_wedge_sync() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(800);
    let f1 = sim.add_peer(
        Behaviour::Flapping {
            up_ms: 4_000,
            down_ms: 3_000,
        },
        chain.clone(),
    );
    let f2 = sim.add_peer(
        Behaviour::Flapping {
            up_ms: 7_000,
            down_ms: 2_000,
        },
        chain,
    );
    sim.connect(f1);
    sim.connect(f2);
    sim.run(600_000, 1_000);
    assert_eq!(
        sim.engine.verified_height(),
        800,
        "flapping peers wedged header sync"
    );
}

#[test]
fn stale_tip_no_reorg_lift() {
    let mut sim = Sim::new(600, T0);
    let branch = sim.fork(500, 900, 42);
    let p = sim.add_peer(Behaviour::Honest, branch);
    sim.connect(p);

    sim.chain
        .set_tip_time(Some(sim.now_unix_for_test() - 7_200));
    sim.run(300_000, 1_000);

    assert_eq!(
        sim.engine.body.applied(),
        599,
        "a 500-deep unsigned reorg was applied because our own tip was old"
    );
    assert!(
        sim.said(|c| matches!(c, Condition::StrandedBeyondReorgCap { .. })),
        "the node refused the deep branch without saying why"
    );
    assert_eq!(sim.engine.fatal(), None);
}

#[test]
fn deep_reorg_no_anchor_refused() {
    let mut sim = Sim::new(600, T0);
    let branch = sim.fork(500, 900, 43);
    let p = sim.add_peer(Behaviour::Honest, branch);
    sim.connect(p);

    sim.pin_tip_time_to_now();
    sim.run(300_000, 5_000);

    assert!(
        sim.said(|c| matches!(c, Condition::StrandedBeyondReorgCap { .. })),
        "the node refused a deep reorg without saying why"
    );
    assert_eq!(
        sim.engine.body.applied(),
        599,
        "a deep reorg was applied without an anchor and with a fresh tip"
    );
}

#[test]
fn reorg_pulls_anchor_from_ahead() {
    let mut sim = Sim::new(600, T0);
    let short = sim.fork(500, 520, 44);
    let long = sim.fork(500, 900, 45);
    let near = sim.add_peer(Behaviour::Honest, short);
    let far = sim.add_peer(Behaviour::Honest, long);
    sim.connect(near);
    sim.connect(far);
    sim.pin_tip_time_to_now();
    sim.run(120_000, 1_000);

    let pulls: Vec<PeerId> = sim
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::Send {
                peer,
                msg: plaine_p2p::wire::Msg::GetCheckpoint,
            } => Some(*peer),
            _ => None,
        })
        .collect();
    assert!(!pulls.is_empty(), "no anchor pull was issued at all");
    assert_eq!(
        pulls[0], far,
        "the anchor was pulled from the wrong peer: it must go to the peer \
         with the highest claimed height, not an arbitrary one"
    );
}

#[test]
fn all_bad_recovers_empty_addrman() {
    use plaine_p2p::addr::AddrMan;
    let mut am = AddrMan::new();
    assert!(am.is_empty());

    am.add([1u8; 16], 9256, true, 0);
    am.on_handshake_ok(&[1u8; 16], 9256, 0);
    for _ in 0..DEMOTE_AFTER_FAILURES {
        am.on_failure(&[1u8; 16], 9256, false);
    }
    assert_eq!(
        am.get(&[1u8; 16], 9256).map(|e| e.table),
        Some(plaine_p2p::addr::Table::New),
        "a failing seed was not demoted - the protected-seed-never-ages-out bug"
    );

    am.clear();
    assert!(am.is_empty());
    assert!(
        am.seeds_still_privileged(),
        "an empty book must re-read its seeds"
    );

    let mut sim = Sim::new(10, T0);
    sim.run(600_000, 10_000);
    assert_eq!(sim.engine.header.state(), HState::ColdStart);
    let retries = sim
        .engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::ColdStartRetry { .. }))
        .count();
    assert!(retries >= 3, "cold start gave up after {} retries", retries);
}

#[test]
fn admission_mirrors_fork_choice() {
    let mut rng = Rng::new(0xDEAD_BEEF);
    for _ in 0..10_000 {
        let mut ours = Work::ZERO;
        let mut cand = Work::ZERO;
        ours.0[0] = rng.below(64);
        cand.0[0] = if rng.below(4) == 0 {
            ours.0[0]
        } else {
            rng.below(64)
        };
        let mut our_tip = [0u8; 32];
        let mut cand_tip = [0u8; 32];
        rng.fill(&mut our_tip);
        rng.fill(&mut cand_tip);
        let height = 1_000 + rng.below(10);
        let depth = rng.below(3);

        let verdict = admit(&cand, &ours, &cand_tip, height, &our_tip, height, depth);

        let expect_ok = cand > ours || (cand == ours && depth == 1 && cand_tip < our_tip);
        assert_eq!(
            verdict.is_ok(),
            expect_ok,
            "admission disagreed with fork choice: cand {:?} ours {:?} depth {}",
            cand.0[0],
            ours.0[0],
            depth
        );

        if let Err(rej) = verdict {
            assert!(matches!(rej, Rejection::LessWork | Rejection::TieBreakLost));
            let o = rej.offence().expect("fork-choice outcomes are typed");
            assert_eq!(o.points(), 0, "a losing fork was scored as misbehaviour");
        }
    }
}

#[test]
fn fork_choice_deterministic() {
    let mut rng = Rng::new(99);
    for _ in 0..10_000 {
        let mut a = Work::ZERO;
        let mut b = Work::ZERO;
        a.0[0] = rng.below(16);
        b.0[0] = rng.below(16);
        let mut ah = [0u8; 32];
        let mut bh = [0u8; 32];
        rng.fill(&mut ah);
        rng.fill(&mut bh);
        let first = admit(&a, &b, &ah, 10, &bh, 10, 1).is_ok();
        for _ in 0..3 {
            assert_eq!(admit(&a, &b, &ah, 10, &bh, 10, 1).is_ok(), first);
        }
    }
}

#[test]
fn rejected_headers_cached_globally() {
    let mut sim = Sim::new(1, T0);
    let forged = sim.extension(50);
    let mut liars = Vec::new();
    for _ in 0..8 {
        liars.push(sim.add_liar(forged.clone(), 5_000));
    }
    for l in &liars {
        sim.connect(*l);
    }
    sim.run(120_000, 1_000);
    assert!(
        sim.engine.interpreter_calls() <= 8,
        "{} interpreter calls for one rejected branch offered by 8 peers",
        sim.engine.interpreter_calls()
    );
    assert!(
        !sim.engine.reject_cache().is_empty(),
        "the rejected branch was not memoised at all"
    );
}

#[test]
fn quarantine_is_never_node_wide() {
    use plaine_p2p::sync::recovery::Quarantine;
    let mut q = Quarantine::new();
    let doomed = [9u8; 32];
    let good = [8u8; 32];
    q.insert(doomed, vec![PeerId(1)], Mono(0));
    assert!(q.contains(&doomed, Mono(0)));
    assert!(
        !q.contains(&good, Mono(0)),
        "quarantining one branch must not quarantine another"
    );

    for i in 0..(QUARANTINE_MAX as u64 + 50) {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        q.insert(h, vec![], Mono(0));
    }
    assert!(q.len() <= QUARANTINE_MAX, "quarantine set is unbounded");

    let expired = Mono(QUARANTINE_MS + 1);
    assert!(!q.contains(&doomed, expired), "quarantine never expires");
}

#[test]
fn tip_serve_no_block_on_validator() {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    let (pub_, rdr) = plaine_p2p::tip::channel(TipSnapshot::default());
    let control = std::sync::Arc::new(Mutex::new(0u64));

    let held = control.clone();
    let guard = held.lock().expect("control lock");
    assert!(
        control.try_lock().is_err(),
        "control path did not actually block - the test would prove nothing"
    );

    let readers: Vec<_> = (0..128)
        .map(|_| {
            let r = rdr.clone();
            std::thread::spawn(move || {
                let mut n = 0u64;
                for _ in 0..2_000 {
                    n = n.wrapping_add(r.tip().height);
                }
                n
            })
        })
        .collect();
    let start = Instant::now();
    for i in 1..=2_000u64 {
        pub_.publish(TipSnapshot {
            height: i,
            ..TipSnapshot::default()
        });
    }
    let elapsed = start.elapsed();
    for t in readers {
        let _ = t.join();
    }
    drop(guard);
    assert!(
        elapsed < Duration::from_secs(2),
        "publishing 2,000 tips behind 128 readers took {:?}",
        elapsed
    );
    assert_eq!(rdr.tip().height, 2_000);
}

#[test]
fn fd_budget_adds_up() {
    assert_eq!(
        FD_TOTAL,
        FD_PEERS
            + FD_INBOUND_HANDSHAKE
            + FD_TRANSIENT_DIALS
            + FD_LISTENERS
            + FD_RPC
            + FD_STORAGE
            + FD_SERVICE
    );
    assert_eq!(
        FD_INBOUND_HANDSHAKE,
        ACCEPT_BURST as u64 + ACCEPT_RATE_PER_SEC as u64 * HANDSHAKE_TIMEOUT_MS / 1_000,
        "the handshake row is the peak, i.e. burst + rate x deadline, not the \
         rate alone"
    );

    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            FD_TOTAL < FD_CEILING,
            "FD budget {} exceeds {}",
            FD_TOTAL,
            FD_CEILING
        );
    }
    assert_eq!(FD_TOTAL, 690);

    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            COLDSTART_DIAL_CONCURRENT < (ADDR_NEW_MAX + ADDR_TRIED_MAX) / 100,
            "the cold-start widening must relax diversity, never concurrency"
        );
    }
}

#[test]
fn no_socket_outlives_its_deadline() {
    let mut s = Session::new(PeerId(1), [1u8; 16], true, Mono(0));
    s.state = plaine_p2p::peer::PeerState::Ready;
    s.ping_sent = Some(Mono(PING_INTERVAL_MS));
    assert!(!s.pong_expired(Mono(PING_INTERVAL_MS + PONG_TIMEOUT_MS - 1)));
    assert!(s.pong_expired(Mono(PING_INTERVAL_MS + PONG_TIMEOUT_MS)));
}

#[test]
fn paused_socket_still_dies() {
    let mut s = Session::new(PeerId(1), [1u8; 16], true, Mono(0));
    s.state = plaine_p2p::peer::PeerState::Ready;
    s.ping_sent = Some(Mono(0));
    s.pause(PauseCause::CommitStall, Mono(1_000));

    assert!(!s.pong_expired(Mono(1_000 + PONG_TIMEOUT_MS + 1)));

    assert!(!s.pause_expired(Mono(1_000 + PAUSE_MAX_MS - 1)));
    assert!(s.pause_expired(Mono(1_000 + PAUSE_MAX_MS)));

    assert_eq!(s.score.value(Mono(1_000 + PAUSE_MAX_MS)), 0);
    assert_eq!(PauseCause::CommitStall.peer_points(), 0);
}

#[test]
fn rotating_pause_no_immortal_socket() {
    let mut ib = Inbox::new();
    ib.pause(PauseCause::LocalInbox, Mono(0));
    for t in (1_000..PAUSE_MAX_MS).step_by(10_000) {
        ib.pause(PauseCause::ValidateQueue, Mono(t));
        ib.pause(PauseCause::CommitStall, Mono(t + 1));
    }
    assert!(ib.pause_expired(Mono(PAUSE_MAX_MS)));
}

#[test]
fn self_dial_detected_by_nonce() {
    let chk = HelloCheck {
        chain_id: [0x50, 0x4C, 0x4E, 0x45],
        our_nonce: 0xABCD,
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        now_unix: T0,
    };
    let mut h = Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: [0x50, 0x4C, 0x4E, 0x45],
        services: SERVICE_FULL_RELAY,
        nonce: 0xABCD,
        time: T0,
        height: 1,
        tip_hash: [0u8; 32],
        cum_work: [0u8; 32],
        listen_port: PORT_P2P,
        user_agent: b"x".to_vec(),
    };
    assert_eq!(chk.judge(&h), HandshakeOutcome::SelfConnection);
    h.nonce = 1;
    assert_eq!(chk.judge(&h), HandshakeOutcome::Accept);
}

#[test]
fn wrong_chain_id_rejected_early() {
    let chk = HelloCheck {
        chain_id: [0x50, 0x4C, 0x4E, 0x45],
        our_nonce: 7,
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        now_unix: T0,
    };
    let h = Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: [0xDE, 0xAD, 0xBE, 0xEF],
        services: SERVICE_FULL_RELAY,
        nonce: 1,
        time: T0,
        height: 9_000_000,
        tip_hash: [1u8; 32],
        cum_work: [0xFF; 32],
        listen_port: PORT_P2P,
        user_agent: Vec::new(),
    };
    let verdict = chk.judge(&h);
    assert_eq!(verdict, HandshakeOutcome::ForeignNetwork);

    assert_eq!(verdict.offence(), None);
}

#[test]
fn reserved_bits_and_big_ua_faults() {
    let chk = HelloCheck {
        chain_id: [0u8; 4],
        our_nonce: 7,
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        now_unix: T0,
    };
    let base = Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: [0u8; 4],
        services: SERVICE_FULL_RELAY,
        nonce: 1,
        time: T0,
        height: 0,
        tip_hash: [0u8; 32],
        cum_work: [0u8; 32],
        listen_port: 0,
        user_agent: Vec::new(),
    };
    let mut mbz = base.clone();
    mbz.services |= 1 << 7;
    assert_eq!(chk.judge(&mbz), HandshakeOutcome::ReservedServiceBits);
    let mut long = base.clone();
    long.user_agent = vec![b'x'; UA_MAX + 1];
    assert_eq!(chk.judge(&long), HandshakeOutcome::Malformed);
    let mut old = base;
    old.min_proto = PROTO_VER + 1;

    assert_eq!(chk.judge(&old), HandshakeOutcome::VersionMismatch);
    assert_eq!(HandshakeOutcome::VersionMismatch.offence(), None);
}

#[test]
fn ban_list_is_bounded_and_expires() {
    use plaine_p2p::peer::BanList;
    let mut b = BanList::new(vec![[42u8; 16]]);
    for i in 0..(BANLIST_MAX as u64 + 100) {
        let mut ip = [0u8; 16];
        ip[..8].copy_from_slice(&i.to_le_bytes());
        b.ban(ip, Mono(0), BAN_TIME_MS);
    }
    assert!(b.len() <= BANLIST_MAX, "ban list is unbounded: {}", b.len());

    b.ban([42u8; 16], Mono(0), BAN_TIME_MS);
    assert!(!b.is_banned(&[42u8; 16], Mono(1)));

    let mut c = BanList::new(vec![]);
    c.ban([7u8; 16], Mono(0), BAN_TIME_MS);
    assert!(c.is_banned(&[7u8; 16], Mono(BAN_TIME_MS - 1)));
    assert!(!c.is_banned(&[7u8; 16], Mono(BAN_TIME_MS + 1)));
}

#[test]
fn local_stall_costs_peers_nothing() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(600);
    let a = sim.add_peer(Behaviour::Honest, chain.clone());
    let b = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(a);
    sim.connect(b);
    sim.run(5_000, 1_000);
    let designated = sim.sync_peer().expect("a sync peer");

    sim.chain.freeze_sink(true);
    sim.engine_event(Event::Paused {
        peer: designated,
        cause: PauseCause::CommitStall,
    });
    let rotations_before = sim.engine.metrics.snapshot().rotations_charged;
    sim.run(120_000, 1_000);

    assert_eq!(
        sim.sync_peer(),
        Some(designated),
        "an honest sync peer was rotated away for our disk being slow"
    );
    assert_eq!(
        sim.engine.metrics.snapshot().rotations_charged,
        rotations_before
    );
    for s in sim.engine.peers().values() {
        assert_eq!(
            s.score.value(sim.now()),
            0,
            "a peer was scored for our own commit stall"
        );
    }

    sim.chain.freeze_sink(false);
    sim.engine_event(Event::Unpaused { peer: designated });
    sim.run(120_000, 1_000);
    assert_eq!(sim.engine.verified_height(), 600, "sync did not resume");
}

#[test]
fn ingest_pause_keeps_clock() {
    assert!(!PauseCause::IngestBudget.suspends_liveness_clocks());
    assert!(PauseCause::LocalInbox.suspends_liveness_clocks());
    assert!(PauseCause::ValidateQueue.suspends_liveness_clocks());
    assert!(PauseCause::CommitStall.suspends_liveness_clocks());
    assert!(!PauseCause::PeerOverran.suspends_liveness_clocks());

    assert_eq!(PauseCause::IngestBudget.peer_points(), 0);
    assert_eq!(PauseCause::PeerOverran.peer_points(), 5);
}

#[test]
fn suspended_clock_has_ceiling() {
    use plaine_p2p::sync::stall::{ProgressClock, StallKind};
    let mut c = ProgressClock::new(Mono(0));
    c.suspend(Mono(0));
    assert_eq!(c.verdict(Mono(SYNC_SUSPEND_MAX_MS - 1), true), None);
    let v = c.verdict(Mono(SYNC_SUSPEND_MAX_MS), true);
    assert!(matches!(v, Some(StallKind::LocalSuspendExceeded { .. })));
    let k = v.expect("a verdict");
    assert_eq!(
        k.peer_points(),
        0,
        "our own disk must cost the peer nothing"
    );
    assert!(
        !k.charges_budget(),
        "a rotation caused by our own suspension must not spend the budget \
         that would let us try somebody else"
    );
}

#[test]
fn commit_error_not_swallowed() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(100);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.chain.set_fatal(Some("simulated disk failure"));
    sim.run(60_000, 1_000);

    assert_eq!(sim.engine.fatal(), Some("simulated disk failure"));
    assert!(
        sim.said(|c| matches!(c, Condition::SinkFatal(_))),
        "a fatal sink error was not surfaced as a named condition"
    );
}

#[test]
fn requested_blocks_kept_under_pressure() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(200);
    let a = sim.add_peer(Behaviour::Honest, chain.clone());
    let b = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(a);
    sim.connect(b);
    sim.run(10_000, 1_000);

    sim.chain.freeze_sink(true);
    sim.run(40_000, 1_000);
    let buffered = sim.engine.body.ready_len();
    assert!(
        buffered > 0,
        "nothing was buffered while the sink was frozen"
    );
    sim.chain.freeze_sink(false);
    sim.run(400_000, 1_000);
    assert_eq!(
        sim.engine.body.applied(),
        200,
        "blocks were discarded rather than held while the sink was full"
    );
}

#[test]
fn every_queue_bounded() {
    let registry: &[(&str, u64, u64, Policy)] = &[
        ("peer inbox", 1, INBOX_BYTES, Policy::PauseReads),
        (
            "inbox pool",
            MAX_PEERS as u64,
            INBOX_POOL_BYTES,
            Policy::PauseReads,
        ),
        (
            "validate queue",
            VALIDATE_Q_ITEMS,
            VALIDATE_Q_BYTES,
            Policy::PauseReads,
        ),
        ("tx queue", TX_Q_ITEMS, TX_Q_BYTES, Policy::DropNewest),
        ("peer outbox", 1, OUTBOX_BYTES, Policy::Disconnect),
        (
            "outbox pool",
            MAX_PEERS as u64,
            OUTBOX_POOL_BYTES,
            Policy::DropLargestOutbox,
        ),
        (
            "anons outbox",
            ANONS_OUTBOX_ITEMS,
            ANONS_OUTBOX_ITEMS * 36,
            Policy::EvictOldest,
        ),
        (
            "reorg prefetch",
            1,
            REORG_PREFETCH_BYTES,
            Policy::StreamApply,
        ),
        (
            "orphan bodies",
            ORPHAN_BODIES_ITEMS,
            ORPHAN_BODIES_BYTES,
            Policy::EvictOldest,
        ),
        (
            "ready-ahead",
            READY_AHEAD_BLOCKS as u64,
            READY_AHEAD_BYTES,
            Policy::ThrottleRequests,
        ),
        (
            "body window",
            BODY_WINDOW_HASHES as u64,
            BODY_WINDOW_BYTES,
            Policy::ThrottleRequests,
        ),
        (
            "staging",
            PRESYNC_LEAD_HEADERS,
            PRESYNC_LEAD_BYTES,
            Policy::ThrottleRequests,
        ),
        (
            "fork tree",
            FORK_HEADERS_MAX as u64,
            FORK_HEADERS_MAX as u64 * 132,
            Policy::EvictOldest,
        ),
        (
            "known headers",
            KNOWN_HEADERS_MAX as u64,
            KNOWN_HEADERS_BYTES,
            Policy::EvictOldest,
        ),
        (
            "wanted bodies",
            WANTED_MAX as u64,
            WANTED_BYTES,
            Policy::ThrottleRequests,
        ),
        (
            "fork bodies",
            FORK_BODY_MAX as u64,
            FORK_BODY_BYTES,
            Policy::ThrottleRequests,
        ),
        (
            "reject cache",
            REJECT_CACHE_MAX as u64,
            REJECT_CACHE_MAX as u64 * 40,
            Policy::EvictOldest,
        ),
        (
            "ban list",
            BANLIST_MAX as u64,
            BANLIST_MAX as u64 * 24,
            Policy::EvictOldest,
        ),
        (
            "quarantine",
            QUARANTINE_MAX as u64,
            QUARANTINE_MAX as u64 * 64,
            Policy::EvictOldest,
        ),
        (
            "time park",
            TIME_PARK_MAX as u64,
            TIME_PARK_MAX as u64 * 132,
            Policy::DropNewest,
        ),
        (
            "addrman new",
            ADDR_NEW_MAX as u64,
            ADDR_NEW_MAX as u64 * 30,
            Policy::EvictOldest,
        ),
        (
            "addrman tried",
            ADDR_TRIED_MAX as u64,
            ADDR_TRIED_MAX as u64 * 30,
            Policy::EvictOldest,
        ),
        (
            "serve egress",
            1,
            SERVE_RATE_GLOBAL_BYTES_PER_SEC,
            Policy::RefuseServe,
        ),
    ];
    let mut total_bytes = 0u64;
    for (name, items, bytes, policy) in registry {
        assert!(*items > 0, "{} has no item bound", name);
        assert!(*bytes > 0, "{} has no byte bound", name);

        let _ = policy;
        total_bytes += *bytes;
    }

    let worst_mib = total_bytes / (1024 * 1024);
    assert!(
        worst_mib > 353 && worst_mib < 600,
        "recomputed worst-case P2P RAM is {} MiB, which is not the ~440 MiB the \
         report states",
        worst_mib
    );
}

#[test]
fn bounded_queues_evict() {
    use plaine_p2p::gate::RejectCache;
    use plaine_p2p::sync::tree::ForkTree;

    let mut rc = RejectCache::new();
    for i in 0..(REJECT_CACHE_MAX as u64 + 500) {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        rc.insert(h);
    }
    assert!(rc.len() <= REJECT_CACHE_MAX);
    assert!(rc.evictions >= 500, "EvictOldest never fired");

    let mut tree = ForkTree::new();
    for i in 0..(FORK_HEADERS_MAX as u64 + 200) {
        let mut prev = [0u8; 32];
        prev[..8].copy_from_slice(&i.to_le_bytes());
        let mut hash = [1u8; 32];
        hash[..8].copy_from_slice(&i.to_le_bytes());
        tree.insert(HeaderRec {
            height: i,
            hash,
            prev_hash: prev,
            time: 0,
            bits: 0,
            target: [0xff; 32],
            raw: [0u8; HEADER_BYTES],
        });
    }
    assert!(tree.len() <= FORK_HEADERS_MAX);
    assert!(tree.tips() <= FORK_TIPS_MAX, "fork tips are unbounded");
}

#[test]
fn inbox_pauses_rather_than_dropping() {
    let mut ib = Inbox::new();
    assert!(ib.accept(INBOX_BYTES - 1, Mono(0)));

    assert!(!ib.accept(1_000, Mono(1)));
    assert_eq!(ib.pause_cause(), Some(PauseCause::LocalInbox));
    ib.consume(INBOX_BYTES / 2 + 1, Mono(2));
    assert_eq!(ib.pause_cause(), None, "reads never resumed");
}

#[test]
fn fork_choice_zero_baddata_bans() {
    let mut s = Score::new(Mono(0));
    for _ in 0..100 {
        assert_eq!(s.apply(Offence::LessWork, Mono(0)), Verdict::Keep);
        assert_eq!(s.apply(Offence::TieBreakLost, Mono(0)), Verdict::Keep);
        assert_eq!(s.apply(Offence::ReorgTooDeep, Mono(0)), Verdict::Keep);
    }
    assert_eq!(s.value(Mono(0)), 0, "a losing fork was scored");

    let mut bad = Score::new(Mono(0));
    assert_eq!(bad.apply(Offence::BadPow, Mono(0)), Verdict::Ban);
    assert!(
        bad.sync_disqualified(),
        "a PoW forger must be sync-ineligible for the whole session, not just \
         for the 24 h IP ban - designation is a role and must be denied by role"
    );

    let mut pre = Score::new(Mono(0));
    assert_eq!(pre.apply(Offence::PreHello, Mono(0)), Verdict::BanShort);
}

#[test]
fn future_headers_score_zero() {
    assert_eq!(Offence::NotYetValid.points(), 0);

    assert_eq!(Offence::BadTimePast.points(), 100);
}

#[test]
fn score_decays_by_half_every_ten_minutes() {
    let mut s = Score::new(Mono(0));
    let _ = s.apply(Offence::UnknownCmd, Mono(0));
    let _ = s.apply(Offence::UnknownCmd, Mono(0));
    assert_eq!(s.value(Mono(0)), 40);
    assert_eq!(s.value(Mono(SCORE_HALF_LIFE_MS)), 20);
    assert_eq!(s.value(Mono(SCORE_HALF_LIFE_MS * 2)), 10);
    assert_eq!(s.value(Mono(SCORE_HALF_LIFE_MS * 20)), 0);
}

#[test]
fn banned_peer_stays_gone() {
    let mut sim = Sim::new(1, T0);
    let forged = sim.extension(10);
    let liar = sim.add_liar(forged, 1_000);
    sim.connect(liar);
    sim.run(30_000, 1_000);
    assert!(
        sim.actions.iter().any(|a| matches!(
            a,
            Action::Disconnect {
                reason: DeadReason::Banned,
                ..
            }
        )),
        "bad PoW did not produce a ban"
    );
    assert!(sim.engine.peers().get(&liar).is_none());
}

#[test]
fn slow_peer_no_hold() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(600);
    let slow = sim.add_peer(Behaviour::Slow { every_ms: 25_000 }, chain.clone());
    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(slow);
    sim.connect(honest);
    sim.run(5_000, 1_000);
    assert_eq!(sim.sync_peer(), Some(slow), "test precondition");

    sim.run(180_000, 1_000);
    assert_eq!(
        sim.engine.verified_height(),
        600,
        "a slow designated peer held the whole sync loop"
    );
}

#[test]
fn anchor_pull_rate_limited() {
    let mut sim = Sim::new(600, T0);
    let branch = sim.fork(500, 900, 46);
    let p = sim.add_peer(Behaviour::Honest, branch);
    sim.connect(p);
    sim.pin_tip_time_to_now();
    sim.run(GETCHECKPOINT_INTERVAL_MS / 2, 5_000);

    let pulls = sim
        .actions
        .iter()
        .filter(|a| {
            matches!(
                a,
                Action::Send {
                    msg: plaine_p2p::wire::Msg::GetCheckpoint,
                    ..
                }
            )
        })
        .count();
    assert!(
        pulls <= ANCHOR_PULL_PEERS,
        "{} anchor pulls issued inside one rate-limit window against {} peers",
        pulls,
        1
    );
}

#[test]
fn equal_timestamp_no_ban() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension_with_a_repeated_second(60, 30);

    let pair = chain.windows(2).find(|w| w[0].time == w[1].time);
    assert!(
        pair.is_some(),
        "test precondition: the generated chain must repeat a second"
    );
    let pair = pair.unwrap();
    assert_eq!(
        pair[1].height,
        pair[0].height + 1,
        "the pair must be consecutive"
    );
    assert_eq!(pair[1].prev_hash, pair[0].hash, "the pair must still link");

    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(honest);
    sim.run(120_000, 1_000);

    assert_eq!(
        sim.engine.verified_height(),
        60,
        "a fresh node did not sync a legal chain that repeats one second"
    );
}
