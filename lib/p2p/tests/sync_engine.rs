use plaine_p2p::constants::*;
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::sync::header_track::HState;
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

#[test]
fn ibd_completes_against_one_honest_peer() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(3_000);
    let p = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(p);

    sim.run(400_000, 1_000);

    assert_eq!(
        sim.engine.verified_height(),
        3_000,
        "verified watermark did not reach the peer's tip"
    );
    assert_eq!(
        sim.engine.body.applied(),
        3_000,
        "bodies did not follow the headers"
    );
    assert_eq!(sim.engine.fatal(), None);
}

#[test]
fn fork_point_found_in_one_round_trip() {
    let mut sim = Sim::new(5_000, T0);
    let chain = sim.extension(100);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);

    let mut ticks = 0;
    while sim.engine.header.staging.staged_len() == 0 && sim.engine.verified_height() == 4_999 {
        sim.step(1_000);
        ticks += 1;
        assert!(ticks < 20, "no headers arrived at all");
    }
    assert_eq!(
        sim.getheaders_seen(p),
        1,
        "more than one GETHEADERS preceded the first useful answer"
    );
    sim.run(20_000, 1_000);
    assert_eq!(sim.engine.verified_height(), 5_099);
}

#[test]
fn presync_bounded_forger_caught() {
    let mut sim = Sim::new(1, T0);
    let forged = sim.extension(20_000);
    let liar = sim.add_liar(forged, 5_000_000);
    sim.connect(liar);
    sim.run(30_000, 1_000);

    assert!(
        sim.engine.header.staging.staged_bytes() <= PRESYNC_LEAD_BYTES,
        "staged {} bytes, ceiling is {}",
        sim.engine.header.staging.staged_bytes(),
        PRESYNC_LEAD_BYTES
    );
    assert!(
        sim.engine.interpreter_calls() < 10,
        "a total forger cost {} interpreter calls; it should be single digits",
        sim.engine.interpreter_calls()
    );
    assert_eq!(
        sim.engine.verified_height(),
        0,
        "no forged header may become verified"
    );

    assert!(!sim.connected(liar), "the forger was not banned");
}

#[test]
fn forged_work_claim_gains_nothing() {
    let mut sim = Sim::new(10, T0);
    let forged = sim.extension(3_600);
    let liar = sim.add_liar(forged, u64::MAX / 2);
    sim.connect(liar);
    sim.run(20_000, 1_000);
    assert!(sim.engine.interpreter_calls() <= 2);
    assert_eq!(sim.engine.verified_height(), 9);
}

#[test]
fn losing_branch_costs_no_bodies() {
    let mut sim = Sim::new(500, T0);
    let branch = sim.fork(200, 20, 77);
    let p = sim.add_peer(Behaviour::Honest, branch);
    sim.connect(p);
    let before = sim.getdata_total();
    sim.run(50_000, 1_000);
    assert_eq!(
        sim.getdata_total(),
        before,
        "bodies were fetched for a branch we would never adopt"
    );
    assert_eq!(
        sim.engine
            .peers()
            .get(&p)
            .map(|s| s.score.value(sim.now()))
            .unwrap_or(0),
        0,
        "a peer on a losing fork was scored"
    );
}

#[test]
fn one_getdata_per_hash() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(20);
    let mut ids = Vec::new();
    for _ in 0..20 {
        ids.push(sim.add_peer(Behaviour::Honest, chain.clone()));
    }
    for id in &ids {
        sim.connect(*id);
    }
    sim.run(30_000, 1_000);
    for h in &chain {
        let n = sim.getdata_for(&h.hash);
        assert!(
            n <= 1,
            "block {} was requested {} times under an announce storm",
            h.height,
            n
        );
    }
    assert_eq!(sim.engine.body.applied(), 20);
}

#[test]
fn headers_only_peer_keeps_its_header_role() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(1_200);
    let p = sim.add_peer(Behaviour::HeadersOnly, chain);
    sim.connect(p);
    sim.run(60_000, 1_000);

    let s = sim.engine.peers().get(&p).expect("peer still connected");
    assert!(s.headers_only, "peer was not classified headers_only");
    assert!(
        !s.body_eligible(sim.now()),
        "a headers_only peer must be excluded from the body supplier set"
    );
    assert!(s.is_ready(), "a headers_only peer must be retained");
    assert!(
        sim.engine.verified_height() >= 1_000,
        "headers must keep flowing from a headers_only peer"
    );
}

#[test]
fn body_unavailable_no_wedge() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(50);
    let p = sim.add_peer(Behaviour::HeadersOnly, chain);
    sim.connect(p);
    sim.run(BODY_STARVE_REPORT_MS + 120_000, 5_000);

    assert!(
        sim.said(|c| matches!(c, Condition::BodyUnavailable { .. })),
        "BodyUnavailable was never reported"
    );
    assert_eq!(
        sim.engine.verified_height(),
        50,
        "verified headers were discarded because bodies were missing"
    );
}

#[test]
fn stall_predicate_ignores_a_quiet_network() {
    let mut sim = Sim::new(200, T0);
    let chain = sim.chain.headers();
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(TRACKING_AUDIT_MS * 10, 5_000);

    assert_eq!(sim.engine.header.state(), HState::Tracking);
    assert_eq!(
        sim.engine.metrics.snapshot().deep_recoveries,
        0,
        "a quiet network triggered recovery"
    );
    assert_eq!(sim.engine.metrics.snapshot().rotations_charged, 0);
    assert!(!sim.said(|c| matches!(c, Condition::StrandedBeyondReorgCap { .. })));
}

#[test]
fn tracking_republishes_the_tip_unconditionally() {
    use plaine_p2p::sync::Action;
    let mut sim = Sim::new(50, T0);
    let chain = sim.chain.headers();
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(TRACKING_AUDIT_MS * 3, 10_000);
    let republishes = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RepublishTip))
        .count();
    assert!(
        republishes >= 2,
        "tip was republished {} times in three audit periods",
        republishes
    );
}

#[test]
fn chain_view_may_regress() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(300);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(20_000, 1_000);
    let before = sim.engine.verified_height();
    assert!(before > 200);

    sim.chain.regress_tip(50);
    let regressed = sim.chain.tip();
    assert!(regressed.height < before, "the mock did not regress");

    sim.run(30_000, 1_000);
    assert_eq!(sim.engine.fatal(), None);
    assert!(sim.engine.header.state() != HState::ColdStart);
    assert!(sim.engine.verified_height() >= before);
}

#[test]
fn fast_forward_skips_pow_samples() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(2_000);
    let anchor_at = chain[1_499];
    sim.chain.set_anchor(Some(Anchor {
        height: anchor_at.height,
        hash: anchor_at.hash,
    }));
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(60_000, 1_000);

    assert_eq!(sim.engine.verified_height(), 2_000);
    let calls = sim.engine.interpreter_calls();
    let ff = sim.engine.fast_forwarded();
    assert!(ff > 1_000, "fast-forward did not happen: {} skipped", ff);

    let expected_full = 2_000 - anchor_at.height;
    assert!(
        calls >= expected_full,
        "only {} interpreter calls for {} headers above the anchor",
        calls,
        expected_full
    );
    let sampled = calls - expected_full;
    let bound = anchor_at.height / (FF_SAMPLE_RATE / 4);
    assert!(
        sampled <= bound,
        "sampling cost {} calls, well above the 1-in-{} budget",
        sampled,
        FF_SAMPLE_RATE
    );
}

#[test]
fn anchor_never_blocks_forward_sync() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(500);
    let a = chain[399];
    sim.chain.set_anchor(Some(Anchor {
        height: a.height,
        hash: a.hash,
    }));
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(40_000, 1_000);
    assert_eq!(sim.engine.verified_height(), 500);
}

#[test]
fn wrong_anchor_hash_rejected() {
    let mut sim = Sim::new(1, T0);
    let real = sim.extension(600);
    let anchor_at = real[499];
    sim.chain.set_anchor(Some(Anchor {
        height: anchor_at.height,
        hash: [0x5A; 32],
    }));
    let p = sim.add_peer(Behaviour::Honest, real);
    sim.connect(p);
    sim.run(40_000, 1_000);
    assert_eq!(sim.engine.fatal(), None, "an anchor mismatch must not be fatal");
    assert!(
        sim.engine.verified_height() < anchor_at.height,
        "headers past a mismatched anchor were accepted (verified {})",
        sim.engine.verified_height()
    );
}
