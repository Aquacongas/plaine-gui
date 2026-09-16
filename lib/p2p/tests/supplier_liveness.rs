use plaine_p2p::constants::*;
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::sync::Action;
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const N: u64 = 400;

fn every_supplier_denied() -> (Sim, Vec<PeerId>, Vec<HeaderRec>) {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(4_000);
    let ids: Vec<PeerId> = (0..3)
        .map(|_| {
            let p = sim.add_peer(Behaviour::HeadersOnly, chain.clone());
            sim.connect(p);
            p
        })
        .collect();
    (sim, ids, chain)
}

#[test]
fn all_denied_still_asks() {
    let (mut sim, ids, _chain) = every_supplier_denied();

    sim.run(150_000, 1_000);

    assert!(
        sim.engine.verified_height() > 0,
        "the peers never delivered a header, so nothing was ever wanted"
    );
    assert!(
        sim.engine.wanted_len() > 0,
        "the body window is empty, so a node that asks nobody is correct"
    );
    let now = sim.now();
    assert_eq!(sim.engine.peers().len(), 3, "peers were lost");
    for id in &ids {
        let s = sim.engine.peers().get(id).expect("peer");
        assert!(
            !s.body_eligible(now),
            "peer {:?} is still an eligible supplier, so this run exercises the \
             tiers that already existed and proves nothing about the new one",
            id
        );
    }

    let before = plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.body_requests);
    sim.run(240_000, 1_000);
    let issued = plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.body_requests) - before;

    assert!(
        issued > 0,
        "{} bodies named, all suppliers denied, {} GETDATA issued; with no eligible supplier it must still ask a denied peer",
        sim.engine.wanted_len(),
        issued
    );

    let now = sim.now();
    for id in &ids {
        let s = sim.engine.peers().get(id).expect("peer");
        assert!(
            !s.body_eligible(now),
            "asking peer {:?} anyway cleared its denial; the tier must yield to \
             liveness, not repeal the rule",
            id
        );
    }
}

#[test]
fn single_peer_downloads_bodies() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(N);
    let only = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(only);
    sim.run(120_000, 1_000);

    assert_eq!(
        sim.sync_peer(),
        Some(only),
        "the only peer was not designated, so the exclusion never applied"
    );
    assert!(
        sim.engine.verified_height() > 0,
        "no headers arrived at all"
    );
    assert!(
        sim.engine.body.applied() > 0,
        "single-peer node got {} headers, zero bodies; sync-peer exclusion should yield to liveness",
        sim.engine.verified_height()
    );
}

#[test]
fn liveness_yield_stops_at_first_tier() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(4_000);
    let ids: Vec<PeerId> = (0..3)
        .map(|_| {
            let p = sim.add_peer(Behaviour::Honest, chain.clone());
            sim.connect(p);
            p
        })
        .collect();
    sim.run(30_000, 1_000);
    let designated = sim.sync_peer().expect("a peer must be designated");

    let now = sim.now();
    let denied: Vec<PeerId> = ids.iter().copied().filter(|p| *p != designated).collect();
    assert_eq!(denied.len(), 2, "fixture: two peers must be denied");
    for p in &denied {
        sim.engine
            .peer_mut(*p)
            .expect("peer")
            .body_slot_lost_until = Some(now.plus_ms(BODY_SLOT_LOST_MS));
    }
    let eligible: Vec<PeerId> = sim
        .engine
        .peers()
        .values()
        .filter(|s| s.body_eligible(now))
        .map(|s| s.id)
        .collect();
    assert_eq!(
        eligible,
        vec![designated],
        "fixture: the designated peer must be the only eligible one"
    );

    let before: Vec<u64> = denied.iter().map(|p| sim.getdata_seen(*p)).collect();
    sim.run(120_000, 1_000);
    let after: Vec<u64> = denied.iter().map(|p| sim.getdata_seen(*p)).collect();
    assert_eq!(
        before, after,
        "liveness tier fired while an eligible supplier existed; it is last-resort only"
    );

    assert!(
        sim.getdata_seen(designated) > 0,
        "nothing was requested from the one eligible peer either"
    );
}

#[test]
fn asking_denied_peer_costs_nothing() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(4_000);
    let ids: Vec<PeerId> = (0..3)
        .map(|_| {
            let p = sim.add_peer(Behaviour::Honest, chain.clone());
            sim.connect(p);
            p
        })
        .collect();
    sim.run(30_000, 1_000);
    assert!(
        sim.engine.wanted_len() > 0,
        "fixture: the window must still want bodies"
    );
    for p in &ids {
        sim.set_behaviour(*p, Behaviour::Silent);
    }

    let scored = |sim: &Sim| {
        sim.actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    Action::Score {
                        offence: plaine_p2p::peer::Offence::DeadlineMiss,
                        ..
                    }
                )
            })
            .count()
    };

    let mut rounds = 0;
    loop {
        sim.run(10_000, 1_000);
        rounds += 1;
        let now = sim.now();
        if sim.engine.peers().values().all(|s| !s.body_eligible(now)) {
            break;
        }
        assert!(
            rounds < 60,
            "fixture: the peers never lost their body slots, so the liveness tier is not in force and this test measures nothing"
        );
    }

    let before = scored(&sim);
    let requests_before =
        plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.body_requests);
    sim.run(240_000, 1_000);
    let charged = scored(&sim) - before;
    let issued =
        plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.body_requests) - requests_before;

    assert!(
        issued > 0,
        "no body was requested after every peer was denied, so no deadline could have been missed and the guard is untested"
    );
    assert_eq!(
        charged, 0,
        "liveness tier issued {} requests to already-denied peers and charged them {} deadline misses",
        issued, charged
    );
}

#[test]
fn no_supplier_reported_on_cadence() {
    let (mut sim, ids, chain) = every_supplier_denied();
    sim.run(60_000, 1_000);
    assert!(sim.engine.wanted_len() > 0, "nothing was ever wanted");
    for id in &ids {
        sim.kill(*id);
    }
    assert!(sim.engine.peers().is_empty(), "a peer survived the kill");

    let before = count_no_supplier(&sim);
    sim.run(300_000, 1_000);
    let said = count_no_supplier(&sim) - before;

    assert!(
        said > 0,
        "the node holds {} named bodies and has no peer to ask for any of them, \
         and said nothing at all about it",
        sim.engine.wanted_len()
    );

    assert!(
        said as u64 <= 300_000 / BODY_UNAVAILABLE_RETRY_MS + 1,
        "the condition was said {} times in 300 s; the documented cadence is \
         one per {} ms",
        said,
        BODY_UNAVAILABLE_RETRY_MS
    );

    let fresh = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(fresh);
    sim.run(120_000, 1_000);
    let after = count_no_supplier(&sim);
    sim.run(180_000, 1_000);
    assert_eq!(
        count_no_supplier(&sim),
        after,
        "a peer is connected and eligible and the node is still reporting that \
         it has nobody to ask"
    );
}

fn count_no_supplier(sim: &Sim) -> usize {
    sim.engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::NoBodySupplier { .. }))
        .count()
}
