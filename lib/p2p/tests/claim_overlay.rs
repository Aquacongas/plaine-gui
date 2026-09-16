use plaine_p2p::constants::*;
use plaine_p2p::mock::{build_chain, Behaviour, Sim};
use plaine_p2p::sync::header_track::HState;
use plaine_p2p::sync::{Action, Event};
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

fn inbound(sim: &mut Sim, n: u64, height: u64) -> PeerId {
    let id = PeerId(50_000 + n);
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12] = 172;
    ip[13] = (n >> 8) as u8;
    ip[14] = n as u8;
    sim.engine_event(Event::PeerReady {
        peer: id,
        ip,
        outbound: false,
        height,
        work: [0u8; 32],
        tip: [0u8; 32],
        services: SERVICE_FULL_RELAY,
    });
    id
}

fn designations(sim: &Sim, peer: PeerId) -> usize {
    sim.actions
        .iter()
        .filter(|a| matches!(a, Action::Designate { peer: p } if *p == peer))
        .count()
}

#[test]
fn echoed_hash_makes_askable() {
    let mut sim = Sim::new(1, T0);

    sim.chain.applied_tip(true);
    let ext = sim.extension(3);
    let novel = ext[0];

    let out_peer = sim.add_peer(Behaviour::Honest, vec![]);
    sim.connect(out_peer);
    let in_peer = inbound(&mut sim, 1, 0);

    sim.engine_event(Event::Headers {
        peer: in_peer,
        raw: vec![novel.raw],
    });
    sim.run(2_000, 250);
    assert!(
        sim.engine.header.best_claimed_height() >= novel.height,
        "the fixture never got the header into the overlay at all"
    );

    assert_eq!(
        sim.engine
            .header
            .best_actionable_height(sim.engine.peers(), sim.now()),
        0,
        "an inbound peer must never count as askable - designation is \
         outbound-only and the two predicates have to agree"
    );

    sim.announce(out_peer, vec![novel.hash]);

    assert_eq!(
        sim.engine
            .header
            .best_actionable_height(sim.engine.peers(), sim.now()),
        novel.height,
        "outbound peer announced height {} but stayed invisible to designation (the fleet-partition wedge)",
        novel.height
    );
}

#[test]
fn horizon_raise_adds_claimant() {
    let mut sim = Sim::new(1, T0);
    let ext = sim.extension(3);
    let held = ext[0];
    let in_peer = inbound(&mut sim, 1, 0);
    sim.engine_event(Event::Headers {
        peer: in_peer,
        raw: vec![held.raw],
    });
    sim.run(1_000, 250);
    let before = sim.engine.header.best_claimed_height();
    assert_eq!(before, held.height, "fixture");

    let ghost = build_chain(900, 1, [9u8; 32], T0, 77)[0];
    for n in 2..102u64 {
        let p = inbound(&mut sim, n, 0);
        sim.announce(p, vec![held.hash, ghost.hash]);
    }
    assert_eq!(
        sim.engine.header.best_claimed_height(),
        before,
        "announcement moved the height read for `in_ibd`, cap-lift and recovery; it may only move who claims an already-claimed height"
    );
    assert!(
        sim.engine.header.best_claimed_height() <= held.height,
        "a hash nobody holds must raise nothing at all"
    );
}

#[test]
fn hash_below_tip_no_claim() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(30);
    let source = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(source);
    sim.run(60_000, 1_000);
    assert_eq!(sim.chain.tip().height, 30, "the fixture did not sync");

    let old = chain[10];
    let echoer = inbound(&mut sim, 7, 0);
    sim.announce(echoer, vec![old.hash]);
    assert_eq!(
        sim.engine.header.claim_height(echoer),
        0,
        "announcing a block we applied long ago made a peer a claimant. That \
         number can never exceed our own tip, so it is not evidence of anything \
         and must stay out of the overlay."
    );
}

#[test]
fn only_inbound_ahead_reported() {
    let mut sim = Sim::new(1, T0);

    sim.chain.applied_tip(true);
    let ext = sim.extension(5);
    let in_peer = inbound(&mut sim, 1, 0);
    sim.engine_event(Event::Headers {
        peer: in_peer,
        raw: vec![ext[0].raw],
    });
    sim.run(3 * TRACKING_AUDIT_MS, 1_000);

    assert_eq!(
        sim.engine.header.state(),
        HState::Tracking,
        "with nobody askable ahead the machine must reach its terminal state, \
         not spin in S1 forever"
    );
    let said = sim
        .engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::AheadPeersAllIneligible { .. }))
        .count();
    assert!(
        said >= 2,
        "node is behind, holds the proving header, cannot ask anybody, said it {said} times in three audits"
    );
}

#[test]
fn catchup_skips_stall_audit() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(10);
    let source = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(source);
    sim.run(30_000, 1_000);
    assert_eq!(sim.chain.tip().height, 10, "the fixture did not sync");
    assert_eq!(sim.engine.header.state(), HState::Tracking);

    let ahead = sim.extension(2);
    let late = sim.add_peer(Behaviour::Honest, [chain.clone(), ahead.clone()].concat());
    sim.connect(late);
    let before = designations(&sim, late);

    sim.run(TRACKING_AUDIT_MS / 4, 250);
    assert!(
        designations(&sim, late) > before,
        "a peer holding two blocks we do not have went undesignated for {} ms. \
         On a 60 s chain that is a whole block time of propagation delay per \
         hop.",
        TRACKING_AUDIT_MS / 4
    );
}

#[test]
fn tip_below_watermark_not_missing() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(300);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(20_000, 1_000);
    let verified = sim.engine.verified_height();
    assert!(verified > 200, "the fixture did not sync");

    sim.chain.regress_tip(50);
    assert!(sim.chain.tip().height < verified, "the mock did not regress");
    let designated_before = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Designate { .. }))
        .count();
    let scored_before = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Score { .. }))
        .count();

    sim.run(30_000, 250);

    let scored = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Score { .. }))
        .count()
        - scored_before;
    assert_eq!(
        scored, 0,
        "the honest peer was charged {scored} offences for our storage regressing"
    );
    assert!(
        !sim.actions.iter().any(|a| matches!(a, Action::Ban { .. })),
        "the node banned its only peer while trying to catch up with itself"
    );
    let designated = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Designate { .. }))
        .count()
        - designated_before;
    assert!(
        designated <= 2,
        "{designated} designations in 30 s with no headers missing"
    );
}

#[test]
fn known_headers_make_askable() {
    let mut sim = Sim::new(1, T0);
    let ext = sim.extension(3);
    let held = ext[0];

    let in_peer = inbound(&mut sim, 1, 0);
    sim.engine_event(Event::Headers {
        peer: in_peer,
        raw: vec![held.raw],
    });
    sim.run(1_000, 250);
    assert_eq!(
        sim.engine.header.claim_height(in_peer),
        held.height,
        "fixture: the first sender must be a claimant"
    );

    let out_peer = sim.add_peer(Behaviour::Honest, vec![]);
    sim.connect(out_peer);
    assert_eq!(sim.engine.header.claim_height(out_peer), 0, "fixture");

    sim.engine_event(Event::Headers {
        peer: out_peer,
        raw: vec![held.raw],
    });
    assert_eq!(
        sim.engine.header.claim_height(out_peer),
        held.height,
        "peer handed us height {} and G0/fork-tree dedup swallowed its claim; a dedup hit should still add the claimant",
        held.height
    );
    assert_eq!(
        sim.engine.header.best_claimed_height(),
        held.height,
        "the maximum over claims moved - it must not"
    );
}
