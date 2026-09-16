use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const AT: u64 = 20;

const WINDOW_MS: u64 = 20_000;

fn parking() -> (Sim, Vec<HeaderRec>) {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.park_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(p);
    sim.run(WINDOW_MS, 1_000);
    (sim, chain)
}

#[test]
fn parked_header_not_memoised() {
    let (sim, chain) = parking();

    assert!(
        sim.chain.accepted_headers() > AT,
        "fixture: only {} headers reached the sink, nothing above {AT} was parked",
        sim.chain.accepted_headers()
    );

    let top = chain.iter().map(|h| h.height).max().unwrap_or(0);
    let parked: Vec<&HeaderRec> =
        chain.iter().filter(|h| h.height > AT && h.height < top).collect();
    assert!(!parked.is_empty(), "fixture: no header above {AT} in the peer's chain");
    let still_locked: Vec<u64> = parked
        .iter()
        .filter(|h| sim.engine.deduplicates(&h.hash))
        .map(|h| h.height)
        .collect();
    // a parked header must not stay in the G0 dedup memo: `known` only ages out
    // below tip - MAX_REORG_DEPTH, so a memo left here is one no peer can ever redeliver.
    assert!(
        still_locked.is_empty(),
        "engine still deduplicates parked headers at heights {still_locked:?}"
    );
}

#[test]
fn parking_keeps_verified_prefix() {
    let (sim, _) = parking();
    assert!(
        sim.engine.known_len() > 0,
        "headers below {AT} connected normally and must still be remembered"
    );
    assert!(
        sim.engine.verified_height() >= AT,
        "watermark {} is below the connected prefix at {AT}",
        sim.engine.verified_height()
    );
}

#[test]
fn parked_header_raises_no_condition() {
    let (sim, _) = parking();
    assert!(
        !sim.said(|c| matches!(c, Condition::HeaderRefusedByChain { .. })),
        "a header held in staging was reported as a chain refusal: {:?}",
        sim.engine.conditions()
    );
    assert!(
        !sim.said(|c| matches!(c, Condition::SinkFatal(_))),
        "conditions: {:?}",
        sim.engine.conditions()
    );
}

#[test]
fn parking_no_rerequest_loop() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);

    sim.run(WINDOW_MS, 1_000);
    let before = sim.getdata_total();
    sim.chain.park_headers_from(AT + 1);
    sim.run(WINDOW_MS, 1_000);
    let during = sim.getdata_total() - before;

    assert!(
        during <= before.max(20) * 2,
        "parking produced {during} GETDATA items against {before} without parking"
    );
}

#[test]
fn parked_body_not_wanted() {
    let (sim, chain) = parking();

    let top = chain.iter().map(|h| h.height).max().unwrap_or(0);
    let still: Vec<u64> = chain
        .iter()
        .filter(|h| h.height > AT && h.height < top && sim.engine.wants_body_of(&h.hash))
        .map(|h| h.height)
        .collect();
    // the chain cannot admit a body for a header it has not connected.
    assert!(still.is_empty(), "engine still wants bodies of parked headers at {still:?}");
}

#[test]
fn no_parking_no_forget() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(WINDOW_MS, 1_000);
    assert_eq!(
        sim.engine.metrics.snapshot().headers_held,
        0,
        "a chain that connected every header reported one as parked"
    );
    assert!(sim.engine.known_len() > 0, "fixture: nothing was ever memoised");
    assert!(
        sim.chain.accepted_headers() >= 40,
        "fixture: only {} headers reached the sink",
        sim.chain.accepted_headers()
    );
}

#[test]
fn parked_headers_counted() {
    let (sim, _) = parking();
    assert!(
        sim.engine.metrics.snapshot().headers_held > 0,
        "chain parked headers but the counter stayed at zero"
    );
}

#[test]
fn audit_breaks_residual_lock() {
    use plaine_p2p::constants::TRACKING_AUDIT_MS;
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.park_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(p);
    sim.run(WINDOW_MS, 1_000);
    let top = *chain.iter().max_by_key(|h| h.height).expect("chain is not empty");
    assert!(
        sim.engine.deduplicates(&top.hash),
        "fixture: the top header was already forgotten inside the audit window"
    );
    assert!(
        !sim.said(|c| matches!(c, Condition::HeaderRefusedByChain { .. })),
        "fixture: the backstop fired inside the audit window"
    );
    sim.run(TRACKING_AUDIT_MS + 20_000, 1_000);
    let named: Vec<u64> = sim
        .engine
        .conditions()
        .iter()
        .filter_map(|c| match c {
            Condition::HeaderRefusedByChain { height, .. } => Some(*height),
            _ => None,
        })
        .collect();
    // the deferred hold cannot reach the last header of a stopped stream, so the
    // audit is the only thing that can free the tip of a competing branch.
    assert!(
        named.contains(&top.height),
        "residual memo at height {} was never undone; backstop named {named:?}",
        top.height
    );
    assert!(
        sim.engine.known_len() <= (AT + 1) as usize,
        "memo set grew to {} against a connected prefix of {AT}",
        sim.engine.known_len()
    );
}
