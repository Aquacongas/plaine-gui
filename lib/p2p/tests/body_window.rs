use plaine_p2p::constants::*;
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const N: u64 = WANTED_MAX as u64 * 6;

fn strict_ibd() -> (Sim, PeerId) {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(N);

    sim.chain.strict_canonical(true);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);

    assert!(
        N > FORK_HEADERS_MAX as u64 + 2 * WANTED_MAX as u64,
        "the fork tree alone could answer the whole first window"
    );
    (sim, p)
}

#[test]
fn long_chain_applies_bodies_to_end() {
    let (mut sim, _p) = strict_ibd();

    let mut ticks = 0;
    while sim.engine.verified_height() < N {
        sim.step(1_000);
        ticks += 1;
        assert!(ticks < 60, "headers never reached the peer's tip");
    }
    assert!(
        sim.engine.body.applied() < WANTED_MAX as u64,
        "the body track was already at {} when the header stream finished, so \
         this scenario never exercises the refill path and proves nothing",
        sim.engine.body.applied()
    );

    sim.run(600_000, 1_000);

    assert_eq!(
        sim.engine.body.applied(),
        N,
        "bodies stopped at {} of {N} (WANTED_MAX {}); window is not sliding, header watermark at {}",
        sim.engine.body.applied(),
        WANTED_MAX,
        sim.engine.verified_height(),
    );
    assert_eq!(sim.engine.fatal(), None);
}

#[test]
fn getdata_past_window_ceiling() {
    let (mut sim, _p) = strict_ibd();

    let mut ticks = 0;
    while sim.engine.body.applied() < WANTED_MAX as u64 {
        sim.step(1_000);
        ticks += 1;
        assert!(ticks < 200, "never even reached the ceiling");
    }
    let at_ceiling = sim.getdata_total();

    sim.run(60_000, 1_000);

    assert!(
        sim.getdata_total() > at_ceiling,
        "{} GETDATA at WANTED_MAX ({}), still {} after 60s; nothing asked past the ceiling, watermark at {}",
        at_ceiling,
        WANTED_MAX,
        sim.getdata_total(),
        sim.engine.verified_height(),
    );
}

#[test]
fn window_holds_only_reachable() {
    let (mut sim, _p) = strict_ibd();

    for _ in 0..600 {
        sim.step(1_000);
        if let Some((lo, hi)) = sim.engine.wanted_span() {
            let applied = sim.engine.body.applied();
            assert!(
                lo > applied,
                "`wanted` holds height {lo} at or below the applied watermark \
                 {applied}; the applier has already passed it"
            );
            assert!(
                hi <= applied + WANTED_MAX as u64,
                "`wanted` holds height {hi} against a window ceiling of {}. \
                 The list holds {} entries, so every count-based bound in the \
                 suite reads as satisfied while the scheduler can reach none \
                 of them.",
                applied + WANTED_MAX as u64,
                sim.engine.wanted_len(),
            );
        }
    }
    assert_eq!(
        sim.engine.body.applied(),
        N,
        "fixture never finished syncing"
    );
}

#[test]
fn window_bound_holds_while_sliding() {
    let (mut sim, _p) = strict_ibd();
    let mut peak = 0;
    for _ in 0..600 {
        sim.step(1_000);
        peak = peak.max(sim.engine.wanted_len());
    }
    assert_eq!(
        sim.engine.body.applied(),
        N,
        "fixture never finished syncing"
    );
    assert!(
        peak <= WANTED_MAX,
        "`wanted` peaked at {peak} entries against its bound of {WANTED_MAX}"
    );
    assert!(
        peak >= BODY_WINDOW_HASHES,
        "`wanted` never rose above {peak} entries, so the refill never \
         actually filled a window and this test is watching nothing"
    );
}

#[test]
fn repeat_offer_keeps_window() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(N);
    sim.chain.strict_canonical(true);
    let p = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(p);

    for h in chain.iter().take(WANTED_MAX) {
        sim.engine.want_body(h.height, h.hash);
    }
    let full = sim.engine.wanted_len();
    assert_eq!(full, WANTED_MAX, "fixture did not fill the window");
    let (_, top_before) = sim.engine.wanted_span().expect("a span");

    let again = &chain[8];
    sim.engine.want_body(again.height, again.hash);

    assert_eq!(
        sim.engine.wanted_len(),
        full,
        "re-offering height {} - already in the window - cost the window an entry",
        again.height
    );
    let (_, top_after) = sim.engine.wanted_span().expect("a span");
    assert_eq!(
        top_after, top_before,
        "the highest wanted height was evicted for a duplicate"
    );
}

#[test]
fn canonical_index_refills() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(N);
    sim.chain.forget_side_headers(true);

    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(600_000, 1_000);

    assert_eq!(
        sim.engine.body.applied(),
        N,
        "the walk could not answer and the canonical index was not asked: stopped at {} of {N}",
        sim.engine.body.applied()
    );
}

#[test]
fn unnamed_backlog_reported() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(N);
    sim.chain.strict_canonical(true);
    sim.chain.forget_side_headers(true);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(200_000, 1_000);

    assert!(
        sim.engine.body.applied() < N,
        "fixture: the node synced anyway, so this asserts nothing"
    );
    let said: Vec<&Condition> = sim
        .engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::BodyBacklogUnreachable { .. }))
        .collect();
    assert!(
        !said.is_empty(),
        "node stopped applying bodies at {} with header watermark at {} and said nothing (looks synced)",
        sim.engine.body.applied(),
        sim.engine.verified_height(),
    );

    assert_eq!(
        said.len(),
        1,
        "said {} times over a 200 s stall",
        said.len()
    );
}

#[test]
fn full_node_says_nothing() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(200);
    sim.chain.strict_canonical(true);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(200_000, 1_000);

    assert_eq!(sim.engine.body.applied(), 200, "fixture never synced");
    assert!(
        !sim.said(|c| matches!(c, Condition::BodyBacklogUnreachable { .. })),
        "a fully synced node reported an unreachable body backlog"
    );
}

fn mined_tip_rig(mined: u64, ahead: u64) -> (Sim, PeerId, u64) {
    let mut sim = Sim::new(1, T0);
    let mine = sim.extension(mined);

    sim.chain.extend(&mine, true);
    assert_eq!(
        sim.engine.body.applied(),
        0,
        "fixture: the watermark must still be the construction-time snapshot"
    );
    let ext = sim.extension(ahead);
    let top = mined + ahead;
    let mut theirs = mine;
    theirs.extend(ext);
    assert_eq!(theirs.last().map(|h| h.height), Some(top));
    let p = sim.add_peer(Behaviour::Honest, theirs);
    sim.connect(p);
    (sim, p, top)
}

#[test]
fn mined_tip_does_not_jam_window() {
    const MINED: u64 = 5;
    let (mut sim, _p, top) = mined_tip_rig(MINED, 40);
    sim.run(180_000, 1_000);

    assert_eq!(
        sim.engine.body.applied(),
        top,
        "mined {MINED} blocks then stopped: watermark {} against a peer at {top}, {} held bodies stuck waiting for height {}",
        sim.engine.body.applied(),
        sim.engine.body.ready_len(),
        sim.engine.body.applied() + 1
    );

    if let Some((lo, _hi)) = sim.engine.wanted_span() {
        assert!(
            lo > sim.engine.body.applied(),
            "the window names height {lo} at or below the watermark {}",
            sim.engine.body.applied()
        );
    }
}

#[test]
fn catchup_waits_for_body() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(400);
    let p = sim.add_peer(Behaviour::HeadersOnly, chain);
    sim.connect(p);
    sim.run(60_000, 1_000);

    assert!(
        sim.engine.verified_height() > 300,
        "fixture: the headers must have arrived (verified {})",
        sim.engine.verified_height()
    );
    assert_eq!(
        sim.engine.body.applied(),
        0,
        "the watermark walked up over four hundred blocks whose bodies this \
         node has never seen; every one of those heights is now permanently \
         un-wantable"
    );
    assert!(
        sim.engine.wanted_len() > 0,
        "the body window emptied; the watermark ran past the whole chain"
    );
}
