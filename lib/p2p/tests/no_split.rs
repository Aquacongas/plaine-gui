use plaine_p2p::constants::*;
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::sync::body_track::{BodyAction, BodyTrack, BState, Supplier};
use plaine_p2p::sync::Action;
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

fn h(n: u64) -> Hash32 {
    let mut x = [0u8; 32];
    x[0] = (n & 0xff) as u8;
    x[1] = ((n >> 8) & 0xff) as u8;
    x[31] = 0xAA;
    x
}

fn suppliers() -> Vec<Supplier> {
    vec![
        Supplier { id: PeerId(1), horizon: 10_000 },
        Supplier { id: PeerId(2), horizon: 10_000 },
    ]
}

fn wedged(now: Mono) -> (BodyTrack, Vec<(u64, Hash32)>) {
    let mut b = BodyTrack::new(0);
    let sup = suppliers();
    let wanted: Vec<(u64, Hash32)> = (1..=64).map(|i| (i, h(i))).collect();

    let _ = b.schedule(&wanted, &sup, now);
    for i in 2..=(READY_AHEAD_BLOCKS as u64 + 1) {
        b.on_body(h(i), vec![0u8; 64], i, now);
    }
    b.drain_applicable(|_, _, _| true, now);
    (b, wanted)
}

#[test]
fn ready_ahead_reveals_missing_head() {
    let now = Mono(1_000_000);
    let (b, _) = wedged(now);
    assert!(
        !b.ready_full(),
        "ready buffer reports full with the head-of-line block missing ({} entries)",
        b.ready_len()
    );
    assert_eq!(
        b.ready_len(),
        READY_AHEAD_BLOCKS - 1,
        "the window admitted {} entries with the head missing; the arithmetic above assumes at most {}",
        b.ready_len(),
        READY_AHEAD_BLOCKS - 1
    );
}

#[test]
fn unappliable_bodies_named() {
    let now = Mono(1_000_000);
    let (mut b, _) = wedged(now);
    let mut t = now;
    b.release_peer(PeerId(1), t);
    b.release_peer(PeerId(2), t);
    assert_eq!(b.inflight_len(), 0, "fixture: the window did not empty");
    assert_eq!(
        b.state(),
        BState::Applying,
        "fixture: the track is already Starved, so the starvation ladder is \
         armed and its own WidenSuppliers would mask ours"
    );

    let mut ticks: Vec<Vec<BodyAction>> = Vec::new();
    for _ in 0..6 {
        t = Mono(t.0 + HOL_TIMEOUT_MS + 1);
        ticks.push(b.tick(&suppliers(), t));
    }
    let acts: Vec<BodyAction> = ticks
        .iter()
        .find(|acts| {
            acts.iter().any(|a| {
                matches!(
                    a,
                    BodyAction::Say(Condition::BodiesUnappliable { missing: 1, .. })
                )
            })
        })
        .cloned()
        .unwrap_or_default();
    let said = !acts.is_empty();
    assert!(
        said,
        "{} bodies are held, height 1 is missing and nothing is in flight for \
         it, and the track said {acts:?}. `BodyUnavailable` cannot fire here - \
         it needs `starved_since`, which needs an in-flight record - so \
         without this condition the state is indistinguishable from synced.",
        b.ready_len()
    );
    assert!(
        acts.iter().any(|a| matches!(a, BodyAction::WidenSuppliers)),
        "the condition was said but no supplier was widened in the same tick. \
         the block may not be in the set, and no timer inside this type \
         can add one: {acts:?}"
    );
}

#[test]
fn report_stops_on_arrival() {
    let now = Mono(1_000_000);
    let (mut b, _) = wedged(now);
    let mut t = now;
    b.release_peer(PeerId(1), t);
    b.release_peer(PeerId(2), t);
    let mut before = 0;
    for _ in 0..4 {
        t = Mono(t.0 + HOL_TIMEOUT_MS + 1);
        before += b
            .tick(&suppliers(), t)
            .iter()
            .filter(|a| matches!(a, BodyAction::Say(Condition::BodiesUnappliable { .. })))
            .count();
    }
    assert!(before >= 1, "fixture: the condition never fired, so there is nothing to stop");

    b.on_body(h(1), vec![0u8; 64], 1, t);
    b.drain_applicable(|_, _, _| true, t);
    assert!(
        b.applied() >= READY_AHEAD_BLOCKS as u64,
        "fixture: the buffer did not drain, applied={}",
        b.applied()
    );

    let mut after = 0;
    for _ in 0..8 {
        t = Mono(t.0 + HOL_TIMEOUT_MS + 1);
        after += b
            .tick(&suppliers(), t)
            .iter()
            .filter(|a| matches!(a, BodyAction::Say(Condition::BodiesUnappliable { .. })))
            .count();
    }
    assert_eq!(
        after, 0,
        "head-of-line block arrived and the buffer drained, but the track reported {after} more times"
    );
}

#[test]
fn idle_track_not_unappliable() {
    let now = Mono(1_000_000);
    let mut b = BodyTrack::new(100);
    let mut t = now;
    let mut said = 0;
    for _ in 0..10 {
        t = Mono(t.0 + HOL_TIMEOUT_MS + 1);
        said += b
            .tick(&suppliers(), t)
            .iter()
            .filter(|a| matches!(a, BodyAction::Say(Condition::BodiesUnappliable { .. })))
            .count();
    }
    assert_eq!(
        said, 0,
        "an idle track at the tip, holding and asking for nothing, reported {said} unappliable-body conditions"
    );
}

#[test]
fn inflight_body_not_unappliable() {
    let now = Mono(1_000_000);
    let (mut b, _) = wedged(now);
    assert_eq!(
        b.inflight_len(),
        1,
        "fixture: the head-of-line block should still be in flight"
    );
    let mut t = now;
    let mut said = 0;
    for _ in 0..6 {
        t = Mono(t.0 + HOL_TIMEOUT_MS + 1);
        said += b
            .tick(&suppliers(), t)
            .iter()
            .filter(|a| matches!(a, BodyAction::Say(Condition::BodiesUnappliable { .. })))
            .count();

        if b.inflight_len() == 0 {
            break;
        }
    }
    assert_eq!(
        said, 0,
        "head-of-line body is in flight but reported unappliable {said} times; with a request outstanding this is just a slow block"
    );
}

#[test]
fn healthy_download_no_unappliable() {
    let now = Mono(1_000_000);
    let mut b = BodyTrack::new(0);
    let sup = suppliers();
    let wanted: Vec<(u64, Hash32)> = (1..=64).map(|i| (i, h(i))).collect();
    let mut t = now;
    let mut said = 0;
    for _ in 0..40u64 {
        let _ = b.schedule(&wanted, &sup, t);

        let want = b.applied() + 1;
        if want <= 64 {
            b.on_body(h(want), vec![0u8; 64], want, t);
        }
        b.drain_applicable(|_, _, _| true, t);
        t = Mono(t.0 + 1_000);
        said += b
            .tick(&sup, t)
            .iter()
            .filter(|a| matches!(a, BodyAction::Say(Condition::BodiesUnappliable { .. })))
            .count();
    }
    assert_eq!(
        said, 0,
        "a healthy in-order download said `BodiesUnappliable` {said} times. The \
         condition must name the state where the ladder is unreachable, not the \
         ordinary gap between a body and the next one."
    );
}

const AT: u64 = 20;

fn swallowing() -> Sim {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);

    sim.chain.swallow_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(180_000, 1_000);
    sim
}

#[test]
fn dropped_header_not_held_forever() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.swallow_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    let mut peak = 0usize;
    let mut dropped_to = usize::MAX;
    for _ in 0..300 {
        sim.run(1_000, 1_000);
        let n = sim.engine.known_len();
        if n > peak {
            peak = n;
            dropped_to = usize::MAX;
        } else if n < peak {
            dropped_to = dropped_to.min(n);
        }
    }
    assert!(
        peak > AT as usize,
        "fixture: `known` never went past {AT}, so nothing was memoised that \
         the chain had not kept"
    );
    assert!(
        dropped_to <= AT as usize + 1,
        "`known` peaked at {peak}, never fell below {dropped_to}, chain kept nothing above {AT}; a `known` entry for an unheld header is a permanent free dedup hit"
    );
}

#[test]
fn kept_nothing_reported() {
    let sim = swallowing();
    assert!(
        sim.said(|c| matches!(c, Condition::HeaderRefusedByChain { .. })),
        "chain kept no header above {AT} and the engine said nothing: {:?}",
        sim.engine.conditions()
    );
}

#[test]
fn stream_recovers_when_kept() {
    let mut sim = swallowing();
    assert!(
        sim.chain.tip().height <= AT,
        "fixture: the chain kept headers past {AT} after all"
    );
    sim.chain.keep_all_headers();
    sim.run(600_000, 1_000);
    assert_eq!(
        sim.chain.tip().height,
        60,
        "the chain started keeping headers again and the node never caught up - \
         it reached {}. Every header above {AT} is memoised in `known`, so every \
         peer's re-delivery is a free dedup hit and nothing is ever offered to \
         the sink a second time.",
        sim.chain.tip().height
    );
}

#[test]
fn kept_all_no_loss() {

    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(180_000, 1_000);
    let said = sim
        .engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::HeaderRefusedByChain { .. }))
        .count();
    assert_eq!(
        said, 0,
        "a healthy sync reported {said} chain refusals. The audit asks the chain \
         whether it holds a header we committed a full `TRACKING_AUDIT_MS` ago; \
         if that is racy on a working node the condition is noise."
    );
    assert!(
        !sim.actions.iter().any(|a| matches!(a, Action::Score { .. })),
        "the peer feeding the canonical chain was scored"
    );
}
