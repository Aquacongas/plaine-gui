use plaine_p2p::constants::STALL_TIMEOUT_MS;
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::sync::Event;
use plaine_p2p::sync::Action;
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const AT: u64 = 20;

const WINDOW_MS: u64 = 20_000;

fn refusing() -> Sim {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.refuse_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(WINDOW_MS, 1_000);
    sim
}

#[test]
fn refusal_reaches_engine_fast() {
    let sim = refusing();
    assert!(
        sim.said(|c| matches!(c, Condition::HeaderRefusedByChain { .. })),
        "the chain kept nothing above {AT} and told the seam so, and the engine \
         said nothing within {WINDOW_MS} ms. `TRACKING_AUDIT_MS` is 60,000 ms, \
         so `audit_commit` cannot have run yet - this window exists precisely to \
         prove the seam carried the verdict, not the inference. \
         Conditions: {:?}",
        sim.engine.conditions()
    );
}

#[test]
fn break_named_at_refusal_height() {
    let sim = refusing();
    let named: Vec<u64> = sim
        .engine
        .conditions()
        .iter()
        .filter_map(|c| match c {
            Condition::HeaderRefusedByChain { height, .. } => Some(*height),
            _ => None,
        })
        .collect();
    assert!(!named.is_empty(), "nothing was said at all");
    assert!(
        named.contains(&(AT + 1)),
        "the chain refused from height {} up and the engine named {named:?}. \
         The lowest refused height is the break; anything higher under-repairs.",
        AT + 1
    );
}

#[test]
fn refused_header_not_memoised() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.refuse_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    let mut peak = 0usize;
    let mut dropped_to = usize::MAX;
    for _ in 0..(WINDOW_MS / 1_000) {
        sim.run(1_000, 1_000);
        let n = sim.engine.known_len();
        if n > peak {
            peak = n;
            dropped_to = usize::MAX;
        } else if n < peak {
            dropped_to = dropped_to.min(n);
        }
    }
    let _ = dropped_to;

    assert!(
        sim.chain.accepted_headers() > AT,
        "fixture: only {} headers ever reached the sink, so nothing above {AT} \
         was ever offered and the bound below proves nothing",
        sim.chain.accepted_headers()
    );

    assert!(
        peak <= AT as usize + 1,
        "`known` peaked at {peak} while the chain kept nothing above {AT}; one past {AT} is the deferred verdict, more is a permanent G0 dedup leak"
    );
}

#[test]
fn node_recovers_when_kept() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.refuse_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(WINDOW_MS, 1_000);
    assert!(
        sim.chain.tip().height <= AT,
        "fixture: the chain kept headers past {AT} after all"
    );
    sim.chain.keep_all_headers();
    sim.run(600_000, 1_000);
    assert_eq!(
        sim.chain.tip().height,
        60,
        "the chain started keeping headers again and the node reached only {}. \
         Every header above {AT} would still be memoised in `known`, so every \
         peer's redelivery is a free dedup hit and nothing is offered to the \
         sink a second time.",
        sim.chain.tip().height
    );
}

#[test]
fn chain_disagreement_no_offence() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.refuse_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(6 * STALL_TIMEOUT_MS, 1_000);
    let scored: Vec<&Action> = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Score { .. }))
        .collect();
    assert!(
        scored.is_empty(),
        "the peer that carried headers our own chain refused was scored: {scored:?}"
    );
}

#[test]
fn healthy_node_no_refusal() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(WINDOW_MS, 1_000);
    let said = sim
        .engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::HeaderRefusedByChain { .. }))
        .count();
    assert_eq!(
        said, 0,
        "a healthy sync reported {said} chain refusals. The seam returns \
         `RefusedAt` only when the chain actually refused something; if that is \
         racy on a working node the condition means nothing."
    );
    assert_eq!(
        sim.chain.tip().height,
        60,
        "fixture: the healthy control did not finish syncing, so it proves nothing"
    );
}

#[test]
fn late_refusal_repaired_on_announce() {
    let mut sim = Sim::new(1, T0);
    let ext = sim.extension(4);

    sim.chain.refuse_headers_from(1);

    sim.chain.applied_tip(true);
    let peer = sim.add_peer(Behaviour::Silent, Vec::new());
    sim.connect(peer);

    sim.announce(peer, vec![ext[0].hash]);
    sim.engine_event(Event::Headers { peer, raw: vec![ext[0].raw] });
    let after_first = sim.engine.known_len() + sim.engine.tree_len();
    assert!(
        after_first > 0,
        "fixture: the announced header was not retained anywhere, so there is \
         nothing for a repair to undo"
    );

    sim.announce(peer, vec![ext[1].hash]);
    sim.engine_event(Event::Headers { peer, raw: vec![ext[1].raw] });

    assert!(
        sim.said(|c| matches!(c, Condition::HeaderRefusedByChain { .. })),
        "chain kept nothing on the announcement path and the engine stayed silent: {:?}",
        sim.engine.conditions()
    );
    assert_eq!(
        sim.engine.known_len() + sim.engine.tree_len(),
        0,
        "announced header the chain never kept is still in `known` or the fork tree; a tree hit returns before the sink, same permanent lock"
    );
    assert!(
        !sim.actions.iter().any(|a| matches!(a, Action::Score { .. })),
        "the announcing peer was scored for our own chain's verdict"
    );
}
