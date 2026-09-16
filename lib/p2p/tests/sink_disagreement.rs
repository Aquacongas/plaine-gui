use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::sync::Action;
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const AT: u64 = 20;

fn setup() -> Sim {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    sim.chain.reject_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(120_000, 1_000);
    sim
}

#[test]
fn refused_header_no_progress() {
    let sim = setup();
    assert!(
        sim.engine.verified_height() <= AT,
        "the engine's verified watermark is {} while the chain refused \
         everything above {AT} and sits at {}. The two must not diverge: the \
         watermark is what `refill_wanted` and the header machine's \
         'have we caught up?' test both read, so a watermark past a chain that \
         cannot move is a node that believes it is done and is at height {}.",
        sim.engine.verified_height(),
        sim.chain.tip().height,
        sim.chain.tip().height
    );
}

#[test]
fn refused_header_not_held() {
    let sim = setup();
    assert!(
        sim.engine.known_len() <= AT as usize + 1,
        "`known` holds {} entries after the chain refused everything above \
         {AT}. `known` means the sink took this and is consulted by G0 dedup, \
         so an entry for a refused header makes every future delivery of it a \
         free dedup hit and the gap unrecoverable by any peer, forever.",
        sim.engine.known_len()
    );
}

#[test]
fn a_refused_header_is_said_out_loud() {
    let sim = setup();
    let said = sim
        .engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::HeaderRefusedByChain { .. }))
        .count();
    assert!(
        said >= 1,
        "chain refused every header above {AT} and the engine stayed silent: {:?}",
        sim.engine.conditions()
    );
}

#[test]
fn chain_refusal_no_offence() {
    let sim = setup();
    let scored = sim
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Score { .. }))
        .count();
    assert_eq!(
        scored, 0,
        "the honest peer was charged {scored} offences because our chain \
         refused headers it served correctly"
    );
    assert!(
        !sim.actions.iter().any(|a| matches!(a, Action::Ban { .. })),
        "the node banned the peer that was feeding it the canonical chain"
    );
}

#[test]
fn stream_recovers_when_accepting() {
    let mut sim = setup();
    assert!(sim.chain.tip().height <= AT, "fixture: the chain did move past {AT}");

    sim.chain.accept_all_headers();
    sim.run(300_000, 1_000);

    assert_eq!(
        sim.chain.tip().height,
        60,
        "the chain started accepting again and the node never caught up. It \
         reached {}. Every header above {AT} is in `known`, so every peer's \
         re-delivery is a free dedup hit and nothing is ever offered to the \
         sink a second time.",
        sim.chain.tip().height
    );
}
