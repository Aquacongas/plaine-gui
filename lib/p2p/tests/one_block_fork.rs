use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

fn two_peers_and_a_sibling(sim: &mut Sim) -> (PeerId, PeerId, HeaderRec) {
    let ours = sim.chain.headers();
    let a = sim.add_peer(Behaviour::Honest, ours.clone());
    let b = sim.add_peer(Behaviour::Honest, ours);
    sim.connect(a);
    sim.connect(b);
    sim.run(5_000, 250);

    let sib = sim.fork(1, 1, 0x5B);
    (a, b, sib[0])
}

#[test]
fn undesignated_sibling_reaches_chain() {
    let mut sim = Sim::new(20, T0);
    let (a, b, sib) = two_peers_and_a_sibling(&mut sim);

    let sync = sim.sync_peer();
    let teller = if sync == Some(a) { b } else { a };
    assert_ne!(
        Some(teller),
        sync,
        "the fixture requires an undesignated announcer; with the sibling on \
         the stream this test cannot distinguish anything"
    );
    sim.grow_peer(teller, vec![sib]);
    sim.announce(teller, vec![sib.hash]);
    sim.run(10_000, 250);

    assert!(
        sim.chain.headers().iter().any(|h| h.hash == sib.hash),
        "sibling at height {} was announced by {:?}, served, PoW-verified, and the chain was never told; without it layer 4 cannot reorg. sync peer was {:?}",
        sib.height,
        teller,
        sync
    );
}

#[test]
fn held_sibling_body_requested() {
    let mut sim = Sim::new(20, T0);
    let (a, b, sib) = two_peers_and_a_sibling(&mut sim);
    let sync = sim.sync_peer();
    let teller = if sync == Some(a) { b } else { a };
    sim.grow_peer(teller, vec![sib]);
    sim.announce(teller, vec![sib.hash]);
    sim.run(5_000, 250);

    assert!(
        sim.chain.headers().iter().any(|h| h.hash == sib.hash),
        "precondition: the chain must hold the sibling header"
    );

    sim.chain.set_wanted_bodies(vec![sib.hash]);
    sim.run(5_000, 250);

    assert!(
        sim.getdata_seen(teller) > 0 || *sim.getdata_count.get(&sib.hash).unwrap_or(&0) > 0,
        "the chain named the sibling's body and no GETDATA was issued for it"
    );
}

#[test]
fn refused_header_not_taken() {
    let mut sim = Sim::new(20, T0);
    let (a, b, sib) = two_peers_and_a_sibling(&mut sim);
    let sync = sim.sync_peer();
    let teller = if sync == Some(a) { b } else { a };
    sim.grow_peer(teller, vec![sib]);

    sim.chain.freeze_sink(true);
    sim.announce(teller, vec![sib.hash]);
    sim.run(3_000, 250);
    assert!(
        !sim.chain.headers().iter().any(|h| h.hash == sib.hash),
        "precondition: a frozen sink must not have taken it"
    );

    sim.chain.freeze_sink(false);

    sim.announce(teller, vec![sib.hash]);
    sim.run(10_000, 250);

    assert!(
        sim.chain.headers().iter().any(|h| h.hash == sib.hash),
        "a header dropped by a full sink was remembered as handled, so the \
         re-announcement was deduplicated and the chain can never get it"
    );
}

#[test]
fn unacked_tip_reannounced() {
    use plaine_p2p::constants::{INV_REPEATS, TIP_REPUBLISH_MS};

    let mut sim = Sim::new(20, T0);
    sim.pin_tip_time_to_now();
    let quiet = sim.add_peer(Behaviour::Honest, Vec::new());
    let echoer = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(quiet);
    sim.connect(echoer);
    sim.run(2_000, 250);

    let base_quiet = sim.inv_seen(quiet);
    let base_echoer = sim.inv_seen(echoer);
    let next = sim.extension(1);
    sim.chain.extend(&next, true);
    sim.run(1_000, 250);
    assert_eq!(
        sim.inv_seen(quiet) - base_quiet,
        1,
        "fixture: exactly one frame must go out for the new tip"
    );
    assert_eq!(
        sim.inv_seen(echoer) - base_echoer,
        1,
        "fixture: exactly one frame must go out for the new tip"
    );

    sim.announce(echoer, vec![next[0].hash]);
    sim.run(3 * TIP_REPUBLISH_MS, 250);

    assert!(
        sim.inv_seen(quiet) - base_quiet > 1,
        "a peer that never acknowledged our tip was told exactly once. One \
         refusal on its side - `probe_due`, or the global probe bucket - and \
         that block is invisible to it until we mine the next one."
    );
    assert!(
        sim.inv_seen(quiet) - base_quiet <= 1 + INV_REPEATS as u64,
        "the repeat is unbounded: {} frames for one tip change",
        sim.inv_seen(quiet) - base_quiet
    );
    assert_eq!(
        sim.inv_seen(echoer) - base_echoer,
        1,
        "the peer that told us it has our tip was told again anyway - a \
         converged mesh now rings once per edge per repeat, for ever"
    );
}

#[test]
fn announced_body_requested() {
    let mut sim = Sim::new(20, T0);
    let ours = sim.chain.headers();
    let a = sim.add_peer(Behaviour::Honest, ours.clone());
    let b = sim.add_peer(Behaviour::Honest, ours);
    sim.connect(a);
    sim.connect(b);
    sim.run(5_000, 250);

    let next = sim.extension(1);
    let block = next[0];
    let sync = sim.sync_peer();
    let teller = if sync == Some(a) { b } else { a };
    assert_ne!(Some(teller), sync, "fixture: the announcer must be undesignated");
    sim.grow_peer(teller, vec![block]);
    sim.announce(teller, vec![block.hash]);
    sim.run(10_000, 250);

    assert!(
        sim.chain.headers().iter().any(|h| h.hash == block.hash),
        "precondition: the chain must hold the announced header"
    );
    assert!(
        *sim.getdata_count.get(&block.hash).unwrap_or(&0) > 0,
        "node holds a header for height {} and never asked anybody for the block",
        block.height
    );
}

#[test]
fn refused_header_not_retained() {
    let mut sim = Sim::new(20, T0);
    let (a, b, sib) = two_peers_and_a_sibling(&mut sim);
    let sync = sim.sync_peer();
    let teller = if sync == Some(a) { b } else { a };
    sim.grow_peer(teller, vec![sib]);

    sim.chain.reject_headers_from(sib.height);
    sim.announce(teller, vec![sib.hash]);
    sim.run(3_000, 250);
    assert!(
        !sim.chain.headers().iter().any(|h| h.hash == sib.hash),
        "precondition: a refusing chain must not have taken it"
    );

    sim.chain.accept_all_headers();
    sim.announce(teller, vec![sib.hash]);
    sim.run(10_000, 250);

    assert!(
        sim.chain.headers().iter().any(|h| h.hash == sib.hash),
        "a refused header was kept as taken, so the re-offer is deduplicated and can never be adopted"
    );
}
