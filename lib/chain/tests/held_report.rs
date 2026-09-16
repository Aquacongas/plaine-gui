mod support;

use plaine_chain::mock::{PowMode, Scenario};
use support::*;

fn fork_run(chain: &Scenario, parent_height: u64, n: u64) -> Vec<[u8; 132]> {
    let mut fork = chain.fork_at(parent_height);
    fork.push_block_with(&[], |mut h| {
        h.nonce = 0xC0DE_0001;
        h
    });
    for _ in 1..n {
        fork.push_block(&[]);
    }
    fork.raw_headers_from(parent_height + 1)
}

fn rig_and_a_parkable_header() -> (Rig, [u8; plaine_consensus::constants::HEADER_BYTES]) {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();
    let park = fork_run(&honest, 18, 1)[0];
    (r, park)
}

#[test]
fn parked_header_is_named() {
    let (mut r, park) = rig_and_a_parkable_header();
    let hash = plaine_consensus::crypto::header_hash(&park);
    let a = r.cm.submit_headers(7, &[park]).expect("not halted");

    assert_eq!((a.connected, a.rejected, a.staged), (0, 0, 1), "fixture: {a:?}");
    let h = a.first_held.unwrap_or_else(|| {
        panic!("staged: 1 but first_held: None; the transport needs the parked hash")
    });
    assert_eq!(h.hash, hash);
    assert_eq!(h.height, 19, "the sibling of block 18 is at height 19");
}

#[test]
fn connected_header_not_held() {
    let p = params();
    let mut honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();
    let blk = honest.push_block(&[]);
    let a = r.cm.submit_headers(7, &[blk.rec.raw]).expect("not halted");
    assert_eq!(a.connected, 1, "fixture: the real next block must connect");
    assert_eq!(
        a.first_held, None,
        "a header the chain connected must not be reported as parked"
    );
}

#[test]
fn refused_header_not_held() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let orphan = Scenario::genesis(&params(), T0 + 999).extend(3).raw_headers_from(3)[0];
    let a = r.cm.submit_headers(7, &[orphan]).expect("not halted");
    assert_eq!(a.rejected, 1, "fixture: {a:?}");
    assert!(a.first_rejection.is_some());
    assert_eq!(a.first_held, None, "a refused header is not a held one");
}

#[test]
fn reparked_header_named_again() {
    let (mut r, park) = rig_and_a_parkable_header();
    let hash = plaine_consensus::crypto::header_hash(&park);
    let first = r.cm.submit_headers(7, &[park]).expect("not halted");
    assert_eq!(first.first_held.map(|h| h.hash), Some(hash));
    let again = r.cm.submit_headers(7, &[park]).expect("not halted");
    assert_eq!(again.duplicates, 1, "fixture: the second copy must dedup, not stage");
    assert_eq!(
        again.first_held.map(|h| h.hash),
        Some(hash),
        "a redelivery of a header we still hold must name it again"
    );
    assert_eq!(again.first_held.map(|h| h.height), Some(19));
}

#[test]
fn unparked_duplicate_no_hold() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let again = honest.raw_headers_from(20)[0];
    let a = r.cm.submit_headers(7, &[again]).expect("not halted");
    assert_eq!(a.duplicates, 1, "fixture: {a:?}");
    assert_eq!(
        a.first_held, None,
        "a duplicate of a header in the arena was reported as parked"
    );
}

#[test]
fn staged_then_connected_not_held() {
    let p = params();
    let mut honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();
    for _ in 0..5 {
        honest.push_block(&[]);
    }
    let raws = honest.raw_headers_from(21);
    assert_eq!(raws.len(), 5, "fixture");
    let a = r.cm.submit_headers(7, &raws).expect("not halted");
    assert_eq!(a.connected, 5, "fixture: the whole run must connect: {a:?}");
    assert_eq!(
        a.first_held, None,
        "headers that connected inside this call must not be reported as parked"
    );
}

#[test]
fn lowest_parked_header_named() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let run = fork_run(&honest, 17, 2);
    let a = r.cm.submit_headers(7, &run).expect("not halted");
    assert_eq!((a.connected, a.staged), (0, 2), "fixture: {a:?}");
    assert_eq!(
        a.first_held.map(|h| h.height),
        Some(18),
        "the lower of the two parked headers must be named"
    );
}

fn parked_run(chain: &Scenario) -> Vec<[u8; 132]> {
    let mut fork = chain.fork_at(16);
    fork.push_block_with(&[], |mut h| {
        h.nonce = 0xC0DE_0002;
        h
    });
    fork.push_block(&[]);
    fork.push_block(&[]);
    fork.raw_headers_from(17)
}

#[test]
fn earlier_parked_branch_named_next_call() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();
    let run = parked_run(&honest);
    assert_eq!(run.len(), 3, "fixture: three headers");
    let first = r.cm.submit_headers(7, &run[..2]).expect("not halted");
    assert_eq!((first.connected, first.staged), (0, 2), "fixture: {first:?}");
    assert_eq!(first.first_held.map(|h| h.height), Some(17), "fixture: {first:?}");
    let next = r.cm.submit_headers(7, &run[2..]).expect("not halted");
    assert_eq!((next.connected, next.staged), (0, 3), "fixture: {next:?}");
    assert_eq!(
        next.first_held.map(|h| h.height),
        Some(17),
        "the chain must name the lowest header it still holds, whichever call brought it"
    );
}

#[test]
fn a_source_holding_nothing_reports_no_hold() {
    let p = params();
    let mut honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let blk = honest.push_block(&[]);
    let a = r.cm.submit_headers(7, &[blk.rec.raw]).expect("not halted");
    assert_eq!((a.connected, a.staged), (1, 0), "fixture: {a:?}");
    assert_eq!(a.first_held, None, "a source holding nothing was reported as holding");
}

#[test]
fn branch_clearing_s6_not_held() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let mut fork = honest.fork_at(16);
    fork.push_block_with(&[], |mut h| {
        h.nonce = 0xC0DE_0003;
        h
    });
    for _ in 0..5 {
        fork.push_block(&[]);
    }
    let run = fork.raw_headers_from(17);
    let a = r.cm.submit_headers(7, &run).expect("not halted");
    assert!(a.connected > 0, "fixture: a heavier branch must connect: {a:?}");
    assert_eq!(a.first_held, None, "a branch that cleared S6 was reported as parked");
}

#[test]
fn duplicate_body_not_missing_header() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::with_mode(&chain, p, PowMode::AlwaysOk);
    r.sync(&chain, 1);
    let h = chain.blocks[3].rec.hash;
    assert!(
        matches!(
            r.cm.submit_block(&h, chain.blocks[3].body.clone()),
            Err(plaine_chain::error::Reject::BodyAlreadyHeld { .. })
        ),
        "a body we already hold must say so, not claim we have no header for it"
    );

    assert!(
        matches!(
            r.cm.submit_block(&[0x77; 32], vec![0u8; 128]),
            Err(plaine_chain::error::Reject::BodyNotAdmissible { .. })
        ),
        "a body for a header this chain has never seen is still not admissible"
    );
}
