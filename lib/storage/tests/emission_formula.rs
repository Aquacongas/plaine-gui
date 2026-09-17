mod common;

use common::*;

use plaine_consensus::emission::{block_reward, cumulative_issued, issued_through};
use plaine_storage::{open, StoreError};

const N: u64 = 64;

fn honest_chain(name: &str, fudge: Option<(u64, i128)>) -> (u128, Result<(), StoreError>) {
    let s = Scratch::new(name);
    let mut cfg = s.cfg();
    cfg.state_ckpt_interval = 0;
    cfg.prune = false;
    cfg.ibd_batch_blocks = Some(32);
    let (mut c, r, _) = open(cfg).expect("open");

    let mut chain = Chain::new(16, 96, 2);
    let mut blocks = chain.build(N, 1);
    for b in blocks.iter_mut() {
        b.issued = block_reward(b.height);
        if let Some((h, d)) = fudge {
            if b.height == h {
                b.issued = (b.issued as i128 + d) as u128;
            }
        }
    }
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();
    assert_eq!(r.tip().height, N - 1);

    (c.issued(), c.verify_emission_against_formula())
}

#[test]
fn consensus_reward_verifies() {
    let _g = serial();
    let (issued, verdict) = honest_chain("emission-honest", None);

    let by_hand: u128 = (0..N).map(block_reward).sum();
    assert_eq!(issued, by_hand, "fixture did not pay block_reward");
    assert_eq!(
        issued,
        issued_through(N - 1),
        "issued_through is the total paid"
    );

    verdict.expect("an honest chain must not be reported as an emission mismatch");
}

#[test]
fn closed_form_off_by_one_block() {
    let paid: u128 = (0..N).map(block_reward).sum();

    assert_eq!(
        issued_through(N - 1),
        paid,
        "issued_through is the total paid"
    );

    assert_eq!(cumulative_issued(N - 1), paid - block_reward(N - 1));

    let at = 43_210u64;
    assert_eq!(
        issued_through(at) - issued_through(at - 1),
        block_reward(at),
        "issued_through is inclusive of its argument"
    );
    assert_eq!(
        cumulative_issued(at + 1) - cumulative_issued(at),
        block_reward(at),
        "cumulative_issued is exclusive of its argument"
    );
    assert_ne!(issued_through(at), cumulative_issued(at));
}

#[test]
fn single_mile_inflation_reported() {
    let _g = serial();
    let (issued, verdict) = honest_chain("emission-inflated", Some((N / 2, 1)));

    let honest: u128 = (0..N).map(block_reward).sum();
    assert_eq!(issued, honest + 1);
    match verdict {
        Err(StoreError::EmissionMismatch {
            stored_mile,
            formula_mile,
        }) => {
            assert_eq!(stored_mile, honest + 1);
            assert_eq!(formula_mile, honest);
        }
        other => panic!("one mile of inflation was not reported: {other:?}"),
    }
}

#[test]
fn empty_store_no_mismatch() {
    let _g = serial();
    let s = Scratch::new("emission-empty");
    let (c, _r, _) = open(s.cfg()).expect("open");
    c.verify_emission_against_formula()
        .expect("an empty store has issued nothing and owes nothing");
}
