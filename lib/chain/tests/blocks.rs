mod support;

use plaine_chain::error::Reject;
use plaine_chain::mock::Scenario;
use plaine_chain::types::Account;
use plaine_chain::{Progress, Store};
use plaine_consensus::emission;
use plaine_consensus::tx::TxError;
use support::*;

fn reject_of(chain: &Scenario, bad: &Scenario) -> Reject {
    let p = params();
    let mut r = Rig::new(chain, p);
    r.sync(chain, 1);
    let before = r.tip_hash();
    r.offer(3, &blocks_above(bad, chain.height()));

    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    assert_eq!(r.tip_hash(), before, "an invalid block never moves the tip");
    assert!(r.store.is_invalid(&bad.tip().hash), "the failure is sticky");
    r.cm.last_branch_failure().cloned().expect("the branch failed for a reason")
}

fn cause_of(r: Reject) -> Reject {
    match r {
        Reject::BranchInvalid { cause, .. } => *cause,
        other => other,
    }
}

#[test]
fn non_author_announcement_invalidates_block() {
    let p = params();
    let author = author_key();
    let chain = Scenario::genesis(&p, T0).with_miner(addr_of(&author)).extend(5);

    let impostor = impostor_key();
    let mut bad = chain.clone();
    let ann = signed_announcement(&impostor, b"emergency fork at height N", 1, 0);
    let cb = bad.normal_coinbase(6, 1);
    bad.push_body(Scenario::encode_body(&[&cb, &ann]));

    let err = cause_of(reject_of(&chain, &bad));
    assert!(
        matches!(err, Reject::Tx { index: 1, err: TxError::NotAuthorKey }),
        "the block must die on rule 1, got {err:?}"
    );
}

#[test]
fn author_announcement_accepted_pays_fee() {
    let p = params();
    let author = author_key();
    let a_addr = addr_of(&author);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.store.set_account(a_addr, Account { balance: 1_000_000, nonce: 0 });
    r.sync(&chain, 1);

    let mut good = chain.clone();
    let ann = signed_announcement(&author, b"emergency fork at height N", 7, 0);
    let cb = good.normal_coinbase(6, 7);
    good.push_body(Scenario::encode_body(&[&cb, &ann]));

    r.offer(3, &blocks_above(&good, 5));
    match r.cm.advance().expect("a correctly keyed announcement is a normal transaction") {
        Progress::Advanced { tip, .. } => assert_eq!(tip.hash, good.tip().hash),
        other => panic!("expected adoption, got {other:?}"),
    }
    let after = r.store.account(&a_addr);
    assert_eq!(after.balance, 1_000_000 - 7, "the fee is really paid");
    assert_eq!(after.nonce, 1, "replay protection is the ordinary account nonce");
}

#[test]
fn duplicate_announcement_in_block_rejected() {
    let p = params();
    let author = author_key();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.store.set_account(addr_of(&author), Account { balance: 1_000_000, nonce: 0 });
    r.sync(&chain, 1);
    let before = r.tip_hash();

    let mut bad = chain.clone();
    let ann = signed_announcement(&author, b"twice", 7, 0);
    let cb = bad.normal_coinbase(6, 14);
    bad.push_body(Scenario::encode_body(&[&cb, &ann, &ann]));

    r.offer(3, &blocks_above(&bad, 5));
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("the second copy replays nonce 0"));
    assert!(
        matches!(err, Reject::Tx { index: 2, err: TxError::BadNonce { expected: 1, got: 0 } }),
        "got {err:?}"
    );
    assert_eq!(r.tip_hash(), before);
}

#[test]
fn bad_sig_announcement_invalidates_block() {
    let p = params();
    let author = author_key();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.store.set_account(addr_of(&author), Account { balance: 1_000_000, nonce: 0 });
    r.sync(&chain, 1);

    let mut ann = signed_announcement(&author, b"tampered", 7, 0);
    let last = ann.len() - 1;
    ann[last] ^= 0x01;
    let mut bad = chain.clone();
    let cb = bad.normal_coinbase(6, 7);
    bad.push_body(Scenario::encode_body(&[&cb, &ann]));

    r.offer(3, &blocks_above(&bad, 5));
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("verify_strict said no"));
    assert!(matches!(err, Reject::Tx { index: 1, err: TxError::BadSignature }), "got {err:?}");
}

fn chain_with_coinbase(
    chain: &Scenario,
    height: u64,
    reward: u128,
    fees: u128,
    note: Vec<u8>,
    note_len_field: Option<u32>,
) -> Scenario {
    let mut s = chain.clone();
    let cb = Scenario::coinbase_bytes(height, s.miner, reward, fees, note);
    let body = Scenario::encode_body(&[&cb]);
    match note_len_field {
        None => {
            s.push_body(body);
        }
        Some(n) => {
            s.push_body_with(body, move |mut h| {
                h.author_note_len = n;
                h
            });
        }
    }
    s
}

#[test]
fn coinbase_wrong_height_rejected() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let bad = chain_with_coinbase(&chain, 99, emission::block_reward(6), 0, Vec::new(), None);
    let err = cause_of(reject_of(&chain, &bad));
    assert!(
        matches!(
            err,
            Reject::Tx { index: 0, err: TxError::CoinbaseHeightMismatch { header: 6, coinbase: 99 } }
        ),
        "got {err:?}"
    );
}

#[test]
fn coinbase_over_reward_rejected() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let bad =
        chain_with_coinbase(&chain, 6, emission::block_reward(6) + 1, 0, Vec::new(), None);
    let err = cause_of(reject_of(&chain, &bad));
    assert!(
        matches!(err, Reject::Tx { index: 0, err: TxError::CoinbaseRewardMismatch { .. } }),
        "got {err:?}"
    );
}

#[test]
fn coinbase_under_reward_rejected() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let bad =
        chain_with_coinbase(&chain, 6, emission::block_reward(6) - 1, 0, Vec::new(), None);
    let err = cause_of(reject_of(&chain, &bad));
    assert!(
        matches!(err, Reject::Tx { index: 0, err: TxError::CoinbaseRewardMismatch { .. } }),
        "got {err:?}"
    );
}

#[test]
fn coinbase_phantom_fees_rejected() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let bad = chain_with_coinbase(&chain, 6, emission::block_reward(6), 1, Vec::new(), None);
    let err = cause_of(reject_of(&chain, &bad));
    assert!(
        matches!(
            err,
            Reject::Tx { index: 0, err: TxError::CoinbaseFeesMismatch { expected: 0, got: 1 } }
        ),
        "got {err:?}"
    );
}

#[test]
fn note_len_header_mismatch_rejected() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let bad = chain_with_coinbase(
        &chain,
        6,
        emission::block_reward(6),
        0,
        b"hello".to_vec(),
        Some(4),
    );
    let err = cause_of(reject_of(&chain, &bad));
    assert!(
        matches!(
            err,
            Reject::Tx { index: 0, err: TxError::AuthorNoteLenMismatch { header: 4, coinbase: 5 } }
        ),
        "got {err:?}"
    );
}

#[test]
fn note_257_rejected_256_ok() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);

    let ok = chain_with_coinbase(
        &chain,
        6,
        emission::block_reward(6),
        0,
        vec![0x41; 256],
        Some(256),
    );
    let mut r = Rig::new(&chain, params());
    r.sync(&chain, 1);
    r.offer(3, &blocks_above(&ok, 5));
    assert!(matches!(r.cm.advance().expect("256 is legal"), Progress::Advanced { .. }));

    let bad = chain_with_coinbase(
        &chain,
        6,
        emission::block_reward(6),
        0,
        vec![0x41; 256],
        Some(257),
    );
    let mut r2 = Rig::new(&chain, params());
    r2.sync(&chain, 1);
    let a = r2.offer(3, &blocks_above(&bad, 5));
    assert_eq!(a.connected, 0, "S1 kills it for the price of a field read");
    assert_eq!(a.rejected, 1);
}

#[test]
fn body_root_mismatch_rejected() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut bad = chain.clone();
    bad.push_block(&[]);
    let other = Scenario::encode_body(&[&bad.normal_coinbase(6, 0), &[0x01u8; 157][..]]);
    bad.corrupt_tip_body(other);

    let p2 = params();
    let mut r = Rig::new(&chain, p2);
    r.sync(&chain, 1);
    let before = r.tip_hash();
    r.offer(3, &blocks_above(&bad, 5));
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("the body does not match the header"));
    assert!(
        matches!(err, Reject::TxRootMismatch | Reject::Tx { .. } | Reject::BodyStructure { .. }),
        "got {err:?}"
    );
    assert_eq!(r.tip_hash(), before);
}

#[test]
fn missing_coinbase_rejected() {
    let p = params();
    let user = user_key(0x40);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.store.set_account(addr_of(&user), Account { balance: 1_000_000, nonce: 0 });
    r.sync(&chain, 1);

    let mut bad = chain.clone();
    let t = signed_transfer(&user, [0xEE; 20], 1, 1, 0);
    bad.push_body(Scenario::encode_body(&[&t]));
    r.offer(3, &blocks_above(&bad, 5));
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("no coinbase"));
    assert!(matches!(err, Reject::Tx { err: TxError::MissingCoinbase, .. }), "got {err:?}");
}

#[test]
fn coinbase_spendable_only_at_maturity() {
    let maturity = plaine_consensus::constants::COINBASE_MATURITY;
    let p = params();
    let miner = user_key(0x51);
    let miner_addr = addr_of(&miner);

    let cb_height = 1u64;
    let first_spend = cb_height + maturity;
    let chain = Scenario::genesis(&p, T0).with_miner(miner_addr).extend(first_spend - 1);
    let reward1 = emission::block_reward(cb_height);
    assert!(reward1 > 10, "the fixture needs a spendable reward");

    let one_short = first_spend - 1;
    let mut early = chain.fork_at(one_short - 1);
    let t = signed_transfer(&miner, [0xEE; 20], 1, 1, 0);
    let cb = early.normal_coinbase(one_short, 1);
    early.push_body(Scenario::encode_body(&[&cb, &t]));
    let err = cause_of(reject_of(&chain.fork_at(one_short - 1), &early));
    assert!(
        matches!(err, Reject::InsufficientBalance { index: 1, need: 2, have: 0 }),
        "one block short of maturity the reward is still immature, got {err:?}"
    );

    let mut late = chain.clone();
    let cb = late.normal_coinbase(first_spend, 1);
    late.push_body(Scenario::encode_body(&[&cb, &t]));
    let mut r = Rig::new(&chain, params());
    r.sync(&chain, 1);
    r.offer(3, &blocks_above(&late, first_spend - 1));
    assert!(matches!(
        r.cm.advance().expect("mature at exactly M deep"),
        Progress::Advanced { .. }
    ));
    assert_eq!(r.cm.tip().hash, late.tip().hash);
}

#[test]
fn maturity_makes_every_reorgable_coinbase_unspendable() {
    use plaine_consensus::constants::{COINBASE_MATURITY, MAX_REORG_DEPTH};
    const { assert!(COINBASE_MATURITY > MAX_REORG_DEPTH) };

    let p = params();
    let miner = user_key(0x52);
    let miner_addr = addr_of(&miner);

    let tip_height = COINBASE_MATURITY + MAX_REORG_DEPTH;
    let spend_height = tip_height + 1;
    let deepest_reorgable = tip_height - MAX_REORG_DEPTH;
    let chain = Scenario::genesis(&p, T0).with_miner(miner_addr).extend(tip_height);

    assert!(
        spend_height - deepest_reorgable < COINBASE_MATURITY,
        "a reorgable coinbase must be short of maturity at the spend height"
    );

    let mut spend = chain.clone();
    let t = signed_transfer(&miner, [0xEE; 20], 1, 1, 0);
    let cb = spend.normal_coinbase(spend_height, 1);
    spend.push_body(Scenario::encode_body(&[&cb, &t]));

    let mut r = Rig::new(&chain, params());
    r.sync(&chain, 1);
    let spendable_now = {
        let newest_matured = spend_height - COINBASE_MATURITY;
        let mut total = 0u128;
        for h in 1..=newest_matured {
            total += emission::block_reward(h);
        }
        total
    };
    r.offer(3, &blocks_above(&spend, tip_height));
    r.cm.advance().expect("the spend is funded by matured rewards only");
    let acct = r.store.account(&miner_addr);
    assert!(acct.balance > 0);
    assert!(
        spendable_now > 2,
        "the matured part must be enough to pay 1 mile + 1 mile fee"
    );

    let mut greedy = chain.clone();
    let big = signed_transfer(&miner, [0xEE; 20], spendable_now, 1, 0);
    let cb = greedy.normal_coinbase(spend_height, 1);
    greedy.push_body(Scenario::encode_body(&[&cb, &big]));
    let err = cause_of(reject_of(&chain, &greedy));
    assert!(
        matches!(err, Reject::InsufficientBalance { index: 1, .. }),
        "immature coinbases must not fund it, got {err:?}"
    );
}

#[test]
fn bad_sig_transfer_invalidates_block() {
    let p = params();
    let user = user_key(0x60);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.store.set_account(addr_of(&user), Account { balance: 1_000_000, nonce: 0 });
    r.sync(&chain, 1);

    let mut t = signed_transfer(&user, [0xEE; 20], 1, 1, 0);
    let last = t.len() - 1;
    t[last] ^= 0x80;
    let mut bad = chain.clone();
    let cb = bad.normal_coinbase(6, 1);
    bad.push_body(Scenario::encode_body(&[&cb, &t]));
    r.offer(3, &blocks_above(&bad, 5));
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("verify_strict said no"));
    assert!(matches!(err, Reject::BadTransferSignature { index: 1 }), "got {err:?}");
}

#[test]
fn transfer_wrong_nonce_rejected() {
    let p = params();
    let user = user_key(0x61);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.store.set_account(addr_of(&user), Account { balance: 1_000_000, nonce: 0 });
    r.sync(&chain, 1);

    let mut bad = chain.clone();
    let t = signed_transfer(&user, [0xEE; 20], 1, 1, 5);
    let cb = bad.normal_coinbase(6, 1);
    bad.push_body(Scenario::encode_body(&[&cb, &t]));
    r.offer(3, &blocks_above(&bad, 5));
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("nonce 5 is not next"));
    assert!(
        matches!(err, Reject::BadNonce { index: 1, expected: 0, got: 5 }),
        "got {err:?}"
    );
}

#[test]
fn two_transfers_run_in_body_order() {
    let p = params();
    let user = user_key(0x62);
    let chain = Scenario::genesis(&p, T0).extend(5);

    let t0 = signed_transfer(&user, [0xEE; 20], 1, 1, 0);
    let t1 = signed_transfer(&user, [0xEE; 20], 1, 1, 1);

    {
        let mut r = Rig::new(&chain, params());
        r.store.set_account(addr_of(&user), Account { balance: 1_000_000, nonce: 0 });
        r.sync(&chain, 1);
        let mut good = chain.clone();
        let cb = good.normal_coinbase(6, 2);
        good.push_body(Scenario::encode_body(&[&cb, &t0, &t1]));
        r.offer(3, &blocks_above(&good, 5));
        assert!(matches!(r.cm.advance().expect("in order"), Progress::Advanced { .. }));
        let a = r.store.account(&addr_of(&user));
        assert_eq!(a.nonce, 2);
        assert_eq!(a.balance, 1_000_000 - 4);
    }
    {
        let mut r = Rig::new(&chain, params());
        r.store.set_account(addr_of(&user), Account { balance: 1_000_000, nonce: 0 });
        r.sync(&chain, 1);
        let mut bad = chain.clone();
        let cb = bad.normal_coinbase(6, 2);
        bad.push_body(Scenario::encode_body(&[&cb, &t1, &t0]));
        r.offer(3, &blocks_above(&bad, 5));
        assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("out of order"));
        assert!(
            matches!(err, Reject::BadNonce { index: 1, expected: 0, got: 1 }),
            "got {err:?}"
        );
    }
}

#[test]
fn transfer_below_fee_floor_rejected() {
    let p = params();
    let user = user_key(0x63);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.store.set_account(addr_of(&user), Account { balance: 1_000_000, nonce: 0 });
    r.sync(&chain, 1);

    let mut bad = chain.clone();
    let t = signed_transfer(&user, [0xEE; 20], 1, 0, 0);
    let cb = bad.normal_coinbase(6, 0);
    bad.push_body(Scenario::encode_body(&[&cb, &t]));
    r.offer(3, &blocks_above(&bad, 5));
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));
    let err = cause_of(r.cm.last_branch_failure().cloned().expect("zero fee"));
    assert!(matches!(err, Reject::FeeBelowFloor { index: 1 }), "got {err:?}");
}

#[test]
fn reserved_tx_type_rejected() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut bad = chain.clone();
    let cb = bad.normal_coinbase(6, 0);
    let reserved = vec![0x7Fu8; 64];
    bad.push_body(Scenario::encode_body(&[&cb, &reserved]));
    let err = cause_of(reject_of(&chain, &bad));
    assert!(
        matches!(err, Reject::Tx { index: 1, err: TxError::RecordDoesNotDecode { .. } }),
        "got {err:?}"
    );
}

#[test]
fn boots_on_genesis_plus_one() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(1);
    let _ = Rig::new(&chain, p);
}
