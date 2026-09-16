mod support;

use plaine_chain::error::Reject;
use plaine_chain::mock::Scenario;
use plaine_chain::types::Account;
use plaine_chain::{Progress, Store};
use plaine_consensus::emission;
use support::*;

fn rig_with_funds(chain: &Scenario, who: [u8; 20], balance: u128) -> Rig {
    let mut r = Rig::new(chain, params());
    r.store.set_account(who, Account { balance, nonce: 0 });
    r.sync(chain, 1);
    r
}

#[test]
fn valid_sig_admitted_broken_rejected() {
    let p = params();
    let user = user_key(0x70);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_with_funds(&chain, addr_of(&user), 1_000_000_000);

    let good = signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 0);
    let a = r.cm.submit_tx(TxOrigin::Local, good).expect("valid");
    assert!(a.executable, "nonce 0 is the sender's next nonce");
    assert_eq!(r.cm.mempool().len(), 1);

    let mut bad = signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 1);
    let last = bad.len() - 1;
    bad[last] ^= 0x40;
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Local, bad),
        Err(Reject::BadTransferSignature { index: 0 })
    ));
    assert_eq!(r.cm.mempool().len(), 1);
}

#[test]
fn wrong_key_announcement_not_pooled() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_with_funds(&chain, addr_of(&impostor_key()), 1_000_000_000);
    let ann = signed_announcement(&impostor_key(), b"not the author", 2_000_000, 0);
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Local, ann),
        Err(Reject::Tx { index: 0, err: plaine_consensus::tx::TxError::NotAuthorKey })
    ));
    assert_eq!(r.cm.mempool().len(), 0);
}

#[test]
fn immature_coinbase_spend_refused() {
    let maturity = plaine_consensus::constants::COINBASE_MATURITY;
    let p = params();
    let miner = user_key(0x71);
    let m = addr_of(&miner);
    let chain = Scenario::genesis(&p, T0).with_miner(m).extend(maturity - 1);
    let mut r = Rig::new(&chain, params());
    r.sync(&chain, 1);
    assert!(r.store.account(&m).balance > 0, "the miner has been paid");

    let tx = signed_transfer(&miner, [0xEE; 20], 1, 2_000_000, 0);
    let err = r.cm.submit_tx(TxOrigin::Local, tx).expect_err("every reward is still immature");
    assert!(matches!(err, Reject::InsufficientBalance { .. }), "got {err:?}");
    assert_eq!(r.cm.mempool().len(), 0);
}

#[test]
fn matured_coinbase_spend_admitted() {
    let p = params();
    let miner = user_key(0x72);
    let m = addr_of(&miner);

    let maturity = plaine_consensus::constants::COINBASE_MATURITY;
    let tip = maturity + 5;
    let chain = Scenario::genesis(&p, T0).with_miner(m).extend(tip);
    let mut r = Rig::new(&chain, params());
    r.sync(&chain, 1);

    let newest_matured = tip + 1 - maturity;
    assert_eq!(newest_matured, 6);
    let matured: u128 = (1..=newest_matured).map(emission::block_reward).sum();
    assert!(matured > 3, "the fixture needs something spendable");
    let tx = signed_transfer(&miner, [0xEE; 20], 1, 2, 0);
    let mut params_low = params();
    params_low.mempool.relay_fee_floor = 1;
    let mut r2 = Rig::new(&chain, params_low);
    r2.sync(&chain, 1);
    let a = r2.cm.submit_tx(TxOrigin::Local, tx).expect("the matured part covers 1 + 2 mile");
    assert!(a.executable);
    let _ = r.cm.mempool().len();
}

#[test]
fn connected_block_removes_mined_txs() {
    let p = params();
    let user = user_key(0x73);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_with_funds(&chain, addr_of(&user), 1_000_000_000);

    let t0 = signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 0);
    let t1 = signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 1);
    r.cm.submit_tx(TxOrigin::Local, t0.clone()).expect("valid");
    r.cm.submit_tx(TxOrigin::Local, t1.clone()).expect("valid");
    assert_eq!(r.cm.mempool().len(), 2);

    let mut next = chain.clone();
    let cb = next.normal_coinbase(6, 2_000_000);
    next.push_body(Scenario::encode_body(&[&cb, &t0]));
    r.offer(3, &blocks_above(&next, 5));
    assert!(matches!(r.cm.advance().expect("adopted"), Progress::Advanced { .. }));

    assert_eq!(r.cm.mempool().len(), 1, "the mined one is gone, the other is not");
    assert_eq!(r.store.account(&addr_of(&user)).nonce, 1);
}

#[test]
fn reorg_reinjects_disconnected_txs() {
    let p = params();
    let user = user_key(0x74);
    let u = addr_of(&user);
    let chain = Scenario::genesis(&p, T0).extend(20);
    let mut r = rig_with_funds(&chain, u, 1_000_000_000);

    let t0 = signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 0);
    let mut honest = chain.clone();
    let cb = honest.normal_coinbase(21, 2_000_000);
    honest.push_body(Scenario::encode_body(&[&cb, &t0]));
    r.offer(3, &blocks_above(&honest, 20));
    assert!(matches!(r.cm.advance().expect("adopted"), Progress::Advanced { .. }));
    assert_eq!(r.store.account(&u).nonce, 1);
    assert_eq!(r.cm.mempool().len(), 0);

    let attacker = chain.fork_at(20).spacing(1).extend(3);
    r.offer(4, &blocks_above(&attacker, 20));
    match r.cm.advance().expect("adopted") {
        Progress::Advanced { rolled_back, tip, .. } => {
            assert_eq!(rolled_back, 1);
            assert_eq!(tip.hash, attacker.tip().hash);
        }
        other => panic!("expected a reorg, got {other:?}"),
    }

    assert_eq!(r.store.account(&u).nonce, 0, "the reorg moved the nonce backwards");
    assert_eq!(r.cm.mempool().len(), 1, "the disconnected transaction was re-injected");
    let pooled = r.cm.mempool().executable_ids();
    assert_eq!(pooled.len(), 1, "it is executable again against the new state");
}

#[test]
fn template_uses_executable_only() {
    let p = params();
    let user = user_key(0x75);
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_with_funds(&chain, addr_of(&user), 1_000_000_000);

    r.cm.submit_tx(TxOrigin::Local, signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 0)).expect("valid");
    let q = r.cm.submit_tx(TxOrigin::Local, signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 2)).expect("queued");
    assert!(!q.executable, "a future nonce waits, it is not dropped");
    assert_eq!(r.cm.mempool().len(), 2);

    let t = r.cm.block_template();
    assert_eq!(t.len(), 1, "only the executable run goes into a template");

    let a = r.cm.submit_tx(TxOrigin::Local, signed_transfer(&user, [0xEE; 20], 10, 2_000_000, 1)).expect("filler");
    assert!(a.executable);
    assert_eq!(a.promoted.len(), 1, "nonce 2 promotes with it");
    assert_eq!(r.cm.block_template().len(), 3);
}

#[test]
fn coinbase_not_relayable() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, params());
    r.sync(&chain, 1);
    let cb = Scenario::coinbase_bytes(6, [0x33; 20], 1, 0, Vec::new());
    assert!(matches!(r.cm.submit_tx(TxOrigin::Local, cb), Err(Reject::TxTypeNotRelayable { type_byte: 0x00 })));
}
