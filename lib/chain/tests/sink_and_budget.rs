mod support;

use plaine_chain::error::{BudgetClass, Condition};
use plaine_chain::mock::{PowMode, Scenario};
use plaine_chain::traits::SinkError;
use plaine_chain::{Progress, Reject};
use plaine_consensus::codec::Header;
use plaine_consensus::constants::MAX_HEADERS_PER_MSG;
use support::*;

fn rig_on(chain: &Scenario) -> Rig {
    let mut r = Rig::new(chain, params());
    r.sync(chain, 1);
    r
}

fn sibling_headers(chain: &Scenario, n: u64) -> Vec<[u8; 132]> {
    let mut fork = chain.clone();
    let child = fork.push_block(&[]);
    let base = Header::decode(&child.rec.raw).expect("132 bytes decode");
    (0..n)
        .map(|i| {
            let mut h = base;
            h.nonce = 0xDEAD_0000 + i;
            h.encode()
        })
        .collect()
}

#[test]
fn one_call_per_source_per_epoch() {
    let honest = Scenario::genesis(&params(), T0).extend(20);
    let mut r = Rig::with_mode(&honest, params(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let raws = sibling_headers(&honest, 500);
    for raw in &raws {
        let _ = r.cm.submit_headers(9, std::slice::from_ref(raw));
    }

    let calls = r.pow.calls();

    assert_eq!(calls, 1, "one failed call per source per tip epoch, and no more");
    assert_eq!(raws.len(), 500, "the other 499 were refused without a call");

    let micros_per_byte_now = (calls * 3_000) as f64 / (raws.len() * 132) as f64;
    assert!(micros_per_byte_now < 0.05, "got {micros_per_byte_now} us/byte");
    assert!(
        r.observed(|c| matches!(
            c,
            Condition::BudgetExhausted { class: BudgetClass::ChildQuota, .. }
        )),
        "the refusal must be observable, or it gets rediscovered as a mystery"
    );
}

#[test]
fn fraudulent_branch_one_call() {
    let honest = Scenario::genesis(&params(), T0).extend(20);
    let mut r = Rig::with_mode(&honest, params(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let attacker = honest.fork_at(10).extend(200);
    let raws: Vec<[u8; 132]> =
        attacker.blocks.iter().skip(11).map(|b| b.rec.raw).collect();
    let _ = r.cm.submit_headers(9, &raws);
    assert_eq!(r.pow.calls(), 1, "front-loading dies at header 1");
}

#[test]
fn interpreter_budget_per_source_and_global() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    const SOURCES: u64 = 8;
    let raws = sibling_headers(&honest, SOURCES * 120);
    let mut i = 0usize;
    for s in 0..SOURCES {
        for _ in 0..120 {
            let _ = r.cm.submit_headers(1_000 + s as u32, std::slice::from_ref(&raws[i]));
            i += 1;
        }
    }

    let calls = r.pow.calls();

    assert_eq!(calls, SOURCES, "one failed call per source, not one burst per source");

    let class = p.class_rate_micros_per_sec();
    assert_eq!(class, 500_000, "P defaults to the VPS floor of 2");
    let aggregate = p.class_shared_rate_micros_per_sec()
        + p.class_reserve_rate_micros_per_sec() * p.max_peers as u64;

    assert!(aggregate <= class, "the two tiers may never sum above the cap");
    assert!(
        class - aggregate < p.max_peers as u64,
        "the shortfall is only the per-source truncation: {} us/s",
        class - aggregate
    );

    assert!(128 * 100_000 / 10 > class, "tier 1 alone still exceeds the class cap");
}

#[test]
fn oversized_batch_refused() {
    let honest = Scenario::genesis(&params(), T0).extend(5);
    let mut r = Rig::with_mode(&honest, params(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();
    let arena_before = r.cm.index().len();
    let sources_before = r.cm.source_count();

    let orphans: Vec<[u8; 132]> = (0..20_000u64)
        .map(|i| {
            let mut h = Header::decode(&honest.tip().raw).expect("decodes");
            h.prev_hash = [0x5A; 32];
            h.nonce = i;
            h.encode()
        })
        .collect();

    assert_eq!(
        r.cm.submit_headers(11, &orphans),
        Err(Reject::BatchTooLong { got: 20_000, cap: MAX_HEADERS_PER_MSG })
    );
    assert_eq!(r.pow.calls(), 0, "no interpreter call");
    assert_eq!(r.cm.index().len(), arena_before, "nothing was staged or connected");

    assert_eq!(r.cm.source_count(), sources_before, "no per-source state was allocated");

    assert!(r.cm.submit_headers(11, &orphans[..MAX_HEADERS_PER_MSG]).is_ok());
}

#[test]
fn cheap_reject_skips_sig() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(3);
    let mut r = rig_on(&honest);
    let victim = user_key(0x21);
    let to = addr_of(&user_key(0x22));

    let stale = signed_transfer(&victim, to, 1, 1, 9);
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Peer(7), stale).expect_err("refused"),
        Reject::BelowRelayFloor { .. }
    ));

    let mut forged = signed_transfer(&victim, to, 1, 1, 9);
    let n = forged.len();
    forged[n - 1] ^= 0xFF;
    assert!(
        matches!(
            r.cm.submit_tx(TxOrigin::Peer(7), forged),
            Err(Reject::BelowRelayFloor { .. })
        ),
        "a broken signature behind a cheap rule proves the cheap rule ran first"
    );

    let mut broke = signed_transfer(&victim, to, 1, 2_000_000, 9);
    let n = broke.len();
    broke[n - 1] ^= 0xFF;
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Peer(7), broke),
        Err(Reject::InsufficientBalance { .. })
    ));

    r.store.set_account(
        addr_of(&victim),
        plaine_chain::types::Account { balance: 10_000_000, nonce: 0 },
    );
    let mut good_but_forged = signed_transfer(&victim, to, 1, 2_000_000, 0);
    let n = good_but_forged.len();
    good_but_forged[n - 1] ^= 0xFF;
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Peer(7), good_but_forged),
        Err(Reject::BadTransferSignature { .. })
    ));
}

#[test]
fn mempool_ingress_per_source_and_global() {
    let p = params();
    assert_eq!(p.mempool.ingress_per_source, 100);
    assert_eq!(p.mempool.ingress_global, 2_000);

    let honest = Scenario::genesis(&p, T0).extend(3);
    let mut r = rig_on(&honest);
    let victim = user_key(0x31);
    let to = addr_of(&user_key(0x32));

    let mut past_bucket = 0u32;
    let mut refused = 0u32;
    for i in 0..120u64 {
        let tx = signed_transfer(&victim, to, 1, 1, i);
        match r.cm.submit_tx(TxOrigin::Peer(31), tx) {
            Err(Reject::BudgetExhausted { source: 31 }) => refused += 1,
            Err(Reject::BelowRelayFloor { .. }) => past_bucket += 1,
            other => panic!("unexpected {other:?}"),
        }
    }

    assert_eq!(past_bucket, 100, "the per-source rate is the declared 100 tx/s");
    assert_eq!(refused, 20);
    assert!(r.observed(|c| matches!(
        c,
        Condition::BudgetExhausted { class: BudgetClass::TxIngress, .. }
    )));

    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Local, signed_transfer(&victim, to, 1, 1, 0)),
        Err(Reject::BelowRelayFloor { .. })
    ));
}

#[test]
fn refusing_sink_keeps_old_chain() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(30);
    let mut r = rig_on(&honest);
    let before_tip = r.tip_hash();
    let before_state = r.store.account_table();
    let before_canon = r.store.canonical_hashes();

    let attacker = honest.fork_at(20).spacing(30).extend(15);
    r.offer(4, &blocks_above(&attacker, 20));
    r.store.fail_next_commit(SinkError::Invalid("refused on purpose"));

    let e = r.cm.advance().expect_err("the sink refused");
    assert!(matches!(e, Reject::SinkRefused { .. }), "got {e:?}");
    assert_eq!(r.tip_hash(), before_tip, "tip unmoved");
    assert_eq!(r.store.account_table(), before_state, "state byte-identical");
    assert_eq!(r.store.canonical_hashes(), before_canon, "canonical index unmoved");
    assert!(r.cm.halted().is_none(), "Invalid is refusal, not corruption");

    match r.cm.advance().expect("retry") {
        Progress::Advanced { .. } => {}
        other => panic!("expected the retry to adopt, got {other:?}"),
    }
    assert_ne!(r.tip_hash(), before_tip, "the second attempt moved the tip");
}

#[test]
fn fatal_sink_halts_before_republish() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(30);
    let mut r = rig_on(&honest);
    let before_tip = r.tip_hash();
    let before_state = r.store.account_table();

    let attacker = honest.fork_at(20).spacing(30).extend(15);
    r.offer(4, &blocks_above(&attacker, 20));
    r.store.fail_next_commit(SinkError::Fatal("writer lost track"));

    let e = r.cm.advance().expect_err("fatal");
    assert!(matches!(e, Reject::Halted { .. }), "got {e:?}");
    assert!(r.cm.halted().is_some(), "halting is a state, not a log line");
    assert_eq!(r.cm.tip().hash, before_tip, "the arena still names the old tip");
    assert_eq!(r.store.account_table(), before_state);

    assert!(matches!(r.cm.advance(), Err(Reject::Halted { .. })));
    assert!(matches!(r.cm.submit_headers(1, &[]), Err(Reject::Halted { .. })));
    assert!(matches!(r.cm.submit_block(&[0u8; 32], vec![]), Err(Reject::Halted { .. })));
}

#[test]
fn rollback_double_write_restores() {
    let p = params();
    let miner = user_key(0x41);
    let sender = user_key(0x42);
    let m_addr = addr_of(&miner);
    let s_addr = addr_of(&sender);

    let honest = Scenario::genesis(&p, T0).with_miner(m_addr).extend(20);
    let mut r = rig_on(&honest);
    r.store.set_account(s_addr, plaine_chain::types::Account { balance: 5_000_000, nonce: 0 });
    let m_before = r.store.account(&m_addr);
    let s_before = r.store.account(&s_addr);
    assert!(m_before.balance > 0, "the miner must already hold coinbase value");

    let mut branch = honest.fork_at(20).with_miner(m_addr);
    let xfer = signed_transfer(&sender, m_addr, 1_000, 7, 0);
    branch.push_block(&[xfer]);
    r.offer(3, &blocks_above(&branch, 20));
    r.cm.advance().expect("adopted");
    assert_eq!(r.height(), 21);
    assert_eq!(
        r.store.account(&m_addr).balance,
        m_before.balance + 1_000 + plaine_consensus::emission::block_reward(21) + 7,
        "the block credited M twice: subsidy + fees, and the transfer"
    );

    let heavier = honest.fork_at(20).with_miner(m_addr).spacing(1).extend(3);
    r.offer(4, &blocks_above(&heavier, 20));
    r.cm.advance().expect("reorged");
    assert_eq!(r.cm.tip().hash, heavier.tip().hash);

    let expected: u128 = m_before.balance
        + (21..=23).map(plaine_consensus::emission::block_reward).sum::<u128>();
    assert_eq!(
        r.store.account(&m_addr).balance,
        expected,
        "rollback restored a mid-block epoch instead of the pre-block value"
    );
    assert_eq!(r.store.account(&s_addr), s_before, "the sender is whole again");
}

#[test]
fn mid_branch_failure_restores_state() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(30);
    let mut r = rig_on(&honest);
    let before_tip = r.tip_hash();
    let before_state = r.store.account_table();
    let commits_before = r.store.commit_count();

    let mut attacker = honest.fork_at(20).spacing(30);
    attacker = attacker.extend(5);
    attacker.push_block(&[]);
    attacker.corrupt_tip_body(attacker.normal_coinbase(99, 7));
    attacker = attacker.extend(4);

    r.offer(4, &blocks_above(&attacker, 20));
    let _ = r.cm.advance();

    assert_eq!(r.tip_hash(), before_tip, "tip unmoved");
    assert_eq!(r.store.account_table(), before_state, "no persistent byte moved");
    assert_eq!(r.store.commit_count(), commits_before, "the sink was never called");
    assert!(r.cm.last_branch_failure().is_some(), "the cause survives for the operator");
}
