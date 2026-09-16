mod support;

use std::time::Instant;

use plaine_chain::error::{BudgetClass, Condition};
use plaine_chain::mock::{BuiltBlock, PowMode, Scenario};
use plaine_chain::types::{Account, Address};
use plaine_chain::{ChainParams, Progress, Reject};
use plaine_consensus::codec::Header;
use support::*;

fn children_of_tip(chain: &Scenario, n: u64) -> Vec<[u8; 132]> {
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

fn tie_break_winning_sibling(chain: &Scenario, miner: Address, tip_hash: [u8; 32]) -> BuiltBlock {
    let at = chain.height() - 1;
    for k in 0..1_000_000u64 {
        let mut f = chain.fork_at(at).with_miner(miner);
        let b = f.push_block_with(&[], move |mut h| {
            h.nonce = k;
            h
        });
        if b.rec.hash < tip_hash {
            return b;
        }
    }
    panic!("no lower-hash sibling in a million nonces");
}

#[test]
fn sibling_flood_one_call_per_source() {
    let honest = Scenario::genesis(&params(), T0).extend(20);
    let mut r = Rig::with_mode(&honest, params(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    for raw in &children_of_tip(&honest, 500) {
        let _ = r.cm.submit_headers(9, std::slice::from_ref(raw));
    }
    assert_eq!(r.pow.calls(), 1, "one failed call, then the quota");
    assert!(r.observed(|c| matches!(
        c,
        Condition::BudgetExhausted { source: 9, class: BudgetClass::ChildQuota }
    )));
}

#[test]
fn quota_is_per_source() {
    let honest = Scenario::genesis(&params(), T0).extend(20);
    let mut r = Rig::with_mode(&honest, params(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let raws = children_of_tip(&honest, 40);
    for (i, raw) in raws.iter().enumerate() {
        let source = 100 + (i as u32 % 4);
        let _ = r.cm.submit_headers(source, std::slice::from_ref(raw));
    }
    assert_eq!(r.pow.calls(), 4, "four sources, four first calls, no more");
}

#[test]
fn quota_rolls_on_tip_advance() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let junk = children_of_tip(&honest, 4);
    for raw in &junk {
        let _ = r.cm.submit_headers(9, std::slice::from_ref(raw));
    }
    assert_eq!(r.pow.calls(), 1);

    r.pow.set_mode(PowMode::AlwaysOk);
    let grown = honest.clone().extend(1);
    r.clock.set_unix(grown.tip().time);
    r.offer(1, &blocks_above(&grown, 20));
    assert!(matches!(r.cm.advance(), Ok(Progress::Advanced { .. })));

    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();
    for raw in &children_of_tip(&grown, 4) {
        let _ = r.cm.submit_headers(9, std::slice::from_ref(raw));
    }
    assert_eq!(r.pow.calls(), 1, "a new epoch buys exactly one more first call");
}

#[test]
fn honest_headers_never_consume_the_child_quota() {
    let honest = Scenario::genesis(&params(), T0).extend(20);
    let mut r = Rig::with_mode(&honest, params(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let raws = children_of_tip(&honest, 8);
    let mut connected = 0u64;
    for raw in &raws {
        connected += r.cm.submit_headers(9, std::slice::from_ref(raw)).expect("ok").connected;
    }
    assert_eq!(connected, 8, "every honest header connects");
    assert_eq!(r.pow.calls(), 8, "each cost exactly one call, quota untouched");
    assert!(!r.observed(|c| matches!(
        c,
        Condition::BudgetExhausted { class: BudgetClass::ChildQuota, .. }
    )));
}

#[test]
fn honest_sibling_accepted_promptly() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let other_miner = addr_of(&user_key(0x71));
    let rival = tie_break_winning_sibling(&honest, other_miner, r.tip_hash());
    let a = r.cm.submit_headers(42, &[rival.rec.raw]).expect("not halted");
    assert_eq!(a.connected, 1, "the rival block is verified on arrival");
    assert_eq!(r.pow.calls(), 1, "one call, the same as any honest header");

    r.cm.submit_block(&rival.rec.hash, rival.body.clone()).expect("body admissible");
    assert!(matches!(r.cm.advance(), Ok(Progress::Advanced { .. })));
    assert_eq!(r.tip_hash(), rival.rec.hash, "the lower-hash sibling wins the tie");
}

#[test]
fn class_budget_holds_at_128_sources() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    const SOURCES: u64 = 128;
    const EACH: u64 = 120;
    let raws = children_of_tip(&honest, SOURCES * EACH);
    let mut i = 0usize;
    for s in 0..SOURCES {
        for _ in 0..EACH {
            let _ = r.cm.submit_headers(2_000 + s as u32, std::slice::from_ref(&raws[i]));
            i += 1;
        }
    }

    let cost = 3_000u64;
    let calls = r.pow.calls();

    assert_eq!(calls, 339, "83 shared + 2 reserved + 127 x 2 reserved");

    let burst_cap = p.class_shared_burst_micros()
        + p.class_reserve_burst_micros(cost) * p.max_peers as u64;
    assert_eq!(burst_cap, 1_018_000, "250 ms shared + 128 x 6 ms reserved");
    assert!(
        calls * cost <= burst_cap,
        "{} us drawn against a {} us class burst",
        calls * cost,
        burst_cap
    );

    assert!(calls * cost * 37 < 38_400_000);

    r.pow.reset();
    r.clock.advance_ms(1_000);
    let more = children_of_tip(&honest, SOURCES);
    for (s, raw) in more.iter().enumerate() {
        let _ = r.cm.submit_headers(2_000 + s as u32, std::slice::from_ref(raw));
    }
    let sustained = r.pow.calls() * cost;
    assert!(
        sustained <= p.class_rate_micros_per_sec(),
        "{sustained} us in one second against a {} us/s cap",
        p.class_rate_micros_per_sec()
    );
}

#[test]
fn honest_peer_keeps_reserve_under_flood() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    const HOSTILE: usize = 30;
    const PER_SEC: usize = 4;
    const SECONDS: usize = 60;
    let flood = children_of_tip(&honest, (HOSTILE * PER_SEC * SECONDS) as u64);
    let mine = children_of_tip(&honest, SECONDS as u64);

    let mut i = 0usize;
    let mut honest_calls = 0u64;
    for one_per_second in &mine {
        for _ in 0..PER_SEC {
            for h in 0..HOSTILE {
                let _ = r.cm.submit_headers(3_000 + h as u32, std::slice::from_ref(&flood[i]));
                i += 1;
            }
        }
        let before = r.pow.calls();
        let mut raw = *one_per_second;
        raw[128] ^= 0xA5;
        let _ = r.cm.submit_headers(9_999, std::slice::from_ref(&raw));
        honest_calls += r.pow.calls() - before;
        r.clock.advance_ms(1_000);
    }
    assert!(
        honest_calls >= 39,
        "the honest peer got {honest_calls} calls in 60 s; the reserve guarantees 39"
    );

    assert!(
        r.observed(|c| matches!(
            c,
            Condition::BudgetExhausted { class: BudgetClass::Interpreter, .. }
        )),
        "the flood must actually have exhausted the shared budget"
    );
}

#[test]
fn boot_invariant_refuses_starving_config() {
    let chain = Scenario::genesis(&params(), T0).extend(1);
    let edge = 2_500usize;
    let ok = ChainParams { max_peers: edge, ..params() };
    assert!(ok.class_reserve_is_survivable(3_000));
    let _ = Rig::new(&chain, ok);

    let bad = ChainParams { max_peers: edge + 1, ..params() };
    assert!(!bad.class_reserve_is_survivable(3_000));
    let g = chain.blocks[0].clone();
    let store = std::sync::Arc::new(plaine_chain::mock::MemStore::with_genesis(
        g.rec,
        g.body,
        &bad,
    ));
    let pow = std::sync::Arc::new(plaine_chain::mock::CountingPow::new(PowMode::AlwaysOk));
    let clock = std::sync::Arc::new(plaine_chain::mock::MockClock::new(T0));
    let built = ChainManager::new(store.clone(), store.clone(), pow, clock, bad, None);
    assert!(
        matches!(built, Err(Reject::BootInvariant { .. })),
        "one peer past the boundary must refuse to boot"
    );
}

#[test]
fn duplicate_header_in_batch_connects_once() {
    let honest = Scenario::genesis(&params(), T0).extend(20);
    let mut r = Rig::with_mode(&honest, params(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();
    let arena_before = r.cm.index().len();

    let raw = children_of_tip(&honest, 1)[0];
    let a = r.cm.submit_headers(9, &[raw, raw]).expect("not halted");
    assert_eq!(a.connected, 1, "one header, one connection");
    assert_eq!(a.duplicates, 1, "the echo is a duplicate, not a second header");
    assert_eq!(r.pow.calls(), 1, "it costs exactly one interpreter call");
    assert_eq!(r.cm.index().len(), arena_before + 1, "the arena grew by exactly one node");

    r.pow.reset();
    let raw2 = children_of_tip(&honest, 2)[1];
    let batch: Vec<[u8; 132]> = (0..500).map(|_| raw2).collect();
    let b = r.cm.submit_headers(10, &batch).expect("not halted");
    assert_eq!(b.connected, 1);
    assert_eq!(r.pow.calls(), 1, "500 copies, one call");
}

#[test]
fn one_shot_sources_dont_grow_map() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);

    let mut orphan = Header::decode(&honest.tip().raw).expect("decodes");
    orphan.prev_hash = [0x5A; 32];
    for s in 0..10_000u32 {
        orphan.nonce = s as u64;
        let _ = r.cm.submit_headers(s, &[orphan.encode()]);
    }
    assert!(
        r.cm.source_count() <= p.max_sources,
        "{} rows held against a cap of {}",
        r.cm.source_count(),
        p.max_sources
    );
}

#[test]
fn owing_source_not_evicted_for_newcomer() {
    let p = ChainParams { max_sources: 4, ..params() };
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);

    r.cm.forget_source(1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let raws = children_of_tip(&honest, 4);
    for (i, raw) in raws.iter().enumerate() {
        let _ = r.cm.submit_headers(i as u32, std::slice::from_ref(raw));
    }
    assert_eq!(r.pow.calls(), 4);
    assert_eq!(r.cm.source_count(), 4);

    let fresh = children_of_tip(&honest, 5)[4];
    assert_eq!(
        r.cm.submit_headers(99, &[fresh]),
        Err(Reject::TooManySources { source: 99, cap: 4 })
    );
    assert_eq!(r.pow.calls(), 4, "it bought no interpreter call either");

    r.cm.forget_source(0);
    assert_eq!(r.cm.source_count(), 3);
    assert!(r.cm.submit_headers(99, &[fresh]).is_ok());
}

#[test]
fn mempool_ingress_binds_globally() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(3);
    let mut r = Rig::new(&honest, p.clone());
    r.sync(&honest, 1);
    let to = addr_of(&user_key(0x52));

    let mut past = 0u32;
    let mut refused = 0u32;
    for s in 0..128u32 {
        for i in 0..20u64 {
            let tx = plaine_chain::mock::unsigned_transfer([(s % 200) as u8 + 1; 32], to, 1, 1, i);
            match r.cm.submit_tx(TxOrigin::Peer(s), tx) {
                Err(Reject::BudgetExhausted { .. }) => refused += 1,
                Err(Reject::BelowRelayFloor { .. }) => past += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    assert_eq!(past, 1_156, "1,000 shared + the reserves of the sources that reached them");
    assert_eq!(refused, 2_560 - 1_156);
    let cap = (p.mempool.ingress_global as u64) / 2
        + 2 * p.max_peers as u64;
    assert!(past as u64 <= cap, "{past} against a burst cap of {cap}");

    let fresh = plaine_chain::mock::unsigned_transfer([0xC7; 32], to, 1, 1, 0);
    assert_eq!(
        r.cm.submit_tx(TxOrigin::Peer(900), fresh),
        Err(Reject::TooManySources { source: 900, cap: p.max_sources })
    );

    r.clock.advance_ms(1_000);
    let fresh = plaine_chain::mock::unsigned_transfer([0xC7; 32], to, 1, 1, 0);
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Peer(900), fresh),
        Err(Reject::BelowRelayFloor { .. })
    ));

    let local = plaine_chain::mock::unsigned_transfer([0xC8; 32], to, 1, 1, 0);
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Local, local),
        Err(Reject::BelowRelayFloor { .. })
    ));
}

#[test]
fn ingress_budget_refills_at_rate() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(3);
    let mut r = Rig::new(&honest, p.clone());
    r.sync(&honest, 1);
    let to = addr_of(&user_key(0x53));

    let spend = |r: &mut Rig, n: u64| -> u32 {
        let mut past = 0;
        for i in 0..n {
            let tx = plaine_chain::mock::unsigned_transfer([0x5B; 32], to, 1, 1, i);
            if matches!(r.cm.submit_tx(TxOrigin::Peer(5), tx), Err(Reject::BelowRelayFloor { .. }))
            {
                past += 1;
            }
        }
        past
    };
    assert_eq!(spend(&mut r, 150), 100, "the burst is one second of the rate");
    assert_eq!(spend(&mut r, 10), 0, "it is empty");
    r.clock.advance_ms(1_000);
    assert_eq!(spend(&mut r, 150), 100, "one second buys 100 back");
}

#[test]
fn failed_replacement_keeps_incumbent() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(3);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let victim = user_key(0x61);
    let to = addr_of(&user_key(0x62));
    r.store.set_account(addr_of(&victim), Account { balance: 100_000_000, nonce: 0 });

    let good = signed_transfer(&victim, to, 1, 2_000_000, 0);
    let admitted = r.cm.submit_tx(TxOrigin::Local, good).expect("valid");
    assert_eq!(r.cm.mempool().len(), 1);

    let mut forged = signed_transfer(&victim, to, 1, 2_600_000, 0);
    let n = forged.len();
    forged[n - 1] ^= 0xFF;
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Peer(3), forged),
        Err(Reject::BadTransferSignature { .. })
    ));

    assert_eq!(r.cm.mempool().len(), 1, "the pool still holds exactly one transaction");
    assert!(
        r.cm.mempool().get(&admitted.txid).is_some(),
        "it is the victim's, with its original txid"
    );
    assert!(r.cm.mempool().get(&admitted.txid).expect("present").executable);

    let honest_bump = signed_transfer(&victim, to, 1, 2_600_000, 0);
    let second = r.cm.submit_tx(TxOrigin::Local, honest_bump).expect("valid replacement");
    assert_eq!(second.removed, vec![admitted.txid]);
    assert_eq!(r.cm.mempool().len(), 1);
}

#[test]
fn refused_submission_no_residue() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(3);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let to = addr_of(&user_key(0x64));

    for s in 1..=64u8 {
        let tx = plaine_chain::mock::unsigned_transfer([s; 32], to, 1, 2_000_000, 0);
        assert!(matches!(
            r.cm.submit_tx(TxOrigin::Local, tx),
            Err(Reject::InsufficientBalance { .. })
        ));
    }
    assert!(r.cm.mempool().is_empty());
    assert_eq!(
        r.cm.mempool().tracked_senders(),
        0,
        "64 refusals from 64 fresh senders must leave nothing behind"
    );

    let victim = user_key(0x67);
    r.store.set_account(addr_of(&victim), Account { balance: 100_000_000, nonce: 0 });
    let admitted = r
        .cm
        .submit_tx(TxOrigin::Local, signed_transfer(&victim, to, 1, 2_000_000, 0))
        .expect("valid");
    assert_eq!(r.cm.mempool().tracked_senders(), 1);
    assert!(r.cm.mempool().get(&admitted.txid).is_some());

    r.clock.set_unix(T0 + 48 * 3_600);
    let other = user_key(0x68);
    r.store.set_account(addr_of(&other), Account { balance: 100_000_000, nonce: 0 });
    r.cm.submit_tx(TxOrigin::Local, signed_transfer(&other, to, 1, 2_000_000, 0))
        .expect("valid");
    assert!(r.cm.mempool().get(&admitted.txid).is_none(), "the TTL sweep ran");
    assert_eq!(
        r.cm.mempool().tracked_senders(),
        1,
        "it took the expired sender's memo with it, leaving only the newcomer"
    );
}

#[test]
fn cheap_reject_skips_sig_check() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(3);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let victim = user_key(0x65);
    let to = addr_of(&user_key(0x66));

    let signed = signed_transfer(&victim, to, 1, 2_000_000, 0);
    let decoded = plaine_consensus::codec::decode_tx(&signed).expect("decodes");
    let t = Instant::now();
    for _ in 0..200 {
        if let plaine_consensus::codec::Tx::Transfer(x) = &decoded {
            let _ = plaine_consensus::crypto::verify_transfer_signature(support::TEST_NETWORK, x);
        }
    }
    let sig_ns = t.elapsed().as_nanos() / 200;

    let spam = signed_transfer(&victim, to, 1, 1, 0);
    let t = Instant::now();
    for _ in 0..200 {
        let _ = r.cm.submit_tx(TxOrigin::Local, spam.clone());
    }
    let reject_ns = t.elapsed().as_nanos() / 200;

    eprintln!(
        "rejected spam tx: {reject_ns} ns/tx; one verify_strict: {sig_ns} ns/tx; \
         ratio {:.1}x",
        sig_ns as f64 / reject_ns.max(1) as f64
    );

    assert!(
        reject_ns * 5 < sig_ns,
        "a cheaply refused tx cost {reject_ns} ns against {sig_ns} ns for one signature"
    );
}
