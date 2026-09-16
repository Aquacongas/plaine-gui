mod support;

use std::sync::Arc;

use plaine_chain::error::{BudgetClass, Condition};
use plaine_chain::mempool::{Mempool, SigProof};
use plaine_chain::mock::{CountingPow, MemStore, MockClock, PowMode, Scenario};
use plaine_chain::traits::SinkError;
use plaine_chain::types::{Account, MempoolParams};
use plaine_chain::{ChainManager, ChainParams, Progress, Reject};
use plaine_consensus::codec::{decode_tx, Header, Tx};
use support::*;

fn children_of(chain: &Scenario, parent_height: u64, n: u64) -> Vec<[u8; 132]> {
    let mut fork = chain.fork_at(parent_height);
    let child = fork.push_block(&[]);
    let base = Header::decode(&child.rec.raw).expect("132 bytes decode");
    (0..n)
        .map(|i| {
            let mut h = base;
            h.nonce = 0xC0DE_0000 + i;
            h.encode()
        })
        .collect()
}

fn rig_on(chain: &Scenario) -> Rig {
    let mut r = Rig::new(chain, params());
    r.sync(chain, 1);
    r
}

#[test]
fn older_ancestor_children_skip_interpreter() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();
    let arena_before = r.cm.index().len();

    let mut last_staged = 0u32;
    let mut sent = 0usize;
    for parent in 10..19u64 {
        for raw in children_of(&honest, parent, 20) {
            let a = r.cm.submit_headers(9, std::slice::from_ref(&raw)).expect("not halted");
            last_staged = a.staged;
            sent += 1;
        }
    }
    assert_eq!(sent, 180);
    assert_eq!(r.pow.calls(), 0, "not one interpreter call for 180 forged headers");
    assert_eq!(r.cm.index().len(), arena_before, "nothing entered the arena");
    assert_eq!(last_staged, 180, "what it bought instead: 180 parked staging slots");

    for raw in children_of(&honest, 20, 20) {
        let _ = r.cm.submit_headers(9, std::slice::from_ref(&raw));
    }
    assert_eq!(r.pow.calls(), 1, "one failed call per source per tip epoch");

    let micros_per_byte = (r.pow.calls() * 3_000) as f64 / (200 * 132) as f64;
    assert!(micros_per_byte < 0.12, "got {micros_per_byte} us/byte");
}

#[test]
fn peer_ceiling_one_failed_call_per_epoch() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let raws = children_of(&honest, 20, 256);
    for s in 0..128usize {
        let _ = r.cm.submit_headers(3_000 + s as u32, &[raws[2 * s]]);
        let _ = r.cm.submit_headers(3_000 + s as u32, &[raws[2 * s + 1]]);
    }
    assert_eq!(r.pow.calls(), 128, "one failed call per source, and the second is refused");

    let per_epoch = r.pow.calls() * 3_000;
    assert_eq!(per_epoch, 384_000);
    let per_second = per_epoch / plaine_consensus::constants::BLOCK_TIME_SECS;
    assert_eq!(per_second, 6_400);
    assert!(per_second * 50 < p.class_rate_micros_per_sec(), "{per_second} us/s");
}

#[test]
fn parked_header_does_not_lock_table() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();

    let park = children_of(&honest, 18, 1)[0];
    for s in 0..p.max_sources as u32 {
        let a = r.cm.submit_headers(2_000 + s, &[park]).expect("not halted");
        assert_eq!(a.staged, 1, "source {s} parked the header");
        assert_eq!(a.connected, 0);
    }
    assert_eq!(r.cm.source_count(), p.max_sources, "the table is exactly full");
    assert_eq!(r.pow.calls(), 0, "it bought no interpreter call anywhere");

    let mut next = honest.clone();
    let blk = next.push_block(&[]);
    let a = r
        .cm
        .submit_headers(9_999, &[blk.rec.raw])
        .expect("a new source must still be admissible");
    assert_eq!(a.connected, 1, "the real next block connects");
    assert_eq!(r.pow.calls(), 1);
    assert_eq!(r.cm.source_count(), p.max_sources, "the table stayed at its cap");
}

#[test]
fn owing_row_not_evicted_by_flood() {
    let p = ChainParams { max_sources: 4, ..params() };
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.cm.forget_source(1);
    r.pow.reset();

    let paid = children_of(&honest, 20, 2);
    for (i, raw) in paid.iter().enumerate() {
        let _ = r.cm.submit_headers(i as u32, std::slice::from_ref(raw));
    }
    assert_eq!(r.pow.calls(), 2, "each owes S7 a failure");

    let park = children_of(&honest, 18, 2);
    for (i, raw) in park.iter().enumerate() {
        let _ = r.cm.submit_headers(2 + i as u32, std::slice::from_ref(raw));
    }
    assert_eq!(r.cm.source_count(), 4);
    assert_eq!(r.pow.calls(), 2, "parking is free and buys nothing");

    let fresh = children_of(&honest, 20, 3)[2];
    assert!(r.cm.submit_headers(99, &[fresh]).is_ok());
    assert_eq!(r.cm.source_count(), 4);

    let more = children_of(&honest, 20, 4)[3];
    let before = r.pow.calls();
    let _ = r.cm.submit_headers(0, &[more]);
    assert_eq!(r.pow.calls(), before, "an owing row is never the victim");
}

#[test]
fn honest_peer_keeps_reserve() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.reset();
    const HONEST: u32 = 77;

    for raw in children_of(&honest, 20, 2) {
        let a = r.cm.submit_headers(HONEST, &[raw]).expect("not halted");
        assert_eq!(a.connected, 1);
    }
    assert_eq!(r.pow.calls(), 2);

    let flood = children_of(&honest, 20, 200);
    let _ = r.cm.submit_headers(5, &flood).expect("not halted");

    assert_eq!(r.pow.calls(), 2 + 83, "the flood is bounded by the shared half plus its own reserve");
    assert!(r.observed(|c| matches!(
        c,
        Condition::BudgetExhausted { source: 5, class: BudgetClass::Interpreter }
    )));

    let late = children_of(&honest, 20, 300)[299];
    let a = r.cm.submit_headers(HONEST, &[late]).expect("not halted");
    assert_eq!(a.connected, 1, "the honest peer was starved out of the class budget");
    assert_eq!(r.pow.calls(), 86);

    let burst_ceiling = p.class_shared_burst_micros()
        + p.class_reserve_burst_micros(3_000) * p.max_sources as u64;
    assert_eq!(burst_ceiling, 1_018_000);
    assert!(p.class_aggregate_rate_micros_per_sec() <= p.class_rate_micros_per_sec());
}

#[test]
fn class_aggregate_counts_rows() {
    let p = params();
    assert_eq!(p.class_rate_micros_per_sec(), 500_000, "250 x P ms/s at the VPS floor P=2");
    assert!(p.max_sources <= p.max_peers, "one reserve per row, so rows may not exceed peers");
    assert!(
        p.class_aggregate_rate_micros_per_sec() <= p.class_rate_micros_per_sec(),
        "{} us/s against a cap of {}",
        p.class_aggregate_rate_micros_per_sec(),
        p.class_rate_micros_per_sec()
    );

    let ingress_aggregate = p.mempool.ingress_shared_rate_milli()
        + p.mempool.ingress_reserve_rate_milli(p.max_peers) * p.max_sources as u64;
    assert!(
        ingress_aggregate <= p.mempool.ingress_global as u64 * 1_000,
        "{ingress_aggregate} milli-tx/s against a declared 2,000 tx/s"
    );

    let old = ChainParams { max_sources: 256, ..params() };
    assert_eq!(old.class_aggregate_rate_micros_per_sec(), 250_000 + 256 * 1_953);
    assert!(old.class_aggregate_rate_micros_per_sec() > old.class_rate_micros_per_sec());
    let chain = Scenario::genesis(&old, T0).extend(1);
    let g = chain.blocks[0].clone();
    let store = Arc::new(MemStore::with_genesis(g.rec, g.body, &old));
    let pow = Arc::new(CountingPow::new(PowMode::AlwaysOk));
    let clock = Arc::new(MockClock::new(T0));
    let built = ChainManager::new(store.clone(), store.clone(), pow, clock, old, None);
    assert!(
        matches!(built, Err(Reject::BootInvariant { .. })),
        "a table that can hold more reserves than the budget bought must not boot"
    );
}

#[test]
fn fatal_sink_deep_replay_exact() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&honest, p.clone());
    r.store.set_snapshot_interval(4);
    r.sync(&honest, 1);
    r.store.set_undo_window(3);
    let before_tip = r.tip_hash();
    let before_state = r.store.account_table();
    let before_canon = r.store.canonical_hashes();
    let commits_before = r.store.commit_count();

    let attacker = honest.fork_at(5).spacing(1).extend(16);
    r.offer(7, &blocks_above(&attacker, 5));
    r.store.fail_next_commit(SinkError::Fatal("the deep writer lost track"));

    let e = r.cm.advance().expect_err("fatal");
    assert!(matches!(e, Reject::Halted { .. }), "got {e:?}");
    assert!(r.cm.halted().is_some(), "halting is a state");
    assert_eq!(r.cm.tip().hash, before_tip, "the arena still names the old tip");
    assert_eq!(r.store.account_table(), before_state, "state byte-identical");
    assert_eq!(r.store.canonical_hashes(), before_canon, "canonical index unmoved");
    assert_eq!(r.store.commit_count(), commits_before, "nothing was committed");
    assert!(r.observed(|c| matches!(c, Condition::DeepReplay { .. })), "the deep path did run");
    assert!(matches!(r.cm.advance(), Err(Reject::Halted { .. })));
}

#[test]
fn fatal_sink_fast_path_exact() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = rig_on(&honest);
    let before_tip = r.tip_hash();
    let before_state = r.store.account_table();
    let before_canon = r.store.canonical_hashes();

    let mut next = honest.clone();
    let blk = next.push_block(&[]);
    r.clock.set_unix(blk.rec.time);
    r.offer(8, std::slice::from_ref(&blk));
    r.store.fail_next_commit(SinkError::Fatal("the writer lost track"));

    let e = r.cm.advance().expect_err("fatal");
    assert!(matches!(e, Reject::Halted { .. }), "got {e:?}");
    assert_eq!(r.cm.tip().hash, before_tip, "the arena still names the old tip");
    assert_eq!(r.store.account_table(), before_state, "state byte-identical");
    assert_eq!(r.store.canonical_hashes(), before_canon, "canonical index unmoved");
    assert!(matches!(r.cm.submit_block(&blk.rec.hash, blk.body.clone()), Err(Reject::Halted { .. })));
}

#[test]
fn invalidating_tip_no_fork_choice() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = rig_on(&honest);

    let other = honest.fork_at(10).spacing(90).extend(5);
    r.offer(4, &blocks_above(&other, 10));
    let tip_before = r.tip_hash();

    r.cm.invalidate(&tip_before);
    assert!(r.cm.index().get(&tip_before).expect("in the arena").invalid());
    assert!(matches!(r.cm.advance(), Ok(Progress::NoChange)));
    assert_eq!(r.tip_hash(), tip_before, "still on the chain we marked invalid");
    assert!(r.cm.halted().is_none(), "nothing anywhere says so");
}

#[test]
fn dead_branch_not_reverified() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let attacker = honest.fork_at(10).extend(20);
    let raws: Vec<[u8; 132]> = attacker.blocks.iter().skip(11).map(|b| b.rec.raw).collect();
    assert_eq!(raws.len(), 20);
    let _ = r.cm.submit_headers_solicited_steady(9, &raws).expect("not halted");
    assert_eq!(r.pow.calls(), 1, "strictly ascending, abort at the first failure");

    for _ in 0..3 {
        let _ = r.cm.submit_headers_solicited_steady(9, &[]).expect("not halted");
    }
    assert_eq!(r.pow.calls(), 1, "saying nothing costs nothing once the branch is dead");
}

#[test]
fn quota_epoch_rolls_on_a_stalled_tip() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p.clone(), PowMode::AlwaysOk);
    r.sync(&honest, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();

    let raws = children_of(&honest, 20, 3);
    let _ = r.cm.submit_headers(9, &[raws[0]]);
    assert_eq!(r.pow.calls(), 1, "the one failure this epoch");
    let _ = r.cm.submit_headers(9, &[raws[1]]);
    assert_eq!(r.pow.calls(), 1, "the quota holds");
    assert!(r.observed(|c| matches!(
        c,
        Condition::BudgetExhausted { source: 9, class: BudgetClass::ChildQuota }
    )));

    r.clock.advance_ms(p.child_quota_window_secs * 1_000);
    let _ = r.cm.submit_headers(9, &[raws[2]]);
    assert_eq!(r.pow.calls(), 2, "a stalled tip must not lock a peer out forever");
}

#[test]
fn refused_replacement_keeps_incumbent() {
    let sender = user_key(0x61);
    let other = user_key(0x62);
    let to = addr_of(&user_key(0x63));
    let mut pool = Mempool::new(MempoolParams {
        max_txs: 100,
        max_bytes: 400,
        relay_fee_floor: 1,
        ..MempoolParams::default()
    });
    let mut obs = |_: Condition| {};
    let rich = Account { balance: u128::MAX / 4, nonce: 0 };

    let incumbent = signed_transfer(&sender, to, 1, 1_000, 0);
    let rival = signed_transfer(&other, to, 1, 100_000, 0);
    let incumbent_id = match decode_tx(&incumbent).expect("decodes") {
        Tx::Transfer(t) => t.txid(),
        _ => panic!("a transfer"),
    };
    pool.submit(incumbent.clone(), rich, u128::MAX / 4, 0, SigProof::from_validated_block(), &mut obs)
        .expect("incumbent pooled");
    pool.submit(rival, rich, u128::MAX / 4, 0, SigProof::from_validated_block(), &mut obs)
        .expect("rival pooled");
    assert_eq!(pool.len(), 2);
    let bytes_before = pool.bytes();
    assert_eq!(bytes_before, 314, "two 157-byte transfers");

    let bulky = signed_announcement(&sender, &[0x7Au8; 1_024], 1_250, 0);
    assert!(bulky.len() + bytes_before > 400, "the fixture must force the eviction loop");
    let verdict =
        pool.submit(bulky, rich, u128::MAX / 4, 0, SigProof::from_validated_block(), &mut obs);
    assert_eq!(verdict, Err(Reject::PoolFull));

    assert!(pool.get(&incumbent_id).is_some(), "a refused replacement ATE the incumbent");
    assert!(pool.get(&incumbent_id).expect("pooled").executable, "it is executable again");
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.bytes(), bytes_before, "the byte accounting came back with it");
}
