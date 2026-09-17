mod support;

use plaine_chain::error::{Condition, Reject};
use plaine_chain::mock::{PowMode, Scenario};
use plaine_chain::{Progress, SinkError, Store};
use plaine_consensus::rules::RuleError;
use support::*;

fn rig_on(chain: &Scenario) -> Rig {
    let p = params();
    let mut r = Rig::new(chain, p);
    r.sync(chain, 1);
    r
}

fn from_scratch(
    chain: &Scenario,
) -> std::collections::BTreeMap<[u8; 20], plaine_chain::types::Account> {
    let r = rig_on(chain);
    r.store.account_table()
}

const CAP: u64 = plaine_consensus::constants::MAX_REORG_DEPTH;

const HONEST_TIP: u64 = CAP * 2;

fn honest_chain() -> Scenario {
    Scenario::genesis(&params(), T0).extend(HONEST_TIP)
}

fn branch_at_depth(honest: &Scenario, depth: u64) -> Scenario {
    honest.fork_at(HONEST_TIP - depth).spacing(1).extend(depth)
}

#[test]
fn reorg_at_cap_depth_adopted() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);
    assert_eq!(r.height(), HONEST_TIP);
    let before = r.tip_hash();

    let attacker = branch_at_depth(&honest, CAP);
    let a = r.offer(7, &blocks_above(&attacker, HONEST_TIP - CAP));
    assert_eq!(a.connected, CAP);

    let p2 =
        r.cm.advance()
            .expect("a depth of exactly the cap is inside it");
    match p2 {
        Progress::Advanced {
            tip,
            rolled_back,
            applied,
        } => {
            assert_eq!(rolled_back, CAP);
            assert_eq!(applied, CAP);
            assert_eq!(tip.height, HONEST_TIP);
            assert_eq!(tip.hash, attacker.tip().hash);
            assert_ne!(tip.hash, before);
        }
        other => panic!("expected an adoption, got {other:?}"),
    }
    assert_eq!(r.cm.stats().reorgs, 1);
    assert_eq!(
        r.store.account_table(),
        from_scratch(&attacker),
        "a reorg must reach byte-identical state to a from-scratch replay"
    );
}

#[test]
fn reorg_past_cap_refused() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);
    let before = r.tip_hash();
    r.pow.reset();

    let attacker = branch_at_depth(&honest, CAP + 1);
    let a = r.offer(7, &blocks_above(&attacker, HONEST_TIP - CAP - 1));
    assert_eq!(a.connected, 0);
    assert!(a.rejected > 0);
    assert_eq!(
        r.pow.calls(),
        0,
        "layer 1 is a cheap gate and must stay one"
    );
    assert_eq!(r.tip_hash(), before);
    assert!(matches!(
        r.cm.advance().expect("not halted"),
        Progress::NoChange
    ));
}

#[test]
fn ingest_gate_not_stricter_than_predicate() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);
    let before = r.tip_hash();

    let cp = signed_checkpoint(&authority_key(), HONEST_TIP + 50, [0xAB; 32]);
    r.cm.submit_checkpoint(&cp).expect("verified");
    assert!(r.cm.anchor().is_some());

    let depth = CAP + 1;
    let attacker = branch_at_depth(&honest, depth);
    let a = r.offer(7, &blocks_above(&attacker, HONEST_TIP - depth));
    assert_eq!(a.connected, depth, "the relaxed gate admits the branch");

    let err = r.cm.advance().expect_err("the strict predicate refuses it");
    assert!(
        matches!(
            err,
            Reject::Rule(RuleError::ReorgTooDeep { depth: d, cap }) if d == depth && cap == CAP
        ),
        "got {err:?}"
    );
    assert_eq!(r.tip_hash(), before, "the tip never moved");
    assert!(
        r.observed(|c| matches!(c, Condition::ReorgTooDeepRefused { depth: d, .. } if *d == depth))
    );
}

#[test]
fn stale_tip_does_not_lift_cap() {
    let window = plaine_consensus::constants::SYNC_WINDOW_SECS;
    let honest = honest_chain();
    let depth = CAP + 1;
    let attacker = branch_at_depth(&honest, depth);
    let base = HONEST_TIP - depth;
    let tip_time = honest.tip().time;

    for lag in [0, window, window + 1, 86_400] {
        let mut r = rig_on(&honest);
        r.clock.set_unix(tip_time + lag);
        let a = r.offer(7, &blocks_above(&attacker, base));
        assert_eq!(
            a.connected, 0,
            "tip {lag} s stale still refuses a branch {depth} deep at the cheap gate"
        );
        assert_eq!(r.height(), HONEST_TIP, "the tip must not move");
        assert!(matches!(
            r.cm.advance().expect("not halted"),
            Progress::NoChange
        ));
    }

    let mut r = rig_on(&honest);
    let cp = signed_checkpoint(&authority_key(), HONEST_TIP + 50, [0xAB; 32]);
    r.cm.submit_checkpoint(&cp).expect("verified");
    r.clock.set_unix(tip_time + window + 1);
    let a = r.offer(7, &blocks_above(&attacker, base));
    assert_eq!(
        a.connected, depth,
        "premise: the relaxed exemption admits it"
    );
    let err = r.cm.advance().expect_err("the strict predicate refuses it");
    assert!(
        matches!(
            err,
            Reject::Rule(RuleError::ReorgTooDeep { depth: d, cap }) if d == depth && cap == CAP
        ),
        "an unsigned reorg {depth} deep must not slip through a stale-tip window: {err:?}"
    );
    assert_eq!(r.height(), HONEST_TIP, "the tip never moved");
}

#[test]
fn anchored_deep_branch_adopted() {
    let honest = honest_chain();
    let depth = CAP + 1;
    let base = HONEST_TIP - depth;
    let attacker = branch_at_depth(&honest, depth);

    let anchored_block = attacker.blocks[(base + depth / 2) as usize].rec;
    assert!(
        anchored_block.height > base,
        "the anchor must sit inside the branch"
    );

    let mut r = rig_on(&honest);
    let cp = signed_checkpoint(&authority_key(), anchored_block.height, anchored_block.hash);
    r.cm.submit_checkpoint(&cp).expect("verified");

    r.offer(7, &blocks_above(&attacker, base));
    match r.cm.advance().expect("the anchor admits it") {
        Progress::Advanced {
            tip, rolled_back, ..
        } => {
            assert_eq!(rolled_back, depth);
            assert_eq!(tip.hash, attacker.tip().hash);
        }
        other => panic!("expected adoption, got {other:?}"),
    }
    assert_eq!(r.store.account_table(), from_scratch(&attacker));
}

#[test]
fn unsigned_deep_reorg_refused() {
    let honest = honest_chain();
    let depth = CAP + 1;
    let attacker = branch_at_depth(&honest, depth);
    let mut r = rig_on(&honest);
    r.offer(7, &blocks_above(&attacker, HONEST_TIP - depth));
    assert_eq!(r.height(), HONEST_TIP);
    assert!(matches!(
        r.cm.advance().expect("not halted"),
        Progress::NoChange
    ));
}

fn branch_bad_at(honest: &Scenario, bad_index: usize) -> Scenario {
    let mut atk = honest.fork_at(5).spacing(61);
    for i in 0..16usize {
        let height = 6 + i as u64;
        if i == bad_index {
            let cb = Scenario::coinbase_bytes(height, atk.miner, 12_345, 0, Vec::new());
            let body = Scenario::encode_body(&[&cb]);
            atk.push_body(body);
        } else {
            atk.push_block(&[]);
        }
    }
    atk
}

fn assert_rolls_back_to_the_original_tip(bad_index: usize) {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = rig_on(&honest);
    let original_tip = r.tip_hash();
    let commits_before = r.store.commit_count();
    let attacker = branch_bad_at(&honest, bad_index);
    let bad = attacker.blocks[6 + bad_index].rec;
    let validated_before = r.cm.stats().bodies_validated;

    r.offer(7, &blocks_above(&attacker, 5));
    assert_eq!(
        r.cm.index().len(),
        21 + 16,
        "every branch header is stored: it cost real PoW"
    );
    let calls_after_headers = r.pow.calls();

    match r.cm.advance() {
        Ok(Progress::NoChange) => {}
        Err(Reject::Rule(RuleError::InsufficientWork { .. })) => {}
        other => panic!("a failed branch must not move the tip, got {other:?}"),
    }

    assert_eq!(r.tip_hash(), original_tip, "the tip never moved");
    assert_eq!(r.height(), 20);
    assert_eq!(
        r.store.commit_count(),
        commits_before,
        "zero sink writes: nothing is written until the whole branch validates"
    );
    assert!(r.store.is_invalid(&bad.hash), "the failure is sticky");
    assert_eq!(
        r.pow.calls(),
        calls_after_headers,
        "descendants are poisoned without re-verifying any of them"
    );
    assert_eq!(
        r.cm.stats().bodies_validated,
        validated_before,
        "a branch that never committed never counts as validated work"
    );
    assert_eq!(
        r.cm.stats().poisoned as usize,
        15 - bad_index,
        "every descendant of the bad block is poisoned in one pass"
    );
    let reported: Vec<(u64, [u8; 32])> = r
        .conditions()
        .iter()
        .filter_map(|c| match c {
            Condition::BranchInvalidAt { height, hash } => Some((*height, *hash)),
            _ => None,
        })
        .collect();
    assert_eq!(
        reported,
        vec![(bad.height, bad.hash)],
        "exactly one block failed: validation stopped there and never ran past it"
    );

    match r.cm.advance() {
        Ok(Progress::NoChange) => {}
        Err(Reject::Rule(RuleError::InsufficientWork { .. })) => {}
        other => panic!("the tip must stay put, got {other:?}"),
    }
    assert_eq!(r.tip_hash(), original_tip);
}

#[test]
fn fail_at_block_eight_rolls_back() {
    assert_rolls_back_to_the_original_tip(7);
}

#[test]
fn fail_at_first_block_rolls_back() {
    assert_rolls_back_to_the_original_tip(0);
}

#[test]
fn fail_at_last_block_rolls_back() {
    assert_rolls_back_to_the_original_tip(15);
}

#[test]
fn rollback_restores_touched_addresses() {
    let p = params();
    let user = user_key(0x21);
    let honest = Scenario::genesis(&p, T0)
        .with_miner(addr_of(&user))
        .extend(30);
    let mut r = rig_on(&honest);
    let before = r.store.account_table();

    let attacker = honest.fork_at(20).spacing(1).extend(10);
    r.offer(7, &blocks_above(&attacker, 20));
    r.cm.advance().expect("adopted");
    assert_eq!(r.height(), 30);

    let heavier = honest.clone().spacing(1).extend(12);
    r.offer(8, &blocks_above(&heavier, 30));
    r.cm.advance().expect("adopted back");
    assert_eq!(r.cm.tip().hash, heavier.tip().hash);

    assert_eq!(r.store.account_table(), from_scratch(&heavier));

    assert_ne!(r.store.account_table(), before);
}

#[test]
fn rollback_heights_must_be_strictly_descending() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = rig_on(&honest);
    let attacker = honest.fork_at(10).spacing(1).extend(10);
    r.offer(7, &blocks_above(&attacker, 10));
    r.cm.advance().expect("adopted");
    assert_eq!(r.cm.tip().hash, attacker.tip().hash);
}

#[test]
fn reorg_below_undo_floor_replays_snapshot() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&honest, p.clone());
    r.store.set_snapshot_interval(4);
    r.sync(&honest, 1);
    assert_eq!(r.height(), 20);

    r.store.set_undo_window(3);

    let attacker = honest.fork_at(5).spacing(1).extend(16);
    r.offer(7, &blocks_above(&attacker, 5));
    match r
        .cm
        .advance()
        .expect("the deep path exists precisely for this")
    {
        Progress::Advanced { tip, .. } => assert_eq!(tip.hash, attacker.tip().hash),
        other => panic!("expected adoption, got {other:?}"),
    }
    assert_eq!(r.cm.stats().deep_reorgs, 1);
    assert!(r.observed(|c| matches!(c, Condition::DeepReplay { from: 4, to: 5, .. })));
    assert_eq!(
        r.store.account_table(),
        from_scratch(&attacker),
        "the deep path must land on the same state as a from-scratch replay"
    );
}

#[test]
fn fork_below_replay_floor_reports_resync() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&honest, p.clone());
    r.store.set_snapshot_interval(4);
    r.sync(&honest, 1);
    r.store.set_undo_window(3);
    r.store.set_replay_floor(10);
    let before = r.tip_hash();

    let attacker = honest.fork_at(5).spacing(1).extend(16);
    r.offer(7, &blocks_above(&attacker, 5));
    let err =
        r.cm.advance()
            .expect_err("below the replay floor there is no honest answer");
    assert!(
        matches!(
            err,
            Reject::ResyncRequired {
                fork_height: 5,
                replay_floor: 10
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        r.tip_hash(),
        before,
        "the tip is untouched, not half-applied"
    );
    assert!(r.observed(|c| matches!(c, Condition::ResyncRequired { .. })));
}

#[test]
fn full_sink_retry_succeeds() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = rig_on(&honest);
    let before = r.tip_hash();
    let attacker = honest.fork_at(10).spacing(1).extend(10);
    r.offer(7, &blocks_above(&attacker, 10));

    r.store.fail_next_commit(SinkError::Full);
    assert!(matches!(r.cm.advance(), Err(Reject::Busy)));
    assert_eq!(r.tip_hash(), before, "Full means nothing was written");
    assert!(r.cm.halted().is_none(), "Full is not fatal");

    match r.cm.advance().expect("the retry goes through") {
        Progress::Advanced { tip, .. } => assert_eq!(tip.hash, attacker.tip().hash),
        other => panic!("expected adoption, got {other:?}"),
    }
    assert_eq!(r.store.account_table(), from_scratch(&attacker));
}

#[test]
fn fatal_sink_halts_manager() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = rig_on(&honest);
    let attacker = honest.fork_at(10).spacing(1).extend(10);
    r.offer(7, &blocks_above(&attacker, 10));

    r.store.fail_next_commit(SinkError::Fatal("torn write"));
    assert!(matches!(
        r.cm.advance(),
        Err(Reject::Halted {
            detail: "torn write"
        })
    ));
    assert_eq!(r.cm.halted(), Some("torn write"));
    assert!(r.observed(|c| matches!(
        c,
        Condition::StorageFatal {
            detail: "torn write"
        }
    )));

    let commits = r.store.commit_count();
    assert!(matches!(r.cm.advance(), Err(Reject::Halted { .. })));
    assert!(matches!(
        r.cm.submit_headers(1, &[]),
        Err(Reject::Halted { .. })
    ));
    assert!(matches!(
        r.cm.submit_tx(TxOrigin::Local, vec![0x01]),
        Err(Reject::Halted { .. })
    ));
    assert_eq!(
        r.store.commit_count(),
        commits,
        "a halted manager touches the sink never again"
    );
}

#[test]
fn tip_extension_is_single_commit() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_on(&chain);
    let next = chain.clone().extend(1);
    r.offer(2, &blocks_above(&next, 5));
    match r.cm.advance().expect("extension") {
        Progress::Advanced {
            rolled_back,
            applied,
            tip,
        } => {
            assert_eq!(rolled_back, 0);
            assert_eq!(applied, 1);
            assert_eq!(tip.hash, next.tip().hash);
        }
        other => panic!("expected extension, got {other:?}"),
    }
    assert_eq!(r.cm.stats().reorgs, 0, "an extension is not a reorg");
}

#[test]
fn missing_body_is_reported() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_on(&chain);
    let next = chain.clone().extend(1);
    let raws: Vec<[u8; 132]> = blocks_above(&next, 5).iter().map(|b| b.rec.raw).collect();
    r.cm.submit_headers_solicited(2, &raws).expect("not halted");
    match r.cm.advance().expect("not halted") {
        Progress::NeedBodies(v) => assert_eq!(v, vec![next.tip().hash]),
        other => panic!("expected NeedBodies, got {other:?}"),
    }
}

#[test]
fn unsolicited_unknown_body_dropped() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_on(&chain);
    let err =
        r.cm.submit_block(&[0x77; 32], vec![0u8; 1024])
            .expect_err("unknown header");
    assert!(matches!(err, Reject::BodyNotAdmissible { .. }), "{err:?}");
}

#[test]
fn body_for_committed_block_refused() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = rig_on(&chain);
    let h = chain.blocks[3].rec.hash;

    assert!(matches!(
        r.cm.submit_block(&h, chain.blocks[3].body.clone()),
        Err(Reject::BodyAlreadyHeld { .. })
    ));
}

#[test]
fn failed_pow_branch_ignored() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p.clone());
    r.sync(&chain, 1);
    r.pow.set_mode(PowMode::AlwaysFail);
    r.pow.reset();
    let next = chain.clone().extend(3);
    let a = r.offer(2, &blocks_above(&next, 5));
    assert_eq!(a.connected, 0);
    assert_eq!(
        r.pow.calls(),
        1,
        "ascending order: the first failure ends the branch"
    );
    assert!(matches!(
        r.cm.advance().expect("not halted"),
        Progress::NoChange
    ));
}
