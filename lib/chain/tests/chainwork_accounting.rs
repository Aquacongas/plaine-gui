mod support;

use std::collections::HashSet;

use plaine_chain::forkchoice::ArenaView;
use plaine_chain::mock::Scenario;
use plaine_chain::types::Work;
use plaine_chain::Progress;
use plaine_consensus::rules::{work_from_target, ChainView};
use support::*;

#[test]
fn view_and_arena_agree_on_work() {
    let p = params();
    let chain = Scenario::genesis(&p, T0)
        .extend(20)
        .spacing(5)
        .extend(20)
        .spacing(200)
        .extend(20);
    let mut r = Rig::new(&chain, p.clone());
    r.sync(&chain, 1);
    assert_eq!(r.height(), 60);

    let idx = r.cm.index();
    let distinct: HashSet<u32> =
        (0..=idx.tip_height()).map(|h| idx.canonical_at(h).expect("dense").bits).collect();
    assert!(
        distinct.len() >= 3,
        "fixture: the canonical chain must carry varying bits or this guard is vacuous, got {}",
        distinct.len()
    );

    let view = ArenaView::new(idx, p.pow_limit);
    let mut running = Work::ZERO;
    for h in 0..=idx.tip_height() {
        let node = idx.canonical_at(h).expect("canonical is dense");
        let seen = view.header_at(h).expect("ChainView contract: h <= tip_height");
        assert_eq!(seen.hash, node.hash, "the view lost the block at height {h}");
        assert_eq!(seen.height, node.height);
        assert_eq!(seen.time, node.time);
        running = running
            .checked_add(&work_from_target(&seen.target))
            .expect("work sum cannot overflow 512 bits");
        assert_eq!(
            running, node.cum_work,
            "the view's target at height {h} does not carry that block's own work"
        );
    }

    let tip = idx.canonical_at(idx.tip_height()).expect("dense");
    let by_hash = view.header_by_hash(&tip.hash).expect("the tip is canonical");
    assert_eq!(by_hash.target, view.header_at(tip.height).expect("dense").target);
}

#[test]
fn deep_replay_records_real_chainwork() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&honest, p.clone());
    r.store.set_snapshot_interval(4);
    r.sync(&honest, 1);
    assert_eq!(r.height(), 20);

    r.store.set_undo_window(3);

    let attacker = honest.fork_at(7).spacing(1).extend(15);
    r.offer(7, &blocks_above(&attacker, 7));
    match r.cm.advance().expect("the deep path exists precisely for this") {
        Progress::Advanced { tip, .. } => assert_eq!(tip.hash, attacker.tip().hash),
        other => panic!("expected adoption, got {other:?}"),
    }
    assert_eq!(r.cm.stats().deep_reorgs, 1, "premise: this must be the deep path");

    let idx = r.cm.index();
    let stored = r.store.stored_chainwork();
    assert_eq!(
        stored.len() as u64,
        idx.tip_height() + 1,
        "the sink must hold one chainwork per canonical height"
    );
    let mut previous = Work::ZERO;
    for h in 0..=idx.tip_height() {
        let node = idx.canonical_at(h).expect("canonical is dense");
        assert_eq!(
            stored[h as usize], node.cum_work,
            "the chainwork committed at height {h} is not the chain's work there"
        );
        if h > 0 {
            assert!(
                stored[h as usize] > previous,
                "chainwork must strictly increase; it does not at height {h}"
            );
        }
        previous = stored[h as usize];
    }
}
