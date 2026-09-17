mod support;

use plaine_chain::checkpoints::CheckpointOutcome;
use plaine_chain::forkchoice::ArenaView;
use plaine_chain::index::HeaderIndex;
use plaine_chain::mock::Scenario;
use plaine_chain::types::ChainParams;
use plaine_chain::work::{expand_bits, target_to_be};
use plaine_consensus::constants::CHECKPOINT_SUNSET_HEIGHT;
use plaine_consensus::rules::{
    evaluate_reorg, work_from_target, HeaderInfo, ReorgParams, ReorgVerdict, RuleError,
};
use support::*;

fn arena(chain: &Scenario, len: usize, p: &ChainParams) -> HeaderIndex {
    let mut idx = HeaderIndex::new();
    let mut cum = plaine_chain::types::Work::ZERO;
    let mut canon = Vec::new();
    for (h, b) in chain.blocks.iter().take(len).enumerate() {
        let t = expand_bits(b.rec.bits, &p.pow_limit).expect("legal target");
        let be = target_to_be(&t);
        cum = cum
            .checked_add(&work_from_target(&be))
            .expect("no overflow");
        if h == 0 {
            canon.push(idx.insert_genesis(&b.rec, cum));
        } else {
            let parent = *canon.last().expect("genesis");
            canon.push(idx.insert(&b.rec, parent, cum, true));
        }
    }
    idx.set_canonical(&canon);
    idx
}

fn candidate(chain: &Scenario, from: u64, count: usize, p: &ChainParams) -> Vec<HeaderInfo> {
    chain
        .blocks
        .iter()
        .skip(from as usize)
        .take(count)
        .map(|b| HeaderInfo {
            height: b.rec.height,
            hash: b.rec.hash,
            time: b.rec.time,
            target: target_to_be(&expand_bits(b.rec.bits, &p.pow_limit).expect("legal")),
        })
        .collect()
}

#[test]
fn genesis_only_node_syncs_past_checkpoint() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(4);

    let idx = arena(&chain, 2, &p);
    let cp_hash = chain.blocks[2].rec.hash;
    let cps = [(2u64, cp_hash)];
    let cand = candidate(&chain, 2, 3, &p);
    let start_height = 2;

    let view = ArenaView::new(&idx, p.pow_limit);
    let verdict = evaluate_reorg(
        &view,
        start_height,
        &cand,
        &ReorgParams {
            anchor: None,
            checkpoints: &cps,
            local_time: chain.tip().time,
        },
    );
    assert_eq!(
        verdict,
        Ok(ReorgVerdict::StrictlyMoreWork),
        "a node holding only genesis+1 must be able to sync forward to 4"
    );

    let coarse_would_reject = cps.iter().any(|(h, _)| *h >= start_height);
    assert!(
        coarse_would_reject,
        "the coarse `h >= fork_point` form rejects this sync"
    );
}

#[test]
fn shortening_attack_rejected_early() {
    let p = params();
    let ours = Scenario::genesis(&p, T0).extend(11);
    let idx = arena(&ours, 12, &p);
    let cps = [(5u64, ours.blocks[5].rec.hash)];

    let attacker = ours.fork_at(3).spacing(1).extend(1);
    let cand = candidate(&attacker, 4, 1, &p);
    let view = ArenaView::new(&idx, p.pow_limit);
    let verdict = evaluate_reorg(
        &view,
        4,
        &cand,
        &ReorgParams {
            anchor: None,
            checkpoints: &cps,
            local_time: ours.tip().time,
        },
    );
    assert_eq!(
        verdict,
        Err(RuleError::CheckpointShorteningAttack { height: 5 })
    );
}

#[test]
fn fork_at_checkpoint_height_dies_on_rule_a() {
    let p = params();
    let ours = Scenario::genesis(&p, T0).extend(11);
    let idx = arena(&ours, 12, &p);
    let cps = [(5u64, ours.blocks[5].rec.hash)];

    let attacker = ours.fork_at(3).spacing(1).extend(9);
    let cand = candidate(&attacker, 4, 9, &p);
    let view = ArenaView::new(&idx, p.pow_limit);
    let verdict = evaluate_reorg(
        &view,
        4,
        &cand,
        &ReorgParams {
            anchor: None,
            checkpoints: &cps,
            local_time: ours.tip().time,
        },
    );
    assert_eq!(verdict, Err(RuleError::CheckpointMismatch { height: 5 }));
}

#[test]
fn extension_past_checkpoint_untouched() {
    let p = params();
    let ours = Scenario::genesis(&p, T0).extend(11);
    let idx = arena(&ours, 12, &p);
    let cps = [(5u64, ours.blocks[5].rec.hash)];
    let longer = ours.clone().extend(3);
    let cand = candidate(&longer, 12, 3, &p);
    let view = ArenaView::new(&idx, p.pow_limit);
    assert_eq!(
        evaluate_reorg(
            &view,
            12,
            &cand,
            &ReorgParams {
                anchor: None,
                checkpoints: &cps,
                local_time: longer.tip().time
            }
        ),
        Ok(ReorgVerdict::StrictlyMoreWork)
    );
}

#[test]
fn held_block_checkpoint_enters_map() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&authority_key(), 5, chain.blocks[5].rec.hash);
    let rep = r.cm.submit_checkpoint(&cp).expect("no error");
    assert_eq!(rep.outcome, CheckpointOutcome::Admitted);
    assert!(rep.anchor_advanced, "a first anchor is an advance");
    assert_eq!(r.cm.checkpoints(), vec![(5, chain.blocks[5].rec.hash)]);
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(5));
}

#[test]
fn contradicting_checkpoint_becomes_anchor_only() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&authority_key(), 5, [0xC1; 32]);
    assert_eq!(
        r.cm.submit_checkpoint(&cp).expect("no error").outcome,
        CheckpointOutcome::StoredAsAnchor
    );
    assert!(
        r.cm.checkpoints().is_empty(),
        "the enforcement map must stay empty"
    );
    assert_eq!(r.cm.anchor().map(|a| a.hash), Some([0xC1; 32]));
    assert!(r.observed(|c| matches!(
        c,
        plaine_chain::error::Condition::AnchorContradiction { height: 5, .. }
    )));
}

#[test]
fn checkpoint_above_tip_is_recovery_anchor() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&authority_key(), 50, [0xD2; 32]);
    assert_eq!(
        r.cm.submit_checkpoint(&cp).expect("no error").outcome,
        CheckpointOutcome::NotHeldYet
    );
    assert!(r.cm.checkpoints().is_empty());
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(50));
}

#[test]
fn an_anchor_is_replaced_only_at_a_strictly_higher_height() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    r.cm.submit_checkpoint(&signed_checkpoint(&authority_key(), 50, [0xD2; 32]))
        .expect("ok");
    assert_eq!(
        r.cm.submit_checkpoint(&signed_checkpoint(&authority_key(), 40, [0xD3; 32]))
            .expect("ok")
            .outcome,
        CheckpointOutcome::AnchorNotSuperseded
    );
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(50));
    r.cm.submit_checkpoint(&signed_checkpoint(&authority_key(), 60, [0xD4; 32]))
        .expect("ok");
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(60));
}

#[test]
fn non_authority_checkpoint_ignored() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&impostor_key(), 5, chain.blocks[5].rec.hash);
    let rep = r.cm.submit_checkpoint(&cp).expect("no error");
    assert_eq!(rep.outcome, CheckpointOutcome::Unverified);
    assert!(
        !rep.anchor_advanced,
        "an unverified checkpoint never moves the anchor"
    );
    assert!(r.cm.checkpoints().is_empty());
    assert!(r.cm.anchor().is_none());
}

#[test]
fn checkpoint_lever_expires_at_sunset() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    for h in [
        CHECKPOINT_SUNSET_HEIGHT,
        CHECKPOINT_SUNSET_HEIGHT + 1,
        u64::MAX,
    ] {
        let cp = signed_checkpoint(&authority_key(), h, [0xE5; 32]);
        assert_eq!(
            r.cm.submit_checkpoint(&cp).expect("no error").outcome,
            CheckpointOutcome::Unverified,
            "height {h} is at or past the sunset"
        );
    }

    let cp = signed_checkpoint(&authority_key(), CHECKPOINT_SUNSET_HEIGHT - 1, [0xE6; 32]);
    assert_eq!(
        r.cm.submit_checkpoint(&cp).expect("no error").outcome,
        CheckpointOutcome::NotHeldYet
    );
}

#[test]
fn genesis_is_never_checkpoint_applied() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&authority_key(), 0, chain.blocks[0].rec.hash);
    assert_eq!(
        r.cm.submit_checkpoint(&cp).expect("no error").outcome,
        CheckpointOutcome::GenesisImmutable
    );
    assert!(r.cm.checkpoints().is_empty());
}

#[test]
fn persisted_anchor_reverified_on_load() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);

    let mut forged = signed_checkpoint(&authority_key(), 7, chain.blocks[7].rec.hash);
    forged.sigs[0].sig[0] ^= 0x01;
    assert!(
        !r.cm.load_anchor(&forged),
        "a tampered signature loads nothing"
    );
    assert!(r.cm.anchor().is_none());

    let genuine = signed_checkpoint(&authority_key(), 7, chain.blocks[7].rec.hash);
    assert!(r.cm.load_anchor(&genuine));
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(7));
}

#[test]
fn wrong_hash_at_checkpoint_dies_at_s1b() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(11);
    let mut r = Rig::new(&chain, p.clone());
    r.sync(&chain, 1);

    assert_eq!(
        r.cm.submit_checkpoint(&signed_checkpoint(
            &authority_key(),
            11,
            chain.blocks[11].rec.hash
        ))
        .expect("ok")
        .outcome,
        CheckpointOutcome::Admitted
    );
    r.pow.reset();

    let rival = chain.fork_at(10).spacing(1).extend(1);
    let a = r.offer(3, &blocks_above(&rival, 10));
    assert_eq!(a.connected, 0);
    assert_eq!(a.rejected, 1);
    assert_eq!(
        r.pow.calls(),
        0,
        "a whitelist test costs nothing and runs first"
    );
    assert_eq!(r.cm.tip().hash, chain.blocks[11].rec.hash);
}
