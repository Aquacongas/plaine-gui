mod support;

use plaine_chain::mock::Scenario;
use plaine_chain::Progress;
use support::*;

const CAP: u64 = plaine_consensus::constants::MAX_REORG_DEPTH;

const HONEST_TIP: u64 = CAP * 2;

fn honest_chain() -> Scenario {
    Scenario::genesis(&params(), T0).extend(HONEST_TIP)
}

fn rig_on(chain: &Scenario) -> Rig {
    let p = params();
    let mut r = Rig::new(chain, p);
    r.sync(chain, 1);
    r
}

fn branch_at_depth(honest: &Scenario, depth: u64) -> Scenario {
    honest.fork_at(HONEST_TIP - depth).spacing(1).extend(depth)
}

fn wedged_rig(honest: &Scenario) -> (Rig, Scenario) {
    let mut r = rig_on(honest);

    let cp = signed_checkpoint(&authority_key(), HONEST_TIP + 50, [0xAB; 32]);
    r.cm.submit_checkpoint(&cp).expect("the authority signature verifies");
    assert!(r.cm.anchor().is_some(), "premise: an anchor is held");

    let depth = CAP + 1;
    let attacker = branch_at_depth(honest, depth);
    let a = r.offer(7, &blocks_above(&attacker, HONEST_TIP - depth));
    assert_eq!(a.connected, depth, "premise: the relaxed gate admits the branch");

    let err = r.cm.advance().expect_err("premise: the strict predicate refuses it");
    assert!(
        matches!(err, plaine_chain::Reject::Rule(_)),
        "premise: the refusal is a rule verdict, not BranchInvalid: {err:?}"
    );
    assert_eq!(r.height(), HONEST_TIP, "premise: the tip did not move");
    (r, attacker)
}

#[test]
fn extension_commits_while_refused_branch_waits() {
    let honest = honest_chain();
    let (mut r, _attacker) = wedged_rig(&honest);

    let extended = honest.fork_at(HONEST_TIP).extend(1);
    let next = extended.blocks[(HONEST_TIP + 1) as usize].clone();

    let window = plaine_consensus::constants::SYNC_WINDOW_SECS;
    assert!(
        next.rec.time <= honest.tip().time + window,
        "fixture: the new block must not itself lift the sync condition"
    );
    r.clock.set_unix(next.rec.time);

    let a = r.offer(1, std::slice::from_ref(&next));
    assert_eq!(a.connected, 1, "our own next block must reach the arena");

    match r.cm.advance() {
        Ok(Progress::Advanced { tip, rolled_back, applied }) => {
            assert_eq!(rolled_back, 0, "a pure extension discards nothing");
            assert_eq!(applied, 1);
            assert_eq!(tip.hash, next.rec.hash);
            assert_eq!(tip.height, HONEST_TIP + 1);
        }
        other => panic!("our own block on our own tip was not committed: {other:?}"),
    }
}

#[test]
fn keeps_committing_through_refusal() {
    let honest = honest_chain();
    let (mut r, _attacker) = wedged_rig(&honest);

    let mut extended = honest.fork_at(HONEST_TIP);
    let window = plaine_consensus::constants::SYNC_WINDOW_SECS;
    for i in 1..=5u64 {
        extended = extended.extend(1);
        let b = extended.blocks[(HONEST_TIP + i) as usize].clone();
        assert!(
            b.rec.time <= honest.tip().time + window,
            "fixture: block {i} must not lift the sync condition by itself"
        );
        r.clock.set_unix(b.rec.time);
        let a = r.offer(1, std::slice::from_ref(&b));
        assert_eq!(a.connected, 1, "honest block {i} must reach the arena");
        let p = r.cm.advance();
        assert!(
            matches!(p, Ok(Progress::Advanced { .. })),
            "honest block {i} at height {} was not committed: {p:?}",
            HONEST_TIP + i
        );
        assert_eq!(r.height(), HONEST_TIP + i);
    }
}

#[test]
fn no_anchor_refuses_deep_branch() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);
    assert!(r.cm.anchor().is_none(), "no anchor: S5's depth filter is live");

    let depth = CAP + 1;
    let attacker = branch_at_depth(&honest, depth);
    let a = r.offer(7, &blocks_above(&attacker, HONEST_TIP - depth));
    assert_eq!(a.connected, 0, "S5 refuses it at ingest");
    assert!(matches!(r.cm.advance().expect("not halted"), Progress::NoChange));

    let extended = honest.fork_at(HONEST_TIP).extend(1);
    let next = extended.blocks[(HONEST_TIP + 1) as usize].clone();
    r.clock.set_unix(next.rec.time);
    assert_eq!(r.offer(1, std::slice::from_ref(&next)).connected, 1);
    match r.cm.advance().expect("nothing refused is in the arena") {
        Progress::Advanced { tip, .. } => assert_eq!(tip.hash, next.rec.hash),
        other => panic!("expected the extension to commit, got {other:?}"),
    }
}
