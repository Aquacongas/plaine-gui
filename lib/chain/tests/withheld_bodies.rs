mod support;

use std::slice;

use plaine_chain::mock::{BuiltBlock, Scenario};
use plaine_chain::Progress;
use support::*;

const HONEST_TIP: u64 = plaine_consensus::constants::MAX_REORG_DEPTH * 2;

fn honest_chain() -> Scenario {
    Scenario::genesis(&params(), T0).extend(HONEST_TIP)
}

fn rig_on(chain: &Scenario) -> Rig {
    let p = params();
    let mut r = Rig::new(chain, p);
    r.sync(chain, 1);
    r
}

fn offer_headers_only(r: &mut Rig, source: u32, blocks: &[BuiltBlock]) -> plaine_chain::Accepted {
    let raws: Vec<[u8; 132]> = blocks.iter().map(|b| b.rec.raw).collect();
    r.cm.submit_headers_solicited(source, &raws)
        .expect("not halted")
}

fn withheld_branch(honest: &Scenario) -> Scenario {
    honest.fork_at(HONEST_TIP).spacing(1).extend(2)
}

fn bodyless_rig(honest: &Scenario) -> (Rig, Scenario) {
    let mut r = rig_on(honest);
    assert!(r.cm.anchor().is_none(), "no anchor: nothing here needs one");

    let attacker = withheld_branch(honest);
    let a = offer_headers_only(&mut r, 7, &blocks_above(&attacker, HONEST_TIP));
    assert_eq!(
        a.connected, 2,
        "premise: the branch is admitted to the arena"
    );
    assert!(
        !r.cm.have_body(&attacker.tip().hash),
        "premise: we do not hold the branch's bodies"
    );

    match r.cm.advance().expect("not halted") {
        Progress::NeedBodies(v) => {
            assert_eq!(v.len(), 2, "premise: both withheld bodies are asked for");
        }
        other => panic!("premise: advance must ask for the withheld bodies, got {other:?}"),
    }
    assert_eq!(r.height(), HONEST_TIP, "premise: the tip did not move");
    (r, attacker)
}

#[test]
fn commits_tip_while_heavier_withholds_bodies() {
    let honest = honest_chain();
    let (mut r, _attacker) = bodyless_rig(&honest);

    let extended = honest.fork_at(HONEST_TIP).extend(1);
    let next = extended.blocks[(HONEST_TIP + 1) as usize].clone();
    r.clock.set_unix(next.rec.time);
    assert_eq!(
        r.offer(1, slice::from_ref(&next)).connected,
        1,
        "our own block reaches the arena"
    );

    match r.cm.advance() {
        Ok(Progress::Advanced {
            tip,
            rolled_back,
            applied,
        }) => {
            assert_eq!(rolled_back, 0, "a pure extension discards nothing");
            assert_eq!(applied, 1);
            assert_eq!(tip.hash, next.rec.hash);
            assert_eq!(tip.height, HONEST_TIP + 1);
        }
        other => panic!("our own block on our own tip was not committed: {other:?}"),
    }
}

#[test]
fn keeps_committing_while_bodies_withheld() {
    let honest = honest_chain();
    let (mut r, _attacker) = bodyless_rig(&honest);

    let mut extended = honest.fork_at(HONEST_TIP);
    for i in 1..=5u64 {
        extended = extended.extend(1);
        let b = extended.blocks[(HONEST_TIP + i) as usize].clone();
        r.clock.set_unix(b.rec.time);
        assert_eq!(
            r.offer(1, slice::from_ref(&b)).connected,
            1,
            "honest block {i} reaches the arena"
        );
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
fn sealed_block_not_rejected_by_withheld_branch() {
    let honest = honest_chain();
    let (mut r, _attacker) = bodyless_rig(&honest);

    let mined = honest.fork_at(HONEST_TIP).extend(1);
    let b = mined.blocks[(HONEST_TIP + 1) as usize].clone();
    r.clock.set_unix(b.rec.time);
    r.cm.submit_headers_solicited(0, &[b.rec.raw])
        .expect("our own header");
    r.cm.submit_block(&b.rec.hash, b.body.clone())
        .expect("our own body");
    let verdict = r.cm.advance();
    assert!(
        matches!(verdict, Ok(Progress::Advanced { .. })),
        "seal() would report SealVerdict::Rejected for a block we mined: {verdict:?}"
    );
}

#[test]
fn withheld_bodies_re_requested_each_pass() {
    let honest = honest_chain();
    let (mut r, attacker) = bodyless_rig(&honest);
    let want: Vec<[u8; 32]> = blocks_above(&attacker, HONEST_TIP)
        .iter()
        .map(|b| b.rec.hash)
        .collect();

    let extended = honest.fork_at(HONEST_TIP).extend(1);
    let next = extended.blocks[(HONEST_TIP + 1) as usize].clone();
    r.clock.set_unix(next.rec.time);
    r.offer(1, slice::from_ref(&next));
    assert!(matches!(r.cm.advance(), Ok(Progress::Advanced { .. })));

    for h in &want {
        assert!(
            r.cm.wanted_bodies().contains(h),
            "after committing, the withheld body {} is no longer asked for",
            hex(h)
        );
    }

    match r.cm.advance().expect("not halted") {
        Progress::NeedBodies(v) => {
            for h in &want {
                assert!(v.contains(h), "NeedBodies dropped {}", hex(h));
            }
        }
        other => panic!("expected NeedBodies once nothing else can be committed, got {other:?}"),
    }
}

#[test]
fn bottom_up_branch_adopted_as_far_as_bodies() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);

    let attacker = honest.fork_at(HONEST_TIP).spacing(1).extend(3);
    let blocks = blocks_above(&attacker, HONEST_TIP);
    offer_headers_only(&mut r, 7, &blocks);

    r.cm.submit_block(&blocks[0].rec.hash, blocks[0].body.clone())
        .expect("admissible");

    match r.cm.advance().expect("not halted") {
        Progress::Advanced {
            tip,
            applied,
            rolled_back,
        } => {
            assert_eq!(rolled_back, 0);
            assert_eq!(applied, 1);
            assert_eq!(
                tip.hash, blocks[0].rec.hash,
                "the buildable prefix of the branch must be adopted"
            );
        }
        other => panic!("expected the prefix to commit, got {other:?}"),
    }
    for b in &blocks[1..] {
        assert!(
            r.cm.wanted_bodies().contains(&b.rec.hash),
            "the undelivered remainder must still be asked for"
        );
    }
}

#[test]
fn branch_with_body_hole_names_it() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);

    let attacker = honest.fork_at(HONEST_TIP).spacing(1).extend(3);
    let blocks = blocks_above(&attacker, HONEST_TIP);
    offer_headers_only(&mut r, 7, &blocks);

    r.cm.submit_block(&blocks[0].rec.hash, blocks[0].body.clone())
        .expect("admissible");
    r.cm.submit_block(&blocks[2].rec.hash, blocks[2].body.clone())
        .expect("admissible");

    match r.cm.advance().expect("not halted") {
        Progress::Advanced { tip, applied, .. } => {
            assert_eq!(applied, 1);
            assert_eq!(tip.hash, blocks[0].rec.hash);
        }
        other => panic!("expected the prefix below the hole to commit, got {other:?}"),
    }

    assert!(
        r.cm.wanted_bodies().contains(&blocks[1].rec.hash),
        "the hole must be named: {:?}",
        r.cm.wanted_bodies().len()
    );

    match r.cm.advance().expect("not halted") {
        Progress::NeedBodies(v) => assert!(v.contains(&blocks[1].rec.hash)),
        other => panic!("expected NeedBodies, got {other:?}"),
    }
}

#[test]
fn branch_adopted_when_bodies_arrive() {
    let honest = honest_chain();
    let (mut r, attacker) = bodyless_rig(&honest);

    for b in blocks_above(&attacker, HONEST_TIP) {
        r.cm.submit_block(&b.rec.hash, b.body.clone())
            .expect("body admissible");
    }
    match r.cm.advance().expect("not halted") {
        Progress::Advanced {
            tip,
            rolled_back,
            applied,
        } => {
            assert_eq!(rolled_back, 0);
            assert_eq!(applied, 2);
            assert_eq!(tip.hash, attacker.tip().hash);
        }
        other => panic!("the branch is adoptable once its bodies are held: {other:?}"),
    }
}

#[test]
fn withheld_branch_outworks_tip() {
    let honest = honest_chain();
    let (r, attacker) = bodyless_rig(&honest);
    let ours = r.cm.tip().chainwork;
    let theirs =
        r.cm.index()
            .get(&attacker.tip().hash)
            .expect("the branch is in the arena")
            .cum_work;
    assert!(
        theirs > ours,
        "fixture: the withheld branch must out-work our tip"
    );
}

fn hex(h: &[u8; 32]) -> String {
    h.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
