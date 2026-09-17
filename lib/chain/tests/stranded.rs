mod support;

use plaine_chain::error::{Condition, Reject};
use plaine_chain::mock::Scenario;
use plaine_chain::{BranchVerdict, Progress};
use plaine_consensus::rules::RuleError;
use support::*;

const CAP: u64 = plaine_consensus::constants::MAX_REORG_DEPTH;

const HONEST_TIP: u64 = CAP * 3;

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
    honest
        .fork_at(HONEST_TIP - depth)
        .spacing(1)
        .extend(depth + 1)
}

fn stage_deep_branch(r: &mut Rig, attacker: &Scenario, base: u64, depth: u64) {
    let cp = signed_checkpoint(&authority_key(), HONEST_TIP + 50, [0xAB; 32]);
    r.cm.submit_checkpoint(&cp).expect("verified");
    assert!(
        r.cm.anchor().is_some(),
        "premise: the relaxed ingest exemption is armed"
    );
    let a = r.offer(7, &blocks_above(attacker, base));
    assert_eq!(
        a.connected,
        depth + 1,
        "premise: the whole branch is in the arena"
    );
}

#[test]
fn best_branch_claims_no_fork() {
    let honest = honest_chain();
    let r = rig_on(&honest);
    let b = r.cm.branch_report();
    assert_eq!(b.verdict, BranchVerdict::OnBest);
    assert_eq!(b.tip, HONEST_TIP);
    assert_eq!(b.best, HONEST_TIP, "the best branch we hold is our chain");
    assert_eq!(b.depth, 0);
    assert_eq!(b.fork_height, b.tip, "a chain does not fork from itself");
    assert_eq!(b.best_hash, r.tip_hash());
}

#[test]
fn headers_without_bodies_report_gap() {
    let honest = honest_chain();
    let mut r = Rig::new(&honest, params());
    r.sync(&honest, 1);

    let longer = honest.extend(CAP * 2);
    let raws = longer.raw_headers_from(HONEST_TIP + 1);
    r.clock.set_unix(longer.tip().time);
    r.cm.submit_headers_solicited(9, &raws)
        .expect("headers ingest");

    assert!(
        matches!(r.cm.advance(), Ok(Progress::NeedBodies(_))),
        "premise: the pass has headers and no bodies"
    );

    let b = r.cm.branch_report();
    assert_eq!(b.tip, HONEST_TIP);
    assert_eq!(
        b.best,
        longer.tip().height,
        "we hold the better branch's tip header"
    );
    assert_eq!(b.depth, 0, "a pure extension discards nothing");
    assert_eq!(
        b.fork_height, HONEST_TIP,
        "it leaves our chain at our own tip"
    );
    match b.verdict {
        BranchVerdict::NeedBodies { missing } => {
            assert_eq!(
                missing as u64,
                CAP * 2,
                "every block of the extension is bodyless"
            )
        }
        other => panic!("a bodyless extension is not a fork and not a strand: {other:?}"),
    }
}

#[test]
fn deep_branch_reports_stranded_fork() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);
    let depth = CAP + 1;
    let attacker = branch_at_depth(&honest, depth);
    let base = HONEST_TIP - depth;

    stage_deep_branch(&mut r, &attacker, base, depth);

    let err =
        r.cm.advance()
            .expect_err("past the cap with no anchor covering the branch");
    assert!(
        matches!(err, Reject::Rule(RuleError::ReorgTooDeep { .. })),
        "got {err:?}"
    );

    let b = r.cm.branch_report();
    assert_eq!(b.verdict, BranchVerdict::Stranded { cap: CAP });
    assert_eq!(b.tip, HONEST_TIP);
    assert_eq!(b.depth, depth);
    assert_eq!(b.fork_height, base, "the report carries the fork point");
    assert_eq!(b.best, attacker.tip().height);
    assert_eq!(b.best_hash, attacker.tip().hash);
}

#[test]
fn unseen_branch_looks_like_quiet_network() {
    let honest = honest_chain();
    let r = rig_on(&honest);
    let _elsewhere = honest.fork_at(HONEST_TIP / 2).spacing(1).extend(HONEST_TIP);

    let b = r.cm.branch_report();
    assert_eq!(
        b.verdict,
        BranchVerdict::OnBest,
        "this report is arena-only by construction and must not pretend otherwise"
    );
}

#[test]
fn refusal_carries_fork_point() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);
    let depth = CAP + 1;
    let base = HONEST_TIP - depth;
    let attacker = branch_at_depth(&honest, depth);
    stage_deep_branch(&mut r, &attacker, base, depth);
    let _ = r.cm.advance();

    assert!(
        r.observed(|c| matches!(
            c,
            Condition::ReorgTooDeepRefused { our_tip, their_tip, depth: d, fork_height }
                if *our_tip == HONEST_TIP
                    && *their_tip == attacker.tip().height
                    && *d == depth
                    && *fork_height == base
        )),
        "the refusal must name where the chains part, not only how deep: {:?}",
        r.conditions()
    );
}

#[test]
fn predicate_uses_configured_cap() {
    let honest = honest_chain();
    let depth = CAP + 1;
    let base = HONEST_TIP - depth;
    let attacker = branch_at_depth(&honest, depth);

    {
        let mut r = rig_on(&honest);
        stage_deep_branch(&mut r, &attacker, base, depth);
        assert!(
            matches!(
                r.cm.advance(),
                Err(Reject::Rule(RuleError::ReorgTooDeep { .. }))
            ),
            "control arm: at the shipped cap this branch is refused"
        );
        assert_eq!(r.height(), HONEST_TIP);
    }

    let p = plaine_chain::ChainParams {
        max_reorg_depth: depth,
        ..params()
    };
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let a = r.offer(7, &blocks_above(&attacker, base));
    assert_eq!(
        a.connected,
        depth + 1,
        "with the cap raised the ingest gate admits the branch, no anchor needed"
    );
    match r.cm.advance() {
        Ok(Progress::Advanced {
            rolled_back,
            applied,
            ..
        }) => {
            assert_eq!(rolled_back, depth);
            assert_eq!(applied, depth + 1);
        }
        other => panic!("the predicate ignored ChainParams::max_reorg_depth: {other:?}"),
    }
    assert_eq!(r.height(), attacker.tip().height);
    assert_eq!(r.cm.branch_report().verdict, BranchVerdict::OnBest);
}

#[test]
fn zero_cap_means_no_cap() {
    let honest = honest_chain();
    let depth = CAP * 2;
    let base = HONEST_TIP - depth;
    let attacker = branch_at_depth(&honest, depth);

    let p = plaine_chain::ChainParams {
        max_reorg_depth: 0,
        ..params()
    };
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let a = r.offer(7, &blocks_above(&attacker, base));
    assert_eq!(a.connected, depth + 1, "cap 0 admits at ingest too");
    assert!(
        matches!(r.cm.advance(), Ok(Progress::Advanced { .. })),
        "cap 0 disables layer 1 entirely, it does not forbid every reorg"
    );
    assert_eq!(r.height(), attacker.tip().height);
}
