mod support;

use plaine_chain::error::Reject;
use plaine_chain::mock::Scenario;
use plaine_chain::{BranchVerdict, Progress};
use support::*;

const APPLIED: u64 = 20;

const BACKLOG: u64 = 20;

fn chain() -> Scenario {
    Scenario::genesis(&params(), T0).extend(APPLIED + BACKLOG)
}

fn stopped_mid_sync(c: &Scenario) -> Rig {
    let mut r = Rig::new(c, params());

    let prefix = c.fork_at(APPLIED);
    r.sync(&prefix, 1);
    assert_eq!(
        r.height(),
        APPLIED,
        "premise: applied tip is where the node stopped"
    );

    r.clock.set_unix(c.tip().time.max(T0));
    let raws: Vec<[u8; 132]> = c.raw_headers_from(APPLIED + 1);
    let a = r.cm.submit_headers_solicited(1, &raws).expect("not halted");
    assert_eq!(
        a.connected, BACKLOG,
        "premise: the whole backlog is in the arena"
    );

    assert_eq!(
        r.store.side_headers_written(),
        APPLIED + BACKLOG,
        "premise: every connected header was persisted, canonical ones included"
    );
    assert_eq!(
        r.store.side_headers_from(0, 4096).len() as u64,
        BACKLOG,
        "premise: the store can still produce the backlog, and only the backlog"
    );
    r
}

fn body_of(c: &Scenario, height: u64) -> (plaine_chain::types::Hash32, Vec<u8>) {
    let b = &c.blocks[height as usize];
    (b.rec.hash, b.body.clone())
}

#[test]
fn restart_accepts_wanted_body() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);

    let (h, body) = body_of(&c, APPLIED + 1);
    assert!(
        r.cm.header_by_hash(&h).is_some(),
        "premise: the store knows this header, which is why a body arrives for it"
    );

    r.restart();

    assert!(
        r.cm.header_by_hash(&h).is_some(),
        "premise: the store still knows it"
    );

    assert_eq!(
        r.cm.submit_block(&h, body),
        Ok(()),
        "the body the node asked for must be admissible after a restart"
    );
    assert!(
        matches!(r.cm.advance(), Ok(Progress::Advanced { .. })),
        "it must apply, not merely be accepted"
    );
    assert_eq!(r.height(), APPLIED + 1, "the tip moves");
}

#[test]
fn restart_finishes_backlog() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    r.restart();
    assert_eq!(
        r.height(),
        APPLIED,
        "a restart never moves the tip by itself"
    );

    for h in APPLIED + 1..=APPLIED + BACKLOG {
        let (hash, body) = body_of(&c, h);
        assert_eq!(r.cm.submit_block(&hash, body), Ok(()), "body at height {h}");
        assert!(
            matches!(r.cm.advance(), Ok(Progress::Advanced { .. })),
            "apply at {h}"
        );
    }
    assert_eq!(
        r.height(),
        APPLIED + BACKLOG,
        "the node reaches the tip it held headers for"
    );
    assert_eq!(
        r.cm.tip().hash,
        c.tip().hash,
        "it is the same chain, not a private one"
    );
}

#[test]
fn rebuilt_arena_names_missing_bodies() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    r.restart();

    assert_eq!(
        r.cm.stats().side_headers_restored,
        BACKLOG,
        "every persisted side header is back in the arena"
    );

    let b = r.cm.branch_report();
    assert_eq!(
        b.verdict,
        BranchVerdict::NeedBodies {
            missing: BACKLOG as usize
        },
        "the node can say which of the four predicaments it is in"
    );
    assert_eq!(b.tip, APPLIED);
    assert_eq!(
        b.best,
        APPLIED + BACKLOG,
        "it knows how far the branch it holds reaches"
    );
    assert_eq!(
        b.fork_height, APPLIED,
        "a pure extension forks at our own tip"
    );
    assert_eq!(
        b.depth, 0,
        "therefore discards nothing, so the reorg cap is not involved"
    );

    let p = r.cm.advance();
    assert!(matches!(p, Ok(Progress::NeedBodies(_))), "got {p:?}");
    let want = r.cm.wanted_bodies().to_vec();
    assert!(
        !want.is_empty(),
        "a pass that found nothing to commit must say what it needs"
    );
    assert_eq!(
        want[0],
        c.blocks[APPLIED as usize + 1].rec.hash,
        "starting at the first gap"
    );
}

#[test]
fn rebuild_links_whole_run() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    r.restart();
    for h in APPLIED + 1..=APPLIED + BACKLOG {
        let (hash, _) = body_of(&c, h);
        assert!(
            r.cm.ancestor_at(&hash, APPLIED).is_some(),
            "header at {h} is in the arena and linked back to the applied tip"
        );
    }
}

#[test]
fn rebuild_respects_arena_budget() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);

    r.params.max_side_headers = 5;
    r.restart();
    assert_eq!(
        r.cm.stats().side_headers_restored,
        5,
        "the rebuild stops at its own cap, not at the store's"
    );
}

#[test]
fn evicted_backlog_bottom_dropped() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    let cut = APPLIED + BACKLOG / 2;
    r.store.evict_side_below(cut);
    assert_eq!(
        r.store.side_headers_from(0, 4096).len() as u64,
        BACKLOG / 2 + 1,
        "premise: the store kept only the top of the backlog"
    );

    r.restart();

    assert_eq!(
        r.cm.stats().side_headers_restored,
        0,
        "the surviving run hangs off a header nobody holds, so none of it links"
    );
    assert_eq!(r.height(), APPLIED, "the tip is not moved by a rebuild");
    let top = c.blocks[(APPLIED + BACKLOG) as usize].rec.hash;
    assert!(
        r.cm.ancestor_at(&top, APPLIED).is_none(),
        "nothing was attached to our tip to make the numbers work"
    );
    assert_eq!(r.cm.branch_report().verdict, BranchVerdict::OnBest);
    assert!(matches!(r.cm.advance(), Ok(Progress::NoChange)));
}

#[test]
fn no_side_enum_still_drains_backlog() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    r.store.hide_side_headers();
    r.restart();

    assert_eq!(
        r.cm.stats().side_headers_restored,
        0,
        "premise: this store answers the enumeration with nothing"
    );

    for h in APPLIED + 1..=APPLIED + BACKLOG {
        let (hash, body) = body_of(&c, h);
        assert_eq!(r.cm.submit_block(&hash, body), Ok(()), "body at height {h}");
        assert!(
            matches!(r.cm.advance(), Ok(Progress::Advanced { .. })),
            "apply at {h}"
        );
    }
    assert_eq!(r.height(), APPLIED + BACKLOG);
    assert_eq!(
        r.cm.stats().headers_readmitted,
        BACKLOG,
        "one header put back per body, which is what 'one link at a time' means"
    );
}

#[test]
fn no_side_enum_cannot_self_diagnose() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    r.store.hide_side_headers();
    r.restart();

    assert_eq!(
        r.cm.branch_report().verdict,
        BranchVerdict::OnBest,
        "with a short arena the node believes it is on the best branch it holds"
    );
    assert!(matches!(r.cm.advance(), Ok(Progress::NoChange)));
    assert!(
        r.cm.wanted_bodies().is_empty(),
        "it can name no body to ask for"
    );
}

#[test]
fn unknown_header_body_refused_after_restart() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    r.restart();
    let bogus = [0x5Au8; 32];
    assert_eq!(
        r.cm.submit_block(&bogus, vec![0u8; 64]),
        Err(Reject::BodyNotAdmissible { hash: bogus }),
        "the store cannot produce a header for it, so it is not admissible"
    );
    assert_eq!(
        r.cm.stats().headers_readmitted,
        0,
        "nothing was put into the arena"
    );
}

#[test]
fn link_repair_refuses_orphan_body() {
    let c = chain();
    let mut r = stopped_mid_sync(&c);
    r.store.hide_side_headers();
    r.restart();

    let (hash, body) = body_of(&c, APPLIED + 2);
    assert!(
        r.cm.header_by_hash(&hash).is_some(),
        "premise: the store knows this header"
    );
    assert_eq!(
        r.cm.submit_block(&hash, body),
        Err(Reject::BodyNotAdmissible { hash }),
        "one link means one link"
    );

    let (h1, b1) = body_of(&c, APPLIED + 1);
    assert_eq!(r.cm.submit_block(&h1, b1), Ok(()));
    let (h2, b2) = body_of(&c, APPLIED + 2);
    assert_eq!(r.cm.submit_block(&h2, b2), Ok(()), "now its parent is here");
}

#[test]
fn invalid_branch_not_wanted_after_restart() {
    use plaine_chain::traits::Sink;

    let c = chain();
    let mut r = stopped_mid_sync(&c);

    let (bad, _) = body_of(&c, APPLIED + 1);
    r.store.mark_invalid(&bad).expect("mock sink");

    r.restart();
    assert_eq!(
        r.cm.stats().side_headers_restored,
        BACKLOG,
        "premise: the headers are back in the arena"
    );

    let p = r.cm.advance();
    assert!(
        matches!(p, Ok(Progress::NoChange)),
        "a poisoned branch is not a candidate: {p:?}"
    );
    assert!(
        r.cm.wanted_bodies().is_empty(),
        "no body of an invalid branch is requested"
    );
    assert_eq!(
        r.cm.submit_block(&bad, c.blocks[APPLIED as usize + 1].body.clone()),
        Err(Reject::BodyNotAdmissible { hash: bad }),
        "its body is refused on invalidity, not on ignorance"
    );
}
