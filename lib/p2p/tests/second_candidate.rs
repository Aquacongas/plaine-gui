use plaine_p2p::constants::{MAX_REORG_DEPTH, REPAIR_STUCK_REPEATS, TRACKING_AUDIT_MS};
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const TIP: u64 = 424;

const FORK_BASE: u64 = 413;

const LINK: u64 = FORK_BASE + 1;
const DEPTH: u64 = TIP - FORK_BASE;

const THEIR_TIP: u64 = 500;
const SOAK_MS: u64 = 3 * TRACKING_AUDIT_MS;

const KEPT_NOTHING: &str = "mock: the chain kept nothing";

fn stranded_with_a_talking_chain(peers: usize) -> (Sim, Vec<HeaderRec>) {
    let mut sim = Sim::new(TIP + 1, T0);

    sim.chain.applied_tip(true);
    let branch = sim.fork(DEPTH, THEIR_TIP - FORK_BASE, 7);
    assert_eq!(branch[0].height, LINK, "fixture: fork base");
    assert_eq!(
        branch.last().expect("branch").height,
        THEIR_TIP,
        "fixture: their tip"
    );
    const { assert!(DEPTH < MAX_REORG_DEPTH) };
    sim.chain.refuse_headers_from(LINK);
    for _ in 0..peers {
        let p = sim.add_peer(Behaviour::Honest, branch.clone());
        sim.connect(p);
    }
    sim.run(SOAK_MS, 1_000);
    (sim, branch)
}

fn breaks(sim: &Sim) -> Vec<u64> {
    sim.engine
        .conditions()
        .iter()
        .filter_map(|c| match c {
            Condition::HeaderRefusedByChain { height, why, .. } if *why == KEPT_NOTHING => {
                Some(*height)
            }
            _ => None,
        })
        .collect()
}

fn ms_to_converge(
    sim: &mut Sim,
    branch: &[HeaderRec],
    budget_ms: u64,
    step_ms: u64,
) -> Option<u64> {
    let mut elapsed = 0;
    while elapsed < budget_ms {
        sim.run(step_ms, step_ms);
        elapsed += step_ms;
        let held = sim.chain.headers();
        if branch.iter().all(|h| held.iter().any(|x| x.hash == h.hash)) {
            return Some(elapsed);
        }
    }
    None
}

fn missing(sim: &Sim, branch: &[HeaderRec]) -> Vec<u64> {
    let held = sim.chain.headers();
    branch
        .iter()
        .filter(|h| !held.iter().any(|x| x.hash == h.hash))
        .map(|h| h.height)
        .collect()
}

#[test]
fn reported_break_does_not_climb() {
    let (sim, _b) = stranded_with_a_talking_chain(1);
    let seen = breaks(&sim);
    assert!(
        !seen.is_empty(),
        "the chain named a break and the engine never reported one"
    );
    let climbed: Vec<u64> = seen.iter().copied().filter(|h| *h != LINK).collect();
    assert!(
        climbed.is_empty(),
        "engine reported {climbed:?} on top of {LINK}; the break must stay pinned at {LINK}, a climbing break resets the stuck detector every round trip"
    );
}

#[test]
fn partition_heals_through_truthful_door() {
    let (mut sim, branch) = stranded_with_a_talking_chain(1);
    sim.chain.keep_all_headers();
    sim.run(600_000, 1_000);
    let gone = missing(&sim, &branch);
    assert!(
        gone.is_empty(),
        "partition healed but the chain did not: {} of {} branch headers never reached the sink twice, lowest at {}; they are stuck in `known` and nothing re-requests them",
        gone.len(),
        branch.len(),
        gone[0]
    );
}

#[test]
fn heal_within_one_audit_truthful() {
    let (mut sim, branch) = stranded_with_a_talking_chain(1);
    sim.chain.keep_all_headers();
    let ms =
        ms_to_converge(&mut sim, &branch, 10 * TRACKING_AUDIT_MS, 1_000).unwrap_or_else(|| {
            panic!(
                "the branch never arrived in {} s",
                10 * TRACKING_AUDIT_MS / 1_000
            )
        });
    assert!(
        ms <= TRACKING_AUDIT_MS,
        "the healed partition took {ms} ms to converge, more than one audit interval \
         of {TRACKING_AUDIT_MS} ms - so the branch is arriving through `audit_commit` \
         and not through the break the chain already named."
    );
    eprintln!("CONVERGED in {ms} ms of virtual time after the heal (truthful door)");
}

#[test]
fn three_peers_do_not_change_it() {
    let (mut sim, branch) = stranded_with_a_talking_chain(3);
    sim.chain.keep_all_headers();
    sim.run(600_000, 1_000);
    let gone = missing(&sim, &branch);
    assert!(
        gone.is_empty(),
        "with three honest peers, {} headers never arrived",
        gone.len()
    );
}

#[test]
fn wedge_is_reported() {
    let (sim, _b) = stranded_with_a_talking_chain(1);
    let (height, _why, repeats) = sim.engine.repair_stuck().unwrap_or_else(|| {
        panic!(
            "repaired the same break for {} audit intervals, tip pinned at {TIP}, never reported stuck: {:?}",
            SOAK_MS / TRACKING_AUDIT_MS,
            sim.engine.conditions()
        )
    });
    assert_eq!(height, LINK, "the node named the wrong break as the wedge");
    assert!(
        repeats >= REPAIR_STUCK_REPEATS,
        "reported after only {repeats} repeats"
    );
    assert!(
        sim.said(|c| matches!(c, Condition::HeaderRepairStuck { our_tip, .. } if *our_tip == TIP)),
        "the getter answers and the condition was never raised, so an embedder \
         draining the ring never hears about it"
    );
}

#[test]
fn healed_node_clears_stuck() {
    let (mut sim, branch) = stranded_with_a_talking_chain(1);
    sim.chain.keep_all_headers();
    sim.run(10 * TRACKING_AUDIT_MS, 1_000);
    assert!(
        missing(&sim, &branch).is_empty(),
        "fixture: the heal must have worked"
    );
    assert_eq!(
        sim.engine.repair_stuck(),
        None,
        "the branch was adopted and the engine still answers `repair_stuck`"
    );
}

#[test]
fn restart_adopts_branch_truthful() {
    let mut sim = Sim::new(TIP + 1, T0);
    sim.chain.applied_tip(true);
    let branch = sim.fork(DEPTH, THEIR_TIP - FORK_BASE, 7);
    let p = sim.add_peer(Behaviour::Honest, branch.clone());
    sim.connect(p);
    sim.run(120_000, 1_000);
    assert!(
        missing(&sim, &branch).is_empty(),
        "the restart control does not hold, so nothing else in this file \
         distinguishes engine state from chain state"
    );
}

#[test]
fn fixture_names_break_like_chain() {
    let mut sim = Sim::new(TIP + 1, T0);
    sim.chain.applied_tip(true);
    let branch = sim.fork(DEPTH, THEIR_TIP - FORK_BASE, 7);
    sim.chain.refuse_headers_from(LINK);

    let second = branch[1];
    assert_eq!(second.height, LINK + 1, "fixture");
    let batch = HeaderBatch {
        headers: vec![second],
        source: PeerId(1),
        door: Door::Announced,
    };
    let _ = sim.chain.submit_headers(batch.clone());
    match sim.chain.submit_headers(batch) {
        Err(SinkError::RefusedAt { height, .. }) => assert_eq!(
            height, LINK,
            "named the refused header's own height, not the parent height to repair from"
        ),
        other => panic!("the mock owed a deferred refusal and answered {other:?}"),
    }
}

#[test]
fn sink_journal_records_offers() {
    let (mut sim, branch) = stranded_with_a_talking_chain(1);
    sim.chain.clear_submissions();
    sim.chain.keep_all_headers();
    sim.run(600_000, 1_000);
    let subs = sim.chain.submissions();
    assert!(
        subs.iter()
            .any(|(lo, hi, v)| *lo <= LINK && *hi >= LINK && *v == "ok"),
        "the branch arrived and the sink's journal has no accepted batch containing \
         height {LINK}: {subs:?}"
    );
    assert!(
        missing(&sim, &branch).is_empty(),
        "fixture: the heal must have worked"
    );
}
