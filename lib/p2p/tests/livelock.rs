use plaine_p2p::constants::{MAX_REORG_DEPTH, REPAIR_STUCK_REPEATS, TRACKING_AUDIT_MS};
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const TIP: u64 = 424;

const FORK_BASE: u64 = 413;

const DEPTH: u64 = TIP - FORK_BASE;

const THEIR_TIP: u64 = 500;

const SOAK_MS: u64 = 3 * TRACKING_AUDIT_MS;

fn stranded() -> (Sim, Vec<HeaderRec>) {
    let mut sim = Sim::new(TIP + 1, T0);

    sim.chain.applied_tip(true);
    let branch = sim.fork(DEPTH, THEIR_TIP - FORK_BASE, 7);
    assert_eq!(branch[0].height, FORK_BASE + 1, "fixture: fork base");
    assert_eq!(
        branch.last().expect("branch").height,
        THEIR_TIP,
        "fixture: their tip"
    );

    sim.chain.swallow_headers_from(FORK_BASE + 1);
    let p = sim.add_peer(Behaviour::Honest, branch.clone());
    sim.connect(p);
    sim.run(SOAK_MS, 1_000);
    (sim, branch)
}

fn repaired_from(sim: &Sim) -> Option<u64> {
    sim.engine.conditions().iter().rev().find_map(|c| match c {
        Condition::HeaderRefusedByChain { height, why, .. }
            if *why == "the chain does not hold a header this engine committed" =>
        {
            Some(*height)
        }
        _ => None,
    })
}

#[test]
fn fork_inside_reorg_cap() {
    const { assert!(DEPTH < MAX_REORG_DEPTH) };
}

#[test]
fn repair_walk_reaches_link() {
    let (sim, _branch) = stranded();
    let at = repaired_from(&sim).expect(
        "the chain kept no header of the competing branch for three audit intervals \
         and the engine never flagged it. audit_commit is the only detector reachable \
         on this path.",
    );
    assert_eq!(
        at,
        FORK_BASE + 1,
        "the repair restarted at {at} instead of walking down to {}. Our own tip is \
         {TIP}, and `audit_commit` filters the `known` sweep with \
         `r.height > self.chain.tip().height`, so on a reorg where every header \
         that matters is at or below our tip the sweep is empty and the repair \
         falls back to the highest commit - the 421 we see in the live \
         end-to-end run.",
        FORK_BASE + 1
    );
}

fn ms_to_converge(sim: &mut Sim, branch: &[HeaderRec], budget_ms: u64, step_ms: u64) -> Option<u64> {
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

#[test]
fn heal_within_one_audit() {
    let (mut sim, branch) = stranded();
    sim.chain.keep_all_headers();
    let ms = ms_to_converge(&mut sim, &branch, 10 * TRACKING_AUDIT_MS, 1_000).unwrap_or_else(|| {
        panic!(
            "the chain started keeping headers again and the competing branch never \
             arrived in {} s of virtual time.",
            10 * TRACKING_AUDIT_MS / 1_000
        )
    });
    assert!(
        ms <= TRACKING_AUDIT_MS,
        "healed partition took {ms} ms to converge, over one audit interval of {TRACKING_AUDIT_MS} ms; the link at height {} waits out an audit per block",
        branch[0].height
    );
    eprintln!("CONVERGED in {ms} ms of virtual time after the heal");
}

#[test]
fn a_healed_partition_heals_the_chain() {
    let (mut sim, branch) = stranded();
    sim.chain.keep_all_headers();
    sim.run(600_000, 1_000);
    let held = sim.chain.headers();
    let missing: Vec<u64> = branch
        .iter()
        .filter(|h| !held.iter().any(|x| x.hash == h.hash))
        .map(|h| h.height)
        .collect();
    assert!(
        missing.is_empty(),
        "partition healed but the chain did not: {} of {} branch headers never reached the sink twice, lowest at {}; nothing clears a `known` header at or below our tip",
        missing.len(),
        branch.len(),
        missing[0]
    );
}

fn permanently_swallowing(ms: u64) -> Sim {
    const AT: u64 = 20;
    let mut sim = Sim::new(1, T0);
    sim.chain.applied_tip(true);
    let chain = sim.extension(60);
    sim.chain.swallow_headers_from(AT + 1);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(ms, 1_000);
    sim
}

const MUST_SAY_WITHIN_MS: u64 = 5 * TRACKING_AUDIT_MS;

#[test]
fn stuck_break_reported() {
    let sim = permanently_swallowing(MUST_SAY_WITHIN_MS);
    let stuck = sim.engine.conditions().iter().find_map(|c| match c {
        Condition::HeaderRepairStuck { height, repeats, our_tip, .. } => {
            Some((*height, *repeats, *our_tip))
        }
        _ => None,
    });
    let (height, repeats, our_tip) = stuck.unwrap_or_else(|| {
        panic!(
            "repaired the same break for {} audit intervals, tip never moved, never reported stuck: {:?}",
            REPAIR_STUCK_REPEATS as u64 + 2,
            sim.engine.conditions()
        )
    });
    assert_eq!(height, 21, "the condition names the wrong break");
    assert_eq!(our_tip, 20, "the condition names the wrong tip");
    assert!(
        repeats >= REPAIR_STUCK_REPEATS,
        "the condition fired after {repeats} reports, below the {REPAIR_STUCK_REPEATS} the constant promises"
    );

    assert_eq!(
        sim.engine.repair_stuck().map(|(h, _, _)| h),
        Some(21),
        "condition was reported but the getter does not answer"
    );
}

#[test]
fn single_refusal_no_wedge() {
    let sim = permanently_swallowing(TRACKING_AUDIT_MS + TRACKING_AUDIT_MS / 2);
    assert!(
        !sim.said(|c| matches!(c, Condition::HeaderRepairStuck { .. })),
        "reported stuck inside two audit intervals, before repair could work: {:?}",
        sim.engine.conditions()
    );
}

#[test]
fn moved_tip_clears_stuck() {
    let mut sim = permanently_swallowing(MUST_SAY_WITHIN_MS);
    assert!(
        sim.engine.repair_stuck().is_some(),
        "fixture: the node must be reporting stuck before the tip is moved"
    );
    let more = sim.extension(1);
    sim.chain.extend(&more, true);
    assert_eq!(
        sim.engine.repair_stuck(),
        None,
        "applied a block and still answers `repair_stuck`; a moving tip is not wedged"
    );
}

#[test]
fn healthy_sync_not_stuck() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(60);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(10 * TRACKING_AUDIT_MS, 1_000);
    assert!(
        !sim.said(|c| matches!(c, Condition::HeaderRepairStuck { .. })),
        "a sync that reached height {} was reported as a wedge",
        sim.chain.tip().height
    );
    assert_eq!(sim.chain.tip().height, 60, "fixture: the sync must have worked");
}

#[test]
fn healed_fork_not_stuck() {
    let (mut sim, _branch) = stranded();
    sim.chain.keep_all_headers();

    sim.run(TRACKING_AUDIT_MS, 1_000);
    let before = sim.engine.conditions().len();
    sim.run(5 * TRACKING_AUDIT_MS, 1_000);
    let after: Vec<_> = sim.engine.conditions()[before..]
        .iter()
        .filter(|c| matches!(c, Condition::HeaderRepairStuck { .. }))
        .cloned()
        .collect();
    assert!(
        after.is_empty(),
        "partition healed but the node kept reporting stuck for five more audit intervals: {after:?}"
    );

    assert_eq!(
        sim.engine.repair_stuck(),
        None,
        "the branch was adopted and the engine still answers `repair_stuck`"
    );
}

#[test]
fn restart_adopts_branch() {
    let mut sim = Sim::new(TIP + 1, T0);
    sim.chain.applied_tip(true);
    let branch = sim.fork(DEPTH, THEIR_TIP - FORK_BASE, 7);
    let p = sim.add_peer(Behaviour::Honest, branch.clone());
    sim.connect(p);
    sim.run(120_000, 1_000);
    let held = sim.chain.headers();
    let missing = branch
        .iter()
        .filter(|h| !held.iter().any(|x| x.hash == h.hash))
        .count();
    assert_eq!(
        missing, 0,
        "fresh engine against a header-keeping chain failed to deliver {missing} of the branch (the restart control)"
    );
}
