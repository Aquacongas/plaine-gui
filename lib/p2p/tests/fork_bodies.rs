use plaine_p2p::constants::*;
use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::sync::Event;
use plaine_p2p::traits::*;

const T0: u64 = 1_800_000_000;

const TIP: u64 = 599;

fn forked(peer: Behaviour) -> (Sim, PeerId, Vec<HeaderRec>) {
    let mut sim = Sim::new(TIP + 1, T0);
    let branch = sim.fork(4, 20, 42);
    assert_eq!(
        branch.first().map(|h| h.height),
        Some(TIP - 3),
        "the branch must start four blocks below our tip"
    );
    let p = sim.add_peer(peer, branch.clone());
    sim.connect(p);
    (sim, p, branch)
}

fn below_our_tip(branch: &[HeaderRec]) -> Vec<HeaderRec> {
    branch.iter().filter(|h| h.height <= TIP).copied().collect()
}

#[test]
fn branch_below_tip_bodies_requested() {
    let (mut sim, _p, branch) = forked(Behaviour::HeadersOnly);
    sim.run(60_000, 1_000);

    assert!(
        sim.engine.verified_height() > TIP,
        "the branch's headers never reached the engine (verified {})",
        sim.engine.verified_height()
    );
    assert_eq!(
        sim.engine.body.applied(),
        TIP,
        "the fixture depends on the body track being stuck at our own tip"
    );

    assert_eq!(
        sim.engine.fork_wanted_heights(),
        vec![TIP - 3, TIP - 2, TIP - 1, TIP],
        "the competing branch's bodies below our own tip were not wanted"
    );

    assert!(
        plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.fork_body_requests) >= 4,
        "the list was built and no GETDATA was issued from it ({} requests)",
        plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.fork_body_requests)
    );
    let _ = branch;
}

#[test]
fn served_branch_reaches_sink() {
    let (mut sim, _p, branch) = forked(Behaviour::Honest);
    sim.run(60_000, 1_000);

    let below = below_our_tip(&branch);
    assert_eq!(below.len(), 4);
    for h in &below {
        assert!(
            sim.getdata_for(&h.hash) >= 1,
            "no GETDATA was ever issued for the branch block at height {}",
            h.height
        );
        assert!(
            ChainView::have_body(&*sim.chain, &h.hash),
            "the body of the branch block at height {} never reached the sink",
            h.height
        );
    }
    assert!(
        plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.fork_bodies_applied) >= 4,
        "the sink took them without the engine counting it"
    );
}

#[test]
fn branch_body_not_unsolicited() {
    let (mut sim, p, _branch) = forked(Behaviour::Honest);
    sim.run(60_000, 1_000);
    let scored = sim
        .actions
        .iter()
        .filter(|a| {
            matches!(
                a,
                plaine_p2p::sync::Action::Score {
                    peer,
                    offence: plaine_p2p::peer::Offence::UnsolicitedBody
                } if *peer == p
            )
        })
        .count();
    assert_eq!(
        scored, 0,
        "the peer that served the reorg was scored {scored} times for doing it"
    );
}

#[test]
fn restart_uses_chain_missing_list() {
    let (mut sim, _p, branch) = forked(Behaviour::HeadersOnly);
    sim.run(30_000, 1_000);
    assert!(sim.engine.verified_height() > TIP, "headers first");

    let below = below_our_tip(&branch);
    sim.chain.set_wanted_bodies(below.iter().map(|h| h.hash).collect());
    sim.run(30_000, 1_000);

    for h in &below {
        assert!(
            sim.engine.fork_wanted_heights().contains(&h.height),
            "the chain named the body at height {} and the transport ignored it",
            h.height
        );
    }
}

#[test]
fn no_request_without_header() {
    let (mut sim, _p, _branch) = forked(Behaviour::HeadersOnly);
    sim.run(30_000, 1_000);
    let before = plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.fork_body_requests);

    let invented: Vec<Hash32> = (0u8..12)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = 0xEE;
            h[1] = i;
            h
        })
        .collect();
    sim.chain.set_wanted_bodies(invented.clone());
    sim.run(30_000, 1_000);

    for h in &invented {
        assert_eq!(
            sim.getdata_for(h),
            0,
            "a body was requested for a header this node does not hold"
        );
    }

    assert_eq!(
        sim.engine.fork_wanted_len(),
        4,
        "invented hashes entered the bounded list"
    );
    let _ = before;
}

#[test]
fn branch_past_cap_no_list() {
    let mut sim = Sim::new(TIP + 1, T0);
    let branch = sim.fork(200, 260, 43);
    let p = sim.add_peer(Behaviour::HeadersOnly, branch.clone());
    sim.connect(p);

    sim.chain
        .set_wanted_bodies(branch.iter().filter(|h| h.height <= TIP).map(|h| h.hash).collect());
    sim.run(60_000, 1_000);

    assert_eq!(
        sim.engine.fork_wanted_len(),
        0,
        "bodies were wanted for a branch the ingest gate refused as deeper than the cap"
    );
    for h in branch.iter().filter(|h| h.height <= TIP) {
        assert_eq!(
            sim.getdata_for(&h.hash),
            0,
            "a GETDATA went out for a block at height {} on a branch past the reorg cap",
            h.height
        );
    }

    assert!(sim.connected(p), "the peer went away, so nothing was refused");
    assert!(
        plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.gate2_reject) > 0,
        "the branch was never actually offered to the context gate"
    );
}

#[test]
fn healthy_download_no_branch_list() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(400);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(120_000, 1_000);

    assert_eq!(sim.engine.body.applied(), 400, "the fixture did not sync");
    assert_eq!(
        sim.engine.fork_wanted_len(),
        0,
        "a linear download produced a competing-branch list"
    );
    assert_eq!(
        plaine_p2p::metrics::Metrics::get(&sim.engine.metrics.fork_body_requests),
        0,
        "a linear download issued competing-branch GETDATA"
    );
    assert!(
        !sim.said(|c| matches!(c, Condition::ForkBodiesWanted { .. })),
        "a linear download reported a fork"
    );
}

#[test]
fn restart_only_from_chain_list() {
    let (mut sim, _p, branch) = forked(Behaviour::Honest);
    sim.run(90_000, 1_000);
    assert!(
        sim.engine.wanted_len() == 0,
        "the fixture needs the ordinary window drained; it holds {}",
        sim.engine.wanted_len()
    );

    let below = below_our_tip(&branch);
    assert_eq!(below.len(), 4);
    for h in &below {
        sim.chain.forget_body(&h.hash);
    }
    sim.run(20_000, 1_000);
    assert_eq!(
        sim.engine.fork_wanted_len(),
        0,
        "the walk found a branch it cannot have had a starting point for"
    );

    sim.chain.set_wanted_bodies(below.iter().map(|h| h.hash).collect());
    sim.run(40_000, 1_000);
    for h in &below {
        assert!(
            ChainView::have_body(&*sim.chain, &h.hash),
            "the chain named the body at height {} and it never came back",
            h.height
        );
    }
}

fn wedged(run_on: u64) -> (Sim, PeerId, Vec<HeaderRec>) {
    wedged_publishing_after(run_on, 60_000)
}

fn wedged_publishing_after(run_on: u64, after_ms: u64) -> (Sim, PeerId, Vec<HeaderRec>) {
    let mut sim = Sim::new(TIP + 1, T0);
    let branch = sim.fork(4, run_on, 77);

    sim.chain.applied_tip(true);
    let p = sim.add_peer(Behaviour::WithholdsBelow { height: TIP }, branch.clone());
    sim.connect(p);

    sim.run(after_ms, 1_000);
    let below: Vec<Hash32> = branch
        .iter()
        .filter(|h| h.height <= TIP)
        .map(|h| h.hash)
        .collect();
    sim.chain.set_wanted_bodies(below);
    (sim, p, branch)
}

fn wedged_live(initial: usize, total: u64) -> (Sim, PeerId, Vec<HeaderRec>) {
    let mut sim = Sim::new(TIP + 1, T0);
    let branch = sim.fork(4, total, 77);
    sim.chain.applied_tip(true);
    let p = sim.add_peer(
        Behaviour::WithholdsBelow { height: TIP },
        branch[..initial.min(branch.len())].to_vec(),
    );
    sim.connect(p);
    sim.run(60_000, 1_000);
    let below: Vec<Hash32> = branch
        .iter()
        .filter(|h| h.height <= TIP)
        .map(|h| h.hash)
        .collect();
    sim.chain.set_wanted_bodies(below);
    (sim, p, branch)
}

fn run_growing(sim: &mut Sim, p: PeerId, branch: &[HeaderRec], from: usize, total_ms: u64) {
    let mut shown = from.min(branch.len());
    let mut t = 0;
    while t < total_ms {
        sim.run(5_000, 1_000);
        t += 5_000;
        if shown < branch.len() {
            shown = (shown + 2).min(branch.len());
            sim.grow_peer(p, branch[..shown].to_vec());
            sim.announce_tip(p);
        }
    }
}

fn unsolicited_body_scores(sim: &Sim, p: PeerId) -> usize {
    sim.actions
        .iter()
        .filter(|a| {
            matches!(
                a,
                plaine_p2p::sync::Action::Score {
                    peer,
                    offence: plaine_p2p::peer::Offence::UnsolicitedBody
                } if *peer == p
            )
        })
        .count()
}

#[test]
fn branch_bodies_survive_watermark() {
    let (mut sim, _p, branch) = wedged(90);
    sim.run(240_000, 1_000);

    assert!(
        sim.engine.body.applied() > TIP + FORK_BODY_MAX as u64,
        "the watermark did not run away, so nothing is being tested (applied {})",
        sim.engine.body.applied()
    );
    let below = below_our_tip(&branch);
    assert_eq!(below.len(), 4);
    for h in &below {
        assert!(
            !ChainView::have_body(&*sim.chain, &h.hash),
            "the peer served a body it was supposed to withhold, at height {}",
            h.height
        );
    }

    assert_eq!(
        sim.engine.fork_wanted_heights(),
        vec![TIP - 3, TIP - 2, TIP - 1, TIP],
        "the bodies that link the competing branch fell out of the request set \
         because the download watermark moved, not because our chain did"
    );
    for h in &below {
        assert!(
            sim.getdata_for(&h.hash) >= 2,
            "the block at height {} was named but not re-asked ({} requests)",
            h.height,
            sim.getdata_for(&h.hash)
        );
    }
}

#[test]
fn withheld_branch_adopted_on_release() {
    let (mut sim, p, branch) = wedged(90);
    sim.run(240_000, 1_000);
    assert!(
        sim.engine.body.applied() > TIP + FORK_BODY_MAX as u64,
        "the delay was not long enough to matter"
    );

    sim.set_behaviour(p, Behaviour::Honest);
    sim.run(120_000, 1_000);

    for h in below_our_tip(&branch) {
        assert!(
            ChainView::have_body(&*sim.chain, &h.hash),
            "the branch was released and the body at height {} was never fetched",
            h.height
        );
    }
    assert_eq!(
        sim.engine.fork_wanted_len(),
        0,
        "the list did not drain after every body arrived"
    );
}

#[test]
fn late_body_still_requested() {
    let (mut sim, p, branch) = wedged(40);
    sim.run(120_000, 1_000);
    let target = *below_our_tip(&branch).first().expect("a link block");
    assert!(
        sim.engine.fork_wanted_heights().contains(&target.height),
        "fixture: the link block must be wanted before it is delivered"
    );
    assert!(
        sim.engine.body.applied() > target.height + FORK_BODY_MAX as u64,
        "fixture: the watermark must have moved far past it"
    );
    let scored_before = unsolicited_body_scores(&sim, p);

    sim.engine_event(Event::Body {
        peer: p,
        hash: target.hash,
        height: target.height,
        bytes: vec![7u8; 256],
    });

    assert!(
        ChainView::have_body(&*sim.chain, &target.hash),
        "a competing-branch body we had asked for was thrown away because the \
         watermark moved between the request and the answer"
    );
    assert_eq!(
        unsolicited_body_scores(&sim, p),
        scored_before,
        "the peer that served the block we cannot recover without was punished for it"
    );
}

#[test]
fn unservable_branch_reported() {
    let (mut sim, p, branch) = wedged_live(20, 140);
    run_growing(&mut sim, p, &branch, 20, 300_000);

    assert!(
        sim.said(|c| matches!(c, Condition::BodyUnavailable { .. })),
        "nobody would serve the branch for five minutes and the node never said so"
    );

    assert!(
        sim.said(|c| matches!(c, Condition::BodyUnavailable { height } if *height <= TIP)),
        "the alarm fired for a height that is not on the competing branch"
    );

    assert!(
        sim.actions
            .iter()
            .any(|a| matches!(a, plaine_p2p::sync::Action::Dial { .. })),
        "nobody served the branch and the node never looked for another peer"
    );
}

#[test]
fn giving_up_is_temporary() {
    let (mut sim, p, branch) = wedged_live(20, 140);
    run_growing(&mut sim, p, &branch, 20, 120_000);
    let link = *below_our_tip(&branch).first().expect("a link block");
    let asked_at_giveup = sim.getdata_for(&link.hash);
    assert!(
        asked_at_giveup >= FORK_BODY_ATTEMPTS as u64,
        "fixture: the ladder must have been burned first ({asked_at_giveup} asks)"
    );
    assert!(
        sim.said(|c| matches!(c, Condition::BodyUnavailable { .. })),
        "fixture: it must have given up before resuming means anything"
    );

    run_growing(&mut sim, p, &branch, 60, 180_000);
    assert!(
        sim.getdata_for(&link.hash) > asked_at_giveup,
        "the node gave up on the competing branch permanently: {} asks before \
         the backoff, {} after",
        asked_at_giveup,
        sim.getdata_for(&link.hash)
    );
}

#[test]
fn reported_depth_is_chains() {
    let (mut sim, _p, _branch) = wedged_publishing_after(90, 240_000);
    sim.run(120_000, 1_000);

    let said: Vec<(u64, u64)> = sim
        .engine
        .conditions()
        .to_vec()
        .into_iter()
        .filter_map(|c| match c {
            Condition::ForkBodiesWanted { applied, depth, .. } => Some((applied, depth)),
            _ => None,
        })
        .collect();
    assert!(!said.is_empty(), "no fork was ever reported");

    for (applied, depth) in &said {
        assert_eq!(
            *applied, TIP,
            "the reported tip is the download watermark, not our chain's tip"
        );
        assert_eq!(*depth, 4, "a four-deep fork was reported at depth {depth}");
    }
}

#[test]
fn missing_run_cut_to_cap() {
    let mut sim = Sim::new(TIP + 1, T0);
    sim.chain.applied_tip(true);
    let p = sim.add_peer(Behaviour::HeadersOnly, Vec::new());
    sim.connect(p);

    let ours = sim.chain.headers();
    let lost: Vec<HeaderRec> = ours
        .iter()
        .filter(|h| h.height >= TIP - 59 && h.height <= TIP)
        .copied()
        .collect();
    assert_eq!(lost.len(), 60, "fixture: sixty blocks, twice the cap");
    for h in &lost {
        sim.chain.forget_body(&h.hash);
    }
    sim.chain
        .set_wanted_bodies(lost.iter().map(|h| h.hash).collect());
    sim.run(30_000, 1_000);

    let want = sim.engine.fork_wanted_heights();
    assert_eq!(
        want.len(),
        FORK_BODY_MAX,
        "sixty named bodies produced a list of {} against a cap of {}",
        want.len(),
        FORK_BODY_MAX
    );
    assert_eq!(
        want.first().copied(),
        Some(TIP - 59),
        "the cut kept the deep end and dropped the block that links the branch"
    );
    assert_eq!(
        want.last().copied(),
        Some(TIP - 59 + FORK_BODY_MAX as u64 - 1),
        "the kept range is not the lowest {FORK_BODY_MAX}"
    );
}

#[test]
fn unavailable_alarm_cadence() {
    let (mut sim, p, branch) = wedged_live(20, 200);
    run_growing(&mut sim, p, &branch, 20, 360_000);

    let n = sim
        .engine
        .conditions()
        .iter()
        .filter(|c| matches!(c, Condition::BodyUnavailable { height } if *height == TIP))
        .count();
    let ticks = 360;
    let expected = 360_000 / BODY_UNAVAILABLE_RETRY_MS as usize;
    assert!(
        n >= 2,
        "the alarm for height {TIP} was raised {n} times in six minutes - it does not repeat"
    );
    assert!(
        n <= expected + 2,
        "the alarm for height {TIP} was raised {n} times in {ticks} ticks; at a \
         {BODY_UNAVAILABLE_RETRY_MS} ms cadence it should be about {expected}"
    );
}
