use plaine_p2p::constants::*;
use plaine_p2p::gate::Budgets;
use plaine_p2p::metrics::Metrics;
use plaine_p2p::mock::{build_chain, Behaviour, Sim};
use plaine_p2p::sync::body_track::{BodyAction, BodyTrack, Supplier};
use plaine_p2p::sync::header_track::HState;
use plaine_p2p::sync::{Action, Event};
use plaine_p2p::traits::*;
use plaine_p2p::wire::Msg;

const T0: u64 = 1_800_000_000;

fn hash_n(n: u64) -> Hash32 {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    h[8] = 0xAB;
    h
}

fn inbound(sim: &mut Sim, n: u64, height: u64) -> PeerId {
    let id = PeerId(50_000 + n);
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12] = 172;
    ip[13] = (n >> 8) as u8;
    ip[14] = n as u8;
    sim.engine_event(Event::PeerReady {
        peer: id,
        ip,
        outbound: false,
        height,
        work: [0u8; 32],
        tip: [0u8; 32],
        services: SERVICE_FULL_RELAY,
    });
    id
}

fn getheaders_to(sim: &Sim, peer: PeerId) -> usize {
    sim.actions
        .iter()
        .filter(|a| {
            matches!(a,
                Action::Send { peer: p, msg: Msg::GetHeaders { .. } } if *p == peer)
        })
        .count()
}

fn scores_for(sim: &Sim, peer: PeerId) -> usize {
    sim.actions
        .iter()
        .filter(|a| matches!(a, Action::Score { peer: p, .. } if *p == peer))
        .count()
}

#[test]
fn announcement_teaches_empty_node() {
    let mut sim = Sim::new(1, T0);
    let peer = sim.add_peer(Behaviour::Honest, Vec::new());

    sim.chain.applied_tip(true);
    sim.connect(peer);
    sim.run(10_000, 1_000);
    assert_eq!(
        sim.engine.peers()[&peer].claimed_height,
        0,
        "the fixture is wrong: the peer must be recorded as empty; that is the \
         premise"
    );

    let chain = sim.extension(500);
    let their_tip = chain.last().expect("chain").hash;
    sim.grow_peer(peer, chain);
    sim.run(60_000, 1_000);
    assert_eq!(
        sim.chain.tip().height,
        0,
        "a peer's chain is invisible until something announces it - if this \
         fails the fixture is no longer reproducing the bug"
    );

    sim.announce(peer, vec![their_tip]);
    sim.run(300_000, 1_000);

    assert_eq!(
        sim.chain.tip().height,
        500,
        "the node never converged. One INV must be enough to make it ask: \
         INV -> GETHEADERS -> HEADERS -> verify -> claim -> designate -> sync"
    );
    assert!(
        getheaders_to(&sim, peer) > 0,
        "the node never asked. This is the exact wire signature the frame \
         logger caught on the WAN boxes: GETHEADERS 0 per edge"
    );
}

#[test]
fn without_announcement_no_propagation() {
    let mut sim = Sim::new(1, T0);
    let peer = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(peer);
    sim.run(10_000, 1_000);

    let chain = sim.extension(500);
    sim.grow_peer(peer, chain);
    sim.run(360_000, 1_000);

    assert_eq!(
        sim.chain.tip().height,
        0,
        "the node converged without any announcement, so the headline test is \
         not measuring the announcement path"
    );
    assert_eq!(
        getheaders_to(&sim, peer),
        0,
        "the node asked for headers from a peer it believes is empty; the right \
         behaviour is to decline, and the fix is the announcement, not a \
         relaxation of that rule"
    );
}

#[test]
fn inv_does_not_raise_claim() {
    let mut sim = Sim::new(1, T0);
    let liar = inbound(&mut sim, 1, 0);
    let state_before = sim.engine.header.state();

    for i in 0..4_096u64 {
        sim.announce(liar, vec![hash_n(i)]);
    }

    assert_eq!(
        sim.engine.header.best_claimed_height(),
        0,
        "4,096 announced hashes moved best_claimed_height. An INV must not be \
         able to flip `in_ibd`, pick a deep-recovery branch, or make `behind` \
         true"
    );
    assert_eq!(
        sim.engine
            .header
            .best_actionable_height(sim.engine.peers(), sim.now()),
        0,
        "4,096 announced hashes moved best_actionable_height"
    );
    assert_eq!(
        sim.engine.peers()[&liar].claimed_height,
        0,
        "an announced hash was treated as a height. A hash is not a height"
    );
    assert_eq!(
        sim.actions
            .iter()
            .filter(|a| matches!(a, Action::Designate { .. }))
            .count(),
        0,
        "an announcement burned a designation"
    );
    assert_eq!(
        sim.engine.header.state(),
        state_before,
        "an announcement moved the header state machine"
    );
    assert_eq!(sim.engine.wanted_len(), 0, "an announced hash entered `wanted`");
}

#[test]
fn mass_announcements_cost_no_interpreter() {
    let mut sim = Sim::with_pow_cost(1, T0, 3);
    let flood = inbound(&mut sim, 1, 0);
    let calls_before = sim.pow.calls();
    let wanted_before = sim.engine.wanted_len();

    let mut n = 0u64;
    for round in 0..40_000u64 {
        let width = match round % 3 {
            0 => 1,
            1 => INV_BLOCKS_PER_MSG_MAX,
            _ => 64,
        };
        let batch: Vec<Hash32> = (0..width)
            .map(|_| {
                n += 1;
                hash_n(n)
            })
            .collect();
        sim.announce(flood, batch);
    }
    assert!(n >= 1_000_000 / 4, "the flood must actually be large");

    assert_eq!(
        sim.pow.calls(),
        calls_before,
        "an announcement reached the interpreter. {} hashes bought {} \
         interpreter calls; the correct number is zero, because no path from \
         Event::Announced reaches pow.verify at all",
        n,
        sim.pow.calls() - calls_before
    );
    assert_eq!(
        sim.engine.wanted_len(),
        wanted_before,
        "an announced hash became a body request. An attacker who can inject \
         arbitrary hashes into the download window gets GETDATA + NOTFOUND + \
         burned BODY_ATTEMPTS + BodyUnavailable - the fan-out bug, rebuilt \
         deliberately and handed to an unauthenticated peer"
    );
}

#[test]
fn unknown_hash_costs_announcer() {
    let mut sim = Sim::with_pow_cost(1, T0, 3);
    let liar = inbound(&mut sim, 1, 0);
    let calls_before = sim.pow.calls();

    let mut n = 0u64;
    for _ in 0..60 {
        for _ in 0..20 {
            n += 1;
            sim.announce(liar, vec![hash_n(n)]);
        }
        sim.step(1_000);
    }

    let probes = getheaders_to(&sim, liar);
    let ceiling = (60_000 / INV_PROBE_INTERVAL_MS) as usize + 1;
    assert!(
        probes <= ceiling,
        "{} novel announced hashes over 60 s bought {} GETHEADERS; the per-peer \
         gate allows at most {} (one per INV_PROBE_INTERVAL_MS = {} ms)",
        n,
        probes,
        ceiling,
        INV_PROBE_INTERVAL_MS
    );
    assert_eq!(sim.pow.calls(), calls_before, "a lie reached the interpreter");
    assert_eq!(
        sim.engine.header.best_claimed_height(),
        0,
        "a hash that does not exist raised a claim"
    );
    assert_eq!(
        sim.engine.header.state(),
        HState::Tracking,
        "an unanswered probe moved the state machine, so it is wired to a \
         liveness clock after all"
    );
}

#[test]
fn announced_claim_still_retired() {
    let mut sim = Sim::new(1, T0);
    let ext = sim.extension(8);

    sim.chain.applied_tip(true);
    let peer = sim.add_peer(Behaviour::Silent, Vec::new());
    sim.connect(peer);

    sim.announce(peer, vec![ext.last().expect("ext").hash]);
    sim.engine_event(Event::Headers {
        peer,
        raw: ext.iter().map(|h| h.raw).collect(),
    });
    assert_eq!(
        sim.engine.header.best_claimed_height(),
        8,
        "a PoW-verified announced header must raise the claim - otherwise the \
         peer can never be designated and the propagation fix does nothing"
    );

    sim.run(20 * 60_000, 1_000);
    assert!(
        sim.engine.header.claim_demoted(peer),
        "a claim bought by an announcement outlived the retirement rule; that \
         is the unfulfillable-claim livelock again"
    );
}

#[test]
fn many_announcers_one_probe() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(1);
    let fresh = chain.last().expect("chain").hash;

    let peers: Vec<PeerId> = (0..100).map(|i| inbound(&mut sim, i, 0)).collect();
    let probes_before = Metrics::get(&sim.engine.metrics.inv_probes);
    for p in &peers {
        sim.announce(*p, vec![fresh]);
    }
    let probes = Metrics::get(&sim.engine.metrics.inv_probes) - probes_before;

    assert_eq!(
        probes, 1,
        "100 peers announcing one new block cost {} probes; the other \
         ninety-nine are the same question",
        probes
    );
    assert_eq!(
        sim.actions
            .iter()
            .filter(|a| matches!(a, Action::Send { msg: Msg::GetHeaders { .. }, .. }))
            .count(),
        1,
        "the probe count and the frames actually emitted disagree"
    );
}

#[test]
fn probe_set_delays_not_suppresses() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(1);
    let fresh = chain.last().expect("chain").hash;

    let squatter = inbound(&mut sim, 1, 0);
    let honest = inbound(&mut sim, 2, 0);
    sim.announce(squatter, vec![fresh]);
    sim.announce(honest, vec![fresh]);
    assert_eq!(
        getheaders_to(&sim, honest),
        0,
        "the suppressor is not suppressing inside its window"
    );

    sim.step(INV_PROBE_INFLIGHT_TTL_MS + TICK_MS);
    sim.announce(honest, vec![fresh]);
    assert_eq!(
        getheaders_to(&sim, honest),
        1,
        "a peer that squatted the outstanding-probe slot suppressed a real block \
         permanently. INV_PROBE_INFLIGHT_TTL_MS = {} ms must bound the delay",
        INV_PROBE_INFLIGHT_TTL_MS
    );
}

#[test]
fn inv_probes_are_rate_limited_per_peer() {
    let mut sim = Sim::new(1, T0);
    let p = inbound(&mut sim, 1, 0);
    for i in 0..1_000u64 {
        sim.announce(p, vec![hash_n(i)]);
    }
    assert_eq!(
        getheaders_to(&sim, p),
        1,
        "1,000 announcements in one tick bought {} probes; the per-peer gate \
         allows one",
        getheaders_to(&sim, p)
    );
}

#[test]
fn unknown_parent_shares_probe_gate() {
    let mut sim = Sim::new(1, T0);
    let p = inbound(&mut sim, 1, 0);
    let orphan = build_chain(5_000, 1, hash_n(999), T0, 77);

    for _ in 0..200 {
        sim.engine_event(Event::Headers {
            peer: p,
            raw: vec![orphan[0].raw],
        });
    }
    assert_eq!(
        getheaders_to(&sim, p),
        1,
        "200 orphan headers emitted {} GETHEADERS. The emitted count must be \
         bounded by INV_PROBE_INTERVAL_MS, not by the header count",
        getheaders_to(&sim, p)
    );
}

#[test]
fn solicited_answer_admits_eight() {
    let mut sim = Sim::with_pow_cost(1, T0, 0);
    let ext = sim.extension(2_000);
    let p = inbound(&mut sim, 1, 0);

    sim.announce(p, vec![ext.last().expect("ext").hash]);
    let calls_before = sim.pow.calls();
    let scored_before = scores_for(&sim, p);
    sim.engine_event(Event::Headers {
        peer: p,
        raw: ext.iter().map(|h| h.raw).collect(),
    });

    assert_eq!(
        scores_for(&sim, p) - scored_before,
        0,
        "an honest peer was scored for answering exactly what we asked for"
    );
    assert_eq!(
        sim.pow.calls() - calls_before,
        INV_HEADERS_ADMIT_MAX as u64,
        "a solicited 2,000-header answer bought {} interpreter calls. \
         solicitation removes the penalty; it must never raise the work above \
         INV_HEADERS_ADMIT_MAX = {}",
        sim.pow.calls() - calls_before,
        INV_HEADERS_ADMIT_MAX
    );
    assert_eq!(
        sim.engine.header.staging.staged_len(),
        0,
        "a non-designated peer's solicited answer reached staging. Only the \
         designated stream may stage - that is the W3 hole"
    );
    assert_eq!(
        sim.engine.header.best_claimed_height(),
        INV_HEADERS_ADMIT_MAX as u64,
        "the claim must rise to exactly the eighth header's height: the headers \
         that passed the interpreter, and not one more"
    );
}

#[test]
fn second_solicited_frame_scored() {
    let mut sim = Sim::with_pow_cost(1, T0, 0);
    let ext = sim.extension(2_000);
    let p = inbound(&mut sim, 1, 0);
    sim.announce(p, vec![ext.last().expect("ext").hash]);

    let raw: Vec<[u8; HEADER_BYTES]> = ext.iter().map(|h| h.raw).collect();
    sim.engine_event(Event::Headers {
        peer: p,
        raw: raw.clone(),
    });
    let scored_after_first = scores_for(&sim, p);
    sim.engine_event(Event::Headers { peer: p, raw });

    assert!(
        scores_for(&sim, p) > scored_after_first,
        "the solicited window survived past one message, so a peer can hold a \
         penalty exemption open by probing us once"
    );
}

#[test]
fn forged_probe_answer_bans() {
    let mut sim = Sim::new(1, T0);
    let ext = sim.extension(8);
    sim.pow.poison_all(&ext);
    let p = inbound(&mut sim, 1, 0);

    sim.announce(p, vec![ext.last().expect("ext").hash]);
    sim.engine_event(Event::Headers {
        peer: p,
        raw: ext.iter().map(|h| h.raw).collect(),
    });

    assert!(
        sim.engine.peers().get(&p).is_none(),
        "a forger that answered our own probe was not banned"
    );
    assert!(
        sim.engine.reject_cache().contains(&ext[0].hash),
        "the forged hash did not enter the global reject cache, so the eighth \
         peer offering it is not free"
    );
    assert_eq!(
        sim.engine.header.best_claimed_height(),
        0,
        "a forged header raised a claim before the interpreter judged it"
    );
}

#[test]
fn announcement_pays_pow_budget() {
    let cost = POW_BUDGET_BURST_MS / 3;
    let mut sim = Sim::with_pow_cost(1, T0, cost);
    let ext = sim.extension(INV_HEADERS_ADMIT_MAX as u64);
    let raw: Vec<[u8; HEADER_BYTES]> = ext.iter().map(|h| h.raw).collect();

    let probed = inbound(&mut sim, 1, 0);
    sim.announce(probed, vec![ext.last().expect("ext").hash]);
    let before = sim.pow.calls();
    sim.engine_event(Event::Headers {
        peer: probed,
        raw: raw.clone(),
    });
    let via_probe = sim.pow.calls() - before;

    let mut sim2 = Sim::with_pow_cost(1, T0, cost);
    let ext2 = sim2.extension(INV_HEADERS_ADMIT_MAX as u64);
    let plain = inbound(&mut sim2, 2, 0);
    let before2 = sim2.pow.calls();
    sim2.engine_event(Event::Headers {
        peer: plain,
        raw: ext2.iter().map(|h| h.raw).collect(),
    });
    let unsolicited = sim2.pow.calls() - before2;

    assert_eq!(
        via_probe, 3,
        "the per-peer interpreter budget did not bind on the probe's answer: \
         burst {} ms at {} ms/call admits exactly 3, and {} were made",
        POW_BUDGET_BURST_MS, cost, via_probe
    );
    assert_eq!(
        via_probe, unsolicited,
        "an INV-induced answer bought {} interpreter calls where an unsolicited \
         one bought {}. The probe must not be a cheaper route to the \
         interpreter than the door that already existed",
        via_probe, unsolicited
    );
}

#[test]
fn unjudged_headers_raise_no_claim() {
    let cost = POW_BUDGET_BURST_MS + 1;
    let mut sim = Sim::with_pow_cost(1, T0, cost);
    let ext = sim.extension(INV_HEADERS_ADMIT_MAX as u64);
    let p = inbound(&mut sim, 1, 0);

    sim.announce(p, vec![ext.last().expect("ext").hash]);
    let before = sim.pow.calls();
    sim.engine_event(Event::Headers {
        peer: p,
        raw: ext.iter().map(|h| h.raw).collect(),
    });

    assert_eq!(
        sim.pow.calls(),
        before,
        "the per-peer budget did not refuse a {} ms call against a {} ms burst",
        cost,
        POW_BUDGET_BURST_MS
    );
    assert!(
        sim.engine.peers().contains_key(&p),
        "the fixture banned the peer, which would mask the assertion below \
         exactly as the forged-header case does"
    );
    assert_eq!(
        sim.engine.header.best_claimed_height(),
        0,
        "eight headers the interpreter never ran on raised this peer's \
         claim to {}. A claim must rise only on evidence that cost real \
         hashing; G2 alone is free to fabricate",
        sim.engine.header.best_claimed_height()
    );
    assert_eq!(
        sim.engine.peers()[&p].claimed_height,
        0,
        "the same, on the session's body-supplier horizon"
    );
}

#[test]
fn announcement_spares_ibd_reserve() {
    let now = Mono(0);
    let mut b = Budgets::new(now);
    let mut spent = 0u64;
    while b.admit_pow_announced(HEADER_VERIFY_US_MAX / 1_000, now) {
        spent += HEADER_VERIFY_US_MAX / 1_000;
        assert!(spent < POW_POOL_MS_PER_SEC * 10, "the floor never bound");
    }
    assert!(
        b.pow_level(now) >= POW_ANNOUNCE_RESERVE_MS,
        "announcements drew the interpreter pool down to {} ms, below the {} \
         ms/s our own IBD needs at the rate floor we enforce on our sync peer",
        b.pow_level(now),
        POW_ANNOUNCE_RESERVE_MS
    );
    assert!(
        b.admit_pow(HEADER_VERIFY_US_MAX / 1_000, now),
        "our own verify_pass was starved by the announcement path. The floor is \
         for us, not for them"
    );
}

#[test]
fn duplicate_announcements_scored() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(50);
    sim.chain.extend(&chain, true);
    let spammer = inbound(&mut sim, 1, 0);
    let held = chain[0].hash;

    let target = DUP_INV_FREE + DUP_INV_PER_POINT * BAN_SCORE;
    for _ in 0..target {
        sim.announce(spammer, vec![held]);
    }

    assert!(
        sim.engine.peers().get(&spammer).is_none(),
        "{} announcements of a hash we already hold did not reach BAN_SCORE. \
         9 owes 1 point per {} duplicates beyond the first {}",
        target,
        DUP_INV_PER_POINT,
        DUP_INV_FREE
    );
    assert_eq!(
        getheaders_to(&sim, spammer),
        0,
        "an announcement of a hash we already hold emitted a GETHEADERS"
    );
}

#[test]
fn announced_deep_fork_no_recovery() {
    let mut sim = Sim::new(1, T0);
    let local = sim.extension(MAX_REORG_DEPTH + 50);
    sim.chain.extend(&local, true);
    sim.pin_tip_time_to_now();

    let state_before = sim.engine.header.state();
    for i in 0..(RECOVERY_FLAP_LIMIT as u64 + 2) {
        let deep = sim.fork(MAX_REORG_DEPTH + 20, 8, 0xD1 + i);
        let p = inbound(&mut sim, 100 + i, 0);
        sim.engine_event(Event::Headers {
            peer: p,
            raw: deep.iter().map(|h| h.raw).collect(),
        });
    }

    assert_ne!(
        sim.engine.header.state(),
        HState::DeepRecovery,
        "an announced deep fork put the node into DeepRecovery. An announcement \
         may only cause a question, nothing more"
    );
    assert_ne!(
        sim.engine.header.state(),
        HState::Quarantined,
        "{} announced deep forks quarantined the node, at zero points to the \
         senders - the anti-DoS machinery turned into the DoS",
        RECOVERY_FLAP_LIMIT + 2
    );
    assert_eq!(
        Metrics::get(&sim.engine.metrics.deep_recoveries),
        0,
        "a non-designated peer's header entered deep recovery"
    );
    assert_eq!(
        sim.engine.header.state(),
        state_before,
        "an announced deep fork moved the header state machine at all"
    );
}

#[test]
fn oversize_frame_charged_first() {
    let mut sim = Sim::with_pow_cost(1, T0, 0);
    let ext = sim.extension(MAX_HEADERS_PER_MSG as u64);
    let raw: Vec<[u8; HEADER_BYTES]> = ext.iter().map(|h| h.raw).collect();
    let full = (MAX_HEADERS_PER_MSG * HEADER_BYTES) as u64;

    let rude = inbound(&mut sim, 1, 0);
    let before = Metrics::get(&sim.engine.metrics.bytes_in);
    sim.engine_event(Event::Headers {
        peer: rude,
        raw: raw.clone(),
    });
    assert_eq!(
        Metrics::get(&sim.engine.metrics.bytes_in) - before,
        full,
        "an oversize unsolicited frame was refused without being charged for \
         the bytes it made us read"
    );

    let polite = inbound(&mut sim, 2, 0);
    sim.announce(polite, vec![ext.last().expect("ext").hash]);
    let before = Metrics::get(&sim.engine.metrics.bytes_in);
    sim.engine_event(Event::Headers { peer: polite, raw });
    assert_eq!(
        Metrics::get(&sim.engine.metrics.bytes_in) - before,
        full,
        "oversize frame charged for {} truncated bytes, not the {} it cost; the waiver drops the score, not the accounting",
        INV_HEADERS_ADMIT_MAX * HEADER_BYTES,
        full
    );
}

#[test]
fn announce_tip_as_level() {
    let mut sim = Sim::new(1, T0);
    sim.pin_tip_time_to_now();
    let a = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(a);
    sim.run(10_000, 1_000);

    let after_first = sim.inv_seen(a);
    assert!(
        after_first <= 1 + INV_REPEATS as u64,
        "our tip changed once and we sent {after_first} INV frames, past the repeat budget: this is a backlog"
    );

    let _ = after_first;

    sim.run(30_000, 1_000);
    let settled = sim.inv_seen(a);
    assert!(
        settled <= 1 + INV_REPEATS as u64,
        "{settled} INV frames for one tip change: the bound is a constant, not a rate"
    );

    sim.run(30_000, 1_000);
    assert_eq!(
        sim.inv_seen(a),
        settled,
        "unchanged tip still announced after the repeat budget was spent"
    );
}

#[test]
fn no_announce_back_to_source() {
    let mut sim = Sim::new(1, T0);
    sim.pin_tip_time_to_now();
    let a = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(a);
    sim.run(10_000, 1_000);
    let baseline = sim.inv_seen(a);

    let next = sim.extension(1);
    sim.chain.extend(&next, true);
    sim.announce(a, vec![next[0].hash]);
    sim.run(10_000, 1_000);

    assert_eq!(
        sim.inv_seen(a),
        baseline,
        "we echoed a block straight back to the peer that told us about it"
    );
}

#[test]
fn absurd_height_cannot_mute_announce() {
    fn frames(with_liar: bool) -> u64 {
        let mut sim = Sim::new(1, T0);
        sim.pin_tip_time_to_now();
        let a = sim.add_peer(Behaviour::Honest, Vec::new());
        sim.connect(a);
        if with_liar {
            inbound(&mut sim, 7, 1u64 << 40);
        }
        sim.run(10_000, 1_000);
        for _ in 0..3 {
            let next = sim.extension(1);
            sim.chain.extend(&next, true);
            sim.run(2_000, 1_000);
        }
        sim.inv_seen(a)
    }
    let quiet = frames(false);
    assert!(quiet > 0, "the fixture never announced anything at all");
    assert_eq!(
        frames(true),
        quiet,
        "one peer claiming height 2^40 changed how many blocks we announce. A \
         forgeable number must never gate our egress"
    );
}

#[test]
fn no_body_request_without_claim() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(200);
    for _ in 0..3 {
        let id = sim.add_peer(Behaviour::Honest, chain.clone());
        sim.connect(id);
    }
    let poor = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(poor);

    sim.run(180_000, 1_000);

    assert_eq!(
        sim.chain.tip().height,
        200,
        "the fixture did not converge, so the counters below mean nothing"
    );
    assert_eq!(
        sim.getdata_seen(poor),
        0,
        "{} GETDATA went to a peer that claims height 0 while three peers \
         claimed 200. The measured before-figure was 4,134",
        sim.getdata_seen(poor)
    );
    assert_eq!(
        sim.notfound_sent(poor),
        0,
        "{} NOTFOUND came back from a peer we should never have asked. The \
         measured before-figure was 6,286",
        sim.notfound_sent(poor)
    );
}

#[test]
fn supplier_chosen_by_horizon() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(200);

    let poor: Vec<PeerId> = (0..10)
        .map(|_| {
            let id = sim.add_peer(Behaviour::Honest, Vec::new());
            sim.connect(id);
            id
        })
        .collect();

    for _ in 0..3 {
        let id = sim.add_peer(Behaviour::Honest, chain.clone());
        sim.connect(id);
    }

    sim.run(180_000, 1_000);
    assert_eq!(
        sim.chain.tip().height,
        200,
        "the fixture did not converge, so the counters below mean nothing"
    );
    let wasted: u64 = poor.iter().map(|p| sim.getdata_seen(*p)).sum();
    assert_eq!(
        wasted, 0,
        "{} GETDATA went to the ten lowest-id peers, all of which claim height \
         0, while three peers claimed 200. The supplier set must be ranked by \
         horizon, not by whatever order the map iterates in",
        wasted
    );
}

#[test]
fn known_hash_raises_body_horizon() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(50);
    let source = sim.add_peer(Behaviour::Honest, chain.clone());
    sim.connect(source);
    sim.run(120_000, 1_000);
    assert_eq!(sim.chain.tip().height, 50, "the fixture did not sync");
    assert!(sim.engine.known_len() > 0, "the fixture never populated `known`");
    let held = chain[40];

    let via_inv = inbound(&mut sim, 1, 0);
    sim.announce(via_inv, vec![held.hash]);
    assert_eq!(
        sim.engine.peers()[&via_inv].claimed_height,
        held.height,
        "an INV naming a block we already hold left the announcer's horizon at \
         0, so it stays last in the body queue forever despite demonstrably \
         being at height {}",
        held.height
    );

    let via_headers = inbound(&mut sim, 2, 0);
    sim.engine_event(Event::Headers {
        peer: via_headers,
        raw: vec![held.raw],
    });
    assert_eq!(
        sim.engine.peers()[&via_headers].claimed_height,
        held.height,
        "a header we already hold left the sender's horizon at 0. G0 `continue`s \
         before `admit_announced`, so this arm has to raise it or nothing does"
    );

    let deep = sim.extension(1);
    sim.chain.extend(&deep, true);
    assert!(
        sim.engine.known_len() > 0 && !sim.engine.reject_cache().contains(&deep[0].hash),
        "fixture check"
    );
    let via_seam = inbound(&mut sim, 3, 0);
    sim.announce(via_seam, vec![deep[0].hash]);
    assert_eq!(
        sim.engine.peers()[&via_seam].claimed_height,
        deep[0].height,
        "an INV naming a block that is in our chain but not in the in-memory \
         `known` memo left the announcer's horizon at 0. The seam lookup that \
         already decides novelty must raise it too, or every block older than \
         the memo is invisible for this purpose"
    );

    assert!(
        sim.engine.header.best_claimed_height() <= sim.chain.tip().height,
        "a free horizon raise leaked into the claim overlay, where it could move \
         `behind`, `in_ibd` and designation"
    );
}

#[test]
fn late_peer_still_told_tip() {
    let mut sim = Sim::new(1, T0);
    sim.pin_tip_time_to_now();
    let early = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(early);
    sim.run(5_000, 1_000);
    assert_eq!(sim.inv_seen(early), 1, "the fixture never announced at all");

    let late = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(late);
    sim.run(5_000, 1_000);

    assert!(
        sim.inv_seen(late) >= 1,
        "a peer that connected after our last block was never told our tip"
    );

    assert!(
        sim.inv_seen(early) <= 1 + INV_REPEATS as u64,
        "the early peer was told {} times: a new session re-armed an existing one",
        sim.inv_seen(early)
    );
}

#[test]
fn silent_peer_asked_as_last_resort() {
    let wanted: Vec<(u64, Hash32)> = (1..=100).map(|h| (h, hash_n(h))).collect();

    let run = |horizon: u64| -> Vec<BodyAction> {
        let mut bt = BodyTrack::new(0);
        let sup = [Supplier {
            id: PeerId(1),
            horizon,
        }];
        bt.schedule(&wanted, &sup, Mono(0))
    };

    let silent = run(0);
    let claiming = run(u64::MAX);
    assert!(
        !silent.is_empty(),
        "a single peer that claims nothing was asked for nothing. That is a \
         self-inflicted body-download stop with no deadline behind it"
    );
    assert_eq!(
        silent, claiming,
        "supplier at horizon 0 differed from a claim-all one; the no-claimant fallback must match the old behaviour"
    );
}

#[test]
fn delivered_body_raises_horizon() {
    let mut sim = Sim::new(1, T0);
    let p = inbound(&mut sim, 1, 0);
    assert_eq!(sim.engine.peers()[&p].claimed_height, 0);

    sim.engine_event(Event::Body {
        peer: p,
        hash: hash_n(4_242),
        height: 7,
        bytes: vec![0u8; 128],
    });
    assert_eq!(
        sim.engine.peers()[&p].claimed_height,
        7,
        "a body this peer actually handed us did not raise its horizon, so a \
         peer silent about its height stays last in the queue forever"
    );
}

#[test]
fn three_notfounds_drop_supplier() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(10);
    let p = sim.add_peer(Behaviour::HeadersOnly, chain.clone());
    sim.connect(p);

    let sup = [Supplier {
        id: p,
        horizon: 10,
    }];
    let wanted: Vec<(u64, Hash32)> = chain.iter().take(3).map(|h| (h.height, h.hash)).collect();
    let _ = sim.engine.body.schedule(&wanted, &sup, sim.now());
    for (_, h) in &wanted {
        sim.engine_event(Event::NotFound { peer: p, hash: *h });
    }

    let s = &sim.engine.peers()[&p];
    assert!(
        s.body_slot_lost_until.is_some(),
        "three refusals did not cost the supplier its slot; before this, `tick` \
         cleared `refused` and skipped DeadlineMiss, so a peer that refused \
         everything was round-robined forever"
    );
    assert_eq!(
        s.score.value(sim.now()),
        0,
        "an honest archive-less peer was scored {} points for answering \
         truthfully. Denying it the role is answer enough",
        s.score.value(sim.now())
    );
}

#[test]
fn notfound_isolated_per_peer() {

    let mut sim = Sim::new(1, T0);

    sim.run(30_000, 1_000);
    let chain = sim.extension(10);

    let a = sim.add_peer(Behaviour::Honest, Vec::new());
    sim.connect(a);
    sim.grow_peer(a, chain.clone());
    let b = inbound(&mut sim, 9, 0);

    let sup = [Supplier { id: a, horizon: 10 }];
    let target = (chain[0].height, chain[0].hash);
    let _ = sim.engine.body.schedule(&[target], &sup, sim.now());
    let issued = sim.engine.body.requests_issued;

    sim.engine_event(Event::NotFound {
        peer: b,
        hash: target.1,
    });

    sim.step(TICK_MS);

    assert_eq!(
        sim.engine.peers()[&a].body_misses,
        0,
        "peer B's NOTFOUND moved peer A's miss counter, so B can cost A its \
         supplier slot on demand"
    );
    assert!(
        sim.engine.body.is_inflight(&target.1),
        "peer B's NOTFOUND cancelled a request in flight to peer A"
    );
    assert_eq!(
        sim.engine.body.requests_issued, issued,
        "peer B's NOTFOUND expired peer A's deadline and re-asked a hash still in flight; repeated, that starves the body into BodyUnavailable"
    );
    assert!(
        !sim.engine.body.starved_hashes().contains(&target.1),
        "peer B's word starved a hash that peer A is still fetching"
    );
    assert_eq!(
        sim.engine.peers()[&b].score.value(sim.now()),
        0,
        "an unsolicited NOTFOUND was scored. It is noise, not misbehaviour \
         anyone can prove"
    );
}
