use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::*;
use plaine_p2p::mock::{build_chain, Behaviour, MockBits, MockPow, Sim};
use plaine_p2p::sync::header_track::HState;
use plaine_p2p::sync::{Action, Event, SyncEngine};
use plaine_p2p::traits::*;
use plaine_p2p::wire::Msg;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const T0: u64 = 1_800_000_000;

fn rotations_of(sim: &Sim, peer: PeerId) -> Vec<RotationKind> {
    sim.engine
        .conditions()
        .iter()
        .filter_map(|c| match c {
            Condition::SyncRotation { peer: p, kind } if *p == peer => Some(*kind),
            _ => None,
        })
        .collect()
}

#[test]
fn stalled_peer_rotated() {
    let mut sim = Sim::new(1, T0);
    sim.pin_tip_time_to_now();
    let chain = sim.extension(15);
    let stuck = sim.add_peer(Behaviour::RepeatsFirstBatch { n: 5 }, chain.clone());
    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(stuck);
    sim.connect(honest);

    sim.run(4_000, 1_000);
    assert_eq!(
        sim.sync_peer(),
        Some(stuck),
        "test precondition: the stuck peer must be designated first"
    );

    let mut answered_at = 0u64;
    let mut rotated_at = 0u64;
    for t in 4..(4 + STALL_TIMEOUT_MS / 1_000 + 4) {
        sim.step(1_000);
        if sim.getheaders_seen(stuck) > 0 && answered_at == 0 && sim.engine.verified_height() > 0 {
            answered_at = t;
        }
        if rotated_at == 0 && !rotations_of(&sim, stuck).is_empty() {
            rotated_at = t;
        }
    }

    let kinds = rotations_of(&sim, stuck);
    assert_eq!(
        kinds.first(),
        Some(&RotationKind::NoProgress),
        "the stuck peer was rotated by {:?}, not by the progress deadline - a \
         test that asserts only on the Undesignate cannot tell STALL_TIMEOUT \
         from LOCATE_TIMEOUT or the rate floor, and that is the whole point of \
         the undefended-mechanism audit",
        kinds
    );
    let _ = answered_at;
    assert!(
        rotated_at * 1_000 >= STALL_TIMEOUT_MS
            && rotated_at * 1_000 <= STALL_TIMEOUT_MS + 4_000,
        "the rotation landed at t={}s: the {}s progress deadline is the only \
         one that can produce that timing, and anything below it would mean \
         LOCATE_TIMEOUT acted instead",
        rotated_at,
        STALL_TIMEOUT_MS / 1_000
    );
    assert!(
        sim.engine
            .peers()
            .get(&stuck)
            .map(|s| s.score.value(sim.now()) > 0)
            .unwrap_or(false),
        "a peer that answered without progressing was not charged a DeadlineMiss"
    );
    assert!(
        sim.engine.metrics.snapshot().rotations_charged > 0,
        "a NoProgress rotation must spend the rotation budget - that is what \
         separates it from the zero-point local kinds"
    );

    sim.run(60_000, 1_000);
    assert_eq!(
        sim.engine.verified_height(),
        15,
        "sync did not complete from the honest peer after the stall rotation"
    );
}

#[test]
fn rotation_keeps_staged_backlog() {
    let mut sim = Sim::with_pow_cost(1, T0, POW_POOL_MS_PER_SEC + 1_000);
    let chain = sim.extension(20_000);
    for _ in 0..4 {
        let p = sim.add_peer(Behaviour::Honest, chain.clone());
        sim.connect(p);
    }

    let mut last = 0u64;
    let mut rotations = 0usize;
    let mut locator_heads: Vec<Hash32> = Vec::new();
    for _ in 0..120 {
        let before = sim.engine.conditions().len();
        let n = sim.actions.len();
        sim.step(1_000);
        rotations += sim.engine.conditions()[before..]
            .iter()
            .filter(|c| matches!(c, Condition::SyncRotation { .. }))
            .count();
        if rotations > 0 {
            locator_heads.extend(sim.actions[n..].iter().filter_map(|a| match a {
                Action::Send {
                    msg: Msg::GetHeaders { locator, .. },
                    ..
                } => locator.first().copied(),
                _ => None,
            }));
        }

        let staged = sim.engine.header.staging.staged_len();
        assert!(
            staged >= last,
            "staging fell from {} to {} headers: rotation is only cheap enough \
             to be the default answer to every header problem because it keeps \
             the backlog, and that is what a discard-on-conflict design did not have",
            last,
            staged
        );
        last = staged;
    }

    assert_eq!(sim.engine.verified_height(), 0, "test precondition");
    assert!(
        rotations >= 2,
        "test precondition: the peer set must actually rotate, got {}",
        rotations
    );
    assert!(
        last > 2 * PROBE_GRANT_HEADERS,
        "test precondition: the backlog must outlast a single probationary \
         grant, got {}",
        last
    );

    let chain_tip = sim.chain.tip().hash;
    assert!(
        !locator_heads.is_empty(),
        "no GETHEADERS was issued after a rotation"
    );
    assert!(
        locator_heads.iter().all(|h| *h != chain_tip),
        "a replacement designee was asked to resume from the chain tip while a \
         {}-header backlog was staged above it",
        last
    );

    assert!(
        sim.headers_served_total() <= last + MAX_HEADERS_PER_MSG as u64,
        "{} headers were served for a {}-header backlog that was never \
         committed and never rejected - the difference is re-download",
        sim.headers_served_total(),
        last
    );
}

#[test]
fn rejected_branch_no_interpreter() {
    let mut sim = Sim::new(1, T0);
    let forged = sim.extension(50);
    let mut liars = Vec::new();
    for _ in 0..8 {
        liars.push(sim.add_liar(forged.clone(), 5_000));
    }
    for l in &liars {
        sim.connect(*l);
    }
    sim.run(120_000, 1_000);

    let calls = sim.engine.interpreter_calls();
    assert!(
        !sim.engine.reject_cache().is_empty(),
        "the rejected branch was not memoised at all"
    );
    assert!(
        calls < liars.len() as u64,
        "{} interpreter calls for one rejected branch offered by {} peers: the \
         cost is scaling with the size of the peer set, which is a \
         per-(peer, tip) memo with a different spelling",
        calls,
        liars.len()
    );
    assert!(
        sim.engine.metrics.snapshot().gate0_dedup_hits > 0,
        "no header was deduplicated at G0 at all"
    );
}

#[test]
fn silent_designee_rotated_on_locate() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(500);
    let silent = sim.add_peer(Behaviour::Silent, chain.clone());
    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(silent);
    sim.connect(honest);

    let mut rotated_at = 0u64;
    for t in 1..=(STALL_TIMEOUT_MS / 1_000) {
        sim.step(1_000);
        if rotated_at == 0 && !rotations_of(&sim, silent).is_empty() {
            rotated_at = t;
        }
    }
    assert_eq!(
        sim.sync_peer(),
        None.or(Some(honest)),
        "the silent peer was not replaced by the honest one"
    );
    assert_eq!(
        rotations_of(&sim, silent).first(),
        Some(&RotationKind::LocateTimeout),
        "the silent designee was rotated by {:?} rather than by the locate \
         deadline",
        rotations_of(&sim, silent)
    );
    assert!(
        rotated_at > 0 && rotated_at * 1_000 < STALL_TIMEOUT_MS,
        "the rotation landed at t={}s, at or beyond STALL_TIMEOUT ({}s): the \
         15 s locate deadline did not act, the 30 s progress deadline did",
        rotated_at,
        STALL_TIMEOUT_MS / 1_000
    );
    assert!(
        sim.getheaders_seen(honest) > 0,
        "the replacement designee was never asked for headers"
    );
}

#[test]
fn unverified_designee_loses_grant() {
    let interp = POW_POOL_MS_PER_SEC + 1_000;
    let mut sim = Sim::with_pow_cost(1, T0, interp);
    let chain = sim.extension(80_000);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(PROBE_GRANT_MS + 5_000, 1_000);

    assert_eq!(
        sim.engine.verified_height(),
        0,
        "test precondition: nothing may verify, or the peer is proven and \
         probation correctly does not apply"
    );
    assert!(
        sim.engine.header.staging.staged_len() > 0,
        "test precondition: the peer must be streaming"
    );
    assert_eq!(
        rotations_of(&sim, p).first(),
        Some(&RotationKind::ProbationExpired),
        "a designee that staged tens of thousands of headers and verified none \
         of them was rotated by {:?}; every other deadline here is satisfied or \
         suppressed, so probation is the only one left",
        rotations_of(&sim, p)
    );

    let mut ok = Sim::with_pow_cost(1, T0, POW_POOL_MS_PER_SEC);
    let chain = ok.extension(80_000);
    let q = ok.add_peer(Behaviour::Honest, chain);
    ok.connect(q);
    ok.run(PROBE_GRANT_MS + 5_000, 1_000);
    assert!(
        ok.engine.verified_height() > 0,
        "test precondition for the converse: this peer's headers must verify"
    );
    assert!(
        !rotations_of(&ok, q).contains(&RotationKind::ProbationExpired),
        "a designee with verified deliveries lost its grant anyway: {:?}",
        rotations_of(&ok, q)
    );
}

fn states_that_republished(sim: &mut Sim, secs: u64) -> Vec<HState> {
    let mut seen: Vec<HState> = Vec::new();
    for _ in 0..secs {
        let before = sim.engine.header.state();
        let n = sim.actions.len();
        sim.step(1_000);
        let republished = sim.actions[n..]
            .iter()
            .any(|a| matches!(a, Action::RepublishTip));
        if republished && !seen.contains(&before) {
            seen.push(before);
        }
    }
    seen
}

#[test]
fn tip_republished_in_every_state() {
    let mut seen: Vec<HState> = Vec::new();

    let mut cold = Sim::new(10, T0);
    seen.extend(states_that_republished(&mut cold, 20));

    let mut ibd = Sim::with_pow_cost(1, T0, HEADER_VERIFY_US_MAX / 1_000);
    let chain = ibd.extension(20_000);
    let p = ibd.add_peer(Behaviour::Honest, chain);
    ibd.connect(p);
    seen.extend(states_that_republished(&mut ibd, 120));

    let mut deep = Sim::new(600, T0);
    let branch = deep.fork(500, 900, 91);
    let d = deep.add_peer(Behaviour::Honest, branch);
    deep.connect(d);
    deep.pin_tip_time_to_now();
    seen.extend(states_that_republished(&mut deep, 400));

    let mut churn = Sim::new(1, T0);
    let tip = churn.extension(300);
    let h = churn.add_peer(Behaviour::Honest, tip);
    let liar = churn.add_liar(Vec::new(), 9_000);
    churn.connect(h);
    churn.connect(liar);
    seen.extend(states_that_republished(&mut churn, 400));

    for required in [
        HState::ColdStart,
        HState::Probing,
        HState::HeaderSync,
        HState::Tracking,
        HState::DeepRecovery,
    ] {
        assert!(
            seen.contains(&required),
            "the tip was never republished while the machine was in {:?}; \
             republishing observed only in {:?}",
            required,
            seen
        );
    }
}

#[test]
fn livelocked_node_republishes_tip() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(300);
    let honest = sim.add_peer(Behaviour::Honest, chain);
    let liar = sim.add_liar(Vec::new(), 9_000);
    sim.connect(honest);
    sim.connect(liar);

    let mut outside_tracking = 0u64;
    let mut total = 0u64;
    for _ in 0..1_200 {
        let before = sim.engine.header.state();
        let n = sim.actions.len();
        sim.step(1_000);
        let republished = sim.actions[n..]
            .iter()
            .filter(|a| matches!(a, Action::RepublishTip))
            .count() as u64;
        total += republished;
        if before != HState::Tracking {
            outside_tracking += republished;
        }
    }

    let expected = 1_200_000 / TIP_REPUBLISH_MS;
    assert!(
        total >= expected - 2,
        "the tip was republished {} times in 1,200 s against a {} ms timer \
         ({} expected)",
        total,
        TIP_REPUBLISH_MS,
        expected
    );
    assert!(
        outside_tracking > 0,
        "every republish happened while the machine was in Tracking, so the \
         timer is still the S4 audit wearing a different name"
    );
}

struct FlatChain {
    genesis: HeaderRec,
    accepted: Mutex<HashMap<Hash32, HeaderRec>>,
}

impl FlatChain {
    fn new(genesis: HeaderRec) -> FlatChain {
        FlatChain {
            genesis,
            accepted: Mutex::new(HashMap::new()),
        }
    }
    fn accepted_len(&self) -> usize {
        self.accepted.lock().expect("lock").len()
    }
}

impl ChainView for FlatChain {
    fn tip(&self) -> TipSnapshot {
        TipSnapshot {
            height: self.genesis.height,
            hash: self.genesis.hash,
            cum_work: [0u8; 32],
            time: self.genesis.time,
        }
    }
    fn header_at(&self, height: u64) -> Option<HeaderRec> {
        (height == self.genesis.height).then_some(self.genesis)
    }
    fn header_by_hash(&self, h: &Hash32) -> Option<HeaderRec> {
        if *h == self.genesis.hash {
            return Some(self.genesis);
        }
        self.accepted.lock().expect("lock").get(h).copied()
    }
    fn ancestor_at(&self, _tip: &Hash32, height: u64) -> Option<Hash32> {
        self.header_at(height).map(|h| h.hash)
    }
    fn locator(&self) -> Vec<Hash32> {
        vec![self.genesis.hash]
    }
    fn headers_from(&self, _l: &[Hash32], _s: &Hash32, _m: usize) -> Vec<[u8; HEADER_BYTES]> {
        Vec::new()
    }
    fn have_body(&self, _h: &Hash32) -> bool {
        true
    }
    fn body_bytes(&self, _h: &Hash32) -> Option<Vec<u8>> {
        None
    }
    fn anchor(&self) -> Option<Anchor> {
        None
    }
    fn checkpoints(&self) -> Vec<(u64, Hash32)> {
        Vec::new()
    }
    fn pow_verified_floor(&self) -> u64 {
        0
    }
}

impl BlockSink for FlatChain {
    fn submit_headers(&self, b: HeaderBatch) -> Result<Accepted, SinkError> {
        let mut g = self.accepted.lock().expect("lock");
        for h in &b.headers {
            g.insert(h.hash, *h);
        }
        Ok(Accepted {
            connected: b.headers.len() as u64,
            verified_height: b.headers.last().map(|h| h.height).unwrap_or(0),
            held: None,
        })
    }
    fn submit_block(&self, _h: Hash32, _b: Vec<u8>) -> Result<(), SinkError> {
        Ok(())
    }
    fn submit_tx(&self, _t: Hash32, _b: Vec<u8>) -> Result<(), SinkError> {
        Ok(())
    }
    fn submit_checkpoint(&self, _c: SignedCheckpoint) -> Result<AnchorUpdate, SinkError> {
        Ok(AnchorUpdate::Unchanged)
    }
    fn capacity(&self) -> SinkCapacity {
        SinkCapacity {
            blocks: u64::MAX,
            bytes: u64::MAX,
        }
    }
}

#[test]
fn known_memo_evicts_at_cap() {
    let n = KNOWN_HEADERS_MAX as u64 + 4_000;
    let genesis = build_chain(0, 1, [0u8; 32], T0, 1)[0];
    let chain = Arc::new(FlatChain::new(genesis));
    let hdrs = build_chain(1, n, genesis.hash, T0, 1);

    let mut eng = SyncEngine::new(
        chain.clone(),
        chain.clone(),
        Arc::new(MockPow::all_valid()),
        Arc::new(MockBits),
        P2pConfig::isolated(),
        11,
        Mono(0),
    );
    eng.set_now_unix(hdrs.last().expect("chain").time);
    let mut pending = eng.on_event(
        Event::PeerReady {
            peer: PeerId(1),
            ip: [1u8; 16],
            outbound: true,
            height: n,
            work: [0xff; 32],
            tip: hdrs.last().expect("chain").hash,
            services: SERVICE_FULL_RELAY,
        },
        Mono(0),
    );

    let mut now = Mono(0);
    for _ in 0..200 {
        for a in std::mem::take(&mut pending) {
            if let Action::Send {
                peer,
                msg: Msg::GetHeaders { .. },
            } = a
            {
                let from = eng.header.staging.staged_height() as usize;
                let batch: Vec<[u8; HEADER_BYTES]> = hdrs
                    .iter()
                    .skip(from)
                    .take(MAX_HEADERS_PER_MSG)
                    .map(|h| h.raw)
                    .collect();
                if !batch.is_empty() {
                    let more = eng.on_event(Event::Headers { peer, raw: batch }, now);
                    pending.extend(more);
                }
            }
        }
        now = now.plus_ms(1_000);
        pending = eng.on_tick(now);
        assert!(
            eng.known_len() <= KNOWN_HEADERS_MAX,
            "the known memo grew to {} against a {}-entry bound",
            eng.known_len(),
            KNOWN_HEADERS_MAX
        );
    }

    assert!(
        chain.accepted_len() as u64 > KNOWN_HEADERS_MAX as u64,
        "test precondition: more headers must be committed than the memo can \
         hold, got {}",
        chain.accepted_len()
    );
    assert_eq!(
        eng.known_len(),
        KNOWN_HEADERS_MAX,
        "the memo is bounded but never actually reached its bound, so the LRU \
         was not exercised"
    );
}

#[test]
fn known_memo_forgets_below_cap() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(2_000);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(60_000, 1_000);

    assert_eq!(sim.engine.verified_height(), 2_000, "test precondition");
    assert!(
        sim.engine.known_len() <= MAX_REORG_DEPTH as usize + 1,
        "the memo holds {} entries after committing 2,000 headers: everything \
         more than MAX_REORG_DEPTH ({}) below the tip should have been \
         forgotten",
        sim.engine.known_len(),
        MAX_REORG_DEPTH
    );
}

fn replay_cost(n: usize, secs: u64) -> u64 {
    let mut sim = Sim::with_pow_cost(1, T0, 3);
    let chain = sim.extension(500);
    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(honest);

    sim.run(60_000, 1_000);

    let fork = sim.fork(1, 8, 0xBEE5);
    let raw: Vec<[u8; HEADER_BYTES]> = fork.iter().map(|h| h.raw).collect();

    let mut fs = Vec::new();
    for i in 0..n {
        let id = PeerId(10_000 + i as u64);
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12] = 172;
        ip[13] = (i >> 8) as u8;
        ip[14] = i as u8;

        sim.engine_event(Event::PeerReady {
            peer: id,
            ip,
            outbound: false,
            height: 500,
            work: [0u8; 32],
            tip: [0u8; 32],
            services: SERVICE_FULL_RELAY,
        });
        fs.push(id);
    }

    let before = sim.pow.calls();
    for _ in 0..secs {
        for f in &fs {
            for _ in 0..6 {
                sim.engine_event(Event::Headers {
                    peer: *f,
                    raw: raw.clone(),
                });
            }
        }
        sim.run(1_000, 1_000);
    }

    for f in &fs {
        assert!(
            sim.engine.peers().contains_key(f),
            "the replaying peer was disconnected; the scenario is meant to be \
             one no rule forbids, so a test that relies on banning it is \
             measuring the wrong thing"
        );
    }
    sim.pow.calls() - before
}

#[test]
fn announced_headers_interpreted_once() {
    let one = replay_cost(1, 60);
    assert!(
        one <= UNSOLICITED_HEADERS_MAX as u64,
        "one peer replaying the same {} headers for 60 s cost {} interpreter \
         calls; a header that is already in the fork tree has already been \
         through the interpreter and re-verifying it buys nothing",
        UNSOLICITED_HEADERS_MAX,
        one
    );
}

#[test]
fn inbound_replay_spares_pool() {
    let calls = replay_cost(MAX_INBOUND, 60);
    let ms = calls * HEADER_VERIFY_US_MAX / 1_000;
    let pool_ms = POW_POOL_MS_PER_SEC * 60;
    assert!(
        ms * 100 / pool_ms < 5,
        "{} inbound peers replaying one set of {} valid headers consumed {} \
         interpreter calls = {} ms of the {} ms the pool grants in 60 s ({}% of \
         the node's whole verify capacity), at a cost to the attacker of {} \
         bytes per replay and zero score",
        MAX_INBOUND,
        UNSOLICITED_HEADERS_MAX,
        calls,
        ms,
        pool_ms,
        ms * 100 / pool_ms,
        UNSOLICITED_HEADERS_MAX * HEADER_BYTES
    );
}

#[test]
fn replayed_announce_refreshes_claim() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(300);
    let honest = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(honest);
    sim.run(60_000, 1_000);

    let announcer = sim.add_peer(Behaviour::Silent, Vec::new());
    sim.connect(announcer);
    sim.run(1_000, 1_000);

    let fork = sim.fork(1, 8, 0xC1A1);
    let raw: Vec<[u8; HEADER_BYTES]> = fork.iter().map(|h| h.raw).collect();
    for _ in 0..5 {
        sim.engine_event(Event::Headers {
            peer: announcer,
            raw: raw.clone(),
        });
    }
    let claimed = sim
        .engine
        .peers()
        .get(&announcer)
        .map(|s| s.claimed_height)
        .unwrap_or(0);
    assert_eq!(
        claimed,
        fork.last().expect("fork").height,
        "the replayed announcement stopped refreshing the peer's claim: the \
         dedup was placed in front of the claim overlay instead of in front of \
         the interpreter"
    );
}

#[test]
fn inflated_claim_retired() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(300);
    let honest = sim.add_peer(Behaviour::Honest, chain);
    let inflated = sim.add_liar(Vec::new(), 9_000);
    sim.connect(honest);
    sim.connect(inflated);

    let mut settled: Option<u64> = None;
    let mut connected_when_settled = false;
    for m in 0..60u64 {
        sim.run(60_000, 1_000);
        if settled.is_none() && sim.engine.header.state() == HState::Tracking {
            settled = Some(m + 1);
            connected_when_settled = sim.engine.peers().contains_key(&inflated);
        }
    }

    let designations = sim.engine.metrics.snapshot().sync_designations;
    let at = settled.expect("the machine never returned to Tracking in an hour");

    assert!(
        at <= 15,
        "took {} minutes to return to Tracking against an unsatisfiable claim; retirement should settle it in three designations",
        at
    );
    assert!(
        connected_when_settled,
        "returned to Tracking only after the claimant disconnected; the claim was retired by BAN_SCORE, not the claim rules. Recovery must not depend on scoring an honest peer to death"
    );
    assert!(
        designations <= 8,
        "{} designations in an hour against one unsatisfiable claim. Each one \
         is a GETHEADERS to an honest peer and a 5-point DeadlineMiss for the \
         peer that could not satisfy a claim it never made",
        designations
    );
    assert_eq!(
        sim.engine.verified_height(),
        300,
        "the honest branch was lost while chasing the claim"
    );
}

#[test]
fn slow_serving_peer_keeps_claim() {

    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(20_000);
    let slow = sim.add_peer(Behaviour::Trickle { n: 10 }, chain);
    sim.connect(slow);
    sim.run(600_000, 1_000);

    assert!(
        sim.engine.peers().contains_key(&slow),
        "test precondition: the peer is slow, not bad, and must still be here"
    );
    assert!(
        !sim.engine.header.claim_demoted(slow),
        "the one peer ahead of us had its claim demoted after {} charged rotations though every batch VERIFIED; node now sits in {:?} at height {} of 20,000 reporting itself synced",
        sim.engine.metrics.snapshot().sync_designations,
        sim.engine.header.state(),
        sim.engine.verified_height()
    );
    assert!(
        sim.engine.verified_height() >= 2_000,
        "the node made {} headers of progress in ten minutes against a peer \
         that answered every single tick; losing the claim costs the designation \
         that would have continued the stream",
        sim.engine.verified_height()
    );
}
