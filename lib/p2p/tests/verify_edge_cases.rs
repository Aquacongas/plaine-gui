use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::*;
use plaine_p2p::gate::Budgets;
use plaine_p2p::mock::{build_chain, Behaviour, MockBits, MockChain, Sim};
use plaine_p2p::sync::header_track::HState;
use plaine_p2p::sync::{Action, Event, SyncEngine};
use plaine_p2p::traits::*;
use plaine_p2p::wire::Msg;
use std::sync::Arc;

const T0: u64 = 1_800_000_000;

#[test]
fn full_queue_keeps_verified() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(400);
    let a = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(a);
    sim.run(3_000, 1_000);

    sim.chain.freeze_sink(true);
    sim.run(30_000, 1_000);
    sim.chain.freeze_sink(false);

    sim.run(1_800_000, 1_000);

    assert_eq!(sim.engine.verified_height(), 400);

    let stored: Vec<u64> = sim.chain.headers().iter().map(|h| h.height).collect();
    let missing: Vec<u64> = (0..=400u64).filter(|h| !stored.contains(h)).collect();
    assert!(
        missing.is_empty(),
        "validator never got heights {:?} ({} headers); one lost per tick of a commit stall, silently",
        &missing[..missing.len().min(8)],
        missing.len()
    );
}

#[test]
fn dropped_header_reoffered() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(400);
    let a = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(a);
    sim.run(3_000, 1_000);
    sim.chain.freeze_sink(true);
    sim.run(30_000, 1_000);
    sim.chain.freeze_sink(false);
    sim.run(1_800_000, 1_000);

    assert_eq!(
        sim.chain.accepted_headers(),
        400,
        "after 30 min of recovery the validator has {} of 400 headers: the \
         dedup entry outlives the data it stands for",
        sim.chain.accepted_headers()
    );
}

#[test]
fn unsatisfiable_claim_no_livelock() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(300);
    let honest = sim.add_peer(Behaviour::Honest, chain);
    let inflated = sim.add_liar(Vec::new(), 9_000);
    sim.connect(honest);
    sim.connect(inflated);
    sim.run(3_600_000, 1_000);

    assert_eq!(sim.engine.verified_height(), 300);
    assert_eq!(
        sim.engine.header.state(),
        HState::Tracking,
        "after an hour at the network tip the machine is in {:?}: it has made \
         {} designations and is emitting StrandedBeyondReorgCap while being \
         fully synced",
        sim.engine.header.state(),
        sim.engine.metrics.snapshot().sync_designations
    );
    assert_eq!(
        sim.engine.metrics.snapshot().quarantines,
        0,
        "the canonical branch tip was quarantined by a node that is on it"
    );
}

#[test]
fn ready_ahead_bound_enforced() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(400);
    for _ in 0..4 {
        let p = sim.add_peer(Behaviour::Honest, chain.clone());
        sim.connect(p);
    }
    sim.run(5_000, 1_000);
    sim.chain.freeze_sink(true);
    sim.run(300_000, 1_000);

    assert!(
        sim.engine.body.ready_len() <= READY_AHEAD_BLOCKS,
        "ready-ahead holds {} blocks against its stated ceiling of {}; at the \
         1 MiB block cap that is {} MiB of unbounded buffer",
        sim.engine.body.ready_len(),
        READY_AHEAD_BLOCKS,
        sim.engine.body.ready_len()
    );
}

#[test]
fn wanted_list_bounded() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(3_000);
    let hdrs = sim.add_peer(Behaviour::HeadersOnly, chain);
    sim.connect(hdrs);
    sim.run(120_000, 1_000);

    assert!(
        sim.engine.wanted_len() <= BODY_WINDOW_HASHES * 4,
        "wanted holds {} entries against a {}-hash body window; nothing bounds \
         it and it is cloned once per tick",
        sim.engine.wanted_len(),
        BODY_WINDOW_HASHES
    );
}

struct CostlyPow;
impl PowVerifier for CostlyPow {
    fn verify(&self, _hdr: &[u8; HEADER_BYTES]) -> bool {
        true
    }

    fn cost_ms(&self) -> u64 {
        HEADER_VERIFY_US_MAX / 1_000
    }
}

#[test]
fn pow_pool_admits_rate_floor() {
    let admitted = POW_POOL_MS_PER_SEC * 1_000 / HEADER_VERIFY_US_MAX;
    let floor = SYNC_MIN_RATE_IBD_PER_10S / 10;
    assert!(
        admitted >= floor,
        "the pow pool admits {} headers/s at {} us/header while the rate floor \
         rotates away from any peer below {}/s",
        admitted,
        HEADER_VERIFY_US_MAX,
        floor
    );
}

#[test]
fn header_phase_survives_budget() {
    let above_anchor = 5_200_000u64 - CHECKPOINT_SUNSET_HEIGHT;
    let doc_minutes_max = 138u64;
    let enforced_minutes = above_anchor * HEADER_VERIFY_US_MAX / 1_000 / POW_POOL_MS_PER_SEC / 60;
    assert!(
        enforced_minutes <= doc_minutes_max,
        "the enforced pow pool puts the header phase at {} min ({} h) against \
         the {} min the crate's own budget test asserts",
        enforced_minutes,
        enforced_minutes / 60,
        doc_minutes_max
    );
}

#[test]
fn staging_window_reachable() {
    let chain = Arc::new(MockChain::linear(1, T0, 1));
    let tip = chain.tip();
    let hdrs = build_chain(1, 140_000, tip.hash, T0, 1);
    let mut eng = SyncEngine::new(
        chain.clone(),
        chain.clone(),
        Arc::new(CostlyPow),
        Arc::new(MockBits),
        P2pConfig::isolated(),
        7,
        Mono(0),
    );
    eng.set_now_unix(hdrs.last().expect("chain").time);
    let acts = eng.on_event(
        Event::PeerReady {
            peer: PeerId(1),
            ip: [1u8; 16],
            outbound: true,
            height: 140_000,
            work: [0xff; 32],
            tip: hdrs.last().expect("chain").hash,
            services: SERVICE_FULL_RELAY,
        },
        Mono(0),
    );

    let mut now = Mono(0);
    let mut peak = 0u64;
    let mut rotations = 0u64;
    let mut pending = acts;
    for _ in 0..600 {
        for a in std::mem::take(&mut pending) {
            match a {
                Action::Send {
                    peer,
                    msg: Msg::GetHeaders { .. },
                } => {
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
                Action::Undesignate { .. } => rotations += 1,
                _ => {}
            }
        }
        now = now.plus_ms(1_000);
        pending = eng.on_tick(now);
        peak = peak.max(eng.header.staging.staged_len());
    }

    let rate = eng.verified_height() / (now.0 / 1_000).max(1);
    assert_eq!(
        rotations, 0,
        "the sync peer was rotated {} times while we were the bottleneck",
        rotations
    );
    assert!(
        rate >= SYNC_MIN_RATE_IBD_PER_10S / 10,
        "engine verifies {} headers/s (peak staging {} of {}), below the {}/s floor it demands of its sync peer",
        rate,
        peak,
        PRESYNC_LEAD_HEADERS,
        SYNC_MIN_RATE_IBD_PER_10S / 10,
    );
}

#[test]
fn sync_reserve_covers_budget() {
    let mut b = Budgets::new(Mono(0));
    let flood = READ_PEER_BYTES_PER_SEC;
    let flooders = READ_GLOBAL_BYTES_PER_SEC / flood;
    for _ in 0..flooders {
        assert!(b.admit_read(flood, Mono(0)));
    }
    let one_headers_msg = (MAX_HEADERS_PER_MSG * HEADER_BYTES) as u64;
    assert!(
        b.admit_read(one_headers_msg, Mono(0)),
        "with {} peers at the per-peer read cap the designated sync peer's \
         HEADERS frame is refused by READ_GLOBAL, which carries no reserve; \
         the ingest reserve protects a budget that is charged second",
        flooders
    );
}

#[test]
fn bad_pow_bans_sender() {
    let mut sim = Sim::new(1, T0);
    let chain = sim.extension(500);
    let honest = sim.add_peer(Behaviour::Honest, chain.clone());
    let quiet = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(honest);
    sim.connect(quiet);
    sim.run(6_000, 1_000);
    let designated = sim.sync_peer().expect("a sync peer");

    let forged = sim.fork(1, 8, 0xBAD);
    sim.pow.poison_all(&forged);
    let raw: Vec<[u8; HEADER_BYTES]> = forged.iter().map(|h| h.raw).collect();
    let culprit = if designated == honest { quiet } else { honest };
    sim.engine_event(Event::Headers { peer: culprit, raw });
    sim.run(10_000, 1_000);

    assert!(
        sim.engine.peers().contains_key(&designated),
        "the designated peer was banned for a forged header supplied by a \
         different peer; the supplier {:?} is still connected: {}",
        culprit,
        sim.engine.peers().contains_key(&culprit)
    );
}
