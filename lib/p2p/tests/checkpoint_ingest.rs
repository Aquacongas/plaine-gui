use plaine_p2p::peer::session::{CheckpointAdmit, Session};
use plaine_p2p::constants::*;
use plaine_p2p::traits::{Hash32, Mono, PeerId};

fn sess() -> Session {
    Session::new(PeerId(1), [7u8; 16], false, Mono(0))
}

fn h(n: u8) -> Hash32 {
    let mut x = [0u8; 32];
    x[0] = n;
    x
}

#[test]
fn repeat_anchor_checked_once() {
    let mut s = sess();
    assert_eq!(s.admit_checkpoint(100, h(1), Mono(0)), CheckpointAdmit::Accept);
    assert_eq!(s.admit_checkpoint(100, h(1), Mono(1_000)), CheckpointAdmit::Duplicate);

    assert_eq!(s.admit_checkpoint(100, h(2), Mono(2_000)), CheckpointAdmit::Accept);

    assert_eq!(s.admit_checkpoint(101, h(1), Mono(3_000)), CheckpointAdmit::Accept);
}

#[test]
fn fifth_checkpoint_scored() {
    let mut s = sess();
    for i in 0..CHECKPOINT_RATE_PER_10MIN {
        assert_eq!(
            s.admit_checkpoint(i as u64, h(i as u8), Mono(i as u64)),
            CheckpointAdmit::Accept,
            "record {i} inside the rate was refused"
        );
    }
    assert_eq!(
        s.admit_checkpoint(900, h(90), Mono(10)),
        CheckpointAdmit::OverRate,
        "a peer sent {} distinct checkpoints inside one window and paid nothing",
        CHECKPOINT_RATE_PER_10MIN + 1
    );

    let after = Mono(CHECKPOINT_RATE_WINDOW_MS + 1);
    assert_eq!(s.admit_checkpoint(901, h(91), after), CheckpointAdmit::Accept);
}

#[test]
fn dedup_ring_covers_window() {
    assert!(CHECKPOINT_DEDUP_MAX as u32 >= CHECKPOINT_RATE_PER_10MIN);
    let mut s = sess();
    for i in 0..CHECKPOINT_DEDUP_MAX {
        let t = Mono((i as u64 + 1) * (CHECKPOINT_RATE_WINDOW_MS + 1));
        assert_eq!(s.admit_checkpoint(i as u64, h(i as u8), t), CheckpointAdmit::Accept);
    }
    let t = Mono((CHECKPOINT_DEDUP_MAX as u64 + 2) * (CHECKPOINT_RATE_WINDOW_MS + 1));
    assert_eq!(
        s.admit_checkpoint((CHECKPOINT_DEDUP_MAX - 1) as u64, h((CHECKPOINT_DEDUP_MAX - 1) as u8), t),
        CheckpointAdmit::Duplicate,
        "the newest record fell out of a ring that is supposed to hold it"
    );
}

#[test]
fn getcheckpoint_rate_limited() {
    let mut s = sess();
    assert!(s.admit_getcheckpoint(Mono(0)));
    assert!(!s.admit_getcheckpoint(Mono(GETCHECKPOINT_INTERVAL_MS - 1)));
    assert!(s.admit_getcheckpoint(Mono(GETCHECKPOINT_INTERVAL_MS + 1)));

    assert!(s.last_getcheckpoint.is_none());
}

use plaine_p2p::mock::{Behaviour, Sim};
use plaine_p2p::peer::Offence;
use plaine_p2p::sync::{Action, Event};
use plaine_p2p::traits::SignedCheckpoint;

const T0: u64 = 1_800_000_000;

fn cp(height: u64, hash: Hash32) -> SignedCheckpoint {
    SignedCheckpoint {
        height,
        hash,
        sigs: Vec::new(),
    }
}

fn rig() -> (Sim, PeerId) {
    let mut sim = Sim::new(4, T0);
    let chain = sim.extension(4);
    let p = sim.add_peer(Behaviour::Honest, chain);
    sim.connect(p);
    sim.run(4_000, 1_000);
    (sim, p)
}

#[test]
fn replayed_checkpoint_deduped() {
    let (mut sim, p) = rig();
    let before = sim.chain.checkpoints_seen();
    for _ in 0..6 {
        sim.engine_event(Event::Checkpoint { peer: p, cp: cp(900, [9u8; 32]) });
    }
    assert_eq!(
        sim.chain.checkpoints_seen() - before,
        1,
        "six copies of one 106-byte record bought {} rendezvous onto the block-applying \
         thread and {} ed25519 verifications",
        sim.chain.checkpoints_seen() - before,
        sim.chain.checkpoints_seen() - before
    );
}

#[test]
fn checkpoint_flood_bounded() {
    let (mut sim, p) = rig();
    let before = sim.chain.checkpoints_seen();
    let mut scored = 0usize;
    for i in 0..40u64 {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        let acts = sim.engine.on_event(
            Event::Checkpoint { peer: p, cp: cp(1_000 + i, h) },
            plaine_p2p::traits::Mono(0),
        );
        scored += acts
            .iter()
            .filter(|a| matches!(a, Action::Score { offence: Offence::GetCheckpointAbuse, .. }))
            .count();
    }
    let reached = sim.chain.checkpoints_seen() - before;
    assert_eq!(
        reached, CHECKPOINT_RATE_PER_10MIN as u64,
        "{reached} of 40 flooded checkpoints reached the sink"
    );
    assert_eq!(
        scored,
        40 - CHECKPOINT_RATE_PER_10MIN as usize,
        "the over-rate frames were dropped without being charged, so a flooder pays nothing"
    );
}

#[test]
fn advancing_anchor_runs_audit() {
    let (mut sim, p) = rig();
    let before = sim.chain.checkpoints_seen();
    sim.engine_event(Event::Checkpoint { peer: p, cp: cp(7_000, [3u8; 32]) });
    assert_eq!(sim.chain.checkpoints_seen() - before, 1);
    assert_eq!(
        plaine_p2p::traits::ChainView::anchor(&*sim.chain).map(|a| a.height),
        Some(7_000),
        "the record reached the sink and the anchor did not move"
    );
}
