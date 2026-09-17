mod support;

use plaine_chain::checkpoints::CheckpointOutcome;
use plaine_chain::mock::Scenario;
use plaine_chain::traits::SinkError;
use plaine_chain::Condition;
use plaine_consensus::checkpoint_record;
use support::*;

#[test]
fn anchor_survives_restart_and_is_enforced() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);

    let cp = signed_checkpoint(&authority_key(), 7, chain.blocks[7].rec.hash);
    let report = r.cm.submit_checkpoint(&cp).expect("no error");
    assert!(
        report.anchor_advanced,
        "the fixture must actually move the anchor"
    );
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(7));

    let raw = r
        .store
        .anchor_record()
        .expect("the sink was asked to persist something");
    assert!(
        raw.len() > 42,
        "a {}-byte row carries no signature, so nothing could ever re-verify it",
        raw.len()
    );

    r.restart();
    assert_eq!(
        r.cm.anchor(),
        None,
        "a rebooted manager starts with no anchor in memory"
    );
    let decoded = checkpoint_record::decode(&raw).expect("the row parses");
    assert!(r.cm.load_anchor(&decoded), "the record re-verified");
    assert_eq!(
        r.cm.anchor().map(|a| (a.height, a.hash)),
        Some((7, chain.blocks[7].rec.hash)),
        "the reloaded node holds the same anchor it had before the restart"
    );

    assert_eq!(
        r.cm.anchor_record().map(|c| c.height),
        Some(7),
        "a reloaded anchor must be servable, or GETCHECKPOINT is refused again"
    );
}

#[test]
fn tampered_row_loads_nothing() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&authority_key(), 7, chain.blocks[7].rec.hash);
    r.cm.submit_checkpoint(&cp).expect("no error");
    let raw = r.store.anchor_record().expect("persisted");

    for at in [42 + 32, 42 + 32 + 31, raw.len() - 1] {
        let mut bad = raw.clone();
        bad[at] ^= 0x01;
        let decoded = checkpoint_record::decode(&bad).expect("still parses: the shape is intact");
        r.restart();
        assert!(
            !r.cm.load_anchor(&decoded),
            "byte {at} was flipped and the record still loaded"
        );
        assert_eq!(
            r.cm.anchor(),
            None,
            "nothing may be installed on a failed verify"
        );
    }

    let mut moved = raw.clone();
    moved[1] ^= 0x01;
    let decoded = checkpoint_record::decode(&moved).expect("parses");
    r.restart();
    assert!(
        !r.cm.load_anchor(&decoded),
        "the height is inside the signed message"
    );
}

#[test]
fn key_rotation_retires_anchors() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p.clone());
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&authority_key(), 7, chain.blocks[7].rec.hash);
    r.cm.submit_checkpoint(&cp).expect("no error");
    let raw = r.store.anchor_record().expect("persisted");
    let decoded = checkpoint_record::decode(&raw).expect("parses");

    let mut rotated = p.clone();
    let new_key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    rotated.authority_keys = vec![new_key.verifying_key().to_bytes()];
    r.restart_with(rotated);
    assert!(
        !r.cm.load_anchor(&decoded),
        "an anchor signed by a key this node no longer trusts must not load"
    );
    assert_eq!(r.cm.anchor(), None);

    r.restart_with(p);
    assert!(r.cm.load_anchor(&decoded));
}

#[test]
fn replayed_checkpoint_no_second_write() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let cp = signed_checkpoint(&authority_key(), 7, chain.blocks[7].rec.hash);

    assert!(r.cm.submit_checkpoint(&cp).expect("ok").anchor_advanced);
    let first = r.store.anchor_record().expect("written once");

    r.store.poison_anchor_record();
    for _ in 0..5 {
        let rep = r.cm.submit_checkpoint(&cp).expect("ok");
        assert!(!rep.anchor_advanced, "a replay never advances the anchor");
    }
    assert_eq!(
        r.store.anchor_record().as_deref(),
        Some(b"POISON".as_slice()),
        "a replayed checkpoint drove a sink write"
    );

    let higher = signed_checkpoint(&authority_key(), 9, chain.blocks[9].rec.hash);
    assert!(r.cm.submit_checkpoint(&higher).expect("ok").anchor_advanced);
    let second = r.store.anchor_record().expect("written again");
    assert_ne!(second, first);
    assert_eq!(
        checkpoint_record::decode(&second).expect("parses").height,
        9
    );
}

#[test]
fn persisted_record_proves_anchor_held() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);

    for h in [3u64, 7, 5, 7, 9, 1] {
        let cp = signed_checkpoint(&authority_key(), h, chain.blocks[h as usize].rec.hash);
        r.cm.submit_checkpoint(&cp).expect("ok");
        let anchor =
            r.cm.anchor()
                .expect("something is anchored after the first");
        let held =
            r.cm.anchor_record()
                .expect("a held anchor always has its record");
        assert_eq!((held.height, held.hash), (anchor.height, anchor.hash));
        let disk =
            checkpoint_record::decode(&r.store.anchor_record().expect("row")).expect("parses");
        assert_eq!(
            (disk.height, disk.hash),
            (anchor.height, anchor.hash),
            "the row on disk proves a different block from the one being enforced"
        );
    }
    assert_eq!(
        r.cm.anchor().map(|a| a.height),
        Some(9),
        "monotone in height"
    );
}

#[test]
fn unpersisted_anchor_reported_still_armed() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);

    r.store.fail_next_anchor(SinkError::Invalid("disk full"));
    let cp = signed_checkpoint(&authority_key(), 7, chain.blocks[7].rec.hash);
    let rep = r.cm.submit_checkpoint(&cp).expect("no error");
    assert!(
        rep.anchor_advanced,
        "the write failing does not un-verify the record"
    );
    assert_eq!(rep.outcome, CheckpointOutcome::Admitted);
    assert_eq!(
        r.cm.anchor().map(|a| a.height),
        Some(7),
        "layer 2 is armed for this process"
    );
    assert!(
        r.store.anchor_record().is_none(),
        "nothing reached the disk"
    );

    let conds = r.conds.lock().expect("conds").clone();
    assert!(
        conds.iter().any(|c| matches!(
            c,
            Condition::AnchorNotPersisted {
                height: 7,
                err: SinkError::Invalid("disk full")
            }
        )),
        "the failure must be reported, not swallowed: {conds:?}"
    );
    assert!(
        !conds
            .iter()
            .any(|c| matches!(c, Condition::StorageFatal { .. })),
        "a durability regression is not a reason to halt a node"
    );
}
