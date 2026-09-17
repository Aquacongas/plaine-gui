mod common;

use common::{serial, Scratch};
use plaine_storage::{open, ANCHOR_RECORD_CAP_BYTES};

fn record(height: u64, tag: u8) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&[tag; 32]);
    v.push(1);
    v.extend_from_slice(&[tag; 32]);
    v.extend_from_slice(&[tag; 64]);
    v
}

#[test]
fn anchor_row_survives_reopen() {
    let _g = serial();
    let s = Scratch::new("anchor-cp-roundtrip");
    let want = record(4_242, 0xAB);
    {
        let (mut c, r, _) = open(s.cfg()).expect("open");
        assert_eq!(
            r.checkpoint_anchor().expect("read"),
            None,
            "a fresh store holds no anchor"
        );
        c.put_checkpoint_anchor(&want).expect("write");
        assert_eq!(r.checkpoint_anchor().expect("read"), Some(want.clone()));
        c.abandon();
    }

    {
        let (c, r, _) = open(s.cfg()).expect("reopen");
        assert_eq!(
            r.checkpoint_anchor().expect("read"),
            Some(want),
            "the anchor row did not survive a restart"
        );
        c.abandon();
    }
}

#[test]
fn anchor_row_overwritten_in_place() {
    let _g = serial();
    let s = Scratch::new("anchor-cp-overwrite");
    let (mut c, r, _) = open(s.cfg()).expect("open");
    c.put_checkpoint_anchor(&record(10, 0x11)).expect("write");
    c.put_checkpoint_anchor(&record(20, 0x22)).expect("write");
    assert_eq!(r.checkpoint_anchor().expect("read"), Some(record(20, 0x22)));
    c.abandon();
}

#[test]
fn bad_size_record_refused() {
    let _g = serial();
    let s = Scratch::new("anchor-cp-bounds");
    let (mut c, r, _) = open(s.cfg()).expect("open");

    assert!(
        c.put_checkpoint_anchor(&[]).is_err(),
        "an empty row is not a record"
    );
    assert!(
        c.put_checkpoint_anchor(&vec![0u8; ANCHOR_RECORD_CAP_BYTES + 1])
            .is_err(),
        "the cap is this crate's own bound and must hold whatever the writer says"
    );
    assert_eq!(
        r.checkpoint_anchor().expect("read"),
        None,
        "a refused write left a row"
    );

    c.put_checkpoint_anchor(&vec![7u8; ANCHOR_RECORD_CAP_BYTES])
        .expect("at the cap");
    assert_eq!(
        r.checkpoint_anchor().expect("read").map(|v| v.len()),
        Some(ANCHOR_RECORD_CAP_BYTES)
    );
    c.abandon();
}

#[test]
fn bytes_round_trip_unaltered() {
    let _g = serial();
    let s = Scratch::new("anchor-cp-opaque");
    let (mut c, r, _) = open(s.cfg()).expect("open");

    let junk: Vec<u8> = (0u8..=255).chain(0u8..=200).collect();
    c.put_checkpoint_anchor(&junk).expect("stored");
    assert_eq!(r.checkpoint_anchor().expect("read"), Some(junk));
    c.abandon();
}
