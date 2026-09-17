mod common;

use std::path::{Path, PathBuf};

use common::{serial, Chain, Scratch};
use plaine_storage::{open, DurabilityMode, StoreConfig, StoreError, StoreReader};

const SEG: u64 = plaine_storage::SEG_BLOCKS;

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.ibd_batch_blocks = Some(4_096);
    c
}

fn seed(name: &str) -> Scratch {
    let s = Scratch::new(name);
    let (mut c, r, rep) = open(cfg_of(&s)).expect("seed open");
    assert!(rep.integrity.is_clean(), "a fresh store reported damage");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(2 * SEG, 1);
    c.extend(&common::commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    s
}

fn hseg(s: &Scratch, seg: u32) -> PathBuf {
    s.0.join("segments")
        .join("hdr")
        .join(format!("{seg:06x}.hseg"))
}
fn bseg(s: &Scratch, seg: u32) -> PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bseg"))
}
fn bidx(s: &Scratch, seg: u32) -> PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bidx"))
}

fn flip_bit(p: &Path, off: u64, bit: u8) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(p)
        .unwrap();
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(off)).unwrap();
    f.read_exact(&mut b).unwrap();
    let before = b[0];
    b[0] ^= 1u8 << bit;
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&b).unwrap();
    f.sync_all().unwrap();
    drop(f);
    let back = {
        let mut g = std::fs::File::open(p).unwrap();
        let mut v = [0u8; 1];
        g.seek(SeekFrom::Start(off)).unwrap();
        g.read_exact(&mut v).unwrap();
        v[0]
    };
    assert_ne!(
        before, back,
        "the flip at offset {off} did not reach the file"
    );
    assert_eq!(
        back,
        before ^ (1u8 << bit),
        "the file holds something other than the flip"
    );
}

fn slot(s: &Scratch, seg: u32, slot: usize) -> (u64, u32) {
    let idx = std::fs::read(bidx(s, seg)).unwrap();
    let off = u32::from_le_bytes(idx[slot * 8..slot * 8 + 4].try_into().unwrap()) as u64;
    let len = u32::from_le_bytes(idx[slot * 8 + 4..slot * 8 + 8].try_into().unwrap());
    (off, len)
}

fn sweep(r: &StoreReader) -> (u32, Vec<u32>, u32) {
    let first = plaine_storage::seg_of(r.prune_floor());
    let last = plaine_storage::seg_of(r.tip().height).max(first);
    let (mut ok, mut bad, mut unjudged) = (0u32, Vec::new(), 0u32);
    for seg in first..=last {
        match r.verify_segment_frames(seg) {
            Ok(Some(true)) => ok += 1,
            Ok(Some(false)) => bad.push(seg),
            Ok(None) | Err(_) => unjudged += 1,
        }
    }
    (ok, bad, unjudged)
}

#[test]
fn sealed_crc_flip_known_bad() {
    let _g = serial();
    let s = seed("sealed-flip-crc");

    {
        let (c, r, _) = open(cfg_of(&s)).expect("open");
        let (ok, bad, unjudged) = sweep(&r);
        assert!(
            bad.is_empty(),
            "the pristine store is already mismatched: {bad:?}"
        );
        assert!(
            ok >= 1,
            "no sealed segment was JUDGED at all: ok={ok} unjudged={unjudged}"
        );
        drop(c);
        drop(r);
    }

    let h = 2_000u64;
    let (off, len) = slot(&s, 0, h as usize);
    assert!(len > 0, "slot {h} has no body");
    flip_bit(&bseg(&s, 0), off + 4, 3);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.integrity.is_clean(),
        "L1's stated coverage is first+last only; it claimed more: {:?}",
        rep.integrity
    );
    let (_, bad, _) = sweep(&r);
    assert_eq!(bad, vec![0], "L2 did not report segment 0 as known bad");
    let mut buf = Vec::new();
    assert!(
        matches!(r.body_at(h, &mut buf), Err(StoreError::CrcMismatch { .. })),
        "a body whose frame CRC was flipped was SERVED"
    );
    println!("  1 bit in a frame crc field: L1 clean, L2 Some(false), read refused");
    drop(c);
    drop(r);
}

#[test]
fn sealed_payload_flip_caught_on_read() {
    let _g = serial();
    let s = seed("sealed-flip-payload");

    let h = 1_500u64;
    let (off, len) = slot(&s, 0, h as usize);
    assert!(len > 8, "slot {h} is too short to have an interior byte");
    flip_bit(&bseg(&s, 0), off + 8 + u64::from(len) / 2, 5);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    let (ok, bad, unjudged) = sweep(&r);
    assert!(
        bad.is_empty(),
        "L2 reported a frame-array mismatch for a PAYLOAD flip; the doc says it hashes \
         (len, crc) pairs only, so either the doc or this test is now wrong"
    );
    assert!(ok >= 1, "nothing was judged: ok={ok} unjudged={unjudged}");
    let mut buf = Vec::new();
    assert!(
        matches!(r.body_at(h, &mut buf), Err(StoreError::CrcMismatch { .. })),
        "a payload with a flipped bit was SERVED; nothing else would have caught it"
    );
    println!("  1 bit in a payload: L1 clean, L2 Some(true) and right to be, read refused");
    drop(c);
    drop(r);
}

#[test]
fn interior_header_flip_invisible_to_l1l2() {
    let _g = serial();
    let s = seed("sealed-flip-header");

    let h = 1_000u64;
    let before = {
        let (c, r, _) = open(cfg_of(&s)).expect("open");
        let hdr = r.header_at(h).unwrap().expect("header present");
        drop(c);
        drop(r);
        hdr
    };

    flip_bit(&hseg(&s, 0), plaine_storage::hdr_offset(h) + 100, 2);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.integrity.is_clean(),
        "L1 caught an interior header flip; its stated coverage says it cannot: {:?}",
        rep.integrity
    );
    let (ok, bad, unjudged) = sweep(&r);
    assert!(
        bad.is_empty(),
        "L2 reported segment(s) {bad:?} bad for a HEADER flip. If this now fires, the L2 \
         tier has grown header coverage and this residual can be retired."
    );
    assert!(ok >= 1, "nothing was judged: ok={ok} unjudged={unjudged}");

    let after = r.header_at(h).unwrap().expect("header still served");
    assert_ne!(
        after, before,
        "the flip did not reach the header the reader serves"
    );

    let child = r.header_at(h + 1).unwrap().expect("child present");
    let mine = plaine_consensus::crypto::header_hash(&after);
    assert_ne!(
        mine,
        child[12..44],
        "the child records this header's hash, so the flip must have broken the link"
    );
    assert!(
        r.header_by_hash(&mine).unwrap().is_none(),
        "the corrupted header answered to its own new hash"
    );

    assert!(
        matches!(
            r.verify_segment_headers(0),
            Err(StoreError::LinkageBroken { height, .. }) if height == h + 1
        ),
        "L3-H did not name the interior header flip that L1 and L2 both miss; the residual \
         is open again and `noded`'s comment about it must go back to saying so: {:?}",
        r.verify_segment_headers(0)
    );

    println!(
        "  1 bit in interior header {h}: L1 clean, L2 clean, header SERVED and unlinked \
         from {}. Span L1+L2 leave uncovered: {} headers per sealed segment - now walked \
         by verify_segment_headers.",
        h + 1,
        SEG - 2
    );
    drop(c);
    drop(r);
}

#[test]
fn frame_len_disagrees_known_bad() {
    let _g = serial();
    let s = seed("sealed-flip-len");

    let h = 2_500u64;
    let (off, len) = slot(&s, 0, h as usize);
    assert!(len > 0, "slot {h} has no body");

    flip_bit(&bseg(&s, 0), off, 0);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.integrity.is_clean(),
        "L1's coverage is first+last only: {:?}",
        rep.integrity
    );
    let (_, bad, _) = sweep(&r);
    assert_eq!(
        bad,
        vec![0],
        "a frame length that disagrees with its sidecar entry was accepted by L2"
    );
    println!("  1 bit in a frame LENGTH field: L2 Some(false) via the sidecar cross-check");
    drop(c);
    drop(r);
}
