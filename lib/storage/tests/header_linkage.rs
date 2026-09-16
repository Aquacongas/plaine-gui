mod common;

use std::path::{Path, PathBuf};

use common::{serial, Chain, Scratch};
use plaine_storage::{open, DurabilityMode, ReorgPlan, StoreConfig, StoreError, StoreReader};

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
    s.0.join("segments").join("hdr").join(format!("{seg:06x}.hseg"))
}

fn flip_bit(p: &Path, off: u64, bit: u8) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(p).unwrap();
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(off)).unwrap();
    f.read_exact(&mut b).unwrap();
    let before = b[0];
    b[0] ^= 1u8 << bit;
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&b).unwrap();
    f.sync_all().unwrap();
    drop(f);
    let mut g = std::fs::File::open(p).unwrap();
    let mut v = [0u8; 1];
    g.seek(SeekFrom::Start(off)).unwrap();
    g.read_exact(&mut v).unwrap();
    assert_ne!(before, v[0], "the flip at offset {off} did not reach the file");
    assert_eq!(v[0], before ^ (1u8 << bit), "the file holds something other than the flip");
}

fn sweep(r: &StoreReader) -> (u64, Vec<(u32, u64)>, u32) {
    let first = plaine_storage::seg_of(r.prune_floor());
    let last = plaine_storage::seg_of(r.tip().height).max(first);
    let (mut links, mut broken, mut unjudged) = (0u64, Vec::new(), 0u32);
    for seg in first..=last {
        match r.verify_segment_headers(seg) {
            Ok(Some(n)) => links += n,
            Ok(None) => unjudged += 1,
            Err(StoreError::LinkageBroken { height, .. }) => broken.push((seg, height)),
            Err(e) => panic!("segment {seg} answered with something other than a verdict: {e:?}"),
        }
    }
    (links, broken, unjudged)
}

#[test]
fn pristine_segment_links_through() {
    let _g = serial();
    let s = seed("hdrlink-clean");
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);

    let n = r.verify_segment_headers(0).expect("segment 0 verdict");
    assert_eq!(
        n,
        Some(SEG),
        "segment 0 must verify {SEG} links: {} inside it plus the one OUT of its last \
         header into segment 1. {} would mean the out-link step did not run, and the last \
         header of every sealed segment would rest on L1's boundary check instead.",
        SEG - 1,
        SEG - 1
    );

    assert_eq!(
        r.verify_segment_headers(1).expect("segment 1 verdict"),
        Some(SEG - 1),
        "the TOP sealed segment must report one link fewer, because its last header has \
         no child below the watermark to state its hash"
    );

    assert_eq!(
        r.verify_segment_headers(2).expect("unsealed segment verdict"),
        None,
        "a segment above the watermark was JUDGED; a tier that judges a moving object \
         reads 'bad' on every healthy node between boundaries and is then ignored"
    );

    assert_eq!(
        r.verify_segment_headers(9_999).expect("absent segment verdict"),
        None,
        "a nonexistent segment passed"
    );

    let (links, broken, unjudged) = sweep(&r);
    assert!(broken.is_empty(), "the pristine store reports broken links: {broken:?}");
    assert_eq!(
        links,
        2 * SEG - 1,
        "the sweep judged nothing, or judged only one of the two sealed segments: \
         links={links} unjudged={unjudged}"
    );
    println!("  pristine: {links} links verified, {unjudged} segment(s) not judgeable");
    drop(c);
    drop(r);
}

#[test]
fn interior_header_flip_refused() {
    let _g = serial();
    let s = seed("hdrlink-interior");

    let h = 1_000u64;

    let before = {
        let (c, r, _) = open(cfg_of(&s)).expect("open");
        assert_eq!(
            r.verify_segment_headers(0).expect("baseline verdict"),
            Some(SEG),
            "the store was not clean to start"
        );
        let hdr = r.header_at(h).unwrap().expect("header present");
        drop(c);
        drop(r);
        hdr
    };

    flip_bit(&hseg(&s, 0), plaine_storage::hdr_offset(h) + 100, 2);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.integrity.is_clean(),
        "L1 caught an interior header flip; its stated coverage is first+last only: {:?}",
        rep.integrity
    );
    assert_eq!(
        r.verify_segment_frames(0).expect("L2 verdict"),
        Some(true),
        "L2 reported a BODY frame mismatch for a HEADER flip; it hashes (len, crc) pairs \
         and reads no header but the segment's first and last"
    );

    let served = r.header_at(h).unwrap().expect("header still served");
    assert_ne!(served, before, "the flip did not reach the header the reader serves");

    match r.verify_segment_headers(0) {
        Err(StoreError::LinkageBroken { height, expected_prev, found_prev }) => {
            assert_eq!(
                height,
                h + 1,
                "the refusal must name the CHILD height, whose stated parent hash is the \
                 thing that has become false"
            );
            assert_ne!(expected_prev, found_prev, "a LinkageBroken with two equal hashes");
            let msg = StoreError::LinkageBroken { height, expected_prev, found_prev }.to_string();
            assert!(
                msg.contains(&(h + 1).to_string()),
                "the message does not name the height: {msg}"
            );
            println!("  interior header {h}: L1 clean, L2 Some(true), L3-H -> {msg}");
        }
        other => panic!(
            "the interior header gap is OPEN again: segment 0 answered {other:?} after one \
             bit was flipped in header {h}"
        ),
    }

    let (_, broken, _) = sweep(&r);
    assert_eq!(broken, vec![(0u32, h + 1)], "the sweep did not name segment 0 at height {}", h + 1);
    drop(c);
    drop(r);
}

#[test]
fn first_header_flip_refused() {
    let _g = serial();
    let s = seed("hdrlink-first");

    flip_bit(&hseg(&s, 0), plaine_storage::hdr_offset(0) + 100, 6);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");

    assert!(
        rep.integrity.body_damage.iter().any(|d| d.segment == 0),
        "flipping header 0 no longer disturbs segment 0's body anchor. If that is now \
         true, the identity half of `anchor::geom` has changed and the 4,094-header \
         bound must be re-derived: {:?}",
        rep.integrity
    );
    assert!(
        rep.integrity.header_damage.is_empty(),
        "L1 named HEADER damage for one flipped header byte; its stated header coverage \
         is first+last identity and the segment boundary, neither of which moved: {:?}",
        rep.integrity
    );
    match r.verify_segment_headers(0) {
        Err(StoreError::LinkageBroken { height, .. }) => {
            assert_eq!(height, 1, "the first header of a sealed segment is outside the walk");
            println!("  first header of segment 0: L3-H -> LinkageBroken at height 1");
        }
        other => panic!("a flip in the segment's FIRST header was not caught: {other:?}"),
    }
    drop(c);
    drop(r);
}

#[test]
fn live_segment_not_judged() {
    let _g = serial();
    let s = Scratch::new("hdrlink-live");
    {
        let (mut c, r, rep) = open(cfg_of(&s)).expect("seed open");
        assert!(rep.integrity.is_clean(), "a fresh store reported damage");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(64, 64, 2);
        let bs = chain.build(2 * SEG + 10, 1);
        c.extend(&common::commits(&bs)).unwrap();
        c.flush().unwrap();
        drop(c);
        drop(r);
    }
    let (c, r, _) = open(cfg_of(&s)).expect("open");
    assert_eq!(r.hdr_watermark(), 2 * SEG + 10, "the seed did not reach the live segment");
    let p = hseg(&s, 2);
    let len = std::fs::metadata(&p).expect("segment 2's header file must EXIST").len();
    assert_eq!(len, 10 * 132, "segment 2 does not hold the ten live headers: {len} bytes");

    assert_eq!(
        r.verify_segment_headers(2).expect("live segment verdict"),
        None,
        "a live, partially filled header segment was JUDGED. It is a moving object: a \
         tier that judges it reads 'bad' on every healthy node between boundaries and is \
         then ignored, which is worse than not running at all."
    );

    assert_eq!(r.verify_segment_headers(0).expect("seg 0"), Some(SEG));
    assert_eq!(r.verify_segment_headers(1).expect("seg 1"), Some(SEG));
    println!("  live segment 2 ({len} bytes on disk): Ok(None), sealed 0 and 1 judged");
    drop(c);
    drop(r);
}

#[test]
fn full_file_below_wm_not_judged() {
    let _g = serial();
    let s = Scratch::new("hdrlink-scratch");
    let (mut c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(rep.integrity.is_clean(), "a fresh store reported damage");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let main = chain.build(SEG + 10, 1);
    c.extend(&common::commits(&main)).unwrap();
    c.flush().unwrap();
    assert_eq!(r.hdr_watermark(), SEG + 10);
    assert_eq!(
        r.verify_segment_headers(0).expect("sealed verdict"),
        Some(SEG),
        "segment 0 is sealed before the reorg and must be judged, or this test proves \
         nothing about the guard"
    );
    let full = std::fs::metadata(hseg(&s, 0)).unwrap().len();
    assert_eq!(full, SEG * 132, "segment 0 is not at the sealed length to begin with");

    let old_tip = r.tip().height;
    let fork = SEG - 5;
    chain.rewind(&main, fork, main[fork as usize].hash);
    let alt = chain.build(2, 7);
    let rollback: Vec<u64> = (fork + 1..=old_tip).rev().collect();
    let cs = common::commits(&alt);
    c.reorg(&ReorgPlan { fork_height: fork, rollback: &rollback, apply: &cs })
        .expect("reorg across the segment boundary");
    drop(cs);

    let wm = r.hdr_watermark();
    assert!(wm < SEG, "the reorg did not drop the watermark below the boundary: {wm}");

    let after = std::fs::metadata(hseg(&s, 0)).unwrap().len();
    assert_eq!(
        after, full,
        "segment 0 was truncated by the reorg; the scratch-above-the-watermark case this \
         test is built on no longer exists"
    );

    assert_eq!(
        r.verify_segment_headers(0).expect("post-reorg verdict"),
        None,
        "a segment whose top is scratch above the watermark was JUDGED. The verdict would \
         have been computed over headers belonging to a branch this store abandoned, and \
         it would have looked clean."
    );
    println!("  wm={wm} < {SEG}, file still {after} B: Ok(None)");
    drop(c);
    drop(r);
}
