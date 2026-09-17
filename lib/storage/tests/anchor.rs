mod common;

use common::{body, body_verified, commits, machine_note, serial, tag, Chain, Scratch};
use plaine_consensus::constants::MAX_REORG_DEPTH;
use plaine_storage::{
    open, DamageKind, DurabilityMode, StoreConfig, StoreError, UnverifiableCause,
};

const SEG: u64 = plaine_storage::SEG_BLOCKS;

const L1_PER_SEG: u64 = plaine_storage::anchor::L1_BYTES_PER_SEGMENT;

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.prune = false;
    c.ibd_batch_blocks = Some(4_096);
    c
}

fn bseg(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bseg"))
}
fn bidx(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bidx"))
}
fn hdr(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("hdr")
        .join(format!("{seg:06x}.hseg"))
}

fn grow(cfg: StoreConfig, chain: &mut Chain, n: u64) {
    let (mut c, _r, _rep) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let bs = chain.build(n, 1);
    c.extend(&commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
}

fn fresh_chain() -> Chain {
    Chain::new(64, 64, 2)
}

#[test]
fn lost_sidecar_rebuilt_verifies() {
    let _g = serial();
    let s = Scratch::new("anchor-honest-rebuild");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, 3 * SEG);

    std::fs::remove_file(bidx(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.bidx_rebuilt_segments.contains(&1),
        "an honest lost sidecar was not rebuilt: {rep:?}"
    );
    assert!(
        rep.integrity.is_clean(),
        "an honest lost sidecar was called damage: {:?}",
        rep.integrity
    );
    assert!(!r.is_degraded(), "a healthy store was quarantined");
    assert_eq!(
        r.body_availability(SEG + 7),
        plaine_storage::RangeAvailability::Verified
    );
    let mut buf = Vec::new();
    assert!(body_verified(&r, SEG + 7, &mut buf) > 0);
    assert!(r.vouches_for_all_bodies(), "{:?}", r.body_vouch());
    println!(
        "  honest lost sidecar: rebuilt, GEOM reproduced, {} anchors verified",
        rep.anchors_verified
    );
    drop(c);
}

#[test]
fn overlong_truncated_still_verifies() {
    use std::io::{Seek, SeekFrom, Write};
    let _g = serial();
    let s = Scratch::new("anchor-overlong");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, 3 * SEG);
    let before = std::fs::metadata(bseg(&s, 1)).unwrap().len();
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(bseg(&s, 1))
            .unwrap();
        f.seek(SeekFrom::Start(before + 50_000)).unwrap();
        f.write_all(&[0xAB; 4_096]).unwrap();
        f.sync_all().unwrap();
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(
        rep.integrity.overlong_truncated.len(),
        1,
        "{:?}",
        rep.integrity
    );
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    assert_eq!(std::fs::metadata(bseg(&s, 1)).unwrap().len(), before);
    assert_eq!(
        r.body_availability(SEG + 7),
        plaine_storage::RangeAvailability::Verified
    );
    assert!(r.vouches_for_all_bodies());
    drop(c);
}

#[test]
fn header_damage_not_body_damage() {
    let _g = serial();
    let s = Scratch::new("anchor-header-damage");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, 3 * SEG);

    let zeros = vec![0u8; plaine_storage::HDR_SEG_BYTES as usize];
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(hdr(&s, 1))
            .unwrap();
        f.write_all(&zeros).unwrap();
        f.sync_all().unwrap();
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(
        rep.integrity.body_damage.len(),
        0,
        "header damage became body damage: {:?}",
        rep.integrity
    );
    assert_eq!(
        rep.integrity.damaged_blocks(),
        SEG,
        "the same fault was counted twice"
    );
    assert_eq!(
        r.body_availability(SEG + 5),
        plaine_storage::RangeAvailability::Unverifiable {
            cause: UnverifiableCause::IdentityUnavailable
        }
    );

    let mut buf = Vec::new();
    assert!(body(&r, SEG + 5, &mut buf) > 0);
    println!(
        "  one damaged header segment widened the unvouched body region by {} heights, reported: {:?}",
        SEG,
        rep.unverifiable_body_ranges
    );
    drop(c);
}

#[test]
fn anchorless_store_opens_honest() {
    let _g = serial();
    let s = Scratch::new("anchor-migration");
    let mut ch = fresh_chain();

    let mut old = cfg_of(&s);
    old.anchor_mint_off = true;
    grow(old, &mut ch, 2 * SEG + 100);

    let (c, r, rep) = open(cfg_of(&s)).expect("an upgraded store must open");
    assert!(
        rep.integrity.is_clean(),
        "absence of a record was treated as damage: {:?}",
        rep.integrity
    );
    assert!(!r.is_degraded(), "an upgraded store must not be degraded");
    assert_eq!(rep.anchors_verified, 0);
    assert_eq!(rep.anchor_floor_raised, None, "no suffix gap exists here");

    assert_eq!(rep.anchor_floor, 3 * SEG);

    let mut buf = Vec::new();
    for h in [0u64, 10, SEG, SEG + 7, 2 * SEG, 2 * SEG + 99] {
        assert!(body(&r, h, &mut buf) > 0, "height {h} stopped being served");
    }

    for h in [0u64, SEG + 7] {
        assert_eq!(
            r.body_availability(h),
            plaine_storage::RangeAvailability::Unverifiable {
                cause: UnverifiableCause::PreAnchor {
                    anchor_floor: 3 * SEG
                }
            }
        );
    }
    let v = r.body_vouch();
    assert!(v.verified.is_empty(), "{v:?}");
    assert_eq!(v.unverifiable.len(), 3, "two sealed + the live tail: {v:?}");
    assert!(v.damaged.is_empty());
    assert!(!r.vouches_for_all_bodies());
    println!(
        "  upgraded store: floor {}, vouch {:?}",
        rep.anchor_floor, v
    );
    drop(c);
    drop(r);

    grow(cfg_of(&s), &mut ch, 2 * SEG);
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    assert_eq!(
        r.body_availability(2 * SEG + 5),
        plaine_storage::RangeAvailability::Unverifiable {
            cause: UnverifiableCause::UnchangedSince {
                anchor_floor: 3 * SEG
            }
        },
        "a backfilled-in-place segment reported provenance it does not have"
    );
    assert_eq!(
        r.body_availability(3 * SEG + 5),
        plaine_storage::RangeAvailability::Verified
    );
    assert_eq!(
        rep.anchors_verified, 1,
        "only segment 3 is grade 1 and sealed"
    );
    assert!(rep.anchor_floor_raised.is_none());
    println!(
        "  after the upgrade: anchors {}, verified {}, vouch {:?}",
        r.body_anchor_count().unwrap(),
        rep.anchors_verified,
        r.body_vouch()
    );
    drop(c);
}

#[test]
fn downgrade_gap_raises_floor() {
    let _g = serial();
    let s = Scratch::new("anchor-downgrade");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, SEG);
    let mut old = cfg_of(&s);
    old.anchor_mint_off = true;
    grow(old, &mut ch, 2 * SEG);

    let (c, r, rep) = open(cfg_of(&s)).expect("a downgraded store must open");
    assert!(
        rep.integrity.is_clean(),
        "a suffix gap was called damage: {:?}",
        rep.integrity
    );
    assert_eq!(
        rep.anchor_floor_raised,
        Some((0, SEG)),
        "the scar must name the exact pair"
    );
    assert_eq!(rep.anchor_floor, SEG);
    for h in [SEG + 5, 2 * SEG + 5] {
        assert_eq!(
            r.body_availability(h),
            plaine_storage::RangeAvailability::Unverifiable {
                cause: UnverifiableCause::WriterRegressed { since: SEG }
            }
        );
    }
    assert_eq!(
        r.body_availability(5),
        plaine_storage::RangeAvailability::Verified
    );
    assert!(!r.is_degraded());
    let mut buf = Vec::new();
    assert!(
        body(&r, 2 * SEG + 5, &mut buf) > 0,
        "a forgiven range stopped serving"
    );
    println!(
        "  downgrade scar: floor {:?} -> {}, {} segments unvouched, nothing damaged",
        rep.anchor_floor_raised.map(|p| p.0),
        rep.anchor_floor,
        rep.unverifiable_body_ranges.len()
    );
    drop(c);
    drop(r);

    let (c, _r, rep2) = open(cfg_of(&s)).expect("reopen");
    assert_eq!(rep2.anchor_floor, SEG);
    assert_eq!(rep2.anchor_floor_raised, None, "the floor moved twice");
    drop(c);
}

#[test]
fn interior_anchor_hole_is_damage() {
    let _g = serial();
    let s = Scratch::new("anchor-interior-hole");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, SEG);
    let mut skip = cfg_of(&s);
    skip.anchor_mint_skip = vec![1];
    grow(skip, &mut ch, 2 * SEG);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.body_damage[0];
    assert_eq!(d.reason, DamageKind::AnchorMissing);
    assert_eq!((d.first_height, d.last_height), (SEG, 2 * SEG - 1));
    assert_eq!(
        rep.anchor_floor_raised, None,
        "an interior hole moved the floor"
    );
    assert_eq!(rep.anchor_floor, 0);
    assert!(r.is_degraded());
    let mut buf = Vec::new();
    assert!(matches!(
        r.body_at(SEG + 5, &mut buf),
        Err(StoreError::SegmentDamaged { .. })
    ));

    assert!(body_verified(&r, 5, &mut buf) > 0);
    assert!(body_verified(&r, 2 * SEG + 5, &mut buf) > 0);
    drop(c);
}

#[test]
fn batch_on_boundary_anchors() {
    let _g = serial();
    let s = Scratch::new("anchor-fencepost");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, SEG);

    assert!(!bseg(&s, 1).exists(), "segment 1 should not exist");

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        r.body_anchor(0).unwrap().is_some(),
        "the sealed segment has no anchor"
    );
    assert_eq!(rep.anchors_verified, 1);
    assert_eq!(
        r.body_availability(4_000),
        plaine_storage::RangeAvailability::Verified
    );
    assert!(r.vouches_for_all_bodies());
    drop(c);
}

#[test]
fn reorg_across_boundary_remints() {
    let _g = serial();
    let s = Scratch::new("anchor-reorg");
    let mut cfg = cfg_of(&s);
    cfg.ibd_batch_blocks = Some(2_048);
    let (mut c, r, _) = open(cfg.clone()).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = fresh_chain();

    let tail = MAX_REORG_DEPTH / 3;
    let main = ch.build(SEG + tail, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    let before = r.body_anchor(0).unwrap().expect("segment 0 anchored");

    let fork = SEG - 10;
    assert!(
        SEG + tail - fork <= MAX_REORG_DEPTH,
        "the fixture outgrew the depth cap"
    );
    ch.rewind(&main, fork, main[fork as usize].hash);

    let alt = ch.build(tail + 20, 2);
    let rollback: Vec<u64> = (fork + 1..SEG + tail).rev().collect();
    c.reorg(&plaine_storage::ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &commits(&alt),
    })
    .unwrap();
    let after = r.body_anchor(0).unwrap().expect("segment 0 re-anchored");
    assert_ne!(before, after, "a stale anchor survived a reorg");
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg).expect("reopen after reorg");
    assert!(
        rep.integrity.is_clean(),
        "an honest reorg was reported as damage: {:?}",
        rep.integrity
    );
    assert_eq!(r.body_anchor(0).unwrap(), Some(after));
    assert!(r.vouches_for_all_bodies());

    let sealed = (r.body_watermark() >> 12) as i64 - 1;
    for seg in 0..8u32 {
        assert!(
            r.body_anchor(seg).unwrap().is_none() || (seg as i64) <= sealed,
            "anchor for segment {seg} above the watermark"
        );
    }
    drop(c);
}

#[test]
fn deep_reorg_no_anchor_above_wm() {
    let _g = serial();
    let s = Scratch::new("anchor-deep-reorg");
    let mut cfg = cfg_of(&s);
    cfg.state_ckpt_interval = 512;
    cfg.state_ckpt_keep = 4;
    cfg.ibd_batch_blocks = Some(512);
    let (mut c, r, _) = open(cfg.clone()).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = fresh_chain();
    let main = ch.build(SEG + 600, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    assert!(r.body_anchor(0).unwrap().is_some());

    let fork = SEG - 300;
    let rewind_to = r
        .checkpoint_at_or_below(fork)
        .unwrap()
        .expect("a checkpoint");
    let mut replay_ch = Chain::new(64, 64, 2);
    let replay_blocks = replay_ch.build(fork + 1, 1);
    ch.rewind(&main, fork, main[fork as usize].hash);
    let alt = ch.build(400, 3);
    c.deep_reorg(&plaine_storage::DeepReorgPlan {
        fork_height: fork,
        rewind_to,
        replay: &commits(&replay_blocks[(rewind_to + 1) as usize..=fork as usize]),
        apply: &commits(&alt),
    })
    .unwrap();
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg).expect("reopen after deep reorg");
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    let sealed = (r.body_watermark() >> 12) as i64 - 1;
    for seg in 0..8u32 {
        assert!(
            r.body_anchor(seg).unwrap().is_none() || (seg as i64) <= sealed,
            "anchor for segment {seg} above the watermark {}",
            r.body_watermark()
        );
    }
    assert!(r.vouches_for_all_bodies(), "{:?}", r.body_vouch());
    drop(c);
}

#[test]
fn anchor_above_wm_is_dropped() {
    use std::io::{Seek, SeekFrom, Write};
    let _g = serial();
    let s = Scratch::new("anchor-rollback");
    let mut ch = fresh_chain();

    grow(cfg_of(&s), &mut ch, 2 * SEG);
    let (c0, r0, _) = open(cfg_of(&s)).expect("open");
    assert!(r0.body_anchor(1).unwrap().is_some());
    let raw = std::fs::read(bidx(&s, 1)).unwrap();
    let off = u32::from_le_bytes([raw[800], raw[801], raw[802], raw[803]]) as u64;
    drop(c0);
    drop(r0);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(bseg(&s, 1))
            .unwrap();
        f.seek(SeekFrom::Start(off + 8)).unwrap();
        f.write_all(&[0xA5]).unwrap();
        f.sync_all().unwrap();
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("open must not refuse and must not panic");
    assert_eq!(
        r.body_watermark(),
        SEG + 100,
        "the watermark did not come down"
    );
    assert_eq!(
        rep.anchors_dropped, 1,
        "a stale anchor survived above the watermark"
    );
    assert!(r.body_anchor(1).unwrap().is_none());
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    drop(c);
    drop(r);

    let (c, _r, rep2) = open(cfg_of(&s)).expect("reopen");
    assert_eq!(rep2.anchors_dropped, 0, "the store cannot converge");
    assert!(rep2.integrity.is_clean());
    drop(c);
}

#[test]
fn pruning_drops_anchor_with_bodies() {
    let _g = serial();
    let s = Scratch::new("anchor-prune");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, 4 * SEG);

    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    assert_eq!(r.body_anchor_count().unwrap(), 4);
    let unlinked = c.prune_to(2 * SEG).unwrap();
    assert_eq!(unlinked, 2);
    assert_eq!(
        r.body_anchor_count().unwrap(),
        2,
        "anchors outlived the bodies they vouch for"
    );
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg_of(&s)).expect("reopen after prune");
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    assert_eq!(r.prune_floor(), 2 * SEG);

    let sealed_retained = 4 - 2;
    assert_eq!(r.body_anchor_count().unwrap(), sealed_retained);
    assert!(r.vouches_for_all_bodies());
    let v = r.body_vouch();
    assert_eq!(
        v.verified,
        vec![(2 * SEG, 4 * SEG - 1)],
        "runs must coalesce"
    );
    drop(c);
}

#[test]
fn deep_tier_closes_boot_gap() {
    use std::io::{Seek, SeekFrom, Write};
    let _g = serial();
    let s = Scratch::new("anchor-l2");
    let mut ch = fresh_chain();
    grow(cfg_of(&s), &mut ch, 2 * SEG);
    let (c0, r0, _) = open(cfg_of(&s)).expect("open");
    assert_eq!(r0.verify_segment_frames(0).unwrap(), Some(true));
    let raw = std::fs::read(bidx(&s, 0)).unwrap();
    let i = 2_000 * 8;
    let off = u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]) as u64;
    let len = u32::from_le_bytes([raw[i + 4], raw[i + 5], raw[i + 6], raw[i + 7]]) as usize;
    drop(c0);
    drop(r0);

    let payload = vec![0x5Au8; len];
    let crc = plaine_storage::crc32c(&payload);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(bseg(&s, 0))
            .unwrap();
        f.seek(SeekFrom::Start(off + 4)).unwrap();
        f.write_all(&crc.to_le_bytes()).unwrap();
        f.write_all(&payload).unwrap();
        f.sync_all().unwrap();
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.integrity.is_clean(),
        "L1 caught more than it claims to: {:?}",
        rep.integrity
    );
    assert_eq!(
        r.body_availability(2_000),
        plaine_storage::RangeAvailability::Verified
    );
    let mut buf = Vec::new();
    assert_eq!(
        body(&r, 2_000, &mut buf),
        len,
        "the substitution reads back clean"
    );
    assert_eq!(buf, payload, "L1 must not read interior payloads");

    assert_eq!(
        r.verify_segment_frames(0).unwrap(),
        Some(false),
        "the deep tier missed an interior substitution"
    );
    assert_eq!(
        r.verify_segment_frames(2).unwrap(),
        None,
        "segment 2 is not sealed"
    );
    println!("  L1 passes an interior CRC-fixed substitution, L2 refuses it");
    drop(c);
}

#[test]
fn l1_reads_counted_bytes() {
    let _g = serial();
    machine_note("anchor L1 boot cost");
    println!(
        "{}per sealed segment: {L1_PER_SEG} B = 32,768 sidecar + 264 header + 16 frame probe",
        tag()
    );
    let mut per_seg_us: Vec<f64> = Vec::new();
    for segs in [1u64, 2, 4, 8] {
        let s = Scratch::new(&format!("anchor-cost-{segs}"));
        let mut ch = fresh_chain();
        grow(cfg_of(&s), &mut ch, segs * SEG);
        let (c, _r, rep) = open(cfg_of(&s)).expect("open");
        assert_eq!(rep.integrity.anchor_segments_checked as u64, segs);
        assert_eq!(rep.integrity.anchors_verified as u64, segs);
        assert_eq!(
            rep.integrity.anchor_bytes_read,
            segs * L1_PER_SEG,
            "the boot tier read something nobody counted"
        );
        per_seg_us.push(rep.integrity.check_micros as f64 / segs as f64);
        println!(
            "{}{segs} sealed segment(s): {} B read (counted, exact), whole integrity sweep \
             {} us = {:.0} us/segment, of {} us open",
            tag(),
            rep.integrity.anchor_bytes_read,
            rep.integrity.check_micros,
            rep.integrity.check_micros as f64 / segs as f64,
            rep.open_micros
        );
        drop(c);
    }

    let five_year_segments = 643u64;
    let bytes = five_year_segments * L1_PER_SEG;
    assert_eq!(bytes, 21_249_864);
    println!(
        "  five-year archive, ARITHMETIC (reproduces byte for byte anywhere): \
         {five_year_segments} sealed segments x {L1_PER_SEG} B = {bytes} B = {:.2} MiB of boot \
         reads, and {} B of redb payload for the anchor rows",
        bytes as f64 / (1024.0 * 1024.0),
        five_year_segments * 69
    );
    println!(
        "  one-year full node: 129 sealed segments x {L1_PER_SEG} B = {} B = {:.2} MiB",
        129 * L1_PER_SEG,
        (129 * L1_PER_SEG) as f64 / (1024.0 * 1024.0)
    );

    let worst = per_seg_us.iter().cloned().fold(0.0f64, f64::max);
    println!(
        "{}PROJECTION, NOT A MEASUREMENT: {:.0} us/segment x {five_year_segments} segments = \
         {:.0} ms of integrity sweep at five years, DEBUG build, box not quiet. The 20.27 MiB \
         above is arithmetic and reproduces; this number does not.",
        tag(),
        worst,
        worst * five_year_segments as f64 / 1000.0
    );
}
