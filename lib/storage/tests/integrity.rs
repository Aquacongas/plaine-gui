mod common;

use std::collections::HashSet;

use common::{body, commits, serial, Block, Chain, Scratch};
use plaine_consensus::constants::HEADER_BYTES;
use plaine_storage::{
    open, DamageKind, DurabilityMode, RangeAvailability, SegmentKind, StoreConfig, StoreError,
};

const SEG: u64 = plaine_storage::SEG_BLOCKS;
const HDR_SEG_BYTES: u64 = plaine_storage::HDR_SEG_BYTES;

fn seed(name: &str, n: u64) -> (Scratch, Vec<Block>) {
    let s = Scratch::new(name);
    let mut cfg = s.cfg();
    cfg.state_ckpt_interval = 0;
    cfg.ibd_batch_blocks = Some(4_096);
    let (mut c, r, rep) = open(cfg).expect("open");
    assert!(rep.integrity.is_clean(), "a fresh store reported damage");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(n, 1);
    c.extend(&commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    (s, bs)
}

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c
}

fn hdr_path(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("hdr")
        .join(format!("{seg:06x}.hseg"))
}
fn bseg_path(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bseg"))
}
fn bidx_path(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bidx"))
}

fn truncate_by(p: &std::path::Path, by: u64) {
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    let len = f.metadata().unwrap().len();
    f.set_len(len - by).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn s1_body_hole_is_damage_not_pruning() {
    let _g = serial();
    let (s, bs) = seed("int-s1", 3 * SEG);

    std::fs::remove_file(bseg_path(&s, 1)).unwrap();
    std::fs::remove_file(bidx_path(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("degraded is the default, so open must succeed");

    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert!(rep.integrity.header_damage.is_empty(), "headers are intact");
    let d = rep.integrity.body_damage[0];
    assert_eq!(d.kind, SegmentKind::Body);
    assert_eq!(d.segment, 1);
    assert_eq!(d.first_height, SEG);
    assert_eq!(d.last_height, 2 * SEG - 1);

    assert_eq!(d.reason, DamageKind::Missing);
    assert_eq!(
        d.actual_len, None,
        "an absent file is not a zero-length one"
    );

    assert_eq!(r.prune_floor(), 0, "a hole was laundered into a prune");
    assert_eq!(r.body_watermark(), 3 * SEG);
    assert_eq!(r.tip().height, 3 * SEG - 1);
    assert_eq!(rep.bodies_truncated_to, None);

    let mut buf = Vec::new();
    match r.body_at(5_000, &mut buf) {
        Err(StoreError::SegmentDamaged {
            segment,
            height,
            first_height,
            last_height,
            reason,
            ..
        }) => {
            assert_eq!((segment, height), (1, 5_000));
            assert_eq!((first_height, last_height), (SEG, 2 * SEG - 1));
            assert_eq!(reason, DamageKind::Missing);
        }
        other => panic!("a body hole answered {other:?} instead of naming itself"),
    }
    assert!(matches!(
        r.body_availability(5_000),
        RangeAvailability::Damaged {
            first: 4_096,
            last: 8_191,
            ..
        }
    ));

    assert_eq!(body(&r, 1_000, &mut buf), bs[1_000].body.len());
    assert_eq!(body(&r, 9_000, &mut buf), bs[9_000].body.len());
    assert_eq!(r.body_availability(1_000), RangeAvailability::Verified);
    assert!(
        r.header_at(5_000).unwrap().is_some(),
        "headers were not touched"
    );
    assert!(r.is_degraded());
    assert_eq!(r.damaged_ranges().len(), 1);
    r.verify_state_fingerprint().unwrap();
    drop(c);
    drop(r);

    let (c2, _r2, rep2) = open(cfg_of(&s)).expect("reopen");
    assert_eq!(rep2.integrity.body_damage, rep.integrity.body_damage);
    drop(c2);
}

#[test]
fn s1b_short_body_names_first_lost() {
    let _g = serial();
    let (s, _bs) = seed("int-s1b", 3 * SEG);
    let full = std::fs::metadata(bseg_path(&s, 1)).unwrap().len();
    truncate_by(&bseg_path(&s, 1), full / 3);
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(rep.integrity.body_damage.len(), 1);
    let d = rep.integrity.body_damage[0];
    assert_eq!(d.reason, DamageKind::Short);
    assert_eq!(d.segment, 1);
    assert_eq!(d.last_height, 2 * SEG - 1);

    assert!(d.first_height > SEG && d.first_height < 2 * SEG - 1);
    let mut buf = Vec::new();
    assert!(body(&r, d.first_height - 1, &mut buf) > 0);
    assert!(r.body_at(d.first_height, &mut buf).is_err());
    drop(c);
}

#[test]
fn s2_short_header_detected_repairable() {
    let _g = serial();
    let (s, bs) = seed("int-s2", 3 * SEG);

    truncate_by(&hdr_path(&s, 1), 132 * 40);

    let (mut c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.header_damage[0];
    assert_eq!(d.kind, SegmentKind::Header);
    assert_eq!(d.segment, 1);
    assert_eq!(d.expected_len, HDR_SEG_BYTES);
    assert_eq!(d.actual_len, Some(HDR_SEG_BYTES - 132 * 40));
    assert_eq!(
        d.first_height, 8_152,
        "the first height the bytes cannot back"
    );
    assert_eq!(d.last_height, 8_191);
    assert_eq!(d.reason, DamageKind::Short);

    assert_eq!(r.hdr_watermark(), 3 * SEG);
    assert_eq!(rep.headers_truncated_to, None);

    let mut out = Vec::new();
    assert!(
        r.headers_range(8_140, 100, &mut out).is_err(),
        "a range across a hole was served short again"
    );
    assert!(r.header_at(8_160).unwrap_or(None).is_none());
    assert!(matches!(
        r.header_at(8_160),
        Err(StoreError::SegmentDamaged { .. })
    ));

    assert_eq!(r.headers_range(8_000, 100, &mut out).unwrap(), 100);
    assert_eq!(r.header_at(8_192).unwrap().unwrap(), bs[8_192].header);

    let fix: Vec<[u8; HEADER_BYTES]> = (8_152..=8_191u64).map(|h| bs[h as usize].header).collect();
    assert_eq!(c.repair_headers(8_152, &fix).unwrap(), 40);
    assert!(!c.is_degraded());
    assert!(!r.is_degraded(), "the reader still thinks it is degraded");
    assert_eq!(r.headers_range(8_140, 100, &mut out).unwrap(), 100);
    assert_eq!(r.header_at(8_160).unwrap().unwrap(), bs[8_160].header);

    assert_eq!(
        r.header_by_hash(&bs[8_160].hash).unwrap().map(|(h, _)| h),
        Some(8_160)
    );
    drop(c);
    drop(r);

    let (c2, _r2, rep2) = open(cfg_of(&s)).expect("reopen");
    assert!(rep2.integrity.is_clean(), "{:?}", rep2.integrity);
    assert_eq!(
        std::fs::metadata(hdr_path(&s, 1)).unwrap().len(),
        HDR_SEG_BYTES
    );
    drop(c2);
}

#[test]
fn s2b_repair_needs_both_anchors() {
    let _g = serial();
    let (s, bs) = seed("int-s2b", 3 * SEG);
    truncate_by(&hdr_path(&s, 1), 132 * 40);
    let (mut c, r, _rep) = open(cfg_of(&s)).expect("open");

    let good: Vec<[u8; HEADER_BYTES]> = (8_152..=8_191u64).map(|h| bs[h as usize].header).collect();

    let mut bad_top = good.clone();
    bad_top[39][124..132].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
    assert!(
        matches!(
            c.repair_headers(8_152, &bad_top),
            Err(StoreError::LinkageBroken { .. })
        ),
        "a run with a broken upper anchor was accepted"
    );

    let mut bad_mid = good.clone();
    bad_mid[20][12..44].copy_from_slice(&[0x11u8; 32]);
    assert!(matches!(
        c.repair_headers(8_152, &bad_mid),
        Err(StoreError::LinkageBroken { .. })
    ));

    assert!(matches!(
        c.repair_headers(8_160, &good[8..]),
        Err(StoreError::BadPlan(_))
    ));

    assert!(c.is_degraded());
    assert!(matches!(
        r.header_at(8_160),
        Err(StoreError::SegmentDamaged { .. })
    ));
    assert_eq!(
        std::fs::metadata(hdr_path(&s, 1)).unwrap().len(),
        HDR_SEG_BYTES - 132 * 40,
        "a rejected repair still touched the file"
    );

    assert_eq!(c.repair_headers(8_152, &good).unwrap(), 40);
    drop(c);
}

#[test]
fn s3_missing_header_bounds_locator() {
    let _g = serial();
    let (s, bs) = seed("int-s3", 3 * SEG);
    std::fs::remove_file(hdr_path(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.header_damage[0];
    assert_eq!(d.segment, 1);
    assert_eq!((d.first_height, d.last_height), (SEG, 2 * SEG - 1));
    assert_eq!(d.reason, DamageKind::Missing);
    assert_eq!(d.expected_len, HDR_SEG_BYTES);
    assert_eq!(d.actual_len, None);
    assert_eq!(r.hdr_watermark(), 3 * SEG, "the chain suffix was destroyed");

    assert_eq!(r.intact_header_floor(), 2 * SEG);
    let mut loc = [[0u8; 32]; 32];
    let n = r.locator(&mut loc).unwrap();
    assert!(n > 0);
    let intact: HashSet<[u8; 32]> = bs[(2 * SEG) as usize..].iter().map(|b| b.hash).collect();
    for h in loc.iter().take(n) {
        assert!(
            intact.contains(h),
            "the locator advertised a hash from below the intact floor"
        );
    }
    drop(c);
    drop(r);
}

#[test]
fn pruning_and_damage_reported_apart() {
    let _g = serial();
    let s = Scratch::new("int-prune-vs-damage");
    let mut cfg = s.cfg();
    cfg.prune = true;
    cfg.body_retain_blocks = 2 * SEG;
    cfg.state_ckpt_interval = 0;
    cfg.ibd_batch_blocks = Some(4_096);
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(6 * SEG, 1);
    c.extend(&commits(&bs)).unwrap();
    c.flush().unwrap();
    let floor = r.prune_floor();
    assert!(floor > 0, "nothing was pruned");
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg_of(&s)).expect("reopen");
    assert!(
        rep.integrity.is_clean(),
        "pruning was reported as damage: {:?}",
        rep.integrity
    );
    assert!(!r.is_degraded());
    assert_eq!(r.prune_floor(), floor);
    drop(c);
    drop(r);

    let victim = (floor / SEG) as u32 + 1;
    std::fs::remove_file(bseg_path(&s, victim)).unwrap();
    std::fs::remove_file(bidx_path(&s, victim)).unwrap();
    let (c, r, rep) = open(cfg_of(&s)).expect("reopen");
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(r.prune_floor(), floor, "the floor moved to cover the hole");

    let pruned_h = floor - 1;
    let damaged_h = (victim as u64) * SEG + 7;
    let mut buf = Vec::new();
    assert!(matches!(
        r.body_at(pruned_h, &mut buf),
        Err(StoreError::BodyPruned { .. })
    ));
    assert!(matches!(
        r.body_at(damaged_h, &mut buf),
        Err(StoreError::SegmentDamaged { .. })
    ));
    assert!(matches!(
        r.body_availability(pruned_h),
        RangeAvailability::Pruned { .. }
    ));
    assert!(matches!(
        r.body_availability(damaged_h),
        RangeAvailability::Damaged { .. }
    ));
    drop(c);
    drop(r);
}

#[test]
fn degraded_node_wont_answer_hole() {
    let _g = serial();
    let (s, bs) = seed("int-degraded", 3 * SEG);
    std::fs::remove_file(hdr_path(&s, 1)).unwrap();
    std::fs::remove_file(bseg_path(&s, 1)).unwrap();
    std::fs::remove_file(bidx_path(&s, 1)).unwrap();
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(rep.integrity.header_damage.len(), 1);
    assert_eq!(rep.integrity.body_damage.len(), 1);
    assert_eq!(rep.integrity.damaged_blocks(), 2 * SEG);

    let mut out = Vec::new();
    let mut buf = Vec::new();
    for h in [SEG, SEG + 1, SEG + 2_000, 2 * SEG - 2, 2 * SEG - 1] {
        assert!(r.header_at(h).is_err(), "header_at({h}) answered");
        assert!(r.hash_at(h).is_err(), "hash_at({h}) answered");
        assert!(
            r.headers_range(h, 4, &mut out).is_err(),
            "headers_range({h}) answered"
        );
        assert!(r.body_at(h, &mut buf).is_err(), "body_at({h}) answered");

        match r.body_at(h, &mut buf) {
            Err(StoreError::BodyPruned { .. }) => panic!("body_at({h}) said pruned"),
            Ok(n) => panic!("body_at({h}) returned {n:?}"),
            Err(_) => {}
        }
        assert!(matches!(
            r.header_availability(h),
            RangeAvailability::Damaged { .. }
        ));
        assert!(matches!(
            r.body_availability(h),
            RangeAvailability::Damaged { .. }
        ));

        assert!(
            r.header_by_hash(&bs[h as usize].hash).is_err(),
            "header_by_hash answered for a height in the hole"
        );
    }

    assert!(matches!(
        r.header_by_hash(&[0x5Au8; 32]),
        Err(StoreError::UnknownWhileDegraded { .. })
    ));

    assert!(r.undo_at(3 * SEG - 5).unwrap().is_some());
    assert!(r.chainwork_at(r.tip().height).unwrap().is_some());
    assert!(r.account(&common::addr(3)).is_ok());
    assert!(r.verify_state_fingerprint().is_ok());

    assert_eq!(r.header_at(100).unwrap().unwrap(), bs[100].header);
    assert_eq!(
        body(&r, 2 * SEG + 5, &mut buf),
        bs[(2 * SEG + 5) as usize].body.len()
    );
    drop(c);
    drop(r);
}

#[test]
fn deep_reorg_names_hole_not_floor() {
    let _g = serial();
    let s = Scratch::new("int-replay-damaged");
    let mut cfg = s.cfg();
    cfg.state_ckpt_interval = 1_024;
    cfg.state_ckpt_keep = 8;
    cfg.ibd_batch_blocks = Some(1_024);
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(3 * SEG, 1);
    c.extend(&commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    std::fs::remove_file(bseg_path(&s, 1)).unwrap();
    std::fs::remove_file(bidx_path(&s, 1)).unwrap();

    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    let fork = 2 * SEG + 10;
    let rewind_to = r.checkpoint_at_or_below(SEG - 1).unwrap().unwrap_or(0);
    let e = c.deep_reorg(&plaine_storage::DeepReorgPlan {
        fork_height: fork,
        rewind_to,
        replay: &[],
        apply: &[],
    });
    match e {
        Err(StoreError::ReplayRangeDamaged {
            damaged_first,
            damaged_last,
            ..
        }) => {
            assert_eq!((damaged_first, damaged_last), (SEG, 2 * SEG - 1));
        }
        other => panic!("expected ReplayRangeDamaged, got {other:?}"),
    }
    drop(c);
}

#[test]
fn strict_integrity_refuses_start() {
    let _g = serial();
    let (s, _bs) = seed("int-strict", 3 * SEG);
    std::fs::remove_file(hdr_path(&s, 1)).unwrap();

    let mut strict = cfg_of(&s);
    strict.strict_integrity = true;
    match open(strict).map(|(c, r, _)| {
        drop(c);
        drop(r);
    }) {
        Err(StoreError::IntegrityRefused {
            damaged_ranges,
            first,
        }) => {
            assert_eq!(damaged_ranges, 1);
            assert!(first.contains("000001"), "{first}");
        }
        other => panic!("strict_integrity did not refuse: {other:?}"),
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("the default must start degraded");
    assert!(r.is_degraded());
    assert_eq!(rep.integrity.header_damage.len(), 1);
    drop(c);
}

#[test]
fn scratch_above_gap_unlinked() {
    let _g = serial();
    let (s, _bs) = seed("int-gap", SEG + 100);

    std::fs::write(hdr_path(&s, 2), [0u8; 132]).unwrap();
    std::fs::write(hdr_path(&s, 4), [0u8; 132]).unwrap();
    std::fs::write(bseg_path(&s, 4), [0u8; 8]).unwrap();
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(!hdr_path(&s, 2).exists(), "segment 2 survived");
    assert!(
        !hdr_path(&s, 4).exists(),
        "segment 4 above the gap survived"
    );
    assert!(!bseg_path(&s, 4).exists());
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    assert_eq!(r.hdr_watermark(), SEG + 100);
    drop(c);
}

#[test]
fn overlong_truncated_losslessly() {
    let _g = serial();
    let (s, bs) = seed("int-overlong", 3 * SEG);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(hdr_path(&s, 1))
            .unwrap();
        f.write_all(&[0xAB; 5_000]).unwrap();
        f.sync_all().unwrap();
    }
    let (c, r, rep) = open(cfg_of(&s)).expect("open");

    assert_eq!(rep.integrity.overlong_truncated.len(), 1);
    assert_eq!(
        rep.integrity.overlong_truncated[0].reason,
        DamageKind::Overlong
    );
    assert!(rep.hdr_scratch_discarded >= 5_000);
    assert!(
        rep.integrity.is_clean(),
        "an overlong segment was left as damage"
    );
    assert_eq!(
        std::fs::metadata(hdr_path(&s, 1)).unwrap().len(),
        HDR_SEG_BYTES
    );
    assert_eq!(r.header_at(8_000).unwrap().unwrap(), bs[8_000].header);
    drop(c);
}

#[test]
fn empty_body_refused() {
    let _g = serial();
    let s = Scratch::new("int-empty-body");
    let (mut c, _r, _) = open(cfg_of(&s)).expect("open");
    let mut chain = Chain::new(8, 32, 1);
    let mut b = chain.build(1, 1);
    b[0].body.clear();
    assert!(matches!(
        c.extend(&commits(&b)),
        Err(StoreError::BadPlan(m)) if m.contains("non-empty")
    ));
    drop(c);
}

#[test]
fn lost_sidecar_rebuilt_from_segment() {
    let _g = serial();
    let (s, bs) = seed("int-sidecar", 3 * SEG);
    std::fs::remove_file(bidx_path(&s, 1)).unwrap();
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.integrity.is_clean(),
        "a derived sidecar was left as permanent damage: {:?}",
        rep.integrity
    );
    assert!(
        rep.bidx_rebuilt_segments.contains(&1),
        "the rebuild was not reported"
    );
    assert!(!r.is_degraded());
    let mut buf = Vec::new();
    for h in [SEG, SEG + 1_234, 2 * SEG - 1] {
        assert_eq!(body(&r, h, &mut buf), bs[h as usize].body.len());
        assert_eq!(buf, bs[h as usize].body);
    }
    assert_eq!(
        std::fs::metadata(bidx_path(&s, 1)).unwrap().len(),
        SEG * 8,
        "the rebuilt sidecar is not exactly one sealed segment long"
    );
    drop(c);
    drop(r);

    truncate_by(&bseg_path(&s, 1), 4_000);
    std::fs::remove_file(bidx_path(&s, 1)).unwrap();
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert!(r.is_degraded());
    drop(c);
}

#[test]
fn wrong_gen_body_caught_by_frame() {
    let _g = serial();
    let (s, _bs) = seed("int-frame", 3 * SEG);
    let len = std::fs::metadata(bseg_path(&s, 1)).unwrap().len();
    std::fs::write(bseg_path(&s, 1), vec![0u8; len as usize]).unwrap();
    let (c, _r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(
        rep.integrity.body_damage.len(),
        1,
        "a zero-filled segment passed"
    );
    assert_eq!(
        rep.integrity.body_damage[0].reason,
        DamageKind::FrameMismatch
    );
    drop(c);
}

#[test]
fn broken_boundary_caught() {
    let _g = serial();
    let (s, _bs) = seed("int-link", 3 * SEG);

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(hdr_path(&s, 1))
            .unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut h = [7u8; HEADER_BYTES];
        h[12..44].copy_from_slice(&[9u8; 32]);
        f.write_all(&h).unwrap();
        f.sync_all().unwrap();
    }
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert_eq!(
        std::fs::metadata(hdr_path(&s, 1)).unwrap().len(),
        HDR_SEG_BYTES
    );
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(
        rep.integrity.header_damage[0].reason,
        DamageKind::LinkBroken
    );
    assert_eq!(rep.integrity.header_damage[0].first_height, SEG);
    assert!(r.header_at(SEG).is_err());
    drop(c);
}

#[test]
fn scan_cost_stays_linear() {
    let _g = serial();
    println!("\nSEGMENT-SET SWEEP COST (debug build, quiet machine assumed for shape only)");
    let mut per_seg = Vec::new();
    for segs in [1u64, 4, 16] {
        let (s, _bs) = seed(&format!("int-cost-{segs}"), segs * SEG);
        let (c, _r, rep) = open(cfg_of(&s)).expect("reopen");
        let checked = rep.integrity.segments_checked.max(1) as f64;
        let us = rep.integrity.check_micros as f64;
        println!(
            "  {segs:>2} segments: segments_checked {:>3}  check {:>6} us ({:>6.1} us/segment)  \
             open {:>7} us  sweep is {:>4.1}% of open",
            rep.integrity.segments_checked,
            rep.integrity.check_micros,
            us / checked,
            rep.open_micros,
            100.0 * us / rep.open_micros.max(1) as f64
        );
        per_seg.push(us / checked);

        assert!(
            rep.integrity.check_micros < rep.open_micros,
            "the sweep out-costs the whole open"
        );
        drop(c);
    }

    assert!(
        per_seg[2] < per_seg[0].max(1.0) * 4.0,
        "per-segment cost grew with chain length: {per_seg:?}"
    );
}
