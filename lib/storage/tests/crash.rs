mod common;

use std::process::Command;

use common::{body, commits, serial, Chain, Scratch};
use plaine_consensus::crypto::header_hash;
use plaine_storage::{open, DurabilityMode, ReorgPlan, StallPoint};

const ENV_POINT: &str = "PLAINE_CRASH_POINT";
const ENV_DIR: &str = "PLAINE_CRASH_DIR";
const ENV_MODE: &str = "PLAINE_CRASH_MODE";

const WARM: u64 = 30;
const FORK: u64 = 20;
const ALT: u64 = 12;

fn chain() -> Chain {
    Chain::new(16, 96, 2)
}

fn cfg_for(dir: &std::path::Path) -> plaine_storage::StoreConfig {
    let mut c = plaine_storage::StoreConfig::new(dir, plaine_storage::Network::Main);
    c.page_cache_bytes = 4 * 1024 * 1024;
    c.ibd_batch_blocks = Some(8);
    c.state_ckpt_interval = 0;
    c
}

fn point_of(name: &str) -> StallPoint {
    match name {
        "AfterHeaderWrite" => StallPoint::AfterHeaderWrite,
        "AfterBodyWrite" => StallPoint::AfterBodyWrite,
        "BeforeRedbCommit" => StallPoint::BeforeRedbCommit,
        "AfterRedbCommit" => StallPoint::AfterRedbCommit,
        "ReorgAfterUndoWritten" => StallPoint::ReorgAfterUndoWritten,
        "ReorgMidHeaderOverwrite" => StallPoint::ReorgMidHeaderOverwrite,
        "ReorgBeforeStateCommit" => StallPoint::ReorgBeforeStateCommit,
        "AfterSegmentSeal" => StallPoint::AfterSegmentSeal,
        "PruneAfterFloorCommitted" => StallPoint::PruneAfterFloorCommitted,
        "PruneMidUnlink" => StallPoint::PruneMidUnlink,
        "BeforeBoundaryCommit" => StallPoint::BeforeBoundaryCommit,
        "AfterBoundaryCommit" => StallPoint::AfterBoundaryCommit,
        other => panic!("unknown stall point {other}"),
    }
}

const SEG: u64 = plaine_storage::SEG_BLOCKS;

fn cfg_big(dir: &std::path::Path) -> plaine_storage::StoreConfig {
    let mut c = cfg_for(dir);
    c.ibd_batch_blocks = Some(2_048);
    c
}

fn worker_boundary(dir: &std::path::Path, want: StallPoint) -> ! {
    let (mut c, _r, _) = open(cfg_big(dir)).expect("child open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = Chain::new(16, 96, 2);
    let warm = ch.build(SEG, 1);
    c.extend(&commits(&warm)).unwrap();
    c.flush().unwrap();
    c.set_mode(DurabilityMode::Tip).unwrap();
    c.set_stall_hook(Box::new(move |p| {
        if p == want {
            std::process::exit(9);
        }
    }));
    let next = ch.build(1, 1);
    let _ = c.extend(&commits(&next));
    std::process::exit(0);
}

fn worker_anchor(dir: &std::path::Path, want: StallPoint) -> ! {
    let (mut c, _r, _) = open(cfg_big(dir)).expect("child open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = Chain::new(16, 96, 2);
    let warm = ch.build(SEG - 1, 1);
    c.extend(&commits(&warm)).unwrap();
    c.flush().unwrap();
    c.set_mode(DurabilityMode::Tip).unwrap();
    c.set_stall_hook(Box::new(move |p| {
        if p == want {
            std::process::exit(9);
        }
    }));
    let next = ch.build(1, 1);
    let _ = c.extend(&commits(&next));
    std::process::exit(0);
}

fn worker_prune(dir: &std::path::Path, want: StallPoint) -> ! {
    let (mut c, _r, _) = open(cfg_big(dir)).expect("child open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = Chain::new(16, 96, 2);
    let warm = ch.build(2 * SEG, 1);
    c.extend(&commits(&warm)).unwrap();
    c.flush().unwrap();
    c.set_stall_hook(Box::new(move |p| {
        if p == want {
            std::process::exit(9);
        }
    }));
    let _ = c.prune_to(SEG);
    std::process::exit(0);
}

#[test]
fn crash_worker() {
    let Ok(point) = std::env::var(ENV_POINT) else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var(ENV_DIR).expect("dir"));
    let mode = std::env::var(ENV_MODE).unwrap_or_else(|_| "extend".into());
    let want = point_of(&point);

    match mode.as_str() {
        "boundary" => worker_boundary(&dir, want),
        "prune" => worker_prune(&dir, want),
        "anchor" => worker_anchor(&dir, want),
        _ => {}
    }

    let (mut c, _r, _) = open(cfg_for(&dir)).expect("child open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = chain();
    let main = ch.build(WARM, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    c.set_mode(DurabilityMode::Tip).unwrap();

    c.set_stall_hook(Box::new(move |p| {
        if p == want {
            std::process::exit(9);
        }
    }));

    if mode == "reorg" {
        ch.rewind(&main, FORK, main[FORK as usize].hash);
        let alt = ch.build(ALT, 2);
        let rollback: Vec<u64> = (FORK + 1..WARM).rev().collect();
        let _ = c.reorg(&ReorgPlan {
            fork_height: FORK,
            rollback: &rollback,
            apply: &commits(&alt),
        });
    } else {
        let next = ch.build(1, 1);
        let _ = c.extend(&commits(&next));
    }

    std::process::exit(0);
}

fn run_child(dir: &std::path::Path, point: &str, mode: &str) -> i32 {
    let exe = std::env::current_exe().expect("test exe");
    let out = Command::new(exe)
        .arg("crash_worker")
        .arg("--exact")
        .arg("--test-threads=1")
        .env(ENV_POINT, point)
        .env(ENV_DIR, dir)
        .env(ENV_MODE, mode)
        .output()
        .expect("spawn child");
    out.status.code().unwrap_or(-1)
}

fn assert_consistent(r: &plaine_storage::StoreReader) {
    let tip = r.tip();
    assert_eq!(r.hdr_watermark(), tip.height + 1);
    let mut prev: Option<[u8; 132]> = None;
    for h in 0..=tip.height {
        let cur = r
            .header_at(h)
            .unwrap()
            .unwrap_or_else(|| panic!("hole at {h}"));
        if let Some(p) = prev {
            assert_eq!(&cur[12..44], &header_hash(&p)[..], "linkage broken at {h}");
        }
        prev = Some(cur);
    }
    assert_eq!(header_hash(&prev.unwrap()), tip.hash, "tip hash mismatch");
    r.verify_state_fingerprint().expect("state fingerprint");
    let mut buf = Vec::new();
    for h in 0..=tip.height {
        let n = body(r, h, &mut buf);
        if h < r.body_watermark() {
            assert!(n > 0, "body missing at {h}");
        }
    }
}

#[test]
fn kill9_at_every_tip_commit_boundary() {
    let _g = serial();
    for point in [
        "AfterHeaderWrite",
        "AfterBodyWrite",
        "BeforeRedbCommit",
        "AfterRedbCommit",
    ] {
        let s = Scratch::new(&format!("crash-{point}"));
        let code = run_child(&s.0, point, "extend");
        assert_eq!(code, 9, "child at {point} did not reach the boundary");

        let (c, r, rep) = open(cfg_for(&s.0)).expect("reopen after kill at {point}");
        let tip = r.tip().height;

        assert!(
            tip == WARM - 1 || tip == WARM,
            "{point}: tip {tip} is neither {} nor {WARM}",
            WARM - 1
        );
        if point == "AfterRedbCommit" {
            assert_eq!(tip, WARM, "the commit was durable, the block must be there");
        } else {
            assert_eq!(
                tip,
                WARM - 1,
                "{point}: an uncommitted block became visible"
            );
        }
        assert_consistent(&r);
        println!(
            "KILL -9 @{point}: tip {tip}, watermark_lowered_to {:?}, scratch discarded              {} header bytes / {} body bytes",
            rep.headers_truncated_to, rep.hdr_scratch_discarded, rep.body_scratch_discarded
        );
        drop(c);
        drop(r);
    }
}

#[test]
fn kill9_at_every_reorg_boundary() {
    let _g = serial();

    for point in [
        "ReorgAfterUndoWritten",
        "ReorgMidHeaderOverwrite",
        "ReorgBeforeStateCommit",
    ] {
        let s = Scratch::new(&format!("crash-{point}"));
        let code = run_child(&s.0, point, "reorg");
        assert_eq!(code, 9, "child at {point} did not reach the boundary");

        let (c, r, rep) = open(cfg_for(&s.0)).expect("reopen after reorg kill");
        let tip = r.tip().height;
        assert_eq!(
            tip,
            WARM - 1,
            "{point}: the reorg was not durable, so the OLD branch must be intact"
        );
        assert_consistent(&r);

        let mut ch = chain();
        let main = ch.build(WARM, 1);
        for b in main.iter() {
            assert_eq!(
                r.header_at(b.height).unwrap().unwrap(),
                b.header,
                "{point}: header {} belongs to neither branch",
                b.height
            );
        }
        println!(
            "KILL -9 @{point}: tip {tip}, hdr_undo replayed {:?}",
            rep.hdr_undo_replayed
        );
        drop(c);
        drop(r);
    }
}

#[test]
fn survived_reorg_not_reentered() {
    let _g = serial();
    let s = Scratch::new("reorg-restart");
    let (mut c, r, _) = open(cfg_for(&s.0)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = chain();
    let main = ch.build(WARM, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    ch.rewind(&main, FORK, main[FORK as usize].hash);
    let alt = ch.build(ALT, 2);
    let rollback: Vec<u64> = (FORK + 1..WARM).rev().collect();
    c.reorg(&ReorgPlan {
        fork_height: FORK,
        rollback: &rollback,
        apply: &commits(&alt),
    })
    .unwrap();
    let tip = r.tip();
    assert_eq!(tip.height, FORK + ALT);
    drop(c);
    drop(r);

    for round in 0..3 {
        let (c, r, rep) = open(cfg_for(&s.0)).expect("reopen");
        assert_eq!(r.tip(), tip, "restart {round} moved the tip");
        assert!(
            rep.hdr_undo_replayed.is_none(),
            "restart {round} re-entered the reorg"
        );
        assert!(rep.headers_truncated_to.is_none());
        assert_consistent(&r);
        drop(c);
        drop(r);
    }
}

#[test]
fn kill9_segment_seal_leaves_scratch() {
    let _g = serial();
    let s = Scratch::new("crash-seal");
    let code = run_child(&s.0, "AfterSegmentSeal", "boundary");
    assert_eq!(code, 9, "the child never reached the seal");

    let (c, r, rep) = open(cfg_for(&s.0)).expect("reopen after a kill mid-seal");
    assert_eq!(
        r.tip().height,
        SEG - 1,
        "an uncommitted block became visible"
    );
    assert_eq!(r.hdr_watermark(), SEG);
    assert!(
        rep.integrity.is_clean(),
        "a seal-time crash was reported as damage: {:?}",
        rep.integrity
    );
    assert!(!r.is_degraded());
    assert!(
        !s.0.join("segments")
            .join("hdr")
            .join("000001.hseg")
            .exists(),
        "the empty successor segment was left behind"
    );

    assert!(
        r.body_anchor(0).unwrap().is_some(),
        "the sealed segment lost its anchor"
    );
    assert!(r.body_anchor(1).unwrap().is_none(), "scratch was anchored");
    assert_eq!(rep.anchors_verified, 1);
    assert!(r.vouches_for_all_bodies(), "{:?}", r.body_vouch());
    assert_consistent(&r);
    println!(
        "KILL -9 @AfterSegmentSeal: tip {}, integrity clean, {} segments checked in {} us",
        r.tip().height,
        rep.integrity.segments_checked,
        rep.integrity.check_micros
    );
    drop(c);
    drop(r);
}

#[test]
fn kill9_sidecar_update_atomic() {
    let _g = serial();
    for point in ["BeforeRedbCommit", "AfterRedbCommit"] {
        let s = Scratch::new(&format!("crash-manifest-{point}"));
        let code = run_child(&s.0, point, "boundary");
        assert_eq!(code, 9, "the child never reached {point}");
        let (c, r, rep) = open(cfg_for(&s.0)).expect("reopen");
        let tip = r.tip().height;
        if point == "AfterRedbCommit" {
            assert_eq!(tip, SEG, "the commit was durable, the block must be there");
            assert_eq!(r.hdr_watermark(), SEG + 1);

            assert_eq!(
                std::fs::metadata(s.0.join("segments").join("hdr").join("000001.hseg"))
                    .unwrap()
                    .len(),
                132
            );
        } else {
            assert_eq!(tip, SEG - 1, "an uncommitted block became visible");
        }
        assert!(
            rep.integrity.is_clean(),
            "{point}: reported damage on a clean crash: {:?}",
            rep.integrity
        );
        assert_consistent(&r);
        println!("KILL -9 @{point} (segment boundary): tip {tip}, integrity clean");
        drop(c);
        drop(r);
    }
}

#[test]
fn kill9_at_anchor_boundary_commit() {
    let _g = serial();

    let refdir = Scratch::new("crash-anchor-reference");
    let want_anchor = {
        let (mut c, r, _) = open(cfg_big(&refdir.0)).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut ch = Chain::new(16, 96, 2);
        let bs = ch.build(SEG, 1);
        c.extend(&commits(&bs)).unwrap();
        c.flush().unwrap();
        let a = r.body_anchor(0).unwrap().expect("reference anchor");
        drop(c);
        drop(r);
        a
    };

    for point in ["BeforeBoundaryCommit", "AfterBoundaryCommit"] {
        let s = Scratch::new(&format!("crash-{point}"));
        let code = run_child(&s.0, point, "anchor");
        assert_eq!(code, 9, "the child never reached {point}");

        let (mut c, r, rep) = open(cfg_for(&s.0)).expect("reopen after a kill on the boundary");
        assert!(
            rep.integrity.is_clean(),
            "{point}: a boundary-commit crash was reported as damage: {:?}",
            rep.integrity
        );
        assert!(
            !r.is_degraded(),
            "{point}: a crash quarantined a healthy store"
        );
        assert!(
            rep.anchor_floor_raised.is_none(),
            "{point}: the floor moved"
        );
        assert_eq!(
            rep.anchors_dropped, 0,
            "{point}: an anchor was left above the watermark"
        );

        if point == "AfterBoundaryCommit" {
            assert_eq!(r.tip().height, SEG - 1);
            assert_eq!(r.body_watermark(), SEG);
            assert_eq!(r.body_anchor(0).unwrap(), Some(want_anchor));
            assert_eq!(rep.anchors_verified, 1);
            assert!(r.vouches_for_all_bodies());
        } else {
            assert_eq!(
                r.tip().height,
                SEG - 2,
                "an uncommitted block became visible"
            );
            assert_eq!(r.body_watermark(), SEG - 1);
            assert!(
                r.body_anchor(0).unwrap().is_none(),
                "an unsealed segment was anchored"
            );
            assert_eq!(rep.anchors_verified, 0);
            assert_eq!(
                rep.integrity.anchor_bytes_read, 0,
                "nothing was owed, nothing read"
            );
            let mut buf = Vec::new();
            assert!(body(&r, SEG - 2, &mut buf) > 0);

            c.set_mode(DurabilityMode::Tip).unwrap();
            let mut ch = Chain::new(16, 96, 2);
            let all = ch.build(SEG, 1);
            c.extend(&commits(&all[(SEG - 1) as usize..])).unwrap();
            c.flush().unwrap();
            assert_eq!(
                r.body_anchor(0).unwrap(),
                Some(want_anchor),
                "the re-minted anchor is not the one a crash-free run produces"
            );
        }
        assert_consistent(&r);
        println!(
            "KILL -9 @{point}: tip {}, watermark {}, anchor {}",
            r.tip().height,
            r.body_watermark(),
            if r.body_anchor(0).unwrap().is_some() {
                "durable"
            } else {
                "not owed"
            }
        );
        drop(c);
        drop(r);
    }
}

#[test]
fn kill9_prune_leaves_stale_files() {
    let _g = serial();
    for point in ["PruneAfterFloorCommitted", "PruneMidUnlink"] {
        let s = Scratch::new(&format!("crash-prune-{point}"));
        let code = run_child(&s.0, point, "prune");
        assert_eq!(code, 9, "the child never reached {point}");
        let (c, r, rep) = open(cfg_for(&s.0)).expect("reopen after a kill mid-prune");

        assert!(
            rep.integrity.is_clean(),
            "{point}: an interrupted prune was reported as DAMAGE: {:?}",
            rep.integrity
        );
        assert_eq!(r.prune_floor(), SEG, "{point}: the floor is not durable");
        assert!(!r.is_degraded());

        assert!(!s
            .0
            .join("segments")
            .join("body")
            .join("000000.bseg")
            .exists());

        assert!(
            r.body_anchor(0).unwrap().is_none(),
            "{point}: an anchor outlived the bodies it vouches for"
        );
        assert_eq!(
            r.body_anchor_count().unwrap(),
            1,
            "{point}: anchor rows must equal the retained sealed segments"
        );
        assert!(r.vouches_for_all_bodies(), "{point}: {:?}", r.body_vouch());
        let mut buf = Vec::new();
        assert!(matches!(
            r.body_at(10, &mut buf),
            Err(plaine_storage::StoreError::BodyPruned { .. })
        ));
        assert!(body(&r, SEG + 10, &mut buf) > 0);
        assert_eq!(r.tip().height, 2 * SEG - 1);
        println!(
            "KILL -9 @{point}: prune_floor {}, segments unlinked at recovery {}, integrity clean",
            r.prune_floor(),
            rep.segments_unlinked
        );
        drop(c);
        drop(r);
    }
}

#[test]
fn torn_tail_truncated_not_parsed() {
    let _g = serial();
    use std::io::{Seek, SeekFrom, Write};

    for (case, garbage) in [
        ("one byte", 1usize),
        ("partial header", 77),
        ("many blocks of junk", 4_000),
    ] {
        let s = Scratch::new(&format!("torn-{}", case.replace(' ', "-")));
        let (mut c, r, _) = open(cfg_for(&s.0)).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut ch = chain();
        let blocks = ch.build(WARM, 1);
        c.extend(&commits(&blocks)).unwrap();
        c.flush().unwrap();
        let tip = r.tip();
        drop(c);
        drop(r);

        let hseg = s.0.join("segments").join("hdr").join("000000.hseg");
        let bseg = s.0.join("segments").join("body").join("000000.bseg");
        let junk: Vec<u8> = (0..garbage).map(|i| (i * 37 + 11) as u8).collect();
        for p in [&hseg, &bseg] {
            let mut f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
            f.seek(SeekFrom::End(0)).unwrap();
            f.write_all(&junk).unwrap();
            f.sync_all().unwrap();
        }

        let (c, r, rep) = open(cfg_for(&s.0)).expect("open must repair, never refuse");
        assert_eq!(r.tip(), tip, "{case}: the tip moved");
        assert_eq!(
            std::fs::metadata(&hseg).unwrap().len(),
            132 * WARM,
            "{case}: header tail not truncated"
        );
        assert_consistent(&r);
        assert!(
            rep.hdr_scratch_discarded >= garbage as u64,
            "{case}: the header tail was not discarded"
        );
        assert!(
            rep.headers_truncated_to.is_none(),
            "{case}: committed data was lost"
        );
        println!(
            "TORN TAIL [{case}]: discarded {} header + {} body scratch bytes, tip unchanged at {}",
            rep.hdr_scratch_discarded, rep.body_scratch_discarded, tip.height
        );
        drop(c);
        drop(r);
    }
}

#[test]
fn corrupt_frame_lowers_body_wm() {
    let _g = serial();
    use std::io::{Seek, SeekFrom, Write};
    let s = Scratch::new("torn-body");
    let (mut c, r, _) = open(cfg_for(&s.0)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = chain();
    let blocks = ch.build(WARM, 1);
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();

    let bidx = s.0.join("segments").join("body").join("000000.bidx");
    let raw = std::fs::read(&bidx).unwrap();
    let off = u32::from_le_bytes([raw[160], raw[161], raw[162], raw[163]]) as u64;
    drop(c);
    drop(r);

    let bseg = s.0.join("segments").join("body").join("000000.bseg");
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&bseg).unwrap();
        f.seek(SeekFrom::Start(off + 8)).unwrap();
        f.write_all(&[0xA5]).unwrap();
        f.sync_all().unwrap();
    }
    let (c, r, rep) = open(cfg_for(&s.0)).expect("open must repair");

    assert_eq!(r.hdr_watermark(), WARM);
    assert_eq!(r.body_watermark(), 20, "body watermark did not come down");
    assert!(rep.bodies_truncated_to.is_some());
    let mut buf = Vec::new();
    assert_eq!(body(&r, 19, &mut buf), blocks[19].body.len());
    assert_eq!(body(&r, 20, &mut buf), 0, "a bad frame was served");
    assert_consistent(&r);
    drop(c);
    drop(r);
}

#[test]
fn rotted_length_no_alloc() {
    let _g = serial();
    use std::io::{Seek, SeekFrom, Write};
    let s = Scratch::new("bad-length");
    let (mut c, r, _) = open(cfg_for(&s.0)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = chain();
    let blocks = ch.build(WARM, 1);
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();
    let bidx = s.0.join("segments").join("body").join("000000.bidx");
    let raw = std::fs::read(&bidx).unwrap();
    let off = u32::from_le_bytes([raw[80], raw[81], raw[82], raw[83]]) as u64;
    drop(c);
    drop(r);

    let bseg = s.0.join("segments").join("body").join("000000.bseg");
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&bseg).unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        f.write_all(&u32::MAX.to_le_bytes()).unwrap();
        f.sync_all().unwrap();
    }
    let t = std::time::Instant::now();
    let (c, r, _) = open(cfg_for(&s.0)).expect("open must repair, not allocate");
    let micros = t.elapsed().as_micros();
    assert_eq!(r.body_watermark(), 10);
    assert_eq!(r.hdr_watermark(), WARM);
    println!("BOGUS LENGTH u32::MAX repaired in {micros} us");
    assert_consistent(&r);
    drop(c);
    drop(r);
}

#[test]
fn derived_index_rebuilt() {
    let _g = serial();
    let s = Scratch::new("index-rebuild");
    let (mut c, r, _) = open(cfg_for(&s.0)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = chain();
    let blocks = ch.build(200, 1);
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();
    c.mark_index_stale().unwrap();
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg_for(&s.0)).expect("reopen");
    assert!(rep.index_rebuilt, "the owed rebuild was skipped");
    for b in blocks.iter().step_by(13) {
        assert_eq!(
            r.header_by_hash(&b.hash).unwrap().map(|(h, _)| h),
            Some(b.height)
        );
    }
    drop(c);
    drop(r);
}
