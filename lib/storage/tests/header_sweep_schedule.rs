mod common;

use std::path::{Path, PathBuf};

use common::{serial, Chain, Scratch};
use plaine_storage::{
    open, sweep_all, DurabilityMode, HeaderSweeper, ReorgPlan, StallPoint, StoreConfig,
    SweepTrigger, SweepVerdict,
};

const SEG: u64 = plaine_storage::SEG_BLOCKS;

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.ibd_batch_blocks = Some(4_096);
    c
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
}

fn seed_two_sealed(name: &str) -> Scratch {
    let s = Scratch::new(name);
    let (mut c, r, rep) = open(cfg_of(&s)).expect("seed open");
    assert!(rep.integrity.is_clean(), "a fresh store reported damage");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(2 * SEG + 10, 1);
    c.extend(&common::commits(&bs)).unwrap();
    c.flush().unwrap();
    assert_eq!(r.hdr_watermark(), 2 * SEG + 10);
    drop(c);
    drop(r);
    s
}

fn tear_reorg_mid_overwrite(c: &mut plaine_storage::Committer, plan: &ReorgPlan<'_>) {
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let hit = hit.clone();
        c.set_stall_hook(Box::new(move |p| {
            if p == StallPoint::ReorgMidHeaderOverwrite {
                hit.store(true, std::sync::atomic::Ordering::SeqCst);
                panic!("PLAINE_TEST_TEAR: killed between two pwrites of the header overwrite");
            }
        }));
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = c.reorg(plan);
    }));
    std::panic::set_hook(prev);
    assert!(r.is_err(), "the reorg returned normally; nothing was torn");
    assert!(
        hit.load(std::sync::atomic::Ordering::SeqCst),
        "the reorg never reached ReorgMidHeaderOverwrite"
    );
}

#[test]
fn reorg_into_sealed_queues_segment() {
    let _g = serial();
    let s = Scratch::new("sweepsched-target");
    let (mut c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let main = chain.build(SEG + 10, 1);
    c.extend(&common::commits(&main)).unwrap();
    c.flush().unwrap();

    let old_tip = r.tip().height;
    assert_eq!(old_tip, SEG + 9);
    assert_eq!(r.verify_segment_headers(0).unwrap(), Some(SEG), "segment 0 must start sealed");
    assert!(r.header_sweep_targets().is_empty(), "nothing has reorged yet");

    let fork = old_tip - 20;
    assert!(fork < SEG, "the fork must land inside sealed segment 0, not above it: {fork}");
    chain.rewind(&main, fork, main[fork as usize].hash);
    let alt = chain.build(25, 7);
    let rollback: Vec<u64> = (fork + 1..=old_tip).rev().collect();
    let cs = common::commits(&alt);
    c.reorg(&ReorgPlan { fork_height: fork, rollback: &rollback, apply: &cs })
        .expect("reorg into the sealed header segment");
    drop(cs);

    let wm = r.hdr_watermark();
    assert!(
        wm >= SEG,
        "the reorg left the watermark below the boundary ({wm}), so segment 0 is no longer \
         sealed and this test is measuring the sealed guard, not the overwrite"
    );
    assert_eq!(
        std::fs::metadata(hseg(&s, 0)).unwrap().len(),
        SEG * 132,
        "segment 0 is not at the sealed length"
    );

    assert_eq!(
        r.header_sweep_targets(),
        vec![0],
        "a reorg rewrote {} headers of a SEALED segment in place and queued nothing. That \
         is L3-H opt-in again: the one event this process can produce that breaks interior \
         header linkage went unrecorded.",
        SEG - fork - 1
    );
    println!(
        "  fork={fork} (seg 0), old_tip={old_tip}, new tip={}, wm={wm}: queued {:?}",
        r.tip().height,
        r.header_sweep_targets()
    );
    drop(c);
    drop(r);
}

#[test]
fn reorg_in_live_segment_queues_nothing() {
    let _g = serial();
    let s = seed_two_sealed("sweepsched-live");
    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let main = chain.build(2 * SEG + 10, 1);
    let old_tip = r.tip().height;
    let fork = old_tip - 5;
    assert!(fork > 2 * SEG, "the fork must be inside the live segment: {fork}");
    chain.rewind(&main, fork, main[fork as usize].hash);
    let alt = chain.build(9, 11);
    let rollback: Vec<u64> = (fork + 1..=old_tip).rev().collect();
    let cs = common::commits(&alt);
    c.reorg(&ReorgPlan { fork_height: fork, rollback: &rollback, apply: &cs })
        .expect("live-tail reorg");
    drop(cs);
    assert!(
        r.header_sweep_targets().is_empty(),
        "a reorg that touched only the live header segment queued {:?}; the sweeper can't \
         judge the live segment, so it should queue nothing here.",
        r.header_sweep_targets()
    );
    println!("  live-tail reorg at {fork}: queued nothing, correctly");
    drop(c);
    drop(r);
}

#[test]
fn sweeper_finds_named_damage() {
    let _g = serial();
    let s = Scratch::new("sweepsched-damage");
    let fork;
    {
        let (mut c, r, _) = open(cfg_of(&s)).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(64, 64, 2);
        let main = chain.build(SEG + 10, 1);
        c.extend(&common::commits(&main)).unwrap();
        c.flush().unwrap();
        let old_tip = r.tip().height;
        fork = old_tip - 20;
        chain.rewind(&main, fork, main[fork as usize].hash);
        let alt = chain.build(25, 7);
        let rollback: Vec<u64> = (fork + 1..=old_tip).rev().collect();
        let cs = common::commits(&alt);
        c.reorg(&ReorgPlan { fork_height: fork, rollback: &rollback, apply: &cs })
            .expect("reorg into the sealed header segment");
        drop(cs);
        assert_eq!(r.header_sweep_targets(), vec![0]);

        let victim = fork + 3;
        assert!(victim < SEG - 1, "the victim must be an interior header of segment 0");
        flip_bit(&hseg(&s, 0), victim * 132 + 60, 3);

        let mut sw = HeaderSweeper::new(1);
        let rep = sw.step(&r);
        println!("  {}", rep.line());
        match rep.verdict() {
            SweepVerdict::Broken(b) => assert_eq!(
                b,
                vec![(0u32, victim + 1)],
                "the sweeper named the wrong break"
            ),
            other => panic!(
                "one budgeted step over a store whose reorged sealed segment holds a flipped \
                 bit answered {other:?}. The targeted queue did not jump the budget, so the \
                 damage waits for the cursor to come round - which on a large store is the \
                 same as never."
            ),
        }
        assert!(!rep.is_clean(), "a report naming a break claimed to be clean");
        drop(c);
        drop(r);
    }
}

#[test]
fn queued_segment_walked_first() {
    let _g = serial();
    let s = Scratch::new("sweepsched-jump");
    let victim;
    {
        let (mut c, r, _) = open(cfg_of(&s)).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(64, 64, 2);
        let main = chain.build(2 * SEG + 10, 1);
        c.extend(&common::commits(&main)).unwrap();
        c.flush().unwrap();
        let old_tip = r.tip().height;

        let fork = 2 * SEG - 11;
        assert!(fork > SEG && fork < 2 * SEG - 1, "the fork must be inside sealed segment 1");
        chain.rewind(&main, fork, main[fork as usize].hash);
        let alt = chain.build(25, 7);
        let rollback: Vec<u64> = (fork + 1..=old_tip).rev().collect();
        let cs = common::commits(&alt);
        c.reorg(&ReorgPlan { fork_height: fork, rollback: &rollback, apply: &cs })
            .expect("reorg into sealed segment 1");
        drop(cs);
        assert_eq!(
            r.header_sweep_targets(),
            vec![1],
            "the reorg queued the wrong segment, or none"
        );
        assert!(r.hdr_watermark() >= 2 * SEG, "segment 1 is no longer sealed");
        victim = fork + 3;
        flip_bit(&hseg(&s, 1), (victim - SEG) * 132 + 60, 2);

        let mut sw = HeaderSweeper::new(1);
        assert_eq!(sw.cursor(), 0, "the cursor must start where the damage is not");
        let rep = sw.step(&r);
        println!("  {}", rep.line());
        match rep.verdict() {
            SweepVerdict::Broken(bk) => assert_eq!(bk, vec![(1u32, victim + 1)]),
            other => panic!(
                "one budgeted step answered {other:?}. The targeted queue did not jump the \
                 budget, so damage a reorg NAMED waits for a cursor that is 243 steps away \
                 on a real store."
            ),
        }
        assert!(rep.attempted.contains(&0), "the budgeted round-robin step did not also run");
        drop(c);
        drop(r);
    }
}

#[test]
fn torn_reorg_seeds_queue() {
    let _g = serial();
    let s = Scratch::new("sweepsched-durable");
    {
        let (mut c, r, _) = open(cfg_of(&s)).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(64, 64, 2);
        let main = chain.build(SEG + 10, 1);
        c.extend(&common::commits(&main)).unwrap();
        c.flush().unwrap();
        let old_tip = r.tip().height;
        let fork = old_tip - 20;
        assert!(fork < SEG - 1, "the fork must be inside sealed segment 0");
        chain.rewind(&main, fork, main[fork as usize].hash);
        let alt = chain.build(25, 7);
        let rollback: Vec<u64> = (fork + 1..=old_tip).rev().collect();
        let cs = common::commits(&alt);
        tear_reorg_mid_overwrite(
            &mut c,
            &ReorgPlan { fork_height: fork, rollback: &rollback, apply: &cs },
        );
        c.abandon();
        drop(cs);
        drop(r);
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("reopen after the torn reorg");
    assert!(
        rep.hdr_undo_replayed.is_some(),
        "recovery replayed no header undo, so this test is not about a torn reorg at all"
    );
    assert_eq!(
        r.header_sweep_targets(),
        vec![0],
        "a reorg torn inside SEALED header segment 0 was replayed by recovery and then \
         nothing was queued to look at it. The one case this tier exists for is the one \
         case an in-memory queue cannot survive."
    );
    let mut sw = HeaderSweeper::new(1);
    let st = sw.step(&r);
    println!("  {}", st.line());
    assert!(st.judged.contains(&0), "the seeded target was not walked on the first step");
    assert!(st.is_clean(), "recovery left segment 0 holding a mix of two branches");
    drop(c);
    drop(r);
}

#[test]
fn periodic_sweeper_reaches_damage() {
    let _g = serial();
    let s = seed_two_sealed("sweepsched-cursor");
    flip_bit(&hseg(&s, 1), 1_000 * 132 + 60, 5);
    let (c, r, _) = open(cfg_of(&s)).expect("open");
    assert!(r.header_sweep_targets().is_empty(), "nothing queued this; the cursor must find it");

    let mut sw = HeaderSweeper::new(1);
    let s0 = sw.step(&r);
    println!("  step 1: {}", s0.line());
    assert_eq!(
        s0.verdict(),
        SweepVerdict::Clean { segments: 1, links: SEG },
        "step one should have walked exactly sealed segment 0"
    );
    assert_eq!(sw.cursor(), 1, "the cursor did not advance");
    assert_eq!(sw.cycles(), 0);

    let s1 = sw.step(&r);
    println!("  step 2: {}", s1.line());
    match s1.verdict() {
        SweepVerdict::Broken(b) => {
            assert_eq!(b, vec![(1u32, 2 * SEG - (SEG - 1_001))], "wrong height named")
        }
        other => panic!("step two over the damaged segment answered {other:?}"),
    }

    let s2 = sw.step(&r);
    println!("  step 3: {}", s2.line());
    assert_eq!(
        s2.verdict(),
        SweepVerdict::NothingJudged,
        "the live top segment was reported as something other than unjudgeable"
    );
    assert!(s2.wrapped, "the cursor did not wrap at the top");
    assert_eq!(sw.cycles(), 1);
    assert_eq!(sw.cursor(), 0, "the cursor did not return to the bottom");
    drop(c);
    drop(r);
}

#[test]
fn zero_budget_sweeper_advances() {
    let _g = serial();
    let s = seed_two_sealed("sweepsched-zero");
    let (c, r, _) = open(cfg_of(&s)).expect("open");
    let mut sw = HeaderSweeper::new(0);
    let rep = sw.step(&r);
    assert_eq!(rep.attempted.len(), 1, "a zero budget attempted {:?}", rep.attempted);
    assert_eq!(sw.cursor(), 1);
    assert!(rep.is_clean());
    drop(c);
    drop(r);
}

#[test]
fn nothing_judged_is_not_clean() {
    let _g = serial();
    let s = Scratch::new("sweepsched-null");
    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(100, 1);
    c.extend(&common::commits(&bs)).unwrap();
    c.flush().unwrap();

    let rep = sweep_all(&r, SweepTrigger::Operator);
    println!("  {}", rep.line());
    assert_eq!(rep.verdict(), SweepVerdict::NothingJudged);
    assert!(
        !rep.is_clean(),
        "a sweep that walked no header at all reported clean. This crate has shipped that \
         bug twice: two corruption scans that landed in the allocator's slack and reported \
         48/48 clean. This assertion stops the third."
    );
    assert!(rep.links == 0 && rep.judged.is_empty());
    assert!(
        rep.line().contains("nothing was judged"),
        "the operator's line does not say a null result happened: {}",
        rep.line()
    );
    assert!(rep.unjudged >= 1, "the attempted segment was not counted as unjudged");
    drop(c);
    drop(r);
}

#[test]
fn full_sweep_names_broken_link() {
    let _g = serial();
    let s = seed_two_sealed("sweepsched-full");
    flip_bit(&hseg(&s, 0), 2_000 * 132 + 12, 1);
    let (c, r, _) = open(cfg_of(&s)).expect("open");
    let rep = sweep_all(&r, SweepTrigger::Startup);
    println!("  {}", rep.line());

    assert_eq!(rep.verdict(), SweepVerdict::Broken(vec![(0, 2_000)]));
    assert!(rep.bytes_read >= plaine_storage::HDR_SEG_BYTES, "the cost was not accounted");

    assert_eq!(
        rep.judged,
        vec![0, 1],
        "the sweep did not report both sealed segments as walked; a segment whose walk          ended in a BREAK was still walked"
    );
    drop(c);
    drop(r);
}

#[test]
fn torn_reorg_reopens_linked() {
    let _g = serial();
    let s = Scratch::new("sweepsched-torn");
    let fork;
    let old_tip;
    {
        let (mut c, r, _) = open(cfg_of(&s)).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(64, 64, 2);
        let main = chain.build(SEG + 10, 1);
        c.extend(&common::commits(&main)).unwrap();
        c.flush().unwrap();
        old_tip = r.tip().height;
        fork = old_tip - 20;
        assert!(fork < SEG - 1, "the fork must be inside sealed segment 0");
        chain.rewind(&main, fork, main[fork as usize].hash);
        let alt = chain.build(25, 7);
        let rollback: Vec<u64> = (fork + 1..=old_tip).rev().collect();
        let cs = common::commits(&alt);

        tear_reorg_mid_overwrite(
            &mut c,
            &ReorgPlan { fork_height: fork, rollback: &rollback, apply: &cs },
        );
        c.abandon();
        drop(cs);
        drop(r);
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("reopen after the torn reorg");
    assert!(
        rep.hdr_undo_replayed.is_some(),
        "recovery replayed no header undo, so the reorg was not torn and this test is a \
         reopen of a finished store wearing a power-loss label"
    );
    println!(
        "  reopened at tip {} (fork was {fork}, old tip {old_tip}), integrity clean={}",
        r.tip().height,
        rep.integrity.is_clean()
    );
    let sw = sweep_all(&r, SweepTrigger::Startup);
    println!("  {}", sw.line());

    assert_eq!(
        sw.verdict(),
        SweepVerdict::Clean { segments: 1, links: SEG },
        "a reorg torn inside a SEALED header segment reopened holding a header stream that \
         does not link. `replay_hdr_undo` put back a mix of two branches."
    );
    drop(c);
    drop(r);
}

#[test]
fn one_step_is_cheap() {
    let _g = serial();
    let s = seed_two_sealed("sweepsched-cost");
    let (c, r, _) = open(cfg_of(&s)).expect("open");

    let _ = r.verify_segment_headers(0);
    let mut sw = HeaderSweeper::new(1);
    let mut best = std::time::Duration::from_secs(3_600);
    for _ in 0..5 {
        let rep = sw.step(&r);
        if rep.is_clean() && rep.elapsed < best {
            best = rep.elapsed;
        }
    }
    println!(
        "  L3-H one segment ({} headers, {} B): best of 5 = {:.3} ms  [debug build]",
        SEG,
        plaine_storage::HDR_SEG_BYTES,
        best.as_secs_f64() * 1e3
    );
    assert!(
        best < std::time::Duration::from_secs(2),
        "one budgeted L3-H step took {best:?}. A tier whose per-step cost is visible to an \
         operator gets switched off by the first latency spike."
    );
    drop(c);
    drop(r);
}

#[test]
#[ignore = "measurement: writes 168 MB, run by hand, release build, settled box"]
fn measure_l3h_against_l2_on_one_sealed_segment() {
    let _g = serial();
    let s = Scratch::new("sweepsched-measure");

    let segs: u64 = std::env::var("PLAINE_L3H_SEGMENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    {
        let mut cfg = cfg_of(&s);

        cfg.ibd_batch_blocks = Some(256);
        let (mut c, r, _) = open(cfg).expect("seed open");
        c.set_mode(DurabilityMode::Ibd).unwrap();

        let mut chain = Chain::new(64, 20_480, 2);
        let target = segs * SEG + 10;
        let mut done = 0u64;
        while done < target {
            let n = (target - done).min(2_048);
            let bs = chain.build(n, 1);
            c.extend(&common::commits(&bs)).unwrap();
            done += n;
        }
        c.flush().unwrap();
        assert_eq!(r.hdr_watermark(), target);
        drop(c);
        drop(r);
    }
    let (c, r, _) = open(cfg_of(&s)).expect("open");

    let bseg = s.0.join("segments").join("body").join("000000.bseg");
    let bsz = std::fs::metadata(&bseg).expect("body segment 0").len();
    assert!(
        bsz > 60 * 1024 * 1024,
        "the body segment is {bsz} B. The L2 half of this comparison is about 4,096 reads \
         SCATTERED over 83.9 MB; over a segment that fits in a few pages it measures nothing."
    );
    let hsz = std::fs::metadata(s.0.join("segments").join("hdr").join("000000.hseg"))
        .expect("header segment 0")
        .len();
    println!("MEASURE  fixture: header segment {hsz} B, body segment {bsz} B, {segs} segment(s) written");

    if segs >= 8 {
        let t = std::time::Instant::now();
        assert_eq!(r.verify_segment_headers(0).expect("L3-H cold"), Some(SEG));
        let a = t.elapsed().as_secs_f64() * 1e3;
        let t = std::time::Instant::now();
        assert_eq!(r.verify_segment_frames(0).expect("L2 cold"), Some(true));
        let bb = t.elapsed().as_secs_f64() * 1e3;
        println!("MEASURE  COLD fixture: {} MB of body written after segment 0", segs * 80);
        println!("MEASURE  COLD L3-H one sealed segment: {a:.3} ms  (first touch)");
        println!("MEASURE  COLD L2   one sealed segment: {bb:.3} ms  (first touch)");
        println!("MEASURE  COLD ratio L2/L3-H = {:.2}x", bb / a.max(1e-9));
        println!(
            "MEASURE  COLD whole-store at height 1,000,000: L3-H {:.1} s, L2 {:.1} s",
            a * (1_000_000.0 / SEG as f64) / 1e3,
            bb * (1_000_000.0 / SEG as f64) / 1e3
        );
    } else {
        println!(
            "MEASURE  COLD: NOT TAKEN. Only {segs} segment(s) were written, so segment 0 is \
             still resident and any number here would be the warm one under a cold heading. \
             Set PLAINE_L3H_SEGMENTS above MemTotal / 83.9 MB."
        );
    }

    assert_eq!(r.verify_segment_headers(0).expect("L3-H verdict"), Some(SEG));
    assert_eq!(r.verify_segment_frames(0).expect("L2 verdict"), Some(true));
    let mut l3h = std::time::Duration::from_secs(3_600);
    let mut l2 = std::time::Duration::from_secs(3_600);
    for _ in 0..9 {
        let t = std::time::Instant::now();
        assert_eq!(r.verify_segment_headers(0).expect("L3-H"), Some(SEG));
        l3h = l3h.min(t.elapsed());

        let t = std::time::Instant::now();
        assert_eq!(r.verify_segment_frames(0).expect("L2"), Some(true));
        l2 = l2.min(t.elapsed());
    }
    let l3h_ms = l3h.as_secs_f64() * 1e3;
    let l2_ms = l2.as_secs_f64() * 1e3;
    println!("MEASURE  WARM L3-H one sealed segment: {l3h_ms:.3} ms  (one sequential read + {SEG} BLAKE3)");
    println!("MEASURE  WARM L2   one sealed segment: {l2_ms:.3} ms  ({SEG} scattered 8-byte reads)");
    println!("MEASURE  WARM ratio L2/L3-H = {:.2}x", l2_ms / l3h_ms.max(1e-9));
    println!(
        "MEASURE  WARM whole-store at height 1,000,000: L3-H {:.0} ms, L2 {:.0} ms, over {} segments",
        l3h_ms * (1_000_000.0 / SEG as f64),
        l2_ms * (1_000_000.0 / SEG as f64),
        1_000_000 / SEG
    );

    drop(c);
    drop(r);
}
