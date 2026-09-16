mod common;

use common::{body, commits, serial, Chain, Scratch};
use plaine_consensus::constants::{MAX_HEADERS_PER_MSG, MAX_REORG_DEPTH};
use plaine_storage::{
    open, DeepReorgPlan, DurabilityMode, InvalidReason, ReorgPlan, StoreError, SEG_BLOCKS,
};

#[test]
fn extend_and_read_back() {
    let _g = serial();
    let s = Scratch::new("roundtrip");
    let mut cfg = s.cfg();
    cfg.state_ckpt_interval = 64;
    let (mut c, r, rep) = open(cfg).expect("open");
    assert_eq!(rep.tip.height, 0);
    assert_eq!(r.hdr_watermark(), 0);

    let mut chain = Chain::new(64, 200, 3);
    let blocks = chain.build(300, 1);
    c.set_mode(DurabilityMode::Ibd).unwrap();
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();

    assert_eq!(r.tip().height, 299);
    assert_eq!(r.hdr_watermark(), 300);
    for b in blocks.iter().step_by(37) {
        assert_eq!(r.header_at(b.height).unwrap().unwrap(), b.header);
        assert_eq!(r.hash_at(b.height).unwrap().unwrap(), b.hash);
        assert_eq!(
            r.header_by_hash(&b.hash).unwrap().map(|(h, _)| h),
            Some(b.height)
        );
        let mut buf = Vec::new();
        assert_eq!(body(&r, b.height, &mut buf), b.body.len());
        assert_eq!(buf, b.body);
    }

    assert!(r.header_at(300).unwrap().is_none());

    for (a, want) in chain.state.iter() {
        assert_eq!(&r.account(a).unwrap(), want);
    }
    r.verify_state_fingerprint().expect("fingerprint");
    assert_eq!(r.issued(), chain.issued);

    let mut out = Vec::new();
    let n = r.headers_range(100, 50, &mut out).unwrap();
    assert_eq!(n, 50);
    assert_eq!(&out[0..132], &blocks[100].header[..]);

    let mut loc = [[0u8; 32]; 32];
    let n = r.locator(&mut loc).unwrap();
    assert!(n > 10 && n <= 32);
    assert_eq!(loc[0], blocks[299].hash);
}

#[test]
fn reorg_at_max_reorg_depth() {
    let _g = serial();
    let s = Scratch::new("reorg100");
    let mut cfg = s.cfg();
    cfg.ibd_batch_blocks = Some(64);
    cfg.state_ckpt_interval = 128;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();

    let mut chain = Chain::new(48, 180, 3);
    let main = chain.build(300, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    assert_eq!(r.tip().height, 299);

    let fork = 299 - MAX_REORG_DEPTH;
    let depth = 299 - fork;
    assert_eq!(depth, MAX_REORG_DEPTH);

    chain.rewind(&main, fork, main[fork as usize].hash);
    let alt = chain.build(depth, 2);
    let rollback: Vec<u64> = (fork + 1..=299).rev().collect();
    let plan = ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &commits(&alt),
    };
    c.reorg(&plan).unwrap();

    assert_eq!(r.tip().height, 299);
    assert_eq!(r.tip().hash, alt.last().unwrap().hash);
    assert_eq!(r.header_at(fork + 1).unwrap().unwrap(), alt[0].header);

    let mid = (depth / 2) as usize;
    assert!(r.header_by_hash(&main[fork as usize + 1 + mid].hash).unwrap().is_none());
    assert_eq!(
        r.header_by_hash(&alt[mid].hash).unwrap().map(|(h, _)| h),
        Some(fork + 1 + mid as u64)
    );
    for (a, want) in chain.state.iter() {
        assert_eq!(&r.account(a).unwrap(), want, "account {a:?}");
    }
    r.verify_state_fingerprint().expect("fingerprint after reorg");
    assert_eq!(r.issued(), chain.issued);

    for h in (fork - 40)..=fork {
        assert_eq!(r.header_at(h).unwrap().unwrap(), main[h as usize].header);
    }

    let too_deep = 299 - MAX_REORG_DEPTH;
    let deep: Vec<u64> = (too_deep..=299).rev().collect();
    assert_eq!(deep.len() as u64, MAX_REORG_DEPTH + 1);
    let e = c.reorg(&ReorgPlan {
        fork_height: too_deep - 1,
        rollback: &deep,
        apply: &commits(&alt),
    });
    assert!(matches!(e, Err(StoreError::BadPlan(_))));
}

#[test]
fn deep_reorg_via_forward_replay() {
    let _g = serial();
    let s = Scratch::new("deep-reorg");
    let mut cfg = s.cfg();
    cfg.ibd_batch_blocks = Some(32);
    cfg.state_ckpt_interval = 64;
    cfg.state_ckpt_keep = 8;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();

    let mut chain = Chain::new(64, 160, 3);
    let main = chain.build(700, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    assert_eq!(r.tip().height, 699);

    let fork = 300u64;

    assert!(699 - fork > plaine_storage::UNDO_RING);
    assert!(fork < r.undo_floor());

    let rewind_to = r
        .checkpoint_at_or_below(fork)
        .unwrap()
        .expect("a state checkpoint at or below the fork");
    assert!(rewind_to >= r.replay_floor());
    assert!(rewind_to <= fork);

    let mut common_bodies = Vec::new();
    for h in rewind_to + 1..=fork {
        let mut buf = Vec::new();
        body(&r, h, &mut buf);
        assert_eq!(buf, main[h as usize].body);
        common_bodies.push(buf);
    }

    chain.rewind(&main, fork, main[fork as usize].hash);
    let alt = chain.build(120, 7);

    let replay: Vec<_> = main[(rewind_to + 1) as usize..=(fork as usize)]
        .iter()
        .map(|b| b.to_commit())
        .collect();
    let apply = commits(&alt);
    c.deep_reorg(&DeepReorgPlan {
        fork_height: fork,
        rewind_to,
        replay: &replay,
        apply: &apply,
    })
    .unwrap();

    assert_eq!(r.tip().height, fork + 120);
    assert_eq!(r.tip().hash, alt.last().unwrap().hash);
    assert_eq!(r.header_at(fork + 1).unwrap().unwrap(), alt[0].header);
    for (a, want) in chain.state.iter() {
        assert_eq!(&r.account(a).unwrap(), want, "account {a:?}");
    }
    r.verify_state_fingerprint()
        .expect("fingerprint after deep reorg");
    assert_eq!(r.issued(), chain.issued);

    for (i, h) in (rewind_to + 1..=fork).enumerate() {
        let mut buf = Vec::new();
        body(&r, h, &mut buf);
        assert_eq!(buf, common_bodies[i]);
        assert_eq!(r.header_at(h).unwrap().unwrap(), main[h as usize].header);
    }

    let tip = r.tip();
    let fp = r.state_fingerprint();
    drop(c);
    drop(r);
    let (c2, r2, rep) = open(s.cfg()).expect("reopen");
    assert_eq!(r2.tip(), tip);
    assert_eq!(r2.state_fingerprint(), fp);
    assert!(rep.headers_truncated_to.is_none());
    drop(c2);
}

#[test]
fn reorg_below_reachable_is_error() {
    let _g = serial();
    let s = Scratch::new("undo-exhausted");
    let mut cfg = s.cfg();
    cfg.ibd_batch_blocks = Some(64);

    cfg.state_ckpt_interval = 0;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();

    let mut chain = Chain::new(32, 120, 2);
    let main = chain.build(600, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();

    assert!(r.checkpoint_at_or_below(100).unwrap().is_none());
    chain.rewind(&main, 100, main[100].hash);
    let alt = chain.build(4, 2);
    let rollback: Vec<u64> = (101..=599).rev().collect();
    let e = c.reorg(&ReorgPlan {
        fork_height: 100,
        rollback: &rollback,
        apply: &commits(&alt),
    });

    assert!(matches!(e, Err(StoreError::BadPlan(_))), "{e:?}");

    let e = c.deep_reorg(&DeepReorgPlan {
        fork_height: 100,
        rewind_to: 100,
        replay: &[],
        apply: &commits(&alt),
    });
    match e {
        Err(StoreError::UndoExhausted {
            requested,
            undo_floor,
            replay_floor,
        }) => {
            assert_eq!(requested, 100);
            assert_eq!(undo_floor, 600 - plaine_storage::UNDO_RING);
            assert_eq!(replay_floor, 0);
        }
        other => panic!("expected UndoExhausted, got {other:?}"),
    }
}

#[test]
fn pruning_keeps_reorg_depth() {
    let _g = serial();
    let s = Scratch::new("prune");
    let mut cfg = s.cfg();
    cfg.prune = true;

    cfg.body_retain_blocks = 2 * SEG_BLOCKS;
    cfg.ibd_batch_blocks = Some(1_024);
    cfg.state_ckpt_interval = 2_048;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();

    let mut chain = Chain::new(256, 32, 2);
    let n = 5 * SEG_BLOCKS;
    let blocks = chain.build(n, 1);
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();
    let tip = r.tip().height;

    let floor = r.prune_floor();
    assert!(floor > 0, "nothing was pruned");
    assert_eq!(floor % SEG_BLOCKS, 0, "pruning is whole segments only");

    let deepest_legal_fork = tip - MAX_REORG_DEPTH;
    assert!(
        deepest_legal_fork > floor,
        "prune floor {floor} reaches a legally reorg-able height {deepest_legal_fork}"
    );
    assert!(
        tip - floor >= 2 * SEG_BLOCKS,
        "retention {} below the configured window",
        tip - floor
    );

    assert!(r.undo_floor() > floor);

    let mut buf = Vec::new();
    for h in deepest_legal_fork..=tip {
        assert_eq!(
            body(&r, h, &mut buf),
            blocks[h as usize].body.len(),
            "missing body at {h}"
        );
    }

    match r.body_at(floor - 1, &mut buf) {
        Err(StoreError::BodyPruned { height, prune_floor }) => {
            assert_eq!(height, floor - 1);
            assert_eq!(prune_floor, floor);
        }
        other => panic!("expected BodyPruned, got {other:?}"),
    }

    assert!(r.header_at(0).unwrap().is_some());
    assert!(r.header_at(floor - 1).unwrap().is_some());
    assert_eq!(r.hash_at(0).unwrap().unwrap(), blocks[0].hash);

    let e = c.deep_reorg(&DeepReorgPlan {
        fork_height: 10,
        rewind_to: 10,
        replay: &[],
        apply: &[],
    });
    assert!(
        matches!(e, Err(StoreError::ForkBelowPruneFloor { .. })),
        "{e:?}"
    );
    let msg = format!("{}", e.unwrap_err());
    assert!(msg.contains("resync required"), "{msg}");
}

#[test]
fn ckpt_horizon_exceeds_max_reorg_depth() {
    let _g = serial();
    let s = Scratch::new("ckpt-horizon");
    let cfg = s.cfg();

    let interval = cfg.state_ckpt_interval;
    let keep = cfg.state_ckpt_keep as u64;
    // The default is small on purpose (a large interval pins freed pages and bloats
    // chain.redb). The property that must hold, whatever the numbers are, is that the
    // retained checkpoints span at least MAX_REORG_DEPTH so any in-window reorg can
    // rewind to a checkpoint at or below its fork height.
    assert!(keep >= 2, "keep {keep} leaves no reorg horizon at all");
    assert!(
        interval * (keep - 1) >= MAX_REORG_DEPTH,
        "default ckpt policy (interval {interval}, keep {keep}) must span \
         MAX_REORG_DEPTH ({MAX_REORG_DEPTH}); interval*(keep-1)={} is too small",
        interval * (keep - 1)
    );

    // Steady state: one seal per block (the default Tip mode), so checkpoints land
    // every `interval` blocks. Tip is the mode a live node runs in and where the
    // reorg horizon actually has to hold.
    let (mut c, r, _) = open(cfg).expect("open");
    let mut chain = Chain::new(64, 24, 1);

    let n = (keep + 1) * interval + 512;
    let blocks = chain.build(n, 1);
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();

    let tip = r.tip().height;
    let floor = r.replay_floor();
    let horizon = tip - floor;
    println!(
        "CHECKPOINT HORIZON at the shipped default (interval {interval}, keep {keep}): \
         tip {tip}, replay_floor {floor}, horizon {horizon} blocks = {:.0}x MAX_REORG_DEPTH",
        horizon as f64 / MAX_REORG_DEPTH as f64
    );
    assert!(floor > 0, "no checkpoint was ever taken");
    assert!(
        horizon >= (keep - 1) * interval,
        "horizon {horizon} is below the (keep-1) x interval the policy promises"
    );

    assert!(
        floor + MAX_REORG_DEPTH < tip,
        "replay floor {floor} does not reach MAX_REORG_DEPTH ({MAX_REORG_DEPTH}) below tip {tip}"
    );
    // A reorg deeper than MAX_REORG_DEPTH is refused by the ForkTooDeep gate, so the
    // horizon only has to COVER MAX_REORG_DEPTH, not dwarf it. A large horizon is not
    // free: every extra block of it is freed pages pinned by an old savepoint - the
    // bloat this interval was shrunk to avoid. Require a one-interval cushion over
    // MAX_REORG_DEPTH so the checkpoint granularity never leaves the floor above it.
    assert!(
        horizon >= MAX_REORG_DEPTH + interval,
        "horizon {horizon} does not clear MAX_REORG_DEPTH ({MAX_REORG_DEPTH}) by an interval ({interval})"
    );

    let base = r.checkpoint_at_or_below(tip - MAX_REORG_DEPTH).unwrap();
    assert!(base.is_some_and(|b| b <= tip - MAX_REORG_DEPTH));
    drop(c);
}

#[test]
fn bytes_on_disk_per_header() {
    let _g = serial();

    fn measure(name: &str, n: u64) -> (u64, u64, u64) {
        let s = Scratch::new(name);
        let mut cfg = s.cfg();
        cfg.ibd_batch_blocks = Some(4_096);
        cfg.state_ckpt_interval = 0;
        let (mut c, r0, _) = open(cfg).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(1_000, 121, 1);
        let blocks = chain.build(n, 1);
        c.extend(&commits(&blocks)).unwrap();
        c.flush().unwrap();
        drop(c);
        drop(r0);
        let hdr = common::dir_bytes(&s.0.join("segments").join("hdr"));
        let db = common::file_bytes(&s.0.join("chain.redb"));
        let total = common::dir_bytes(&s.0);
        (hdr, db, total)
    }

    let n1 = 4_096u64;
    let n2 = 16_384u64;
    let (h1, d1, t1) = measure("size-a", n1);
    let (h2, d2, t2) = measure("size-b", n2);
    let dn = (n2 - n1) as f64;

    assert_eq!(h1, 132 * n1, "header segment carries per-record overhead");
    assert_eq!(h2, 132 * n2);
    let hdr_marginal = (h2 - h1) as f64 / dn;
    assert!((hdr_marginal - 132.0).abs() < 1e-9);

    let db_marginal = (d2 - d1) as f64 / dn;
    let total_marginal = (t2 - t1) as f64 / dn;
    println!(
        "MARGINAL BYTES/BLOCK  header segment {hdr_marginal:.1}  redb {db_marginal:.1}  \
         whole store {total_marginal:.1}  (body payload 121 + frame 8 + sidecar 8)"
    );
    println!(
        "HEADER COST RATIO vs {:.2}x lighter (132.0 vs 378.2 B)",
        378.2 / 132.0
    );

    assert!(
        total_marginal < 400.0,
        "whole-store marginal cost {total_marginal:.1} B/block exceeds budget"
    );

    assert!(hdr_marginal + db_marginal < 378.2 + 137.0);
}

#[test]
fn memory_and_row_caps() {
    let _g = serial();
    let s = Scratch::new("caps");
    let mut cfg = s.cfg();
    cfg.reader_fd_cap = 8;
    cfg.side_headers_cap = 64;
    cfg.invalid_cap = 32;
    cfg.ibd_batch_blocks = Some(512);
    cfg.state_ckpt_interval = 0;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();

    let mut chain = Chain::new(64, 256, 2);
    let blocks = chain.build(3 * SEG_BLOCKS, 1);
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();

    let budget = plaine_storage::MemoryBudget::default();
    assert_eq!(budget.page_cache_bytes, 128 * 1024 * 1024);
    assert!(budget.commit_staging_bytes >= 2 * plaine_storage::MAX_BODY_BYTES / 2);

    let mut out = Vec::new();
    assert!(r
        .headers_range(0, MAX_HEADERS_PER_MSG as u32 + 1, &mut out)
        .is_err());
    let n = r
        .headers_range(0, MAX_HEADERS_PER_MSG as u32, &mut out)
        .unwrap();
    assert_eq!(n as usize, MAX_HEADERS_PER_MSG);
    assert_eq!(out.len(), MAX_HEADERS_PER_MSG * 132);

    let mut buf = Vec::new();
    for h in (0..3 * SEG_BLOCKS).step_by(97) {
        body(&r, h, &mut buf);
        assert!(buf.capacity() <= plaine_storage::MAX_BODY_BYTES);
    }

    assert!(
        c.staging_bytes() <= 2 * plaine_storage::MAX_BODY_BYTES,
        "committer staging {} bytes",
        c.staging_bytes()
    );

    assert!(r.open_fd_count() <= 8, "fds {}", r.open_fd_count());

    let side: Vec<_> = (0..200u64)
        .map(|i| {
            let mut hdr = [0u8; 132];
            hdr[4..12].copy_from_slice(&i.to_le_bytes());
            let hash = plaine_consensus::crypto::header_hash(&hdr);
            (hash, hdr, i, plaine_storage::HeaderStatus::PowOk)
        })
        .collect();
    c.put_side_headers(&side).unwrap();
    let (side_rows, _) = r.row_counts().unwrap();
    assert_eq!(side_rows, 64, "side_headers cap not enforced");
    assert!(r.side_header(&side[0].0).unwrap().is_none(), "lowest kept");
    assert!(r.side_header(&side[199].0).unwrap().is_some(), "highest evicted");

    let inv: Vec<_> = (0..100u64)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&i.to_le_bytes());
            (h, InvalidReason::BadPow)
        })
        .collect();
    c.mark_invalid_batch(&inv).unwrap();
    let (_, inv_rows) = r.row_counts().unwrap();
    assert_eq!(inv_rows, 32);
    assert!(r.is_invalid(&inv[99].0).unwrap());
    assert!(!r.is_invalid(&inv[0].0).unwrap());
    assert_eq!(c.clear_invalid_all().unwrap(), 32);
    assert!(!r.is_invalid(&inv[99].0).unwrap());
}

#[test]
fn invalid_reason_survives_round_trip() {
    let _g = serial();
    let s = Scratch::new("invalid-reason");
    let (mut c, r, _) = open(s.cfg()).expect("open");

    let mut pow = [0u8; 32];
    pow[0] = 1;
    let mut cp = [0u8; 32];
    cp[0] = 2;
    let mut unheard_of = [0u8; 32];
    unheard_of[0] = 3;

    c.mark_invalid_batch(&[(pow, InvalidReason::BadPow), (cp, InvalidReason::BadCheckpoint)])
        .unwrap();

    assert_eq!(r.invalid_reason(&pow).unwrap(), Some(InvalidReason::BadPow));
    assert_eq!(r.invalid_reason(&cp).unwrap(), Some(InvalidReason::BadCheckpoint));
    assert_ne!(r.invalid_reason(&pow).unwrap(), r.invalid_reason(&cp).unwrap());

    assert_eq!(r.invalid_reason(&unheard_of).unwrap(), None);
    assert!(!r.is_invalid(&unheard_of).unwrap());

    assert_eq!(InvalidReason::BadCheckpoint.as_str(), "bad-checkpoint");
    assert_eq!(InvalidReason::BadPow.as_str(), "bad-pow");

    let census = r.invalid_census().unwrap();
    assert_eq!(census.len(), 2, "{census:?}");
    assert!(census.contains(&(InvalidReason::BadPow, 1)), "{census:?}");
    assert!(census.contains(&(InvalidReason::BadCheckpoint, 1)), "{census:?}");

    assert_eq!(c.clear_invalid_all().unwrap(), 2);
    assert!(r.invalid_census().unwrap().is_empty());
    assert_eq!(r.invalid_reason(&cp).unwrap(), None);
}

#[test]
fn fd_count_stays_bounded() {
    let _g = serial();
    let s = Scratch::new("fds");
    let mut cfg = s.cfg();
    cfg.reader_fd_cap = 12;
    cfg.ibd_batch_blocks = Some(2_048);
    cfg.state_ckpt_interval = 0;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(32, 24, 1);
    let blocks = chain.build(20 * SEG_BLOCKS, 1);
    c.extend(&commits(&blocks)).unwrap();
    c.flush().unwrap();

    let mut buf = Vec::new();
    let mut peak = 0usize;
    for h in (0..20 * SEG_BLOCKS).step_by(211) {
        let _ = r.header_at(h).unwrap();
        let _ = r.body_at(h, &mut buf);
        peak = peak.max(r.open_fd_count());
    }
    println!("SEGMENTS TOUCHED 20, PEAK READER FDS {peak} (cap 12)");
    assert!(peak <= 12, "fd ceiling broken: {peak}");
}

#[test]
fn prefix_collision_uses_overflow() {
    let _g = serial();
    let s = Scratch::new("collision");
    let mut cfg = s.cfg();

    cfg.hash_prefix_bytes = 1;
    cfg.ibd_batch_blocks = Some(64);
    cfg.state_ckpt_interval = 128;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();

    let mut chain = Chain::new(32, 64, 2);
    let main = chain.build(400, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();

    assert!(
        r.hash_index_full_rows() > 100,
        "the overflow table never ran: {} rows",
        r.hash_index_full_rows()
    );

    for b in main.iter() {
        assert_eq!(
            r.header_by_hash(&b.hash).unwrap().map(|(h, _)| h),
            Some(b.height),
            "height {}",
            b.height
        );
    }

    let mut fake = main[7].hash;
    fake[31] ^= 0xFF;
    assert!(r.header_by_hash(&fake).unwrap().is_none());

    let fork = 399 - MAX_REORG_DEPTH;
    chain.rewind(&main, fork, main[fork as usize].hash);
    let alt = chain.build(MAX_REORG_DEPTH, 5);
    let rollback: Vec<u64> = (fork + 1..=399).rev().collect();
    c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &commits(&alt),
    })
    .unwrap();
    for b in main.iter().take(fork as usize + 1) {
        assert_eq!(
            r.header_by_hash(&b.hash).unwrap().map(|(h, _)| h),
            Some(b.height),
            "survivor {} lost after reorg",
            b.height
        );
    }
    for b in alt.iter() {
        assert_eq!(
            r.header_by_hash(&b.hash).unwrap().map(|(h, _)| h),
            Some(b.height)
        );
    }
    for b in main.iter().skip(fork as usize + 1) {
        assert!(r.header_by_hash(&b.hash).unwrap().is_none());
    }
}

#[test]
fn commit_stall_does_not_block_readers() {
    let _g = serial();
    let s = Scratch::new("stall");
    let mut cfg = s.cfg();
    cfg.ibd_batch_blocks = Some(64);
    cfg.state_ckpt_interval = 0;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 128, 3);
    let warm = chain.build(200, 1);
    c.extend(&commits(&warm)).unwrap();
    c.flush().unwrap();

    let stalled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stalled.clone();
    c.set_mode(DurabilityMode::Tip).unwrap();
    c.set_stall_hook(Box::new(move |p| {
        if p == plaine_storage::StallPoint::BeforeRedbCommit {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(1_500));
        }
    }));

    let r2 = r.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let d2 = done.clone();
    let stalled2 = stalled.clone();
    let h = std::thread::spawn(move || {
        while !stalled2.load(std::sync::atomic::Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        let loop_start = std::time::Instant::now();
        let mut worst = 0u128;
        let mut first = 0u128;
        let mut buf = Vec::new();
        let mut hdrs = Vec::new();
        for i in 0..200u64 {
            let t = std::time::Instant::now();
            let _ = r2.tip();
            let _ = r2.header_at(i % 200).unwrap();
            let _ = r2.hash_at(i % 200).unwrap();
            let _ = body(&r2, i % 200, &mut buf);
            let _ = r2.account(&common::addr(i % 64)).unwrap();
            let _ = r2.headers_range(i % 100, 32, &mut hdrs).unwrap();
            let us = t.elapsed().as_micros();

            if i == 0 {
                first = us;
            } else {
                worst = worst.max(us);
            }
            d2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        (first, worst, loop_start.elapsed().as_micros())
    });

    let next = chain.build(1, 1);
    c.extend(&commits(&next)).unwrap();
    let (first, worst, total) = h.join().unwrap();
    assert_eq!(done.load(std::sync::atomic::Ordering::SeqCst), 200);
    println!(
        "READER LATENCY DURING A 1,500,000 us COMMIT STALL: 200 full read passes in {total} us          (first, cold fds: {first} us; steady-state worst: {worst} us)"
    );

    assert!(
        total < 750_000,
        "200 read passes took {total} us against a 1,500,000 us stall"
    );
    assert!(
        worst < 250_000,
        "a reader waited {worst} us, which is the order of the stall itself"
    );
}

#[test]
fn open_is_o1_in_chain_height() {
    let _g = serial();
    fn open_micros(name: &str, n: u64) -> u64 {
        let s = Scratch::new(name);
        let mut cfg = s.cfg();
        cfg.ibd_batch_blocks = Some(4_096);
        cfg.state_ckpt_interval = 0;
        let (mut c, r0, _) = open(cfg).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(512, 48, 2);
        let blocks = chain.build(n, 1);
        c.extend(&commits(&blocks)).unwrap();
        c.flush().unwrap();

        drop(c);
        drop(r0);
        let mut best = u64::MAX;
        for _ in 0..3 {
            let (c2, r2, rep) = open(s.cfg()).expect("reopen");
            best = best.min(rep.open_micros);
            drop(c2);
            drop(r2);
        }
        best
    }
    let small = open_micros("o1-small", 1_000);
    let large = open_micros("o1-large", 40_000);
    println!("OPEN MICROS: 1,000 blocks {small}  40,000 blocks {large}  (40x the chain)");
    assert!(
        large < small.max(1) * 4,
        "open cost scales with chain height: {small} -> {large} for 40x the blocks"
    );
}

#[test]
fn differential_vs_reference() {
    let _g = serial();
    let s = Scratch::new("differential");
    let mut base = s.cfg();
    base.ibd_batch_blocks = Some(16);
    base.state_ckpt_interval = 32;
    base.state_ckpt_keep = 6;

    let mut chain = Chain::new(40, 96, 3);
    let mut history: Vec<common::Block> = Vec::new();
    let mut rng = common::Rng(0xDEAD_BEEF);
    let (mut c, mut r, _) = open(base.clone()).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let seed = chain.build(20, 1);
    c.extend(&commits(&seed)).unwrap();
    c.flush().unwrap();
    history.extend(seed);

    for round in 0..24u64 {
        match rng.below(10) {
            0..=5 => {
                let n = 1 + rng.below(30);
                let bs = chain.build(n, round + 100);
                c.extend(&commits(&bs)).unwrap();
                c.flush().unwrap();
                history.extend(bs);
            }
            6..=7 if history.len() > 40 => {
                let tip = chain.height - 1;
                let depth = 1 + rng.below(20.min(tip));
                let fork = tip - depth;
                if fork < c.undo_floor() {
                    continue;
                }
                let fork_hash = history[fork as usize].hash;
                chain.rewind(&history, fork, fork_hash);
                history.retain(|b| b.height <= fork);
                let bs = chain.build(depth + 1, round + 500);
                let rollback: Vec<u64> = (fork + 1..=tip).rev().collect();
                c.reorg(&ReorgPlan {
                    fork_height: fork,
                    rollback: &rollback,
                    apply: &commits(&bs),
                })
                .unwrap();
                history.extend(bs);
            }
            8 => {
                drop(c);
                drop(r);
                let (c2, r2, rep) = open(base.clone()).expect("reopen");
                assert!(rep.headers_truncated_to.is_none(), "clean restart truncated");
                c = c2;
                r = r2;
                c.set_mode(DurabilityMode::Ibd).unwrap();
            }
            _ => {}
        }

        assert_eq!(r.tip().height, chain.height - 1);
        assert_eq!(r.tip().hash, history.last().unwrap().hash);
        assert_eq!(r.issued(), chain.issued);
        for a in 0..40u64 {
            let key = common::addr(a);
            let want = chain.state.get(&key).copied().unwrap_or_default();
            assert_eq!(r.account(&key).unwrap(), want, "round {round} account {a}");
        }
        let probe = rng.below(chain.height);
        let b = &history[probe as usize];
        assert_eq!(r.header_at(probe).unwrap().unwrap(), b.header);
        assert_eq!(r.hash_at(probe).unwrap().unwrap(), b.hash);
        let mut buf = Vec::new();
        body(&r, probe, &mut buf);
        assert_eq!(buf, b.body);
        assert_eq!(
            r.header_by_hash(&b.hash).unwrap().map(|(h, _)| h),
            Some(probe)
        );
        r.verify_state_fingerprint().expect("fingerprint");
    }
}

#[test]
fn side_headers_from_is_ascending() {
    let _g = serial();
    let s = Scratch::new("sidescan");
    let mut cfg = s.cfg();
    cfg.side_headers_cap = 512;
    let (mut c, r, _) = open(cfg).expect("open");

    let rows: Vec<_> = (0..400u64)
        .rev()
        .map(|i| {
            let mut hdr = [0u8; 132];
            hdr[4..12].copy_from_slice(&i.to_le_bytes());
            let hash = plaine_consensus::crypto::header_hash(&hdr);
            (hash, hdr, i, plaine_storage::HeaderStatus::Connected)
        })
        .collect();
    c.put_side_headers(&rows).unwrap();

    let all = r.side_headers_from(0, 4096).unwrap();
    assert_eq!(all.len(), 400, "every row comes back");
    for (i, s) in all.iter().enumerate() {
        assert_eq!(s.height, i as u64, "ascending height, entry {i}");
    }

    let from = r.side_headers_from(300, 4096).unwrap();
    assert_eq!(from.len(), 100);
    assert_eq!(from[0].height, 300, "`from` is inclusive");
    let capped = r.side_headers_from(0, 7).unwrap();
    assert_eq!(capped.len(), 7);
    assert_eq!(capped[6].height, 6, "the ceiling truncates the top");
    assert!(r.side_headers_from(0, 0).unwrap().is_empty(), "max 0 reads nothing");
    assert!(r.side_headers_from(400, 10).unwrap().is_empty(), "nothing above the highest row");

    let more: Vec<_> = (400..1_000u64)
        .map(|i| {
            let mut hdr = [0u8; 132];
            hdr[4..12].copy_from_slice(&i.to_le_bytes());
            let hash = plaine_consensus::crypto::header_hash(&hdr);
            (hash, hdr, i, plaine_storage::HeaderStatus::Connected)
        })
        .collect();
    c.put_side_headers(&more).unwrap();
    let all = r.side_headers_from(0, 100_000).unwrap();
    assert_eq!(all.len(), 512, "bounded by side_headers_cap and nothing else");
    assert_eq!(all[0].height, 488, "lowest-height-first eviction");
    assert_eq!(all[511].height, 999);

    let h0 = plaine_consensus::crypto::header_hash(&all[0].header);
    let one = r.side_header(&h0).unwrap().expect("row present");
    assert_eq!(one.height, 488);
    assert_eq!(one.header, all[0].header);
}
