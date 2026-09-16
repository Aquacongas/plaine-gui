mod common;

use common::*;

use plaine_storage::{open, Account, DurabilityMode, StoreConfig, StoreError};
use redb::{Database, ReadableTable, TableDefinition};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.prune = false;
    c.ibd_batch_blocks = Some(2_048);
    c
}

fn seed(name: &str, n: u64) -> Scratch {
    let s = Scratch::new(name);
    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = Chain::new(64, 200, 3);
    let bs = ch.build(n, 1);
    c.extend(&commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    s
}

fn segment_bytes(s: &Scratch) -> u64 {
    dir_bytes(&s.0.join("segments"))
}

fn segment_files(s: &Scratch) -> Vec<String> {
    let mut v = Vec::new();
    for sub in ["hdr", "body"] {
        if let Ok(rd) = std::fs::read_dir(s.0.join("segments").join(sub)) {
            for e in rd.flatten() {
                v.push(format!("{sub}/{}", e.file_name().to_string_lossy()));
            }
        }
    }
    v.sort();
    v
}

#[test]
fn i1_missing_redb_refused() {
    let _g = serial();
    let s = seed("sweep-i1", 3 * 4_096 + 500);
    let before_bytes = segment_bytes(&s);
    let before_files = segment_files(&s);
    println!("  before: {} files, {} B of segments", before_files.len(), before_bytes);
    assert!(before_bytes > 4_000_000);

    std::fs::remove_file(s.0.join("chain.redb")).unwrap();

    let res = open(cfg_of(&s));
    match &res {
        Ok((_, r, _)) => println!("  open OK -> tip {}", r.tip().height),
        Err(e) => println!("  open REFUSED: {e}"),
    }
    println!("  after: {} files, {} B", segment_files(&s).len(), segment_bytes(&s));
    match res {
        Err(StoreError::OrphanSegments { hdr_segments, body_segments, bytes }) => {
            assert_eq!(hdr_segments, 4, "3*4096+500 blocks span four header segments");
            assert_eq!(body_segments, 4);
            assert!(bytes > 4_000_000, "the error must state the size of what it saved");
        }
        other => panic!(
            "expected OrphanSegments, got {:?}",
            other.map(|(_, r, _)| r.tip().height)
        ),
    }
    assert_eq!(segment_files(&s), before_files, "files changed");
    assert_eq!(segment_bytes(&s), before_bytes, "bytes changed");
}

#[test]
fn i2_foreign_redb_no_meta_refused() {
    let _g = serial();
    let s = seed("sweep-i2", 2 * 4_096 + 10);
    let before = segment_files(&s);
    assert!(before.len() >= 6);

    std::fs::remove_file(s.0.join("chain.redb")).unwrap();
    {
        const ALIEN: TableDefinition<u64, u64> = TableDefinition::new("somebody_elses_table");
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(ALIEN).unwrap();
            t.insert(1u64, 2u64).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
    }

    let res = open(cfg_of(&s));
    println!("  foreign redb -> {:?}", res.as_ref().err().map(|e| e.to_string()));
    assert!(matches!(res, Err(StoreError::OrphanSegments { .. })));
    assert_eq!(segment_files(&s), before, "segments changed under a foreign redb");
}

#[test]
fn i3_deleted_meta_row_keeps_chain() {
    let _g = serial();
    let s = seed("sweep-i3", 4_096 + 200);
    let before = segment_files(&s);
    assert!(!before.is_empty());

    {
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(META).unwrap();
            let wm = t.get("hdr_watermark").unwrap().unwrap().value().to_vec();
            println!(
                "  hdr_watermark row still says {}",
                u64::from_le_bytes(wm[..8].try_into().unwrap())
            );
            t.remove("schema_version").unwrap();
        }
        txn.commit().unwrap();
        drop(db);
    }

    let res = open(cfg_of(&s));
    println!("  one missing meta row -> {:?}", res.as_ref().err().map(|e| e.to_string()));
    assert!(matches!(res, Err(StoreError::OrphanSegments { .. })));
    assert_eq!(segment_files(&s), before, "one lost meta row cost segments");
}

#[test]
fn i5_fresh_store_opens() {
    let _g = serial();
    let s = Scratch::new("sweep-i5");
    {
        let (c, r, rep) = open(cfg_of(&s)).expect("a fresh directory must open");
        assert_eq!(r.hdr_watermark(), 0);
        assert!(rep.integrity.is_clean());
        drop(c);
        drop(r);
    }

    {
        let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut ch = Chain::new(32, 120, 2);
        c.extend(&commits(&ch.build(300, 1))).unwrap();
        c.flush().unwrap();
        drop(c);
        drop(r);
    }
    std::fs::remove_file(s.0.join("chain.redb")).unwrap();
    assert!(matches!(open(cfg_of(&s)), Err(StoreError::OrphanSegments { .. })));
    std::fs::rename(s.0.join("segments"), s.0.join("segments.aside")).unwrap();
    let (c, r, rep) = open(cfg_of(&s)).expect("the remedy in the error message must work");
    println!("  after moving segments aside: tip {}", r.tip().height);
    assert_eq!(r.hdr_watermark(), 0);
    assert!(rep.integrity.is_clean());
    drop(c);
    drop(r);
}

#[test]
fn i4_short_alien_redb_destroys_nothing() {
    let _g = serial();
    let a = seed("sweep-i4a", 600);
    let b = {
        let s = Scratch::new("sweep-i4b");
        let (mut c, r, _) = open(cfg_of(&s)).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut ch = Chain::new(64, 200, 3);
        let bs = ch.build(300, 7);
        c.extend(&commits(&bs)).unwrap();
        c.flush().unwrap();
        drop(c);
        drop(r);
        s
    };

    let hseg = a.0.join("segments").join("hdr").join("000000.hseg");
    let before = std::fs::metadata(&hseg).unwrap().len();
    std::fs::copy(b.0.join("chain.redb"), a.0.join("chain.redb")).unwrap();
    drop(b);

    let res = open(cfg_of(&a));
    let after = std::fs::metadata(&hseg).unwrap().len();
    match &res {
        Ok((_, r, _)) => println!("  open OK, tip {}", r.tip().height),
        Err(e) => println!("  open REFUSED: {e}"),
    }
    println!("  000000.hseg {before} B -> {after} B");
    assert!(
        matches!(res, Err(StoreError::TipNotInSegments { .. })),
        "expected TipNotInSegments"
    );
    assert_eq!(before, 600 * 132);
    assert_eq!(
        after, before,
        "the error says nothing was truncated; {} headers went missing",
        (before - after) / 132
    );

    assert!(matches!(open(cfg_of(&a)), Err(StoreError::TipNotInSegments { .. })));
    assert_eq!(std::fs::metadata(&hseg).unwrap().len(), before);
}

#[test]
fn i6_torn_redb_named_not_panic() {
    let _g = serial();

    for cut in [4_096u64, 65_536, 1 << 20] {
        let s = seed(&format!("i6-torn-{cut}"), 2_000);
        let db = s.0.join("chain.redb");
        let hseg = s.0.join("segments").join("hdr").join("000000.hseg");
        let before_db = std::fs::metadata(&db).unwrap().len();
        let before_seg = std::fs::metadata(&hseg).unwrap().len();
        assert!(before_db > cut, "store too small to cut {cut}");

        {
            let f = std::fs::OpenOptions::new().write(true).open(&db).unwrap();
            f.set_len(before_db - cut).unwrap();
            f.sync_all().unwrap();
        }

        let res = open(cfg_of(&s));
        match &res {
            Err(StoreError::DatabaseAsserted { path, file_len, detail }) => {
                assert_eq!(path, &db);
                assert_eq!(*file_len, before_db - cut);
                assert!(!detail.is_empty(), "the assertion text must be carried");
            }
            Ok(_) => panic!("cut {cut}: a torn chain.redb opened without error"),
            Err(other) => panic!("cut {cut}: expected DatabaseAsserted, got {other}"),
        }

        assert_eq!(std::fs::metadata(&db).unwrap().len(), before_db - cut);
        assert_eq!(
            std::fs::metadata(&hseg).unwrap().len(),
            before_seg,
            "cut {cut}: a refused open must not touch the segments"
        );

        assert!(matches!(
            open(cfg_of(&s)),
            Err(StoreError::DatabaseAsserted { .. })
        ));
    }
}

#[test]
fn i7_flipped_redb_no_wrong_header() {
    use std::io::{Seek, SeekFrom, Write};
    let _g = serial();

    const N: u64 = 300;
    const PROBES: u64 = 400;

    let s = seed("i7-flip-scan", N);
    let db = s.0.join("chain.redb");
    let len = std::fs::metadata(&db).unwrap().len();
    let pristine = std::fs::read(&db).unwrap();

    let (truth, accounts) = {
        let (c, r, _) = open(cfg_of(&s)).expect("open pristine");
        let hashes: Vec<[u8; 32]> = (0..N).map(|h| r.hash_at(h).unwrap().expect("hash")).collect();
        for h in &hashes {
            assert!(r.header_by_hash(h).unwrap().is_some(), "hash_index seeded");
        }
        let accs: Vec<([u8; 20], Account)> = (0..64u64)
            .map(addr)
            .map(|a| (a, r.account(&a).unwrap()))
            .collect();
        drop(c);
        drop(r);
        (hashes, accs)
    };

    let (mut refused, mut panicked, mut opened_clean, mut opened_flagged) = (0, 0, 0, 0);
    let mut wrong = Vec::new();

    for i in 0..PROBES {
        let at = (len / PROBES) * i + 37;
        if at >= len {
            break;
        }
        std::fs::write(&db, &pristine).unwrap();
        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&db).unwrap();
            f.seek(SeekFrom::Start(at)).unwrap();
            let flipped = pristine[at as usize] ^ 0xFF;
            f.write_all(&[flipped]).unwrap();
            f.sync_all().unwrap();
        }

        assert_ne!(
            std::fs::read(&db).unwrap()[at as usize],
            pristine[at as usize],
            "the flip at {at} did not reach the disk"
        );

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (c, r, _) = open(cfg_of(&s))?;

            let mut bad = Vec::new();

            for (h, want) in truth.iter().enumerate() {
                match r.header_by_hash(want) {
                    Ok(Some((height, _))) if height == h as u64 => {}
                    Ok(Some(_)) => bad.push((h as u64, "hash_index points at the wrong height")),
                    Ok(None) => bad.push((h as u64, "hash_index lost the header")),
                    Err(_) => {}
                }
            }

            for (i, (a, want)) in accounts.iter().enumerate() {
                match r.account(a) {
                    Ok(got) if got == *want => {}
                    Ok(_) => bad.push((i as u64, "account row differs")),
                    Err(_) => {}
                }
            }
            let fp = r.verify_state_fingerprint().is_ok();
            drop(c);
            drop(r);
            Ok::<_, StoreError>((bad, fp))
        }));

        match outcome {
            Err(_) => panicked += 1,
            Ok(Err(_)) => refused += 1,
            Ok(Ok((bad, fp))) => {
                if !bad.is_empty() {
                    if fp {
                        wrong.push((at, bad.len(), bad[0].1));
                    } else {
                        opened_flagged += 1;
                    }
                } else if fp {
                    opened_clean += 1;
                } else {
                    opened_flagged += 1;
                }
            }
        }
    }

    std::fs::write(&db, &pristine).unwrap();

    println!(
        "\n  i7: {PROBES} single-byte flips across {len} B of chain.redb\n     \
         refused {refused} | panicked {panicked} | opened+correct {opened_clean} | \
         opened+fingerprint-flagged {opened_flagged} | SILENTLY WRONG {}",
        wrong.len()
    );
    for (at, n, why) in &wrong {
        println!(
            "     offset {at}: {n} redb-backed read(s) wrong ({why}) AND verify_state_fingerprint said OK"
        );
    }

    assert!(
        wrong.is_empty(),
        "a flipped byte produced redb-backed answers that differ from what was \
         written, with a clean state fingerprint: {wrong:?}"
    );

    assert_eq!(
        panicked, 0,
        "a redb assertion escaped open() as a panic instead of a refusal"
    );

    assert!(
        refused + opened_flagged > 0,
        "every probe landed in free space; the scan proved nothing - widen it"
    );
}
