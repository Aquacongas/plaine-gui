mod common;

use common::*;

use plaine_consensus::constants::MAX_REORG_DEPTH;
use plaine_storage::{
    open, DurabilityMode, ReorgPlan, StateDelta, StoreConfig, StoreError, UndoRec,
};

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.prune = false;
    c.ibd_batch_blocks = Some(256);
    c
}

fn seeded(name: &str, n: u64) -> (Scratch, Chain, Vec<Block>) {
    let s = Scratch::new(name);
    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = Chain::new(48, 180, 3);
    let main = ch.build(n, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    (s, ch, main)
}

#[test]
fn g1_empty_body_refused() {
    let _g = serial();
    let (s, mut ch, main) = seeded("sweep-g1", 200);
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");

    let mut probe = ch.build_one(1);
    probe.body.clear();
    let e = c.extend(&[probe.to_commit()]);
    assert!(
        matches!(e, Err(StoreError::BadPlan(_))),
        "extend accepted an empty body: {e:?}"
    );
    ch.rewind(&[probe], 199, main[199].hash);

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let n = 199 - fork + 1;
    let mut alt = ch.build(n, 2);
    alt[4].body.clear();
    let victim = alt[4].height;
    let rollback: Vec<u64> = (fork + 1..=199).rev().collect();
    let cs = commits(&alt);
    let plan = ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &cs,
    };
    let receipt = c.reorg(&plan);
    println!(
        "  reorg with an empty body -> {:?}",
        receipt.as_ref().err().map(|e| e.to_string())
    );
    assert!(
        matches!(receipt, Err(StoreError::BadPlan(_))),
        "reorg accepted an empty body: {receipt:?}"
    );
    drop(cs);

    assert_eq!(r.tip().height, 199);
    assert_eq!(r.tip().hash, main[199].hash);
    assert_eq!(
        r.header_at(victim).unwrap().unwrap(),
        main[victim as usize].header
    );
    assert!(
        !c.is_poisoned(),
        "a refusal before the first write must not poison"
    );
    let mut buf = Vec::new();
    assert!(r.body_at(victim, &mut buf).unwrap().is_some());
    r.verify_state_fingerprint().expect("state untouched");
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg_of(&s)).expect("reopen");
    println!("  reopen: body_damage = {:?}", rep.integrity.body_damage);
    assert!(rep.integrity.is_clean());
    assert_eq!(r.body_watermark(), 200);
    drop(c);
    drop(r);
}

#[test]
fn g2_mismatched_pair_refused() {
    let _g = serial();
    let (s, mut ch, main) = seeded("sweep-g2", 200);
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let alt = ch.build(199 - fork + 1, 2);

    let victim = alt[4].deltas[2];
    println!(
        "  height {} pays {:?} -> balance {}",
        alt[4].height,
        &victim.addr[..4],
        victim.balance
    );
    let deltas: Vec<StateDelta> = alt[4].deltas.clone();
    let undo: Vec<UndoRec> = alt[4].undo[..2].to_vec();

    {
        let mut b = alt[4].to_commit();
        b.deltas = &deltas;
        b.undo = &undo;
        b.height = 200;
        let e = c.extend(&[b]);
        assert!(
            matches!(e, Err(StoreError::BadPlan(_))),
            "extend accepted a mismatched pair: {e:?}"
        );
    }

    let mut cs = commits(&alt);
    cs[4].deltas = &deltas;
    cs[4].undo = &undo;
    let rollback: Vec<u64> = (fork + 1..=199).rev().collect();
    let plan = ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &cs,
    };
    let out = c.reorg(&plan);
    println!(
        "  reorg with 3 deltas / 2 undo -> {:?}",
        out.as_ref().err().map(|e| e.to_string())
    );
    assert!(
        matches!(out, Err(StoreError::BadPlan(_))),
        "reorg accepted a mismatched pair: {out:?}"
    );

    assert_eq!(r.tip().height, 199);
    assert_eq!(r.tip().hash, main[199].hash);
    assert!(!c.is_poisoned());
    r.verify_state_fingerprint()
        .expect("fingerprint after a refused reorg");
    drop(c);
    drop(r);
}

#[test]
fn g3_refused_reorg_no_change() {
    let _g = serial();
    let (s, mut ch, main) = seeded("sweep-g3", 200);
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");
    let before_tip = r.tip();
    let before_issued = r.issued();
    r.verify_state_fingerprint().expect("healthy before");

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let alt = ch.build(199 - fork + 1, 2);

    let mut undo = alt[5].undo.clone();
    undo[0].addr = [0xEE; 20];
    let mut cs = commits(&alt);
    cs[5].undo = &undo;
    let rollback: Vec<u64> = (fork + 1..=199).rev().collect();
    let plan = ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &cs,
    };
    let e = c.reorg(&plan);
    println!("  reorg -> {:?}", e.as_ref().err().map(|x| x.to_string()));
    assert!(matches!(e, Err(StoreError::BadPlan(_))), "expected refusal");
    drop(cs);

    let on_disk = r.header_at(fork + 1).unwrap().unwrap();
    assert_eq!(
        on_disk,
        main[(fork + 1) as usize].header,
        "a REFUSED plan reached the header segment"
    );
    assert!(
        !c.is_poisoned(),
        "an up-front refusal must leave the handle usable"
    );

    c.mark_invalid(&alt[5].hash, plaine_storage::InvalidReason::BadTx)
        .expect("mark_invalid after a refused branch");
    assert_eq!(r.tip(), before_tip);
    assert_eq!(r.issued(), before_issued);
    drop(c);
    drop(r);

    let hseg = s.0.join("segments").join("hdr").join("000000.hseg");
    assert_eq!(std::fs::metadata(&hseg).unwrap().len(), 200 * 132);
    let (c, r, rep) = open(cfg_of(&s)).expect("the store must still open");
    println!(
        "  reopen: tip {} truncated_to {:?} clean {}",
        r.tip().height,
        rep.headers_truncated_to,
        rep.integrity.is_clean()
    );
    assert_eq!(r.tip().hash, main[199].hash);
    assert!(rep.headers_truncated_to.is_none());
    assert!(rep.integrity.is_clean());
    assert_eq!(std::fs::metadata(&hseg).unwrap().len(), 200 * 132);
    drop(c);
    drop(r);
}

#[test]
fn g3b_failure_poisons_handle_disk_recovers() {
    let _g = serial();
    let (s, mut ch, main) = seeded("sweep-g3b", 200);
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let alt = ch.build(199 - fork + 1, 2);
    let cs = commits(&alt);
    let rollback: Vec<u64> = (fork + 1..=199).rev().collect();

    c.set_stall_hook(Box::new(|p| {
        if p == plaine_storage::StallPoint::ReorgBeforeStateCommit {
            panic!("injected fault after the in-place header overwrite");
        }
    }));
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let hit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.reorg(&ReorgPlan {
            fork_height: fork,
            rollback: &rollback,
            apply: &cs,
        })
    }));
    std::panic::set_hook(hook);
    assert!(hit.is_err(), "the injected fault did not fire");
    drop(cs);

    let on_disk = r.header_at(fork + 1).unwrap().unwrap();
    assert_eq!(on_disk, alt[0].header, "the overwrite did not happen");

    assert!(
        c.is_poisoned(),
        "a panic through the reorg left a usable handle"
    );
    assert!(matches!(
        c.mark_invalid(&alt[0].hash, plaine_storage::InvalidReason::BadTx),
        Err(StoreError::Poisoned { .. })
    ));
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg_of(&s)).expect("open must recover");
    println!(
        "  reopen: hdr_undo_replayed {:?} tip {} truncated {:?}",
        rep.hdr_undo_replayed,
        r.tip().height,
        rep.headers_truncated_to
    );
    assert!(
        rep.hdr_undo_replayed.is_some(),
        "the undo blob was not replayed"
    );
    assert_eq!(r.tip().height, 199);
    assert_eq!(r.tip().hash, main[199].hash);
    assert_eq!(
        r.header_at(fork + 1).unwrap().unwrap(),
        main[(fork + 1) as usize].header
    );
    assert!(rep.integrity.is_clean());
    r.verify_state_fingerprint().expect("state after recovery");
    drop(c);
    drop(r);
}

#[test]
fn g3c_poisoned_handle_refuses_writes() {
    let _g = serial();
    let (s, mut ch, main) = seeded("sweep-g3c", 200);
    let (c, r, _) = open(cfg_of(&s)).expect("reopen");

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let alt = ch.build(199 - fork + 1, 2);
    let cs = commits(&alt);
    let rollback: Vec<u64> = (fork + 1..=199).rev().collect();

    {
        use redb::{Database, TableDefinition};
        const UNDO: TableDefinition<u64, &[u8]> = TableDefinition::new("undo");
        drop(c);
        drop(r);
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(UNDO).unwrap();
            t.remove(195u64).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
    }
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");
    let e = c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &cs,
    });
    println!("  reorg -> {:?}", e.as_ref().err().map(|x| x.to_string()));
    assert!(e.is_err(), "the fault did not fire");
    assert!(
        c.is_poisoned(),
        "a mid-flight failure did not poison the handle"
    );

    let m = c.mark_invalid(&alt[5].hash, plaine_storage::InvalidReason::BadTx);
    println!(
        "  mark_invalid -> {:?}",
        m.as_ref().err().map(|x| x.to_string())
    );
    assert!(matches!(m, Err(StoreError::Poisoned { .. })));
    assert!(matches!(c.flush(), Err(StoreError::Poisoned { .. })));
    assert!(matches!(
        c.clear_invalid_all(),
        Err(StoreError::Poisoned { .. })
    ));
    assert!(matches!(c.prune_to(10), Err(StoreError::Poisoned { .. })));
    assert!(matches!(
        c.extend(&commits(&alt)[..1]),
        Err(StoreError::Poisoned { .. })
    ));
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg_of(&s)).expect("open after a poisoned handle");
    println!(
        "  reopen: tip {} clean {}",
        r.tip().height,
        rep.integrity.is_clean()
    );
    assert_eq!(r.tip().height, 199);
    drop(c);
    drop(r);
}

#[test]
fn g4_reorg_enforces_max_body_bytes() {
    let _g = serial();
    let (s, mut ch, main) = seeded("sweep-g4", 200);
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let mut alt = ch.build(199 - fork + 1, 2);

    let over = plaine_storage::MAX_BODY_BYTES + 1;
    alt[4].body = vec![0x5Au8; over];
    let cs = commits(&alt);
    let rollback: Vec<u64> = (fork + 1..=199).rev().collect();
    let out = c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &cs,
    });
    println!(
        "  reorg with a {over}-byte body -> {:?}",
        out.as_ref().err().map(|e| e.to_string())
    );
    assert!(
        matches!(out, Err(StoreError::BadPlan(_))),
        "reorg accepted a body over MAX_BODY_BYTES: {out:?}"
    );
    assert_eq!(r.tip().height, 199);
    assert_eq!(r.body_watermark(), 200);
    drop(cs);
    drop(c);
    drop(r);

    let (c, r, rep) = open(cfg_of(&s)).expect("reopen");
    println!(
        "  after a clean restart: bodies_truncated_to {:?}",
        rep.bodies_truncated_to
    );
    assert!(
        rep.bodies_truncated_to.is_none(),
        "the watermark walked back"
    );
    assert_eq!(r.hdr_watermark(), 200);
    assert_eq!(r.body_watermark(), 200);
    let mut buf = Vec::new();
    assert!(r.body_at(196, &mut buf).unwrap().is_some());
    drop(c);
    drop(r);
}

#[test]
fn g5_apply_heights_contiguous() {
    let _g = serial();
    let (s, mut ch, main) = seeded("sweep-g5", 200);
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let alt = ch.build(199 - fork + 1, 2);
    let mut cs = commits(&alt);
    cs[3].height += 7;
    let rollback: Vec<u64> = (fork + 1..=199).rev().collect();
    let out = c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &cs,
    });
    println!(
        "  reorg with a gap in apply -> {:?}",
        out.as_ref().err().map(|e| e.to_string())
    );
    assert!(matches!(out, Err(StoreError::BadPlan(_))), "{out:?}");
    assert_eq!(r.tip().hash, main[199].hash);
    drop(cs);
    drop(c);
    drop(r);
}
