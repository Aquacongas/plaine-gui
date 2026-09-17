mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use common::*;

use plaine_consensus::constants::MAX_REORG_DEPTH;
use plaine_storage::{
    barriers_performed, open, Account, DurabilityMode, ReorgPlan, StallPoint, StateDelta,
    StoreConfig, StoreError, UndoRec,
};

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.prune = false;
    c.ibd_batch_blocks = Some(256);
    c
}

#[test]
fn barrier_before_watermark_commit() {
    let _g = serial();
    let s = Scratch::new("defence-barrier");
    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    let mut ch = Chain::new(16, 120, 2);

    c.set_mode(DurabilityMode::Tip).unwrap();
    let at_commit = Arc::new(AtomicU64::new(u64::MAX));
    let sink = at_commit.clone();
    c.set_stall_hook(Box::new(move |p| {
        if p == StallPoint::BeforeRedbCommit {
            sink.store(barriers_performed(), Ordering::SeqCst);
        }
    }));

    let blocks = ch.build(4, 1);
    let mut prev = barriers_performed();
    for b in &blocks {
        at_commit.store(u64::MAX, Ordering::SeqCst);
        c.extend(&[b.to_commit()]).unwrap();
        let sampled = at_commit.load(Ordering::SeqCst);
        println!(
            "  height {:>2}: barriers before {prev}, at BeforeRedbCommit {sampled}",
            b.height
        );
        assert_ne!(sampled, u64::MAX, "the commit boundary was never reached");

        assert!(
            sampled >= prev + 3,
            "height {} committed with {} barrier(s) since the last commit; the segment writes \
             were not flushed before the watermark rose",
            b.height,
            sampled - prev
        );
        prev = barriers_performed();
    }
    assert_eq!(r.tip().height, 3);

    let main = ch.build(40, 1);
    c.set_mode(DurabilityMode::Ibd).unwrap();
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    let tip = r.tip().height;
    let fork = tip - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, r.hash_at(fork).unwrap().unwrap());
    let alt = ch.build(tip - fork + 1, 9);
    let rollback: Vec<u64> = (fork + 1..=tip).rev().collect();
    let before = barriers_performed();
    c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &rollback,
        apply: &commits(&alt),
    })
    .unwrap();
    let after = barriers_performed();
    println!("  reorg: {} barrier(s)", after - before);
    assert!(
        after > before,
        "a reorg raised both watermarks without a single segment barrier"
    );
    drop(c);
    drop(r);
}

#[test]
fn spent_to_zero_keeps_nonce() {
    let _g = serial();
    let s = Scratch::new("defence-nonce");
    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    let mut ch = Chain::new(8, 100, 1);
    let spender = addr(1);
    let sink = addr(2);

    let mut b0 = ch.build_one(1);
    b0.deltas = vec![StateDelta {
        addr: spender,
        balance: 5_000,
        nonce: 1,
    }];
    b0.undo = vec![UndoRec {
        addr: spender,
        prev_balance: 0,
        prev_nonce: 0,
        existed: false,
    }];
    let mut b1 = ch.build_one(1);

    b1.deltas = vec![
        StateDelta {
            addr: spender,
            balance: 0,
            nonce: 2,
        },
        StateDelta {
            addr: sink,
            balance: 5_000,
            nonce: 0,
        },
    ];
    b1.undo = vec![
        UndoRec {
            addr: spender,
            prev_balance: 5_000,
            prev_nonce: 1,
            existed: true,
        },
        UndoRec {
            addr: sink,
            prev_balance: 0,
            prev_nonce: 0,
            existed: false,
        },
    ];
    c.extend(&commits(&[b0, b1])).unwrap();
    c.flush().unwrap();

    let got = r.account(&spender).unwrap();
    println!("  spender after spending everything: {got:?}");
    assert_eq!(
        got,
        Account {
            balance: 0,
            nonce: 2
        },
        "a zero-balance account with nonce > 0 was deleted: its nonce is now replayable"
    );
    r.verify_state_fingerprint()
        .expect("fingerprint after a spend-to-zero");

    drop(c);
    drop(r);
    let (mut c, r, _) = open(cfg_of(&s)).expect("reopen");
    assert_eq!(
        r.account(&spender).unwrap(),
        Account {
            balance: 0,
            nonce: 2
        }
    );

    let mut b2 = ch.build_one(1);
    b2.deltas = vec![StateDelta {
        addr: spender,
        balance: 7,
        nonce: 3,
    }];
    b2.undo = vec![UndoRec {
        addr: spender,
        prev_balance: 0,
        prev_nonce: 2,
        existed: true,
    }];
    c.extend(&[b2.to_commit()]).unwrap();
    c.flush().unwrap();
    assert_eq!(
        r.account(&spender).unwrap(),
        Account {
            balance: 7,
            nonce: 3
        }
    );

    let mut b3 = ch.build_one(1);
    b3.deltas = vec![StateDelta {
        addr: sink,
        balance: 0,
        nonce: 0,
    }];
    b3.undo = vec![UndoRec {
        addr: sink,
        prev_balance: 5_000,
        prev_nonce: 0,
        existed: true,
    }];
    c.extend(&[b3.to_commit()]).unwrap();
    c.flush().unwrap();
    assert_eq!(r.account(&sink).unwrap(), Account::default());

    r.verify_state_fingerprint()
        .expect("fingerprint after a real delete");
    drop(c);
    drop(r);
}

#[test]
fn misordered_rollback_refused() {
    let _g = serial();
    let s = Scratch::new("defence-order");
    let (mut c, r, _) = open(cfg_of(&s)).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut ch = Chain::new(48, 180, 3);
    let main = ch.build(200, 1);
    c.extend(&commits(&main)).unwrap();
    c.flush().unwrap();
    let before_tip = r.tip();
    let before_fp = r.state_fingerprint();

    let fork = 199 - MAX_REORG_DEPTH / 3;
    ch.rewind(&main, fork, main[fork as usize].hash);
    let alt = ch.build(199 - fork + 1, 2);
    let cs = commits(&alt);

    let ascending: Vec<u64> = (fork + 1..=199).collect();
    let e = c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &ascending,
        apply: &cs,
    });
    println!(
        "  ascending rollback -> {:?}",
        e.as_ref().err().map(|x| x.to_string())
    );
    assert!(matches!(e, Err(StoreError::BadPlan(_))), "{e:?}");

    let mut repeated: Vec<u64> = (fork + 1..=199).rev().collect();
    repeated[1] = repeated[0];
    let e = c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &repeated,
        apply: &cs,
    });
    println!(
        "  repeated height    -> {:?}",
        e.as_ref().err().map(|x| x.to_string())
    );
    assert!(matches!(e, Err(StoreError::BadPlan(_))), "{e:?}");

    let mut shuffled: Vec<u64> = (fork + 1..=199).rev().collect();
    let n = shuffled.len();
    shuffled.swap(n / 2, n / 2 + 1);
    let e = c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &shuffled,
        apply: &cs,
    });
    println!(
        "  shuffled interior  -> {:?}",
        e.as_ref().err().map(|x| x.to_string())
    );
    assert!(matches!(e, Err(StoreError::BadPlan(_))), "{e:?}");

    assert_eq!(r.tip(), before_tip);
    assert_eq!(r.state_fingerprint(), before_fp);
    assert!(!c.is_poisoned());
    r.verify_state_fingerprint().expect("state untouched");

    let descending: Vec<u64> = (fork + 1..=199).rev().collect();
    c.reorg(&ReorgPlan {
        fork_height: fork,
        rollback: &descending,
        apply: &cs,
    })
    .expect("the descending form of the same plan");
    assert_eq!(r.tip().hash, alt.last().unwrap().hash);
    r.verify_state_fingerprint()
        .expect("state after the accepted reorg");
    drop(cs);
    drop(c);
    drop(r);
}
