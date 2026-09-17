mod support;

use plaine_chain::error::Condition;
use plaine_chain::mock::{PowMode, Scenario};
use plaine_chain::Progress;
use plaine_consensus::codec::Header;
use plaine_consensus::constants::VERSION_BASE;
use support::*;

fn synced_rig() -> (Rig, Scenario) {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    assert_eq!(r.height(), 20);
    r.pow.reset();
    (r, chain)
}

fn assert_no_verify(name: &str, tweak: impl Fn(Header) -> Header) {
    let (mut r, chain) = synced_rig();
    let parent = chain.tip();
    let bits = chain.expected_bits(parent.height);
    let hdr = tweak(Header {
        version: VERSION_BASE,
        height: parent.height + 1,
        prev_hash: parent.hash,
        tx_root: [7u8; 32],
        ext_root: [0u8; 32],
        time: parent.time + 60,
        bits,
        author_note_len: 0,
        nonce: 0,
    });
    let a = r.cm.submit_headers(9, &[hdr.encode()]).expect("not halted");
    assert_eq!(a.connected, 0, "{name}: nothing may be connected");
    assert_eq!(a.rejected, 1, "{name}: exactly one rejection");
    assert_eq!(
        r.pow.calls(),
        0,
        "{name}: the interpreter must not be reached"
    );
    assert_eq!(r.height(), 20, "{name}: the tip must not move");
}

#[test]
fn s1_bad_ext_root_skips_interpreter() {
    assert_no_verify("ext_root", |mut h| {
        h.ext_root = [1u8; 32];
        h
    });
}

#[test]
fn s1_note_len_257_skips_interpreter() {
    assert_no_verify("author_note_len 257", |mut h| {
        h.author_note_len = 257;
        h
    });
}

#[test]
fn s1_wrong_version_skips_interpreter() {
    assert_no_verify("version top bits", |mut h| {
        h.version = 0x4000_0000;
        h
    });
}

#[test]
fn s1_bits_over_limit_skips_interpreter() {
    assert_no_verify("bits over POW_LIMIT", |mut h| {
        h.bits = 0x2100_ffff;
        h
    });
}

#[test]
fn s2_unknown_parent_skips_interpreter() {
    assert_no_verify("unknown parent", |mut h| {
        h.prev_hash = [0xAB; 32];
        h
    });
}

#[test]
fn s2_bad_height_skips_interpreter() {
    assert_no_verify("height lie", |mut h| {
        h.height = 5_000;
        h
    });
}

#[test]
fn s3_bad_bits_skips_interpreter() {
    assert_no_verify("bits != ASERT(parent)", |mut h| {
        h.bits = 0x1d00_ffff;
        h
    });
}

#[test]
fn s4_stale_time_skips_interpreter() {
    assert_no_verify("time <= MTP", |mut h| {
        h.time = T0;
        h
    });
}

#[test]
fn s4_future_time_skips_interpreter() {
    let (mut r, chain) = synced_rig();
    let parent = chain.tip();
    let now = r.clock.now_unix();
    let hdr = Header {
        version: VERSION_BASE,
        height: parent.height + 1,
        prev_hash: parent.hash,
        tx_root: [7u8; 32],
        ext_root: [0u8; 32],
        time: now + 601,
        bits: chain.expected_bits(parent.height),
        author_note_len: 0,
        nonce: 0,
    };
    let a = r.cm.submit_headers(9, &[hdr.encode()]).expect("not halted");
    assert_eq!(a.rejected, 1);
    assert_eq!(
        r.pow.calls(),
        0,
        "MAX_FUTURE_DRIFT is checked before the interpreter"
    );
}

#[test]
fn s5_deep_fork_skips_interpreter() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(200);
    let mut r = Rig::new(&chain, p.clone());
    r.sync(&chain, 1);
    assert_eq!(r.height(), 200);
    r.pow.reset();

    let attacker = chain.fork_at(99).spacing(1).extend(101);
    let a = r.offer(7, &blocks_above(&attacker, 99));
    assert_eq!(a.connected, 0);
    assert!(a.rejected > 0);
    assert_eq!(
        r.pow.calls(),
        0,
        "layer 1 refuses the branch before any PoW work"
    );
    assert_eq!(r.height(), 200);
}

#[test]
fn s6_no_more_work_skips_interpreter() {
    let (mut r, chain) = synced_rig();

    let parent = chain.blocks[19].rec;
    let mut sibling = None;
    for n in 0..4096u64 {
        let h = Header {
            version: VERSION_BASE,
            height: 20,
            prev_hash: parent.hash,
            tx_root: [9u8; 32],
            ext_root: [0u8; 32],
            time: parent.time + 60,
            bits: chain.expected_bits(parent.height),
            author_note_len: 0,
            nonce: n,
        };
        let rec = rec(h.encode());
        if rec.hash > r.tip_hash() {
            sibling = Some(h);
            break;
        }
    }
    let h = sibling.expect("a higher-hash sibling exists within 4096 nonces");
    let a = r.cm.submit_headers(9, &[h.encode()]).expect("not halted");
    assert_eq!(a.connected, 0);
    assert_eq!(
        r.pow.calls(),
        0,
        "equal work with a higher hash is not worth an interpreter call"
    );
}

#[test]
fn s0_known_header_skips_interpreter() {
    let (mut r, chain) = synced_rig();
    let a =
        r.cm.submit_headers(9, &chain.raw_headers_from(1))
            .expect("not halted");
    assert_eq!(
        a.duplicates, 20,
        "every one of them is already in the arena"
    );
    assert_eq!(a.connected, 0);
    assert_eq!(r.pow.calls(), 0, "dedup is stage 0, not step 7");
}

#[test]
fn tie_break_costs_one_verify() {
    let (mut r, chain) = synced_rig();
    let parent = chain.blocks[19].rec;
    let mut lower = None;
    for n in 1..8192u64 {
        let h = Header {
            version: VERSION_BASE,
            height: 20,
            prev_hash: parent.hash,
            tx_root: [9u8; 32],
            ext_root: [0u8; 32],
            time: parent.time + 60,
            bits: chain.expected_bits(parent.height),
            author_note_len: 0,
            nonce: n,
        };
        if rec(h.encode()).hash < r.tip_hash() {
            lower = Some(h);
            break;
        }
    }
    let h = lower.expect("a lower-hash sibling exists within 8192 nonces");
    let a = r.cm.submit_headers(9, &[h.encode()]).expect("not halted");
    assert_eq!(a.connected, 1, "the equal-work sibling is admitted");
    assert_eq!(r.pow.calls(), 1, "exactly one extra verify, no more");
}

#[test]
fn front_loaded_branch_one_call() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(30);
    let mut r = Rig::with_mode(&chain, p.clone(), PowMode::AlwaysOk);
    r.sync(&chain, 1);
    let attacker = chain.fork_at(10).spacing(1).extend(200);
    let first_bad = attacker.blocks[11].rec.hash;
    r.pow.set_mode(PowMode::AllButListed);
    r.pow.reject_hash(first_bad);
    r.pow.reset();
    let a = r.offer(7, &blocks_above(&attacker, 10));
    assert_eq!(a.connected, 0);
    assert_eq!(
        r.pow.calls(),
        1,
        "the fraud at height 11 must cost one verify, not 200 and not a descending scan"
    );
    assert_eq!(r.height(), 30, "the tip never moved");
}

#[test]
fn an_orphan_header_pool_is_unrepresentable() {
    let (mut r, _chain) = synced_rig();
    let before = r.cm.index().len();
    let mut batch = Vec::new();
    for i in 0..2_000u64 {
        let h = Header {
            version: VERSION_BASE,
            height: 21,
            prev_hash: {
                let mut p = [0u8; 32];
                p[0..8].copy_from_slice(&i.to_le_bytes());
                p
            },
            tx_root: [0u8; 32],
            ext_root: [0u8; 32],
            time: T0 + 21 * 60,
            bits: r.params.genesis_bits,
            author_note_len: 0,
            nonce: i,
        };
        batch.push(h.encode());
    }
    let a = r.cm.submit_headers(4, &batch).expect("not halted");
    assert_eq!(a.rejected, 2_000);
    assert_eq!(a.connected, 0);
    assert_eq!(a.staged, 0, "an orphan is never staged either");
    assert_eq!(
        r.cm.index().len(),
        before,
        "the arena did not grow by one entry"
    );
    assert_eq!(r.pow.calls(), 0);
}

#[test]
fn future_drift_not_memoised() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let next = chain.clone().extend(1);
    let block = next.blocks[6].clone();

    r.clock.set_unix(block.rec.time - 601);
    let a =
        r.cm.submit_headers(3, &[block.rec.raw])
            .expect("not halted");
    assert_eq!(a.rejected, 1);
    assert_eq!(a.connected, 0);

    r.clock.set_unix(block.rec.time);
    let b =
        r.cm.submit_headers(3, &[block.rec.raw])
            .expect("not halted");
    assert_eq!(b.duplicates, 0, "the verdict must not have been memoised");
    assert_eq!(
        b.connected, 1,
        "the same bytes are accepted once the clock is right"
    );
}

#[test]
fn pow_failure_is_memoised() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let next = chain.clone().extend(1);
    let block = next.blocks[6].clone();
    r.pow.set_mode(PowMode::AllButListed);
    r.pow.reject_hash(block.rec.hash);
    r.pow.reset();

    let a =
        r.cm.submit_headers(3, &[block.rec.raw])
            .expect("not halted");
    assert_eq!(a.connected, 0);
    assert_eq!(r.pow.calls(), 1);
    let b =
        r.cm.submit_headers(3, &[block.rec.raw])
            .expect("not halted");
    assert_eq!(
        b.duplicates, 1,
        "a PoW failure is intrinsic, so it is memoised"
    );
    assert_eq!(r.pow.calls(), 1, "the second offer costs nothing");
}

#[test]
fn the_interpreter_budget_binds_in_virtual_time() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(1);
    let mut r = Rig::new(&chain, p.clone());
    r.sync(&chain, 1);
    let long = chain.clone().extend(400);
    r.clock.set_unix(long.tip().time);
    r.pow.set_cost_micros(3_000);
    r.pow.reset();

    let a =
        r.cm.submit_headers(2, &long.raw_headers_from(2))
            .expect("not halted");
    assert_eq!(
        a.connected, 85,
        "the class budget binds before the per-peer bucket: 83 shared + 2 reserved"
    );
    assert!(r.observed(|c| matches!(
        c,
        Condition::BudgetExhausted {
            class: plaine_chain::error::BudgetClass::Interpreter,
            ..
        }
    )));

    r.clock.advance_ms(10_000);
    let b =
        r.cm.submit_headers(2, &long.raw_headers_from(2))
            .expect("not halted");
    assert_eq!(
        b.connected, 48,
        "the per-peer bucket is the binding tier once it refills"
    );
}

#[test]
fn duplicate_flood_abandons_batch() {
    let (mut r, chain) = synced_rig();
    let one = chain.blocks[10].rec.raw;
    let batch: Vec<[u8; 132]> = (0..1_000).map(|_| one).collect();
    let a = r.cm.submit_headers(6, &batch).expect("not halted");
    assert_eq!(
        a.duplicates, 257,
        "the batch is abandoned one past max_duplicates_per_batch"
    );
    assert_eq!(r.pow.calls(), 0);
    for _ in 0..5 {
        r.cm.submit_headers(6, &batch).expect("not halted");
    }
    assert!(
        r.observed(|c| matches!(c, Condition::DuplicateFlood { source: 6, .. })),
        "the transport gets a scoreable signal, not a typed reason"
    );
}

#[test]
fn tip_regression_resyncs_forward() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(10);
    let mut r = Rig::new(&chain, p.clone());
    r.sync(&chain, 1);
    assert_eq!(r.height(), 10);

    r.store.set_tip_regression(3);

    let cm2 = plaine_chain::ChainManager::new(
        r.store.clone(),
        r.store.clone(),
        r.pow.clone(),
        r.clock.clone(),
        p.clone(),
        None,
    )
    .expect("a regressed tip is not corruption");
    assert_eq!(cm2.tip().height, 7);
    let mut r2 = Rig { cm: cm2, ..r };
    r2.store.set_tip_regression(0);
    let longer = chain.clone().extend(5);
    r2.sync(&longer, 8);
    assert_eq!(r2.height(), 15, "it re-synced forward rather than wedging");
    assert!(matches!(
        r2.cm.advance().expect("not halted"),
        Progress::NoChange
    ));
}
