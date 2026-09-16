mod common;

use common::*;

use plaine_storage::{open, DurabilityMode, StoreConfig, StoreError};
use redb::{Database, ReadableTable, TableDefinition};

const UNDO: TableDefinition<u64, &[u8]> = TableDefinition::new("undo");
const STATE: TableDefinition<&[u8; 20], &[u8; 24]> = TableDefinition::new("state");

const SUBSIDY: u128 = 137_672;

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.prune = false;
    c.ibd_batch_blocks = Some(1_024);
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

fn drop_last_header(s: &Scratch) {
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");
    let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
    let len = f.metadata().unwrap().len();
    f.set_len(len - 132).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn h1_rewritten_undo_still_mints() {
    let _g = serial();
    let s = seed("sweep-h1", 300);

    let (addr, forged) = {
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        let mut blob = {
            let txn = db.begin_read().unwrap();
            let t = txn.open_table(UNDO).unwrap();
            t.get(299u64).unwrap().unwrap().value().to_vec()
        };
        let count = u32::from_le_bytes(blob[0..4].try_into().unwrap());
        assert!(count >= 1);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&blob[20..40]);
        assert_eq!(blob[20 + 44], 0, "record 0 must be an EXISTING account");
        let forged: u128 = 999_000_000_000_000_000_000;
        blob[40..56].copy_from_slice(&forged.to_le_bytes());
        blob[4..20].copy_from_slice(&0u128.to_le_bytes());
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(UNDO).unwrap();
            t.insert(299u64, blob.as_slice()).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
        (addr, forged)
    };

    drop_last_header(&s);
    let (c, r, rep) = open(cfg_of(&s)).expect("open must repair");
    assert_eq!(rep.headers_truncated_to, Some(299));

    let got = r.account(&addr).unwrap();
    println!("  account {:02x?}.. balance after rollback : {}", &addr[..4], got.balance);
    println!("  forged pre-image                        : {forged}");
    println!("  issued after rolling back one height    : {}", r.issued());
    println!("  issued a correct rollback would give    : {}", 299 * SUBSIDY);
    println!("  open() integrity.is_clean()             : {}", rep.integrity.is_clean());
    println!("  verify_state_fingerprint()              : {:?}", r.verify_state_fingerprint().is_ok());

    assert_eq!(got.balance, forged, "the forged pre-image was not restored");
    assert_eq!(
        r.issued(),
        300 * SUBSIDY,
        "issued should have dropped to 299 subsidies"
    );
    assert!(rep.integrity.is_clean(), "the boot sweep saw nothing");
    assert!(
        r.verify_state_fingerprint().is_ok(),
        "even the explicit fingerprint check passes: it was maintained FROM the forgery"
    );
    assert!(!r.is_degraded());

    assert_eq!(r.tip().hash, r.hash_at(r.tip().height).unwrap().unwrap());
    drop(c);
    drop(r);
}

#[test]
fn h1b_impossible_issued_named_error() {
    let _g = serial();
    let s = seed("sweep-h1b", 300);
    {
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        let mut blob = {
            let txn = db.begin_read().unwrap();
            let t = txn.open_table(UNDO).unwrap();
            t.get(299u64).unwrap().unwrap().value().to_vec()
        };

        blob[4..20].copy_from_slice(&(u128::MAX / 2).to_le_bytes());
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(UNDO).unwrap();
            t.insert(299u64, blob.as_slice()).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
    }
    drop_last_header(&s);
    let res = open(cfg_of(&s));
    match &res {
        Ok((_, r, _)) => println!("  open OK, issued now {}", r.issued()),
        Err(e) => println!("  open REFUSED: {e}"),
    }
    match res {
        Err(StoreError::EmissionMismatch { stored_mile, formula_mile }) => {
            assert_eq!(stored_mile, 300 * SUBSIDY);
            assert_eq!(formula_mile, u128::MAX / 2);
        }
        other => panic!(
            "expected EmissionMismatch, got {:?}",
            other.map(|(_, r, _)| r.issued())
        ),
    }
}

#[test]
fn h2_fingerprint_forgeable_from_public() {
    let _g = serial();
    let s = seed("sweep-h2", 200);

    let (addr, before, after) = {
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        let (addr, raw) = {
            let txn = db.begin_read().unwrap();
            let t = txn.open_table(STATE).unwrap();
            let e = t.iter().unwrap().next().unwrap().unwrap();
            (*e.0.value(), *e.1.value())
        };
        let before = u128::from_le_bytes(raw[0..16].try_into().unwrap());
        let after = before + 21_000_000_000_000_000_000_000;
        let mut new = raw;
        new[0..16].copy_from_slice(&after.to_le_bytes());
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(STATE).unwrap();
            t.insert(&addr, &new).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
        (addr, before, after)
    };

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    println!("  balance {before} -> {after}");
    println!("  open() integrity.is_clean()  : {}", rep.integrity.is_clean());
    println!("  account balance served       : {}", r.account(&addr).unwrap().balance);
    println!(
        "  verify_state_fingerprint()   : {:?}  <- public, and the caller's to call",
        r.verify_state_fingerprint().is_ok()
    );
    assert!(rep.integrity.is_clean());
    assert!(!r.is_degraded());
    assert_eq!(r.account(&addr).unwrap().balance, after);

    assert!(
        r.verify_state_fingerprint().is_err(),
        "the fingerprint no longer notices an edited row"
    );
    drop(c);
    drop(r);

    {
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
        let mut fp = {
            let txn = db.begin_read().unwrap();
            let t = txn.open_table(META).unwrap();
            let v = t.get("state_fingerprint").unwrap().unwrap().value().to_vec();
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        };
        let mut pre = [0u8; 44];
        pre[0..20].copy_from_slice(&addr);
        pre[20..36].copy_from_slice(&before.to_le_bytes());
        let nonce = {
            let txn = db.begin_read().unwrap();
            let t = txn.open_table(STATE).unwrap();
            let raw = *t.get(&addr).unwrap().unwrap().value();
            u64::from_le_bytes(raw[16..24].try_into().unwrap())
        };
        pre[36..44].copy_from_slice(&nonce.to_le_bytes());
        let old_d = plaine_consensus::blake3::hash(&pre);
        pre[20..36].copy_from_slice(&after.to_le_bytes());
        let new_d = plaine_consensus::blake3::hash(&pre);
        for i in 0..32 {
            fp[i] ^= old_d[i] ^ new_d[i];
        }
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(META).unwrap();
            t.insert("state_fingerprint", &fp[..]).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    println!("  after patching the fingerprint:");
    println!("    integrity.is_clean()        : {}", rep.integrity.is_clean());
    println!("    verify_state_fingerprint()  : {:?}", r.verify_state_fingerprint().is_ok());
    println!("    balance served              : {}", r.account(&addr).unwrap().balance);
    assert!(
        r.verify_state_fingerprint().is_ok(),
        "fingerprint is XOR-of-BLAKE3 over public inputs, so it can always be patched back"
    );
    assert_eq!(r.account(&addr).unwrap().balance, after);
    drop(c);
    drop(r);
}
