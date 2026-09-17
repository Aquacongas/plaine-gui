mod common;

use common::{serial, Chain, Scratch};
use plaine_storage::{open, DurabilityMode, StoreConfig, StoreError};
use redb::{Database, ReadableTable, TableDefinition};

const STATE: TableDefinition<&[u8; 20], &[u8; 24]> = TableDefinition::new("state");

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c
}

fn seed(name: &str) -> Scratch {
    let s = Scratch::new(name);
    let (mut c, r, _) = open(cfg_of(&s)).expect("seed open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(200, 1);
    c.extend(&common::commits(&bs)).unwrap();
    c.flush().unwrap();
    r.verify_state_fingerprint()
        .expect("a fresh store must verify");
    drop(c);
    drop(r);
    s
}

#[test]
fn flipped_state_bit_reports_mismatch() {
    let _g = serial();
    let s = seed("fp-flip");

    let (addr, before, after) = {
        let db = Database::create(s.0.join("chain.redb")).unwrap();
        let (addr, raw) = {
            let txn = db.begin_read().unwrap();
            let t = txn.open_table(STATE).unwrap();
            let e = t.iter().unwrap().next().unwrap().unwrap();
            (*e.0.value(), *e.1.value())
        };
        let mut new = raw;
        new[3] ^= 0x08;
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(STATE).unwrap();
            t.insert(&addr, &new).unwrap();
        }
        txn.commit().unwrap();
        drop(db);
        (addr, raw, new)
    };
    assert_ne!(before, after, "the flip did not change the row");

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    assert!(
        rep.integrity.is_clean(),
        "open() must not read the state table: {:?}",
        rep.integrity
    );
    let err = r
        .verify_state_fingerprint()
        .expect_err("one flipped bit in an account row went unnoticed");
    match &err {
        StoreError::StateFingerprint { stored, computed } => {
            assert_ne!(stored, computed, "the mismatch reports two equal digests");
        }
        other => panic!("a rotted state row was reported as {other:?}, not as a mismatch"),
    }
    let msg = err.to_string();
    assert!(
        msg.contains("fingerprint"),
        "the message does not name the fingerprint: {msg}"
    );
    assert!(
        !msg.contains("io:") && !msg.to_lowercase().contains("i/o"),
        "a mismatch is being described as an I/O failure: {msg}"
    );
    println!("  1 bit in a state row -> {msg}");
    println!("  addr {}", plaine_storage::crc32c(&addr));
    drop(c);
    drop(r);
}

#[test]
fn mismatch_has_one_construction_site() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites = Vec::new();
    let mut files = 0u32;
    for e in std::fs::read_dir(&dir).expect("src/ must be readable") {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&p).unwrap();
        for (n, line) in text.lines().enumerate() {
            if line.contains("StoreError::StateFingerprint {")
                || line.contains("Err(StoreError::StateFingerprint")
            {
                sites.push(format!(
                    "{}:{}",
                    p.file_name().unwrap().to_string_lossy(),
                    n + 1
                ));
            }
        }
    }

    assert!(
        files >= 10,
        "the scan read only {files} source files; it did not run"
    );
    assert_eq!(
        sites.len(),
        1,
        "StoreError::StateFingerprint is constructed at {} sites: {sites:?}. \
         `noded` branches on this variant to decide between refusing to start and \
         logging a soft warning, so a second construction site is a second meaning.",
        sites.len()
    );
    assert!(
        sites[0].starts_with("reader.rs:"),
        "the one construction site moved out of reader.rs: {sites:?}"
    );
    println!(
        "  StoreError::StateFingerprint constructed at exactly one site: {}",
        sites[0]
    );
}
