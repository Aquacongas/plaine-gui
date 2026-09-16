mod common;

use common::*;

use plaine_consensus::crypto::header_hash;
use plaine_storage::{open, DurabilityMode, StoreConfig, StoreError};

use redb::{Database, TableDefinition};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

fn restore_write(p: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[cfg(not(unix))]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut perms = std::fs::metadata(p).unwrap().permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(p, perms).unwrap();
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

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

#[test]
fn f1_repaired_tip_names_header() {
    let _g = serial();
    let s = seed("sweep-f1", 300);
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");

    {
        let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        let len = f.metadata().unwrap().len();
        f.set_len(len - 132).unwrap();
        f.sync_all().unwrap();
    }

    let (c, r, rep) = open(cfg_of(&s)).expect("open must repair, never refuse");
    assert_eq!(
        rep.headers_truncated_to,
        Some(299),
        "the repair path under test did not run"
    );

    let tip = r.tip();
    assert_eq!(tip.height, 298);
    let real_hash = r.hash_at(298).unwrap().unwrap();
    let real_header = r.header_at(298).unwrap().unwrap();
    assert_eq!(header_hash(&real_header), real_hash);

    println!("  headers_truncated_to : {:?}", rep.headers_truncated_to);
    println!("  reader.tip().height  : {}", tip.height);
    println!("  reader.tip().hash    : {}", hex(&tip.hash));
    println!("  hash_at(tip.height)  : {}", hex(&real_hash));
    println!("  tip().chainwork      : {}", hex(&tip.chainwork[24..32]));

    assert_eq!(
        tip.hash, real_hash,
        "the published tip hash must name the tip header"
    );
    assert_ne!(tip.hash, [0u8; 32], "the zeroed tip is back");

    let published = u64::from_be_bytes(tip.chainwork[24..32].try_into().unwrap());
    println!("  published chainwork  : {published} (299's would be 300)");
    assert!(
        published <= 299,
        "a repaired tip advertised the work of a block it discarded: {published}"
    );

    let base = r.chainwork_base(298).unwrap().expect("a checkpoint exists");
    assert_eq!(
        u64::from_be_bytes(base.1[24..32].try_into().unwrap()),
        published,
        "the published work is not the checkpoint base"
    );

    drop(c);
    drop(r);
}

#[test]
fn f1b_missing_live_hdr_real_tip() {
    let _g = serial();
    let s = seed("sweep-f1b", 4_200);
    std::fs::remove_file(s.0.join("segments").join("hdr").join("000001.hseg")).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open must repair");
    assert_eq!(rep.headers_truncated_to, Some(4_096));
    let tip = r.tip();
    assert_eq!(tip.height, 4_095);
    println!("  tip.hash   : {}", hex(&tip.hash));
    println!("  hash_at    : {}", hex(&r.hash_at(4_095).unwrap().unwrap()));
    assert_eq!(
        tip.hash,
        r.hash_at(4_095).unwrap().unwrap(),
        "tip hash after a lost segment"
    );
    assert!(
        u64::from_be_bytes(tip.chainwork[24..32].try_into().unwrap()) <= 4_096,
        "the work of the lost tip is still advertised"
    );

    println!("  chainwork_at(4096)   : {:?}", r.chainwork_at(4_096).unwrap().is_some());
    assert!(
        r.chainwork_at(4_096).unwrap().is_none(),
        "a checkpoint above the repaired tip survived"
    );
    assert!(
        r.chainwork_at(3_072).unwrap().is_some(),
        "the checkpoints BELOW the tip must survive; they are the lower bound"
    );
    drop(c);
    drop(r);
}

fn poke_meta(s: &Scratch, rows: &[(&str, Vec<u8>)]) {
    let db = Database::create(s.0.join("chain.redb")).expect("redb open");
    let txn = db.begin_write().unwrap();
    {
        let mut t = txn.open_table(META).unwrap();
        for (k, v) in rows {
            t.insert(*k, v.as_slice()).unwrap();
        }
    }
    txn.commit().unwrap();
    drop(db);
}

fn open_result(s: &Scratch) -> Result<Result<(), StoreError>, String> {
    let cfg = cfg_of(s);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || match open(cfg) {
        Ok((c, r, _)) => {
            drop(c);
            drop(r);
            Ok(())
        }
        Err(e) => Err(e),
    }));
    std::panic::set_hook(hook);
    out.map_err(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
    })
}

#[test]
fn f2_old_schema_named_not_panic() {
    let _g = serial();
    let s = seed("sweep-f2-tip", 40);

    poke_meta(
        &s,
        &[
            ("schema_version", 0u64.to_le_bytes().to_vec()),
            ("tip", vec![7u8; 40]),
        ],
    );
    let got = open_result(&s).expect("open must not panic on an older schema");
    println!("  open() on schema 0 + 40-byte tip -> {got:?}");
    match got {
        Err(StoreError::SchemaVersion { found: 0, expected: 1 }) => {}
        other => panic!("expected SchemaVersion{{0,1}}, got {other:?}"),
    }
}

#[test]
fn f2b_short_network_row_named() {
    let _g = serial();
    let s = seed("sweep-f2-net", 40);
    poke_meta(&s, &[("network", vec![9u8; 2])]);
    let got = open_result(&s).expect("open must not panic");
    println!("  open() on a 2-byte network row -> {got:?}");
    match got {
        Err(StoreError::MetaRowMalformed { key: "network", len: 2, expected: 4 }) => {}
        other => panic!("expected MetaRowMalformed(network), got {other:?}"),
    }
}

#[test]
fn f2c_short_issued_row_named() {
    let _g = serial();
    let s = seed("sweep-f2-issued", 40);

    poke_meta(&s, &[("issued", 5u64.to_le_bytes().to_vec())]);
    let got = open_result(&s).expect("open must not panic");
    println!("  open() on an 8-byte issued row -> {got:?}");
    match got {
        Err(StoreError::MetaRowMalformed { key: "issued", len: 8, expected: 16 }) => {}
        other => panic!("expected MetaRowMalformed(issued), got {other:?}"),
    }
}

#[test]
fn f2d_short_fingerprint_row_named() {
    let _g = serial();
    let s = seed("sweep-f2-fp", 40);
    poke_meta(&s, &[("state_fingerprint", vec![0u8; 16])]);
    let got = open_result(&s).expect("open must not panic");
    println!("  open() on a 16-byte fingerprint row -> {got:?}");
    match got {
        Err(StoreError::MetaRowMalformed { key: "state_fingerprint", len: 16, expected: 32 }) => {}
        other => panic!("expected MetaRowMalformed(state_fingerprint), got {other:?}"),
    }
}

#[test]
fn f2e_bad_bidx_row_named() {
    let _g = serial();
    let s = seed("sweep-f2-bidx", 40);
    poke_meta(
        &s,
        &[("bidx_sealed_through", 0x8000_0000_0000_0000u64.to_le_bytes().to_vec())],
    );
    let got = open_result(&s).expect("open must not panic on an absurd segment number");
    println!("  open() on bidx_sealed_through = i64::MIN -> {got:?}");
    match got {
        Err(StoreError::MetaRowMalformed { key: "bidx_sealed_through", .. }) => {}
        other => panic!("expected MetaRowMalformed(bidx_sealed_through), got {other:?}"),
    }
}

#[test]
fn f2f_an_untouched_meta_still_opens() {
    let _g = serial();
    let s = seed("sweep-f2-ok", 40);
    let (c, r, rep) = open(cfg_of(&s)).expect("a healthy meta must still open");
    assert_eq!(r.tip().height, 39);
    assert!(rep.integrity.is_clean());
    assert!(rep.headers_truncated_to.is_none());
    drop(c);
    drop(r);
}

#[test]
fn f3_zero_count_range_on_degraded() {
    let _g = serial();
    let s = seed("sweep-f3", 3 * 4_096);

    std::fs::remove_file(s.0.join("segments").join("hdr").join("000001.hseg")).unwrap();
    let (c, r, rep) = open(cfg_of(&s)).expect("open must not refuse by default");
    assert!(r.is_degraded(), "the store did not enter degraded mode");
    println!("  header_damage: {}", rep.integrity.header_damage.len());

    let mut out = Vec::new();
    println!("  headers_range(0, 4, ..) -> {:?}", r.headers_range(0, 4, &mut out));

    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut o = Vec::new();
        r.headers_range(0, 0, &mut o)
    }));
    std::panic::set_hook(hook);
    let got = got.expect("headers_range(from, 0) must not panic");
    println!("  headers_range(0, 0, ..) -> {got:?}");
    assert_eq!(got.unwrap(), 0, "a zero count is an empty answer");

    let mut o = Vec::new();
    assert_eq!(r.headers_range(4_096, 0, &mut o).unwrap(), 0);
    assert_eq!(r.headers_range(u64::MAX, 0, &mut o).unwrap(), 0);
    drop(c);
}

#[test]
fn f1c_deep_flip_publishes_kept_hash() {
    let _g = serial();
    let s = seed("sweep-f1c", 300);
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");
    let mut raw = std::fs::read(&seg).unwrap();
    let before = raw[295 * 132..296 * 132].to_vec();
    raw[295 * 132 + 100] ^= 0x40;
    std::fs::write(&seg, &raw).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open must repair");
    println!("  headers_truncated_to : {:?}", rep.headers_truncated_to);
    let tip = r.tip();
    println!("  tip.height           : {}", tip.height);
    println!("  tip.hash             : {}", hex(&tip.hash));
    let kept = r.header_at(295).unwrap().unwrap();
    println!("  header_at(295) is the corrupt one: {}", kept[..] != before[..]);
    assert_eq!(rep.headers_truncated_to, Some(296));
    assert_eq!(tip.height, 295);
    assert_ne!(&kept[..], &before[..], "the corrupt header is the new tip");

    assert_eq!(
        tip.hash,
        r.hash_at(295).unwrap().unwrap(),
        "the tip hash must name the tip header, corrupt or not"
    );
    drop(c);
    drop(r);
}

#[test]
fn f4_readonly_hdr_fails_open_cleanly() {
    let _g = serial();
    let s = seed("sweep-f4", 300);
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");
    let before = std::fs::metadata(&seg).unwrap().len();
    let mut p = std::fs::metadata(&seg).unwrap().permissions();
    p.set_readonly(true);
    std::fs::set_permissions(&seg, p).unwrap();

    let res = open(cfg_of(&s));
    let after = std::fs::metadata(&seg).unwrap().len();
    match &res {
        Ok((_, r, _)) => println!("  open OK (tip {})", r.tip().height),
        Err(e) => println!("  open REFUSED: {e}"),
    }
    println!("  000000.hseg {before} B -> {after} B");
    assert_eq!(before, after, "a read-only volume cost bytes");

    restore_write(&seg);
    drop(res);
}
