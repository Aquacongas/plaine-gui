mod common;

use std::time::Instant;

use common::{commits, serial, Chain, Scratch};
use plaine_storage::{open, BlockToCommit, DurabilityMode, StoreError};

const BLOCKS_PER_YEAR: f64 = 525_960.0;
const MB: f64 = 1_000_000.0;

#[derive(Debug, Clone, Copy)]
struct Sizes {
    blocks: u64,
    hdr: u64,
    bseg: u64,
    bidx: u64,
    redb: u64,
    total: u64,
    extend_secs: f64,
}

fn dir_of(p: &std::path::Path, sub: &[&str]) -> u64 {
    let mut q = p.to_path_buf();
    for s in sub {
        q = q.join(s);
    }
    common::dir_bytes(&q)
}

fn build_store(
    name: &str,
    n: u64,
    accounts: u64,
    txs: usize,
    ckpt: u64,
    txindex: bool,
) -> (Sizes, Scratch) {
    let s = Scratch::new(name);
    let mut cfg = s.cfg();
    cfg.ibd_batch_blocks = Some(4_096);
    cfg.state_ckpt_interval = ckpt;
    cfg.txindex = txindex;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();

    let mut chain = Chain::new(accounts, 120 + txs * 157, 2 * txs + 1);
    let mut secs = 0f64;
    let mut done = 0u64;
    let chunk = 2_048u64;
    while done < n {
        let k = chunk.min(n - done);
        let bs = chain.build(k, 1);

        let ids: Vec<Vec<[u8; 32]>> = bs
            .iter()
            .map(|b| {
                (0..txs as u64)
                    .map(|i| {
                        let mut t = [0u8; 32];
                        t[0..8].copy_from_slice(&b.height.to_le_bytes());
                        t[8..16].copy_from_slice(&i.to_le_bytes());
                        t[16] = 0xA7;
                        t
                    })
                    .collect()
            })
            .collect();
        let cs: Vec<BlockToCommit<'_>> = bs
            .iter()
            .zip(ids.iter())
            .map(|(b, v)| {
                let mut t = b.to_commit();
                if txindex {
                    t.txids = Some(v.as_slice());
                }
                t
            })
            .collect();
        let t0 = Instant::now();
        c.extend(&cs).unwrap();
        secs += t0.elapsed().as_secs_f64();
        done += k;
    }
    let t0 = Instant::now();
    c.flush().unwrap();
    secs += t0.elapsed().as_secs_f64();
    drop(c);
    drop(r);

    let sizes = Sizes {
        blocks: n,
        hdr: dir_of(&s.0, &["segments", "hdr"]),
        bseg: {
            let d = s.0.join("segments").join("body");
            let mut t = 0;
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                if e.path().extension().and_then(|x| x.to_str()) == Some("bseg") {
                    t += e.metadata().unwrap().len();
                }
            }
            t
        },
        bidx: {
            let d = s.0.join("segments").join("body");
            let mut t = 0;
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                if e.path().extension().and_then(|x| x.to_str()) == Some("bidx") {
                    t += e.metadata().unwrap().len();
                }
            }
            t
        },
        redb: common::file_bytes(&s.0.join("chain.redb")),
        total: common::dir_bytes(&s.0),
        extend_secs: secs,
    };
    (sizes, s)
}

fn line(label: &str, v: f64) {
    println!("{}{label:<46} {v:>14.2}", common::tag());
}

#[test]
#[ignore]
fn audit_bytes_on_disk() {
    let _g = serial();

    let n1 = 8_192u64;
    let n2 = 24_576u64;
    let dn = (n2 - n1) as f64;

    for (label, txs) in [("quiet 2 tx/block", 2usize), ("busy 64 tx/block", 64)] {
        let (a, _ka) = build_store(&format!("aud-a-{txs}"), n1, 2_000, txs, 0, false);
        let (b, _kb) = build_store(&format!("aud-b-{txs}"), n2, 2_000, txs, 0, false);
        println!("\n=== MARGINAL COST, {label} (state universe saturated) ===");
        println!(
            "  n1={} bytes: hdr {} bseg {} bidx {} redb {} total {}",
            n1, a.hdr, a.bseg, a.bidx, a.redb, a.total
        );
        println!(
            "  n2={} bytes: hdr {} bseg {} bidx {} redb {} total {}",
            n2, b.hdr, b.bseg, b.bidx, b.redb, b.total
        );
        let mh = (b.hdr - a.hdr) as f64 / dn;
        let mb = (b.bseg - a.bseg) as f64 / dn;
        let mx = (b.bidx - a.bidx) as f64 / dn;
        let md = (b.redb as f64 - a.redb as f64) / dn;
        let mt = (b.total as f64 - a.total as f64) / dn;
        line("header segment  B/block", mh);
        line("body segment    B/block", mb);
        line("body sidecar    B/block", mx);
        line("redb            B/block", md);
        line("WHOLE STORE     B/block", mt);
        line(
            "  of which per TRANSACTION (B/tx)",
            if txs > 0 {
                (mb - 128.0) / txs as f64
            } else {
                0.0
            },
        );
        println!("  --- extrapolated ---");
        line("headers  MB/year (segments)", mh * BLOCKS_PER_YEAR / MB);
        line(
            "headers  MB/5yr  (segments)",
            mh * BLOCKS_PER_YEAR * 5.0 / MB,
        );
        line("redb     MB/year (index+ring)", md * BLOCKS_PER_YEAR / MB);
        line("redb     MB/5yr", md * BLOCKS_PER_YEAR * 5.0 / MB);
        line("bodies   GB/year", mb * BLOCKS_PER_YEAR / (MB * 1000.0));
        line(
            "HEADER-SIDE MB/year (hdr+redb)",
            (mh + md) * BLOCKS_PER_YEAR / MB,
        );
        line("headers-in-redb MB/year", 254.0 * BLOCKS_PER_YEAR / MB);
        line(
            "raw header bytes MB/year (132 B)",
            132.0 * BLOCKS_PER_YEAR / MB,
        );
        line("ratio vs B/record", 254.0 / (mh + md));
    }
}

#[test]
#[ignore]
fn audit_state_and_txindex_rows() {
    let _g = serial();

    let mut prev = 0u64;
    for accounts in [50_000u64, 200_000] {
        let writes = 5usize;
        let need = ((accounts as f64) * (accounts as f64).ln() / writes as f64) as u64;
        let (sz, s) = build_store(
            &format!("aud-state-{accounts}"),
            need.max(2_048),
            accounts,
            (writes - 1) / 2,
            0,
            false,
        );
        let (_c, r, _) = open(s.cfg()).expect("reopen");
        drop(r);
        println!(
            "\n=== STATE TABLE, {accounts} accounts, {} blocks ===\n  redb {} B, delta over previous {} B",
            sz.blocks,
            sz.redb,
            sz.redb as i64 - prev as i64
        );
        line(
            "redb B per account (gross)",
            sz.redb as f64 / accounts as f64,
        );
        line("raw B per account (20+24)", 44.0);
        prev = sz.redb;
    }

    let n1 = 4_096u64;
    let n2 = 12_288u64;
    let txs = 20usize;
    let (a, _ka) = build_store("aud-txi-a", n1, 2_000, txs, 0, true);
    let (b, _kb) = build_store("aud-txi-b", n2, 2_000, txs, 0, true);
    let (c, _kc) = build_store("aud-txi-c", n1, 2_000, txs, 0, false);
    let (d, _kd) = build_store("aud-txi-d", n2, 2_000, txs, 0, false);
    let dn = (n2 - n1) as f64;
    let with = (b.redb as f64 - a.redb as f64) / dn;
    let without = (d.redb as f64 - c.redb as f64) / dn;
    println!("\n=== TXINDEX at {txs} tx/block ===");
    line("redb B/block with txindex", with);
    line("redb B/block without", without);
    line("=> B per txindex ROW", (with - without) / txs as f64);
    line(
        "GB/year at 20 tx/block",
        (with - without) * BLOCKS_PER_YEAR / (MB * 1000.0),
    );
    line("claim B/row", 42.0);
    line("claim GB/year", 0.9);
}

fn build_batch(name: &str, n: u64, accounts: u64, txs: usize, batch: u32) -> (u64, u64, Scratch) {
    let s = Scratch::new(name);
    let mut cfg = s.cfg();
    cfg.ibd_batch_blocks = Some(batch);
    cfg.state_ckpt_interval = 0;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(accounts, 120 + txs * 157, 2 * txs + 1);
    let mut done = 0u64;
    while done < n {
        let k = 2_048u64.min(n - done);
        let bs = chain.build(k, 1);
        c.extend(&commits(&bs)).unwrap();
        done += k;
    }
    c.flush().unwrap();
    drop(c);
    drop(r);
    let redb = common::file_bytes(&s.0.join("chain.redb"));
    (redb, n, s)
}

#[test]
#[ignore]
fn audit_redb_growth_vs_batch_and_length() {
    let _g = serial();

    println!("\n=== REDB FILE vs IBD BATCH (16,384 blocks, 64 tx/block, 2,000 accounts) ===");
    for batch in [512u32, 2_048, 8_192, 32_768] {
        let (redb, _n, _s) = build_batch(&format!("aud-bat-{batch}"), 16_384, 2_000, 64, batch);
        println!(
            "  batch {batch:>6}: chain.redb {:>12} B  ({:.1} MiB)",
            redb,
            redb as f64 / 1048576.0
        );
    }
    println!("\n=== REDB FILE vs CHAIN LENGTH (batch 4,096, 64 tx/block) ===");
    let mut prev = (0u64, 0u64);
    for n in [8_192u64, 16_384, 32_768, 65_536] {
        let (redb, _n, _s) = build_batch(&format!("aud-len-{n}"), n, 2_000, 64, 4_096);
        let marg = if prev.1 > 0 {
            (redb as f64 - prev.0 as f64) / (n - prev.1) as f64
        } else {
            f64::NAN
        };
        println!(
            "  {n:>6} blocks: chain.redb {:>12} B ({:.1} MiB)  marginal since previous {marg:.2} B/block",
            redb,
            redb as f64 / 1048576.0
        );
        prev = (redb, n);
    }
    println!("\n=== REDB FILE vs CHAIN LENGTH (batch 4,096, 2 tx/block) ===");
    let mut prev = (0u64, 0u64);
    for n in [8_192u64, 32_768, 131_072] {
        let (redb, _n, _s) = build_batch(&format!("aud-len2-{n}"), n, 2_000, 2, 4_096);
        let marg = if prev.1 > 0 {
            (redb as f64 - prev.0 as f64) / (n - prev.1) as f64
        } else {
            f64::NAN
        };
        println!(
            "  {n:>6} blocks: chain.redb {:>12} B ({:.1} MiB)  marginal since previous {marg:.2} B/block  -> {:.1} MB/year",
            redb,
            redb as f64 / 1048576.0,
            marg * BLOCKS_PER_YEAR / MB
        );
        prev = (redb, n);
    }
}

#[test]
#[ignore]
fn audit_default_config_savepoint_cost() {
    let _g = serial();

    let n = 24_576u64;
    let (off, _a) = build_store("aud-ckpt-off", n, 20_000, 20, 0, false);
    let (on, _b) = build_store("aud-ckpt-on", n, 20_000, 20, 4_096, false);
    println!(
        "\n=== STATE CHECKPOINTS (interval 4,096, keep {} = the shipped default), {n} blocks, 20k accounts ===\n\
           SUPERSEDED by audit_checkpoint_cost_vs_length_and_keep, which reports live pages\n\
           rather than the file: the file grows in geometric steps and its ratio is quantised.",
        plaine_storage::StoreConfig::new(".", plaine_storage::Network::Main).state_ckpt_keep
    );
    line("redb bytes, checkpoints OFF", off.redb as f64);
    line("redb bytes, checkpoints ON (default)", on.redb as f64);
    line("inflation factor", on.redb as f64 / off.redb.max(1) as f64);
    line("extra MB", (on.redb as f64 - off.redb as f64) / MB);
}

#[test]
#[ignore]
fn audit_full_scale_one_and_five_years() {
    let _g = serial();

    for (label, n, txs, prune) in [
        ("1 YEAR, 2 tx/block, archive", 525_960u64, 2usize, false),
        ("5 YEARS, 2 tx/block, PRUNED full node", 2_629_800, 2, true),
        (
            "5 YEARS, coinbase only, PRUNED full node",
            2_629_800,
            0,
            true,
        ),
    ] {
        let s = Scratch::new(&format!("aud-scale-{n}-{txs}-{prune}"));
        let mut cfg = s.cfg();
        cfg.prune = prune;
        cfg.ibd_batch_blocks = Some(4_096);
        cfg.state_ckpt_interval = 0;
        cfg.page_cache_bytes = 128 * 1024 * 1024;
        let (mut c, r, _) = open(cfg).expect("open");
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(1_000_000, 120 + txs * 157, 2 * txs + 1);
        let t0 = Instant::now();
        let mut done = 0u64;
        let mut extend_secs = 0f64;
        while done < n {
            let k = 4_096u64.min(n - done);
            let bs = chain.build(k, 1);
            let t = Instant::now();
            c.extend(&commits(&bs)).unwrap();
            extend_secs += t.elapsed().as_secs_f64();
            done += k;
        }
        let t = Instant::now();
        c.flush().unwrap();
        extend_secs += t.elapsed().as_secs_f64();
        let wall = t0.elapsed().as_secs_f64();
        let floor = r.prune_floor();
        drop(c);
        drop(r);

        let hdr = dir_of(&s.0, &["segments", "hdr"]);
        let bodyd = s.0.join("segments").join("body");
        let (mut bseg, mut bidx) = (0u64, 0u64);
        for e in std::fs::read_dir(&bodyd).unwrap().flatten() {
            let len = e.metadata().unwrap().len();
            match e.path().extension().and_then(|x| x.to_str()) {
                Some("bseg") => bseg += len,
                Some("bidx") => bidx += len,
                _ => {}
            }
        }
        let redb = common::file_bytes(&s.0.join("chain.redb"));
        let total = common::dir_bytes(&s.0);

        let (_c2, r2, rep) = open(s.cfg()).expect("reopen");
        let reopen_us = rep.open_micros;
        drop(r2);

        println!("\n=== {label}: {n} blocks ===");
        println!("  built + committed in {wall:.1} s wall, {extend_secs:.1} s inside extend() = {:.0} blocks/s", n as f64 / extend_secs);
        println!("  prune_floor {floor}");
        line("headers   MB", hdr as f64 / MB);
        line("  B per header (must be 132.00)", hdr as f64 / n as f64);
        line("bodies    MB", bseg as f64 / MB);
        line("sidecars  MB", bidx as f64 / MB);
        line("chain.redb MB", redb as f64 / MB);
        line("TOTAL     MB", total as f64 / MB);
        line("TOTAL     GB", total as f64 / MB / 1000.0);
        line("reopen (open_micros) ms", reopen_us as f64 / 1000.0);
        line("redb B per block", redb as f64 / n as f64);
        line(
            "header-side MB/year (hdr + redb)",
            (hdr + redb) as f64 / MB / (n as f64 / BLOCKS_PER_YEAR),
        );
        line("headers-in-redb MB/year", 133.6);
    }
}

#[test]
#[ignore]
fn audit_import_throughput() {
    let _g = serial();
    println!("\n=== IMPORT THROUGHPUT (no PoW; storage only) ===");
    println!("  PoW floor for reference: 1.3-3 ms/header => 333-769 blocks/s per thread");
    for (label, txs, n) in [
        ("quiet   2 tx/block (0.43 KB)", 2usize, 24_576u64),
        ("planned 20 tx/block (3.3 KB)", 20, 24_576),
        ("busy   64 tx/block (10.2 KB)", 64, 16_384),
        ("SPEC 9 planning 20 KB block", 127, 8_192),
    ] {
        let (ibd, _k) = build_store(&format!("aud-tp-{txs}"), n, 4_000, txs, 0, false);
        let bps = ibd.blocks as f64 / ibd.extend_secs;
        println!(
            "\n  {label}: {} blocks in {:.3} s",
            ibd.blocks, ibd.extend_secs
        );
        line("IBD blocks/s", bps);
        line("IBD MB/s written", ibd.total as f64 / MB / ibd.extend_secs);
        line("storage us/block", 1e6 / bps);
        line("x faster than the 3 ms PoW worst case", bps / 333.0);
        line(
            "years of chain per minute of storage time",
            bps * 60.0 / BLOCKS_PER_YEAR,
        );
    }

    let s = Scratch::new("aud-tip");
    let mut cfg = s.cfg();
    cfg.state_ckpt_interval = 0;
    let (mut c, _r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Tip).unwrap();
    let mut chain = Chain::new(4_000, 120 + 20 * 157, 41);
    let bs = chain.build(400, 1);
    let cs = commits(&bs);
    let t0 = Instant::now();
    for one in cs.chunks(1) {
        c.extend(one).unwrap();
    }
    let el = t0.elapsed().as_secs_f64();
    println!("\n  TIP MODE (durable commit + segment barriers per block), 400 blocks");
    line("blocks/s", 400.0 / el);
    line("ms per block (fsync-bound)", el * 1000.0 / 400.0);
    line("budget at 60 s block time (ms)", 60_000.0);
    drop(c);
}

fn seed(name: &str, n: u64) -> Scratch {
    let s = Scratch::new(name);
    let mut cfg = s.cfg();
    cfg.state_ckpt_interval = 0;
    cfg.ibd_batch_blocks = Some(1_024);
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 200, 3);
    let bs = chain.build(n, 1);
    c.extend(&commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    s
}

fn truncate(p: &std::path::Path, by: u64) {
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    let len = f.metadata().unwrap().len();
    f.set_len(len.saturating_sub(by)).unwrap();
    f.sync_all().unwrap();
}

#[test]
#[ignore]
fn audit_corrupt_truncate_tip_header_segment() {
    let _g = serial();

    let s = seed("aud-cut-tip", 3_000);
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");
    truncate(&seg, 132 * 10);
    match open(s.cfg()) {
        Ok((c, r, rep)) => {
            println!("\n=== TRUNCATED LIVE HEADER SEGMENT (-10 headers) ===");
            println!("  open SUCCEEDED. tip {} (was 2999)", r.tip().height);
            println!("  headers_truncated_to {:?}", rep.headers_truncated_to);
            println!(
                "  hdr_watermark {} body_watermark {}",
                r.hdr_watermark(),
                r.body_watermark()
            );
            println!(
                "  state fingerprint check: {:?}",
                r.verify_state_fingerprint().is_ok()
            );
            println!(
                "  header_at(2989) present: {}",
                r.header_at(2989).unwrap().is_some()
            );
            drop(c);
            drop(r);
        }
        Err(e) => println!("\n=== TRUNCATED LIVE HEADER SEGMENT: open REFUSED: {e}"),
    }
}

#[test]
#[ignore]
fn audit_corrupt_truncate_old_header_segment() {
    let _g = serial();

    let s = seed("aud-cut-old", 3 * 4_096);
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");
    truncate(&seg, 132 * 50);
    match open(s.cfg()) {
        Ok((c, r, rep)) => {
            println!("\n=== TRUNCATED SEALED HEADER SEGMENT 0 (-50 headers, depth ~8k) ===");
            println!(
                "  open SUCCEEDED (this is the finding). tip {}",
                r.tip().height
            );
            println!(
                "  headers_truncated_to {:?}  index_rebuilt {}",
                rep.headers_truncated_to, rep.index_rebuilt
            );
            println!(
                "  header_at(4045) -> {:?}",
                r.header_at(4_045).unwrap().map(|_| "present")
            );
            println!(
                "  header_at(4000) -> {:?}",
                r.header_at(4_000).unwrap().map(|_| "present")
            );
            println!(
                "  hash_at(4045) -> {:?}",
                r.hash_at(4_045).unwrap().is_some()
            );
            let mut out = Vec::new();

            match r.headers_range(4_040, 20, &mut out) {
                Ok(got) => println!("  headers_range(4040,20) returned {got} headers"),
                Err(e) => println!("  headers_range(4040,20) REFUSED (correct): {e}"),
            }

            let below = r
                .headers_range(4_020, 20, &mut out)
                .expect("a range wholly below the damage must still be served");
            assert_eq!(below, 20, "20 intact headers below the damage boundary");
            drop(c);
            drop(r);
        }
        Err(e) => println!("\n=== TRUNCATED SEALED HEADER SEGMENT: open REFUSED: {e}"),
    }
}

#[test]
#[ignore]
fn audit_corrupt_delete_body_segment() {
    let _g = serial();

    let s = seed("aud-del-body", 3 * 4_096);
    let b1 = s.0.join("segments").join("body").join("000001.bseg");
    let x1 = s.0.join("segments").join("body").join("000001.bidx");
    std::fs::remove_file(&b1).unwrap();
    std::fs::remove_file(&x1).unwrap();
    match open(s.cfg()) {
        Ok((c, r, rep)) => {
            println!("\n=== DELETED BODY SEGMENT 1 of 3 (prune floor 0) ===");
            println!(
                "  open SUCCEEDED. tip {}  body_watermark {}",
                r.tip().height,
                r.body_watermark()
            );
            println!(
                "  bodies_truncated_to {:?}  segments_unlinked {}",
                rep.bodies_truncated_to, rep.segments_unlinked
            );
            println!("  prune_floor reported to caller: {}", r.prune_floor());
            println!("  damage: {:?}", rep.integrity.body_damage);
            let mut buf = Vec::new();
            println!(
                "  body_at(5000) -> {:?}",
                r.body_at(5_000, &mut buf).map_err(|e| e.to_string())
            );
            println!(
                "  body_availability(5000) -> {:?}",
                r.body_availability(5_000)
            );
            println!("  body_at(1000) -> {:?}", r.body_at(1_000, &mut buf));
            println!("  body_at(9000) -> {:?}", r.body_at(9_000, &mut buf));
            drop(c);
            drop(r);
        }
        Err(e) => println!("\n=== DELETED BODY SEGMENT: open REFUSED: {e}"),
    }
}

#[test]
#[ignore]
fn audit_corrupt_delete_header_segment() {
    let _g = serial();

    let s = seed("aud-del-hdr", 3 * 4_096);
    std::fs::remove_file(s.0.join("segments").join("hdr").join("000001.hseg")).unwrap();
    match open(s.cfg()) {
        Ok((c, r, rep)) => {
            println!("\n=== DELETED HEADER SEGMENT 1 of 3 (heights 4096..8191) ===");
            println!(
                "  open SUCCEEDED. tip {} hdr_watermark {}",
                r.tip().height,
                r.hdr_watermark()
            );
            println!(
                "  headers_truncated_to {:?} index_rebuilt {}",
                rep.headers_truncated_to, rep.index_rebuilt
            );
            println!("  damage: {:?}", rep.integrity.header_damage);
            for h in [4_000u64, 4_096, 6_000, 8_191, 8_192, 12_000] {
                println!(
                    "    header_at({h}) -> {:?}   availability {:?}",
                    r.header_at(h)
                        .map(|o| o.is_some())
                        .map_err(|e| e.to_string()),
                    r.header_availability(h)
                );
            }
            let mut out = Vec::new();
            println!(
                "  headers_range(4090, 200) -> {:?}",
                r.headers_range(4_090, 200, &mut out)
                    .map_err(|e| e.to_string())
            );
            let mut loc = [[0u8; 32]; 32];
            println!(
                "  locator() -> {} entries, none below intact_header_floor {}",
                r.locator(&mut loc).unwrap(),
                r.intact_header_floor()
            );
            println!(
                "  state fingerprint still verifies: {}",
                r.verify_state_fingerprint().is_ok()
            );
            drop(c);
            drop(r);
        }
        Err(e) => println!("\n=== DELETED HEADER SEGMENT: open REFUSED -> {e}"),
    }
}

#[test]
#[ignore]
fn audit_corrupt_truncate_body_segment_midfile() {
    let _g = serial();
    let s = seed("aud-cut-body", 3_000);
    let b = s.0.join("segments").join("body").join("000000.bseg");
    let len = std::fs::metadata(&b).unwrap().len();
    truncate(&b, len / 2);
    match open(s.cfg()) {
        Ok((c, r, rep)) => {
            println!("\n=== BODY SEGMENT TRUNCATED IN HALF ===");
            println!(
                "  open SUCCEEDED. hdr_wm {} body_wm {}",
                r.hdr_watermark(),
                r.body_watermark()
            );
            println!("  bodies_truncated_to {:?}", rep.bodies_truncated_to);
            let mut buf = Vec::new();
            let last_ok = (0..3_000u64).rev().find(|h| {
                r.body_at(*h, &mut buf)
                    .map(|n| n.is_some())
                    .unwrap_or(false)
            });
            println!("  deepest readable body: {last_ok:?}");
            println!(
                "  headers intact: {}",
                r.header_at(2_999).unwrap().is_some()
            );
            drop(c);
            drop(r);
        }
        Err(e) => println!("\n=== BODY SEGMENT TRUNCATED: open REFUSED: {e}"),
    }
}

#[test]
#[ignore]
fn audit_corrupt_truncate_the_index() {
    let _g = serial();

    for cut in [4_096u64, 65_536, 1 << 20] {
        let s = seed(&format!("aud-cut-redb-{cut}"), 2_000);
        let db = s.0.join("chain.redb");
        let before = std::fs::metadata(&db).unwrap().len();
        if before <= cut {
            continue;
        }
        truncate(&db, cut);
        let cfg = s.cfg();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open(cfg)));
        match res {
            Ok(Ok((c, r, _))) => {
                println!("\n=== REDB TRUNCATED BY {cut} B (of {before}) ===");
                println!(
                    "  !!! open SUCCEEDED. tip {} watermark {}",
                    r.tip().height,
                    r.hdr_watermark()
                );
                println!(
                    "  fingerprint: {:?}",
                    r.verify_state_fingerprint().map_err(|e| e.to_string())
                );
                drop(c);
                drop(r);
            }
            Ok(Err(e)) => {
                println!("\n=== REDB TRUNCATED BY {cut} B (of {before}): open REFUSED -> {e}")
            }
            Err(_) => println!("\n=== REDB TRUNCATED BY {cut} B (of {before}): open PANICKED"),
        }
    }
}

#[test]
#[ignore]
fn audit_corrupt_delete_the_index_entirely() {
    let _g = serial();
    let s = seed("aud-del-redb", 2_000);
    std::fs::remove_file(s.0.join("chain.redb")).unwrap();
    match open(s.cfg()) {
        Ok((c, r, rep)) => {
            println!("\n=== chain.redb DELETED, segments intact ===");
            println!(
                "  open SUCCEEDED. tip {} hdr_wm {}",
                r.tip().height,
                r.hdr_watermark()
            );
            println!(
                "  headers_truncated_to {:?} segments_unlinked {}",
                rep.headers_truncated_to, rep.segments_unlinked
            );
            println!(
                "  hseg still on disk: {} B",
                common::file_bytes(&s.0.join("segments").join("hdr").join("000000.hseg"))
            );
            drop(c);
            drop(r);
        }
        Err(e) => println!("\n=== chain.redb DELETED: open REFUSED -> {e}"),
    }
}

#[test]
#[ignore]
fn audit_corrupt_flip_a_header_byte_deep() {
    let _g = serial();
    use std::io::{Seek, SeekFrom, Write};
    let s = seed("aud-flip", 3 * 4_096);
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        f.seek(SeekFrom::Start(132 * 1_000 + 50)).unwrap();
        f.write_all(&[0xFF]).unwrap();
        f.sync_all().unwrap();
    }
    match open(s.cfg()) {
        Ok((c, r, rep)) => {
            println!("\n=== ONE FLIPPED BYTE IN HEADER 1000 (depth ~11k) ===");
            println!(
                "  open SUCCEEDED. tip {} truncated_to {:?}",
                r.tip().height,
                rep.headers_truncated_to
            );
            let h1000 = r.header_at(1_000).unwrap().unwrap();
            let h1001 = r.header_at(1_001).unwrap().unwrap();
            let links = h1001[12..44] == plaine_consensus::crypto::header_hash(&h1000)[..];
            println!("  header 1000 served: yes. links to 1001: {links}  <-- broken chain served as canonical");
            println!("  THE RESIDUAL, stated: interior bit rot inside ONE segment is still not");
            println!("  detected. The boundary check shrinks the undetected span from the whole");
            println!("  chain to at most 4,094 headers; closing it costs an O(height) walk.");
            let e = r
                .header_by_hash(&plaine_consensus::crypto::header_hash(&h1000))
                .unwrap();
            println!(
                "  header_by_hash(corrupted hash) -> {:?}",
                e.map(|(h, _)| h)
            );
            drop(c);
            drop(r);
        }
        Err(e) => println!("\n=== FLIPPED HEADER BYTE: open REFUSED -> {e}"),
    }
}

#[test]
#[ignore]
fn audit_short_header_segment_scaling() {
    let _g = serial();

    println!("\n=== SHORT HEADER SEGMENT: cost of open vs chain height ===");
    for n in [500u64, 1_000, 1_500, 2_000] {
        let s = seed(&format!("aud-short-{n}"), n);
        let seg = s.0.join("segments").join("hdr").join("000000.hseg");
        let before = std::fs::metadata(&seg).unwrap().len();
        truncate(&seg, 132);
        let t = Instant::now();
        let res = open(s.cfg());
        let ms = t.elapsed().as_millis();
        let after = std::fs::metadata(&seg).map(|m| m.len()).unwrap_or(0);
        match res {
            Ok((c, r, rep)) => {
                println!(
                    "  height {n}: open OK in {ms} ms, tip {}, truncated_to {:?}, hseg {before} -> {after} B",
                    r.tip().height,
                    rep.headers_truncated_to
                );
                drop(c);
                drop(r);
            }
            Err(e) => println!(
                "  height {n}: open REFUSED in {ms} ms -> {e}   | hseg {before} -> {after} B (loss: {} headers)",
                (before - after) / 132
            ),
        }
    }
}

#[test]
#[ignore]
fn audit_hole_in_the_middle_of_the_header_range() {
    let _g = serial();

    let s = seed("aud-hole", 3 * 4_096);
    let seg = s.0.join("segments").join("hdr").join("000000.hseg");
    truncate(&seg, 132 * 50);
    let (c, r, rep) = open(s.cfg()).expect("open");
    println!("\n=== HOLE AT 4046..4095, CHAIN CONTINUES AT 4096, TIP 12287 ===");
    println!(
        "  open OK, truncated_to {:?}, tip {}",
        rep.headers_truncated_to,
        r.tip().height
    );
    println!("  damage: {:?}", rep.integrity.header_damage);
    for h in [4_045u64, 4_046, 4_050, 4_095, 4_096, 5_000] {
        println!(
            "    header_at({h}) -> {:?}   availability {:?}",
            r.header_at(h)
                .map(|o| o.is_some())
                .map_err(|e| e.to_string()),
            r.header_availability(h)
        );
    }
    let mut out = Vec::new();
    println!(
        "  headers_range(4040, 100) -> {:?} (asked 100; it used to answer 12 and never recover)",
        r.headers_range(4_040, 100, &mut out)
            .map_err(|e| e.to_string())
    );
    let mut loc = [[0u8; 32]; 32];
    println!(
        "  locator() -> {} entries, intact_header_floor {}",
        r.locator(&mut loc).unwrap(),
        r.intact_header_floor()
    );
    drop(c);
    drop(r);
}

#[derive(Debug, Clone, Copy)]
struct Run {
    blocks: u64,
    hdr: u64,
    redb: u64,
    total: u64,
    secs: f64,
}

#[allow(clippy::too_many_arguments)]
fn build_tuned(
    name: &str,
    n: u64,
    accounts: u64,
    writes_per_block: usize,
    body_len: usize,
    batch: u32,
    ckpt: u64,
    keep: u32,
) -> (Run, Scratch) {
    let s = Scratch::new(name);
    let mut cfg = s.cfg();
    cfg.ibd_batch_blocks = Some(batch);
    cfg.state_ckpt_interval = ckpt;
    cfg.state_ckpt_keep = keep;
    cfg.page_cache_bytes = 128 * 1024 * 1024;
    let (mut c, r, _) = open(cfg).expect("open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(accounts, body_len, writes_per_block);
    let mut done = 0u64;
    let mut secs = 0f64;
    while done < n {
        let k = 4_096u64.min(n - done);
        let bs = chain.build(k, 1);
        let t = Instant::now();
        c.extend(&commits(&bs)).unwrap();
        secs += t.elapsed().as_secs_f64();
        done += k;
    }
    let t = Instant::now();
    c.flush().unwrap();
    secs += t.elapsed().as_secs_f64();
    drop(c);
    drop(r);
    let run = Run {
        blocks: n,
        hdr: dir_of(&s.0, &["segments", "hdr"]),
        redb: common::file_bytes(&s.0.join("chain.redb")),
        total: common::dir_bytes(&s.0),
        secs,
    };
    (run, s)
}

fn weigh(s: &Scratch) -> (u64, u64, Vec<plaine_storage::TableFootprint>) {
    let (mut c, r, _) = open(s.cfg()).expect("reopen");
    let tables = r.table_footprints().unwrap();
    let db = c.db_footprint().unwrap();
    let allocated = db.allocated_pages * db.page_size;
    let page_size = db.page_size;
    drop(c);
    drop(r);
    (allocated, page_size, tables)
}

#[test]
#[ignore]
fn audit_redb_file_and_bytes_per_header() {
    let _g = serial();
    common::machine_note("C1 + C2: the redb file, and the true cost of a header");
    let t = common::tag();

    let (a, _ka) = build_tuned("c2-a", 32_768, 2_000, 5, 120 + 2 * 157, 4_096, 0, 4);
    let (b, kb) = build_tuned("c2-b", 131_072, 2_000, 5, 120 + 2 * 157, 4_096, 0, 4);
    let dn = (b.blocks - a.blocks) as f64;
    let mh = (b.hdr - a.hdr) as f64 / dn;
    let md = (b.redb as f64 - a.redb as f64) / dn;
    println!("{t}C2 scenario: 2 tx/block, 5 writes/block, 2,000 accounts, batch 4,096, ckpt OFF");
    println!("{t}  n1 {} blocks: hdr {} redb {}", a.blocks, a.hdr, a.redb);
    println!("{t}  n2 {} blocks: hdr {} redb {}", b.blocks, b.hdr, b.redb);

    let (alloc, ps, tables) = weigh(&kb);
    let hi = tables.iter().find(|f| f.name == "hash_index").unwrap();
    let cw = tables.iter().find(|f| f.name == "chainwork_ckpt").unwrap();
    let idx_per_header = hi.page_bytes(ps) as f64 / hi.rows.max(1) as f64;
    let cw_per_header = cw.page_bytes(ps) as f64 / cw.rows.max(1) as f64 / 1_024.0;
    let here = 132.0 + idx_per_header + cw_per_header;
    println!("{t}  --- (i) RETAINED CONTENT, from redb's own per-table accounting ---");
    println!(
        "{t}  file {} B, allocated pages {} B ({:.1}x the file is free space at the high-water mark)",
        b.redb,
        alloc,
        b.redb as f64 / alloc.max(1) as f64
    );
    line("header segment            B/header (exact)", 132.0);
    line("hash_index row footprint  B/header", idx_per_header);
    line("chainwork ckpt amortised  B/header", cw_per_header);
    line("=> B PER HEADER, HERE (definitive)", here);
    line("claim B/header (THEIRS, unmeasurable here)", 254.0);
    line("ratio 254 / here", 254.0 / here);
    line("MB/year here", here * BLOCKS_PER_YEAR / MB);
    line("MB/5yr here", here * BLOCKS_PER_YEAR * 5.0 / MB);
    line(
        "GB over TEN years saved vs 254 B",
        (254.0 - here) * BLOCKS_PER_YEAR * 10.0 / (MB * 1000.0),
    );

    println!("{t}  --- (ii) the FILE-DELTA method, which measures the allocator ---");
    line("header segment B/block (must be 132.00)", mh);
    line("redb file-delta B/block", md);
    line("=> B per header by file delta", mh + md);
    println!("{t}  RETRACTED here: 155.7 B (no method stated). Audit's refutation: 197.07 B,");
    println!("{t}  by this same file-delta method. Both are the allocator talking.");

    let n = 131_072u64;
    let acc = 200_000u64;
    let default_keep =
        plaine_storage::StoreConfig::new(".", plaine_storage::Network::Main).state_ckpt_keep;
    let (off, koff) = build_tuned("c1-off", n, acc, 41, 256, 4_096, 0, default_keep);
    let (on, kon) = build_tuned("c1-on", n, acc, 41, 256, 4_096, 4_096, default_keep);
    let (old, kold) = build_tuned("c1-old", n, acc, 41, 256, 4_096, 4_096, 4);
    let (alloc_off, _, _) = weigh(&koff);
    let (alloc_on, _, _) = weigh(&kon);
    let (alloc_old, _, _) = weigh(&kold);
    println!(
        "\n{t}C1 scenario: {n} blocks ({:.2} of a year), {acc} accounts, 41 writes/block, \
         batch 4,096, bodies 256 B",
        n as f64 / BLOCKS_PER_YEAR
    );
    println!("{t}  (the shipped default is keep {default_keep}; keep 4 was the default this run changed)");
    line("chain.redb MB, state checkpoints OFF", off.redb as f64 / MB);
    line(
        "chain.redb MB, SHIPPED DEFAULT (4,096 / keep 2)",
        on.redb as f64 / MB,
    );
    line(
        "chain.redb MB, OLD default (4,096 / keep 4)",
        old.redb as f64 / MB,
    );
    line(
        "inflation of the shipped default (FILE)",
        on.redb as f64 / off.redb.max(1) as f64,
    );
    line(
        "inflation of the old default (FILE)",
        old.redb as f64 / off.redb.max(1) as f64,
    );
    line("live pages MB, OFF", alloc_off as f64 / MB);
    line("live pages MB, SHIPPED DEFAULT", alloc_on as f64 / MB);
    line("live pages MB, OLD default", alloc_old as f64 / MB);
    line(
        "inflation, shipped default (LIVE, quantisation-free)",
        alloc_on as f64 / alloc_off.max(1) as f64,
    );
    line(
        "inflation, old default (LIVE)",
        alloc_old as f64 / alloc_off.max(1) as f64,
    );
    line("the RETRACTED claim, 121.5 MiB, in MB", 127.40);
    line("  x that claim, OFF", off.redb as f64 / MB / 127.40);
    line("  x that claim, ON", on.redb as f64 / MB / 127.40);
    line("128 MiB page-cache budget, in MB", 134.22);
    line("  x the page cache, OFF", off.redb as f64 / MB / 134.22);
    line("  x the page cache, ON", on.redb as f64 / MB / 134.22);
    line("redb B/block, OFF", off.redb as f64 / n as f64);
    line("redb B/block, shipped default", on.redb as f64 / n as f64);
}

#[test]
#[ignore]
fn audit_checkpoint_cost_vs_length_and_keep() {
    let _g = serial();
    common::machine_note("C3: what the default checkpoint policy actually costs");
    let t = common::tag();
    println!("{t}interval fixed at 4,096; bodies 256 B (inert here); batch 4,096; 41 writes/block");
    println!("{t}DECISION RULE: ratio flat in length AND in keep => saturated, keep 4 stays.");
    println!("{t}               ratio scales with keep          => unsaturated, cut keep to 2.");
    println!("{t}               ratio climbs with length        => reclamation leak, escalate.");
    println!("{t}Both FILE and LIVE PAGES are reported: the file grows in geometric steps and");
    println!("{t}never shrinks, so a file ratio is quantised and a live-page ratio is not.");
    for accounts in [20_000u64, 200_000] {
        let sat_blocks = (accounts as f64) * (accounts as f64).ln() / 41.0;
        println!(
            "\n{t}=== {accounts} accounts (whole state tree dirtied every {sat_blocks:.0} blocks) ==="
        );
        for n in [24_576u64, 98_304] {
            let (off, koff) = build_tuned(
                &format!("c3-off-{accounts}-{n}"),
                n,
                accounts,
                41,
                256,
                4_096,
                0,
                4,
            );
            let (alloc_off, _, _) = weigh(&koff);
            println!(
                "{t}  {n:>6} blocks (tree dirtied {:>5.1}x): OFF file {:>7.1} MB, live {:>7.1} MB",
                n as f64 / sat_blocks,
                off.redb as f64 / MB,
                alloc_off as f64 / MB
            );
            for keep in [1u32, 2, 4] {
                let (on, kon) = build_tuned(
                    &format!("c3-on-{accounts}-{n}-{keep}"),
                    n,
                    accounts,
                    41,
                    256,
                    4_096,
                    4_096,
                    keep,
                );
                let (alloc_on, _, _) = weigh(&kon);
                println!(
                    "{t}      keep {keep}: file {:>7.1} MB ({:>5.3}x)  live {:>7.1} MB ({:>5.3}x)",
                    on.redb as f64 / MB,
                    on.redb as f64 / off.redb.max(1) as f64,
                    alloc_on as f64 / MB,
                    alloc_on as f64 / alloc_off.max(1) as f64
                );
            }
        }
    }
}

#[test]
#[ignore]
fn audit_state_table_attribution() {
    let _g = serial();
    common::machine_note("C4: per-account cost, attributed to the table that owns it");
    let t = common::tag();

    let n = 32_768u64;
    let mut points: Vec<(f64, f64)> = Vec::new();
    for accounts in [50_000u64, 100_000, 200_000, 400_000] {
        let (run, s) = build_tuned(&format!("c4-{accounts}"), n, accounts, 41, 256, 4_096, 0, 4);
        let (mut c, r, _) = open(s.cfg()).expect("reopen");
        let tables = r.table_footprints().unwrap();
        let db = c.db_footprint().unwrap();
        let ps = db.page_size;
        let st = tables.iter().find(|f| f.name == "state").unwrap();
        let p = st.stored_bytes as f64 / accounts as f64;
        let q = st.page_bytes(ps) as f64 / accounts as f64;
        let file = run.redb as f64;
        let s_gross = file / accounts as f64;
        println!(
            "\n{t}=== {accounts} accounts, {n} blocks, 41 writes/block, batch 4,096, ckpt OFF ==="
        );
        println!(
            "{t}  chain.redb {} B, page size {ps}, allocated pages {}",
            run.redb, db.allocated_pages
        );
        line("P  state payload      B/account (must be ~44)", p);
        line("Q  state table pages  B/account  <-- THE NUMBER", q);
        line("   Q - P = redb page slack + branch keys (INHERENT)", q - p);
        line("S  whole file / accounts (what `du` shows)", s_gross);
        line(
            "   S - Q = other tables + free pages (NOT this line's)",
            s_gross - q,
        );
        let table_pages: u64 = tables.iter().map(|f| f.page_bytes(ps)).sum();
        let allocated = db.allocated_pages * ps;
        line(
            "R  allocated - sum(table pages), MB (TRANSIENT)",
            (allocated as f64 - table_pages as f64) / MB,
        );
        line(
            "   file - allocated pages, MB",
            (file - allocated as f64) / MB,
        );
        println!("{t}  --- every table, pages x {ps} B ---");
        for f in &tables {
            if f.rows == 0 {
                continue;
            }
            println!(
                "{t}    {:<16} rows {:>9}  pages {:>7}  stored {:>11} B  footprint {:>11} B  \
                 B/row {:>8.2}  frag {:>9} B",
                f.name,
                f.rows,
                f.leaf_pages + f.branch_pages,
                f.stored_bytes,
                f.page_bytes(ps),
                f.page_bytes(ps) as f64 / f.rows as f64,
                f.fragmented_bytes
            );
        }
        points.push((accounts as f64, file));
        drop(c);
        drop(r);
    }

    let k = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0).sum();
    let sy: f64 = points.iter().map(|p| p.1).sum();
    let sxx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let slope = (k * sxy - sx * sy) / (k * sxx - sx * sx);
    let intercept = (sy - slope * sx) / k;

    println!("\n{t}=== S - Q: accounts, or the IBD batch high-water mark? (200,000 accounts) ===");
    for batch in [512u32, 4_096, 32_768] {
        let (run, s2) = build_tuned(
            &format!("c4-batch-{batch}"),
            n,
            200_000,
            41,
            256,
            batch,
            0,
            4,
        );
        let (mut c2, r2, _) = open(s2.cfg()).expect("reopen");
        let tables = r2.table_footprints().unwrap();
        let db = c2.db_footprint().unwrap();
        let st = tables.iter().find(|f| f.name == "state").unwrap();
        println!(
            "{t}  batch {batch:>6}: chain.redb {:>11} B ({:>6.1} MB)  S {:>7.2} B/acct  \
             Q {:>6.2} B/acct  allocated {:>6.1} MB  file-allocated {:>6.1} MB",
            run.redb,
            run.redb as f64 / MB,
            run.redb as f64 / 200_000.0,
            st.page_bytes(db.page_size) as f64 / 200_000.0,
            (db.allocated_pages * db.page_size) as f64 / MB,
            (run.redb as f64 - (db.allocated_pages * db.page_size) as f64) / MB
        );
        drop(c2);
        drop(r2);
    }

    println!("\n{t}REGRESSION of chain.redb on account count, at constant {n} blocks:");
    line("slope  B per marginal account", slope);
    line(
        "intercept MB (everything that is not accounts)",
        intercept / MB,
    );
    line("the retracted figure, whole-file/accounts", 235.8);
    line("raw payload B/account (20 + 24)", 44.0);
    println!("{t}NOTE: an 18 B value (a 1e24-mile balance ceiling needs 10 B, not 16) would cut the 44 B payload");
    println!("{t}to 38 B, i.e. 13.6% of P. Whether that is worth a schema bump depends on");
    println!("{t}whether P or Q-P dominates - which is exactly what the numbers above say.");
}

#[test]
#[ignore]
fn audit_ibd_vs_pow_capacity() {
    let _g = serial();
    common::machine_note("C5: storage throughput against verification capacity");
    let t = common::tag();
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("{t}cores available: {cores}. The committer is a SINGLE WRITER by construction, so");
    println!("{t}the storage column does not scale with P while the verification column does.");

    let mut storage: Vec<(usize, f64)> = Vec::new();
    for (txs, n) in [
        (2usize, 49_152u64),
        (20, 24_576),
        (64, 16_384),
        (127, 8_192),
    ] {
        let (run, _k) = build_tuned(
            &format!("c5-{txs}"),
            n,
            4_000,
            2 * txs + 1,
            120 + txs * 157,
            4_096,
            0,
            4,
        );
        let bps = run.blocks as f64 / run.secs;
        println!(
            "{t}  {txs:>3} tx/block ({:>6} B bodies): {:>6} blocks in {:>6.2} s = {:>8.0} blocks/s, \
             {:>6.1} MB/s, {:>6.0} us/block",
            120 + txs * 157,
            run.blocks,
            run.secs,
            bps,
            run.total as f64 / MB / run.secs,
            1e6 / bps
        );
        storage.push((txs, bps));
    }

    let hdr = [7u8; 132];
    let t0 = Instant::now();
    let mut sink = 0u8;
    for i in 0..200_000u32 {
        let mut h = hdr;
        h[0] = i as u8;
        sink ^= plaine_consensus::crypto::header_hash(&h)[0];
    }
    let per_hash = t0.elapsed().as_secs_f64() / 200_000.0;
    println!("{t}  (sink {sink})");
    line(
        "measured header_hash us (the PoW check itself)",
        per_hash * 1e6,
    );
    println!("\n{t}PoW capacity, from the cited 1.3-3.0 ms/header band (P threads):");
    for p in [1usize, 2, 4, 8, 16] {
        println!(
            "{t}  P={p:<3} {:>8.0} - {:<8.0} blocks/s",
            p as f64 / 3.0e-3,
            p as f64 / 1.3e-3
        );
    }
    println!("\n{t}CROSSOVER: the thread count P* at which verification catches storage.");
    println!("{t}  P* = storage_blocks_per_s x seconds_per_header_verified. Below P*, PoW binds");
    println!("{t}  and the architecture's claim holds; above it, this single writer binds.");
    println!("{t}  tx/block   storage blk/s      P* at 1.3 ms   P* at 3.0 ms");
    for (txs, bps) in &storage {
        println!(
            "{t}  {txs:>8}   {bps:>13.0}      {:>12.1}   {:>12.1}",
            bps * 1.3e-3,
            bps * 3.0e-3
        );
    }
    println!("{t}Storage column MEASURED on this machine; PoW column CITED, not re-measured - ");
    println!("{t}its dominant term is signature verification, which lives in the validator.");

    let probe = Scratch::new("c5-syscall");
    let (f, _) = {
        let p = probe.0.join("w.bin");
        (std::fs::File::create(&p).unwrap(), p)
    };
    use std::io::Write;
    let one = [0u8; 132];
    let many = vec![0u8; 132 * 4_096];
    let t0 = Instant::now();
    {
        let mut w = &f;
        for _ in 0..4_096 {
            w.write_all(&one).unwrap();
        }
    }
    let split = t0.elapsed().as_secs_f64();
    let t0 = Instant::now();
    {
        let mut w = &f;
        w.write_all(&many).unwrap();
    }
    let joined = t0.elapsed().as_secs_f64();
    drop(f);
    println!("\n{t}THE CHEAP IMPROVEMENT, priced before it is adopted:");
    println!(
        "{t}  4,096 x 132 B writes: {:>8.0} us total, {:>5.2} us each",
        split * 1e6,
        split * 1e6 / 4_096.0
    );
    println!("{t}  1 x 540,672 B write:  {:>8.0} us total", joined * 1e6);
    let saving_us_per_block = (split - joined) * 1e6 / 4_096.0 * 2.0;
    line("upper bound on the saving, us/block", saving_us_per_block);
    for (txs, bps) in &storage {
        let now = 1e6 / bps;
        line(
            &format!("  at {txs} tx/block: us/block now -> best case"),
            now - saving_us_per_block,
        );
        line(
            "     => best-case blocks/s",
            1e6 / (now - saving_us_per_block).max(0.001),
        );
    }
}

#[test]
#[ignore]
fn audit_open_guard_after_a_failed_open() {
    let _g = serial();

    let s = seed("aud-guard", 200);
    let mut bad = s.cfg();
    bad.network = plaine_storage::Network::Main;
    match open(bad) {
        Err(StoreError::NetworkMismatch { .. }) => {
            println!("\n=== network mismatch refused, as designed")
        }
        Err(e) => println!("\n=== refused for another reason: {e}"),
        Ok(_) => println!("\n=== !!! network mismatch ACCEPTED"),
    }
    match open(s.cfg()) {
        Ok((c, _r, _)) => {
            println!("  and the guard was released: a correct open still works");
            drop(c);
        }
        Err(e) => println!("  !!! GUARD LEAKED: {e}"),
    }
}

#[test]
#[ignore]
fn audit_side_header_scan_at_the_row_cap() {
    let _g = serial();
    common::machine_note("side_headers_from, the arena rebuild's boot read");
    let s = Scratch::new("aud-sidescan");
    let mut cfg = s.cfg();
    cfg.side_headers_cap = 16_384;
    let (mut c, r, _) = open(cfg).expect("open");

    let mut make = |lo: u64, hi: u64| {
        let rows: Vec<_> = (lo..hi)
            .map(|i| {
                let mut hdr = [0u8; 132];
                hdr[4..12].copy_from_slice(&i.to_le_bytes());
                let hash = plaine_consensus::crypto::header_hash(&hdr);
                (hash, hdr, i, plaine_storage::HeaderStatus::Connected)
            })
            .collect();
        for part in rows.chunks(2_048) {
            c.put_side_headers(part).unwrap();
        }
    };

    for (label, upto) in [
        ("4,096 rows", 4_096u64),
        ("16,384 rows (the cap)", 16_384u64),
    ] {
        make(0, upto);

        let n0 = r.side_headers_from(0, 100_000).unwrap().len();
        let t = Instant::now();
        let mut n = 0;
        for _ in 0..5 {
            n = r.side_headers_from(0, 100_000).unwrap().len();
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / 5.0;
        assert_eq!(n, n0);
        println!("{}{label:24} rows {n:6}   {us:9.0} us/scan", common::tag());
    }
}
