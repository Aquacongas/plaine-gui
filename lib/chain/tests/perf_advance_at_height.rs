mod support;

use std::time::{Duration, Instant};

use plaine_chain::mock::Scenario;
use plaine_chain::Progress;
use support::*;

const MAX_HEIGHT: u64 = 2_000_000;

fn heights() -> Vec<u64> {
    let raw = std::env::var("PLAINE_PERF_HEIGHTS").unwrap_or_else(|_| "2000,4000".to_string());
    let hs: Vec<u64> = raw
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .expect("PLAINE_PERF_HEIGHTS: comma-separated integers")
        })
        .collect();
    for h in &hs {
        assert!(
            *h >= 100,
            "a height below 100 measures the fixture, not the chain"
        );
        assert!(
            *h <= MAX_HEIGHT,
            "height {h} is above MAX_HEIGHT ({MAX_HEIGHT}); the fixture is ~1 KB/block resident"
        );
    }
    hs
}

fn samples() -> usize {
    std::env::var("PLAINE_PERF_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24)
}

fn stats(mut v: Vec<Duration>) -> (Duration, Duration, Duration) {
    v.sort_unstable();
    (v[v.len() / 2], v[0], v[v.len() - 1])
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

const STAGE: usize = 8_000;

fn sync_staged(r: &mut Rig, chain: &Scenario) {
    let n = chain.blocks.len();
    let mut from = 1usize;
    while from < n {
        let to = (from + STAGE).min(n);
        r.clock.set_unix(chain.blocks[to - 1].rec.time.max(T0));
        let raws: Vec<[u8; 132]> = chain.blocks[from..to].iter().map(|b| b.rec.raw).collect();
        for part in raws.chunks(plaine_consensus::constants::MAX_HEADERS_PER_MSG) {
            r.cm.submit_headers_solicited(1, part)
                .expect("headers ingest");
        }
        for b in &chain.blocks[from..to] {
            let _ = r.cm.submit_block(&b.rec.hash, b.body.clone());
        }
        while let Ok(Progress::Advanced { .. }) = r.cm.advance() {}
        from = to;
    }
}

fn run(h: u64, n: usize) {
    let t = Instant::now();
    let chain = Scenario::genesis(&params(), T0).extend(h);
    let built = t.elapsed();

    let t = Instant::now();
    let mut r = Rig::new(&chain, params());
    sync_staged(&mut r, &chain);
    let synced = t.elapsed();
    assert_eq!(r.height(), h, "the fixture must actually be at height {h}");

    let ext = chain.fork_at(h).extend(n as u64);

    let mut advance_times = Vec::with_capacity(n);
    for i in 1..=n {
        let b = ext.blocks[h as usize + i].clone();
        r.clock.set_unix(b.rec.time);
        assert_eq!(r.offer(1, std::slice::from_ref(&b)).connected, 1);
        let t = Instant::now();
        let p = r.cm.advance().expect("not halted");
        advance_times.push(t.elapsed());
        assert!(matches!(p, Progress::Advanced { .. }), "sample {i}: {p:?}");
    }
    let (a_med, a_min, a_max) = stats(advance_times);

    let tip_h = r.height();
    let cp_hash = r.cm.header_at(tip_h - 1).expect("canonical").hash;
    let cp = signed_checkpoint(&authority_key(), tip_h - 1, cp_hash);
    let mut cp_times = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        r.cm.submit_checkpoint(&cp).expect("a valid signature");
        cp_times.push(t.elapsed());
    }
    let (c_med, c_min, c_max) = stats(cp_times);

    let dup = ext.blocks[h as usize + 1].rec.raw;
    let mut dup_times = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        let _ = r.cm.submit_headers_solicited(9, &[dup]);
        dup_times.push(t.elapsed());
    }
    let (d_med, d_min, d_max) = stats(dup_times);

    println!(
        "height {h:>9}  build {:>7.1}s  sync {:>7.1}s  |  \
         advance med {:>10.1} us [{:>10.1}..{:>10.1}]  |  \
         checkpoint med {:>10.1} us [{:>9.1}..{:>9.1}]  |  \
         control med {:>7.2} us [{:>6.2}..{:>6.2}]",
        built.as_secs_f64(),
        synced.as_secs_f64(),
        us(a_med),
        us(a_min),
        us(a_max),
        us(c_med),
        us(c_min),
        us(c_max),
        us(d_med),
        us(d_min),
        us(d_max),
    );
}

fn run_skips(h: u64, branches: usize, per_branch: u64, n: usize) {
    let chain = Scenario::genesis(&params(), T0).extend(h);
    let mut r = Rig::new(&chain, params());
    sync_staged(&mut r, &chain);
    assert_eq!(r.height(), h);

    let mut sib = chain.fork_at(h);
    for k in 0..branches {
        sib.blocks.truncate(h as usize + 1);
        sib = sib.spacing(1 + k as u64).extend(per_branch);

        let raws: Vec<[u8; 132]> = sib.blocks[h as usize + 1..]
            .iter()
            .map(|b| b.rec.raw)
            .collect();
        for part in raws.chunks(plaine_consensus::constants::MAX_HEADERS_PER_MSG) {
            r.cm.submit_headers_solicited(20 + k as u32, part)
                .expect("headers ingest");
        }
    }

    let ext = chain.fork_at(h).extend(n as u64);
    let mut times = Vec::with_capacity(n);
    let mut committed = 0usize;
    for i in 1..=n {
        let b = ext.blocks[h as usize + i].clone();
        r.clock.set_unix(b.rec.time);
        assert_eq!(r.offer(1, std::slice::from_ref(&b)).connected, 1);
        let t = Instant::now();
        let p = r.cm.advance().expect("not halted");
        times.push(t.elapsed());
        if matches!(p, Progress::Advanced { .. }) {
            committed += 1;
        }
    }
    let (med, lo, hi) = stats(times);
    println!(
        "height {h:>9}  bodyless branches {branches:>3} x {per_branch:<3}           advance med {:>10.1} us [{:>10.1}..{:>10.1}]  committed {committed}/{n}",
        us(med),
        us(lo),
        us(hi),
    );
}

#[test]
#[ignore = "measurement: needs --release and a settled, pinned box"]
fn advance_cost_vs_bodyless_branches() {
    let n = 8;
    for h in heights() {
        for branches in [0usize, 4, 16] {
            run_skips(h, branches, 24, n);
        }
    }
}

#[test]
#[ignore = "measurement: needs --release and a settled, pinned box"]
fn advance_and_checkpoint_cost_against_tip_height() {
    let n = samples();
    println!("samples per point: {n}");
    for h in heights() {
        run(h, n);
    }
}
