use plaine_consensus::asert::{asert_next_bits, Target, POW_LIMIT};
use plaine_consensus::constants::{
    ASERT_HALF_LIFE_SECS, BLOCK_TIME_SECS, COINBASE_MATURITY, GENESIS_BITS, MAX_REORG_DEPTH,
};

const HS_PER_THREAD: f64 = 11_522.71;

const HS_EIGHT_THREADS: f64 = 88_015.85;

fn work_of(bits: u32) -> f64 {
    let t = Target::from_compact(bits).expect("legal compact bits");
    let mut x = 0f64;
    for limb in t.0.iter().rev() {
        x = x * 18_446_744_073_709_551_616.0 + *limb as f64;
    }
    18_446_744_073_709_551_616.0f64.powi(4) / (x + 1.0)
}

struct Rng(u64);
impl Rng {
    fn exp(&mut self, mean: f64) -> f64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        let u = (((x.wrapping_mul(0x2545_F491_4F6C_DD1D)) >> 11) as f64) / ((1u64 << 53) as f64);
        -mean * u.max(1e-18).ln()
    }
}

fn grow(n: usize, hs: f64, step: Option<(usize, f64)>, seed: Option<u64>) -> Vec<f64> {
    let genesis_time: u64 = 1_800_000_000;
    let anchor_parent_time = genesis_time - BLOCK_TIME_SECS;
    let mut rng = seed.map(Rng);
    let mut t = Vec::with_capacity(n + 1);
    t.push(genesis_time as f64);
    for h in 1..=n {
        let bits = asert_next_bits(
            GENESIS_BITS,
            0,
            anchor_parent_time,
            (h - 1) as u64,
            t[h - 1] as u64,
            &POW_LIMIT,
        )
        .expect("anchor is height 0, so the parent is never below it");
        let rate = match step {
            Some((at, f)) if h > at => hs * f,
            _ => hs,
        };
        let mean = work_of(bits) / rate;
        let dt = match rng.as_mut() {
            Some(r) => r.exp(mean),
            None => mean,
        };
        t.push(t[h - 1] + dt);
    }
    t
}

fn tightest_window(t: &[f64], n: usize) -> (f64, usize) {
    let mut best = f64::INFINITY;
    let mut at = 0usize;
    for i in 1..t.len().saturating_sub(n) {
        let w = t[i + n] - t[i];
        if w < best {
            best = w;
            at = i;
        }
    }
    (best, at)
}

fn unhealable_after(share: f64, cap: usize, hs: f64) -> f64 {
    let genesis_time: u64 = 1_800_000_000;
    let anchor_parent_time = genesis_time - BLOCK_TIME_SECS;
    let warm = 2_000usize;
    let mut t = grow(warm, hs, None, None);
    let fork_t = t[warm];
    for h in warm + 1..warm + cap + 2 {
        let bits = asert_next_bits(
            GENESIS_BITS,
            0,
            anchor_parent_time,
            (h - 1) as u64,
            t[h - 1] as u64,
            &POW_LIMIT,
        )
        .expect("asert");
        t.push(t[h - 1] + work_of(bits) / (hs * share));
    }
    t[warm + cap + 1] - fork_t
}

const REFERENCE_SECS: f64 = 3_237.0;

const TOLERANCE_SECS: f64 = 60.0;

#[test]
fn even_split_window_matches_reference() {
    let cap = MAX_REORG_DEPTH as usize;
    let secs = unhealable_after(0.5, cap, 180_000.0);
    println!(
        "cap {cap}: an even split becomes unhealable after {:.0} s = {:.1} min \
         (reference value {:.1} min)",
        secs,
        secs / 60.0,
        REFERENCE_SECS / 60.0
    );

    assert!(
        unhealable_after(0.5, cap * 2, 180_000.0) > secs,
        "twice the cap must tolerate a longer partition, or this is not measuring the cap"
    );
    assert!(
        unhealable_after(0.1, cap, 180_000.0) > secs,
        "a 10% minority mines slower and must stay inside the cap for longer, or this is not \
         measuring the split"
    );

    assert!(
        (secs - REFERENCE_SECS).abs() <= TOLERANCE_SECS,
        "the reorg-cap derivation moved: reference {:.1} min, now {:.1} min. \
         Re-derive rather than editing REFERENCE_SECS to match.",
        REFERENCE_SECS / 60.0,
        secs / 60.0
    );
}

#[test]
fn cap_bounds_majority_rewrite() {
    for hs in [1.0e3f64, 1.0e6, 1.0e9] {
        let work_per_block = BLOCK_TIME_SECS as f64 * hs;
        let attacker_hashes = (MAX_REORG_DEPTH + 1) as f64 * work_per_block;
        let network_seconds = attacker_hashes / hs;
        assert!(
            (network_seconds - ((MAX_REORG_DEPTH + 1) * BLOCK_TIME_SECS) as f64).abs() < 1e-6,
            "the bound must be independent of network size"
        );
    }

    let minutes = (MAX_REORG_DEPTH + 1) * BLOCK_TIME_SECS / 60;
    println!(
        "cap {MAX_REORG_DEPTH}: a majority rewrite costs {minutes} network-minutes of work, \
         i.e. {} confirmations is the finality this chain can publish",
        MAX_REORG_DEPTH + 1
    );
}

#[test]
fn maturity_keeps_2x_margin() {
    const {
        assert!(
            COINBASE_MATURITY >= 2 * MAX_REORG_DEPTH,
            "maturity must stay at least twice the reorg cap"
        )
    };
}

#[test]
fn stochastic_windows_shorter() {
    let cap = MAX_REORG_DEPTH as usize;
    let det = tightest_window(&grow(20_000, HS_EIGHT_THREADS, None, None), cap).0;
    let mut worst = f64::INFINITY;
    for s in 0..20u64 {
        let t = grow(
            20_000,
            HS_EIGHT_THREADS,
            None,
            Some(0xdead_beef ^ s.wrapping_mul(0x9e37_79b9)),
        );
        worst = worst.min(tightest_window(&t, cap).0);
    }
    println!(
        "tightest {cap}-block window: deterministic {det:.1} s, worst of 20 stochastic seeds \
         {worst:.1} s"
    );
    assert!(
        worst < det,
        "the deterministic model must be the conservative one; if it is not, every table in this \
         file overstates the safety of the cap"
    );
}

#[test]
fn difficulty_ramp_ends_within_four_hours() {
    for hs in [HS_PER_THREAD, HS_EIGHT_THREADS, 1.8e6, 1.8e7] {
        let t = grow(20_000, hs, None, None);
        let end = (1..t.len() - 1)
            .find(|&i| t[i + 1] - t[i] >= 0.9 * BLOCK_TIME_SECS as f64)
            .expect("the ramp must end inside 20 000 blocks");
        let secs = t[end] - t[0];
        println!(
            "{hs:>12.0} H/s: ramp ends at height {end} after {:.0} s ({:.2} h); \
             {MAX_REORG_DEPTH} blocks at genesis = {:.1} s",
            secs,
            secs / 3600.0,
            t[MAX_REORG_DEPTH as usize + 1] - t[1]
        );
        assert!(
            secs <= 4.0 * 3600.0,
            "the launch difficulty ramp now takes {:.2} h at {hs} H/s. The plan for covering it \
             (a reachable anchor, a loud stranded node, a written recovery) assumes a few hours, \
             not a few days. ASERT_HALF_LIFE_SECS = {ASERT_HALF_LIFE_SECS}.",
            secs / 3600.0
        );
    }
}

#[test]
fn derivation_tables() {
    let cap = MAX_REORG_DEPTH as usize;
    println!("\nMAX_REORG_DEPTH = {MAX_REORG_DEPTH}  BLOCK_TIME_SECS = {BLOCK_TIME_SECS}");
    println!(
        "work at GENESIS_BITS = {:.0} hashes/block\n",
        work_of(GENESIS_BITS)
    );

    println!("-- the honest cost: minutes until a partition cannot heal (mature difficulty) --");
    println!("  cap  | share 0.50 | share 0.30 | share 0.10");
    for c in [15usize, 30, 60, 100, 144, 200, 288] {
        print!("  {c:4} |");
        for share in [0.5f64, 0.3, 0.1] {
            print!(" {:10.1} |", unhealable_after(share, c, 180_000.0) / 60.0);
        }
        println!();
    }

    println!("\n-- the launch window: what {cap} blocks is worth before ASERT converges --");
    for (label, hs) in [
        ("1 thread", HS_PER_THREAD),
        ("8 threads", HS_EIGHT_THREADS),
        ("16 threads", 180_000.0),
        ("10 boxes", 1.8e6),
        ("100 boxes", 1.8e7),
    ] {
        let t = grow(20_000, hs, None, None);
        println!(
            "  {label:11} {hs:>12.0} H/s  first block {:>7.2} s  {cap} blocks {:>7.1} s",
            t[1] - t[0],
            t[cap + 1] - t[1]
        );
    }

    println!("\n-- and after a step up in hash rate at mature difficulty --");
    for f in [2.0f64, 4.0, 10.0, 100.0] {
        let t = grow(4_000, 180_000.0, Some((2_000, f)), None);
        let mut best = f64::INFINITY;
        for i in 2_000..t.len() - cap - 1 {
            best = best.min(t[i + cap] - t[i]);
        }
        println!(
            "  x{f:<5}  interval right after the step {:>6.1} s   tightest {cap}-block window \
             {:>7.0} s ({:.1} min)",
            t[2_001] - t[2_000],
            best,
            best / 60.0
        );
    }
    println!();
}
