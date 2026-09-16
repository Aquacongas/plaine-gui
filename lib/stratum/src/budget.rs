use crate::limits::*;

pub fn shares_per_sec(conns: usize, setpoint_secs: f64) -> f64 {
    conns as f64 / setpoint_secs
}

pub fn verify_cores(shares_per_sec: f64, secs_per_share: f64) -> f64 {
    shares_per_sec * secs_per_share
}

pub fn pool_verify_threads(cores: usize) -> usize {
    (cores / 4).max(2)
}

pub fn pool_capacity_shares_per_sec(threads: usize) -> f64 {
    threads as f64 / SHARE_VERIFY_SECS_WORST
}

pub fn worst_case_verify_wait_secs(conns: usize, threads: usize) -> f64 {
    conns as f64 / pool_capacity_shares_per_sec(threads)
}

// a solo node shares its cores with consensus and networking, so budget only a
// quarter of them for share verification.
pub fn node_share_capacity_per_sec(p: usize) -> f64 {
    0.25 * p as f64 / SHARE_VERIFY_SECS_WORST
}

pub fn setpoint_floor_secs(conns: usize, p: usize) -> f64 {
    conns as f64 / node_share_capacity_per_sec(p)
}

pub fn effective_setpoint_secs(conns: usize, p: usize) -> f64 {
    VARDIFF_SETPOINT_SECS.max(setpoint_floor_secs(conns, p))
}

pub fn connection_slice_exhaustion_secs(hashrate: f64) -> f64 {
    (1u64 << X_BITS) as f64 / hashrate
}

pub fn thread_slice_exhaustion_secs(hashrate_per_thread: f64) -> f64 {
    (1u64 << 32) as f64 / hashrate_per_thread
}

pub fn thread_exhaustion_hashrate(job_life_secs: f64) -> f64 {
    (1u64 << 32) as f64 / job_life_secs
}

pub fn connection_exhaustion_hashrate(job_life_secs: f64) -> f64 {
    (1u64 << X_BITS) as f64 / job_life_secs
}

#[derive(Debug, Clone, Copy)]
pub struct ConnMemory {
    pub read_buf: usize,
    pub write_buf: usize,
    pub json_arena: usize,
    pub job_slots: usize,
    pub dedup: usize,
    pub session: usize,
    pub queued_share: usize,
    pub task: usize,
}

fn json_arena_bytes() -> usize {
    crate::json::Doc::new().resident_bytes()
}

fn job_slots_bytes() -> usize {
    crate::job::JobSlots::new().resident_bytes()
}

fn session_struct_bytes() -> usize {
    core::mem::size_of::<crate::session::Session>()
}

fn queued_share_bytes() -> usize {
    core::mem::size_of::<crate::verify::ShareWork>()
}

const TASK_BYTES: usize = 1_024;

impl ConnMemory {
    pub fn typical() -> ConnMemory {
        ConnMemory {
            read_buf: READ_BUF_INITIAL,
            write_buf: 512,
            json_arena: json_arena_bytes(),
            job_slots: job_slots_bytes(),
            dedup: 0,
            session: session_struct_bytes(),
            queued_share: queued_share_bytes(),
            task: TASK_BYTES,
        }
    }

    pub fn worst(max_line_post_auth: usize) -> ConnMemory {
        ConnMemory {
            read_buf: max_line_post_auth,
            write_buf: OUT_BUF_CAP,
            json_arena: json_arena_bytes() - READ_BUF_INITIAL + max_line_post_auth,
            job_slots: job_slots_bytes(),
            dedup: (JOB_SLOTS + 1) * crate::job::dedup_bytes(),
            session: session_struct_bytes(),
            queued_share: queued_share_bytes(),
            task: TASK_BYTES,
        }
    }

    pub fn total(&self) -> usize {
        self.read_buf
            + self.write_buf
            + self.json_arena
            + self.job_slots
            + self.dedup
            + self.session
            + self.queued_share
            + self.task
    }
}

pub fn global_resident_bytes() -> usize {
    let e1 = crate::nonce::E1Allocator::resident_bytes();
    let bans = BAN_TABLE_ENTRIES * 60;
    let diffs = DIFF_CACHE_ENTRIES * 66;
    e1 + bans + diffs
}

pub fn total_resident_bytes(conns: usize, max_line_post_auth: usize) -> usize {
    conns * ConnMemory::worst(max_line_post_auth).total() + global_resident_bytes()
}

pub fn valid_flood_hashrate_per_conn(min_diff: u64) -> f64 {
    min_diff as f64 * SUBMIT_RATE_PER_SEC
}

pub fn idle_squat_hashrate_per_slot(min_diff: u64) -> f64 {
    min_diff as f64 / IDLE_EVICT.as_secs() as f64
}

pub fn invalid_shares_to_ban() -> u32 {
    let (points, _) = crate::proto::ErrorCode::LowDifficulty.penalty();
    BAN_THRESHOLD.div_ceil(points)
}

pub fn flood_drain_secs(conns: usize, threads: usize) -> f64 {
    conns as f64 * invalid_shares_to_ban() as f64 / pool_capacity_shares_per_sec(threads)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RYZEN_7950X: f64 = 43_358.0;
    const XEON_E5_2680V4: f64 = 13_215.0;
    const POCO_X7: f64 = 3_338.0;

    #[test]
    fn cpu_at_one_thousand_and_ten_thousand_connections() {
        let k1 = shares_per_sec(1_000, VARDIFF_SETPOINT_SECS);
        assert_eq!(k1, 50.0);
        assert!((verify_cores(k1, SHARE_VERIFY_SECS_BEST) - 0.065).abs() < 1e-9);
        assert!((verify_cores(k1, SHARE_VERIFY_SECS_WORST) - 0.15).abs() < 1e-9);

        let k10 = shares_per_sec(10_000, VARDIFF_SETPOINT_SECS);
        assert_eq!(k10, 500.0);
        assert!((verify_cores(k10, SHARE_VERIFY_SECS_BEST) - 0.65).abs() < 1e-9);
        assert!((verify_cores(k10, SHARE_VERIFY_SECS_WORST) - 1.5).abs() < 1e-9);
    }

    #[test]
    fn full_pool_of_sixteen_thousand_still_fits() {
        let full = shares_per_sec(Caps::POOL.max_connections, VARDIFF_SETPOINT_SECS);
        assert!((full - 819.2).abs() < 0.01);
        let worst = verify_cores(full, SHARE_VERIFY_SECS_WORST);
        assert!((worst - 2.4576).abs() < 0.001, "{worst} cores");

        let threads = pool_verify_threads(16);
        assert_eq!(threads, 4);
        let cap = pool_capacity_shares_per_sec(threads);
        assert!((cap - 1_333.33).abs() < 0.1, "{cap} shares/s");
        assert!(cap / full > 1.6, "headroom only x{}", cap / full);
    }

    #[test]
    fn worst_case_verification_wait_is_inside_a_job_life() {
        let w = worst_case_verify_wait_secs(Caps::POOL.max_connections, pool_verify_threads(16));
        assert!((w - 12.29).abs() < 0.05, "{w} s");
        assert!(
            w < 60.0,
            "a share must never expire waiting for the interpreter"
        );
    }

    #[test]
    fn node_setpoint_floor_matches_the_node_arch_formula() {
        assert!((node_share_capacity_per_sec(4) - 333.33).abs() < 0.1);
        assert!((node_share_capacity_per_sec(2) - 166.67).abs() < 0.1);
        let floor = setpoint_floor_secs(Caps::SOLO.max_connections, 4);
        assert!((floor - 0.768).abs() < 0.01, "{floor}");
        assert_eq!(effective_setpoint_secs(256, 4), VARDIFF_SETPOINT_SECS);
        assert!(VARDIFF_SETPOINT_SECS / floor > 26.0);

        let ceiling4 = setpoint_floor_secs(SOLO_MAX_CONNECTIONS_CEILING, 4);
        let ceiling2 = setpoint_floor_secs(SOLO_MAX_CONNECTIONS_CEILING, 2);
        assert!((ceiling4 - 24.58).abs() < 0.05, "{ceiling4}");
        assert!((ceiling2 - 49.15).abs() < 0.05, "{ceiling2}");
        assert!(effective_setpoint_secs(SOLO_MAX_CONNECTIONS_CEILING, 2) > 49.0);
    }

    #[test]
    fn default_solo_load_is_a_few_percent_of_one_core() {
        let rate = shares_per_sec(256, VARDIFF_SETPOINT_SECS);
        assert!((rate - 12.8).abs() < 0.01);
        let lo = verify_cores(rate, SHARE_VERIFY_SECS_BEST);
        let hi = verify_cores(rate, SHARE_VERIFY_SECS_WORST);
        assert!((lo - 0.0166).abs() < 0.001 && (hi - 0.0384).abs() < 0.001);
    }

    #[test]
    fn sixteen_thread_miner_takes_months_to_exhaust_its_slice() {
        let secs = connection_slice_exhaustion_secs(RYZEN_7950X);
        let days = secs / 86_400.0;
        assert!((days - 293.5).abs() < 1.0, "{days} days");

        let per_thread = thread_slice_exhaustion_secs(RYZEN_7950X / 16.0);
        assert!((per_thread / 86_400.0 - 18.34).abs() < 0.1);

        let margin = per_thread / 60.0;
        assert!(margin > 26_000.0, "margin only x{margin}");
    }

    #[test]
    fn slower_machines_have_even_more_headroom() {
        for hr in [XEON_E5_2680V4, POCO_X7] {
            let days = connection_slice_exhaustion_secs(hr) / 86_400.0;
            assert!(days > 900.0, "{hr} H/s exhausts in {days} days");
        }
    }

    #[test]
    fn degenerate_exhaustion_needs_absurd_hardware() {
        let per_thread = thread_exhaustion_hashrate(60.0);
        assert!((per_thread / 1e6 - 71.58).abs() < 0.1, "{per_thread}");
        let per_conn = connection_exhaustion_hashrate(60.0);
        assert!((per_conn / 1e9 - 18.33).abs() < 0.01, "{per_conn}");

        let ratio = per_conn / RYZEN_7950X;
        assert!(ratio > 400_000.0, "{ratio}");
    }

    #[test]
    fn e1_space_cannot_run_out() {
        assert!(E1_SPACE as usize > Caps::POOL.max_connections * 1_000);

        let wrap_hours = E1_SPACE as f64 / 100.0 / 3_600.0;
        assert!((wrap_hours - 46.6).abs() < 0.5, "{wrap_hours} h");
    }

    #[test]
    fn per_connection_memory_at_the_documented_line_limit_exceeds_24_kib() {
        let worst = ConnMemory::worst(MAX_LINE_POST_AUTH);
        assert!(
            worst.total() > 24 * 1024,
            "worst case is {} B; the tension is resolved elsewhere",
            worst.total()
        );
    }

    #[test]
    fn the_budget_closes_if_the_post_auth_line_limit_is_2_kib() {
        let worst = ConnMemory::worst(2 * 1024);
        assert!(
            worst.total() <= 24 * 1024,
            "still {} B at a 2 KiB line limit",
            worst.total()
        );
    }

    #[test]
    fn steady_state_per_connection_is_well_under_the_budget() {
        let t = ConnMemory::typical().total();
        assert!(t < 10 * 1024, "{t} B");
    }

    #[test]
    fn every_memory_line_item_is_derived_from_the_type_it_describes() {
        let arena = crate::json::Doc::new().resident_bytes();
        assert_eq!(arena, ConnMemory::typical().json_arena);

        let expected_nodes = JSON_MAX_VALUES * 16;
        assert!(arena > expected_nodes + READ_BUF_INITIAL, "{arena} B");
        assert!(arena <= 4 * 1024, "the arena grew past 4 KiB: {arena} B");

        assert_eq!(
            ConnMemory::typical().job_slots,
            crate::job::JobSlots::new().resident_bytes()
        );
        assert_eq!(ConnMemory::typical().dedup, 0, "lazy, not preallocated");
        assert_eq!(
            ConnMemory::worst(2 * 1024).dedup,
            (JOB_SLOTS + 1) * crate::job::dedup_bytes()
        );
        assert_eq!(
            ConnMemory::typical().session,
            core::mem::size_of::<crate::session::Session>()
        );
        assert_eq!(
            ConnMemory::typical().queued_share,
            core::mem::size_of::<crate::verify::ShareWork>()
        );
    }

    #[test]
    fn pool_and_solo_totals() {
        let pool = total_resident_bytes(Caps::POOL.max_connections, 2 * 1024);
        assert!(
            pool < 400 * 1024 * 1024,
            "{} MiB",
            pool / 1024 / 1024
        );

        let solo = total_resident_bytes(Caps::SOLO.max_connections, 2 * 1024);
        assert!(solo < 24 * 1024 * 1024, "{} MiB", solo / 1024 / 1024);
    }

    #[test]
    fn the_solo_operator_ceiling_blows_the_node_arch_line_item() {
        let ceiling = total_resident_bytes(SOLO_MAX_CONNECTIONS_CEILING, 2 * 1024);
        let mib = ceiling / 1024 / 1024;
        assert!(mib > 64, "{mib} MiB against a 64 MiB line item");
        assert!(mib < 512, "{mib} MiB");
    }

    #[test]
    fn global_tables_are_small_and_capped() {
        let g = global_resident_bytes();
        assert!(g < 12 * 1024 * 1024, "{} B", g);

        assert_eq!(crate::nonce::E1Allocator::resident_bytes(), 2 * 1024 * 1024);
    }

    #[test]
    fn flooding_with_valid_shares_costs_more_than_mining() {
        let per_conn = valid_flood_hashrate_per_conn(MIN_DIFF);
        assert!((per_conn - 24_576.0).abs() < 1.0, "{per_conn} H/s");
        let fleet = per_conn * 10_000.0;
        assert!((fleet / 1e6 - 245.76).abs() < 0.1, "{fleet}");
        let ryzens = fleet / RYZEN_7950X;
        assert!((ryzens - 5_668.0).abs() < 5.0, "{ryzens} 7950X-equivalents");
    }

    #[test]
    fn squatting_every_slot_costs_real_hashing() {
        let per_slot = idle_squat_hashrate_per_slot(MIN_DIFF);
        assert!((per_slot - 4.551).abs() < 0.01);
        let pool = per_slot * Caps::POOL.max_connections as f64;
        assert!((pool / 1000.0 - 74.57).abs() < 0.05, "{pool} H/s");
    }

    #[test]
    fn idle_eviction_break_even_coin_flip() {
        let per_slot = idle_squat_hashrate_per_slot(MIN_DIFF);
        let expected_at_break_even = per_slot * IDLE_EVICT.as_secs() as f64 / MIN_DIFF as f64;
        assert!((expected_at_break_even - 1.0).abs() < 1e-9);
        let p_evicted = (-expected_at_break_even).exp();
        assert!((p_evicted - 0.3679).abs() < 0.001, "{p_evicted}");

        let expected_at_100 = 100.0 * IDLE_EVICT.as_secs() as f64 / MIN_DIFF as f64;
        assert!(expected_at_100 > 20.0);
        assert!((-expected_at_100).exp() < 1e-9);
    }

    #[test]
    fn an_invalid_share_flood_drains_in_about_two_minutes() {
        assert_eq!(invalid_shares_to_ban(), 10);
        let secs = flood_drain_secs(Caps::POOL.max_connections, pool_verify_threads(16));
        assert!((secs - 122.9).abs() < 0.5, "{secs} s");

        assert_eq!(Caps::POOL.new_conns_per_ip_per_min, 6);
    }

    #[test]
    fn notify_traffic_is_negligible_even_at_ten_thousand_connections() {
        let notifies_per_min = 60.0 / TEMPLATE_REFRESH.as_secs() as f64 + 1.0;
        let bytes_per_sec_per_conn = 330.0 * notifies_per_min / 60.0;
        assert!(bytes_per_sec_per_conn < 30.0, "{bytes_per_sec_per_conn}");
        let total = bytes_per_sec_per_conn * 10_000.0;
        assert!(total < 300_000.0, "{total} B/s");
    }

    #[test]
    fn a_small_pool_host_still_runs_two_verification_threads() {
        assert_eq!(pool_verify_threads(1), 2, "the floor, not cores/4");
        assert_eq!(pool_verify_threads(4), 2, "the floor still binds at 4 cores");
        assert_eq!(pool_verify_threads(7), 2);
        assert_eq!(pool_verify_threads(8), 2, "cores/4 reaches the floor here");
        assert_eq!(pool_verify_threads(12), 3, "and takes over above it");
        assert_eq!(pool_verify_threads(16), 4);
    }

    #[test]
    fn global_budget_covers_its_types() {
        let e1 = crate::nonce::E1Allocator::resident_bytes();
        let floor = e1
            + BAN_TABLE_ENTRIES * core::mem::size_of::<crate::abuse::IpRecord>()
            + DIFF_CACHE_ENTRIES * core::mem::size_of::<crate::abuse::AddrState>();
        assert!(
            global_resident_bytes() >= floor,
            "the global budget {} B understates the {} B its types alone need",
            global_resident_bytes(),
            floor
        );
    }

    #[test]
    fn task_frame_allowance_is_generous() {
        let t = ConnMemory::typical();
        assert_eq!(
            t.task, 1_024,
            "TASK_BYTES is a deliberately generous tokio task-frame allowance"
        );
    }

    #[test]
    fn worst_case_grows_with_line_limit() {
        let small = ConnMemory::worst(2 * 1024);
        let large = ConnMemory::worst(8 * 1024);
        let delta = large.total() - small.total();
        assert_eq!(
            delta,
            2 * (8 * 1024 - 2 * 1024),
            "a longer line costs both the read buffer and the arena"
        );
        assert_eq!(large.read_buf, 8 * 1024);
        assert_eq!(
            large.json_arena - small.json_arena,
            8 * 1024 - 2 * 1024,
            "the arena is the second of the two"
        );
    }

    #[test]
    fn shares_to_ban_rounds_up() {
        let (points, _) = crate::proto::ErrorCode::LowDifficulty.penalty();
        let n = invalid_shares_to_ban();
        assert!(
            n * points >= BAN_THRESHOLD,
            "{n} shares at {points} points = {}, under BAN_THRESHOLD {BAN_THRESHOLD}: must round up",
            n * points
        );
        assert!(
            (n - 1) * points < BAN_THRESHOLD,
            "and it must not round further up than it has to"
        );
        assert_eq!(
            BAN_THRESHOLD % points,
            0,
            "BAN_THRESHOLD {BAN_THRESHOLD} and penalty {points} no longer divide evenly"
        );
    }
}
