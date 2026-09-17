use crate::limits::*;

// EWMA of shares/sec, one estimator per tau horizon. A zero or negative
// interval bails out early, since a repeated timestamp must never nudge the average.
fn decay_time(f: &mut f64, fadd: f64, fsecs: f64, interval: f64) {
    if fsecs <= 0.0 {
        return;
    }
    let dexp = fsecs / interval;
    let fprop = 1.0 - 1.0 / dexp.exp();
    let ftotal = 1.0 + fprop;
    *f += fadd / fsecs * fprop;
    *f /= ftotal;
}

// warm-up correction: the fraction of a horizon we have actually observed, so
// a young estimator isn't read as if it had run forever. floored away from 0.
fn time_bias(t: f64, interval: f64) -> f64 {
    let b = 1.0 - 1.0 / (t / interval).exp();
    if b < 1e-9 {
        1e-9
    } else {
        b
    }
}

#[cfg(test)]
fn snap_to_ladder(d: f64) -> u64 {
    snap_to_ladder_in(d, 1.0, u64::MAX as f64, &DIFF_LADDER)
}

fn snap_to_ladder_in(d: f64, lo: f64, hi: f64, ladder: &[f64]) -> u64 {
    if !d.is_finite() || d <= 1.0 {
        return (lo.max(1.0)).min(hi.max(1.0)) as u64;
    }
    let (lo, hi) = (lo.max(1.0), hi.max(1.0));
    let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
    let k = d.log10().floor();
    let mut best: Option<f64> = None;
    let mut best_err = f64::MAX;

    for dk in [k - 1.0, k, k + 1.0] {
        let scale = 10f64.powf(dk);
        for m in ladder.iter().copied() {
            let cand = m * scale;
            if !cand.is_finite() || cand < lo || cand > hi {
                continue;
            }
            let err = (cand / d).ln().abs();
            if err < best_err {
                best_err = err;
                best = Some(cand);
            }
        }
    }
    let chosen = best.unwrap_or_else(|| d.clamp(lo, hi));
    if chosen >= u64::MAX as f64 {
        u64::MAX
    } else {
        chosen.round().max(1.0) as u64
    }
}

pub struct Vardiff {
    dsps: [f64; 3],
    cur: u64,
    last_stable: u64,
    pinned: Option<u64>,
    min_diff: u64,
    max_diff: u64,
    setpoint: f64,
    started_ms: u64,
    last_update_ms: u64,
    last_share_ms: u64,
    last_retarget_ms: u64,
    shares_total: u32,
    shares_since_retarget: u32,
    cad: Cadence,
    pub retargets: u64,
}

impl Vardiff {
    pub fn new(
        start_diff: u64,
        min_diff: u64,
        max_diff: u64,
        setpoint: f64,
        now_ms: u64,
    ) -> Vardiff {
        let cur = start_diff.clamp(min_diff.min(max_diff), max_diff.max(min_diff));
        Vardiff {
            dsps: [0.0; 3],
            cur,
            last_stable: cur,
            pinned: None,
            min_diff,
            max_diff,
            setpoint,
            started_ms: now_ms,
            last_update_ms: now_ms,
            last_share_ms: now_ms,
            last_retarget_ms: now_ms,
            shares_total: 0,
            shares_since_retarget: 0,
            cad: Cadence::DEFAULT,
            retargets: 0,
        }
    }

    pub fn set_cadence(&mut self, cad: Cadence) {
        self.cad = cad;
    }

    pub fn pin(&mut self, d: u64) {
        let d = d.clamp(
            self.min_diff.min(self.max_diff),
            self.max_diff.max(self.min_diff),
        );
        self.pinned = Some(d);
        self.cur = d;
    }

    pub fn is_pinned(&self) -> bool {
        self.pinned.is_some()
    }

    pub fn current(&self) -> u64 {
        self.cur
    }

    pub fn last_stable(&self) -> u64 {
        self.last_stable
    }

    pub fn set_bounds(&mut self, min_diff: u64, max_diff: u64) {
        self.min_diff = min_diff;
        self.max_diff = max_diff.max(min_diff);
        let c = self.cur.clamp(self.min_diff, self.max_diff);
        self.cur = c;
    }

    pub fn on_share(&mut self, served_difficulty: u64, now_ms: u64) -> Option<u64> {
        if self.pinned.is_some() {
            return None;
        }
        let secs = (now_ms.saturating_sub(self.last_update_ms)) as f64 / 1000.0;
        self.last_share_ms = now_ms;

        // a share from some other rung (a stale job) says nothing about this
        // one: throw the window away rather than feed it in.
        if served_difficulty != self.cur {
            self.shares_since_retarget = 0;
            self.last_retarget_ms = now_ms;
            self.last_update_ms = now_ms;
            return None;
        }

        for i in 0..3 {
            decay_time(
                &mut self.dsps[i],
                served_difficulty as f64,
                secs.max(0.001),
                self.cad.tau[i],
            );
        }
        self.last_update_ms = now_ms;
        self.shares_total = self.shares_total.saturating_add(1);
        self.shares_since_retarget = self.shares_since_retarget.saturating_add(1);
        self.decide(now_ms, false)
    }

    pub fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if self.pinned.is_some() {
            return None;
        }
        let secs = (now_ms.saturating_sub(self.last_update_ms)) as f64 / 1000.0;
        if secs <= 0.0 {
            return None;
        }
        for i in 0..3 {
            decay_time(&mut self.dsps[i], 0.0, secs, self.cad.tau[i]);
        }
        self.last_update_ms = now_ms;

        self.decide(now_ms, true)
    }

    fn want(&self, i: usize, now_ms: u64) -> f64 {
        let age = ((now_ms.saturating_sub(self.started_ms)) as f64 / 1000.0).max(1.0);
        let rate = self.dsps[i] / time_bias(age, self.cad.tau[i]);
        rate * self.setpoint
    }

    // Silence only ever lowers, and not before the knee, a few setpoints in.
    // An ordinary Poisson gap between shares stays under it and doesn't retarget.
    fn want_silence(&self, now_ms: u64) -> f64 {
        let t = (now_ms.saturating_sub(self.last_share_ms)) as f64 / 1000.0;
        let knee = self.cad.silence_slack * self.setpoint;
        if t <= knee {
            return f64::MAX;
        }
        self.cur as f64 * knee / t
    }

    fn gate_open(&self, now_ms: u64) -> bool {
        let gate_shares = if self.shares_total < self.cad.warmup_shares {
            self.cad.warmup_gate_shares
        } else {
            self.cad.retarget_gate_shares
        };
        let elapsed = (now_ms.saturating_sub(self.last_retarget_ms)) as f64 / 1000.0;
        self.shares_since_retarget >= gate_shares || elapsed >= self.cad.retarget_gate_secs
    }

    fn decide(&mut self, now_ms: u64, lower_only: bool) -> Option<u64> {
        let cur = self.cur as f64;
        let w1 = self.want(0, now_ms);
        let w5 = self.want(1, now_ms);
        let w60 = self.want(2, now_ms);

        // Raising needs all three horizons to agree, so take the min, so a brief
        // burst on the fast one can't ratchet a rig up. Lowering consults only
        // the two faster horizons: back off quickly, climb slowly.
        let (want_raise, want_lower) = if lower_only {
            (0.0, self.want_silence(now_ms))
        } else {
            (w1.min(w5).min(w60), w1.min(w5))
        };

        let zone = if self.shares_total >= self.cad.mature_shares {
            self.cad.mature_zone
        } else {
            self.cad.dead_zone
        };

        let want = if !lower_only && want_raise > cur * zone {
            want_raise
        } else if want_lower < cur / zone {
            want_lower
        } else {
            return None;
        };
        if want <= 0.0 {
            return None;
        }

        // a big miss escapes the gate at once; smaller corrections wait for the
        // share- or time-gate, so we aren't chasing estimator noise.
        let ratio = want / cur;
        let fast = ratio > self.cad.fast_escape || ratio < 1.0 / self.cad.fast_escape;
        if !fast && !self.gate_open(now_ms) {
            return None;
        }

        // half the log distance (sqrt of the ratio), clamped to one step: we
        // approach without overshoot.
        let lo = (cur / self.cad.max_step).max(self.min_diff as f64);
        let hi = (cur * self.cad.max_step).min(self.max_diff as f64);
        let damped = cur * ratio.sqrt();
        let snapped = snap_to_ladder_in(damped, lo, hi, &self.cad.ladder[..self.cad.ladder_len]);

        if snapped == self.cur {
            return None;
        }
        self.last_stable = self.cur;
        self.cur = snapped;
        self.shares_since_retarget = 0;
        self.last_retarget_ms = now_ms;
        self.retargets += 1;
        Some(snapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simulate(mut v: Vardiff, hashrate: f64, secs: u64, start_ms: u64) -> (Vardiff, Vec<u64>) {
        let mut hist = vec![v.current()];
        let mut t = start_ms;
        let end = start_ms + secs * 1000;
        let mut next_share = t + ((v.current() as f64 / hashrate) * 1000.0) as u64;
        while t < end {
            t += VARDIFF_TICK.as_millis() as u64;
            if t >= next_share {
                let served = v.current();
                if let Some(d) = v.on_share(served, t) {
                    hist.push(d);
                }
                next_share = t + ((v.current() as f64 / hashrate) * 1000.0) as u64;
            } else if let Some(d) = v.on_tick(t) {
                hist.push(d);
                next_share = t + ((v.current() as f64 / hashrate) * 1000.0) as u64;
            }
        }
        (v, hist)
    }

    fn fresh(start: u64) -> Vardiff {
        Vardiff::new(start, MIN_DIFF, 1_000_000_000, VARDIFF_SETPOINT_SECS, 0)
    }

    #[test]
    fn ladder_snapping_is_log_nearest() {
        assert_eq!(snap_to_ladder(1.0), 1);
        assert_eq!(snap_to_ladder(60_000.0), 60_000);
        assert_eq!(snap_to_ladder(59_000.0), 60_000);

        assert_eq!(snap_to_ladder(9_000.0), 10_000);
        assert_eq!(snap_to_ladder(11_000.0), 12_000);
        assert_eq!(snap_to_ladder(8_500.0), 8_000);
        assert_eq!(snap_to_ladder(1_234_567.0), 1_200_000);

        assert_eq!(snap_to_ladder(f64::NAN), 1);
        assert_eq!(snap_to_ladder(-5.0), 1);
        assert_eq!(snap_to_ladder(0.0), 1);
    }

    #[test]
    fn desktop_converges_to_setpoint() {
        let (v, hist) = simulate(fresh(START_DIFF), 43_358.0, 900, 0);
        let want = 43_358.0 * VARDIFF_SETPOINT_SECS;
        let got = v.current() as f64;
        assert!(
            (got / want) > 0.6 && (got / want) < 1.7,
            "converged to {got}, wanted about {want} (history {hist:?})"
        );
    }

    fn measure_share_interval(
        v: Vardiff,
        hashrate: f64,
        settle_secs: u64,
        measure_secs: u64,
    ) -> (Vardiff, f64, u64) {
        let (mut v, _) = simulate(v, hashrate, settle_secs, 0);
        let start = settle_secs * 1000;
        let end = start + measure_secs * 1000;
        let mut t = start;
        let mut next_share = t + ((v.current() as f64 / hashrate) * 1000.0) as u64;
        let mut shares = 0u64;
        let retargets_before = v.retargets;
        while t < end {
            t += VARDIFF_TICK.as_millis() as u64;
            if t >= next_share {
                let served = v.current();
                v.on_share(served, t);
                shares += 1;
                next_share = t + ((v.current() as f64 / hashrate) * 1000.0) as u64;
            } else if v.on_tick(t).is_some() {
                next_share = t + ((v.current() as f64 / hashrate) * 1000.0) as u64;
            }
        }
        let interval = measure_secs as f64 / shares.max(1) as f64;
        let moves = v.retargets - retargets_before;
        (v, interval, moves)
    }

    #[test]
    fn share_rate_converges_across_hashrates() {
        for hashrate in [100.0, 3_338.0, 13_215.0, 43_358.0, 500_000.0] {
            let v = Vardiff::new(START_DIFF, MIN_DIFF, 1e12 as u64, VARDIFF_SETPOINT_SECS, 0);
            let (v, interval, moves) = measure_share_interval(v, hashrate, 3_600, 1_800);

            let attainable = (MIN_DIFF as f64 / hashrate).max(VARDIFF_SETPOINT_SECS);
            let ratio = interval / attainable;
            assert!(
                (0.6..=1.7).contains(&ratio),
                "{hashrate} H/s settled at one share per {interval:.1} s \
                 (attainable {attainable:.1} s, difficulty {})",
                v.current()
            );

            assert!(
                moves <= 2,
                "{hashrate} H/s retargeted {moves} times in a settled half hour"
            );
        }
    }

    #[test]
    fn longer_setpoint_slows_share_rate() {
        let slow = Vardiff::new(START_DIFF, MIN_DIFF, 1e12 as u64, 60.0, 0);
        let (_, interval, _) = measure_share_interval(slow, 43_358.0, 3_600, 1_800);
        let ratio = interval / 60.0;
        assert!(
            (0.6..=1.7).contains(&ratio),
            "a 60 s setpoint produced one share per {interval:.1} s"
        );
    }

    #[test]
    fn phone_converges_downward() {
        let (v, _) = simulate(fresh(START_DIFF), 3_338.0, 900, 0);
        let want = 3_338.0 * VARDIFF_SETPOINT_SECS;
        let got = v.current() as f64;
        assert!((got / want) > 0.5 && (got / want) < 2.0, "got {got}");
    }

    #[test]
    fn weak_machine_rescued_by_silence() {
        let mut v = fresh(START_DIFF);
        let mut t = 0u64;
        let mut lowered = 0;
        while t < 300_000 {
            t += VARDIFF_TICK.as_millis() as u64;
            if v.on_tick(t).is_some() {
                lowered += 1;
            }
        }
        assert!(lowered > 0, "silence never lowered difficulty");
        assert!(
            v.current() < START_DIFF / 4,
            "after 300 s of silence at 60 000, difficulty is still {}",
            v.current()
        );
        assert!(v.current() >= MIN_DIFF);
    }

    #[test]
    fn silence_never_lowers_before_the_knee() {
        let mut v = fresh(START_DIFF);
        let knee = (SILENCE_SLACK * VARDIFF_SETPOINT_SECS) as u64 * 1000;
        for t in (0..=knee).step_by(2_000) {
            assert_eq!(v.on_tick(t), None, "lowered at t={t}ms");
        }
    }

    #[test]
    fn poisson_gap_does_not_move_settled_rig() {
        let (mut v, _) = simulate(fresh(START_DIFF), 43_358.0, 1_800, 0);
        let settled = v.current();
        let mut t = 1_800_000;
        for _ in 0..30 {
            t += 2_000;
            assert_eq!(v.on_tick(t), None, "a normal quiet stretch retargeted");
        }
        assert_eq!(v.current(), settled);
    }

    #[test]
    fn tick_never_raises() {
        let mut v = fresh(MIN_DIFF);

        let mut t = 0;
        for _ in 0..50 {
            t += 100;
            v.on_share(v.current(), t);
        }
        let before = v.current();
        for _ in 0..600 {
            t += 2_000;
            if let Some(d) = v.on_tick(t) {
                assert!(d < before || d <= v.current(), "tick raised difficulty");
            }
        }
    }

    #[test]
    fn no_limit_cycle_when_steady() {
        let (v, _) = simulate(fresh(START_DIFF), 43_358.0, 1_560, 0);
        let before = v.retargets;
        let (v, hist) = simulate(v, 43_358.0, 240, 1_560_000);
        let moves = v.retargets - before;
        assert!(
            moves <= 1,
            "{moves} retargets in a steady 4 minutes ({hist:?})"
        );
    }

    #[test]
    fn identical_rigs_same_rung() {
        let rungs: Vec<u64> = (0..5)
            .map(|i| {
                let v = Vardiff::new(
                    START_DIFF,
                    MIN_DIFF,
                    1_000_000_000,
                    VARDIFF_SETPOINT_SECS,
                    i * 7_000,
                );
                simulate(v, 13_215.0, 1_800, i * 7_000).0.current()
            })
            .collect();
        let first = rungs[0];
        assert!(
            rungs.iter().all(|r| *r == first),
            "identical rigs landed on different rungs: {rungs:?}"
        );
    }

    #[test]
    fn step_never_exceeds_max() {
        let mut v = fresh(1_000_000);
        let mut t = 0;
        let mut prev = v.current();
        for _ in 0..2_000 {
            t += 2_000;
            if let Some(d) = v.on_tick(t) {
                let r = prev as f64 / d as f64;
                assert!(r <= VARDIFF_MAX_STEP + 1e-9, "step of x{r}");
                prev = d;
            }
        }
    }

    #[test]
    fn pinning_disables_regulator() {
        let mut v = fresh(START_DIFF);
        v.pin(120_000);
        assert!(v.is_pinned());
        assert_eq!(v.current(), 120_000);
        let mut t = 0;
        for _ in 0..1_000 {
            t += 2_000;
            assert_eq!(v.on_tick(t), None);
            assert_eq!(v.on_share(120_000, t), None);
        }
        assert_eq!(v.current(), 120_000);
    }

    #[test]
    fn pinning_is_clamped_into_bounds() {
        let mut v = Vardiff::new(START_DIFF, MIN_DIFF, 100_000, VARDIFF_SETPOINT_SECS, 0);
        v.pin(1);
        assert_eq!(v.current(), MIN_DIFF);
        v.pin(u64::MAX);
        assert_eq!(v.current(), 100_000);
    }

    #[test]
    fn stale_share_resets_window() {
        let mut v = fresh(START_DIFF);
        let before = v.retargets;
        for i in 1..40u64 {
            assert_eq!(v.on_share(START_DIFF * 3, i * 1_000), None);
        }
        assert_eq!(
            v.retargets, before,
            "stale-difficulty shares moved the loop"
        );
    }

    #[test]
    fn bounds_are_respected_everywhere() {
        let (v, _) = simulate(
            Vardiff::new(START_DIFF, MIN_DIFF, 100_000, VARDIFF_SETPOINT_SECS, 0),
            43_358.0,
            1_800,
            0,
        );
        assert!(v.current() >= MIN_DIFF && v.current() <= 100_000);
    }

    #[test]
    fn setpoint_floor_lengthens_rate() {
        let (a, _) = simulate(fresh(START_DIFF), 43_358.0, 1_800, 0);
        let v = Vardiff::new(START_DIFF, MIN_DIFF, 1_000_000_000, 25.0, 0);
        let (b, _) = simulate(v, 43_358.0, 1_800, 0);
        assert!(b.current() >= a.current());
    }

    const POSE_NOW_MS: u64 = 36_000_000;

    fn posed(cur: u64, want_ratio: [f64; 3], shares_total: u32) -> Vardiff {
        let mut v = Vardiff::new(cur, 1, u64::MAX / 4, VARDIFF_SETPOINT_SECS, 0);
        for (d, r) in v.dsps.iter_mut().zip(want_ratio) {
            *d = r * cur as f64 / VARDIFF_SETPOINT_SECS;
        }
        v.shares_total = shares_total;
        v.shares_since_retarget = RETARGET_GATE_SHARES;
        v.last_retarget_ms = 0;
        v.last_share_ms = POSE_NOW_MS;
        v.last_update_ms = POSE_NOW_MS;
        v
    }

    #[test]
    fn pose_asks_what_it_says() {
        let v = posed(100_000, [2.0, 3.0, 4.0], 0);
        for (i, r) in [2.0, 3.0, 4.0].iter().enumerate() {
            let got = v.want(i, POSE_NOW_MS) / 100_000.0;
            assert!(
                (got - r).abs() < 1e-3,
                "horizon {i} asks x{got}, posed x{r}"
            );
        }
    }

    #[test]
    fn burst_on_one_horizon_cannot_raise() {
        let mut v = posed(100_000, [3.0, 0.9, 0.9], 0);
        assert_eq!(v.decide(POSE_NOW_MS, false), None);
        assert_eq!(v.current(), 100_000);
    }

    #[test]
    fn stale_slow_horizon_cannot_lower() {
        let mut v = posed(100_000, [1.0, 1.0, 0.2], 0);
        assert_eq!(v.decide(POSE_NOW_MS, false), None);
    }

    #[test]
    fn dead_zone_absorbs_estimator_error() {
        for r in [1.4, 1.0 / 1.4] {
            let mut v = posed(100_000, [r; 3], 0);
            assert_eq!(v.decide(POSE_NOW_MS, false), None, "moved on a x{r} error");
        }
    }

    #[test]
    fn empty_estimator_does_not_cut() {
        let mut v = posed(100_000, [0.0; 3], 0);
        assert_eq!(v.decide(POSE_NOW_MS, false), None);
        assert_eq!(v.current(), 100_000);
    }

    #[test]
    fn mature_uses_tighter_zone() {
        let mut young = posed(100_000, [1.25; 3], VARDIFF_MATURE_SHARES - 1);
        assert_eq!(young.decide(POSE_NOW_MS, false), None);
        let mut mature = posed(100_000, [1.25; 3], VARDIFF_MATURE_SHARES);
        assert!(mature.decide(POSE_NOW_MS, false).is_some());
    }

    #[test]
    fn gate_holds_small_correction_until_open() {
        let mut v = posed(100_000, [1.6; 3], WARMUP_SHARES);
        v.shares_since_retarget = 0;
        v.last_retarget_ms = POSE_NOW_MS;
        assert_eq!(
            v.decide(POSE_NOW_MS, false),
            None,
            "retargeted with the gate shut"
        );
        v.shares_since_retarget = RETARGET_GATE_SHARES - 1;
        assert_eq!(
            v.decide(POSE_NOW_MS, false),
            None,
            "one share short of the gate"
        );
        v.shares_since_retarget = RETARGET_GATE_SHARES;
        assert!(
            v.decide(POSE_NOW_MS, false).is_some(),
            "the gate never opened on shares"
        );

        let mut t = posed(100_000, [1.6; 3], WARMUP_SHARES);
        t.shares_since_retarget = 0;
        t.last_retarget_ms = POSE_NOW_MS;
        assert_eq!(t.decide(POSE_NOW_MS, false), None);
        let later = POSE_NOW_MS + (RETARGET_GATE_SECS as u64) * 1_000;
        assert!(
            t.decide(later, false).is_some(),
            "the gate never opened on time"
        );
    }

    #[test]
    fn warmup_gate_is_smaller() {
        let mut warming = posed(100_000, [1.6; 3], WARMUP_SHARES - 1);
        warming.shares_since_retarget = WARMUP_GATE_SHARES;
        warming.last_retarget_ms = POSE_NOW_MS;
        assert!(
            warming.decide(POSE_NOW_MS, false).is_some(),
            "a warming rig was made to wait for the full gate"
        );
        let mut warm = posed(100_000, [1.6; 3], WARMUP_SHARES);
        warm.shares_since_retarget = WARMUP_GATE_SHARES;
        warm.last_retarget_ms = POSE_NOW_MS;
        assert_eq!(
            warm.decide(POSE_NOW_MS, false),
            None,
            "a warmed rig was still using the warmup gate"
        );
    }

    #[test]
    fn retarget_moves_half_log_distance() {
        let mut v = posed(100_000, [4.0; 3], VARDIFF_MATURE_SHARES);
        assert_eq!(v.decide(POSE_NOW_MS, false), Some(200_000));
    }

    #[test]
    fn step_clamped_however_far_wrong() {
        let mut up = posed(100_000, [100.0; 3], VARDIFF_MATURE_SHARES);
        assert_eq!(up.decide(POSE_NOW_MS, false), Some(400_000));
        let mut down = posed(100_000, [0.01; 3], VARDIFF_MATURE_SHARES);
        assert_eq!(down.decide(POSE_NOW_MS, false), Some(25_000));
    }

    #[test]
    fn bounds_enforced_at_construction_and_move() {
        let sp = VARDIFF_SETPOINT_SECS;
        assert_eq!(
            Vardiff::new(50, MIN_DIFF, 1_000_000, sp, 0).current(),
            MIN_DIFF
        );
        assert_eq!(
            Vardiff::new(u64::MAX, MIN_DIFF, 1_000_000, sp, 0).current(),
            1_000_000
        );

        let _ = Vardiff::new(START_DIFF, 1_000_000, MIN_DIFF, sp, 0);

        let mut v = fresh(1_000_000);
        v.set_bounds(MIN_DIFF, 100_000);
        assert_eq!(
            v.current(),
            100_000,
            "a difficulty above the new maximum survived"
        );
        v.set_bounds(500_000, 1_000_000);
        assert_eq!(
            v.current(),
            500_000,
            "a difficulty below the new minimum survived"
        );
    }

    #[test]
    fn retarget_resets_its_window() {
        let mut v = posed(100_000, [4.0; 3], VARDIFF_MATURE_SHARES);
        assert_eq!(v.decide(POSE_NOW_MS, false), Some(200_000));
        assert_eq!(
            v.shares_since_retarget, 0,
            "the window survived its own retarget"
        );
        assert_eq!(v.last_retarget_ms, POSE_NOW_MS);
        assert_eq!(v.retargets, 1);

        assert_eq!(v.last_stable(), 100_000);
        v.shares_since_retarget = RETARGET_GATE_SHARES;
        v.last_retarget_ms = 0;
        let want = 4.0 * v.cur as f64 / VARDIFF_SETPOINT_SECS;
        v.dsps = [want; 3];
        assert_eq!(v.decide(POSE_NOW_MS, false), Some(400_000));
        assert_eq!(
            v.last_stable(),
            200_000,
            "last_stable is the difficulty before the LAST move, not the first"
        );
        assert_eq!(v.retargets, 2);
    }

    #[test]
    fn estimator_total_on_degenerate_time() {
        let mut f = 1234.5;
        decay_time(&mut f, 8_192.0, 0.0, DSPS_TAU[0]);
        assert_eq!(f, 1234.5, "a zero interval moved the estimator");
        decay_time(&mut f, 8_192.0, -5.0, DSPS_TAU[0]);
        assert_eq!(f, 1234.5, "a negative interval moved the estimator");
        assert!(time_bias(0.0, DSPS_TAU[0]) >= 1e-9);
        assert!(
            (1.0f64 / time_bias(0.0, DSPS_TAU[0])).is_finite(),
            "dividing by time_bias overflowed"
        );

        let mut v = fresh(START_DIFF);
        v.on_share(v.current(), 1_000);
        v.on_share(v.current(), 1_000);
        assert!(
            v.dsps.iter().all(|d| d.is_finite()),
            "dsps went non-finite: {:?}",
            v.dsps
        );
        assert_eq!(
            v.on_tick(1_000),
            None,
            "a repeated tick timestamp retargeted"
        );
        assert!(
            v.dsps.iter().all(|d| d.is_finite()),
            "dsps went non-finite: {:?}",
            v.dsps
        );
        assert!(v.current() > 0);
    }

    #[test]
    fn repeated_tick_cannot_retarget_twice() {
        let mut v = fresh(START_DIFF);
        let mut t = 0u64;
        let mut first = None;
        while t < 4_000_000 {
            t += VARDIFF_TICK.as_millis() as u64;
            if let Some(d) = v.on_tick(t) {
                first = Some(d);
                break;
            }
        }
        let first = first.expect("silence never lowered at all");
        assert_eq!(
            v.on_tick(t),
            None,
            "the same millisecond retargeted a second time"
        );
        assert_eq!(v.current(), first);
    }

    #[test]
    fn first_silence_step_at_six_setpoints() {
        let mut v = fresh(START_DIFF);
        let mut first = None;
        let mut t = 0u64;
        while t < 4_000_000 {
            t += VARDIFF_TICK.as_millis() as u64;
            if v.on_tick(t).is_some() {
                first = Some(t);
                break;
            }
        }
        let first = first.expect("silence never lowered at all");
        let setpoints = first as f64 / 1_000.0 / VARDIFF_SETPOINT_SECS;
        assert!(
            (setpoints - SILENCE_SLACK * VARDIFF_DEAD_ZONE).abs() <= 0.2,
            "the first silence step landed at {setpoints} setpoints, not \
             SILENCE_SLACK * VARDIFF_DEAD_ZONE = {}",
            SILENCE_SLACK * VARDIFF_DEAD_ZONE
        );
    }
}
#[cfg(test)]
mod pin_bounds {
    use super::*;

    #[test]
    fn pinning_survives_inverted_bounds() {
        let mut v = Vardiff::new(4096, 8192, 16, VARDIFF_SETPOINT_SECS, 0);
        assert_eq!(
            (v.min_diff, v.max_diff),
            (8192, 16),
            "the inversion is stored as given"
        );
        v.pin(4096);
        let got = v.current();
        assert!(
            (16..=8192).contains(&got),
            "pinned to {got}, outside both bounds however they are read"
        );
    }

    #[test]
    fn pinning_inside_ordinary_bounds_is_untouched() {
        let mut v = Vardiff::new(1024, 16, 8192, VARDIFF_SETPOINT_SECS, 0);
        v.pin(1);
        assert_eq!(v.current(), 16, "below the floor clamps up to it");
        v.pin(99_999);
        assert_eq!(v.current(), 8192, "above the ceiling clamps down to it");
    }
}
