use crate::limits::*;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last_ms: u64,
    unlimited: bool,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, burst: f64, now_ms: u64) -> TokenBucket {
        TokenBucket {
            tokens: burst,
            rate: rate_per_sec,
            burst,
            last_ms: now_ms,
            unlimited: false,
        }
    }

    pub fn unlimited() -> TokenBucket {
        TokenBucket {
            tokens: 0.0,
            rate: 0.0,
            burst: 0.0,
            last_ms: 0,
            unlimited: true,
        }
    }

    pub fn take(&mut self, now_ms: u64) -> bool {
        if self.unlimited {
            return true;
        }
        let dt = (now_ms.saturating_sub(self.last_ms)) as f64 / 1000.0;
        self.last_ms = now_ms;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

const NIL: u32 = u32::MAX;

struct LruEntry<K, V> {
    key: K,
    val: V,
    prev: u32,
    next: u32,
}

pub struct Lru<K, V> {
    index: HashMap<K, u32>,
    entries: Vec<LruEntry<K, V>>,
    head: u32,
    tail: u32,
    cap: usize,
}

impl<K: std::hash::Hash + Eq + Clone, V> Lru<K, V> {
    pub fn new(cap: usize) -> Lru<K, V> {
        Lru {
            index: HashMap::new(),
            entries: Vec::new(),
            head: NIL,
            tail: NIL,
            cap: cap.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    fn unlink(&mut self, i: u32) {
        let (p, n) = {
            let e = &self.entries[i as usize];
            (e.prev, e.next)
        };
        if p != NIL {
            self.entries[p as usize].next = n;
        } else {
            self.head = n;
        }
        if n != NIL {
            self.entries[n as usize].prev = p;
        } else {
            self.tail = p;
        }
    }

    fn push_front(&mut self, i: u32) {
        self.entries[i as usize].prev = NIL;
        self.entries[i as usize].next = self.head;
        if self.head != NIL {
            self.entries[self.head as usize].prev = i;
        }
        self.head = i;
        if self.tail == NIL {
            self.tail = i;
        }
    }

    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let i = *self.index.get(k)?;
        self.unlink(i);
        self.push_front(i);
        Some(&mut self.entries[i as usize].val)
    }

    pub fn put(&mut self, k: K, v: V) {
        if let Some(&i) = self.index.get(&k) {
            self.entries[i as usize].val = v;
            self.unlink(i);
            self.push_front(i);
            return;
        }
        if self.index.len() >= self.cap {
            let victim = self.tail;
            if victim != NIL {
                let old_key = self.entries[victim as usize].key.clone();
                self.index.remove(&old_key);
                self.unlink(victim);
                self.entries[victim as usize].key = k.clone();
                self.entries[victim as usize].val = v;
                self.push_front(victim);
                self.index.insert(k, victim);
                return;
            }
        }
        let i = self.entries.len() as u32;
        self.entries.push(LruEntry {
            key: k.clone(),
            val: v,
            prev: NIL,
            next: NIL,
        });
        self.push_front(i);
        self.index.insert(k, i);
    }

    pub fn entry_or_default(&mut self, k: K) -> &mut V
    where
        V: Default,
    {
        if self.index.contains_key(&k) {
            return self.get_mut(&k).expect("just checked");
        }
        self.put(k.clone(), V::default());
        self.get_mut(&k).expect("just inserted")
    }

    pub fn entry_or_default_protected<F>(&mut self, k: K, evictable: F) -> Option<&mut V>
    where
        V: Default,
        F: Fn(&V) -> bool,
    {
        if self.index.contains_key(&k) {
            return self.get_mut(&k);
        }
        if self.index.len() < self.cap {
            self.put(k.clone(), V::default());
            return self.get_mut(&k);
        }

        // Scan up from the LRU tail for the first entry the caller marks
        // evictable. That is what stops connection churn from knocking out a live
        // ban or an in-use conn count; neither is evictable while it matters.
        let mut victim = self.tail;
        while victim != NIL {
            if evictable(&self.entries[victim as usize].val) {
                break;
            }
            victim = self.entries[victim as usize].prev;
        }
        if victim == NIL {
            return None;
        }
        let old_key = self.entries[victim as usize].key.clone();
        self.index.remove(&old_key);
        self.unlink(victim);
        self.entries[victim as usize].key = k.clone();
        self.entries[victim as usize].val = V::default();
        self.push_front(victim);
        self.index.insert(k, victim);
        Some(&mut self.entries[victim as usize].val)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Soft,
    Hard,
}

#[derive(Debug, Clone, Default)]
pub struct IpRecord {
    seen: bool,
    hard: u32,
    soft: u32,
    last_decay_ms: u64,
    banned_until_ms: u64,
    ban_count: u32,
    pub conns: u32,
    new_conns: u32,
    new_conn_window_ms: u64,
    throttled_until_ms: u64,
}

impl IpRecord {
    fn effective(&self, soft_cap: u32) -> u32 {
        self.hard + self.soft.min(soft_cap)
    }
}

pub struct BanTable {
    ips: Lru<IpAddr, IpRecord>,
    pub bans_issued: u64,
    pub saturated: u64,
    scratch: IpRecord,
    pol: BanPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Ok,
    Banned,
    PerIpLimit,
    PerIpRate,
    ServerFull,
    AcceptRate,
    Throttled,
}

impl BanTable {
    pub fn new() -> BanTable {
        BanTable::with_policy(BanPolicy::DEFAULT)
    }

    pub fn with_policy(pol: BanPolicy) -> BanTable {
        BanTable {
            ips: Lru::new(pol.table_entries.max(1)),
            bans_issued: 0,
            saturated: 0,
            scratch: IpRecord::default(),
            pol,
        }
    }

    fn decayed(&mut self, ip: IpAddr, now_ms: u64) -> &mut IpRecord {
        let evictable = |r: &IpRecord| {
            r.conns == 0 && r.banned_until_ms <= now_ms && r.throttled_until_ms <= now_ms
        };
        let r = match self.ips.entry_or_default_protected(ip, evictable) {
            Some(r) => r,
            None => {
                // Full table, nothing evictable. Rather than drop a real ban to
                // make room, hand back a throwaway record and bump `saturated`
                // so an operator can see it happening.
                self.saturated += 1;
                self.scratch = IpRecord::default();
                self.scratch.seen = true;
                self.scratch.last_decay_ms = now_ms;
                self.scratch.new_conn_window_ms = now_ms;
                return &mut self.scratch;
            }
        };
        if !r.seen {
            r.seen = true;
            r.last_decay_ms = now_ms;
            r.new_conn_window_ms = now_ms;
        }
        let decay_secs = self.pol.decay_secs.max(1);
        let elapsed = now_ms.saturating_sub(r.last_decay_ms) / 1000;
        let points = (elapsed / decay_secs) as u32;
        if points > 0 {
            // drain soft before hard. A NAT'd farm's stale-share noise lands in
            // soft; the codes that actually earn a ban land in hard, so hard is
            // the bucket that should linger.
            let from_soft = points.min(r.soft);
            r.soft -= from_soft;
            r.hard = r.hard.saturating_sub(points - from_soft);
            r.last_decay_ms += (points as u64) * decay_secs * 1000;
        }
        r
    }

    pub fn score(&mut self, ip: IpAddr, now_ms: u64) -> u32 {
        if !self.pol.enabled {
            return 0;
        }
        let cap = self.pol.soft_cap;
        self.decayed(ip, now_ms).effective(cap)
    }

    pub fn is_banned(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        if !self.pol.enabled {
            return false;
        }
        self.decayed(ip, now_ms).banned_until_ms > now_ms
    }

    pub fn penalise(
        &mut self,
        ip: IpAddr,
        points: u32,
        severity: Severity,
        now_ms: u64,
    ) -> Option<u64> {
        if !self.pol.enabled || self.pol.threshold == 0 {
            return None;
        }
        let cap = self.pol.soft_cap;
        let threshold = self.pol.threshold;
        let base_secs = self.pol.base_secs;
        let ladder = self.pol.ladder_factor.max(1);
        let max_secs = self.pol.max_secs;
        let r = self.decayed(ip, now_ms);
        match severity {
            Severity::Soft => r.soft = r.soft.saturating_add(points),
            Severity::Hard => r.hard = r.hard.saturating_add(points),
        }
        if r.effective(cap) < threshold || r.banned_until_ms > now_ms {
            return None;
        }

        // each repeat offence multiplies the ban length up to the daily cap. the
        // check above (banned_until_ms > now) means a single flood at machine
        // speed still counts as one offence, not one per packet.
        let mut secs = base_secs;
        for _ in 0..r.ban_count {
            secs = secs.saturating_mul(ladder);
            if secs >= max_secs {
                break;
            }
        }
        let secs = secs.min(max_secs);
        r.ban_count = r.ban_count.saturating_add(1);
        r.banned_until_ms = now_ms + secs * 1000;
        // score is spent by the ban; start the next window clean.
        r.hard = 0;
        r.soft = 0;
        self.bans_issued += 1;
        Some(secs * 1000)
    }

    pub fn throttle(&mut self, ip: IpAddr, now_ms: u64) {
        if !self.pol.enabled || self.pol.throttle_ms == 0 {
            return;
        }
        let throttle_ms = self.pol.throttle_ms;
        let r = self.decayed(ip, now_ms);
        r.throttled_until_ms = now_ms + throttle_ms;
    }

    pub fn admit(
        &mut self,
        ip: IpAddr,
        now_ms: u64,
        caps: &Caps,
        total_conns: usize,
        accept_bucket: &mut TokenBucket,
    ) -> Admit {
        if caps.max_connections != 0 && total_conns >= caps.max_connections {
            return Admit::ServerFull;
        }
        let per_ip = caps.max_per_ip as u32;
        let per_min = caps.new_conns_per_ip_per_min;
        let r = self.decayed(ip, now_ms);
        if now_ms.saturating_sub(r.new_conn_window_ms) >= 60_000 {
            r.new_conn_window_ms = now_ms;
            r.new_conns = 0;
        }

        r.new_conns = r.new_conns.saturating_add(1);
        if r.banned_until_ms > now_ms {
            return Admit::Banned;
        }
        if r.throttled_until_ms > now_ms {
            return Admit::Throttled;
        }
        if per_ip != 0 && r.conns >= per_ip {
            return Admit::PerIpLimit;
        }
        if per_min != 0 && r.new_conns > per_min {
            return Admit::PerIpRate;
        }

        // take the shared accept token last, and only for a conn we will
        // actually seat. a rejected peer's reconnect loop then costs it nothing
        // from the global budget.
        if !accept_bucket.take(now_ms) {
            return Admit::AcceptRate;
        }
        r.conns += 1;
        Admit::Ok
    }

    pub fn attempts_this_minute(&mut self, ip: IpAddr, now_ms: u64) -> u32 {
        self.decayed(ip, now_ms).new_conns
    }

    pub fn conns(&mut self, ip: IpAddr, now_ms: u64) -> u32 {
        self.decayed(ip, now_ms).conns
    }

    pub fn release(&mut self, ip: IpAddr, now_ms: u64) {
        let r = self.decayed(ip, now_ms);
        r.conns = r.conns.saturating_sub(1);
    }

    pub fn len(&self) -> usize {
        self.ips.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }
}

impl Default for BanTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddrState {
    pub last_difficulty: u64,
    pub updated_ms: u64,
    logins_this_min: u32,
    login_window_ms: u64,
    storm_since_ms: u64,
    pub pinned_floor: Option<u64>,
}

pub struct DiffCache {
    map: Lru<[u8; 20], AddrState>,
    pol: DiffPolicy,
}

impl DiffCache {
    pub fn new() -> DiffCache {
        DiffCache::with_policy(DiffPolicy::DEFAULT)
    }

    pub fn with_policy(pol: DiffPolicy) -> DiffCache {
        DiffCache {
            map: Lru::new(pol.cache_entries.max(1)),
            pol,
        }
    }

    pub fn start_for(&mut self, addr: &[u8; 20], now_ms: u64) -> (u64, Option<u64>) {
        let start = self.pol.start_diff;
        let ttl = self.pol.cache_ttl_ms;
        match self.map.get_mut(addr) {
            Some(s)
                if now_ms.saturating_sub(s.updated_ms) <= ttl
                    && s.last_difficulty > 0 =>
            {
                (s.last_difficulty, s.pinned_floor)
            }
            // stale or empty entry: warm up from the default. The storm floor is
            // not a cached difficulty, though, so it rides through the TTL.
            Some(s) => (start, s.pinned_floor),
            None => (start, None),
        }
    }

    pub fn record(&mut self, addr: &[u8; 20], difficulty: u64, now_ms: u64) {
        let s = self.map.entry_or_default(*addr);
        s.last_difficulty = difficulty;
        s.updated_ms = now_ms;
    }

    pub fn note_login(&mut self, addr: &[u8; 20], last_stable: u64, now_ms: u64) -> Option<u64> {
        if !self.pol.storm_enabled {
            return self.map.get_mut(addr).and_then(|s| s.pinned_floor);
        }
        let per_min = self.pol.storm_per_min;
        let window_ms = self.pol.storm_window_ms;
        let min_diff = self.pol.min_diff;
        let s = self.map.entry_or_default(*addr);
        if now_ms.saturating_sub(s.login_window_ms) >= 60_000 {
            if s.logins_this_min <= per_min {
                s.storm_since_ms = 0;
            }
            s.login_window_ms = now_ms;
            s.logins_this_min = 0;
        }
        s.logins_this_min += 1;
        if s.logins_this_min > per_min {
            if s.storm_since_ms == 0 {
                s.storm_since_ms = now_ms;
            } else if now_ms.saturating_sub(s.storm_since_ms) >= window_ms {
                // sustained over-threshold reconnects, not a single flap: pin a
                // floor so a rig that keeps dropping doesn't re-warm from scratch
                // (never below the protocol minimum).
                // TODO: once pinned this floor never lifts on its own; a rig
                // that settles back down keeps the raised floor until its cache
                // entry is evicted.
                s.pinned_floor = Some(last_stable.max(min_diff));
            }
        }
        s.pinned_floor
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for DiffCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn token_bucket_rate_and_burst() {
        let mut b = TokenBucket::new(SUBMIT_RATE_PER_SEC, SUBMIT_BURST, 0);
        for i in 0..10 {
            assert!(b.take(0), "burst token {i} refused");
        }
        assert!(!b.take(0), "burst exceeded but still admitted");

        assert!(b.take(1_000));
        assert!(b.take(1_000));
        assert!(b.take(1_000));
        assert!(!b.take(1_000));
    }

    #[test]
    fn submit_ceiling_over_a_job_life_is_190() {
        let mut b = TokenBucket::new(SUBMIT_RATE_PER_SEC, SUBMIT_BURST, 0);
        let mut admitted = 0;
        for ms in (0..=60_000).step_by(10) {
            if b.take(ms) {
                admitted += 1;
            }
        }

        let formula = (SUBMIT_BURST + SUBMIT_RATE_PER_SEC * 60.0) as usize;
        assert_eq!(formula, 190);
        assert!((189..=190).contains(&admitted), "{admitted}");
        assert!(admitted < DEDUP_PER_JOB);
    }

    #[test]
    fn duplicate_flooder_banned_after_four() {
        let mut t = BanTable::new();
        for i in 0..3 {
            assert_eq!(t.penalise(ip(1), 25, Severity::Hard, i * 100), None);
        }
        assert!(t.penalise(ip(1), 25, Severity::Hard, 400).is_some());
        assert!(t.is_banned(ip(1), 400));
    }

    #[test]
    fn slice_violator_banned_after_two() {
        let mut t = BanTable::new();
        assert_eq!(t.penalise(ip(2), 50, Severity::Hard, 0), None);
        assert!(t.penalise(ip(2), 50, Severity::Hard, 10).is_some());
    }

    #[test]
    fn ten_low_difficulty_shares_ban() {
        let mut t = BanTable::new();
        for i in 0..9 {
            assert_eq!(t.penalise(ip(3), 10, Severity::Hard, i), None);
        }
        assert!(t.penalise(ip(3), 10, Severity::Hard, 9).is_some());
    }

    #[test]
    fn natted_farm_not_banned_by_staleness() {
        let mut t = BanTable::new();
        let mut now = 0u64;
        for _ in 0..200 {
            for _ in 0..64 {
                assert_eq!(
                    t.penalise(ip(4), 1, Severity::Soft, now),
                    None,
                    "a NAT'd farm was banned for being stale"
                );
            }
            now += 60_000;
        }
        assert!(!t.is_banned(ip(4), now));
    }

    #[test]
    fn soft_score_contributes_with_hard() {
        let mut t = BanTable::new();
        for _ in 0..100 {
            t.penalise(ip(5), 1, Severity::Soft, 0);
        }
        assert_eq!(t.score(ip(5), 0), SOFT_SCORE_CAP);

        for _ in 0..7 {
            assert_eq!(t.penalise(ip(5), 10, Severity::Hard, 0), None);
        }
        assert!(t.penalise(ip(5), 10, Severity::Hard, 0).is_some());
    }

    #[test]
    fn decay_drains_a_full_score_in_ten_minutes() {
        let mut t = BanTable::new();
        for _ in 0..9 {
            t.penalise(ip(6), 10, Severity::Hard, 0);
        }
        assert_eq!(t.score(ip(6), 0), 90);
        assert_eq!(t.score(ip(6), 600_000), 0, "1 point / 6 s => 100 in 600 s");
    }

    #[test]
    fn honest_border_stales_never_ban() {
        let mut t = BanTable::new();
        for min in 0..600u64 {
            t.penalise(ip(7), 1, Severity::Soft, min * 60_000);
            assert!(!t.is_banned(ip(7), min * 60_000));
        }
    }

    #[test]
    fn ban_ladder_multiplies_by_four_to_a_daily_cap() {
        let mut t = BanTable::new();
        let mut now = 0u64;
        let mut durations = Vec::new();
        for _ in 0..6 {
            let d = loop {
                if let Some(d) = t.penalise(ip(8), 50, Severity::Hard, now) {
                    break d;
                }
                now += 1;
            };
            durations.push(d / 1000);
            now += d + 1;
        }
        assert_eq!(durations, vec![600, 2_400, 9_600, 38_400, 86_400, 86_400]);
    }

    #[test]
    fn per_ip_and_global_admission() {
        let mut t = BanTable::new();
        let caps = Caps::POOL;
        let mut accept = TokenBucket::new(caps.global_accept_per_sec as f64, 100.0, 0);

        for i in 0..6 {
            assert_eq!(
                t.admit(ip(9), 0, &caps, i, &mut accept),
                Admit::Ok,
                "connection {i}"
            );
        }
        assert_eq!(t.admit(ip(9), 0, &caps, 6, &mut accept), Admit::PerIpRate);

        let mut now = 60_001;
        for i in 6..64 {
            if i % 6 == 0 {
                now += 60_001;
            }
            assert_eq!(t.admit(ip(9), now, &caps, i, &mut accept), Admit::Ok);
        }
        now += 60_001;
        assert_eq!(t.admit(ip(9), now, &caps, 64, &mut accept), Admit::PerIpLimit);
    }

    #[test]
    fn server_full_and_accept_rate_are_distinct() {
        let mut t = BanTable::new();
        let caps = Caps::SOLO;
        let mut accept = TokenBucket::new(caps.global_accept_per_sec as f64, 1.0, 0);
        assert_eq!(
            t.admit(ip(10), 0, &caps, caps.max_connections, &mut accept),
            Admit::ServerFull
        );
        assert_eq!(t.admit(ip(10), 0, &caps, 0, &mut accept), Admit::Ok);
        assert_eq!(t.admit(ip(11), 0, &caps, 0, &mut accept), Admit::AcceptRate);
    }

    #[test]
    fn garbage_throttles_the_source_for_a_minute() {
        let mut t = BanTable::new();
        let caps = Caps::POOL;
        let mut accept = TokenBucket::new(1000.0, 1000.0, 0);
        t.throttle(ip(12), 0);
        assert_eq!(t.admit(ip(12), 0, &caps, 0, &mut accept), Admit::Throttled);
        assert_eq!(t.admit(ip(12), 30_000, &caps, 0, &mut accept), Admit::Throttled);
        assert_eq!(t.admit(ip(12), 60_001, &caps, 0, &mut accept), Admit::Ok);
    }

    #[test]
    fn banned_ips_cannot_reconnect() {
        let mut t = BanTable::new();
        let caps = Caps::POOL;
        let mut accept = TokenBucket::new(1000.0, 1000.0, 0);
        t.penalise(ip(13), 100, Severity::Hard, 0);
        assert_eq!(t.admit(ip(13), 0, &caps, 0, &mut accept), Admit::Banned);
        assert_eq!(
            t.admit(ip(13), 600_001, &caps, 0, &mut accept),
            Admit::Ok,
            "the ban must expire"
        );
    }

    #[test]
    fn banned_host_cannot_spend_accept_budget() {
        let mut t = BanTable::new();
        let caps = Caps::POOL;
        let mut accept = TokenBucket::new(0.0, 500.0, 0);
        t.penalise(ip(20), 100, Severity::Hard, 0);
        for i in 0..5_000 {
            assert_eq!(
                t.admit(ip(20), 1_000, &caps, 0, &mut accept),
                Admit::Banned,
                "attempt {i}"
            );
        }
        assert_eq!(
            t.admit(ip(21), 1_000, &caps, 0, &mut accept),
            Admit::Ok,
            "an honest peer was starved by a banned one's reconnect loop"
        );
    }

    #[test]
    fn banned_attempts_count_own_window() {
        let mut t = BanTable::new();
        let caps = Caps::POOL;
        let mut accept = TokenBucket::new(1_000.0, 1_000.0, 0);
        t.penalise(ip(22), 100, Severity::Hard, 0);
        for _ in 0..20 {
            assert_eq!(t.admit(ip(22), 0, &caps, 0, &mut accept), Admit::Banned);
        }
        assert_eq!(t.attempts_this_minute(ip(22), 0), 20);
        assert_eq!(t.conns(ip(22), 0), 0, "a banned peer holds no slot");
    }

    #[test]
    fn refused_conn_costs_no_shared_budget() {
        let mut t = BanTable::new();
        let caps = Caps::POOL;

        let mut accept = TokenBucket::new(0.0, 1.0, 0);
        t.throttle(ip(23), 0);
        assert_eq!(t.admit(ip(23), 0, &caps, 0, &mut accept), Admit::Throttled);
        assert_eq!(
            t.admit(ip(24), 0, &caps, 0, &mut accept),
            Admit::Ok,
            "a throttled peer spent the token it was never going to use"
        );
    }

    #[test]
    fn churn_keeps_live_ban_and_conn() {
        let mut t = BanTable::new();

        let caps = Caps {
            new_conns_per_ip_per_min: u32::MAX,
            ..Caps::POOL
        };
        let mut accept = TokenBucket::new(1e9, 1e9, 0);
        let banned = ip(30);
        let holder = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        t.penalise(banned, 100, Severity::Hard, 0);
        assert!(t.is_banned(banned, 1_000));
        for _ in 0..caps.max_per_ip {
            assert_eq!(t.admit(holder, 0, &caps, 0, &mut accept), Admit::Ok);
        }

        {
            let probe = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
            assert_eq!(t.admit(probe, 1_000, &caps, 0, &mut accept), Admit::Ok);
            t.release(probe, 1_000);
            for k in 0..caps.max_per_ip {
                assert_eq!(
                    t.admit(probe, 1_000, &caps, 0, &mut accept),
                    Admit::Ok,
                    "admission {k} of {} refused; release did not return the per-ip slot",
                    caps.max_per_ip
                );
            }
            for _ in 0..caps.max_per_ip {
                t.release(probe, 1_000);
            }
        }

        for i in 0..(BAN_TABLE_ENTRIES as u32 * 2) {
            let a = IpAddr::V4(Ipv4Addr::from((0x0100_0000u32 + i).to_be_bytes()));
            let _ = t.admit(a, 1_000, &caps, 0, &mut accept);
            t.release(a, 1_000);
        }

        assert!(
            t.is_banned(banned, 1_000),
            "a ban with 599 s to run was evicted by connection churn"
        );
        assert_eq!(
            t.admit(banned, 1_000, &caps, 0, &mut accept),
            Admit::Banned
        );
        assert_eq!(
            t.admit(holder, 1_000, &caps, 0, &mut accept),
            Admit::PerIpLimit,
            "concurrency accounting for a live host was evicted"
        );
        assert_eq!(t.len(), BAN_TABLE_ENTRIES);
    }

    #[test]
    fn full_live_table_reports_saturation() {
        let mut t = BanTable::new();
        for i in 0..BAN_TABLE_ENTRIES {
            let a = IpAddr::V4(Ipv4Addr::from((i as u32).to_be_bytes()));
            t.penalise(a, 100, Severity::Hard, 0);
        }
        assert_eq!(t.saturated, 0);
        let fresh = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(t.score(fresh, 0), 0);
        assert!(t.saturated > 0, "saturation must be visible to an operator");

        assert!(t.is_banned(IpAddr::V4(Ipv4Addr::from(0u32.to_be_bytes())), 0));
    }

    #[test]
    fn lru_evicts_and_never_grows_past_its_cap() {
        let mut l: Lru<u32, u32> = Lru::new(4);
        for i in 0..100 {
            l.put(i, i * 2);
        }
        assert_eq!(l.len(), 4);
        assert_eq!(l.entries.len(), 4, "slot reuse, not vector growth");
        assert_eq!(l.get_mut(&99).copied(), Some(198));
        assert_eq!(l.get_mut(&0), None);
    }

    #[test]
    fn lru_keeps_the_recently_used() {
        let mut l: Lru<u32, u32> = Lru::new(3);
        l.put(1, 1);
        l.put(2, 2);
        l.put(3, 3);
        assert_eq!(l.get_mut(&1).copied(), Some(1));
        l.put(4, 4);
        assert_eq!(l.get_mut(&1).copied(), Some(1));
        assert_eq!(l.get_mut(&2), None);
    }

    #[test]
    fn ban_table_is_capped() {
        let mut t = BanTable::new();
        for i in 0..(BAN_TABLE_ENTRIES + 1000) {
            let a = IpAddr::V4(Ipv4Addr::from((i as u32).to_be_bytes()));
            t.penalise(a, 1, Severity::Hard, 0);
        }
        assert_eq!(t.len(), BAN_TABLE_ENTRIES);
    }

    #[test]
    fn diff_cache_returns_the_last_step_and_expires() {
        let mut c = DiffCache::new();
        let a = [1u8; 20];
        assert_eq!(c.start_for(&a, 0), (START_DIFF, None));
        c.record(&a, 250_000, 1_000);
        assert_eq!(c.start_for(&a, 2_000), (250_000, None));
        let day = DIFF_CACHE_TTL.as_millis() as u64;
        assert_eq!(
            c.start_for(&a, 1_000 + day + 1),
            (START_DIFF, None),
            "stale entries fall back to the designed default"
        );
    }

    #[test]
    fn diff_cache_is_capped() {
        let mut c = DiffCache::new();
        for i in 0..(DIFF_CACHE_ENTRIES + 500) {
            let mut a = [0u8; 20];
            a[..8].copy_from_slice(&(i as u64).to_le_bytes());
            c.record(&a, 1234, 0);
        }
        assert_eq!(c.len(), DIFF_CACHE_ENTRIES);
    }

    #[test]
    fn reconnect_storm_pins_the_floor() {
        let mut c = DiffCache::new();
        let a = [2u8; 20];
        let mut now = 0u64;
        let mut pinned = None;

        for _ in 0..6 {
            for _ in 0..5 {
                pinned = c.note_login(&a, 250_000, now);
                now += 1_000;
            }
            now += 60_000;
        }
        assert_eq!(pinned, Some(250_000));
    }

    #[test]
    fn normal_reconnect_does_not_pin() {
        let mut c = DiffCache::new();
        let a = [3u8; 20];
        let mut now = 0u64;
        for _ in 0..30 {
            assert_eq!(c.note_login(&a, 250_000, now), None);
            now += 120_000;
        }
    }

    #[test]
    fn idle_eviction_hash_cost() {
        let per_slot = MIN_DIFF as f64 / IDLE_EVICT.as_secs() as f64;
        assert!((per_slot - 4.551).abs() < 0.01, "{per_slot}");
        let all_slots = per_slot * Caps::POOL.max_connections as f64;
        assert!((all_slots - 74_566.0).abs() < 10.0, "{all_slots}");
    }

    #[test]
    fn valid_share_flooding_costs_real_hashrate() {
        let per_conn = MIN_DIFF as f64 * SUBMIT_RATE_PER_SEC;
        assert!((per_conn - 24_576.0).abs() < 1.0);
        let fleet = per_conn * 10_000.0;

        let ryzens = fleet / 43_358.0;
        assert!(ryzens > 5_000.0, "{ryzens} 7950X-equivalents");
    }

    #[test]
    fn closed_conn_returns_per_ip_slot() {
        let mut b = BanTable::new();
        let caps = Caps::POOL;
        let mut accept = TokenBucket::new(500.0, 500.0, 0);
        let peer = ip(28);

        let mut now = 1_000u64;
        for i in 0..(caps.max_per_ip as u32 + 8) {
            assert_eq!(
                b.admit(peer, now, &caps, 0, &mut accept),
                Admit::Ok,
                "attempt {i} was refused: a serially reconnecting address must \
                 never accumulate a concurrent connection count"
            );
            assert_eq!(b.conns(peer, now), 1);
            b.release(peer, now);
            assert_eq!(b.conns(peer, now), 0, "the slot must come back on close");
            now += 61_000;
        }
    }

    #[test]
    fn score_decays_from_first_contact() {
        let step = BAN_DECAY_SECS * 1000;
        let mut b = BanTable::new();
        let peer = ip(9);

        let first = 3_000u64;
        assert!(first % step != 0, "the whole point is a partial step");
        b.penalise(peer, 50, Severity::Hard, first);

        assert_eq!(
            b.score(peer, first + step - 1),
            50,
            "the decay clock started at boot, so this IP was forgiven a point \
             for time it was not here for"
        );
        assert_eq!(b.score(peer, first + step), 49, "and one step later, exactly one");
    }

    #[test]
    fn decay_forgives_soft_first() {
        let step = BAN_DECAY_SECS * 1000;
        let mut b = BanTable::new();
        let peer = ip(10);
        b.penalise(peer, SOFT_SCORE_CAP + 15, Severity::Soft, 1_000);
        b.penalise(peer, 60, Severity::Hard, 1_000);
        let before = b.score(peer, 1_000);
        assert_eq!(before, 60 + SOFT_SCORE_CAP, "effective = hard + min(soft, cap)");

        assert_eq!(
            b.score(peer, 1_000 + step),
            before,
            "one step comes out of soft, which is above its cap, so effective is unchanged"
        );

        assert_eq!(b.score(peer, 1_000 + 15 * step), before);
        assert_eq!(b.score(peer, 1_000 + 16 * step), before - 1);
    }

    #[test]
    fn read_count_does_not_change_decay() {
        let step = BAN_DECAY_SECS * 1000;
        let peer = ip(11);
        let (mut rare, mut often) = (BanTable::new(), BanTable::new());
        rare.penalise(peer, 60, Severity::Hard, 0);
        often.penalise(peer, 60, Severity::Hard, 0);

        let mut t = 0u64;
        for _ in 0..6 {
            t += step + step / 2;
            let _ = often.score(peer, t);
        }
        assert_eq!(
            often.score(peer, t),
            rare.score(peer, t),
            "the score that was read six times decayed less than the one that \
             was read once, over identical elapsed time"
        );
        assert_eq!(rare.score(peer, t), 60 - 9, "nine whole steps elapsed");
    }

    #[test]
    fn ban_not_reissued_within_flood() {
        let mut b = BanTable::new();
        let peer = ip(12);
        let first = b
            .penalise(peer, BAN_THRESHOLD, Severity::Hard, 1_000)
            .expect("the threshold must ban");
        assert_eq!(first, BAN_BASE.as_millis() as u64, "the first ban is the base");

        for i in 0..25 {
            assert_eq!(
                b.penalise(peer, BAN_THRESHOLD, Severity::Hard, 1_000 + i),
                None,
                "packet {i} of one flood re-issued the ban"
            );
        }
        assert_eq!(b.bans_issued, 1, "one offence is one ban");
        assert!(b.is_banned(peer, 1_000 + BAN_BASE.as_millis() as u64 - 1));
        assert!(
            !b.is_banned(peer, 1_000 + BAN_BASE.as_millis() as u64 + 1),
            "and it is still only the base ban, not a laddered one"
        );
    }

    #[test]
    fn recorded_diff_ttl_runs_from_record() {
        let mut c = DiffCache::new();
        let addr = [3u8; 20];

        let now = DIFF_CACHE_TTL.as_millis() as u64 * 3;
        c.record(&addr, 123_456, now);
        assert_eq!(
            c.start_for(&addr, now).0,
            123_456,
            "a difficulty recorded a moment ago must be served back"
        );
    }

    #[test]
    fn storm_floor_needs_sustained_window() {
        let mut c = DiffCache::new();
        let addr = [4u8; 20];
        let per_min = RECONNECT_STORM_PER_MIN;
        let window = RECONNECT_STORM_WINDOW.as_millis() as u64;

        let mut now = 1_000u64;
        for _ in 0..(per_min + 1) {
            assert_eq!(
                c.note_login(&addr, 1, now),
                None,
                "one over-threshold minute is a flap, not a storm"
            );
            now += 1_000;
        }

        let start = now;
        let mut pinned = None;
        while now < start + window + 60_000 {
            pinned = c.note_login(&addr, 1, now);
            now += 10_000;
        }
        assert_eq!(
            pinned,
            Some(MIN_DIFF),
            "a sustained storm pins the floor, lifted to MIN_DIFF"
        );
    }

    #[test]
    fn expired_entry_keeps_storm_floor() {
        let mut c = DiffCache::new();
        let addr = [5u8; 20];
        let per_min = RECONNECT_STORM_PER_MIN;
        let window = RECONNECT_STORM_WINDOW.as_millis() as u64;

        let mut now = 1_000u64;
        let mut pinned = None;
        while now < window + 120_000 {
            for _ in 0..(per_min + 1) {
                pinned = c.note_login(&addr, 40_000, now);
                now += 1_000;
            }
            now += 1_000;
        }
        assert_eq!(pinned, Some(40_000), "the storm must have pinned a floor");
        c.record(&addr, 40_000, now);

        let later = now + DIFF_CACHE_TTL.as_millis() as u64 + 1;
        let (start, floor) = c.start_for(&addr, later);
        assert_eq!(start, START_DIFF, "an expired difficulty is a warm-up");
        assert_eq!(
            floor,
            Some(40_000),
            "the storm floor is not a cached difficulty and must survive the TTL"
        );
    }
}
