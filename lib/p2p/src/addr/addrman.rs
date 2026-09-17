use crate::addr::persist::PeerRec;
use crate::constants::*;
use crate::peer::session::group_of;
use crate::traits::Mono;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreStats {
    pub loaded: u64,
    pub filtered: u64,
    pub over_quota: u64,
    pub too_old: u64,
    pub duplicate: u64,
    pub full: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    New,
    Tried,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingest {
    Added,
    Refreshed,
    Filtered,
    OverQuota,
    TableFull,
    TooOld,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrEntry {
    pub ip: [u8; 16],
    pub port: u16,
    pub services: u32,
    pub last_seen: u64,
    pub table: Table,
    pub failures: u32,
    pub protocol_deaths: u32,
    pub from_seed: bool,
    // the /16 group of whoever *told us* about this addr, not the addr's own
    // group; the per-source quota keys on this to stop one peer flooding the book.
    pub source_group: [u8; 4],
    pub foreign_until: Option<Mono>,
    pub last_attempt: Option<Mono>,
}

impl AddrEntry {
    fn new(ip: [u8; 16], port: u16, from_seed: bool) -> AddrEntry {
        AddrEntry {
            ip,
            port,
            services: 0,
            last_seen: 0,
            table: Table::New,
            failures: 0,
            protocol_deaths: 0,
            from_seed,
            source_group: [0u8; 4],
            foreign_until: None,
            last_attempt: None,
        }
    }

    pub fn dialable(&self, now: Mono) -> bool {
        match self.foreign_until {
            Some(t) => now >= t,
            None => true,
        }
    }
}

#[derive(Debug, Default)]
pub struct AddrMan {
    entries: Vec<AddrEntry>,
    index: HashMap<([u8; 16], u16), usize>,
    // per-source-group new counts, so the quota check stays O(1)
    new_by_source: HashMap<[u8; 4], usize>,
    n_new: usize,
    n_tried: usize,
}

impl AddrMan {
    pub fn new() -> AddrMan {
        AddrMan {
            entries: Vec::new(),
            index: HashMap::new(),
            new_by_source: HashMap::new(),
            n_new: 0,
            n_tried: 0,
        }
    }

    fn note_added(&mut self, i: usize) {
        let e = self.entries[i];
        self.index.insert((e.ip, e.port), i);
        match e.table {
            Table::New => {
                self.n_new += 1;
                *self.new_by_source.entry(e.source_group).or_insert(0) += 1;
            }
            Table::Tried => self.n_tried += 1,
        }
    }

    fn note_removed(&mut self, e: &AddrEntry) {
        self.index.remove(&(e.ip, e.port));
        match e.table {
            Table::New => {
                self.n_new = self.n_new.saturating_sub(1);
                if let Some(c) = self.new_by_source.get_mut(&e.source_group) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        self.new_by_source.remove(&e.source_group);
                    }
                }
            }
            Table::Tried => self.n_tried = self.n_tried.saturating_sub(1),
        }
    }

    fn set_table(&mut self, i: usize, t: Table) {
        if self.entries[i].table == t {
            return;
        }
        let sg = self.entries[i].source_group;
        match t {
            Table::Tried => {
                self.n_new = self.n_new.saturating_sub(1);
                if let Some(c) = self.new_by_source.get_mut(&sg) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        self.new_by_source.remove(&sg);
                    }
                }
                self.n_tried += 1;
            }
            Table::New => {
                self.n_tried = self.n_tried.saturating_sub(1);
                self.n_new += 1;
                *self.new_by_source.entry(sg).or_insert(0) += 1;
            }
        }
        self.entries[i].table = t;
    }

    fn remove_at(&mut self, i: usize) {
        let e = self.entries.swap_remove(i);
        self.note_removed(&e);
        if i < self.entries.len() {
            let moved = self.entries[i];
            self.index.insert((moved.ip, moved.port), i);
        }
    }

    fn push(&mut self, e: AddrEntry) {
        self.entries.push(e);
        let i = self.entries.len() - 1;
        self.note_added(i);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn count(&self, t: Table) -> usize {
        match t {
            Table::New => self.n_new,
            Table::Tried => self.n_tried,
        }
    }

    pub fn count_new_from(&self, source_group: [u8; 4]) -> usize {
        self.new_by_source.get(&source_group).copied().unwrap_or(0)
    }

    pub fn get(&self, ip: &[u8; 16], port: u16) -> Option<&AddrEntry> {
        self.index.get(&(*ip, port)).map(|i| &self.entries[*i])
    }

    pub fn add(&mut self, ip: [u8; 16], port: u16, from_seed: bool, last_seen: u64) -> bool {
        if let Some(i) = self.index.get(&(ip, port)).copied() {
            let e = &mut self.entries[i];
            e.last_seen = e.last_seen.max(last_seen);
            e.from_seed |= from_seed;
            return false;
        }
        if self.n_new >= ADDR_NEW_MAX {
            self.evict_one_new();
        }
        let mut e = AddrEntry::new(ip, port, from_seed);
        e.last_seen = last_seen;
        self.push(e);
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_from_peer(
        &mut self,
        ip: [u8; 16],
        port: u16,
        services: u32,
        claimed_seen: u64,
        source_group: [u8; 4],
        now_unix: u64,
        allow_local: bool,
    ) -> Ingest {
        if !crate::addr::routable::admissible(&ip, port, allow_local) {
            return Ingest::Filtered;
        }
        let last_seen = claimed_seen.min(now_unix);
        if now_unix.saturating_sub(last_seen) > ADDR_MAX_AGE_SECS {
            return Ingest::TooOld;
        }
        if let Some(i) = self.index.get(&(ip, port)).copied() {
            let e = &mut self.entries[i];
            e.last_seen = e.last_seen.max(last_seen);
            if e.services == 0 {
                e.services = services;
            }
            return Ingest::Refreshed;
        }
        if self.count_new_from(source_group) >= ADDR_PER_SOURCE_GROUP_MAX {
            return Ingest::OverQuota;
        }
        if self.n_new >= ADDR_NEW_MAX {
            return Ingest::TableFull;
        }
        let mut e = AddrEntry::new(ip, port, false);
        e.last_seen = last_seen;
        e.services = services;
        e.source_group = source_group;
        self.push(e);
        Ingest::Added
    }

    pub fn restore(
        &mut self,
        recs: &[PeerRec],
        now_unix: u64,
        allow_local: bool,
        rng: &mut crate::rng::Rng,
    ) -> RestoreStats {
        let mut st = RestoreStats::default();
        // Shuffle before loading. If the file holds more than the quota, the
        // survivors should be a random subset, not whoever was written first.
        let mut order: Vec<usize> = (0..recs.len()).collect();
        for i in (1..order.len()).rev() {
            let j = rng.below(i as u64 + 1) as usize;
            order.swap(i, j);
        }
        for r in order.into_iter().map(|i| &recs[i]) {
            if !crate::addr::routable::admissible(&r.ip, r.port, allow_local) {
                st.filtered += 1;
                continue;
            }
            let last_seen = r.last_seen.min(now_unix);
            if now_unix.saturating_sub(last_seen) > ADDR_MAX_AGE_SECS {
                st.too_old += 1;
                continue;
            }
            if self.index.contains_key(&(r.ip, r.port)) {
                st.duplicate += 1;
                continue;
            }
            match r.table {
                Table::Tried => {
                    if self.n_tried >= ADDR_TRIED_MAX {
                        st.full += 1;
                        continue;
                    }
                }
                Table::New => {
                    if self.count_new_from(r.source_group) >= ADDR_PER_SOURCE_GROUP_MAX {
                        st.over_quota += 1;
                        continue;
                    }
                    if self.n_new >= ADDR_NEW_MAX {
                        st.full += 1;
                        continue;
                    }
                }
            }
            let mut e = AddrEntry::new(r.ip, r.port, false);
            e.last_seen = last_seen;
            e.services = r.services;
            e.table = r.table;
            e.source_group = r.source_group;
            self.push(e);
            st.loaded += 1;
        }
        st
    }

    pub fn reap_expired(&mut self, now_unix: u64) -> usize {
        let mut gone = 0;
        let mut i = 0;
        while i < self.entries.len() {
            let e = self.entries[i];
            let expired = e.table == Table::New
                && !e.from_seed
                && now_unix.saturating_sub(e.last_seen) > ADDR_MAX_AGE_SECS;
            if expired {
                self.remove_at(i);
                gone += 1;
            } else {
                i += 1;
            }
        }
        gone
    }

    // evict the new-table entry that costs diversity the least: prefer one from
    // a peer-attributed source over an operator/seed one, then the most
    // over-represented source group, then the most crowded address group.
    // FIXME: O(n) over the whole `new` table, and this runs on every insert once
    // it's full. Fine at ADDR_NEW_MAX today; a bucketed heap would make it O(log n).
    fn evict_one_new(&mut self) {
        let mut by_addr_group: HashMap<[u8; 4], usize> = HashMap::new();
        for e in self.entries.iter().filter(|e| e.table == Table::New) {
            *by_addr_group.entry(group_of(&e.ip)).or_insert(0) += 1;
        }
        let mut victim: Option<(usize, (bool, usize, usize))> = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.table != Table::New {
                continue;
            }
            let key = (
                e.source_group != [0u8; 4],
                self.new_by_source
                    .get(&e.source_group)
                    .copied()
                    .unwrap_or(0),
                by_addr_group.get(&group_of(&e.ip)).copied().unwrap_or(0),
            );
            let better = match victim {
                None => true,
                Some((_, best)) => key > best,
            };
            if better {
                victim = Some((i, key));
            }
        }
        if let Some((i, _)) = victim {
            self.remove_at(i);
        }
    }

    pub fn on_handshake_ok(&mut self, ip: &[u8; 16], port: u16, services: u32) {
        let Some(i) = self.index.get(&(*ip, port)).copied() else {
            return;
        };
        self.set_table(i, Table::Tried);
        self.entries[i].failures = 0;
        self.entries[i].services = services;
        self.enforce_tried_cap();
    }

    // Over the tried cap: demote the least-recently-attempted entry back to new
    // rather than deleting it, so a good address survives for a later feeler.
    fn enforce_tried_cap(&mut self) {
        while self.n_tried > ADDR_TRIED_MAX {
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.table == Table::Tried)
                .min_by_key(|(_, e)| e.last_attempt.unwrap_or(Mono::ZERO))
                .map(|(i, _)| i);
            match oldest {
                Some(i) => {
                    self.set_table(i, Table::New);
                    self.entries[i].failures = 0;
                }
                None => break,
            }
        }
    }

    pub fn on_failure(&mut self, ip: &[u8; 16], port: u16, protocol: bool) -> bool {
        let Some(i) = self.index.get(&(*ip, port)).copied() else {
            return false;
        };
        {
            let e = &mut self.entries[i];
            e.failures = e.failures.saturating_add(1);
            if protocol {
                e.protocol_deaths = e.protocol_deaths.saturating_add(1);
            }
        }
        let e = self.entries[i];
        let demote = e.table == Table::Tried
            && (e.failures >= DEMOTE_AFTER_FAILURES
                || e.protocol_deaths >= DEMOTE_AFTER_PROTOCOL_DEATHS);
        if demote {
            self.set_table(i, Table::New);
            self.entries[i].failures = 0;
            self.entries[i].protocol_deaths = 0;
        }
        demote
    }

    pub fn mark_foreign(&mut self, ip: &[u8; 16], port: u16, now: Mono) {
        if let Some(i) = self.index.get(&(*ip, port)).copied() {
            self.entries[i].foreign_until = Some(now.plus_ms(FOREIGN_NETWORK_MS));
        }
    }

    pub fn seeds_still_privileged(&self) -> bool {
        self.entries.len() < SEED_DEMOTION_ADDR_COUNT
    }

    pub fn select_dial(
        &self,
        want: usize,
        connected: &[([u8; 16], u16)],
        now: Mono,
        widen: bool,
    ) -> Vec<([u8; 16], u16)> {
        self.select_dial_filtered(want, connected, now, widen, true)
    }

    pub fn select_dial_filtered(
        &self,
        want: usize,
        connected: &[([u8; 16], u16)],
        now: Mono,
        widen: bool,
        allow_local: bool,
    ) -> Vec<([u8; 16], u16)> {
        let cap = if widen {
            want.min(COLDSTART_DIAL_CONCURRENT)
        } else {
            want
        };
        let per_group = if widen {
            OUTBOUND_PER_GROUP_WIDENED
        } else {
            OUTBOUND_PER_GROUP
        };
        let mut used: Vec<[u8; 4]> = connected.iter().map(|(ip, _)| group_of(ip)).collect();
        let mut out: Vec<([u8; 16], u16)> = Vec::new();

        // tried first: prefer addresses we have actually reached before falling
        // back to unproven ones, and cap dials per group for network diversity.
        for want_table in [Table::Tried, Table::New] {
            for e in self.entries.iter().filter(|e| e.table == want_table) {
                if out.len() >= cap {
                    return out;
                }
                if !e.dialable(now) {
                    continue;
                }
                if !e.from_seed && !crate::addr::routable::admissible(&e.ip, e.port, allow_local) {
                    continue;
                }
                if connected.iter().any(|(ip, p)| *ip == e.ip && *p == e.port) {
                    continue;
                }
                if let Some(t) = e.last_attempt {
                    if !now.expired(t, DIAL_RETRY_MS) {
                        continue;
                    }
                }
                let g = group_of(&e.ip);
                if used.iter().filter(|x| **x == g).count() >= per_group {
                    continue;
                }
                used.push(g);
                out.push((e.ip, e.port));
            }
        }
        out
    }

    pub fn select_feeler(&self, now: Mono) -> Option<([u8; 16], u16)> {
        self.entries
            .iter()
            .filter(|e| e.table == Table::New && e.dialable(now))
            .min_by_key(|e| e.last_attempt.unwrap_or(Mono::ZERO))
            .map(|e| (e.ip, e.port))
    }

    pub fn note_attempt(&mut self, ip: &[u8; 16], port: u16, now: Mono) {
        if let Some(i) = self.index.get(&(*ip, port)).copied() {
            self.entries[i].last_attempt = Some(now);
        }
    }

    pub fn sample(
        &self,
        max: usize,
        now_unix: u64,
        rng: &mut crate::rng::Rng,
        allow_local: bool,
    ) -> Vec<AddrEntry> {
        let want = max.min(ADDR_MSG_MAX);
        let n = self.entries.len();
        if n == 0 || want == 0 {
            return Vec::new();
        }
        let probes = n.min(ADDR_SAMPLE_PROBES);
        // walk from a random start in coprime steps: touches distinct entries in
        // pseudo-random order without allocating and shuffling the whole table.
        let mut idx = rng.below(n as u64) as usize;
        let stride = coprime_stride(n, rng);
        let mut out: Vec<AddrEntry> = Vec::with_capacity(want.min(probes));
        for _ in 0..probes {
            let e = self.entries[idx];
            idx = (idx + stride) % n;
            if e.foreign_until.is_some() {
                continue;
            }
            if now_unix.saturating_sub(e.last_seen) > ADDR_MAX_AGE_SECS {
                continue;
            }
            if !crate::addr::routable::admissible(&e.ip, e.port, allow_local) {
                continue;
            }
            out.push(e);
            if out.len() >= want {
                break;
            }
        }
        out
    }

    pub fn entries(&self) -> &[AddrEntry] {
        &self.entries
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
        self.new_by_source.clear();
        self.n_new = 0;
        self.n_tried = 0;
    }

    pub fn counters_consistent(&self) -> bool {
        let n_new = self
            .entries
            .iter()
            .filter(|e| e.table == Table::New)
            .count();
        let n_tried = self
            .entries
            .iter()
            .filter(|e| e.table == Table::Tried)
            .count();
        if n_new != self.n_new || n_tried != self.n_tried {
            return false;
        }
        if self.index.len() != self.entries.len() {
            return false;
        }
        for (i, e) in self.entries.iter().enumerate() {
            if self.index.get(&(e.ip, e.port)) != Some(&i) {
                return false;
            }
        }
        let mut by_src: HashMap<[u8; 4], usize> = HashMap::new();
        for e in self.entries.iter().filter(|e| e.table == Table::New) {
            *by_src.entry(e.source_group).or_insert(0) += 1;
        }
        by_src == self.new_by_source
    }
}

fn coprime_stride(n: usize, rng: &mut crate::rng::Rng) -> usize {
    if n <= 2 {
        return 1;
    }
    let mut s = 1 + rng.below(n as u64 - 1) as usize;
    for _ in 0..n {
        if gcd(s, n) == 1 {
            return s;
        }
        s += 1;
        if s >= n {
            s = 1;
        }
    }
    1
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}
