use crate::constants::*;
use crate::traits::Mono;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct BanList {
    // keyed by 16-byte address (v4 sits in the v6-mapped range).
    entries: HashMap<[u8; 16], Entry>,
    // insertion order, used to evict the oldest ban when the list is full.
    order: Vec<[u8; 16]>,
    whitelist: Vec<[u8; 16]>,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    until: Mono,
}

impl BanList {
    pub fn new(whitelist: Vec<[u8; 16]>) -> BanList {
        BanList {
            entries: HashMap::new(),
            order: Vec::new(),
            whitelist,
        }
    }

    pub fn ban(&mut self, ip: [u8; 16], now: Mono, dur_ms: u64) {
        if self.whitelist.contains(&ip) {
            return;
        }
        let until = now.plus_ms(dur_ms);
        if self.entries.insert(ip, Entry { until }).is_none() {
            self.order.push(ip);

            // Bounded memory beats perfect enforcement: past the cap, drop the
            // oldest ban even if it hasn't expired.
            if self.order.len() > BANLIST_MAX {
                let victim = self.order.remove(0);
                self.entries.remove(&victim);
            }
        }
    }

    pub fn is_banned(&self, ip: &[u8; 16], now: Mono) -> bool {
        match self.entries.get(ip) {
            Some(e) => e.until > now,
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn sweep(&mut self, now: Mono) {
        self.entries.retain(|_, e| e.until > now);
        let live = &self.entries;
        self.order.retain(|ip| live.contains_key(ip));
    }
}
