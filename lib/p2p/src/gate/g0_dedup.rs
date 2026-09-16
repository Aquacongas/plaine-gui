use crate::constants::REJECT_CACHE_MAX;
use crate::traits::Hash32;
use std::collections::HashMap;

pub use crate::sync::recovery::AuditPass;

#[derive(Debug, Default)]
pub struct RejectCache {
    map: HashMap<Hash32, u64>,
    order: Vec<Hash32>,
    tick: u64,
    pub evictions: u64,
}

impl RejectCache {
    pub fn new() -> RejectCache {
        RejectCache::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn insert(&mut self, h: Hash32) {
        self.tick += 1;
        if self.map.insert(h, self.tick).is_none() {
            self.order.push(h);
            if self.order.len() > REJECT_CACHE_MAX {
                let victim = self.order.remove(0);
                self.map.remove(&victim);
                self.evictions += 1;
            }
        }
    }

    pub fn contains(&self, h: &Hash32) -> bool {
        self.map.contains_key(h)
    }

    pub fn audit_clear(&mut self, _pass: &AuditPass) {
        self.map.clear();
        self.order.clear();
    }
}
