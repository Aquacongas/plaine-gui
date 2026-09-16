use crate::constants::*;
use crate::traits::{Hash32, HeaderRec};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ForkTree {
    by_hash: HashMap<Hash32, HeaderRec>,
    order: Vec<Hash32>,
    tips: Vec<Hash32>,
    pub evictions: u64,
}

impl ForkTree {
    pub fn new() -> ForkTree {
        ForkTree::default()
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn tips(&self) -> usize {
        self.tips.len()
    }

    pub fn insert(&mut self, h: HeaderRec) {
        if self.by_hash.insert(h.hash, h).is_none() {
            self.order.push(h.hash);
            while self.order.len() > FORK_HEADERS_MAX {
                let v = self.order.remove(0);
                self.by_hash.remove(&v);
                self.tips.retain(|t| *t != v);
                self.evictions += 1;
            }
        }

        self.tips.retain(|t| *t != h.prev_hash);
        if !self.tips.contains(&h.hash) {
            self.tips.push(h.hash);
            while self.tips.len() > FORK_TIPS_MAX {
                self.tips.remove(0);
                self.evictions += 1;
            }
        }
    }

    pub fn get(&self, h: &Hash32) -> Option<&HeaderRec> {
        self.by_hash.get(h)
    }

    pub fn forget(&mut self, hash: &Hash32) {
        if self.by_hash.remove(hash).is_none() {
            return;
        }
        self.order.retain(|x| x != hash);
        self.tips.retain(|x| x != hash);
    }

    pub fn truncate_from(&mut self, height: u64) {
        let doomed: Vec<Hash32> = self
            .by_hash
            .iter()
            .filter(|(_, h)| h.height >= height)
            .map(|(k, _)| *k)
            .collect();
        for d in doomed {
            self.by_hash.remove(&d);
            self.order.retain(|x| *x != d);
            self.tips.retain(|x| *x != d);
        }
    }
}
