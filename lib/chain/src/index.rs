use std::collections::HashMap;

use crate::types::{Hash32, HeaderRec, Work};

pub const NO_PARENT: u32 = u32::MAX;

pub const FLAG_POW_OK: u8 = 0b0000_0001;

pub const FLAG_INVALID: u8 = 0b0000_0010;

pub const FLAG_HAVE_BODY: u8 = 0b0000_0100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub hash: Hash32,
    pub prev: u32,
    pub height: u64,
    pub time: u64,
    pub bits: u32,
    pub cum_work: Work,
    pub branch_base_height: u64,
    pub flags: u8,
}

impl Node {
    pub fn pow_ok(&self) -> bool {
        self.flags & FLAG_POW_OK != 0
    }

    pub fn invalid(&self) -> bool {
        self.flags & FLAG_INVALID != 0
    }

    pub fn have_body(&self) -> bool {
        self.flags & FLAG_HAVE_BODY != 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct HeaderIndex {
    nodes: Vec<Node>,
    by_hash: HashMap<Hash32, u32>,
    canonical: Vec<u32>,
}

impl HeaderIndex {
    pub fn new() -> HeaderIndex {
        HeaderIndex::default()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn node(&self, idx: u32) -> &Node {
        &self.nodes[idx as usize]
    }

    pub fn index_of(&self, hash: &Hash32) -> Option<u32> {
        self.by_hash.get(hash).copied()
    }

    pub fn get(&self, hash: &Hash32) -> Option<&Node> {
        self.index_of(hash).map(|i| self.node(i))
    }

    pub fn contains(&self, hash: &Hash32) -> bool {
        self.by_hash.contains_key(hash)
    }

    pub fn tip_index(&self) -> u32 {
        *self.canonical.last().expect("genesis is always canonical")
    }

    pub fn tip(&self) -> &Node {
        self.node(self.tip_index())
    }

    pub fn tip_height(&self) -> u64 {
        self.tip().height
    }

    pub fn canonical_at(&self, height: u64) -> Option<&Node> {
        self.canonical.get(height as usize).map(|i| self.node(*i))
    }

    pub fn is_canonical(&self, idx: u32) -> bool {
        let h = self.node(idx).height as usize;
        self.canonical.get(h) == Some(&idx)
    }

    pub fn insert_genesis(&mut self, rec: &HeaderRec, work: Work) -> u32 {
        assert!(self.nodes.is_empty(), "genesis inserted twice");
        let node = Node {
            hash: rec.hash,
            prev: NO_PARENT,
            height: rec.height,
            time: rec.time,
            bits: rec.bits,
            cum_work: work,
            branch_base_height: rec.height,
            flags: FLAG_POW_OK | FLAG_HAVE_BODY,
        };
        self.nodes.push(node);
        self.by_hash.insert(rec.hash, 0);
        self.canonical.push(0);
        0
    }

    pub fn insert(&mut self, rec: &HeaderRec, parent: u32, cum_work: Work, pow_ok: bool) -> u32 {
        if let Some(existing) = self.index_of(&rec.hash) {
            return existing;
        }
        let p = self.node(parent);
        debug_assert_eq!(rec.height, p.height + 1, "height gate runs before insert");
        // Fork depth is tip_height - branch_base_height, the last canonical height
        // this branch agreed with.
        let branch_base_height =
            if self.is_canonical(parent) { p.height } else { p.branch_base_height };
        let inherited_invalid = p.invalid();
        let idx = self.nodes.len() as u32;
        let mut flags = 0u8;
        if pow_ok {
            flags |= FLAG_POW_OK;
        }
        if inherited_invalid {
            flags |= FLAG_INVALID;
        }
        self.nodes.push(Node {
            hash: rec.hash,
            prev: parent,
            height: rec.height,
            time: rec.time,
            bits: rec.bits,
            cum_work,
            branch_base_height,
            flags,
        });
        self.by_hash.insert(rec.hash, idx);
        idx
    }

    pub fn set_have_body(&mut self, idx: u32) {
        self.nodes[idx as usize].flags |= FLAG_HAVE_BODY;
    }

    pub fn set_invalid_flag(&mut self, idx: u32) {
        debug_assert!(
            self.nodes[idx as usize + 1..].iter().all(|n| n.prev != idx),
            "set_invalid_flag is only sound before this node has children"
        );
        self.nodes[idx as usize].flags |= FLAG_INVALID;
    }

    // NOTE: children are always stored after their parent, so one forward pass
    // poisons every descendant.
    pub fn mark_invalid(&mut self, idx: u32) -> u64 {
        self.nodes[idx as usize].flags |= FLAG_INVALID;
        let mut poisoned = 0u64;
        for i in (idx as usize + 1)..self.nodes.len() {
            let prev = self.nodes[i].prev;
            if prev != NO_PARENT && self.nodes[prev as usize].invalid() && !self.nodes[i].invalid() {
                self.nodes[i].flags |= FLAG_INVALID;
                poisoned += 1;
            }
        }
        poisoned
    }

    pub fn set_canonical(&mut self, chain: &[u32]) {
        self.canonical.clear();
        self.canonical.extend_from_slice(chain);
        // Canonical set changed: recompute every node's fork base in one forward pass.
        for i in 0..self.nodes.len() {
            let prev = self.nodes[i].prev;
            let base = if prev == NO_PARENT {
                self.nodes[i].height
            } else {
                let p = self.nodes[prev as usize];
                if self.canonical.get(p.height as usize) == Some(&prev) {
                    p.height
                } else {
                    p.branch_base_height
                }
            };
            self.nodes[i].branch_base_height = base;
        }
    }

    pub fn canonical_chain(&self) -> Vec<u32> {
        self.canonical.clone()
    }

    pub fn ancestry(&self, idx: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cur = idx;
        loop {
            out.push(cur);
            let prev = self.node(cur).prev;
            if prev == NO_PARENT {
                break;
            }
            cur = prev;
        }
        out.reverse();
        out
    }

    pub fn ancestor_at(&self, idx: u32, height: u64) -> Option<u32> {
        let mut cur = idx;
        loop {
            let n = self.node(cur);
            if n.height == height {
                return Some(cur);
            }
            if n.height < height || n.prev == NO_PARENT {
                return None;
            }
            cur = n.prev;
        }
    }

    pub fn time_window(&self, idx: u32, span: usize) -> Vec<u64> {
        let mut out = Vec::with_capacity(span);
        let mut cur = idx;
        for _ in 0..span {
            let n = self.node(cur);
            out.push(n.time);
            if n.prev == NO_PARENT {
                break;
            }
            cur = n.prev;
        }
        out.reverse();
        out
    }

    pub fn side_count(&self) -> usize {
        self.nodes.len() - self.canonical.len()
    }

    pub fn indices(&self) -> std::ops::Range<u32> {
        0..self.nodes.len() as u32
    }
}
