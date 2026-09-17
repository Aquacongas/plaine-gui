use crate::constants::{HASH_BYTES, MERKLE_MAX_DEPTH, TX_ROOT_EMPTY};
use crate::crypto;

pub type Hash32 = [u8; HASH_BYTES];

pub fn leaf_hash(tx_bytes: &[u8]) -> Hash32 {
    crypto::merkle_leaf(tx_bytes)
}

pub fn node_hash(left: &Hash32, right: &Hash32, duplicated: bool) -> Hash32 {
    crypto::merkle_node(left, right, duplicated)
}

pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return TX_ROOT_EMPTY;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(node_hash(&level[i], &level[i + 1], false));
            i += 2;
        }
        if i < level.len() {
            // Odd leaf out: self-pair under the dup flag, never confused with a
            // real pair (CVE-2012-2459).
            next.push(node_hash(&level[i], &level[i], true));
        }
        level = next;
    }
    level[0]
}

pub fn tx_root(txs: &[&[u8]]) -> Hash32 {
    let leaves: Vec<Hash32> = txs.iter().map(|t| leaf_hash(t)).collect();
    merkle_root(&leaves)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub index: u32,
    pub tx_count: u32,
    pub siblings: Vec<Hash32>,
}

pub fn merkle_proof(leaves: &[Hash32], index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || index >= leaves.len() || leaves.len() > u32::MAX as usize {
        return None;
    }
    let tx_count = leaves.len();
    let mut siblings = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let is_odd_last = idx == level.len() - 1 && level.len() % 2 == 1;
        if !is_odd_last {
            let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            siblings.push(level[sib]);
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(node_hash(&level[i], &level[i + 1], false));
            i += 2;
        }
        if i < level.len() {
            next.push(node_hash(&level[i], &level[i], true));
        }
        level = next;
        idx /= 2;
    }
    Some(MerkleProof {
        index: index as u32,
        tx_count: tx_count as u32,
        siblings,
    })
}

pub fn verify_merkle_proof(leaf: &Hash32, proof: &MerkleProof, root: &Hash32) -> bool {
    // NOTE: tx_count is a shape hint, not authenticated. A wrong count just
    // fails the hash comparison against the real root; it cannot forge
    // membership. See proof_shape_hint_is_not_authenticated in the tests.
    if proof.tx_count == 0 || proof.index >= proof.tx_count {
        return false;
    }
    if proof.siblings.len() > MERKLE_MAX_DEPTH {
        return false;
    }
    let mut h = *leaf;
    let mut idx = proof.index as u64;
    let mut width = proof.tx_count as u64;
    let mut used = 0usize;
    while width > 1 {
        if idx == width - 1 && width % 2 == 1 {
            h = node_hash(&h, &h, true);
        } else {
            let Some(sib) = proof.siblings.get(used) else {
                return false;
            };
            used += 1;
            h = if idx % 2 == 0 {
                node_hash(&h, sib, false)
            } else {
                node_hash(sib, &h, false)
            };
        }
        idx /= 2;
        width = width.div_ceil(2);
    }
    // reject a proof padded with extra siblings: every one must have been used
    used == proof.siblings.len() && h == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_TXS_PER_BLOCK;

    fn leaves(n: usize) -> Vec<Hash32> {
        (0..n).map(|i| leaf_hash(&[i as u8; 7])).collect()
    }

    #[test]
    fn cve_2012_2459_dup_changes_root() {
        let honest = leaves(3);
        let mut forged = honest.clone();
        forged.push(honest[2]);
        assert_ne!(
            merkle_root(&honest),
            merkle_root(&forged),
            "[A,B,C] and [A,B,C,C] must not share a root"
        );

        for n in 1..=9usize {
            let l = leaves(n);
            let mut dup = l.clone();
            dup.push(l[n - 1]);
            assert_ne!(merkle_root(&l), merkle_root(&dup), "n = {n}");
        }
    }

    #[test]
    fn distinct_lists_never_share_a_root() {
        use std::collections::HashMap;
        let alphabet: Vec<Hash32> = (0..4u8).map(|i| leaf_hash(&[i])).collect();
        let mut seen: HashMap<Hash32, Vec<Hash32>> = HashMap::new();

        let mut state = 0x243F_6A88_85A3_08D3u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..500 {
            let n = (next() % 32 + 1) as usize;
            let list: Vec<Hash32> = (0..n).map(|_| alphabet[(next() % 4) as usize]).collect();
            let root = merkle_root(&list);
            if let Some(prev) = seen.get(&root) {
                assert_eq!(prev, &list, "two distinct lists share a root");
            } else {
                seen.insert(root, list);
            }
        }
    }

    #[test]
    fn shape_rules_single_empty_and_flag() {
        let l = leaves(1);
        assert_eq!(merkle_root(&l), l[0], "n=1 root is the leaf hash itself");
        assert_ne!(merkle_root(&l), node_hash(&l[0], &l[0], true));
        assert_ne!(merkle_root(&l), node_hash(&l[0], &l[0], false));
        assert_eq!(merkle_root(&[]), TX_ROOT_EMPTY);
        let (a, b) = (leaf_hash(b"a"), leaf_hash(b"b"));
        assert_ne!(
            node_hash(&a, &b, false),
            node_hash(&a, &b, true),
            "the flag is in the preimage"
        );
        assert_ne!(
            node_hash(&a, &b, false),
            node_hash(&b, &a, false),
            "order matters"
        );
    }

    #[test]
    fn cross_domain_node_substitution_fails() {
        let (a, b) = (leaf_hash(b"a"), leaf_hash(b"b"));
        let node = node_hash(&a, &b, false);
        let mut sixty_four = Vec::with_capacity(64);
        sixty_four.extend_from_slice(&a);
        sixty_four.extend_from_slice(&b);
        assert_ne!(leaf_hash(&sixty_four), node);

        let mut sixty_five = vec![0u8];
        sixty_five.extend_from_slice(&a);
        sixty_five.extend_from_slice(&b);
        assert_ne!(leaf_hash(&sixty_five), node);
    }

    #[test]
    fn pinned_preimages() {
        let mut leaf_pre = b"PLNE-leaf".to_vec();
        leaf_pre.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(leaf_hash(&[0xAA, 0xBB]), crate::blake3::hash(&leaf_pre));

        let (a, b) = (leaf_hash(&[0x01]), leaf_hash(&[0x02]));
        let mut node_pre = b"PLNE-node".to_vec();
        node_pre.push(0x00);
        node_pre.extend_from_slice(&a);
        node_pre.extend_from_slice(&b);
        assert_eq!(node_hash(&a, &b, false), crate::blake3::hash(&node_pre));
        let mut dup_pre = b"PLNE-node".to_vec();
        dup_pre.push(0x01);
        dup_pre.extend_from_slice(&a);
        dup_pre.extend_from_slice(&a);
        assert_eq!(node_hash(&a, &a, true), crate::blake3::hash(&dup_pre));
    }

    fn reference_root(level: &[Hash32]) -> Hash32 {
        if level.is_empty() {
            return TX_ROOT_EMPTY;
        }
        if level.len() == 1 {
            return level[0];
        }
        let mut next = Vec::new();
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(node_hash(&level[i], &level[i + 1], false));
            i += 2;
        }
        if i < level.len() {
            next.push(node_hash(&level[i], &level[i], true));
        }
        reference_root(&next)
    }

    #[test]
    fn pinned_root_hexes() {
        const PINNED: [(usize, &str); 6] = [
            (
                1,
                "14b10741e82e6e9bd48e6cccc3bdff302ba435ebabf418ca8e85a581e4d4023e",
            ),
            (
                2,
                "3a126089dc41e2b9fdac3f1a49775be90fa1fad7cfa8d89275c1284c70a7d00d",
            ),
            (
                3,
                "d243a4fb442dbd714ce2b797675c978b879f0c3e9272c5380a0bd8ec53584273",
            ),
            (
                4,
                "5f07ff69927801655a9cc2135c1106394b27b623f0079a2c1a90256e0aea3773",
            ),
            (
                5,
                "7fc09a1e6dba594292987513e287415d8949059065c626fdf70fd06ba6b30a77",
            ),
            (
                8,
                "2a12919f34a969a8509a45ce37246fdf006b03d57f63c12be0478b91e36118da",
            ),
        ];
        for (n, want) in PINNED {
            let l = leaves(n);
            let got = crate::hex::encode(&merkle_root(&l));
            assert_eq!(got, crate::hex::encode(&reference_root(&l)), "n = {n}");
            assert_eq!(got, want, "n = {n}");
        }

        assert_eq!(crate::hex::encode(&leaf_hash(&[0u8; 7])), PINNED[0].1);
    }

    #[test]
    fn proofs_verify_for_every_index() {
        for n in 1..=17usize {
            let l = leaves(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let p = merkle_proof(&l, i).expect("in range");
                assert!(verify_merkle_proof(&l[i], &p, &root), "n = {n}, i = {i}");
            }
        }
        assert!(merkle_proof(&[], 0).is_none());
        assert!(merkle_proof(&leaves(3), 3).is_none());
    }

    #[test]
    fn tampered_proofs_are_rejected() {
        let n = 11;
        let l = leaves(n);
        let root = merkle_root(&l);
        let base = merkle_proof(&l, 5).unwrap();
        assert!(verify_merkle_proof(&l[5], &base, &root));

        let mut p = base.clone();
        p.index = 4;
        assert!(!verify_merkle_proof(&l[5], &p, &root));

        let mut p = base.clone();
        p.index = n as u32;
        assert!(!verify_merkle_proof(&l[5], &p, &root));

        let mut p = base.clone();
        p.siblings[0][0] ^= 0x01;
        assert!(!verify_merkle_proof(&l[5], &p, &root));

        let mut p = base.clone();
        p.siblings.pop();
        assert!(!verify_merkle_proof(&l[5], &p, &root));

        let mut p = base.clone();
        p.siblings.push([0xAA; 32]);
        assert!(!verify_merkle_proof(&l[5], &p, &root));

        assert!(!verify_merkle_proof(&l[6], &base, &root));

        let mut p = base.clone();
        p.tx_count = 0;
        assert!(!verify_merkle_proof(&l[5], &p, &root));

        let p = MerkleProof {
            index: 0,
            tx_count: 2,
            siblings: vec![[0u8; 32]; 13],
        };
        assert!(!verify_merkle_proof(&l[0], &p, &root));
    }

    #[test]
    fn proof_shape_hint_is_not_authenticated() {
        let l3 = leaves(3);
        let root3 = merkle_root(&l3);
        let honest = merkle_proof(&l3, 0).unwrap();
        assert_eq!(honest.tx_count, 3);
        assert!(verify_merkle_proof(&l3[0], &honest, &root3));

        let lying = MerkleProof {
            index: 0,
            tx_count: 4,
            siblings: honest.siblings.clone(),
        };
        assert!(
            verify_merkle_proof(&l3[0], &lying, &root3),
            "documented limitation: tx_count is a shape hint, not authenticated data"
        );

        assert!(!verify_merkle_proof(
            &leaf_hash(b"not in the tree"),
            &lying,
            &root3
        ));
    }

    #[test]
    fn full_block_is_depth_twelve() {
        let l = leaves(MAX_TXS_PER_BLOCK.min(4096));

        let mut levels = 0;
        let mut w = l.len();
        while w > 1 {
            w = w.div_ceil(2);
            levels += 1;
        }
        assert_eq!(levels, MERKLE_MAX_DEPTH, "4096 leaves is exactly 12 levels");
        let root = merkle_root(&l);
        assert_ne!(root, TX_ROOT_EMPTY);
        let p = merkle_proof(&l, 4095).unwrap();
        assert!(p.siblings.len() <= MERKLE_MAX_DEPTH);
        assert!(verify_merkle_proof(&l[4095], &p, &root));
    }
}
