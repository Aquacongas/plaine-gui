use plaine_consensus::asert::{asert_next_bits, AsertError, Target};
use plaine_consensus::constants::ASERT_ANCHOR_INTERVAL;
use plaine_consensus::rules::{work_from_target, Work};

use crate::types::Hash32;

// Target limbs are little-endian; serialize big-endian so byte-wise hash
// compares order like the number.
pub fn target_to_be(t: &Target) -> Hash32 {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        bytes[8 * i..8 * i + 8].copy_from_slice(&t.0[3 - i].to_be_bytes());
    }
    bytes
}

pub fn expand_bits(bits: u32, pow_limit: &Target) -> Option<Target> {
    let t = Target::from_compact(bits).ok()?;
    if t.is_zero() || t > *pow_limit {
        return None;
    }
    Some(t)
}

#[derive(Clone, Debug)]
pub struct WorkCache {
    slots: [Option<(u32, Work)>; 64],
    hits: u64,
    misses: u64,
}

impl Default for WorkCache {
    fn default() -> Self {
        WorkCache::new()
    }
}

impl WorkCache {
    pub fn new() -> WorkCache {
        WorkCache {
            slots: [None; 64],
            hits: 0,
            misses: 0,
        }
    }

    // Direct-mapped memo on the low 6 bits; a collision recomputes, never lies.
    pub fn work(&mut self, bits: u32, pow_limit: &Target) -> Option<Work> {
        let idx = (bits as usize) & 63;
        if let Some((k, w)) = self.slots[idx] {
            if k == bits {
                self.hits += 1;
                return Some(w);
            }
        }
        self.misses += 1;
        let t = expand_bits(bits, pow_limit)?;
        let w = work_from_target(&target_to_be(&t));
        self.slots[idx] = Some((bits, w));
        Some(w)
    }

    pub fn counters(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

pub fn anchor_height_for(parent_height: u64, interval: u64) -> u64 {
    let interval = if interval == 0 {
        ASERT_ANCHOR_INTERVAL
    } else {
        interval
    };
    (parent_height / interval) * interval
}

pub fn expected_child_bits(
    anchor_bits: u32,
    anchor_height: u64,
    anchor_parent_time: u64,
    parent_height: u64,
    parent_time: u64,
    pow_limit: &Target,
) -> Result<u32, AsertError> {
    asert_next_bits(
        anchor_bits,
        anchor_height,
        anchor_parent_time,
        parent_height,
        parent_time,
        pow_limit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChainParams;

    #[test]
    fn pow_limit_default_is_240_bit() {
        let t = ChainParams::default_pow_limit();
        let be = target_to_be(&t);

        assert_eq!(&be[0..2], &[0x00, 0x00]);
        assert!(be[2..].iter().all(|b| *b == 0xff));
    }

    #[test]
    fn work_memo_matches_direct() {
        let limit = ChainParams::default_pow_limit();
        let mut cache = WorkCache::new();
        let mut state: u32 = 0x1234_5678;
        let mut checked = 0u32;
        for _ in 0..10_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let bits = state;
            let memo = cache.work(bits, &limit);
            let direct = expand_bits(bits, &limit).map(|t| work_from_target(&target_to_be(&t)));
            assert_eq!(memo, direct, "memo disagreed for bits {bits:#010x}");
            if memo.is_some() {
                checked += 1;
            }
        }
        assert!(
            checked > 0,
            "the random sweep produced no legal targets at all"
        );
    }

    #[test]
    fn work_memo_hits_on_repeated_bits() {
        let limit = ChainParams::default_pow_limit();
        let mut cache = WorkCache::new();
        let bits = limit.to_compact();
        for _ in 0..100 {
            assert!(cache.work(bits, &limit).is_some());
        }
        let (hits, misses) = cache.counters();
        assert_eq!(misses, 1);
        assert_eq!(hits, 99);
    }

    #[test]
    fn zero_and_over_limit_rejected() {
        let limit = ChainParams::default_pow_limit();
        assert!(
            expand_bits(0, &limit).is_none(),
            "zero target must not expand"
        );

        assert!(expand_bits(0x1d00_ffff, &limit).is_some());

        assert!(expand_bits(0x2100_ffff, &limit).is_none());
    }

    #[test]
    fn anchor_height_is_interval_floor() {
        assert_eq!(anchor_height_for(0, 8), 0);
        assert_eq!(anchor_height_for(7, 8), 0);
        assert_eq!(anchor_height_for(8, 8), 8);
        assert_eq!(anchor_height_for(15, 8), 8);
        assert_eq!(anchor_height_for(250_000, 100_000), 200_000);
    }
}
