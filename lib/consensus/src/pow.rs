use crate::blake3;
use crate::constants::{HASH_BYTES, HEADER_BYTES};

pub const DOMAIN_POW_SEED: &[u8] = b"PLNE-pow-seed";

pub const DOMAIN_POW_FINAL: &[u8] = b"PLNE-pow-final";

pub fn seed(header: &[u8; HEADER_BYTES]) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_POW_SEED);
    h.update(header);
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_le_bytes(b)
}

pub fn pow_hash(header: &[u8; HEADER_BYTES], isochron_digest: u64) -> [u8; HASH_BYTES] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_POW_FINAL);
    h.update(header);
    h.update(&isochron_digest.to_le_bytes());
    h.finalize()
}

pub fn meets(pow_hash_be: &[u8; HASH_BYTES], target_be: &[u8; HASH_BYTES]) -> bool {
    pow_hash_be <= target_be
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(nonce: u64) -> [u8; HEADER_BYTES] {
        let mut h = [7u8; HEADER_BYTES];
        h[124..].copy_from_slice(&nonce.to_le_bytes());
        h
    }

    #[test]
    fn the_seed_changes_completely_when_the_nonce_moves_by_one() {
        let a = seed(&hdr(0));
        let b = seed(&hdr(1));
        assert_ne!(a, b);

        let diff = (a ^ b).count_ones();
        assert!((16..=48).contains(&diff), "poor avalanche: {diff} bits differ");
    }

    #[test]
    fn the_finalisation_commits_to_the_header_and_not_only_to_the_digest() {
        let d = 0x0123_4567_89ab_cdefu64;
        assert_ne!(pow_hash(&hdr(0), d), pow_hash(&hdr(1), d));
        assert_ne!(pow_hash(&hdr(0), d), pow_hash(&hdr(0), d ^ 1));
    }

    #[test]
    fn the_two_domains_are_distinct() {
        assert_ne!(DOMAIN_POW_SEED, DOMAIN_POW_FINAL);
    }

    #[test]
    fn meets_is_plain_big_endian_comparison() {
        let mut t = [0u8; 32];
        t[0] = 0x10;
        let mut low = [0u8; 32];
        low[0] = 0x0f;
        let mut high = [0u8; 32];
        high[0] = 0x11;
        assert!(meets(&low, &t));
        assert!(meets(&t, &t));
        assert!(!meets(&high, &t));
    }
}
