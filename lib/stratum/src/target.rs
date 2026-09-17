use plaine_consensus::asert::Target as ConsensusTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target(pub [u8; 32]);

impl Target {
    pub const MAX: Target = Target([0xFF; 32]);

    // both the digest and the target are big-endian, so "hash <= target" is a
    // plain lexicographic byte compare.
    #[inline]
    pub fn accepts(&self, digest_be: &[u8; 32]) -> bool {
        digest_be.as_slice() <= self.0.as_slice()
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            s.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0'));
        }
        s
    }

    pub fn from_compact(bits: u32) -> Option<Target> {
        let t = ConsensusTarget::from_compact(bits).ok()?;

        let mut out = [0u8; 32];
        for (i, limb) in t.0.iter().enumerate() {
            let be = limb.to_be_bytes();
            let start = (3 - i) * 8;
            out[start..start + 8].copy_from_slice(&be);
        }
        Some(Target(out))
    }

    // target = floor(2^256 / d), laid out big-endian. d of 0 or 1 has no useful
    // meaning, so it clamps to the maximum (easiest) target.
    pub fn from_difficulty(d: u64) -> Target {
        if d <= 1 {
            return Target::MAX;
        }
        let dividend: [u64; 5] = [0, 0, 0, 0, 1];
        let mut q = [0u64; 5];
        let mut rem: u64 = 0;
        for i in (0..5).rev() {
            let cur = ((rem as u128) << 64) | dividend[i] as u128;
            q[i] = (cur / d as u128) as u64;
            rem = (cur % d as u128) as u64;
        }
        debug_assert_eq!(q[4], 0, "d >= 2 means the quotient fits in 256 bits");
        let mut out = [0u8; 32];
        for (i, limb) in q.iter().take(4).enumerate() {
            let be = limb.to_be_bytes();
            let start = (3 - i) * 8;
            out[start..start + 8].copy_from_slice(&be);
        }
        Target(out)
    }

    // inverse of from_difficulty by long division of 2^256 by the target. an
    // all-zero target is infinitely hard, reported as the u64 ceiling.
    pub fn to_difficulty(&self) -> u64 {
        if self.0 == [0u8; 32] {
            return u64::MAX;
        }

        let divisor = self.0;
        let mut rem = [0u8; 32];
        let mut q: u64 = 0;

        for bit in (0..=256usize).rev() {
            let carry_in = if bit == 256 { 1u8 } else { 0u8 };
            let mut carry = carry_in;
            for i in (0..32).rev() {
                let v = ((rem[i] as u16) << 1) | carry as u16;
                rem[i] = v as u8;
                carry = (v >> 8) as u8;
            }
            if carry != 0 || rem.as_slice() >= divisor.as_slice() {
                let mut borrow = 0i16;
                for i in (0..32).rev() {
                    let v = rem[i] as i16 - divisor[i] as i16 - borrow;
                    if v < 0 {
                        rem[i] = (v + 256) as u8;
                        borrow = 1;
                    } else {
                        rem[i] = v as u8;
                        borrow = 0;
                    }
                }
                q = match q.checked_mul(2).and_then(|x| x.checked_add(1)) {
                    Some(v) => v,
                    None => return u64::MAX,
                };
            } else {
                q = match q.checked_mul(2) {
                    Some(v) => v,
                    None => return u64::MAX,
                };
            }
        }
        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_diff_target_is_2_pow_243() {
        let t = Target::from_difficulty(8_192);
        let mut want = [0u8; 32];
        want[1] = 0x08;
        assert_eq!(t.0, want);
        assert_eq!(&t.to_hex()[..8], "00080000");
    }

    #[test]
    fn difficulty_round_trips() {
        for d in [2u64, 3, 8_192, 60_000, 1_000_000, 1 << 40, u64::MAX / 2] {
            let t = Target::from_difficulty(d);
            assert_eq!(t.to_difficulty(), d, "round trip failed for d={d}");
        }
    }

    #[test]
    fn one_and_zero_clamp_to_max() {
        assert_eq!(Target::from_difficulty(0), Target::MAX);
        assert_eq!(Target::from_difficulty(1), Target::MAX);
    }

    #[test]
    fn acceptance_is_a_plain_byte_compare() {
        let t = Target::from_difficulty(8_192);
        let mut d = [0u8; 32];
        d[1] = 0x08;
        assert!(t.accepts(&d));
        d[31] = 1;
        assert!(!t.accepts(&d));
        assert!(t.accepts(&[0u8; 32]));
        assert!(!t.accepts(&[0xFFu8; 32]));
    }

    #[test]
    fn no_two_pow_64_trap() {
        let t = Target::from_difficulty(8_192);
        assert_ne!(t.to_difficulty(), 0);
        assert_eq!(t.to_difficulty(), 8_192);
    }

    #[test]
    fn compact_bits_convert() {
        let bits = plaine_consensus::asert::Target::MAX.to_compact();
        assert!(Target::from_compact(bits).is_some());

        let _ = Target::from_compact(0xFFFF_FFFF);
        let _ = Target::from_compact(0);
    }

    #[test]
    fn compact_bits_msb_limb_first() {
        let bits = plaine_consensus::asert::Target::MAX.to_compact();
        let ct = plaine_consensus::asert::Target::from_compact(bits).expect("consensus");
        let t = Target::from_compact(bits).expect("share target");

        assert_eq!(t.0[0..8], ct.0[3].to_be_bytes(), "top limb is not first");
        assert_eq!(
            t.0[24..32],
            ct.0[0].to_be_bytes(),
            "bottom limb is not last"
        );

        assert_ne!(
            ct.0[3], ct.0[0],
            "this constant is limb-palindromic: pick another"
        );
    }

    #[test]
    fn all_zero_target_is_infinite() {
        assert_eq!(Target([0u8; 32]).to_difficulty(), u64::MAX);

        assert_eq!(Target::MAX.to_difficulty(), 1);
    }

    #[test]
    fn hex_is_64_lowercase_chars() {
        let h = Target::from_difficulty(60_000).to_hex();
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
