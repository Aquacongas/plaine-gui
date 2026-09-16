use crate::constants::{ASERT_HALF_LIFE_SECS, ASERT_TARGET_SPACING_SECS};

pub const POW_LIMIT: Target = Target(crate::constants::POW_LIMIT_LIMBS);

const RADIX_BITS: u32 = 16;
const RADIX: i128 = 1 << RADIX_BITS;

// Cubic fit to 2^x on [0,1) in 48-bit fixed point: the aserti3-2d coefficients,
// verbatim from Bitcoin Cash. Not ours to retune.
const CUBE_C1: u128 = 195_766_423_245_049;
const CUBE_C2: u128 = 971_821_376;
const CUBE_C3: u128 = 5_127;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct Target(pub [u64; 4]);

impl Target {
    pub const ZERO: Target = Target([0; 4]);

    pub const ONE: Target = Target([1, 0, 0, 0]);
    pub const MAX: Target = Target([u64::MAX; 4]);

    pub const fn from_u64(v: u64) -> Target {
        Target([v, 0, 0, 0])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    pub const fn low_u64(&self) -> u64 {
        self.0[0]
    }

    pub const fn bit_len(&self) -> u32 {
        let mut i = 4usize;
        while i > 0 {
            i -= 1;
            if self.0[i] != 0 {
                return (i as u32) * 64 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    fn shl(&self, n: u32) -> Target {
        debug_assert!(n < 256);
        let limb = (n / 64) as usize;
        let bit = n % 64;
        let mut out = [0u64; 4];
        for i in (0..4).rev() {
            if i >= limb {
                let src = i - limb;
                let mut x = self.0[src] << bit;
                if bit > 0 && src > 0 {
                    x |= self.0[src - 1] >> (64 - bit);
                }
                out[i] = x;
            }
        }
        Target(out)
    }

    const fn shr(&self, n: u32) -> Target {
        if n >= 256 {
            return Target::ZERO;
        }
        let limb = (n / 64) as usize;
        let bit = n % 64;
        let mut out = [0u64; 4];
        let mut i = 0usize;
        while i < 4 {
            let src = i + limb;
            if src < 4 {
                let mut x = self.0[src] >> bit;
                if bit > 0 && src + 1 < 4 {
                    x |= self.0[src + 1] << (64 - bit);
                }
                out[i] = x;
            }
            i += 1;
        }
        Target(out)
    }

    pub fn from_be_hex(s: &str) -> Result<Target, AsertError> {
        let bytes = crate::hex::decode(s).map_err(|_| AsertError::BadHex)?;
        if bytes.len() != 32 {
            return Err(AsertError::BadHex);
        }
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            limbs[3 - i] = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        }
        Ok(Target(limbs))
    }

    pub fn to_be_hex(&self) -> String {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[8 * i..8 * i + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        crate::hex::encode(&bytes)
    }

    pub fn from_compact(bits: u32) -> Result<Target, AsertError> {
        let size = bits >> 24;
        let word = (bits & 0x007f_ffff) as u64;
        if word != 0 && (bits & 0x0080_0000) != 0 {
            return Err(AsertError::NegativeCompact);
        }
        if word == 0 {
            return Ok(Target::ZERO);
        }
        if size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32) {
            return Err(AsertError::OverflowCompact);
        }
        let target = if size <= 3 {
            Target::from_u64(word >> (8 * (3 - size)))
        } else {
            Target::from_u64(word).shl(8 * (size - 3))
        };
        Ok(target)
    }

    pub const fn to_compact(&self) -> u32 {
        let mut size = self.bit_len().div_ceil(8);
        let mut compact: u64 = if size <= 3 {
            self.low_u64() << (8 * (3 - size))
        } else {
            self.shr(8 * (size - 3)).low_u64()
        };

        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        debug_assert!(compact & !0x007f_ffff == 0);
        (compact as u32) | (size << 24)
    }
}

impl PartialOrd for Target {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Target {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        core::cmp::Ordering::Equal
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AsertError {
    NegativeCompact,
    OverflowCompact,
    ParentBelowAnchor,
    BadHex,
}

impl core::fmt::Display for AsertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            AsertError::NegativeCompact => "compact bits encode a negative target",
            AsertError::OverflowCompact => "compact bits overflow 256 bits",
            AsertError::ParentBelowAnchor => "parent height below anchor height",
            AsertError::BadHex => "target hex must be exactly 64 hex digits",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AsertError {}

pub fn asert_next_target_from_ref(
    ref_target: &Target,
    height_diff: u64,
    time_diff: i128,
    pow_limit: &Target,
) -> Target {
    let ideal: i128 =
        (ASERT_TARGET_SPACING_SECS as i128) * (height_diff as i128 + 1);

    // Truncating division, matching the BCH C++ int64 `/`. div_euclid and floor
    // disagree with it on negative exponents; either one forks the chain.
    let exponent: i128 =
        ((time_diff - ideal) * RADIX) / (ASERT_HALF_LIFE_SECS as i128);

    // Only the final target is clamped, never the exponent. Split it into whole
    // shifts (arithmetic >> is floor) and a non-negative 16-bit fraction.
    let mut shifts: i128 = exponent >> RADIX_BITS;
    let frac: u64 = (exponent & 0xffff) as u64;
    debug_assert_eq!(shifts * RADIX + frac as i128, exponent);

    let f = frac as u128;
    let factor: u64 = (RADIX as u64)
        + (((CUBE_C1 * f + CUBE_C2 * f * f + CUBE_C3 * f * f * f + (1u128 << 47))
            >> 48) as u64);

    // 320-bit intermediate: an overshoot clamps high, never wraps to an easy target.
    let mut wide = mul_256_by_64(ref_target, factor);
    shifts -= RADIX_BITS as i128;
    if shifts <= 0 {
        let n = (-shifts).min(320) as u32;
        wide = shr_320(&wide, n);
    } else {
        let bl = bit_len_320(&wide) as i128;
        if bl != 0 {
            if bl + shifts > 256 {
                return *pow_limit;
            }
            wide = shl_320(&wide, shifts as u32);
        }
    }
    if wide[4] != 0 {
        return *pow_limit;
    }
    let next = Target([wide[0], wide[1], wide[2], wide[3]]);
    if next.is_zero() {
        return Target::ONE;
    }
    if next > *pow_limit {
        return *pow_limit;
    }
    next
}

pub fn asert_next_target(
    anchor_bits: u32,
    anchor_height: u64,
    anchor_parent_time: u64,
    parent_height: u64,
    parent_time: u64,
    pow_limit: &Target,
) -> Result<Target, AsertError> {
    if parent_height < anchor_height {
        return Err(AsertError::ParentBelowAnchor);
    }
    let ref_target = Target::from_compact(anchor_bits)?;
    let height_diff = parent_height - anchor_height;
    let time_diff = parent_time as i128 - anchor_parent_time as i128;
    Ok(asert_next_target_from_ref(
        &ref_target,
        height_diff,
        time_diff,
        pow_limit,
    ))
}

pub fn asert_next_bits(
    anchor_bits: u32,
    anchor_height: u64,
    anchor_parent_time: u64,
    parent_height: u64,
    parent_time: u64,
    pow_limit: &Target,
) -> Result<u32, AsertError> {
    Ok(asert_next_target(
        anchor_bits,
        anchor_height,
        anchor_parent_time,
        parent_height,
        parent_time,
        pow_limit,
    )?
    .to_compact())
}

fn mul_256_by_64(a: &Target, b: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for (slot, limb) in out.iter_mut().zip(a.0.iter()) {
        let p = (*limb as u128) * (b as u128) + carry;
        *slot = p as u64;
        carry = p >> 64;
    }
    out[4] = carry as u64;
    out
}

fn bit_len_320(v: &[u64; 5]) -> u32 {
    for i in (0..5).rev() {
        if v[i] != 0 {
            return (i as u32) * 64 + (64 - v[i].leading_zeros());
        }
    }
    0
}

fn shr_320(v: &[u64; 5], n: u32) -> [u64; 5] {
    if n >= 320 {
        return [0; 5];
    }
    let limb = (n / 64) as usize;
    let bit = n % 64;
    let mut out = [0u64; 5];
    for (i, slot) in out.iter_mut().enumerate() {
        let src = i + limb;
        if src < 5 {
            let mut x = v[src] >> bit;
            if bit > 0 && src + 1 < 5 {
                x |= v[src + 1] << (64 - bit);
            }
            *slot = x;
        }
    }
    out
}

fn shl_320(v: &[u64; 5], n: u32) -> [u64; 5] {
    debug_assert!(n < 320);
    let limb = (n / 64) as usize;
    let bit = n % 64;
    let mut out = [0u64; 5];
    for i in (0..5).rev() {
        if i >= limb {
            let src = i - limb;
            let mut x = v[src] << bit;
            if bit > 0 && src > 0 {
                x |= v[src - 1] >> (64 - bit);
            }
            out[i] = x;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::GENESIS_BITS;

    #[test]
    fn pow_limit_is_2_240_minus_1() {
        let expected = format!("{}{}", "0000", "f".repeat(60));
        assert_eq!(POW_LIMIT.to_be_hex(), expected);
        assert_eq!(POW_LIMIT.bit_len(), 240);

        assert_eq!(POW_LIMIT.0[0], u64::MAX);
        assert_eq!(POW_LIMIT.0[1], u64::MAX);
        assert_eq!(POW_LIMIT.0[2], u64::MAX);
        assert_eq!(POW_LIMIT.0[3], (1u64 << 48) - 1);
    }

    #[test]
    fn genesis_bits_is_compact_pow_limit() {
        assert_eq!(POW_LIMIT.to_compact(), GENESIS_BITS);
        assert_eq!(GENESIS_BITS, 0x1F00_FFFF);
    }

    #[test]
    fn genesis_bits_round_trip_exact() {
        let t = Target::from_compact(GENESIS_BITS).unwrap();
        assert_eq!(t.to_compact(), GENESIS_BITS);
        assert_eq!(Target::from_compact(t.to_compact()).unwrap(), t);

        assert_eq!(
            Target::from_compact(Target::from_compact(GENESIS_BITS).unwrap().to_compact()).unwrap(),
            t
        );
    }

    #[test]
    fn genesis_bits_decode_greatest_below_limit() {
        let t = Target::from_compact(GENESIS_BITS).unwrap();

        assert_eq!(t.to_be_hex(), format!("0000ffff{}", "0".repeat(56)));
        assert_eq!(t.0, [0, 0, 0, 0x0000_FFFF_0000_0000]);
        assert_eq!(t.bit_len(), 240);

        assert!(t <= POW_LIMIT);
        assert!(t < POW_LIMIT, "not equal: 2^240-1 has no compact encoding");

        let two224_minus_1 = Target([u64::MAX, u64::MAX, u64::MAX, (1u64 << 32) - 1]);
        assert_eq!(two224_minus_1.bit_len(), 224);
        let mut sum = [0u64; 4];
        let mut carry = 0u128;
        for (i, slot) in sum.iter_mut().enumerate() {
            let s = t.0[i] as u128 + two224_minus_1.0[i] as u128 + carry;
            *slot = s as u64;
            carry = s >> 64;
        }
        assert_eq!(carry, 0);
        assert_eq!(
            Target(sum),
            POW_LIMIT,
            "genesis target + (2^224 - 1) must be exactly POW_LIMIT"
        );
    }

    #[test]
    fn genesis_bits_maximal_at_or_below_limit() {
        let genesis = Target::from_compact(GENESIS_BITS).unwrap();
        let mut best: Option<(u32, Target)> = None;

        for size in 0u32..=34 {
            for mantissa in [0x7f_ffffu32, 0x00_ffff, 0x00_00ff, 0x00_0001] {
                let bits = (size << 24) | mantissa;
                let Ok(t) = Target::from_compact(bits) else {
                    continue;
                };
                if t.is_zero() || t > POW_LIMIT {
                    continue;
                }
                assert!(
                    t <= genesis,
                    "compact {bits:#010x} decodes to {} which is above the genesis \
                     target {} yet at or below POW_LIMIT - 0x1F00FFFF would not be maximal",
                    t.to_be_hex(),
                    genesis.to_be_hex()
                );
                if best.map(|(_, b)| t > b).unwrap_or(true) {
                    best = Some((bits, t));
                }
            }
        }
        let (bits, t) = best.expect("some representable target is <= POW_LIMIT");
        assert_eq!(t, genesis);
        assert_eq!(bits, GENESIS_BITS);
    }

    #[test]
    fn compact_never_rounds_up() {
        let mut targets = vec![
            POW_LIMIT,
            Target::from_compact(GENESIS_BITS).unwrap(),
            Target::ONE,
            Target::from_u64(1),
            Target::from_u64(u64::MAX),
            Target::from_be_hex(T0_HEX).unwrap(),
        ];

        for n in [1u32, 7, 8, 63, 64, 100, 200, 239] {
            targets.push(POW_LIMIT.shr(n));
        }
        for t in targets {
            if t.is_zero() {
                continue;
            }
            assert!(t <= POW_LIMIT, "test input must be inside the clamp range");
            let back = Target::from_compact(t.to_compact()).unwrap();
            assert!(back <= t, "re-encoding {} rounded up to {}", t.to_be_hex(), back.to_be_hex());
            assert!(back <= POW_LIMIT);
        }
    }

    #[test]
    fn clamp_uses_real_pow_limit() {
        assert_eq!(
            asert_next_target_from_ref(&POW_LIMIT, 100, 9660, &POW_LIMIT),
            POW_LIMIT
        );

        assert_eq!(
            asert_next_bits(GENESIS_BITS, 0, 0, 100, 9660, &POW_LIMIT).unwrap(),
            GENESIS_BITS
        );

        assert_eq!(
            asert_next_bits(GENESIS_BITS, 0, 0, 100, 6060, &POW_LIMIT).unwrap(),
            GENESIS_BITS
        );

        let harder = asert_next_target(GENESIS_BITS, 0, 0, 100, 2460, &POW_LIMIT).unwrap();
        assert!(harder < Target::from_compact(GENESIS_BITS).unwrap());
    }

    const T0_HEX: &str = "0000000100000000000000000000000000000000000000000000000000000000";

    const T0_BITS: u32 = 0x1d01_0000;

    fn t0() -> Target {
        Target::from_be_hex(T0_HEX).unwrap()
    }

    fn wide_limit() -> Target {
        Target::MAX
    }

    fn vec_target(hd: u64, td: i128) -> Target {
        asert_next_target(T0_BITS, 0, 0, hd, td as u64, &wide_limit()).unwrap()
    }

    #[test]
    fn t0_bits_decode_to_2_pow_224() {
        assert_eq!(Target::from_compact(T0_BITS).unwrap(), t0());
        assert_eq!(t0().to_compact(), T0_BITS);
        assert_eq!(t0().bit_len(), 225);
    }

    #[test]
    fn v1_on_schedule_keeps_bits() {
        let next = vec_target(100, 6060);
        assert_eq!(next, t0());
        assert_eq!(next.to_be_hex(), T0_HEX);
        assert_eq!(
            asert_next_bits(T0_BITS, 0, 0, 100, 6060, &wide_limit()).unwrap(),
            T0_BITS
        );
    }

    #[test]
    fn v2_fast_by_60s_trunc_division() {
        let next = vec_target(100, 6000);
        assert_eq!(
            next.to_be_hex(),
            "00000000fd118000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn v3_slow_by_60s() {
        let next = vec_target(100, 6120);
        assert_eq!(
            next.to_be_hex(),
            "0000000102fc0000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn v4_one_half_life_ahead_doubles_difficulty() {
        let next = vec_target(100, 2460);
        assert_eq!(
            next.to_be_hex(),
            "0000000080000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn v5_one_half_life_behind_halves_difficulty() {
        let next = vec_target(100, 9660);
        assert_eq!(
            next.to_be_hex(),
            "0000000200000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn v8_half_half_life_cubic() {
        let next = vec_target(100, 7860);
        assert_eq!(
            next.to_be_hex(),
            "000000016a020000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn v6_clamp_high_to_pow_limit() {
        for limit_hex in [
            T0_HEX,
            "00000000ffff0000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000001e240",
        ] {
            let limit = Target::from_be_hex(limit_hex).unwrap();
            let next = asert_next_target_from_ref(&limit, 100, 9660, &limit);
            assert_eq!(next, limit, "pow_limit {limit_hex}");
        }
    }

    #[test]
    fn v7_clamp_low_to_one() {
        let next = asert_next_target_from_ref(&Target::ONE, 100, 2460, &wide_limit());
        assert_eq!(next, Target::ONE);
    }

    #[test]
    fn deep_behind_clamps_no_wrap() {
        let limit = t0();

        let next =
            asert_next_target(T0_BITS, 0, 0, 100, 1_000_000_000, &limit).unwrap();
        assert_eq!(next, limit);

        let next2 = asert_next_target_from_ref(&limit, 100, 6060 + 2 * 3600, &limit);
        assert_eq!(next2, limit);
    }

    #[test]
    fn deep_ahead_clamps_to_one() {
        let next = asert_next_target_from_ref(&t0(), 1_000_000, 0, &wide_limit());
        assert_eq!(next, Target::ONE);
    }

    #[test]
    fn anti_symmetry_approximate() {
        let r = Target::from_u64(1u64 << 60);
        let base: i128 = 6060;
        for delta in [60i128, 600, 1800, 3000, 3599] {
            let plus = asert_next_target_from_ref(&r, 100, base + delta, &Target::MAX);
            let minus = asert_next_target_from_ref(&r, 100, base - delta, &Target::MAX);
            assert_eq!(plus.0[2], 0);
            assert_eq!(minus.0[2], 0);
            let p = (plus.0[0] as u128) | ((plus.0[1] as u128) << 64);
            let m = (minus.0[0] as u128) | ((minus.0[1] as u128) << 64);
            let product = p * m;
            let ideal: u128 = 1u128 << 120;
            let err = product.abs_diff(ideal);

            assert!(
                err <= ideal / 1000,
                "delta {delta}: product {product} vs ideal {ideal}"
            );
        }
    }

    #[test]
    fn bits_round_trip() {
        for bits in [
            0x1d00_ffffu32,
            T0_BITS,
            0x1c0a_e493,
            0x1801_7e73,
            0x0412_3456,
            0x0312_3400,
            0x0212_3400,
            0x0112_0000,
            0x2100_ffff,
        ] {
            let t = Target::from_compact(bits).unwrap();
            assert_eq!(t.to_compact(), bits, "bits {bits:#010x}");
        }

        for hex_t in [
            T0_HEX,
            "000000000000000000000000007fffff00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ] {
            let t = Target::from_be_hex(hex_t).unwrap();
            assert_eq!(Target::from_compact(t.to_compact()).unwrap(), t);
        }
    }

    #[test]
    fn bits_reject_negative() {
        for bits in [0x0180_0001u32, 0x1d80_0000 | 0x1234, 0x0480_8080] {
            assert_eq!(
                Target::from_compact(bits),
                Err(AsertError::NegativeCompact),
                "bits {bits:#010x}"
            );
        }

        assert_eq!(Target::from_compact(0x0180_0000).unwrap(), Target::ZERO);
    }

    #[test]
    fn bits_reject_overflow() {
        for bits in [
            0xff00_0001u32,
            0x2300_0001,
            0x2200_0100,
            0x2101_0000,
        ] {
            assert_eq!(
                Target::from_compact(bits),
                Err(AsertError::OverflowCompact),
                "bits {bits:#010x}"
            );
        }

        assert!(Target::from_compact(0x2200_00ff).is_ok());
        assert!(Target::from_compact(0x2100_ffff).is_ok());
        assert!(Target::from_compact(0x2000_ffff).is_ok());
    }

    #[test]
    fn bits_zero_mantissa_decodes_to_zero() {
        for bits in [0x0000_0000u32, 0x1d00_0000, 0xff00_0000] {
            assert_eq!(Target::from_compact(bits).unwrap(), Target::ZERO);
        }
        assert_eq!(Target::ZERO.to_compact(), 0);
    }

    #[test]
    fn parent_below_anchor_errors() {
        assert_eq!(
            asert_next_target(T0_BITS, 10, 0, 9, 600, &wide_limit()),
            Err(AsertError::ParentBelowAnchor)
        );
    }

    #[test]
    fn zero_ref_yields_floor_one() {
        let next = asert_next_target_from_ref(&Target::ZERO, 100, 6060, &wide_limit());
        assert_eq!(next, Target::ONE);
    }

    #[test]
    fn target_ordering_and_hex_roundtrip() {
        let a = Target::from_be_hex(T0_HEX).unwrap();
        let b = a.shr(1);
        assert!(b < a);
        assert!(a > Target::ONE && Target::ONE > Target::ZERO);
        assert_eq!(Target::from_be_hex(&a.to_be_hex()).unwrap(), a);
    }
}
