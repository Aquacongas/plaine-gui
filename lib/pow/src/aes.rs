use crate::consts::AESKEY;

const fn key_word(off: usize) -> u64 {
    let mut v = 0u64;
    let mut i = 0;
    while i < 8 {
        v |= (AESKEY[off + i] as u64) << (8 * i);
        i += 1;
    }
    v
}
const KEY_LO: u64 = key_word(0);
const KEY_HI: u64 = key_word(8);

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::{KEY_HI, KEY_LO};
    use core::arch::x86_64::{__m128i, _mm_aesenc_si128, _mm_set_epi64x, _mm_storeu_si128};

    pub fn detect() -> bool {
        is_x86_feature_detected!("aes")
    }

    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn aesenc_key(state: [u64; 2], key: [u64; 2]) -> [u64; 2] {
        // SAFETY: caller guarantees the aes feature these intrinsics need.
        unsafe {
            let k = _mm_set_epi64x(key[1] as i64, key[0] as i64);
            let v = _mm_set_epi64x(state[1] as i64, state[0] as i64);
            let mut out = [0u64; 2];
            _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), _mm_aesenc_si128(v, k));
            out
        }
    }

    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn aesenc(state: [u64; 2]) -> [u64; 2] {
        // SAFETY: aes upheld by the caller; just forwards with the fixed key.
        unsafe { aesenc_key(state, [KEY_LO, KEY_HI]) }
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::{KEY_HI, KEY_LO};
    use core::arch::aarch64::{
        vaeseq_u8, vaesmcq_u8, vcombine_u64, vcreate_u64, vdupq_n_u8, veorq_u8, vgetq_lane_u64,
        vreinterpretq_u64_u8, vreinterpretq_u8_u64,
    };

    pub fn detect() -> bool {
        std::arch::is_aarch64_feature_detected!("aes")
    }

    // arm splits the aes round differently from x86: vaese does addroundkey (with a
    // zero key) then subbytes+shiftrows, vaesmc does mixcolumns. we xor our real key
    // in afterwards so the result matches x86's single _mm_aesenc_si128.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn aesenc_key(state: [u64; 2], key: [u64; 2]) -> [u64; 2] {
        let v = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(state[0]), vcreate_u64(state[1])));
        let k = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(key[0]), vcreate_u64(key[1])));
        let r = veorq_u8(vaesmcq_u8(vaeseq_u8(v, vdupq_n_u8(0))), k);
        let r = vreinterpretq_u64_u8(r);
        [vgetq_lane_u64(r, 0), vgetq_lane_u64(r, 1)]
    }

    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn aesenc(state: [u64; 2]) -> [u64; 2] {
        unsafe { aesenc_key(state, [KEY_LO, KEY_HI]) }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "Isochron v1 needs hardware AES: AES-NI on x86-64 or the ARMv8 crypto extensions. \
     No software fallback - see src/aes.rs."
);

pub(crate) use imp::{aesenc, aesenc_key, detect};
