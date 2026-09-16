use plaine_pow::{Isochron, Scratch, AESKEY, FILL_DOM};

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    for x in 1..=255u8 {
        for y in 1..=255u8 {
            if gmul(x, y) == 1 {
                inv[x as usize] = y;
                break;
            }
        }
    }
    let mut s = [0u8; 256];
    for x in 0..=255usize {
        let y = inv[x];
        let r = |n: u32| y.rotate_left(n);
        s[x] = y ^ r(1) ^ r(2) ^ r(3) ^ r(4) ^ 0x63;
    }
    s
}

fn shift_rows(s: [u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            o[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    }
    o
}

fn sub_bytes(s: [u8; 16], tbl: &[u8; 256]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = tbl[s[i] as usize];
    }
    o
}

fn mix_columns(s: [u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        o[4 * c] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
        o[4 * c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
        o[4 * c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
        o[4 * c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
    }
    o
}

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

fn sw_x86_form(s: [u8; 16], k: [u8; 16], tbl: &[u8; 256]) -> [u8; 16] {
    xor16(mix_columns(shift_rows(sub_bytes(s, tbl))), k)
}

fn sw_arm_form(s: [u8; 16], k: [u8; 16], tbl: &[u8; 256]) -> [u8; 16] {
    xor16(mix_columns(sub_bytes(shift_rows(s), tbl)), k)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn hw_aesenc(s: [u8; 16], k: [u8; 16]) -> [u8; 16] {
    use core::arch::x86_64::{__m128i, _mm_aesenc_si128, _mm_loadu_si128, _mm_storeu_si128};

    unsafe {
        let sv = _mm_loadu_si128(s.as_ptr().cast::<__m128i>());
        let kv = _mm_loadu_si128(k.as_ptr().cast::<__m128i>());
        let mut o = [0u8; 16];
        _mm_storeu_si128(o.as_mut_ptr().cast::<__m128i>(), _mm_aesenc_si128(sv, kv));
        o
    }
}

#[test]
fn sbox_matches_fips197_known_answers() {
    let s = sbox();
    for (x, want) in [
        (0x00usize, 0x63u8),
        (0x01, 0x7c),
        (0x10, 0xca),
        (0x53, 0xed),
        (0xff, 0x16),
    ] {
        assert_eq!(s[x], want, "S-box[{x:#04x}] = {:#04x}, want {want:#04x}", s[x]);
    }
}

#[test]
fn mixcolumns_matches_fips197_known_answers() {
    for (input, want) in [
        ([0xdbu8, 0x13, 0x53, 0x45], [0x8eu8, 0x4d, 0xa1, 0xbc]),
        ([0xf2, 0x0a, 0x22, 0x5c], [0x9f, 0xdc, 0x58, 0x9d]),
        ([0x01, 0x01, 0x01, 0x01], [0x01, 0x01, 0x01, 0x01]),
        ([0xc6, 0xc6, 0xc6, 0xc6], [0xc6, 0xc6, 0xc6, 0xc6]),
        ([0xd4, 0xd4, 0xd4, 0xd5], [0xd5, 0xd5, 0xd7, 0xd6]),
    ] {
        let mut s = [0u8; 16];
        s[..4].copy_from_slice(&input);
        let o = mix_columns(s);
        assert_eq!(&o[..4], &want, "MixColumns({input:02x?})");
    }
}

#[test]
fn shiftrows_permutation() {
    let mut s = [0u8; 16];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }

    assert_eq!(
        shift_rows(s),
        [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    );
}

#[test]
fn x86_and_arm_forms_agree() {
    #[cfg(target_arch = "x86_64")]
    assert!(is_x86_feature_detected!("aes"), "AES-NI required");
    let tbl = sbox();

    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut nxt = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };

    for trial in 0..10_000 {
        let mut s = [0u8; 16];
        let mut k = [0u8; 16];
        s[0..8].copy_from_slice(&nxt().to_le_bytes());
        s[8..16].copy_from_slice(&nxt().to_le_bytes());
        k[0..8].copy_from_slice(&nxt().to_le_bytes());
        k[8..16].copy_from_slice(&nxt().to_le_bytes());

        let a = sw_x86_form(s, k, &tbl);
        let b = sw_arm_form(s, k, &tbl);
        assert_eq!(
            a, b,
            "trial {trial}: x86 and arm orderings disagree - state {s:02x?} key {k:02x?}"
        );

        #[cfg(target_arch = "x86_64")]
        {
            let h = unsafe { hw_aesenc(s, k) };
            assert_eq!(
                a, h,
                "trial {trial}: software model disagrees with hardware AESENC - \
                 state {s:02x?} key {k:02x?}"
            );
        }
    }
}

#[test]
fn software_model_matches_fill() {
    let tbl = sbox();
    let iso = Isochron::new().expect("hardware AES");
    let seed = 0x00AB_CDEF_1234_5678u64;
    let mut pad = Scratch::new();
    iso.fill(&mut pad, seed);

    for i in 0..4u64 {
        let mut line = [0u8; 16];
        line[0..8].copy_from_slice(&seed.to_le_bytes());
        line[8..16].copy_from_slice(&(i ^ FILL_DOM).to_le_bytes());
        let out = sw_x86_form(sw_x86_form(line, AESKEY, &tbl), AESKEY, &tbl);

        let lo = u64::from_le_bytes(out[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_eq!(
            pad.words()[2 * i as usize],
            lo,
            "fill line {i} low word: software model {lo:016x}, crate {:016x}",
            pad.words()[2 * i as usize]
        );
        assert_eq!(
            pad.words()[2 * i as usize + 1],
            hi,
            "fill line {i} high word: software model {hi:016x}, crate {:016x}",
            pad.words()[2 * i as usize + 1]
        );
    }
}
