#![allow(dead_code)]

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

pub fn sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    for x in 1..=255u16 {
        for y in 1..=255u16 {
            if gmul(x as u8, y as u8) == 1 {
                inv[x as usize] = y as u8;
                break;
            }
        }
    }
    let mut s = [0u8; 256];
    for x in 0..256usize {
        let b = inv[x];
        let mut r = 0u8;
        for i in 0..8 {
            let bit = ((b >> i) & 1)
                ^ ((b >> ((i + 4) % 8)) & 1)
                ^ ((b >> ((i + 5) % 8)) & 1)
                ^ ((b >> ((i + 6) % 8)) & 1)
                ^ ((b >> ((i + 7) % 8)) & 1)
                ^ ((0x63 >> i) & 1);
            r |= bit << i;
        }
        s[x] = r;
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
        let a = &s[4 * c..4 * c + 4];
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

pub fn aesenc(s: [u8; 16], k: [u8; 16], tbl: &[u8; 256]) -> [u8; 16] {
    xor16(mix_columns(shift_rows(sub_bytes(s, tbl))), k)
}

pub fn to_words(b: [u8; 16]) -> [u64; 2] {
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
    ]
}

pub fn to_bytes(w: [u64; 2]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&w[0].to_le_bytes());
    b[8..16].copy_from_slice(&w[1].to_le_bytes());
    b
}
