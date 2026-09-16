use crate::aes::{aesenc, aesenc_key};
use crate::consts::{FILL_DOM, SCRATCH_BYTES, SCRATCH_WORDS};

const LINES: usize = (SCRATCH_BYTES / 16) as usize;

// four aes chains folded at the end - wide enough to fill the 4 pipelined aesenc units.
const CHAINS: usize = 4;

const _: () = assert!(LINES % CHAINS == 0, "CHAINS must divide LINES");

#[inline]
fn chain_init(seed: u64) -> [[u64; 2]; CHAINS] {
    let mut a = [[0u64; 2]; CHAINS];
    let mut j = 0;
    while j < CHAINS {
        a[j] = [seed ^ FILL_DOM, !seed ^ (j as u64)];
        j += 1;
    }
    a
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn fill(sc: &mut [u64; SCRATCH_WORDS], seed: u64) -> u64 {
    let mut a = chain_init(seed);
    let mut i = 0usize;
    while i < LINES {
        // SAFETY: the fn's target_feature gate guarantees aes here.
        let (v0, v1, v2, v3) = unsafe {
            (
                aesenc(aesenc([seed, (i as u64) ^ FILL_DOM])),
                aesenc(aesenc([seed, ((i + 1) as u64) ^ FILL_DOM])),
                aesenc(aesenc([seed, ((i + 2) as u64) ^ FILL_DOM])),
                aesenc(aesenc([seed, ((i + 3) as u64) ^ FILL_DOM])),
            )
        };

        sc[2 * i] = v0[0];
        sc[2 * i + 1] = v0[1];
        sc[2 * i + 2] = v1[0];
        sc[2 * i + 3] = v1[1];
        sc[2 * i + 4] = v2[0];
        sc[2 * i + 5] = v2[1];
        sc[2 * i + 6] = v3[0];
        sc[2 * i + 7] = v3[1];

        // SAFETY: still under the aes gate.
        unsafe {
            a[0] = aesenc_key(a[0], v0);
            a[1] = aesenc_key(a[1], v1);
            a[2] = aesenc_key(a[2], v2);
            a[3] = aesenc_key(a[3], v3);
        }
        i += CHAINS;
    }

    // final fold of the four chains, then two more rounds to diffuse.
    // SAFETY: aes gate, as above.
    unsafe {
        let t = aesenc_key(a[0], a[1]);
        let t = aesenc_key(t, a[2]);
        let t = aesenc_key(t, a[3]);
        let t = aesenc(aesenc(t));
        t[0] ^ t[1]
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn fill_ref(sc: &mut [u64; SCRATCH_WORDS], seed: u64) -> u64 {
    let mut acc = [[0u8; 16]; CHAINS];
    for (j, a) in acc.iter_mut().enumerate() {
        put64le(&mut a[0..8], seed ^ FILL_DOM);
        put64le(&mut a[8..16], !seed ^ (j as u64));
    }

    for i in 0..LINES {
        let mut line = [0u8; 16];
        put64le(&mut line[0..8], seed);
        put64le(&mut line[8..16], (i as u64) ^ FILL_DOM);

        // SAFETY: aes-gated fn.
        let w = unsafe { aesenc(aesenc([ld64le(&line[0..8]), ld64le(&line[8..16])])) };
        put64le(&mut line[0..8], w[0]);
        put64le(&mut line[8..16], w[1]);

        sc[2 * i] = ld64le(&line[0..8]);
        sc[2 * i + 1] = ld64le(&line[8..16]);

        let a = &mut acc[i % CHAINS];

        // SAFETY: same gate.
        let r = unsafe {
            aesenc_key(
                [ld64le(&a[0..8]), ld64le(&a[8..16])],
                [ld64le(&line[0..8]), ld64le(&line[8..16])],
            )
        };
        put64le(&mut a[0..8], r[0]);
        put64le(&mut a[8..16], r[1]);
    }

    let mut fin = acc[0];
    for a in acc.iter().skip(1) {
        // SAFETY: aes gate.
        let r = unsafe {
            aesenc_key(
                [ld64le(&fin[0..8]), ld64le(&fin[8..16])],
                [ld64le(&a[0..8]), ld64le(&a[8..16])],
            )
        };
        put64le(&mut fin[0..8], r[0]);
        put64le(&mut fin[8..16], r[1]);
    }

    // SAFETY: aes gate, last use.
    let f = unsafe { aesenc(aesenc([ld64le(&fin[0..8]), ld64le(&fin[8..16])])) };
    put64le(&mut fin[0..8], f[0]);
    put64le(&mut fin[8..16], f[1]);
    ld64le(&fin[0..8]) ^ ld64le(&fin[8..16])
}

fn put64le(p: &mut [u8], v: u64) {
    for (i, b) in p.iter_mut().enumerate().take(8) {
        *b = (v >> (8 * i)) as u8;
    }
}

fn ld64le(p: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in p.iter().enumerate().take(8) {
        v |= (b as u64) << (8 * i);
    }
    v
}
