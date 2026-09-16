mod common;

use common::{aesenc, sbox, to_bytes, to_words};
use plaine_pow::{Isochron, Scratch, AESKEY, FILL_DOM, SCRATCH_BYTES, SCRATCH_WORDS};

const LINES: usize = (SCRATCH_BYTES / 16) as usize;
const CHAINS: usize = 4;

fn fold_of_pad(words: &[u64; SCRATCH_WORDS], seed: u64, tbl: &[u8; 256]) -> u64 {
    let mut acc = [[0u8; 16]; CHAINS];
    for (j, a) in acc.iter_mut().enumerate() {
        *a = to_bytes([seed ^ FILL_DOM, !seed ^ (j as u64)]);
    }
    for i in 0..LINES {
        let line = to_bytes([words[2 * i], words[2 * i + 1]]);

        acc[i % CHAINS] = aesenc(acc[i % CHAINS], line, tbl);
    }
    let mut fin = acc[0];
    for a in acc.iter().skip(1) {
        fin = aesenc(fin, *a, tbl);
    }
    fin = aesenc(aesenc(fin, AESKEY, tbl), AESKEY, tbl);
    let w = to_words(fin);
    w[0] ^ w[1]
}

fn iso() -> Isochron {
    Isochron::new().expect("hardware AES")
}

#[test]
fn reference_fold_matches_fill() {
    let iso = iso();
    let tbl = sbox();
    let mut pad = Scratch::new();
    for seed in [0u64, 1, 0x243F_6A88_85A3_08D3, u64::MAX] {
        let ps = iso.fill(&mut pad, seed);
        assert_eq!(
            ps,
            fold_of_pad(pad.words(), seed, &tbl),
            "the software fold and the crate's fill disagree at seed {seed:016x}"
        );
    }
}

#[test]
fn two_fills_agree() {
    let iso = iso();
    let mut a = Scratch::new();
    let mut b = Scratch::new();
    for seed in [0u64, 7, 0xFEDC_BA09_8765_4321, u64::MAX] {
        assert_eq!(iso.fill(&mut a, seed), iso.fill_ref(&mut b, seed));
        assert_eq!(a.words(), b.words());
    }
}

#[test]
fn flipped_pad_bit_moves_progseed() {
    let iso = iso();
    let tbl = sbox();
    let mut pad = Scratch::new();
    let seed = 0x243F_6A88_85A3_08D3u64;
    let base = iso.fill(&mut pad, seed);
    assert_eq!(base, fold_of_pad(pad.words(), seed, &tbl));

    let mut probes: Vec<usize> = vec![
        0,
        1,
        2,
        3,
        SCRATCH_WORDS - 1,
        SCRATCH_WORDS - 2,
        2 * (LINES - 4),
        2 * (LINES - 3),
        2 * (LINES - 2),
        2 * (LINES - 1),
    ];
    let mut w = 7usize;
    while w < SCRATCH_WORDS {
        probes.push(w);
        w += 997;
    }

    let mut flipped = *pad.words();
    for &w in &probes {
        for bit in [0u32, 31, 63] {
            flipped[w] ^= 1u64 << bit;
            let got = fold_of_pad(&flipped, seed, &tbl);
            flipped[w] ^= 1u64 << bit;
            assert_ne!(
                got, base,
                "flipping bit {bit} of pad word {w} left the program seed unchanged"
            );
        }
    }
}

#[test]
fn fold_is_not_order_blind() {
    let iso = iso();
    let tbl = sbox();
    let mut pad = Scratch::new();
    let seed = 0x243F_6A88_85A3_08D3u64;
    let base = iso.fill(&mut pad, seed);
    let mut w = *pad.words();

    for (x, y, what) in [
        (0usize, 4usize, "same chain"),
        (0, 1, "different chains"),
        (LINES - 2, LINES - 1, "the last two lines"),
    ] {
        w.swap(2 * x, 2 * y);
        w.swap(2 * x + 1, 2 * y + 1);
        assert_ne!(
            fold_of_pad(&w, seed, &tbl),
            base,
            "swapping lines {x} and {y} ({what}) left the program seed unchanged"
        );
        w.swap(2 * x, 2 * y);
        w.swap(2 * x + 1, 2 * y + 1);
    }
}

#[test]
fn pad_free_shortcut_fails() {
    fn pad_free_shortcut(seed: u64) -> u64 {
        let tbl = sbox();
        let init = to_bytes([seed ^ FILL_DOM, !seed]);
        let w = to_words(aesenc(aesenc(init, AESKEY, &tbl), AESKEY, &tbl));
        w[0] ^ w[1]
    }

    let iso = iso();
    let mut pad = Scratch::new();
    for seed in [0u64, 1, 42, 0x243F_6A88_85A3_08D3, u64::MAX] {
        let ps = iso.fill(&mut pad, seed);

        let (mut x0, mut x1) = (0u64, 0u64);
        for i in 0..LINES {
            x0 ^= pad.words()[2 * i];
            x1 ^= pad.words()[2 * i + 1];
        }
        assert_eq!(
            (x0, x1),
            (0, 0),
            "the line XOR stopped being zero at seed {seed:016x}"
        );

        let tbl = sbox();
        let old_fold = {
            let init = to_bytes([seed ^ FILL_DOM ^ x0, !seed ^ x1]);
            let w = to_words(aesenc(aesenc(init, AESKEY, &tbl), AESKEY, &tbl));
            w[0] ^ w[1]
        };
        assert_eq!(
            old_fold,
            pad_free_shortcut(seed),
            "the old XOR fold is by construction the pad-free shortcut"
        );

        assert_ne!(
            ps,
            pad_free_shortcut(seed),
            "the pad-free shortcut still computes the program seed at seed {seed:016x}"
        );
    }
}

#[test]
fn progseed_needs_whole_pad() {
    let iso = iso();
    let mut pad = Scratch::new();
    let seed = 0x243F_6A88_85A3_08D3u64;
    let full = iso.fill(&mut pad, seed);
    let tbl = sbox();

    for n in [LINES / 4, LINES / 2, 3 * LINES / 4, LINES - 1] {
        let mut acc = [[0u8; 16]; CHAINS];
        for (j, a) in acc.iter_mut().enumerate() {
            *a = to_bytes([seed ^ FILL_DOM, !seed ^ (j as u64)]);
        }
        for i in 0..n {
            let line = to_bytes([pad.words()[2 * i], pad.words()[2 * i + 1]]);
            acc[i % CHAINS] = aesenc(acc[i % CHAINS], line, &tbl);
        }
        let mut fin = acc[0];
        for a in acc.iter().skip(1) {
            fin = aesenc(fin, *a, &tbl);
        }
        fin = aesenc(aesenc(fin, AESKEY, &tbl), AESKEY, &tbl);
        let w = to_words(fin);
        assert_ne!(
            w[0] ^ w[1],
            full,
            "folding only the first {n} of {LINES} lines reproduced the program seed"
        );
    }
}
