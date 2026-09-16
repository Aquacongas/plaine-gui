use plaine_pow::{Scratch, SCRATCH_WORDS};
use plaine_pow_mine::{Miner, BATCH};

const NONCES: u64 = 40 * BATCH as u64;

#[test]
fn batch_agrees_with_interpreter() {
    let mut miner = Miner::new().expect("hardware AES and a mappable batch region");
    let iso = miner.isochron();

    let mut ref_pad = Scratch::new();

    let mut pads: Vec<Scratch> = (0..BATCH).map(|_| Scratch::new()).collect();
    let mut seeds = vec![0u64; BATCH];
    let mut digests = vec![0u64; BATCH];

    let stride = 0x9E37_79B9_7F4A_7C15u64;
    let mut seed = 0x0123_4567_89AB_CDEFu64;

    let mut checked = 0u64;
    while checked < NONCES {
        let k = BATCH.min((NONCES - checked) as usize);
        for slot in seeds.iter_mut().take(k) {
            *slot = seed;
            seed = seed.wrapping_add(stride);
        }

        miner
            .mine_hash_batch(&mut pads[..k], &seeds[..k], &mut digests[..k])
            .expect("batch hash");

        for j in 0..k {
            let want = iso.verify_hash(&mut ref_pad, seeds[j]);

            assert_eq!(
                digests[j], want,
                "batch digest mismatch at nonce {} (seed {:016x}): batch {:016x}, interpreter {want:016x}",
                checked + j as u64,
                seeds[j],
                digests[j]
            );

            if let Some(i) = (0..SCRATCH_WORDS).find(|&i| pads[j].words()[i] != ref_pad.words()[i])
            {
                let n = (0..SCRATCH_WORDS)
                    .filter(|&i| pads[j].words()[i] != ref_pad.words()[i])
                    .count();
                panic!(
                    "batch scratchpad differs at nonce {} (seed {:016x}), first at word {i}: \
                     batch {:016x}, interpreter {:016x} ({n} of {SCRATCH_WORDS} words differ)",
                    checked + j as u64,
                    seeds[j],
                    pads[j].words()[i],
                    ref_pad.words()[i]
                );
            }
        }
        checked += k as u64;
    }

    assert_eq!(checked, NONCES);
}

#[test]
fn batch_preserves_slot_order() {
    let mut miner = Miner::new().expect("hardware AES and a mappable batch region");

    let seeds: Vec<u64> = [
        0xDEAD_BEEF_0000_0001u64,
        0x0000_0000_0000_0000,
        0xFFFF_FFFF_FFFF_FFFF,
        0x8000_0000_0000_0000,
        0x0123_4567_89AB_CDEF,
        0x7FFF_FFFF_FFFF_FFFF,
        0xAAAA_AAAA_AAAA_AAAA,
        0x5555_5555_5555_5555,
    ]
    .iter()
    .copied()
    .cycle()
    .take(BATCH)
    .enumerate()

    .map(|(i, s)| s.wrapping_add((i as u64).wrapping_mul(0x1_0001)))
    .collect();

    let mut pads: Vec<Scratch> = (0..BATCH).map(|_| Scratch::new()).collect();
    let mut digests = vec![0u64; BATCH];
    miner
        .mine_hash_batch(&mut pads, &seeds, &mut digests)
        .expect("batch hash");

    let mut single_pad = Scratch::new();
    for (i, &s) in seeds.iter().enumerate() {
        let want = miner.mine_hash(&mut single_pad, s).expect("single hash");
        assert_eq!(
            digests[i], want,
            "slot {i} (seed {s:016x}) = {:016x}, mine_hash = {want:016x}: batch did not \
             keep digests aligned to their slot index",
            digests[i]
        );
    }
}

#[test]
fn partial_batches_are_correct_for_every_k() {
    let mut miner = Miner::new().expect("hardware AES and a mappable batch region");
    let iso = miner.isochron();
    let mut ref_pad = Scratch::new();

    for k in [1usize, 2, 7, 15, 31, BATCH] {
        let seeds: Vec<u64> = (0..k)
            .map(|i| 0xB16B_00B5_0000_0000u64 ^ ((i as u64).wrapping_mul(0x9E37_79B9)))
            .collect();
        let mut pads: Vec<Scratch> = (0..k).map(|_| Scratch::new()).collect();
        let mut digests = vec![0u64; k];
        miner
            .mine_hash_batch(&mut pads, &seeds, &mut digests)
            .expect("partial batch");
        for j in 0..k {
            let want = iso.verify_hash(&mut ref_pad, seeds[j]);
            assert_eq!(
                digests[j], want,
                "k={k} slot {j} (seed {:016x}): batch {:016x}, interpreter {want:016x}",
                seeds[j], digests[j]
            );
        }
    }
}
