use plaine_pow::{build_program, Isochron, Scratch};
use plaine_pow_mine::{emit_native, CodeW, Miner, BATCH, NATIVE_CODE_BYTES, REGION_BYTES};

#[test]
fn sealed_region_is_x_not_w() {
    let mut w = CodeW::new().expect("map a code region");

    let before = w.protection();
    if let Some(writable) = before.writable {
        assert!(
            writable,
            "a freshly mapped CodeW is not writable ({}). The emitter is about to \
             write into it, so this would be a fault, not a policy problem.",
            before.raw
        );
    }

    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let prog = build_program(iso.fill(&mut pad, 1));
    emit_native(&prog, w.code_mut());

    let x = w.seal().expect("seal the region executable");
    let after = x.protection();

    match after.writable {
        Some(false) => {}
        Some(true) => panic!("W^X violated: sealed code region is still writable ({})", after.raw),

        // unverified is not the same as satisfied - fail rather than assume.
        None => panic!("could not read the sealed region's protection here: {}", after.raw),
    }
    assert_eq!(
        after.executable,
        Some(true),
        "the sealed region is not executable ({}), yet seal() reported success",
        after.raw
    );

    let w = x.unseal().expect("unseal the region writable");
    let back = w.protection();
    assert_eq!(
        back.writable,
        Some(true),
        "unseal() did not restore write access ({})",
        back.raw
    );
    assert_eq!(
        back.executable,
        Some(false),
        "unseal() left the region executable ({}) - W and X are both present",
        back.raw
    );
}

#[test]
fn resting_miner_holds_w_not_x() {
    let mut miner = Miner::new().expect("hardware AES and a mappable code page");
    let mut pad = Scratch::new();
    miner.mine_hash(&mut pad, 1).expect("one hash");

    let p = miner.protection().expect("the miner holds a region");
    assert_eq!(
        p.executable,
        Some(false),
        "the miner's resting code region is executable ({}) - it should be back in \
         its writable state between nonces, and never both at once",
        p.raw
    );
    assert_eq!(p.writable, Some(true), "resting region is not writable ({})", p.raw);
}

#[test]
fn sealed_batch_region_is_x_not_w() {
    let mut w = CodeW::new().expect("map a batch code region");

    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    for j in 0..BATCH {
        let prog = build_program(iso.fill(&mut pad, j as u64 + 1));
        emit_native(&prog, w.slot_mut(j));
    }

    let x = w.seal().expect("seal the whole batch region executable");
    let after = x.protection();
    match after.writable {
        Some(false) => {}
        Some(true) => panic!(
            "W^X violated: sealed batch region still writable ({}) - all {BATCH} slots flip as one",
            after.raw
        ),
        None => panic!(
            "could not determine the sealed batch region's protection: {}",
            after.raw
        ),
    }
    assert_eq!(
        after.executable,
        Some(true),
        "the sealed batch region is not executable ({}), yet seal() succeeded - the \
         query must cover the whole {REGION_BYTES}-byte region, not one page",
        after.raw
    );

    let w = x.unseal().expect("unseal the batch region writable");
    let back = w.protection();
    assert_eq!(back.writable, Some(true), "unseal did not restore write ({})", back.raw);
    assert_eq!(back.executable, Some(false), "unseal left the batch executable ({})", back.raw);
}

#[test]
fn batch_under_one_seal_agrees() {
    let mut miner = Miner::new().expect("hardware AES and a mappable batch region");

    let base = 0x0123_4567_89AB_0000u64;
    let seeds: Vec<u64> = (0..BATCH).map(|i| base.wrapping_add(i as u64)).collect();
    let mut pads: Vec<Scratch> = (0..BATCH).map(|_| Scratch::new()).collect();
    let mut out = vec![0u64; BATCH];
    miner
        .mine_hash_batch(&mut pads, &seeds, &mut out)
        .expect("batch hash");

    let mut ref_pad = Scratch::new();
    for (i, &seed) in seeds.iter().enumerate() {
        let want = miner.mine_hash(&mut ref_pad, seed).expect("reference hash");
        assert_eq!(
            out[i], want,
            "batch slot {i} (seed {seed:016x}) = {:016x}, per-nonce mine_hash = {want:016x}",
            out[i]
        );
    }

    let p = miner.protection().expect("the miner holds a region");
    assert_eq!(p.executable, Some(false), "resting batch region is executable ({})", p.raw);
    assert_eq!(p.writable, Some(true), "resting batch region is not writable ({})", p.raw);
}

#[test]
#[ignore = "measurement, not an assertion"]
fn wx_flip_cost() {
    use std::time::Instant;

    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let prog = build_program(iso.fill(&mut pad, 1));

    const N: u32 = 2000;
    let mut w = CodeW::new().expect("map");
    emit_native(&prog, w.code_mut());
    let t = Instant::now();
    for _ in 0..N {
        w = w.seal().expect("seal").unseal().expect("unseal");
    }
    let flips = t.elapsed().as_secs_f64() / f64::from(N);

    let mut miner = Miner::new().expect("miner");
    const H: u32 = 200;
    let mut sink = 0u64;
    for i in 0..16u32 {
        sink ^= miner.mine_hash(&mut pad, u64::from(i)).expect("warmup");
    }
    let t = Instant::now();
    for i in 0..H {
        sink ^= miner.mine_hash(&mut pad, 1000 + u64::from(i)).expect("hash");
    }
    let hash = t.elapsed().as_secs_f64() / f64::from(H);
    std::hint::black_box(sink);

    println!(
        "W^X flip pair  {:8.2} us\nhash (fill+gen+emit+run) {:8.1} us -> {:8.1} H/s/thread\n\
         flips are {:.3}% of a hash",
        flips * 1e6,
        hash * 1e6,
        1.0 / hash,
        100.0 * flips / hash
    );
}

#[allow(clippy::assertions_on_constants)]
#[test]
fn the_region_is_big_enough_and_page_shaped() {
    assert!(
        NATIVE_CODE_BYTES <= REGION_BYTES,
        "the emitted program ({NATIVE_CODE_BYTES} bytes) does not fit a region \
         ({REGION_BYTES} bytes)"
    );

    assert_eq!(REGION_BYTES % 65_536, 0);
}
