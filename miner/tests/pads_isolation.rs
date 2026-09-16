use plaine_pow::{Isochron, Scratch, SCRATCH_WORDS};
use plaine_pow_mine::{Miner, Pads, BATCH};

const STRIDE: u64 = 0x9E37_79B9_7F4A_7C15;
const FIRST: u64 = 0x0123_4567_89AB_CDEF;

fn have_aes() -> bool {
    Isochron::new().is_ok()
}

#[test]
fn pads_agree_with_interpreter_concurrently() {
    if !have_aes() {
        eprintln!("no hardware AES on this host; skipping");
        return;
    }
    const WORKERS: usize = 4;
    let (pads, err) = Pads::many(WORKERS, BATCH, true);
    assert!(err.is_none(), "the ordinary-page fallback must never fail: {err:?}");
    assert_eq!(pads.len(), WORKERS);

    let mut handles = Vec::new();
    for (w, mut pads) in pads.into_iter().enumerate() {
        handles.push(std::thread::spawn(move || {
            let mut miner = Miner::new().expect("a miner per worker");
            let iso = miner.isochron();
            let mut reference = Scratch::new();

            let mut seed = FIRST.wrapping_add(STRIDE.wrapping_mul(w as u64 * 1024));
            let mut seeds = vec![0u64; BATCH];
            let mut digests = vec![0u64; BATCH];
            for round in 0..6 {
                for s in seeds.iter_mut() {
                    *s = seed;
                    seed = seed.wrapping_add(STRIDE);
                }
                miner
                    .mine_hash_batch_on(&mut pads, &seeds, &mut digests)
                    .expect("batch over this worker's pads");
                for j in 0..BATCH {
                    let want = iso.verify_hash(&mut reference, seeds[j]);
                    assert_eq!(
                        digests[j], want,
                        "worker {w} round {round} slot {j} (seed {:016x}): the shared-\
                         reservation pad computed {:016x}, the interpreter {want:016x}",
                        seeds[j], digests[j]
                    );
                    let got = pads.words(j);
                    if let Some(i) = (0..SCRATCH_WORDS).find(|&i| got[i] != reference.words()[i]) {
                        let n = (0..SCRATCH_WORDS)
                            .filter(|&i| got[i] != reference.words()[i])
                            .count();
                        panic!(
                            "worker {w} round {round} pad {j} (seed {:016x}) differs from the \
                             interpreter's, first at word {i}: {:016x} vs {:016x} ({n} of \
                             {SCRATCH_WORDS} words differ)",
                            seeds[j],
                            got[i],
                            reference.words()[i]
                        );
                    }
                    assert_eq!(pads.checksum(j), reference.checksum(), "padck, worker {w} slot {j}");
                }
            }
        }));
    }
    for (w, h) in handles.into_iter().enumerate() {
        h.join().unwrap_or_else(|_| panic!("worker {w} panicked"));
    }
}

#[test]
fn worker_stays_in_its_own_pads() {
    if !have_aes() {
        eprintln!("no hardware AES on this host; skipping");
        return;
    }
    const WORKERS: usize = 3;
    let (mut pads, err) = Pads::many(WORKERS, BATCH, true);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(pads.len(), WORKERS);

    let mut miner = Miner::new().expect("miner");
    let iso = miner.isochron();
    let mut reference = Scratch::new();

    for (w, p) in pads.iter().enumerate() {
        for j in 0..BATCH {
            assert!(p.words(j).iter().all(|&x| x == 0), "worker {w} pad {j} started dirty");
        }
    }

    let seeds: Vec<u64> = (0..BATCH).map(|i| FIRST ^ STRIDE.wrapping_mul(i as u64)).collect();
    let mut digests = vec![0u64; BATCH];
    miner.mine_hash_batch_on(&mut pads[1], &seeds, &mut digests).expect("full batch");

    for j in 0..BATCH {
        assert_eq!(digests[j], iso.verify_hash(&mut reference, seeds[j]), "slot {j}");
        assert_eq!(pads[1].words(j), reference.words(), "worker 1 pad {j}");
    }
    for w in [0usize, 2] {
        for j in 0..BATCH {
            assert!(
                pads[w].words(j).iter().all(|&x| x == 0),
                "worker {w}'s pad {j} was written by worker 1's batch - the slices overlap or \
                 a slot pointer is off by a pad"
            );
        }
    }

    let k = BATCH - 1;
    let seeds2: Vec<u64> = (0..k).map(|i| FIRST.wrapping_add(0x51 + i as u64)).collect();
    let mut digests2 = vec![0u64; k];
    miner.mine_hash_batch_on(&mut pads[2], &seeds2, &mut digests2).expect("partial batch");

    for j in 0..k {
        assert_eq!(digests2[j], iso.verify_hash(&mut reference, seeds2[j]), "partial slot {j}");
        assert_eq!(pads[2].words(j), reference.words(), "worker 2 pad {j}");
    }
    assert!(
        pads[2].words(k).iter().all(|&x| x == 0),
        "pad {k} was written although only {k} nonces were asked for"
    );
    assert!(
        pads[0].words(0).iter().all(|&x| x == 0),
        "worker 0's pads were written by worker 2's partial batch"
    );

    for j in 0..BATCH {
        let want = iso.verify_hash(&mut reference, seeds[j]);
        assert_eq!(digests[j], want);
        assert_eq!(pads[1].words(j), reference.words(), "worker 1 pad {j} changed under it");
    }
}

#[test]
#[ignore = "measurement, not an assertion"]
fn how_many_regions_this_machine_puts_on_huge_pages() {
    let n: usize = std::env::var("PLAINE_PAD_PROBE_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);
    let n = n.clamp(1, 4096);

    for round in 0..3 {
        let (pads, err) = Pads::many(n, BATCH, true);
        let huge = pads.iter().filter(|p| p.pages().is_huge()).count();
        let kind = pads.first().map(|p| p.pages());
        eprintln!(
            "round {round}: {huge}/{n} worker regions on huge pages ({kind:?}){}",
            match &err {
                Some(e) => format!(", stopped at worker {}: {e}", pads.len()),
                None => String::new(),
            }
        );
        drop(pads);
    }

    let ever = plaine_pow_mine::pad::observed_ever();
    eprintln!(
        "three rounds: {}/{} regions on huge pages ({})",
        ever.huge(),
        ever.total(),
        ever.tag()
    );
}
