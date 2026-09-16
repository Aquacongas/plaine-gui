mod oracle;

use plaine_pow::{build_program, Op, Program, Scratch, ALL_OPS, SCRATCH_WORDS};
use plaine_pow_mine::Miner;

fn compare(miner: &mut Miner, prog: &Program, seed: u64, tag: &str) {
    let iso = miner.isochron();
    let mut a = Scratch::new();
    let mut b = Scratch::new();

    let psa = iso.fill(&mut a, seed);
    let psb = iso.fill(&mut b, seed);
    assert_eq!(
        psa, psb,
        "{tag}: the two pads' program seeds diverge ({psa:016x} vs {psb:016x}) - \
         the fill is not deterministic, so nothing below can be attributed to the JIT"
    );

    let ri = iso.interp(prog, &mut a, seed);
    let rj = miner
        .run(prog, &mut b, seed)
        .unwrap_or_else(|e| panic!("{tag}: could not run the JIT: {e}"));

    if let Some(i) = (0..SCRATCH_WORDS).find(|&i| a.words()[i] != b.words()[i]) {
        let n = (0..SCRATCH_WORDS)
            .filter(|&i| a.words()[i] != b.words()[i])
            .count();
        panic!(
            "{tag}: SCRATCHPAD DIFFERS after the run - first difference at word {i}: \
             interp {:016x}, jit {:016x} ({n} of {SCRATCH_WORDS} words differ; \
             digests interp {ri:016x} jit {rj:016x})",
            a.words()[i],
            b.words()[i]
        );
    }
    // same pad, different digest: the memory ops are fine, look in the register file.
    assert_eq!(
        ri, rj,
        "{tag}: digest mismatch on an identical scratchpad - interp {ri:016x}, jit {rj:016x} (seed {seed:016x})"
    );
    assert_eq!(
        a.checksum(),
        b.checksum(),
        "{tag}: padck differs though every word matched - suspect the comparison itself"
    );
}

#[test]
fn interp_and_jit_agree_on_every_opcode() {
    let v = oracle::parse();
    let mut miner = Miner::new().expect("hardware AES and a mappable code page");

    for row in &v.opcodes {
        let op = Op::from_u8(row.op).expect("vector opcode in range");
        let prog = oracle::fill_single(op, row.prognonce);
        compare(&mut miner, &prog, row.seed, op.name());
    }
    assert_eq!(v.opcodes.len(), ALL_OPS.len(), "every opcode must be covered");
}

#[test]
fn jit_agrees_with_oracle_per_opcode() {
    let v = oracle::parse();
    let mut miner = Miner::new().expect("hardware AES and a mappable code page");
    let iso = miner.isochron();
    let mut pad = Scratch::new();

    for row in &v.opcodes {
        let op = Op::from_u8(row.op).expect("vector opcode in range");
        let prog = oracle::fill_single(op, row.prognonce);
        iso.fill(&mut pad, row.seed);
        let digest = miner.run(&prog, &mut pad, row.seed).expect("jit run");

        assert_eq!(
            digest,
            row.digest,
            "opcode {} {}: JIT digest mismatch - expected {:016x}, got {digest:016x} \
             (seed {:016x}, prognonce {:016x})",
            row.op,
            op.name(),
            row.digest,
            row.seed,
            row.prognonce
        );

        let ck = pad.checksum();
        assert_eq!(
            ck,
            row.padck,
            "opcode {} {}: JIT padck mismatch - expected {:016x}, got {ck:016x} \
             (seed {:016x}, prognonce {:016x})",
            row.op,
            op.name(),
            row.padck,
            row.seed,
            row.prognonce
        );
    }
}

#[test]
fn interp_and_jit_agree_on_nonces() {
    let v = oracle::parse();
    let mut miner = Miner::new().expect("hardware AES and a mappable code page");
    let iso = miner.isochron();
    let mut tmp = Scratch::new();

    for row in &v.nonces {
        let ps = iso.fill(&mut tmp, row.seed);
        assert_eq!(
            ps, row.progseed,
            "nonce i={} seed {:016x}: PROGRAM SEED mismatch - expected {:016x}, \
             got {ps:016x} (the fill diverged; the JIT is not implicated)",
            row.i, row.seed, row.progseed
        );
        let prog = build_program(ps);
        compare(
            &mut miner,
            &prog,
            row.seed,
            &format!("nonce i={} seed {:016x}", row.i, row.seed),
        );
    }
}

#[test]
fn mine_hash_reproduces_chain_order() {
    let v = oracle::parse();
    let mut miner = Miner::new().expect("hardware AES and a mappable code page");
    let iso = miner.isochron();
    let mut jit_pad = Scratch::new();
    let mut int_pad = Scratch::new();

    for row in v.nonces.iter().step_by(8) {
        let jit = miner.mine_hash(&mut jit_pad, row.seed).expect("mine_hash");
        let int = iso.verify_hash(&mut int_pad, row.seed);
        assert_eq!(
            jit, row.digest,
            "mine_hash(seed {:016x}) = {jit:016x}, oracle says {:016x}",
            row.seed, row.digest
        );
        assert_eq!(
            jit, int,
            "mine_hash and verify_hash disagree at seed {:016x}: {jit:016x} vs {int:016x}",
            row.seed
        );
        assert_eq!(
            jit_pad.checksum(),
            row.padck,
            "mine_hash(seed {:016x}): padck mismatch - expected {:016x}, got {:016x}",
            row.seed,
            row.padck,
            jit_pad.checksum()
        );
    }
}

#[test]
fn interp_and_jit_agree_on_odd_operands() {
    let mut miner = Miner::new().expect("hardware AES and a mappable code page");
    let mut rng = plaine_pow::Rng::new(0x5EED_0000_D15A_57E5, 3);

    for round in 0..24u32 {
        let mut slots = [plaine_pow::Instr::new(Op::Add, 0, 0, 0); plaine_pow::PROG_INSTR];
        for slot in slots.iter_mut() {
            let w = rng.next();
            let op = ALL_OPS[(w % ALL_OPS.len() as u64) as usize];
            let d = ((w >> 8) & 7) as u8;

            let s = (d + 1 + ((w >> 16) & 7) as u8 % 7) % 8;
            debug_assert_ne!(d, s);
            *slot = plaine_pow::Instr::new(op, d, s, rng.next() as u32);
        }
        let prog = Program::from_slots(slots);
        compare(
            &mut miner,
            &prog,
            0x00AB_CDEF_1234_5678 ^ u64::from(round),
            &format!("mixed round {round}"),
        );
    }
}

#[test]
fn jit_requires_d_ne_s() {
    const DIVERGES_WHEN_ALIASED: [Op; 5] = [Op::Or, Op::And, Op::Andn, Op::Rola, Op::Rora];

    let mut miner = Miner::new().expect("hardware AES and a mappable code page");
    let iso = miner.isochron();

    for &op in ALL_OPS.iter() {
        let mut slots = [plaine_pow::Instr::new(op, 0, 0, 0); plaine_pow::PROG_INSTR];
        for (i, slot) in slots.iter_mut().enumerate() {
            let d = (i % 8) as u8;

            *slot = plaine_pow::Instr::new(op, d, d, (i as u32).wrapping_mul(0x9E37_79B9));
        }
        let prog = Program::from_slots(slots);

        let mut a = Scratch::new();
        let mut b = Scratch::new();
        iso.fill(&mut a, 7);
        iso.fill(&mut b, 7);
        let ri = iso.interp(&prog, &mut a, 7);
        let rj = miner.run(&prog, &mut b, 7).expect("jit run");
        let agree = ri == rj && a.words()[..] == b.words()[..];

        if DIVERGES_WHEN_ALIASED.contains(&op) {
            assert!(
                !agree,
                "{} now agrees with the interpreter at d == s; if deliberate, the oracle bytes \
                 and ISO_CODE_BYTES moved with it",
                op.name()
            );
        } else {
            assert!(
                agree,
                "{} diverges at d == s and is not on the known list - interp {ri:016x}, jit {rj:016x}",
                op.name()
            );
        }
    }
}

#[test]
fn code_region_reused_across_nonces() {
    let v = oracle::parse();
    let mut miner = Miner::new().expect("hardware AES and a mappable code page");
    let mut pad = Scratch::new();

    let mut got = Vec::new();
    for row in v.nonces.iter().take(24) {
        got.push(miner.mine_hash(&mut pad, row.seed).expect("mine_hash"));
    }
    for (row, d) in v.nonces.iter().zip(&got) {
        assert_eq!(
            *d, row.digest,
            "reused code region: seed {:016x} gave {d:016x}, oracle says {:016x}",
            row.seed, row.digest
        );
    }

    let again = miner.mine_hash(&mut pad, v.nonces[0].seed).expect("mine_hash");
    assert_eq!(again, got[0], "the miner is not idempotent across nonces");
}
