mod oracle;

use plaine_pow::{build_program, Isochron, Scratch, ALL_OPS, HIST, OP_COUNT, PROG_INSTR};
use plaine_pow_mine::{
    emit_aarch64_into, emit_x86_64, emit_x86_64_into, ARM64_EPILOGUE, ARM64_LEN, ARM64_PROLOGUE,
    ISO_CODE_BYTES, ISO_CODE_BYTES_AARCH64, REGION_BYTES, X86_EPILOGUE, X86_LEN, X86_PROLOGUE,
};

#[allow(clippy::assertions_on_constants)]
#[test]
fn compile_time_identity_matches_oracle() {
    let body: usize = (0..OP_COUNT)
        .map(|i| HIST[i] as usize * X86_LEN[i] as usize)
        .sum();
    assert_eq!(body, 13263, "sum of HIST[op] * X86_LEN[op] over the ISA");
    assert_eq!(X86_PROLOGUE + body + X86_EPILOGUE, 13449);
    assert_eq!(ISO_CODE_BYTES, 13449, "the C oracle emits 13449 bytes");
    assert!(
        ISO_CODE_BYTES <= REGION_BYTES,
        "the emitted program must fit one mapped region"
    );

    assert!(ISO_CODE_BYTES < 32 * 1024);
}

#[test]
fn emitted_size_is_identical_for_every_nonce_x86() {
    let v = oracle::parse();
    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let mut buf = vec![0u8; REGION_BYTES];

    let mut seen: Option<usize> = None;
    for row in &v.nonces {
        let ps = iso.fill(&mut pad, row.seed);
        assert_eq!(ps, row.progseed, "nonce i={}: fill diverged", row.i);
        let prog = build_program(ps);

        let n = emit_x86_64_into(&prog, &mut buf);
        match seen {
            None => seen = Some(n),
            Some(first) => assert_eq!(
                n, first,
                "EMITTED SIZE VARIES WITH NONCE: {n} bytes at i={} (seed {:016x}), \
                 {first} bytes at i=0",
                row.i, row.seed
            ),
        }
        assert_eq!(
            n, row.codesize,
            "nonce i={} seed {:016x}: emitted {n} bytes, oracle recorded {}",
            row.i, row.seed, row.codesize
        );
    }
    assert_eq!(seen, Some(ISO_CODE_BYTES));
}

#[allow(clippy::assertions_on_constants)]
#[test]
fn emitted_size_is_identical_for_every_nonce_aarch64() {
    let v = oracle::parse();
    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let mut buf = vec![0u8; REGION_BYTES];

    let mut seen: Option<usize> = None;
    for row in v.nonces.iter() {
        let ps = iso.fill(&mut pad, row.seed);
        let prog = build_program(ps);
        let n = emit_aarch64_into(&prog, &mut buf);
        match seen {
            None => seen = Some(n),
            Some(first) => assert_eq!(
                n, first,
                "AARCH64 EMITTED SIZE VARIES WITH NONCE: {n} bytes at i={} \
                 (seed {:016x}), {first} bytes at i=0 - the most likely cause is a \
                 conditional movk in a_imm32",
                row.i, row.seed
            ),
        }
        assert_eq!(n % 4, 0, "A64 instructions are 4 bytes");
    }
    assert_eq!(seen, Some(ISO_CODE_BYTES_AARCH64));

    assert_eq!(ISO_CODE_BYTES_AARCH64, 15568);
    assert!(ISO_CODE_BYTES_AARCH64 <= REGION_BYTES);
}

#[test]
fn single_opcode_pins_aarch64_lengths() {
    let mut buf = vec![0u8; REGION_BYTES];
    for &op in ALL_OPS.iter() {
        let prog = oracle::fill_single(op, 0xC0FFEE + op.index() as u64);
        let n = emit_aarch64_into(&prog, &mut buf);
        let want =
            ARM64_PROLOGUE + PROG_INSTR * ARM64_LEN[op.index() as usize] as usize + ARM64_EPILOGUE;
        assert_eq!(
            n,
            want,
            "512-slot {} program emitted {n} aarch64 bytes, ARM64_LEN[{}] = {} predicts {want}",
            op.name(),
            op.index(),
            ARM64_LEN[op.index() as usize]
        );
    }
}

#[test]
fn frozen_histogram_matches_lengths() {
    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let ps = iso.fill(&mut pad, 0x00AB_CDEF_1234_5678);
    let prog = build_program(ps);

    let mut tally = [0u32; OP_COUNT];
    for slot in prog.slots().iter() {
        tally[slot.op().index() as usize] += 1;
    }
    assert_eq!(tally, HIST, "a real program's opcode census is not HIST");

    let x86: usize = (0..OP_COUNT)
        .map(|i| tally[i] as usize * X86_LEN[i] as usize)
        .sum();
    assert_eq!(X86_PROLOGUE + x86 + X86_EPILOGUE, ISO_CODE_BYTES);
    let arm: usize = (0..OP_COUNT)
        .map(|i| tally[i] as usize * ARM64_LEN[i] as usize)
        .sum();
    assert_eq!(
        ARM64_PROLOGUE + arm + ARM64_EPILOGUE,
        ISO_CODE_BYTES_AARCH64
    );
}

#[test]
fn same_program_emits_same_bytes() {
    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let prog = build_program(iso.fill(&mut pad, 7));
    let mut a = vec![0u8; ISO_CODE_BYTES];
    let mut b = vec![0u8; ISO_CODE_BYTES];
    emit_x86_64(&prog, (&mut a[..]).try_into().unwrap());
    emit_x86_64(&prog, (&mut b[..]).try_into().unwrap());
    assert_eq!(a, b, "the emitter is not a pure function of the program");
}

#[test]
fn release_profile_still_has_overflow_checks() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let wrapped = std::panic::catch_unwind(|| {
        let a = std::hint::black_box(u64::MAX);
        let b = std::hint::black_box(1u64);
        std::hint::black_box(a + b)
    });
    std::panic::set_hook(prev);
    assert!(
        wrapped.is_err(),
        "u64::MAX + 1 wrapped: overflow-checks is off. miner/Cargo.toml must set its own \
         [profile.release] overflow-checks = true; a nested workspace inherits nothing"
    );
}
