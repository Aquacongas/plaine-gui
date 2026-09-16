mod oracle;

use plaine_pow::{build_program, Isochron, Scratch, PROG_INSTR};
use plaine_pow_mine::{
    emit_x86_64, emit_x86_64_into, x86_slot_offsets, ISO_CODE_BYTES, X86_EPILOGUE, X86_LEN,
    X86_PROLOGUE,
};

fn locate(prog: &plaine_pow::Program, off: usize) -> String {
    if off < X86_PROLOGUE {
        return format!("prologue byte {off} of {X86_PROLOGUE}");
    }
    let bounds = x86_slot_offsets(prog);
    let body_end = bounds[PROG_INSTR] as usize;
    if off >= body_end {
        return format!(
            "epilogue byte {} of {X86_EPILOGUE}",
            off.saturating_sub(body_end)
        );
    }
    for i in 0..PROG_INSTR {
        let (lo, hi) = (bounds[i] as usize, bounds[i + 1] as usize);
        if off >= lo && off < hi {
            let slot = prog.slots()[i];
            return format!(
                "slot {i}, opcode {} (d={} s={} imm={:08x}), byte {} of {}",
                slot.op().name(),
                slot.d(),
                slot.s(),
                slot.imm(),
                off - lo,
                hi - lo
            );
        }
    }
    format!("offset {off} (unlocatable - the slot offset table is inconsistent)")
}

#[test]
fn emitted_x86_matches_oracle() {
    let v = oracle::parse();
    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let mut buf = vec![0u8; ISO_CODE_BYTES];
    let out: &mut [u8; ISO_CODE_BYTES] = (&mut buf[..]).try_into().unwrap();

    for block in &v.code {
        let ps = iso.fill(&mut pad, block.seed);
        assert_eq!(
            ps, block.progseed,
            "code block seed {:016x}: PROGRAM SEED mismatch - expected {:016x}, got {ps:016x} \
             (the fill diverged; the emitter is not implicated)",
            block.seed, block.progseed
        );
        let prog = build_program(ps);
        emit_x86_64(&prog, out);

        assert_eq!(
            out.len(),
            block.size,
            "code block seed {:016x}: emitted {} bytes, oracle emitted {}",
            block.seed,
            out.len(),
            block.size
        );

        if let Some(off) = (0..block.size).find(|&j| out[j] != block.bytes[j]) {
            let ctx_lo = off.saturating_sub(8);
            let ctx_hi = (off + 8).min(block.size);
            let hexit = |b: &[u8]| -> String {
                b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
            };
            panic!(
                "code block seed {:016x} (progseed {ps:016x}): first byte difference at \
                 offset {off} - {}\n  expected 0x{:02x}, got 0x{:02x}\n  \
                 oracle [{ctx_lo}..{ctx_hi}]: {}\n  rust   [{ctx_lo}..{ctx_hi}]: {}",
                block.seed,
                locate(&prog, off),
                block.bytes[off],
                out[off],
                hexit(&block.bytes[ctx_lo..ctx_hi]),
                hexit(&out[ctx_lo..ctx_hi]),
            );
        }
    }
}

#[test]
fn slot_offset_table_matches_emitter() {
    let v = oracle::parse();
    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let mut a = vec![0u8; ISO_CODE_BYTES];
    let mut b = vec![0u8; ISO_CODE_BYTES];
    let abuf: &mut [u8; ISO_CODE_BYTES] = (&mut a[..]).try_into().unwrap();
    let bbuf: &mut [u8; ISO_CODE_BYTES] = (&mut b[..]).try_into().unwrap();

    let ps = iso.fill(&mut pad, v.nonces[0].seed);
    let prog = build_program(ps);
    emit_x86_64(&prog, abuf);
    let bounds = x86_slot_offsets(&prog);

    assert_eq!(bounds[0] as usize, X86_PROLOGUE);
    assert_eq!(
        bounds[PROG_INSTR] as usize + X86_EPILOGUE,
        ISO_CODE_BYTES,
        "slot offsets plus epilogue must account for the whole program"
    );

    for probe in [0usize, 1, 137, 255, 511] {
        let mut slots = *prog.slots();
        let old = slots[probe];

        slots[probe] = plaine_pow::Instr::new(
            old.op(),
            old.d(),
            old.s(),
            old.imm() ^ 0x8000_0000,
        );
        let perturbed = plaine_pow::Program::from_slots(slots);
        emit_x86_64(&perturbed, bbuf);

        let off = (0..ISO_CODE_BYTES)
            .find(|&j| abuf[j] != bbuf[j])
            .unwrap_or_else(|| {
                panic!(
                    "perturbing slot {probe} ({}) changed no emitted byte - the immediate \
                     is not reaching the code",
                    old.op().name()
                )
            });
        let (lo, hi) = (bounds[probe] as usize, bounds[probe + 1] as usize);
        assert!(
            off >= lo && off < hi,
            "slot {probe} ({}) is predicted at [{lo}..{hi}) but perturbing it first \
             changed byte {off} - x86_slot_offsets disagrees with the emitter, so every \
             golden-diff failure message would point at the wrong opcode",
            old.op().name()
        );

        let last = (0..ISO_CODE_BYTES)
            .rev()
            .find(|&j| abuf[j] != bbuf[j])
            .unwrap();
        assert!(
            last < hi,
            "slot {probe} ({}) changed byte {last}, outside its predicted range \
             [{lo}..{hi}) - the expansion length depends on the immediate, which is a \
             P2 violation",
            old.op().name()
        );
    }
}

const ORACLE_SINGLE_OP_CODE_SIZE: [usize; 21] = [
    5818,
    5818,
    5818,
    7866,
    7866,
    10938,
    3770,
    3770,
    3770,
    3770,
    7354,
    7354,
    14522,
    14522,
    32442,
    14522,
    14522,
    32442,
    5818,
    12474,
    24250,
];

#[test]
fn single_opcode_matches_oracle() {
    let mut buf = vec![0u8; 64 * 1024];
    for &op in plaine_pow::ALL_OPS.iter() {
        let prog = oracle::fill_single(op, 0xC0FFEE + op.index() as u64);
        let n = emit_x86_64_into(&prog, &mut buf);
        let want = X86_PROLOGUE + PROG_INSTR * X86_LEN[op.index() as usize] as usize + X86_EPILOGUE;
        assert_eq!(
            n,
            want,
            "512-slot {} program emitted {n} bytes, X86_LEN[{}] = {} predicts {want}",
            op.name(),
            op.index(),
            X86_LEN[op.index() as usize]
        );
        assert_eq!(
            n,
            ORACLE_SINGLE_OP_CODE_SIZE[op.index() as usize],
            "512-slot {} program emitted {n} bytes, the C oracle reported {}",
            op.name(),
            ORACLE_SINGLE_OP_CODE_SIZE[op.index() as usize]
        );
    }
}
