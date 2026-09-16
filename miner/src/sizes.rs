use plaine_pow::{HIST, OP_COUNT, PROG_INSTR};

const fn weighted(len: &[u32; OP_COUNT]) -> usize {
    let mut i = 0;
    let mut acc = 0usize;
    while i < OP_COUNT {
        acc += (HIST[i] as usize) * (len[i] as usize);
        i += 1;
    }
    acc
}

// encoded length in bytes of each opcode's x86-64 body; must match what emit_x86 writes and the
// C oracle measured, so a change here is consensus-visible.
pub const X86_LEN: [u32; OP_COUNT] = [
    11,
    11,
    11,
    15,
    15,
    21,
    7,
    7,
    7,
    7,
    14,
    14,
    28,
    28,
    63,
    28,
    28,
    63,
    11,
    24,
    47,
];

pub const X86_PROLOGUE: usize = 10 + 10 + 4 + (8 * 7 + 7 * 7) + 3;

pub const X86_EPILOGUE: usize = 3 + 3 + 7 + 6 + 3 + 21 + 11;

pub const ISO_CODE_BYTES: usize = X86_PROLOGUE + weighted(&X86_LEN) + X86_EPILOGUE;

const _: () = assert!(X86_PROLOGUE == 132);
const _: () = assert!(X86_EPILOGUE == 54);
const _: () = assert!(
    ISO_CODE_BYTES == 13449,
    "emitted x86-64 code size no longer matches the C oracle's 13449 bytes. \
     Either an encoding changed length or the frozen opcode histogram moved; \
     both are consensus-visible and neither is a test to relax."
);

pub const ARM64_LEN: [u32; OP_COUNT] = [
    16,
    16,
    16,
    20,
    20,
    20,
    8,
    8,
    8,
    8,
    20,
    16,
    32,
    36,
    68,
    32,
    36,
    68,
    8,
    20,
    52,
];

pub const ARM64_PROLOGUE: usize = 20 + 4 + 4 + 4 + 16 + 16 + (8 * 12 + 7 * 4) + 4;

pub const ARM64_EPILOGUE: usize = 16 + 32 + 20 + 4;

pub const ISO_CODE_BYTES_AARCH64: usize =
    ARM64_PROLOGUE + weighted(&ARM64_LEN) + ARM64_EPILOGUE;

const _: () = assert!(ARM64_PROLOGUE == 192);
const _: () = assert!(ARM64_EPILOGUE == 72);
const _: () = assert!(ISO_CODE_BYTES_AARCH64 % 4 == 0, "A64 instructions are 4 bytes");

const _: () = assert!(ISO_CODE_BYTES_AARCH64 == 15568);

// 32 slots of 16 KiB each is exactly one 2 MiB region, so a full batch maps onto a single huge page.
pub const BATCH: usize = 32;

pub const SLOT_BYTES: usize = 16_384;

pub const REGION_BYTES: usize = BATCH * SLOT_BYTES;

const _: () = assert!(ISO_CODE_BYTES <= SLOT_BYTES);
const _: () = assert!(ISO_CODE_BYTES_AARCH64 <= SLOT_BYTES);
const _: () = assert!(SLOT_BYTES % 4_096 == 0);
const _: () = assert!(REGION_BYTES % 65_536 == 0);
const _: () = assert!(ISO_CODE_BYTES <= REGION_BYTES);
const _: () = assert!(ISO_CODE_BYTES_AARCH64 <= REGION_BYTES);

pub fn x86_slot_offsets(prog: &plaine_pow::Program) -> [u32; PROG_INSTR + 1] {
    let mut off = [0u32; PROG_INSTR + 1];
    off[0] = X86_PROLOGUE as u32;
    for (i, slot) in prog.slots().iter().enumerate() {
        off[i + 1] = off[i] + X86_LEN[slot.op().index() as usize];
    }
    off
}
