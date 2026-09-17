pub const SCRATCH_BYTES: u32 = 65_536;

pub const SCRATCH_WORDS: usize = (SCRATCH_BYTES / 8) as usize;

// -8 masks a u64 in bounds and word-aligned, -16 a 16-byte aes line. both rely
// on SCRATCH_BYTES being a power of two.
pub const SCRATCH_MASK: u64 = (SCRATCH_BYTES - 8) as u64;

pub const LINE_MASK: u64 = (SCRATCH_BYTES - 16) as u64;

const _: () = assert!(
    SCRATCH_BYTES.is_power_of_two(),
    "SCRATCH_BYTES must be a power of two"
);

pub const LOOPS: u32 = 1024;

pub const BLOCKS: usize = 32;

pub const BLOCK_INSTR: usize = 16;

pub const PROG_INSTR: usize = BLOCKS * BLOCK_INSTR;

const _: () = assert!(PROG_INSTR == 512);

pub const NREG: usize = 8;

pub const MULT: u64 = 0x9E37_79B9_7F4A_7C15;

pub const C1: u32 = 0x6A09_E667;

pub const C2: u32 = 0xBB67_AE85;

pub const FILL_DOM: u64 = 0x1F83_D9AB_5BE0_CD19;

pub const AESKEY: [u8; 16] = [
    0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A, 0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C,
];

pub const PER_BLOCK: [u8; BLOCK_INSTR] = [0, 0, 0, 0, 0, 0, 1, 2, 3, 3, 3, 3, 3, 4, 5, 5];

pub const ROLE_OFFS: [u8; 8] = [3, 5, 1, 7, 2, 6, 4, 5];

pub const RNG_DOM_PROGRAM: u64 = 2;

pub const RNG_DOM_SINGLE: u64 = 7;

// per-opcode slot counts, the same for every seed - build_program's round-robin pins them.
pub const HIST: [u32; 21] = [
    32, 32, 32, 32, 32, 32, 8, 8, 8, 8, 16, 16, 27, 27, 27, 27, 26, 26, 16, 16, 64,
];

const fn sum_u32(xs: &[u32]) -> u32 {
    let mut i = 0;
    let mut acc = 0u32;
    while i < xs.len() {
        acc += xs[i];
        i += 1;
    }
    acc
}

const _: () = assert!(
    sum_u32(&HIST) as usize == PROG_INSTR,
    "HIST must cover every program slot"
);

#[cfg(target_endian = "big")]
compile_error!("Isochron v1 is defined over little-endian byte strings; big-endian is unsupported");
