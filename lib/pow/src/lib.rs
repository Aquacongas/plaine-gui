#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod aes;
mod consts;
mod fill;
mod interp;
mod op;
mod program;
mod rng;
mod scratch;

pub use consts::{
    AESKEY, BLOCKS, BLOCK_INSTR, C1, C2, FILL_DOM, HIST, LINE_MASK, LOOPS, MULT, NREG, PER_BLOCK,
    PROG_INSTR, RNG_DOM_PROGRAM, RNG_DOM_SINGLE, ROLE_OFFS, SCRATCH_BYTES, SCRATCH_MASK,
    SCRATCH_WORDS,
};
pub use op::{Class, Op, ALL_OPS, ALU_POOL, MEM_POOL, MUL_POOL, OP_COUNT, ROTREG_POOL, ROT_POOL};
pub use program::{build_program, Instr, Program};
pub use rng::Rng;
pub use scratch::Scratch;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PowError {
    NoHardwareAes,

    PlatformHashMismatch { seed: u64, expected: u64, got: u64 },
}

impl core::fmt::Display for PowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PowError::NoHardwareAes => write!(
                f,
                "Isochron v1 requires hardware AES (AES-NI on x86-64, ARMv8 crypto on aarch64)"
            ),
            PowError::PlatformHashMismatch {
                seed,
                expected,
                got,
            } => write!(
                f,
                "platform hash mismatch: seed {seed:016x} expected {expected:016x} got {got:016x}"
            ),
        }
    }
}

impl std::error::Error for PowError {}

#[derive(Clone, Copy, Debug)]
pub struct Isochron(());

impl Isochron {
    pub fn new() -> Result<Self, PowError> {
        if aes::detect() {
            Ok(Isochron(()))
        } else {
            Err(PowError::NoHardwareAes)
        }
    }

    pub fn verify_hash(self, pad: &mut Scratch, seed: u64) -> u64 {
        let ps = self.fill(pad, seed);
        let prog = build_program(ps);
        self.interp(&prog, pad, seed)
    }

    pub fn fill(self, pad: &mut Scratch, seed: u64) -> u64 {
        // SAFETY: an Isochron only exists once aes::detect() has said yes.
        unsafe { fill::fill(pad.words_mut(), seed) }
    }

    pub fn fill_ref(self, pad: &mut Scratch, seed: u64) -> u64 {
        // SAFETY: aes present - Isochron::new checked it.
        unsafe { fill::fill_ref(pad.words_mut(), seed) }
    }

    pub fn interp(self, prog: &Program, pad: &mut Scratch, seed: u64) -> u64 {
        // SAFETY: same aes guarantee the other two rely on.
        unsafe { interp::interp(prog, pad.words_mut(), seed) }
    }
}

// (seed, digest) pairs baked in: a bad cpu or a miscompile trips here, not on-chain.
// must match the vector file.
pub const SELF_CHECK: [(u64, u64); 8] = [
    (0x243f_6a88_85a3_08d3, 0x9f5a_a169_a464_943a),
    (0xc276_e442_04ed_84e8, 0xf6ba_bd7c_f0d3_9924),
    (0x60ae_5dfb_8438_00fd, 0x3199_a8a5_476c_7284),
    (0xfee5_d7b5_0382_7d12, 0x26a7_5c20_47c8_5663),
    (0xa1c4_cd8e_ab96_973e, 0xfea2_78ff_5083_daf7),
    (0xbd81_aa4e_50d4_a1be, 0xd073_8712_9035_749d),
    (0xd93e_870d_f612_ac3e, 0xc3bc_c13f_9e36_bc53),
    (0xf4fb_63cd_9b50_b6be, 0x57cc_cb8a_fb5f_b07f),
];

pub fn platform_self_check() -> Result<(), PowError> {
    let iso = Isochron::new()?;
    let mut pad = Scratch::new();
    for &(seed, expected) in SELF_CHECK.iter() {
        let got = iso.verify_hash(&mut pad, seed);
        if got != expected {
            return Err(PowError::PlatformHashMismatch {
                seed,
                expected,
                got,
            });
        }
    }
    Ok(())
}
