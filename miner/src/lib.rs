#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod client;
mod emit_arm64;
mod emit_x86;
pub mod pad;
mod page;
mod sizes;

pub use emit_arm64::{emit_aarch64, emit_aarch64_into};
pub use emit_x86::{emit_x86_64, emit_x86_64_into};
pub use pad::{PadPages, Pads};
pub use page::{CodeW, CodeX, Protection};
pub use sizes::{
    x86_slot_offsets, ARM64_EPILOGUE, ARM64_LEN, ARM64_PROLOGUE, BATCH, ISO_CODE_BYTES,
    ISO_CODE_BYTES_AARCH64, REGION_BYTES, SLOT_BYTES, X86_EPILOGUE, X86_LEN, X86_PROLOGUE,
};

use plaine_pow::{build_program, Isochron, PowError, Program, Scratch};

#[cfg(target_arch = "x86_64")]
pub const NATIVE_CODE_BYTES: usize = ISO_CODE_BYTES;

#[cfg(target_arch = "aarch64")]
pub const NATIVE_CODE_BYTES: usize = ISO_CODE_BYTES_AARCH64;

#[cfg(target_arch = "x86_64")]
pub fn emit_native(prog: &Program, out: &mut [u8; NATIVE_CODE_BYTES]) {
    emit_x86_64(prog, out)
}

#[cfg(target_arch = "aarch64")]
pub fn emit_native(prog: &Program, out: &mut [u8; NATIVE_CODE_BYTES]) {
    emit_aarch64(prog, out)
}

#[cfg(target_arch = "x86_64")]
pub fn emit_native_into(prog: &Program, out: &mut [u8]) -> usize {
    emit_x86_64_into(prog, out)
}

#[cfg(target_arch = "aarch64")]
pub fn emit_native_into(prog: &Program, out: &mut [u8]) -> usize {
    emit_aarch64_into(prog, out)
}

static AES_KEY: [u8; 16] = plaine_pow::AESKEY;

#[derive(Debug)]
pub enum MineError {
    Pow(PowError),
    Map(std::io::Error),
}

impl core::fmt::Display for MineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MineError::Pow(e) => write!(f, "{e}"),
            MineError::Map(e) => write!(f, "could not map W^X code memory: {e}"),
        }
    }
}

impl std::error::Error for MineError {}

impl From<PowError> for MineError {
    fn from(e: PowError) -> Self {
        MineError::Pow(e)
    }
}
impl From<std::io::Error> for MineError {
    fn from(e: std::io::Error) -> Self {
        MineError::Map(e)
    }
}

pub struct Miner {
    code: Option<CodeW>,
    iso: Isochron,
}

impl Miner {
    pub fn new() -> Result<Self, MineError> {
        Ok(Miner {
            code: Some(CodeW::new()?),
            iso: Isochron::new()?,
        })
    }

    pub fn run(&mut self, prog: &Program, pad: &mut Scratch, seed: u64) -> Result<u64, MineError> {
        let mut w = self
            .code
            .take()
            .expect("this Miner was poisoned by an earlier page-protection failure");

        let n = emit_native_into(prog, w.region_mut());
        debug_assert!(n <= REGION_BYTES);
        let x = w.seal()?;

        // SAFETY: we emitted a full program into w before sealing, so x is code we wrote.
        let digest = unsafe { x.call(pad, seed, &AES_KEY) };
        self.code = Some(x.unseal()?);
        Ok(digest)
    }

    pub fn mine_hash(&mut self, pad: &mut Scratch, seed: u64) -> Result<u64, MineError> {
        let prog_seed = self.iso.fill(pad, seed);
        let prog = build_program(prog_seed);
        self.run(&prog, pad, seed)
    }

    pub fn mine_hash_batch(
        &mut self,
        pads: &mut [Scratch],
        seeds: &[u64],
        out: &mut [u64],
    ) -> Result<(), MineError> {
        let k = seeds.len();
        assert!(k <= BATCH, "batch of {k} exceeds BATCH = {BATCH}");
        assert!(
            pads.len() == k && out.len() == k,
            "mine_hash_batch: pads ({}), seeds ({k}) and out ({}) must be parallel",
            pads.len(),
            out.len()
        );

        let mut w = self
            .code
            .take()
            .expect("this Miner was poisoned by an earlier page-protection failure");

        // fill every slot writable, seal once. a per-nonce flip contends on mprotect and cost 3.65x
        // on a 32-core EPYC; going RWX would dodge that but we don't.
        for j in 0..k {
            let prog_seed = self.iso.fill(&mut pads[j], seeds[j]);
            let prog = build_program(prog_seed);
            emit_native(&prog, w.slot_mut(j));
        }
        let x = w.seal()?;
        for j in 0..k {
            // SAFETY: slot j got a full program from emit_native above.
            out[j] = unsafe { x.call_slot(j, &mut pads[j], seeds[j], &AES_KEY) };
        }
        self.code = Some(x.unseal()?);
        Ok(())
    }

    pub fn mine_hash_batch_on(
        &mut self,
        pads: &mut Pads,
        seeds: &[u64],
        out: &mut [u64],
    ) -> Result<(), MineError> {
        let k = seeds.len();
        assert!(k <= BATCH, "batch of {k} exceeds BATCH = {BATCH}");
        assert!(
            pads.len() >= k && out.len() == k,
            "mine_hash_batch_on: {} pads and {} outputs for {k} seeds",
            pads.len(),
            out.len()
        );

        let mut w = self
            .code
            .take()
            .expect("this Miner was poisoned by an earlier page-protection failure");

        for (j, &seed) in seeds.iter().enumerate() {
            let prog_seed = pads.fill(self.iso, j, seed);
            let prog = build_program(prog_seed);
            emit_native(&prog, w.slot_mut(j));
        }
        let x = w.seal()?;
        for j in 0..k {
            // SAFETY: slot j is a full program; slot_ptr(j) is pad j's own live window.
            out[j] = unsafe { x.call_slot_ptr(j, pads.slot_ptr(j), seeds[j], &AES_KEY) };
        }
        self.code = Some(x.unseal()?);
        Ok(())
    }

    pub fn isochron(&self) -> Isochron {
        self.iso
    }

    pub fn protection(&self) -> Option<Protection> {
        self.code.as_ref().map(|c| c.protection())
    }
}

#[cfg(test)]
mod batch_on_pads {
    use super::*;
    use plaine_pow::{Scratch, SCRATCH_WORDS};

    const STRIDE: u64 = 0x9E37_79B9_7F4A_7C15;
    const FIRST: u64 = 0x0123_4567_89AB_CDEF;

    #[test]
    fn agrees_with_interpreter() {
        let Ok(mut miner) = Miner::new() else {
            eprintln!("no hardware AES or no mappable region here; skipping");
            return;
        };
        let iso = miner.isochron();
        let mut pads = Pads::new(BATCH, true).expect("map the pads");
        let mut ref_pad = Scratch::new();
        let mut seeds = vec![0u64; BATCH];
        let mut digests = vec![0u64; BATCH];

        let mut seed = FIRST;
        for _batch in 0..20 {
            for slot in seeds.iter_mut() {
                *slot = seed;
                seed = seed.wrapping_add(STRIDE);
            }
            miner
                .mine_hash_batch_on(&mut pads, &seeds, &mut digests)
                .expect("batch over mapped pads");

            for j in 0..BATCH {
                let want = iso.verify_hash(&mut ref_pad, seeds[j]);
                assert_eq!(
                    digests[j], want,
                    "digest mismatch in slot {j} (seed {:016x}): batch {:016x} vs interpreter {want:016x}",
                    seeds[j], digests[j]
                );

                let got = pads.words(j);
                if let Some(i) = (0..SCRATCH_WORDS).find(|&i| got[i] != ref_pad.words()[i]) {
                    let n = (0..SCRATCH_WORDS)
                        .filter(|&i| got[i] != ref_pad.words()[i])
                        .count();
                    panic!(
                        "pad {j} (seed {:016x}) differs at word {i}: {:016x} vs {:016x} ({n}/{SCRATCH_WORDS} words)",
                        seeds[j], got[i], ref_pad.words()[i]
                    );
                }
                assert_eq!(pads.checksum(j), ref_pad.checksum(), "padck differs in slot {j}");
            }
        }
    }

    #[test]
    fn matches_scratch_batch_slot_for_slot() {
        let Ok(mut miner) = Miner::new() else {
            eprintln!("no hardware AES or no mappable region here; skipping");
            return;
        };
        let mut mapped = Pads::new(BATCH, true).expect("map the pads");
        let mut heap: Vec<Scratch> = (0..BATCH).map(|_| Scratch::new()).collect();
        let mut seeds = vec![0u64; BATCH];
        let mut a = vec![0u64; BATCH];
        let mut b = vec![0u64; BATCH];

        let mut seed = FIRST ^ STRIDE;
        for _batch in 0..4 {
            for slot in seeds.iter_mut() {
                *slot = seed;
                seed = seed.wrapping_add(STRIDE);
            }
            miner.mine_hash_batch_on(&mut mapped, &seeds, &mut a).expect("mapped");
            miner.mine_hash_batch(&mut heap, &seeds, &mut b).expect("scratch");
            assert_eq!(a, b, "the mapped-pad batch and the Scratch batch disagree");
            for (j, h) in heap.iter().enumerate() {
                assert_eq!(
                    mapped.words(j),
                    h.words(),
                    "slot {j}: post-run pads differ between the two batch paths"
                );
            }
        }
    }

    #[test]
    fn partial_batch_touches_k_pads() {
        let Ok(mut miner) = Miner::new() else {
            eprintln!("no hardware AES or no mappable region here; skipping");
            return;
        };
        for k in [1usize, 2, 7, BATCH - 1] {
            let mut pads = Pads::new(BATCH, false).expect("map the pads");
            let seeds: Vec<u64> = (0..k).map(|i| FIRST ^ (i as u64)).collect();
            let mut out = vec![0u64; k];
            miner.mine_hash_batch_on(&mut pads, &seeds, &mut out).expect("partial batch");

            let mut want_pad = Scratch::new();
            for j in 0..k {
                let want = miner.isochron().verify_hash(&mut want_pad, seeds[j]);
                assert_eq!(out[j], want, "k={k}, slot {j}");
            }
            for j in k..BATCH {
                assert!(
                    pads.words(j).iter().all(|&w| w == 0),
                    "k={k}: pad {j} was written although only {k} nonces were asked for"
                );
            }
        }
    }
}
