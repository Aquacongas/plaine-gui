use crate::consts::{MULT, SCRATCH_BYTES, SCRATCH_WORDS};

const ALIGN_BYTES: usize = 65_536;
const ALIGN_WORDS: usize = ALIGN_BYTES / 8;

pub struct Scratch {
    buf: Box<[u64]>,
    off: usize,
}

impl Scratch {
    pub fn new() -> Self {
        // over-allocate by one alignment so the 64 KiB-aligned window always fits.
        let buf = vec![0u64; SCRATCH_WORDS + ALIGN_WORDS].into_boxed_slice();
        let base = buf.as_ptr() as usize;
        let pad_start = base.next_multiple_of(ALIGN_BYTES);
        let off = (pad_start - base) / 8;
        debug_assert!(off <= ALIGN_WORDS);
        Scratch { buf, off }
    }

    pub fn words(&self) -> &[u64; SCRATCH_WORDS] {
        self.buf[self.off..self.off + SCRATCH_WORDS]
            .try_into()
            .expect("scratch window is SCRATCH_WORDS long by construction")
    }

    pub fn words_mut(&mut self) -> &mut [u64; SCRATCH_WORDS] {
        (&mut self.buf[self.off..self.off + SCRATCH_WORDS])
            .try_into()
            .expect("scratch window is SCRATCH_WORDS long by construction")
    }

    pub fn as_mut_ptr(&mut self) -> *mut u64 {
        self.words_mut().as_mut_ptr()
    }

    pub fn checksum(&self) -> u64 {
        let mut h = 0u64;
        for &w in self.words().iter() {
            h = (h ^ w).wrapping_mul(MULT);
        }
        h
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scratch")
            .field("bytes", &SCRATCH_BYTES)
            .finish()
    }
}
