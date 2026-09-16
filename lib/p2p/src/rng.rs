#[derive(Clone, Copy, Debug)]
pub struct Rng {
    s: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng {
            s: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.s;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.s = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.byte();
        }
    }
}
