#![deny(clippy::arithmetic_side_effects)]

#[derive(Clone, Debug)]
pub struct Rng {
    s0: u64,
}

const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
const MIX1: u64 = 0xBF58_476D_1CE4_E5B9;
const MIX2: u64 = 0x94D0_49BB_1331_11EB;
const DOM_MULT: u64 = 0xD6E8_FEB8_6659_FD93;

impl Rng {
    pub fn new(seed: u64, dom: u64) -> Self {
        let mut r = Rng {
            s0: seed ^ dom.wrapping_mul(DOM_MULT),
        };

        // splitmix64. burn a few so adjacent seeds don't start correlated.
        for _ in 0..4 {
            r.next();
        }
        r
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        let x = self.s0.wrapping_add(GAMMA);
        self.s0 = x;
        let mut x = x;
        x ^= x >> 30;
        x = x.wrapping_mul(MIX1);
        x ^= x >> 27;
        x = x.wrapping_mul(MIX2);
        x ^ (x >> 31)
    }
}
