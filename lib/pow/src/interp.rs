#![deny(clippy::arithmetic_side_effects)]

use crate::aes::aesenc;
use crate::consts::{C1, C2, LINE_MASK, LOOPS, MULT, NREG, SCRATCH_MASK, SCRATCH_WORDS};
use crate::op::Op;
use crate::program::Program;

// Mix operand with key, keep the high bits (>>40 drops the low, less-mixed ones),
// then mask to an aligned in-bounds offset.
#[inline(always)]
fn addr_of(v: u64, k: u32) -> u64 {
    ((v ^ (k as u64)).wrapping_mul(MULT) >> 40) & SCRATCH_MASK
}

#[inline(always)]
fn line_of(v: u64, k: u32) -> u64 {
    ((v ^ (k as u64)).wrapping_mul(MULT) >> 40) & LINE_MASK
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn interp(prog: &Program, sc: &mut [u64; SCRATCH_WORDS], seed: u64) -> u64 {
    let mut r = [0u64; NREG];
    for (i, e) in r.iter_mut().enumerate() {
        let i = i as u64;
        *e = seed
            .wrapping_mul(2u64.wrapping_mul(i).wrapping_add(1))
            .wrapping_add(i);
    }

    let slots = prog.slots();

    for lp in 0..LOOPS {
        for slot in slots.iter() {
            let d = slot.d() as usize;
            let s = slot.s() as usize;
            let imm = slot.imm();
            let immw = imm as u64;
            // odd shift amount, never 0 (a rotate-by-0 slot would be dead).
            let k = (imm & 63) | 1;

            match slot.op() {
                Op::Add => {
                    r[d] = r[d].wrapping_add(r[s]);
                    r[d] ^= immw;
                }
                Op::Sub => {
                    r[d] = r[d].wrapping_sub(r[s]);
                    r[d] ^= immw;
                }
                Op::Xor => {
                    r[d] ^= r[s];
                    r[d] = r[d].wrapping_add(immw);
                }

                Op::Or => r[d] = r[d].rotate_left(17) ^ (r[s] | immw),
                Op::And => r[d] = r[d].rotate_left(23) ^ (r[s] & immw),
                Op::Andn => r[d] = r[d].rotate_left(29) ^ ((!r[s]) & immw),
                Op::Rolx => r[d] = r[d].rotate_left(k) ^ r[s],
                Op::Rola => r[d] = r[d].rotate_left(k).wrapping_add(r[s]),
                Op::Rorx => r[d] = r[d].rotate_right(k) ^ r[s],
                Op::Rora => r[d] = r[d].rotate_right(k).wrapping_add(r[s]),
                Op::Vrol => r[d] = r[d].rotate_left((r[s] & 63) as u32) ^ immw,
                Op::Vror => r[d] = r[d].rotate_right((r[s] & 63) as u32).wrapping_add(immw),

                Op::Load => {
                    let a = addr_of(r[s], imm ^ C1);
                    r[d] ^= sc[(a >> 3) as usize];
                }
                Op::Store => {
                    let a = addr_of(r[d], imm ^ C1);
                    let w = (a >> 3) as usize;
                    sc[w] = sc[w].wrapping_add(r[s]);
                }
                Op::Rmw => {
                    let a = addr_of(r[s], imm ^ C1);
                    let w = (a >> 3) as usize;
                    let v = sc[w].wrapping_add(r[d]);
                    sc[w] = v;

                    let b = addr_of(v, C2);
                    r[d] ^= sc[(b >> 3) as usize];
                }

                Op::Loadb => {
                    let a = addr_of(r[s], imm ^ C2);
                    r[d] ^= sc[(a >> 3) as usize];
                }
                Op::Storeb => {
                    let a = addr_of(r[d], imm ^ C2);
                    let w = (a >> 3) as usize;
                    sc[w] = sc[w].wrapping_add(r[s]);
                }
                Op::Rmwb => {
                    let a = addr_of(r[s], imm ^ C2);
                    let w = (a >> 3) as usize;
                    let v = sc[w] ^ r[d];
                    sc[w] = v;

                    let b = addr_of(v, C1);
                    r[d] = r[d].wrapping_add(sc[(b >> 3) as usize]);
                }

                // |1 keeps the multiplier odd, hence invertible.
                Op::Mullo => r[d] = r[d].wrapping_mul(r[s] | 1),
                Op::Mulhi => {
                    let t = (r[d] as u128).wrapping_mul((r[s] | 1) as u128);

                    r[d] = ((t >> 64) as u64) ^ immw;
                }

                Op::Aesr => {
                    let a = line_of(r[s], imm ^ C1);
                    let w = (a >> 3) as usize;

                    debug_assert_eq!(w & 1, 0, "AESR line address must be 16-byte aligned");

                    // SAFETY: aes gate on the enclosing fn.
                    let v = unsafe { aesenc([sc[w], sc[w | 1]]) };
                    sc[w] = v[0];
                    sc[w | 1] = v[1];
                    r[d] ^= sc[w];
                }
            }
        }

        // mix the loop counter in - stops iterations collapsing together.
        r[0] ^= lp as u64;
    }

    let mut out = 0u64;
    for &v in r.iter() {
        out ^= v;
    }
    out
}
