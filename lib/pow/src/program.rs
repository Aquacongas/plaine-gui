use crate::consts::{BLOCKS, BLOCK_INSTR, NREG, PER_BLOCK, PROG_INSTR, RNG_DOM_PROGRAM, ROLE_OFFS};
use crate::op::{Op, ALU_POOL, MEM_POOL, MUL_POOL, ROTREG_POOL, ROT_POOL};
use crate::rng::Rng;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Instr {
    op: Op,
    d: u8,
    s: u8,
    imm: u32,
}

impl Instr {
    pub const fn new(op: Op, d: u8, s: u8, imm: u32) -> Self {
        Instr {
            op,
            d: d & 7,
            s: s & 7,
            imm,
        }
    }

    pub const fn op(self) -> Op {
        self.op
    }

    pub const fn d(self) -> u8 {
        self.d
    }

    pub const fn s(self) -> u8 {
        self.s
    }

    pub const fn imm(self) -> u32 {
        self.imm
    }
}

#[derive(Clone, Copy)]
pub struct Program([Instr; PROG_INSTR]);

impl Program {
    pub fn slots(&self) -> &[Instr; PROG_INSTR] {
        &self.0
    }

    pub const fn from_slots(slots: [Instr; PROG_INSTR]) -> Self {
        Program(slots)
    }
}

impl core::fmt::Debug for Program {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Program")
            .field("slots", &PROG_INSTR)
            .finish()
    }
}

pub fn build_program(prog_seed: u64) -> Program {
    let mut n = Rng::new(prog_seed, RNG_DOM_PROGRAM);

    let mut ctr = [0u32; 6];
    let mut prog = [Instr::new(Op::Add, 0, 0, 0); PROG_INSTR];

    for b in 0..BLOCKS {
        let mut idx = [0u8; BLOCK_INSTR];
        for (i, e) in idx.iter_mut().enumerate() {
            *e = i as u8;
        }
        // fisher-yates over the block. PER_BLOCK's class mix stays fixed, only placement moves.
        for i in (1..BLOCK_INSTR).rev() {
            let j = (n.next() % (i as u64 + 1)) as usize;
            idx.swap(i, j);
        }

        for i in 0..BLOCK_INSTR {
            let t = idx[i] as usize;
            let k = PER_BLOCK[t] as usize;
            let dr = t % NREG;

            // fixed nonzero offset from d - a slot never has d == s.
            let sr = (dr + ROLE_OFFS[t % 8] as usize) % NREG;

            // round-robin per class; pins the opcode histogram identical across seeds (see HIST).
            let op = match k {
                0 => ALU_POOL[(ctr[0] % 6) as usize],
                1 => ROT_POOL[(ctr[1] % 4) as usize],
                2 => ROTREG_POOL[(ctr[2] & 1) as usize],
                3 => MEM_POOL[(ctr[3] % 6) as usize],
                4 => MUL_POOL[(ctr[4] & 1) as usize],
                _ => Op::Aesr,
            };
            ctr[k] = ctr[k].wrapping_add(1);

            prog[b * BLOCK_INSTR + i] = Instr::new(op, dr as u8, sr as u8, n.next() as u32);
        }
    }

    Program(prog)
}
