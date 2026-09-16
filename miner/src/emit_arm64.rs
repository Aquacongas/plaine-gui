use plaine_pow::{Instr, Op, Program, C1, C2, LINE_MASK, LOOPS, MULT, NREG, SCRATCH_MASK};

use crate::sizes::{ARM64_EPILOGUE, ARM64_LEN, ARM64_PROLOGUE, ISO_CODE_BYTES_AARCH64};

const RMAP: [u32; NREG] = [19, 20, 21, 22, 23, 24, 25, 26];

const A_SC: u32 = 27;
const A_MULT: u32 = 28;
const A_MSK: u32 = 11;
const A_LMSK: u32 = 13;
const A_T0: u32 = 9;
const A_T1: u32 = 10;
const A_T2: u32 = 14;
const A_LOOP: u32 = 12;
const A_ZR: u32 = 31;

struct Emitter<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Emitter<'_> {
    fn ei(&mut self, w: u32) {
        let b = self.at * 4;
        self.buf[b..b + 4].copy_from_slice(&w.to_le_bytes());
        self.at += 1;
    }

    fn a_and(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0x8A00_0000 | (m << 16) | (n << 5) | d);
    }

    fn a_bic(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0x8A20_0000 | (m << 16) | (n << 5) | d);
    }

    fn a_orr(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0xAA00_0000 | (m << 16) | (n << 5) | d);
    }

    fn a_eor(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0xCA00_0000 | (m << 16) | (n << 5) | d);
    }

    fn a_add(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0x8B00_0000 | (m << 16) | (n << 5) | d);
    }

    fn a_sub(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0xCB00_0000 | (m << 16) | (n << 5) | d);
    }

    fn a_mov(&mut self, d: u32, m: u32) {
        self.a_orr(d, A_ZR, m);
    }

    fn a_neg(&mut self, d: u32, m: u32) {
        self.a_sub(d, A_ZR, m);
    }

    fn a_addi(&mut self, d: u32, n: u32, imm12: u32) {
        self.ei(0x9100_0000 | ((imm12 & 0xFFF) << 10) | (n << 5) | d);
    }

    fn a_cmpi(&mut self, n: u32, imm12: u32) {
        self.ei(0xF100_0000 | ((imm12 & 0xFFF) << 10) | (n << 5) | A_ZR);
    }

    fn a_movz(&mut self, d: u32, v: u16, hw: u32) {
        self.ei(0xD280_0000 | (hw << 21) | ((v as u32) << 5) | d);
    }

    fn a_movk(&mut self, d: u32, v: u16, hw: u32) {
        self.ei(0xF280_0000 | (hw << 21) | ((v as u32) << 5) | d);
    }

    fn a_imm32(&mut self, d: u32, v: u32) {
        self.a_movz(d, v as u16, 0);
        self.a_movk(d, (v >> 16) as u16, 1);
    }

    fn a_imm64(&mut self, d: u32, v: u64) {
        self.a_movz(d, v as u16, 0);
        self.a_movk(d, (v >> 16) as u16, 1);
        self.a_movk(d, (v >> 32) as u16, 2);
        self.a_movk(d, (v >> 48) as u16, 3);
    }

    fn a_ror_i(&mut self, d: u32, n: u32, k: u32) {
        self.ei(0x93C0_0000 | (n << 16) | ((k & 63) << 10) | (n << 5) | d);
    }

    fn a_ror_r(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0x9AC0_2C00 | (m << 16) | (n << 5) | d);
    }

    fn a_lsr_i(&mut self, d: u32, n: u32, k: u32) {
        self.ei(0xD340_0000 | ((k & 63) << 16) | (63 << 10) | (n << 5) | d);
    }

    fn a_mul(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0x9B00_7C00 | (m << 16) | (n << 5) | d);
    }

    fn a_umulh(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0x9BC0_7C00 | (m << 16) | (n << 5) | d);
    }

    fn a_orr1(&mut self, d: u32, n: u32) {
        self.ei(0xB240_0000 | (n << 5) | d);
    }

    fn a_umov_d0(&mut self, xd: u32, vn: u32) {
        self.ei(0x4E08_3C00 | (vn << 5) | xd);
    }

    fn a_ldr(&mut self, t: u32, base: u32, idx: u32) {
        self.ei(0xF860_6800 | (idx << 16) | (base << 5) | t);
    }

    fn a_str(&mut self, t: u32, base: u32, idx: u32) {
        self.ei(0xF820_6800 | (idx << 16) | (base << 5) | t);
    }

    fn a_ldr_q(&mut self, t: u32, base: u32, idx: u32) {
        self.ei(0x3CE0_6800 | (idx << 16) | (base << 5) | t);
    }

    fn a_str_q(&mut self, t: u32, base: u32, idx: u32) {
        self.ei(0x3CA0_6800 | (idx << 16) | (base << 5) | t);
    }

    fn a_ldr_q_off(&mut self, t: u32, base: u32, imm12: u32) {
        self.ei(0x3DC0_0000 | (imm12 << 10) | (base << 5) | t);
    }

    fn a_aese(&mut self, d: u32, n: u32) {
        self.ei(0x4E28_4800 | (n << 5) | d);
    }

    fn a_aesmc(&mut self, d: u32, n: u32) {
        self.ei(0x4E28_6800 | (n << 5) | d);
    }

    fn a_veor(&mut self, d: u32, n: u32, m: u32) {
        self.ei(0x6E20_1C00 | (m << 16) | (n << 5) | d);
    }

    fn a_movi0(&mut self, d: u32) {
        self.ei(0x4F00_0400 | d);
    }

    fn a_stp_pre(&mut self, t1: u32, t2: u32) {
        self.ei(0xA980_0000 | (0x7E << 15) | (t2 << 10) | (31 << 5) | t1);
    }

    fn a_ldp_post(&mut self, t1: u32, t2: u32) {
        self.ei(0xA8C0_0000 | (0x02 << 15) | (t2 << 10) | (31 << 5) | t1);
    }

    fn a_addr(&mut self, src: u32, k: u32, maskreg: u32, tmp: u32) {
        debug_assert_ne!(src, tmp, "a_addr clobbers tmp before reading src");
        debug_assert_ne!(src, A_T0, "a_addr writes its result to x9");
        self.a_imm32(tmp, k);
        self.a_eor(A_T0, src, tmp);
        self.a_mul(A_T0, A_T0, A_MULT);
        self.a_lsr_i(A_T0, A_T0, 40);
        self.a_and(A_T0, A_T0, maskreg);
    }
}

fn emit_one(e: &mut Emitter<'_>, in_: &Instr) {
    let d = RMAP[in_.d() as usize];
    let s = RMAP[in_.s() as usize];
    let imm = in_.imm();
    let k = (imm & 63) | 1;

    match in_.op() {
        Op::Add => {
            e.a_add(d, d, s);
            e.a_imm32(A_T0, imm);
            e.a_eor(d, d, A_T0);
        }
        Op::Sub => {
            e.a_sub(d, d, s);
            e.a_imm32(A_T0, imm);
            e.a_eor(d, d, A_T0);
        }
        Op::Xor => {
            e.a_eor(d, d, s);
            e.a_imm32(A_T0, imm);
            e.a_add(d, d, A_T0);
        }

        Op::Or => {
            e.a_ror_i(d, d, 64 - 17);
            e.a_imm32(A_T0, imm);
            e.a_orr(A_T0, s, A_T0);
            e.a_eor(d, d, A_T0);
        }
        Op::And => {
            e.a_ror_i(d, d, 64 - 23);
            e.a_imm32(A_T0, imm);
            e.a_and(A_T0, s, A_T0);
            e.a_eor(d, d, A_T0);
        }
        Op::Andn => {
            e.a_ror_i(d, d, 64 - 29);
            e.a_imm32(A_T0, imm);
            e.a_bic(A_T0, A_T0, s);
            e.a_eor(d, d, A_T0);
        }
        Op::Rolx => {
            e.a_ror_i(d, d, 64 - k);
            e.a_eor(d, d, s);
        }
        Op::Rola => {
            e.a_ror_i(d, d, 64 - k);
            e.a_add(d, d, s);
        }
        Op::Rorx => {
            e.a_ror_i(d, d, k);
            e.a_eor(d, d, s);
        }
        Op::Rora => {
            e.a_ror_i(d, d, k);
            e.a_add(d, d, s);
        }

        Op::Vrol => {
            e.a_neg(A_T0, s);
            e.a_ror_r(d, d, A_T0);
            e.a_imm32(A_T1, imm);
            e.a_eor(d, d, A_T1);
        }
        Op::Vror => {
            e.a_ror_r(d, d, s);
            e.a_imm32(A_T1, imm);
            e.a_add(d, d, A_T1);
        }

        Op::Load => {
            e.a_addr(s, imm ^ C1, A_MSK, A_T1);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_eor(d, d, A_T1);
        }
        Op::Loadb => {
            e.a_addr(s, imm ^ C2, A_MSK, A_T1);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_eor(d, d, A_T1);
        }

        Op::Store => {
            e.a_addr(d, imm ^ C1, A_MSK, A_T1);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_add(A_T1, A_T1, s);
            e.a_str(A_T1, A_SC, A_T0);
        }
        Op::Storeb => {
            e.a_addr(d, imm ^ C2, A_MSK, A_T1);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_add(A_T1, A_T1, s);
            e.a_str(A_T1, A_SC, A_T0);
        }
        Op::Rmw => {
            e.a_addr(s, imm ^ C1, A_MSK, A_T1);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_add(A_T1, A_T1, d);
            e.a_str(A_T1, A_SC, A_T0);
            e.a_addr(A_T1, C2, A_MSK, A_T2);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_eor(d, d, A_T1);
        }
        Op::Rmwb => {
            e.a_addr(s, imm ^ C2, A_MSK, A_T1);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_eor(A_T1, A_T1, d);
            e.a_str(A_T1, A_SC, A_T0);
            e.a_addr(A_T1, C1, A_MSK, A_T2);
            e.a_ldr(A_T1, A_SC, A_T0);
            e.a_add(d, d, A_T1);
        }

        Op::Mullo => {
            e.a_orr1(A_T0, s);
            e.a_mul(d, d, A_T0);
        }
        Op::Mulhi => {
            e.a_orr1(A_T0, s);
            e.a_umulh(d, d, A_T0);
            e.a_imm32(A_T1, imm);
            e.a_eor(d, d, A_T1);
        }
        Op::Aesr => {
            e.a_addr(s, imm ^ C1, A_LMSK, A_T1);
            e.a_ldr_q(1, A_SC, A_T0);

            e.a_aese(1, 2);
            e.a_aesmc(1, 1);
            e.a_veor(1, 1, 0);
            e.a_str_q(1, A_SC, A_T0);

            e.a_umov_d0(A_T1, 1);
            e.a_eor(d, d, A_T1);
        }
    }
}

pub fn emit_aarch64(prog: &Program, out: &mut [u8; ISO_CODE_BYTES_AARCH64]) {
    let n = emit_aarch64_into(prog, out);
    assert_eq!(
        n, ISO_CODE_BYTES_AARCH64,
        "emitted {n} bytes, the frozen isocost size is {ISO_CODE_BYTES_AARCH64}"
    );
}

pub fn emit_aarch64_into(prog: &Program, out: &mut [u8]) -> usize {
    let mut e = Emitter { buf: out, at: 0 };

    e.a_stp_pre(19, 20);
    e.a_stp_pre(21, 22);
    e.a_stp_pre(23, 24);
    e.a_stp_pre(25, 26);
    e.a_stp_pre(27, 28);

    e.a_mov(A_SC, 0);
    e.a_ldr_q_off(0, 2, 0);
    e.a_movi0(2);
    e.a_imm64(A_MULT, MULT);
    e.a_imm32(A_MSK, SCRATCH_MASK as u32);
    e.a_imm32(A_LMSK, LINE_MASK as u32);

    for (i, &reg) in RMAP.iter().enumerate() {
        e.a_imm32(A_T0, (2 * i + 1) as u32);
        e.a_mul(reg, 1, A_T0);
        if i != 0 {
            e.a_addi(reg, reg, i as u32);
        }
    }
    e.a_movz(A_LOOP, 0, 0);

    assert_eq!(
        e.at * 4,
        ARM64_PROLOGUE,
        "aarch64 prologue emitted {} bytes, sizes.rs says {ARM64_PROLOGUE}",
        e.at * 4
    );

    let loop_top = e.at;
    for (i, slot) in prog.slots().iter().enumerate() {
        let before = e.at;
        emit_one(&mut e, slot);
        let n = (e.at - before) * 4;
        let want = ARM64_LEN[slot.op().index() as usize] as usize;
        assert_eq!(
            n,
            want,
            "slot {i} {}: emitted {n} bytes, ARM64_LEN says {want}",
            slot.op().name()
        );
    }

    let epi = e.at;
    e.a_eor(RMAP[0], RMAP[0], A_LOOP);
    e.a_addi(A_LOOP, A_LOOP, 1);
    e.a_cmpi(A_LOOP, LOOPS);
    {
        let off = (loop_top as i64) - (e.at as i64);
        let imm19 = (off as i32 as u32) & 0x7_FFFF;
        e.ei(0x5400_0000 | (imm19 << 5) | 11);
    }

    e.a_mov(0, RMAP[0]);
    for &reg in RMAP.iter().skip(1) {
        e.a_eor(0, 0, reg);
    }

    e.a_ldp_post(27, 28);
    e.a_ldp_post(25, 26);
    e.a_ldp_post(23, 24);
    e.a_ldp_post(21, 22);
    e.a_ldp_post(19, 20);
    e.ei(0xD65F_03C0);

    assert_eq!(
        (e.at - epi) * 4,
        ARM64_EPILOGUE,
        "aarch64 epilogue emitted {} bytes, sizes.rs says {ARM64_EPILOGUE}",
        (e.at - epi) * 4
    );

    let want: usize = ARM64_PROLOGUE
        + prog
            .slots()
            .iter()
            .map(|s| ARM64_LEN[s.op().index() as usize] as usize)
            .sum::<usize>()
        + ARM64_EPILOGUE;
    assert_eq!(
        e.at * 4,
        want,
        "emitted {} bytes, the per-opcode length table predicts {want}",
        e.at * 4
    );
    e.at * 4
}
