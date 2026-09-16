use plaine_pow::{Instr, Op, Program, C1, C2, LINE_MASK, LOOPS, MULT, NREG, SCRATCH_MASK};

use crate::sizes::{ISO_CODE_BYTES, X86_EPILOGUE, X86_LEN, X86_PROLOGUE};

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RSI: u8 = 6;
const R10: u8 = 10;
const R11: u8 = 11;

// NREG virtual registers pinned to fixed x86 registers for the whole body - no variable-length
// register move anywhere in a slot.
const RMAP: [u8; NREG] = [3, 5, 12, 13, 14, 15, 8, 9];

// every opcode emits a fixed byte count regardless of operands (lengths frozen in X86_LEN). that is
// isocost: same size, same shape, for every program. changing a length is consensus-visible.
struct Emitter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Emitter<'_> {
    fn e8(&mut self, b: u8) {
        self.buf[self.pos] = b;
        self.pos += 1;
    }
    fn e32(&mut self, v: u32) {
        self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_le_bytes());
        self.pos += 4;
    }
    fn e64(&mut self, v: u64) {
        self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_le_bytes());
        self.pos += 8;
    }
    fn ebytes(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }

    fn alu_rr(&mut self, opc: u8, dst: u8, src: u8) {
        self.e8(0x48 | (u8::from(src >= 8) << 2) | u8::from(dst >= 8));
        self.e8(opc);
        self.e8(0xC0 | ((src & 7) << 3) | (dst & 7));
    }

    fn alu_ri(&mut self, digit: u8, dst: u8, imm: u32) {
        self.e8(0x48 | u8::from(dst >= 8));
        self.e8(0x81);
        self.e8(0xC0 | (digit << 3) | (dst & 7));
        self.e32(imm);
    }

    fn alu_ri8(&mut self, digit: u8, dst: u8, imm: u8) {
        self.e8(0x48 | u8::from(dst >= 8));
        self.e8(0x83);
        self.e8(0xC0 | (digit << 3) | (dst & 7));
        self.e8(imm);
    }

    fn mov_ri64(&mut self, dst: u8, imm: u64) {
        self.e8(0x48 | u8::from(dst >= 8));
        self.e8(0xB8 | (dst & 7));
        self.e64(imm);
    }

    fn mov_ri32(&mut self, dst: u8, imm: u32) {
        debug_assert!(dst < 8, "mov_ri32 dst {dst} would need a REX prefix; that breaks the fixed 5-byte length");
        self.e8(0xB8 | (dst & 7));
        self.e32(imm);
    }

    fn rot_ri(&mut self, right: bool, dst: u8, k: u8) {
        self.e8(0x48 | u8::from(dst >= 8));
        self.e8(0xC1);
        self.e8(0xC0 | (u8::from(right) << 3) | (dst & 7));
        self.e8(k);
    }

    fn rot_rcl(&mut self, right: bool, dst: u8) {
        self.e8(0x48 | u8::from(dst >= 8));
        self.e8(0xD3);
        self.e8(0xC0 | (u8::from(right) << 3) | (dst & 7));
    }

    fn shr_ri(&mut self, dst: u8, k: u8) {
        self.e8(0x48 | u8::from(dst >= 8));
        self.e8(0xC1);
        self.e8(0xC0 | (5 << 3) | (dst & 7));
        self.e8(k);
    }

    fn not_r(&mut self, dst: u8) {
        self.e8(0x48 | u8::from(dst >= 8));
        self.e8(0xF7);
        self.e8(0xC0 | (2 << 3) | (dst & 7));
    }

    fn imul_rr(&mut self, dst: u8, src: u8) {
        self.e8(0x48 | (u8::from(dst >= 8) << 2) | u8::from(src >= 8));
        self.e8(0x0F);
        self.e8(0xAF);
        self.e8(0xC0 | ((dst & 7) << 3) | (src & 7));
    }

    fn imul_rri(&mut self, dst: u8, src: u8, imm: u32) {
        self.e8(0x48 | (u8::from(dst >= 8) << 2) | u8::from(src >= 8));
        self.e8(0x69);
        self.e8(0xC0 | ((dst & 7) << 3) | (src & 7));
        self.e32(imm);
    }

    fn mul_r(&mut self, src: u8) {
        self.e8(0x48 | u8::from(src >= 8));
        self.e8(0xF7);
        self.e8(0xC0 | (4 << 3) | (src & 7));
    }

    fn mem_rr(&mut self, opc: u8, reg: u8) {
        self.e8(0x48 | (u8::from(reg >= 8) << 2));
        self.e8(opc);
        self.e8(0x04 | ((reg & 7) << 3));
        self.e8(0x38);
    }

    fn and_eax(&mut self, m: u32) {
        self.e8(0x25);
        self.e32(m);
    }

    fn emit_addr(&mut self, src: u8, k: u32, mask: u32, tmp: u8) {
        // src != RAX by construction: RMAP has no RAX, and RMW/RMWB pass RCX as the second address.
        debug_assert_ne!(src, RAX, "emit_addr assumes src != RAX");
        self.alu_rr(0x89, RAX, src);
        self.mov_ri32(tmp, k);
        self.alu_rr(0x31, RAX, tmp);
        self.imul_rr(RAX, R11);
        self.shr_ri(RAX, 40);
        self.and_eax(mask);
    }

    fn imm_op(&mut self, opc_rr: u8, dst: u8, imm: u32, tmp: u8) {
        self.mov_ri32(tmp, imm);
        self.alu_rr(opc_rr, dst, tmp);
    }
}

fn emit_one(e: &mut Emitter<'_>, in_: &Instr) {
    let d = RMAP[in_.d() as usize];
    let s = RMAP[in_.s() as usize];
    let imm = in_.imm();
    let k = ((imm & 63) | 1) as u8;

    match in_.op() {
        Op::Add => {
            e.alu_rr(0x01, d, s);
            e.imm_op(0x31, d, imm, RCX);
        }
        Op::Sub => {
            e.alu_rr(0x29, d, s);
            e.imm_op(0x31, d, imm, RCX);
        }
        Op::Xor => {
            e.alu_rr(0x31, d, s);
            e.imm_op(0x01, d, imm, RCX);
        }
        Op::Or => {
            e.rot_ri(false, d, 17);
            e.mov_ri32(RCX, imm);
            e.alu_rr(0x09, RCX, s);
            e.alu_rr(0x31, d, RCX);
        }
        Op::And => {
            e.rot_ri(false, d, 23);
            e.mov_ri32(RCX, imm);
            e.alu_rr(0x21, RCX, s);
            e.alu_rr(0x31, d, RCX);
        }
        Op::Andn => {
            e.rot_ri(false, d, 29);
            e.alu_rr(0x89, RDX, s);
            e.not_r(RDX);
            e.mov_ri32(RCX, imm);
            e.alu_rr(0x21, RCX, RDX);
            e.alu_rr(0x31, d, RCX);
        }
        Op::Rolx => {
            e.rot_ri(false, d, k);
            e.alu_rr(0x31, d, s);
        }
        Op::Rola => {
            e.rot_ri(false, d, k);
            e.alu_rr(0x01, d, s);
        }
        Op::Rorx => {
            e.rot_ri(true, d, k);
            e.alu_rr(0x31, d, s);
        }
        Op::Rora => {
            e.rot_ri(true, d, k);
            e.alu_rr(0x01, d, s);
        }

        Op::Vrol => {
            e.alu_rr(0x89, RCX, s);
            e.rot_rcl(false, d);
            e.imm_op(0x31, d, imm, RCX);
        }
        Op::Vror => {
            e.alu_rr(0x89, RCX, s);
            e.rot_rcl(true, d);
            e.imm_op(0x01, d, imm, RCX);
        }

        Op::Load => {
            e.emit_addr(s, imm ^ C1, SCRATCH_MASK as u32, RCX);
            e.mem_rr(0x33, d);
        }
        Op::Loadb => {
            e.emit_addr(s, imm ^ C2, SCRATCH_MASK as u32, RCX);
            e.mem_rr(0x33, d);
        }

        Op::Store => {
            e.emit_addr(d, imm ^ C1, SCRATCH_MASK as u32, RCX);
            e.mem_rr(0x01, s);
        }
        Op::Storeb => {
            e.emit_addr(d, imm ^ C2, SCRATCH_MASK as u32, RCX);
            e.mem_rr(0x01, s);
        }
        Op::Rmw => {
            e.emit_addr(s, imm ^ C1, SCRATCH_MASK as u32, RCX);
            e.mem_rr(0x8B, RCX);
            e.alu_rr(0x01, RCX, d);
            e.mem_rr(0x89, RCX);

            e.emit_addr(RCX, C2, SCRATCH_MASK as u32, RDX);
            e.mem_rr(0x33, d);
        }
        Op::Rmwb => {
            e.emit_addr(s, imm ^ C2, SCRATCH_MASK as u32, RCX);
            e.mem_rr(0x8B, RCX);
            e.alu_rr(0x31, RCX, d);
            e.mem_rr(0x89, RCX);

            e.emit_addr(RCX, C1, SCRATCH_MASK as u32, RDX);
            e.mem_rr(0x03, d);
        }

        Op::Mullo => {
            e.alu_rr(0x89, RCX, s);
            e.alu_ri8(1, RCX, 1);
            e.imul_rr(d, RCX);
        }
        Op::Mulhi => {
            e.alu_rr(0x89, RCX, s);
            e.alu_ri8(1, RCX, 1);
            e.alu_rr(0x89, RAX, d);
            e.mul_r(RCX);
            e.alu_rr(0x89, d, RDX);
            e.imm_op(0x31, d, imm, RCX);
        }
        Op::Aesr => {
            e.emit_addr(s, imm ^ C1, LINE_MASK as u32, RCX);

            e.ebytes(&[
                0xF3, 0x0F, 0x6F, 0x0C, 0x38,
                0x66, 0x0F, 0x38, 0xDC, 0xC8,
                0xF3, 0x0F, 0x7F, 0x0C, 0x38,
            ]);

            e.ebytes(&[0x66, 0x48, 0x0F, 0x7E, 0xC9]);
            e.alu_rr(0x31, d, RCX);
        }
    }
}

pub fn emit_x86_64(prog: &Program, out: &mut [u8; ISO_CODE_BYTES]) {
    let n = emit_x86_64_into(prog, out);
    assert_eq!(
        n, ISO_CODE_BYTES,
        "emitted {n} bytes, the frozen isocost size is {ISO_CODE_BYTES}"
    );
}

pub fn emit_x86_64_into(prog: &Program, out: &mut [u8]) -> usize {
    let mut e = Emitter { buf: out, pos: 0 };

    e.ebytes(&[0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
    e.mov_ri64(R11, MULT);
    e.ebytes(&[0xF3, 0x0F, 0x6F, 0x02]);

    for (i, &reg) in RMAP.iter().enumerate() {
        e.imul_rri(reg, RSI, (2 * i + 1) as u32);
        if i != 0 {
            e.alu_ri(0, reg, i as u32);
        }
    }
    e.ebytes(&[0x45, 0x31, 0xD2]);

    assert_eq!(
        e.pos, X86_PROLOGUE,
        "prologue emitted {} bytes, sizes.rs says {X86_PROLOGUE}",
        e.pos
    );

    let loop_top = e.pos;
    for (i, slot) in prog.slots().iter().enumerate() {
        let before = e.pos;
        emit_one(&mut e, slot);
        let n = e.pos - before;
        let want = X86_LEN[slot.op().index() as usize] as usize;

        assert_eq!(
            n,
            want,
            "slot {i} {}: emitted {n} bytes, X86_LEN says {want}",
            slot.op().name()
        );
    }

    let epi = e.pos;
    e.alu_rr(0x31, RMAP[0], R10);
    e.ebytes(&[0x49, 0xFF, 0xC2]);
    e.e8(0x49);
    e.e8(0x81);
    e.e8(0xFA);
    e.e32(LOOPS);
    e.e8(0x0F);
    e.e8(0x8C);

    let disp = (loop_top as i64) - ((e.pos + 4) as i64);
    e.e32(disp as i32 as u32);

    e.alu_rr(0x89, RAX, RMAP[0]);
    for &reg in RMAP.iter().skip(1) {
        e.alu_rr(0x31, RAX, reg);
    }

    e.ebytes(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5D, 0x5B, 0xC3]);

    assert_eq!(
        e.pos - epi,
        X86_EPILOGUE,
        "epilogue emitted {} bytes, sizes.rs says {X86_EPILOGUE}",
        e.pos - epi
    );

    let want: usize = X86_PROLOGUE
        + prog
            .slots()
            .iter()
            .map(|s| X86_LEN[s.op().index() as usize] as usize)
            .sum::<usize>()
        + X86_EPILOGUE;
    assert_eq!(
        e.pos, want,
        "emitted {} bytes, the per-opcode length table predicts {want}",
        e.pos
    );
    e.pos
}
