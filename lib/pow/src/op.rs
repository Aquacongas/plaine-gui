#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    Alu = 0,
    RotImm = 1,
    RotReg = 2,
    Mem = 3,
    Mul = 4,
    Aes = 5,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Op {
    Add = 0,
    Sub = 1,
    Xor = 2,
    Or = 3,
    And = 4,
    Andn = 5,
    Rolx = 6,
    Rola = 7,
    Rorx = 8,
    Rora = 9,
    Vrol = 10,
    Vror = 11,
    Load = 12,
    Store = 13,
    Rmw = 14,
    Loadb = 15,
    Storeb = 16,
    Rmwb = 17,
    Mullo = 18,
    Mulhi = 19,
    Aesr = 20,
}

pub const OP_COUNT: usize = 21;

pub const ALL_OPS: [Op; OP_COUNT] = [
    Op::Add,
    Op::Sub,
    Op::Xor,
    Op::Or,
    Op::And,
    Op::Andn,
    Op::Rolx,
    Op::Rola,
    Op::Rorx,
    Op::Rora,
    Op::Vrol,
    Op::Vror,
    Op::Load,
    Op::Store,
    Op::Rmw,
    Op::Loadb,
    Op::Storeb,
    Op::Rmwb,
    Op::Mullo,
    Op::Mulhi,
    Op::Aesr,
];

pub const ALU_POOL: [Op; 6] = [Op::Add, Op::Sub, Op::Xor, Op::Or, Op::And, Op::Andn];

pub const ROT_POOL: [Op; 4] = [Op::Rolx, Op::Rola, Op::Rorx, Op::Rora];

pub const MEM_POOL: [Op; 6] = [
    Op::Load,
    Op::Store,
    Op::Rmw,
    Op::Loadb,
    Op::Storeb,
    Op::Rmwb,
];

pub const MUL_POOL: [Op; 2] = [Op::Mullo, Op::Mulhi];

pub const ROTREG_POOL: [Op; 2] = [Op::Vrol, Op::Vror];

impl Op {
    pub const fn name(self) -> &'static str {
        match self {
            Op::Add => "ADD",
            Op::Sub => "SUB",
            Op::Xor => "XOR",
            Op::Or => "OR",
            Op::And => "AND",
            Op::Andn => "ANDN",
            Op::Rolx => "ROLX",
            Op::Rola => "ROLA",
            Op::Rorx => "RORX",
            Op::Rora => "RORA",
            Op::Vrol => "VROL",
            Op::Vror => "VROR",
            Op::Load => "LOAD",
            Op::Store => "STORE",
            Op::Rmw => "RMW",
            Op::Loadb => "LOADB",
            Op::Storeb => "STOREB",
            Op::Rmwb => "RMWB",
            Op::Mullo => "MULLO",
            Op::Mulhi => "MULHI",
            Op::Aesr => "AESR",
        }
    }

    pub const fn class(self) -> Class {
        match self {
            Op::Add | Op::Sub | Op::Xor | Op::Or | Op::And | Op::Andn => Class::Alu,
            Op::Rolx | Op::Rola | Op::Rorx | Op::Rora => Class::RotImm,
            Op::Vrol | Op::Vror => Class::RotReg,
            Op::Load | Op::Store | Op::Rmw | Op::Loadb | Op::Storeb | Op::Rmwb => Class::Mem,
            Op::Mullo | Op::Mulhi => Class::Mul,
            Op::Aesr => Class::Aes,
        }
    }

    pub const fn index(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(v: u8) -> Option<Op> {
        if (v as usize) < OP_COUNT {
            Some(ALL_OPS[v as usize])
        } else {
            None
        }
    }
}

const _: () = {
    let mut i = 0;
    while i < OP_COUNT {
        assert!(
            ALL_OPS[i] as usize == i,
            "ALL_OPS must be in discriminant order"
        );
        i += 1;
    }
};
