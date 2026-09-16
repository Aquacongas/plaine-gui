#![allow(dead_code)]

use plaine_pow::{Instr, Op, Program, Rng, NREG, PROG_INSTR, RNG_DOM_SINGLE, ROLE_OFFS};

pub const VECTORS: &str = include_str!("../../../lib/pow/tests/vectors/isochron-v1.txt");

pub struct OpcodeRow {
    pub op: u8,
    pub name: String,
    pub seed: u64,
    pub prognonce: u64,
    pub digest: u64,
    pub padck: u64,
}

pub struct NonceRow {
    pub i: usize,
    pub seed: u64,
    pub progseed: u64,
    pub padck: u64,
    pub digest: u64,
    pub codesize: usize,
}

pub struct CodeRow {
    pub seed: u64,
    pub progseed: u64,
    pub size: usize,
    pub bytes: Vec<u8>,
}

pub struct Vectors {
    pub opcodes: Vec<OpcodeRow>,
    pub nonces: Vec<NonceRow>,
    pub code: Vec<CodeRow>,
}

struct Cursor<'a> {
    lines: Vec<&'a str>,
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a str) -> Self {
        let lines = src
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        Cursor { lines, at: 0 }
    }
    fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.at).copied()
    }
    fn next(&mut self) -> &'a str {
        let l = self
            .peek()
            .unwrap_or_else(|| panic!("vector file truncated at line index {}", self.at));
        self.at += 1;
        l
    }
    fn expect_tag(&mut self, tag: &str) -> &'a str {
        let l = self.next();
        assert!(
            l == tag || l.starts_with(&format!("{tag} ")),
            "expected a `{tag}` line at line index {}, got: {l}",
            self.at - 1
        );
        l
    }
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    for tok in line.split(' ').skip(1) {
        if let Some(v) = tok.strip_prefix(&format!("{key}=")) {
            return v;
        }
    }
    panic!("field `{key}` missing from vector line: {line}");
}

fn hex64(line: &str, key: &str) -> u64 {
    let s = field(line, key);
    assert_eq!(s.len(), 16, "u64 field `{key}` must be 16 hex digits: {line}");
    u64::from_str_radix(s, 16).unwrap_or_else(|e| panic!("field `{key}` = `{s}`: {e}"))
}

fn dec<T: std::str::FromStr>(line: &str, key: &str) -> T
where
    T::Err: std::fmt::Display,
{
    let s = field(line, key);
    s.parse()
        .unwrap_or_else(|e| panic!("field `{key}` = `{s}`: {e}"))
}

fn section_count(cur: &mut Cursor<'_>, name: &str) -> usize {
    let l = cur.expect_tag("section");
    assert_eq!(
        l.split(' ').nth(1).unwrap_or(""),
        name,
        "expected `section {name}`, got: {l}"
    );
    dec::<usize>(l, "count")
}

pub fn parse() -> Vectors {
    let mut cur = Cursor::new(VECTORS);
    assert_eq!(cur.next(), "format 1", "unsupported vector file format");
    for _ in 0..4 {
        cur.expect_tag("const");
    }

    let n = section_count(&mut cur, "opcodes");
    let mut opcodes = Vec::with_capacity(n);
    for _ in 0..n {
        let l = cur.expect_tag("opcode");
        opcodes.push(OpcodeRow {
            op: dec(l, "op"),
            name: field(l, "name").to_string(),
            seed: hex64(l, "seed"),
            prognonce: hex64(l, "prognonce"),
            digest: hex64(l, "digest"),
            padck: hex64(l, "padck"),
        });
    }
    assert_eq!(opcodes.len(), n, "opcodes: count= disagrees with rows");

    let n = section_count(&mut cur, "nonces");
    let mut nonces = Vec::with_capacity(n);
    for _ in 0..n {
        let l = cur.expect_tag("nonce");
        nonces.push(NonceRow {
            i: dec(l, "i"),
            seed: hex64(l, "seed"),
            progseed: hex64(l, "progseed"),
            padck: hex64(l, "padck"),
            digest: hex64(l, "digest"),
            codesize: dec(l, "codesize"),
        });
    }
    assert_eq!(nonces.len(), n, "nonces: count= disagrees with rows");

    let n = section_count(&mut cur, "fills");
    for _ in 0..n {
        cur.expect_tag("fill");
    }

    let n = section_count(&mut cur, "code");
    let mut code = Vec::with_capacity(n);
    for _ in 0..n {
        let l = cur.expect_tag("code");
        let size: usize = dec(l, "size");
        let mut bytes = Vec::with_capacity(size);
        loop {
            let hl = cur.next();
            if hl == "endcode" {
                break;
            }
            assert!(
                hl.len() % 2 == 0 && hl.bytes().all(|b| b.is_ascii_hexdigit()),
                "code hex line malformed: {hl}"
            );
            for j in (0..hl.len()).step_by(2) {
                bytes.push(u8::from_str_radix(&hl[j..j + 2], 16).expect("hex byte"));
            }
        }
        assert_eq!(
            bytes.len(),
            size,
            "code block seed {:016x}: size= says {size}, hex carries {}",
            hex64(l, "seed"),
            bytes.len()
        );
        code.push(CodeRow {
            seed: hex64(l, "seed"),
            progseed: hex64(l, "progseed"),
            size,
            bytes,
        });
    }
    assert_eq!(code.len(), n, "code: count= disagrees with blocks");

    assert_eq!(cur.next(), "end", "vector file must terminate with `end`");
    assert!(cur.peek().is_none(), "trailing content after `end`");

    assert_eq!(opcodes.len(), 21, "opcodes section row count");
    assert_eq!(nonces.len(), 512, "nonces section row count");
    assert_eq!(code.len(), 4, "code section block count");
    Vectors {
        opcodes,
        nonces,
        code,
    }
}

pub fn fill_single(op: Op, prognonce: u64) -> Program {
    let mut rng = Rng::new(prognonce, RNG_DOM_SINGLE);
    let mut slots = [Instr::new(Op::Add, 0, 0, 0); PROG_INSTR];
    for (i, slot) in slots.iter_mut().enumerate() {
        let dr = (i % NREG) as u8;
        let sr = ((dr as usize + ROLE_OFFS[i % 8] as usize) % NREG) as u8;
        *slot = Instr::new(op, dr, sr, rng.next() as u32);
    }
    Program::from_slots(slots)
}
