use plaine_pow::{
    build_program, Instr, Isochron, Op, Program, Rng, Scratch, AESKEY, ALL_OPS, C1, C2, FILL_DOM,
    HIST, LOOPS, MULT, NREG, OP_COUNT, PER_BLOCK, PROG_INSTR, RNG_DOM_SINGLE, ROLE_OFFS,
    SCRATCH_BYTES, SCRATCH_WORDS, SELF_CHECK,
};

const VECTORS: &str = include_str!("vectors/isochron-v1.txt");

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
    assert_eq!(
        s.len(),
        16,
        "u64 field `{key}` must be exactly 16 hex digits, got `{s}` in: {line}"
    );
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

fn csv_u8(line: &str, key: &str) -> Vec<u8> {
    field(line, key)
        .split(',')
        .map(|t| t.parse().expect("csv field must be decimal u8"))
        .collect()
}

fn section_count(cur: &mut Cursor<'_>, name: &str) -> usize {
    let l = cur.expect_tag("section");
    let got = l.split(' ').nth(1).unwrap_or("");
    assert_eq!(got, name, "expected `section {name}`, got: {l}");
    dec::<usize>(l, "count")
}

struct OpcodeRow {
    op: u8,
    name: String,
    seed: u64,
    prognonce: u64,
    digest: u64,
    padck: u64,
}
struct NonceRow {
    i: usize,
    seed: u64,
    progseed: u64,
    padck: u64,
    digest: u64,
    codesize: usize,
}
struct FillRow {
    i: usize,
    seed: u64,
    progseed: u64,
    padck: u64,
}
struct CodeRow {
    seed: u64,
    progseed: u64,
    size: usize,
    bytes: usize,
}

struct Vectors {
    opcodes: Vec<OpcodeRow>,
    nonces: Vec<NonceRow>,
    fills: Vec<FillRow>,
    code: Vec<CodeRow>,
}

fn parse_and_check_consts() -> Vectors {
    let mut cur = Cursor::new(VECTORS);

    assert_eq!(cur.next(), "format 1", "unsupported vector file format");

    let c = cur.expect_tag("const");
    assert_eq!(
        dec::<u32>(c, "scratch_bytes"),
        SCRATCH_BYTES,
        "const scratch_bytes mismatch"
    );
    assert_eq!(dec::<u32>(c, "loops"), LOOPS, "const loops mismatch");
    assert_eq!(
        dec::<usize>(c, "prog_instr"),
        PROG_INSTR,
        "const prog_instr mismatch"
    );
    assert_eq!(dec::<usize>(c, "nreg"), NREG, "const nreg mismatch");
    assert_eq!(
        dec::<usize>(c, "opcount"),
        OP_COUNT,
        "const opcount mismatch"
    );

    let c = cur.expect_tag("const");
    assert_eq!(hex64(c, "mult"), MULT, "const mult mismatch");
    assert_eq!(
        u32::from_str_radix(field(c, "c1"), 16).unwrap(),
        C1,
        "const c1 mismatch: file {}, crate {C1:08x}",
        field(c, "c1")
    );
    assert_eq!(
        u32::from_str_radix(field(c, "c2"), 16).unwrap(),
        C2,
        "const c2 mismatch: file {}, crate {C2:08x}",
        field(c, "c2")
    );
    assert_eq!(hex64(c, "fill_dom"), FILL_DOM, "const fill_dom mismatch");

    let c = cur.expect_tag("const");
    let key = field(c, "aeskey");
    assert_eq!(key.len(), 32, "aeskey must be 32 hex chars");
    let crate_key: String = AESKEY.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(key, crate_key, "const aeskey mismatch");

    let c = cur.expect_tag("const");
    assert_eq!(
        csv_u8(c, "role_offs"),
        ROLE_OFFS.to_vec(),
        "const role_offs mismatch"
    );
    assert_eq!(
        csv_u8(c, "per_block"),
        PER_BLOCK.to_vec(),
        "const per_block mismatch"
    );

    let n = section_count(&mut cur, "opcodes");
    assert_eq!(n, OP_COUNT, "opcodes section must cover the whole ISA");
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
    assert_eq!(
        opcodes.len(),
        n,
        "opcodes section: count= disagrees with rows"
    );

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
    assert_eq!(
        nonces.len(),
        n,
        "nonces section: count= disagrees with rows"
    );

    let n = section_count(&mut cur, "fills");
    let mut fills = Vec::with_capacity(n);
    for _ in 0..n {
        let l = cur.expect_tag("fill");
        fills.push(FillRow {
            i: dec(l, "i"),
            seed: hex64(l, "seed"),
            progseed: hex64(l, "progseed"),
            padck: hex64(l, "padck"),
        });
    }
    assert_eq!(fills.len(), n, "fills section: count= disagrees with rows");

    let n = section_count(&mut cur, "code");
    let mut code = Vec::with_capacity(n);
    for _ in 0..n {
        let l = cur.expect_tag("code");
        let size: usize = dec(l, "size");
        let mut bytes = 0usize;
        loop {
            let hl = cur.next();
            if hl == "endcode" {
                break;
            }
            assert!(
                hl.len() % 2 == 0 && hl.bytes().all(|b| b.is_ascii_hexdigit()),
                "code hex line malformed: {hl}"
            );
            bytes += hl.len() / 2;
        }
        assert_eq!(
            bytes,
            size,
            "code block for seed {:016x}: size= says {size}, hex carries {bytes}",
            hex64(l, "seed")
        );
        code.push(CodeRow {
            seed: hex64(l, "seed"),
            progseed: hex64(l, "progseed"),
            size,
            bytes,
        });
    }
    assert_eq!(code.len(), n, "code section: count= disagrees with blocks");

    assert_eq!(cur.next(), "end", "vector file must terminate with `end`");
    assert!(
        cur.peek().is_none(),
        "trailing content after `end`: {:?}",
        cur.peek()
    );

    Vectors {
        opcodes,
        nonces,
        fills,
        code,
    }
}

fn iso() -> Isochron {
    Isochron::new().expect("this CPU must have hardware AES to run the Isochron tests")
}

fn fill_single(op: Op, prognonce: u64) -> Program {
    let mut rng = Rng::new(prognonce, RNG_DOM_SINGLE);
    let mut slots = [Instr::new(Op::Add, 0, 0, 0); PROG_INSTR];
    for (i, slot) in slots.iter_mut().enumerate() {
        let dr = (i % NREG) as u8;
        let sr = ((dr as usize + ROLE_OFFS[i % 8] as usize) % NREG) as u8;
        *slot = Instr::new(op, dr, sr, rng.next() as u32);
    }
    Program::from_slots(slots)
}

#[test]
fn tier0_constants_match_oracle() {
    let v = parse_and_check_consts();

    assert_eq!(v.opcodes.len(), 21, "opcodes section row count");
    assert_eq!(v.nonces.len(), 512, "nonces section row count");
    assert_eq!(v.fills.len(), 64, "fills section row count");
    assert_eq!(v.code.len(), 4, "code section block count");

    for r in &v.opcodes {
        let op = Op::from_u8(r.op).unwrap_or_else(|| panic!("vector op={} out of range", r.op));
        assert_eq!(
            op.name(),
            r.name,
            "opcode {} name mismatch: file {}, crate {}",
            r.op,
            r.name,
            op.name()
        );
    }

    let sz = v.nonces[0].codesize;
    for r in &v.nonces {
        assert_eq!(
            r.codesize, sz,
            "codesize varies with nonce at i={} (seed {:016x}): {} vs {sz}",
            r.i, r.seed, r.codesize
        );
    }
    for b in &v.code {
        assert_eq!(
            b.size, sz,
            "code block seed {:016x} size {} != nonce-section codesize {sz}",
            b.seed, b.size
        );
        assert_eq!(b.bytes, b.size, "code block byte count");
    }
}

#[test]
fn tier0_self_check_in_oracle() {
    let v = parse_and_check_consts();
    for &(seed, digest) in SELF_CHECK.iter() {
        let row = v
            .nonces
            .iter()
            .find(|r| r.seed == seed)
            .unwrap_or_else(|| panic!("self-check seed {seed:016x} is not in the vector file"));
        assert_eq!(
            row.digest, digest,
            "self-check seed {seed:016x}: embedded digest {digest:016x} != file digest {:016x}",
            row.digest
        );
    }
}

#[test]
fn tier1_fill_ref_equals_fill_over_full_pad() {
    let iso = iso();
    let seed = 0x00AB_CDEF_1234_5678u64;
    let mut a = Scratch::new();
    let mut b = Scratch::new();
    let pr = iso.fill_ref(&mut a, seed);
    let pf = iso.fill(&mut b, seed);
    assert_eq!(
        pr, pf,
        "fill_ref/fill program seed diverges for seed {seed:016x}: ref {pr:016x} fast {pf:016x}"
    );
    for i in 0..SCRATCH_WORDS {
        assert_eq!(
            a.words()[i],
            b.words()[i],
            "fill_ref/fill pad diverges at word {i} (seed {seed:016x}): ref {:016x} fast {:016x}",
            a.words()[i],
            b.words()[i]
        );
    }
}

#[test]
fn tier1_fill_is_deterministic_and_seed_sensitive() {
    let iso = iso();
    let mut a = Scratch::new();
    let mut b = Scratch::new();

    let p1 = iso.fill(&mut a, 42);
    let p2 = iso.fill(&mut b, 42);
    assert_eq!(p1, p2, "same seed must give the same program seed");
    assert_eq!(
        a.checksum(),
        b.checksum(),
        "same seed must give the same pad"
    );

    let p3 = iso.fill(&mut b, 43);
    assert_ne!(p3, p2, "seed+1 must give a different program seed");
    assert_ne!(
        a.checksum(),
        b.checksum(),
        "seed+1 must give a different pad"
    );
}

#[test]
fn tier1_fill_vectors() {
    let v = parse_and_check_consts();
    let iso = iso();
    let mut pad = Scratch::new();
    for row in &v.fills {
        let want_seed = (row.i as u64).wrapping_mul(MULT) ^ FILL_DOM;
        assert_eq!(
            row.seed, want_seed,
            "fill vector i={}: seed column {:016x} != schedule {want_seed:016x}",
            row.i, row.seed
        );
        let ps = iso.fill(&mut pad, row.seed);
        assert_eq!(
            ps, row.progseed,
            "fill vector i={} seed {:016x}: progseed expected {:016x}, got {ps:016x}",
            row.i, row.seed, row.progseed
        );
        let ck = pad.checksum();
        assert_eq!(
            ck, row.padck,
            "fill vector i={} seed {:016x}: padck expected {:016x}, got {ck:016x}",
            row.i, row.seed, row.padck
        );
    }
}

#[test]
fn tier1_code_seeds_fill_to_progseeds() {
    let v = parse_and_check_consts();
    let iso = iso();
    let mut pad = Scratch::new();
    for b in &v.code {
        let ps = iso.fill(&mut pad, b.seed);
        assert_eq!(
            ps, b.progseed,
            "code block seed {:016x}: progseed expected {:016x}, got {ps:016x}",
            b.seed, b.progseed
        );
    }
}

#[test]
fn tier2_every_opcode_matches_the_oracle() {
    let v = parse_and_check_consts();
    let iso = iso();
    let mut pad = Scratch::new();

    for row in &v.opcodes {
        let op = Op::from_u8(row.op).unwrap();
        assert_eq!(
            row.prognonce,
            0xC0FFEEu64 + row.op as u64,
            "opcode {} {}: prognonce schedule changed",
            row.op,
            op.name()
        );
        let prog = fill_single(op, row.prognonce);
        iso.fill(&mut pad, row.seed);
        let digest = iso.interp(&prog, &mut pad, row.seed);

        assert_eq!(
            digest,
            row.digest,
            "opcode {} {}: digest mismatch - expected {:016x}, got {digest:016x} \
             (seed {:016x}, prognonce {:016x})",
            row.op,
            op.name(),
            row.digest,
            row.seed,
            row.prognonce
        );

        let ck = pad.checksum();
        assert_eq!(
            ck,
            row.padck,
            "opcode {} {}: padck mismatch - expected {:016x}, got {ck:016x} \
             (seed {:016x}, prognonce {:016x})",
            row.op,
            op.name(),
            row.padck,
            row.seed,
            row.prognonce
        );
    }
}

#[test]
fn tier2_full_chain_nonce_vectors() {
    let v = parse_and_check_consts();
    let iso = iso();
    let mut pad = Scratch::new();

    for row in &v.nonces {
        let want_seed = 0x243F_6A88_85A3_08D3u64.wrapping_add(MULT.wrapping_mul(row.i as u64));
        assert_eq!(
            row.seed, want_seed,
            "nonce vector i={}: seed column {:016x} != schedule {want_seed:016x}",
            row.i, row.seed
        );

        let ps = iso.fill(&mut pad, row.seed);
        assert_eq!(
            ps, row.progseed,
            "nonce i={} seed {:016x}: program seed mismatch - expected {:016x}, got {ps:016x} \
             (fill diverged, not the interpreter)",
            row.i, row.seed, row.progseed
        );

        let prog = plaine_pow::build_program(ps);
        let digest = iso.interp(&prog, &mut pad, row.seed);
        assert_eq!(
            digest, row.digest,
            "nonce i={} seed {:016x} progseed {ps:016x}: digest mismatch - \
             expected {:016x}, got {digest:016x}",
            row.i, row.seed, row.digest
        );

        let ck = pad.checksum();
        assert_eq!(
            ck, row.padck,
            "nonce i={} seed {:016x} progseed {ps:016x}: padck mismatch - \
             expected {:016x}, got {ck:016x}",
            row.i, row.seed, row.padck
        );
    }
}

#[test]
fn tier2_verify_hash_matches_chain() {
    let v = parse_and_check_consts();
    let iso = iso();
    let mut pad = Scratch::new();
    for row in v.nonces.iter().take(16) {
        let got = iso.verify_hash(&mut pad, row.seed);
        assert_eq!(
            got, row.digest,
            "verify_hash(seed {:016x}) = {got:016x}, oracle says {:016x}",
            row.seed, row.digest
        );
    }
}

#[test]
fn tier2_histogram_frozen_per_nonce() {
    let v = parse_and_check_consts();

    for row in &v.nonces {
        let prog = build_program(row.progseed);
        let mut tally = [0u32; OP_COUNT];
        for slot in prog.slots().iter() {
            tally[slot.op().index() as usize] += 1;
        }
        for (i, op) in ALL_OPS.iter().enumerate() {
            assert_eq!(
                tally[i],
                HIST[i],
                "nonce i={} progseed {:016x}: opcode {} appears {} times, frozen histogram says {}",
                row.i,
                row.progseed,
                op.name(),
                tally[i],
                HIST[i]
            );
        }

        for (i, op) in ALL_OPS.iter().enumerate() {
            assert!(
                tally[i] > 0,
                "nonce i={}: opcode {} absent from the program",
                row.i,
                op.name()
            );
        }
        assert_eq!(
            tally.iter().sum::<u32>() as usize,
            PROG_INSTR,
            "nonce i={}: histogram does not account for every slot",
            row.i
        );
    }
}

#[test]
fn tier2_roles_in_range_never_equal() {
    let v = parse_and_check_consts();
    for row in v.nonces.iter() {
        let prog = build_program(row.progseed);
        for (i, slot) in prog.slots().iter().enumerate() {
            assert!(slot.d() < 8 && slot.s() < 8, "slot {i}: role out of range");
            assert_ne!(
                slot.d(),
                slot.s(),
                "nonce i={} slot {i} {}: d == s, which build_program should never emit",
                row.i,
                slot.op().name()
            );
        }
    }
}

#[test]
fn platform_self_check_passes_on_this_build() {
    plaine_pow::platform_self_check().expect("platform self check");
}
