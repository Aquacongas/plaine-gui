use plaine_pow::{
    build_program, Class, Instr, Isochron, Op, Scratch, ALL_OPS, ALU_POOL, HIST, LINE_MASK,
    MEM_POOL, MUL_POOL, OP_COUNT, PER_BLOCK, PROG_INSTR, ROTREG_POOL, ROT_POOL, SCRATCH_BYTES,
    SCRATCH_MASK,
};

#[test]
fn masks_cover_whole_pad() {
    assert!(SCRATCH_BYTES.is_power_of_two());
    assert_eq!(SCRATCH_MASK, 0xFFF8);
    assert_eq!(LINE_MASK, 0xFFF0);

    assert_eq!(SCRATCH_MASK & 7, 0, "SCRATCH_MASK must be 8-byte aligned");
    assert_eq!(LINE_MASK & 15, 0, "LINE_MASK must be 16-byte aligned");
    assert!(SCRATCH_MASK as u32 + 8 == SCRATCH_BYTES);
    assert!(LINE_MASK as u32 + 16 == SCRATCH_BYTES);
}

#[test]
fn opcode_table_is_consistent() {
    assert_eq!(ALL_OPS.len(), OP_COUNT);
    for (i, op) in ALL_OPS.iter().enumerate() {
        assert_eq!(op.index() as usize, i, "{} has the wrong discriminant", op.name());
        assert_eq!(Op::from_u8(i as u8), Some(*op));
    }
    assert_eq!(Op::from_u8(OP_COUNT as u8), None, "decode must be range-checked");
    assert_eq!(Op::from_u8(255), None);

    let mut seen = [0u32; OP_COUNT];
    for (pool, class) in [
        (&ALU_POOL[..], Class::Alu),
        (&ROT_POOL[..], Class::RotImm),
        (&ROTREG_POOL[..], Class::RotReg),
        (&MEM_POOL[..], Class::Mem),
        (&MUL_POOL[..], Class::Mul),
        (&[Op::Aesr][..], Class::Aes),
    ] {
        for op in pool {
            assert_eq!(op.class(), class, "{} is in the wrong pool", op.name());
            seen[op.index() as usize] += 1;
        }
    }
    for (i, n) in seen.iter().enumerate() {
        assert_eq!(*n, 1, "{} appears in {n} class pools, want 1", ALL_OPS[i].name());
    }
}

#[test]
fn frozen_tables_shape() {
    let mut per_class = [0u32; 6];
    for &k in PER_BLOCK.iter() {
        per_class[k as usize] += 1;
    }
    assert_eq!(per_class, [6, 1, 1, 5, 1, 2], "frozen per-block class layout");
    assert_eq!(PER_BLOCK.len() * 32, PROG_INSTR);

    assert_eq!(HIST.iter().sum::<u32>() as usize, PROG_INSTR);
    assert_eq!(&HIST[0..6], &[32u32; 6], "ALU");
    assert_eq!(&HIST[6..10], &[8u32; 4], "rot-imm");
    assert_eq!(&HIST[10..12], &[16u32; 2], "rot-reg");
    assert_eq!(&HIST[12..18], &[27u32, 27, 27, 27, 26, 26], "memory");
    assert_eq!(&HIST[18..20], &[16u32; 2], "mul");
    assert_eq!(HIST[20], 64, "AESR");

    assert_eq!(HIST[12..18].iter().sum::<u32>(), 160);
}

#[test]
fn instr_roles_are_total() {
    for d in 0..=255u8 {
        let i = Instr::new(Op::Add, d, d.wrapping_add(1), 0);
        assert!(i.d() < 8 && i.s() < 8, "role {d} escaped the mask");
        assert_eq!(i.d(), d & 7);
    }
}

#[test]
fn mulhi_high_half_of_odd_product() {
    fn mulhi(a: u64, b: u64) -> u64 {
        (((a as u128).wrapping_mul((b | 1) as u128)) >> 64) as u64
    }

    fn mulhi_ref(a: u64, b: u64) -> u64 {
        let b = b | 1;
        let (al, ah) = (a & 0xFFFF_FFFF, a >> 32);
        let (bl, bh) = (b & 0xFFFF_FFFF, b >> 32);
        let ll = al * bl;
        let lh = al * bh;
        let hl = ah * bl;
        let hh = ah * bh;
        let mid = (ll >> 32).wrapping_add(lh & 0xFFFF_FFFF).wrapping_add(hl & 0xFFFF_FFFF);
        hh.wrapping_add(lh >> 32)
            .wrapping_add(hl >> 32)
            .wrapping_add(mid >> 32)
    }
    let vals = [
        0u64,
        1,
        2,
        3,
        0xFFFF_FFFF,
        1 << 32,
        1 << 63,
        u64::MAX,
        0x9E37_79B9_7F4A_7C15,
        0x9E37_79B9_7F4A_7C14,
    ];
    for &a in &vals {
        for &b in &vals {
            assert_eq!(
                mulhi(a, b),
                mulhi_ref(a, b),
                "MULHI({a:016x}, {b:016x})"
            );
        }
    }
    assert_eq!(mulhi(u64::MAX, u64::MAX), u64::MAX - 1);

    assert_eq!(mulhi(1 << 63, 2), mulhi(1 << 63, 3));
    assert_ne!(mulhi(1 << 63, 2), 0);
}

#[test]
fn rotations_match_c_form() {
    #[allow(clippy::manual_rotate)]
    fn c_rotl(x: u64, k: u32) -> u64 {
        let k = k & 63;
        if k != 0 {
            (x << k) | (x >> (64 - k))
        } else {
            x
        }
    }
    #[allow(clippy::manual_rotate)]
    fn c_rotr(x: u64, k: u32) -> u64 {
        let k = k & 63;
        if k != 0 {
            (x >> k) | (x << (64 - k))
        } else {
            x
        }
    }
    for x in [0u64, 1, u64::MAX, 1 << 63, 0x0123_4567_89AB_CDEF] {
        for k in 0..=130u32 {
            assert_eq!(x.rotate_left(k), c_rotl(x, k), "rotl({x:016x}, {k})");
            assert_eq!(x.rotate_right(k), c_rotr(x, k), "rotr({x:016x}, {k})");
        }
    }
}

#[test]
fn scratch_size_and_alignment() {
    let mut pad = Scratch::new();
    assert_eq!(pad.words().len(), (SCRATCH_BYTES / 8) as usize);
    let addr = pad.as_mut_ptr() as usize;

    assert_eq!(addr % 65536, 0, "pad must be 64 KiB aligned, got {addr:#x}");
}

#[test]
fn checksum_is_order_sensitive() {
    let mut a = Scratch::new();
    a.words_mut()[0] = 1;
    a.words_mut()[1] = 2;
    let ck_a = a.checksum();
    let mut b = Scratch::new();
    b.words_mut()[0] = 2;
    b.words_mut()[1] = 1;
    assert_ne!(ck_a, b.checksum(), "padck must depend on word order");
    let empty = Scratch::new();
    assert_ne!(ck_a, empty.checksum());
}

#[test]
fn build_program_deterministic() {
    let p1 = build_program(0xFEDC_BA09_8765_4321);
    let p2 = build_program(0xFEDC_BA09_8765_4321);
    let p3 = build_program(0xFEDC_BA09_8765_4322);
    assert_eq!(p1.slots(), p2.slots(), "same program seed, same program");
    assert_ne!(p1.slots(), p3.slots(), "program seed+1 must change the program");
}

#[test]
fn unsafe_stays_in_its_four_files() {
    const CLEAN: [&str; 5] = ["consts.rs", "op.rs", "rng.rs", "program.rs", "scratch.rs"];
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in CLEAN {
        let text = std::fs::read_to_string(src.join(name))
            .unwrap_or_else(|e| panic!("src/{name}: {e}"));
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") || code.starts_with("///") {
                continue;
            }
            assert!(
                !code.contains("unsafe"),
                "src/{name}:{}: `unsafe` has spread outside aes.rs / fill.rs / \
                 interp.rs / lib.rs: {line}",
                n + 1
            );
        }
    }
}

#[test]
fn gate_script_names_miner() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/check.sh");
    let src = std::fs::read_to_string(script)
        .unwrap_or_else(|e| panic!("the required gate script {script} is missing: {e}"));
    for needle in ["miner/Cargo.toml", "plaine-pow-mine", "--release", "clippy"] {
        assert!(
            src.contains(needle),
            "check.sh no longer mentions `{needle}`; the pow gate has been weakened"
        );
    }
}

#[test]
fn jit_absent_from_node_build() {
    let pow = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let node = pow.parent().and_then(|p| p.parent()).expect("node/");

    let manifest = std::fs::read_to_string(pow.join("Cargo.toml")).expect("Cargo.toml");
    assert!(
        !manifest.contains("[features]"),
        "plaine-pow has grown a [features] section; a `jit` feature would let feature \
         unification compile the emitter into the node's rlib"
    );

    let ws = std::fs::read_to_string(node.join("Cargo.toml")).expect("node/Cargo.toml");
    assert!(
        !ws.contains("crates/pow/mine"),
        "node/Cargo.toml lists crates/pow/mine as a workspace member; the JIT is back \
         in the node's build"
    );

    for name in ["VirtualAlloc", "VirtualProtect", "mprotect", "PROT_EXEC"] {
        for entry in std::fs::read_dir(pow.join("src")).expect("src/") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source file");
            assert!(
                !text.contains(name),
                "{}: the node's PoW crate mentions `{name}` - it has acquired \
                 executable-memory machinery",
                path.display()
            );
        }
    }
}

#[test]
fn reused_pad_changes_digest() {
    let iso = Isochron::new().expect("hardware AES");
    let mut pad = Scratch::new();
    let seed = 0x1234_5678_9ABC_DEF0u64;
    let first = iso.verify_hash(&mut pad, seed);
    let again = iso.verify_hash(&mut pad, seed);
    assert_eq!(first, again, "verify_hash must be a pure function of the seed");

    let prog = build_program(iso.fill(&mut pad, seed ^ 1));
    let wrong = iso.interp(&prog, &mut pad, seed);
    assert_ne!(wrong, first);
}
