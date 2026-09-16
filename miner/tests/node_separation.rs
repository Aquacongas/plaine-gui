use std::path::{Path, PathBuf};

fn mine_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn pow_dir() -> PathBuf {
    mine_dir().parent().expect("repo root").join("lib").join("pow")
}
fn node_dir() -> PathBuf {
    mine_dir().parent().expect("repo root").to_path_buf()
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn this_package_roots_its_own_workspace() {
    let toml = read(&mine_dir().join("Cargo.toml"));
    let has = toml
        .lines()
        .any(|l| l.trim() == "[workspace]" || l.trim().starts_with("[workspace]"));
    assert!(
        has,
        "mine/Cargo.toml no longer has a bare [workspace] table. Without it this \
         package joins node/'s workspace, and the JIT enters the node's lockfile and \
         dependency graph."
    );
}

#[test]
fn node_workspace_excludes_miner() {
    let toml = read(&node_dir().join("Cargo.toml"));
    assert!(
        !toml.contains("crates/pow/mine"),
        "node/Cargo.toml now lists crates/pow/mine as a workspace member. The JIT is \
         back in the node's build."
    );

    assert!(
        !toml.contains("crates/*"),
        "node/Cargo.toml's members list has become a glob; it must name its members \
         explicitly or nested packages get swept in"
    );

    assert!(
        !toml.contains("plaine-pow-mine"),
        "node/Cargo.toml mentions plaine-pow-mine"
    );
}

#[test]
fn miner_absent_from_node_lock() {
    let lock = node_dir().join("Cargo.lock");
    if !lock.exists() {
        eprintln!("note: {} does not exist yet; skipping", lock.display());
        return;
    }
    let text = read(&lock);
    assert!(
        !text.contains("plaine-pow-mine"),
        "plaine-pow-mine is in node/Cargo.lock: the JIT entered the node's resolved graph \
         (and no, DCE is not a guarantee it stays out)"
    );

    assert!(
        text.contains("plaine-pow"),
        "node/Cargo.lock does not mention plaine-pow at all - this is not the \
         lockfile this test thinks it is"
    );
}

#[test]
fn shipping_crate_has_no_page_mapping() {
    const FORBIDDEN: [&str; 6] = [
        "VirtualAlloc",
        "VirtualProtect",
        "mprotect",
        "PAGE_EXECUTE",
        "PROT_EXEC",
        "transmute",
    ];
    let src = pow_dir().join("src");
    let mut checked = 0;
    for entry in std::fs::read_dir(&src).expect("crates/pow/src") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = read(&path);
        checked += 1;
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "{} mentions `{needle}`: the node's PoW crate has acquired \
                 executable-memory machinery",
                path.display()
            );
        }
    }
    assert!(checked >= 8, "expected to scan the whole of crates/pow/src, saw {checked} files");
}

#[test]
fn the_emitters_contain_no_unsafe() {
    for name in ["emit_x86.rs", "emit_arm64.rs", "sizes.rs"] {
        let text = read(&mine_dir().join("src").join(name));
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") || code.starts_with("///") || code.starts_with("//!") {
                continue;
            }
            assert!(
                !code.contains("unsafe"),
                "src/{name}:{}: `unsafe` has spread outside page.rs and lib.rs: {line}",
                n + 1
            );
        }
    }
}
