use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn all() -> Vec<(PathBuf, String)> {
    let mut v = Vec::new();
    rust_files(&src(), &mut v);
    v.into_iter()
        .map(|p| {
            let s = std::fs::read_to_string(&p).unwrap_or_default();
            (p, s)
        })
        .collect()
}

fn toml_code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find('#') {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn chain_manager_never_shared() {
    for (p, s) in all() {
        let code = code_only(&s);
        for bad in ["Mutex<ChainManager", "RwLock<ChainManager", "Arc<ChainManager"] {
            assert!(
                !code.contains(bad),
                "{} contains `{bad}`. The chain manager stays by value in the validator \
                 thread's closure; sharing it moves consensus onto a tokio worker.",
                p.display()
            );
        }
    }
}

#[test]
fn async_wire_avoids_manager() {
    for (p, s) in all() {
        if !p.components().any(|c| c.as_os_str() == "wire") {
            continue;
        }
        let code = code_only(&s);
        let asyncy = code.contains("async fn") || code.contains(".await");
        if !asyncy {
            continue;
        }
        for bad in ["plaine_chain::ChainManager", "ChainManager<", "plaine_storage::Committer"] {
            assert!(
                !code.contains(bad),
                "{} is async AND names `{bad}`",
                p.display()
            );
        }
    }
}

#[test]
fn token_claimed_in_one_file() {
    let claims: Vec<String> = all()
        .into_iter()
        .filter(|(p, s)| {
            code_only(s).contains("OnConsensusThread::claim")
                && !p.ends_with("mod.rs")
        })
        .map(|(p, _)| p.display().to_string())
        .collect();
    assert_eq!(
        claims.len(),
        1,
        "`OnConsensusThread::claim` must be called in exactly one place - the validator thread's \
         own closure - and it is called in: {claims:?}"
    );
    assert!(
        claims[0].ends_with("validator.rs"),
        "the token is claimed in {}, not in validator.rs",
        claims[0]
    );
}

#[test]
fn plaine_pow_is_named_in_exactly_one_file() {
    let files: Vec<String> = all()
        .into_iter()
        .filter(|(_, s)| {
            let c = code_only(s);
            c.contains("plaine_pow::") || c.contains("use plaine_pow")
        })
        .map(|(p, _)| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        files,
        vec!["pow.rs".to_string()],
        "plaine_pow must be reachable from exactly one file, found: {files:?}"
    );
}

#[test]
fn emitter_not_reachable() {
    let manifest = toml_code_only(
        &std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read Cargo.toml"),
    );
    assert!(
        !manifest.contains("plaine-pow-mine"),
        "plaine-noded's manifest names the JIT crate"
    );
    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..");
    let lock = std::fs::read_to_string(ws.join("Cargo.lock")).unwrap_or_default();
    assert!(
        !lock.contains("plaine-pow-mine"),
        "the node workspace's lockfile resolves plaine-pow-mine, so the emitter is in the build"
    );
    let wsm = toml_code_only(
        &std::fs::read_to_string(ws.join("Cargo.toml")).expect("workspace manifest"),
    );
    assert!(!wsm.contains("crates/pow/mine"), "the workspace lists the miner as a member");
    assert!(!wsm.contains("crates/*"), "the members list has become a glob");

    for (p, s) in all() {
        let c = code_only(&s);
        for bad in ["VirtualAlloc", "VirtualProtect", "mprotect", "PROT_EXEC", "CodeW", "CodeX"] {
            assert!(!c.contains(bad), "{} names `{bad}`", p.display());
        }
    }
}

#[test]
fn crate_forbids_unsafe() {
    let main = std::fs::read_to_string(src().join("main.rs")).expect("main.rs");
    assert!(
        main.contains("#![forbid(unsafe_code)]"),
        "the node keeps forbid(unsafe_code); only crates/pow is exempt and its unsafe is confined \
         to four files with SAFETY comments"
    );
}

#[test]
fn dependency_policy_holds() {
    let manifest = toml_code_only(
        &std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read Cargo.toml"),
    );
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("a dependencies section");
    for banned in ["serde", "clap", "anyhow", "tracing", "log =", "env_logger", "reqwest"] {
        assert!(
            !deps.contains(banned),
            "plaine-noded depends on `{banned}`, which the dependency policy forbids"
        );
    }
    for name in deps.lines().filter_map(|l| l.split('=').next()).map(str::trim) {
        if name.is_empty() || name.starts_with('#') || name.starts_with('[') {
            continue;
        }
        assert!(
            name.starts_with("plaine-") || name == "tokio",
            "unexpected dependency `{name}`: the node links the plaine crates and tokio, nothing \
             else"
        );
    }
}

#[test]
fn no_regtest_in_shipped_binary() {
    let code: Vec<(PathBuf, String)> = all()
        .into_iter()
        .map(|(p, s)| {
            let shipped = s.split("#[cfg(test)]").next().unwrap_or_default().to_string();
            (p, code_only(&shipped))
        })
        .collect();
    for (p, s) in &code {
        assert!(
            !s.contains("regtest") && !s.contains("Regtest"),
            "{} names the regtest profile. The shipped node must not reach a relaxed \
             difficulty floor.",
            p.display()
        );
    }
    let config = std::fs::read_to_string(src().join("config.rs")).expect("config.rs");
    let enum_body = config
        .split("pub enum Network {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("config::Network exists");
    let variants = enum_body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with('#'))
        .count();
    assert_eq!(
        variants, 1,
        "config::Network must stay Main only: a second variant is how a relaxed \
         consensus profile becomes selectable from a config file"
    );
}

#[test]
fn health_line_fed_both_clocks() {
    let node = all()
        .into_iter()
        .find(|(p, _)| p.file_name().is_some_and(|f| f == "node.rs"))
        .map(|(_, s)| code_only(&s))
        .expect("node.rs is in the crate");

    for feed in ["tracker.observe_gap(", "tracker.observe_top_claim(", "tracker.observe("] {
        assert!(
            node.contains(feed),
            "`node.rs` never calls `{feed}`, so that clock reads zero for the \
             life of the process and its stall arm is unreachable: a node \
             extending its own branch would report SYNCING for ever."
        );
    }
}

#[test]
fn p2p_rings_read_with_cursor() {
    let node = all()
        .into_iter()
        .find(|(p, _)| p.file_name().is_some_and(|f| f == "node.rs"))
        .map(|(_, s)| code_only(&s))
        .expect("node.rs is in the crate");
    for banned in ["net.actions()", "net.conditions()"] {
        assert!(
            !node.contains(banned),
            "`node.rs` calls `{banned}`, which snapshots a bounded ring; a cursor \
             from its length freezes and the reader goes silent. Use \
             `actions_since`/`conditions_since`."
        );
    }

    for required in [
        "net.actions_since(",
        "net.conditions_since(",
        "self.conditions_seen.store(next",
        "self.actions_seen.store(next",
    ] {
        assert!(
            node.contains(required),
            "`node.rs` never calls `{required}`: the engine journal and the \
             condition ring go unread, and the condition ring feeds the template gate."
        );
    }
}

mod followup_drift_guards {
    use super::all;

    fn source_of(name: &str) -> String {
        all()
            .into_iter()
            .find(|(p, _)| p.file_name().is_some_and(|f| f == name))
            .unwrap_or_else(|| panic!("{name} is in src/"))
            .1
    }

    #[test]
    fn stratum_ceiling_not_duplicated() {
        let src = source_of("config.rs");
        let decl = src
            .lines()
            .find(|l| l.contains("pub const STRATUM_CONNECTION_CEILING"))
            .expect("the constant is declared in config.rs");

        let idx = src.find(decl).expect("found above");
        let window = &src[idx..(idx + 220).min(src.len())];
        assert!(
            window.contains("plaine_stratum::limits::SOLO_MAX_CONNECTIONS_CEILING"),
            "the ceiling must come from `plaine-stratum`, which is where the \
             cost of raising it is written down: {window}"
        );
        assert!(
            !window.contains("8_192") && !window.contains("8192"),
            "the number is spelled out again: {window}"
        );
    }

    #[test]
    fn template_bound_not_duplicated() {
        let src = source_of("jobs.rs");
        let line = src
            .lines()
            .find(|l| l.contains("if c.len() >="))
            .expect("the cache bound is in jobs.rs");
        assert!(
            line.contains("plaine_stratum::limits::SOLO_TEMPLATE_LRU"),
            "the bound must come from the trait's constant: {line}"
        );
        assert!(!line.contains("64"), "the number is spelled out again: {line}");
    }

    #[test]
    fn boot_verifies_state_fingerprint() {
        let src = source_of("node.rs");
        let at = src
            .find("reader.verify_state_fingerprint()")
            .expect("node.rs must call verify_state_fingerprint on the boot path");
        let arm = &src[at..(at + 1400).min(src.len())];
        assert!(
            arm.contains("StoreError::StateFingerprint"),
            "the mismatch must be told apart from an I/O fault: a census we \
             could not take is not a census of zero"
        );
        assert!(
            arm.contains("return Err(StartError::Storage"),
            "a fingerprint mismatch must refuse the start: it names no range to \
             quarantine, and every balance this node serves comes from that table"
        );
    }

    #[test]
    fn idle_clock_told_height_both_sites() {
        let beat = super::code_only(&source_of("node.rs"));
        assert!(
            beat.contains("idle_secs_at("),
            "node.rs must read the idle clock through `idle_secs_at`, which takes \
             the height: otherwise the verdict is judged against a clock never \
             told where the chain is"
        );
        assert!(
            !beat.contains("tracker.idle_secs("),
            "node.rs must not read the bare idle clock: that reads it before \
             anything told the clock the height in the same observation"
        );

        let rpc = super::code_only(&source_of("rpcview.rs"));
        assert!(
            rpc.contains("refreshed("),
            "`chain_getInfo` must re-run the ladder on the facts it serves, not quote a \
             verdict the heartbeat reached up to a minute ago beside a height and a tip \
             age read now"
        );

        let tick = super::code_only(&source_of("main.rs"));
        assert!(
            tick.contains("thresholds_line("),
            "the startup banner must state the stall thresholds and the quiet arm's \
             false-firing rate: an operator judging a `chain STALLED` line needs that \
             number in the same journal"
        );
        assert!(
            tick.contains("note_height("),
            "the heartbeat loop's 200 ms tick must keep the idle clock at real \
             resolution; without it the clock dates a block from the beat that \
             noticed it, and the printed duration is not the one measured"
        );
    }
}
