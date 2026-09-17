use std::path::{Path, PathBuf};

fn frozen() -> Vec<(&'static str, u128)> {
    use plaine_consensus::constants as c;
    vec![
        ("MAX_REORG_DEPTH", c::MAX_REORG_DEPTH as u128),
        ("COINBASE_MATURITY", c::COINBASE_MATURITY as u128),
        ("MAX_HEADERS_PER_MSG", c::MAX_HEADERS_PER_MSG as u128),
        ("MAX_P2P_MSG_BYTES", c::MAX_P2P_MSG_BYTES as u128),
        ("MAX_PEERS", c::MAX_PEERS as u128),
        (
            "CHECKPOINT_SUNSET_HEIGHT",
            c::CHECKPOINT_SUNSET_HEIGHT as u128,
        ),
        ("HEADER_BYTES", c::HEADER_BYTES as u128),
        ("PORT_P2P", c::PORT_P2P as u128),
        ("PORT_RPC", c::PORT_RPC as u128),
        ("BLOCK_TIME_SECS", c::BLOCK_TIME_SECS as u128),
        ("BLOCKS_PER_YEAR", c::BLOCKS_PER_YEAR as u128),
        ("SYNC_WINDOW_SECS", c::SYNC_WINDOW_SECS as u128),
        ("MAX_FUTURE_DRIFT_SECS", c::MAX_FUTURE_DRIFT_SECS as u128),
        ("PUBKEY_BYTES", c::PUBKEY_BYTES as u128),
    ]
}

fn node_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("node/")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == ".git" || name == "miner" {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            if p.file_name().and_then(|n| n.to_str()) == Some("constant_drift.rs") {
                continue;
            }
            out.push(p);
        }
    }
}

fn parse_literal(raw: &str) -> Option<u128> {
    let t = raw
        .trim()
        .trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '_');
    let t = t.replace('_', "");
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u128>().ok()
    }
}

fn drifted(text: &str, name: &str, value: u128) -> Vec<(usize, u128)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let Some(at) = line.find(name) else { continue };

        if !line.contains("assert_eq!") {
            continue;
        }
        let after = &line[at + name.len()..];
        let Some(rest) = after.strip_prefix(',') else {
            continue;
        };
        let rhs = rest.split(&[',', ')'][..]).next().unwrap_or("").trim();
        if rhs.is_empty() || rhs.contains(['*', '+', '-', '/', ':']) {
            continue;
        }
        let Some(lit) = parse_literal(rhs) else {
            continue;
        };
        if lit != value {
            out.push((i + 1, lit));
        }
    }
    out
}

#[test]
fn no_crate_pins_stale_constant() {
    let mut files = Vec::new();
    rust_files(&node_dir(), &mut files);
    assert!(
        files.len() > 50,
        "found only {} rust files - the walk is wrong",
        files.len()
    );

    let table = frozen();
    let mut findings = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (name, value) in &table {
            for (line, found) in drifted(&text, name, *value) {
                findings.push(format!(
                    "{}:{line}: pins {name} to {found}, but it is {value}",
                    path.strip_prefix(node_dir()).unwrap_or(path).display()
                ));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "a consensus constant moved and these pins did not:\n  {}",
        findings.join("\n  ")
    );
}

#[test]
fn scanner_catches_wrong_line() {
    let historical = "    assert_eq!(spec::MAX_REORG_DEPTH, 100);";
    let hits = drifted(historical, "MAX_REORG_DEPTH", 30);
    assert_eq!(
        hits,
        vec![(1, 100)],
        "the scanner no longer sees the drift it was written for"
    );

    assert!(drifted(
        "    assert_eq!(spec::MAX_REORG_DEPTH, 30);",
        "MAX_REORG_DEPTH",
        30
    )
    .is_empty());

    assert!(drifted(
        "    assert_eq!(spec::COINBASE_MATURITY, 2 * spec::MAX_REORG_DEPTH);",
        "COINBASE_MATURITY",
        60
    )
    .is_empty());

    assert_eq!(
        drifted(
            "assert_eq!(spec::BLOCKS_PER_YEAR, 525_961);",
            "BLOCKS_PER_YEAR",
            525_960
        ),
        vec![(1, 525_961)]
    );
    assert_eq!(
        drifted(
            "assert_eq!(spec::MAX_P2P_MSG_BYTES, 0x80_0000);",
            "MAX_P2P_MSG_BYTES",
            1
        ),
        vec![(1, 0x80_0000)]
    );
}
