mod support;

use plaine_chain::mock::{CountingPow, MemStore, MockClock};
use plaine_chain::{Clock, PowVerifier, Sink, Store};

const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn runtime_dep_is_only_consensus() {
    let deps = section(MANIFEST, "[dependencies]");
    let names: Vec<&str> = deps
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split(['=', ' ']).next())
        .collect();
    assert_eq!(names, vec!["plaine-consensus"], "runtime dependencies drifted: {names:?}");
}

#[test]
fn signer_is_dev_dep_only() {
    let deps = section(MANIFEST, "[dependencies]");
    let code: String = deps
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!code.contains("ed25519"), "the signer must not be a runtime dependency");
    let dev = section(MANIFEST, "[dev-dependencies]");
    assert!(dev.contains("ed25519-dalek"), "the tests do need a signer");
}

#[test]
fn no_module_reaches_for_a_forbidden_crate() {
    let sources: [(&str, &str); 16] = [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("body.rs", include_str!("../src/body.rs")),
        ("checkpoints.rs", include_str!("../src/checkpoints.rs")),
        ("error.rs", include_str!("../src/error.rs")),
        ("forkchoice.rs", include_str!("../src/forkchoice.rs")),
        ("gates.rs", include_str!("../src/gates.rs")),
        ("header.rs", include_str!("../src/header.rs")),
        ("index.rs", include_str!("../src/index.rs")),
        ("manager.rs", include_str!("../src/manager.rs")),
        ("mempool.rs", include_str!("../src/mempool.rs")),
        ("mock.rs", include_str!("../src/mock.rs")),
        ("reorg.rs", include_str!("../src/reorg.rs")),
        ("state.rs", include_str!("../src/state.rs")),
        ("traits.rs", include_str!("../src/traits.rs")),
        ("types.rs", include_str!("../src/types.rs")),
        ("work.rs", include_str!("../src/work.rs")),
    ];
    for (name, src) in sources {
        for forbidden in ["tokio", "serde", "anyhow", "tracing::", "ed25519_dalek"] {
            assert!(
                !src.contains(&format!("use {forbidden}")),
                "{name} imports {forbidden}"
            );
        }
        assert!(!src.contains("unsafe "), "{name} contains an unsafe block");
    }
}

#[test]
fn crate_forbids_unsafe_code() {
    assert!(
        include_str!("../src/lib.rs").contains("#![forbid(unsafe_code)]"),
        "forbid(unsafe_code) must be at crate level, where it cannot be forgotten in a module"
    );
}

fn assert_send_sync<T: Send + Sync + ?Sized>() {}

#[test]
fn traits_and_mock_are_send_sync() {
    assert_send_sync::<dyn Store>();
    assert_send_sync::<dyn Sink>();
    assert_send_sync::<dyn PowVerifier>();
    assert_send_sync::<dyn Clock>();
    assert_send_sync::<MemStore>();
    assert_send_sync::<CountingPow>();
    assert_send_sync::<MockClock>();
}

#[test]
fn limits_come_from_consensus() {
    use plaine_consensus::constants as k;
    let p = plaine_chain::ChainParams::default();
    assert_eq!(k::HEADER_BYTES, 132);
    assert_eq!(k::MAX_BLOCK_BYTES, 1_048_576);
    assert_eq!(k::MAX_TXS_PER_BLOCK, 4_096);
    assert_eq!(k::MAX_TX_BYTES, 8_192);
    assert_eq!(p.max_reorg_depth, k::MAX_REORG_DEPTH);
    assert_eq!(p.sync_window_secs, k::SYNC_WINDOW_SECS);
    assert_eq!(p.mempool.max_txs, k::MAX_MEMPOOL_TXS);
    assert_eq!(p.mempool.max_nonce_gap, k::MAX_MEMPOOL_NONCE_GAP);
    assert_eq!(p.mempool.max_txs_per_sender, k::MAX_MEMPOOL_TXS_PER_SENDER);
    assert_eq!(p.asert_anchor_interval, k::ASERT_ANCHOR_INTERVAL);
    const { assert!(k::COINBASE_MATURITY > k::MAX_REORG_DEPTH) };
}

#[test]
fn interpreter_budget_uses_tighter_number() {
    let p = plaine_chain::ChainParams::default();
    assert_eq!(p.pow_budget_micros, 100_000);
    assert_eq!(p.pow_budget_window_ms, 10_000);
    assert_eq!(p.pow_budget_burst_micros, 300_000);
}

fn section<'a>(toml: &'a str, header: &str) -> &'a str {
    let start = toml.find(header).unwrap_or_else(|| panic!("no {header} section")) + header.len();
    let rest = &toml[start..];
    let end = rest
        .lines()
        .scan(0usize, |acc, l| {
            let at = *acc;
            *acc += l.len() + 1;
            Some((at, l))
        })
        .find(|(_, l)| l.trim_start().starts_with('['))
        .map(|(at, _)| at)
        .unwrap_or(rest.len());
    &rest[..end]
}
