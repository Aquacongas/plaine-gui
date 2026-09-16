#[path = "common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;

const MAINNET_INPUT: &str = include_str!("../src/genesis/mainnet.input");
const MAINNET_NOTE: &[u8] = include_bytes!("../src/genesis/mainnet.note");

fn mainnet_genesis() -> String {
    let input = plaine_wallet::genesis::parse_input(MAINNET_INPUT)
        .expect("the embedded mainnet genesis input must parse");
    let g = plaine_wallet::genesis::build(&input, MAINNET_NOTE)
        .expect("the embedded mainnet genesis must build");
    plaine_consensus::hex::encode(&g.block_hash)
}

#[test]
fn fresh_dir_writes_config_and_serves() {
    let dir = scratch("startup");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_101, 20_102, 20_103, &[]);
    let node = start("node", &dir, &cfg, 20_101, 20_102, 20_103);

    let written = data.join("noded.toml");
    if written.exists() {
        let text = std::fs::read_to_string(&written).expect("read the generated config");
        for line in text.lines() {
            let l = line.trim();
            assert!(
                l.is_empty() || l.starts_with('#') || l.starts_with('['),
                "the generated config must be inert on first run, found a live line: {l:?}"
            );
        }
    }

    let info = rpc(node.rpc, "chain_getInfo", "[]").expect("chain_getInfo");
    assert_eq!(text(&info, "network").as_deref(), Some("main"));

    let expected = mainnet_genesis();
    assert_eq!(num(&info, "height"), Some(0), "a fresh node is at height 0");
    assert_eq!(
        text(&info, "tipHash").as_deref(),
        Some(expected.as_str()),
        "the tip of a fresh node is not the genesis its own embedded input file builds. The \
         binary and this test read the SAME mainnet.input and mainnet.note, so a mismatch means \
         the node committed something other than what that material describes - not that the \
         material changed."
    );

    let g = rpc(node.rpc, "chain_getBlockByHeight", "[0,0]").expect("genesis block");
    assert!(g.contains(&expected), "genesis block record names its own hash");

    let audit = rpc(node.rpc, "emission_audit", "[0]").expect("emission_audit");
    assert_eq!(num(&audit, "issuedMile"), num(&audit, "expectedByFormulaMile"));
}

#[test]
fn second_start_loads_not_recreates() {
    let dir = scratch("startup-reload");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_111, 20_112, 20_113, &[]);
    let first = {
        let n = start("first", &dir, &cfg, 20_111, 20_112, 20_113);
        let h = tip_hash(n.rpc).expect("tip");
        drop(n);
        h
    };

    std::thread::sleep(Duration::from_millis(500));
    let second = start("second", &dir, &cfg, 20_111, 20_112, 20_113);
    assert_eq!(
        tip_hash(second.rpc).as_deref(),
        Some(first.as_str()),
        "a reopened data directory must load the SAME genesis, not create a second one"
    );
}

#[test]
fn all_seams_open_and_coherent() {
    let dir = scratch("startup-seams");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_121, 20_122, 20_123, &[]);
    let node = start("node", &dir, &cfg, 20_121, 20_122, 20_123);

    for (what, port) in [("p2p", node.p2p), ("stratum", node.stratum)] {
        std::net::TcpStream::connect(("127.0.0.1", port))
            .unwrap_or_else(|e| panic!("{what} is not accepting on 127.0.0.1:{port}: {e}"));
    }

    let info = rpc(node.rpc, "chain_getInfo", "[]").expect("chain_getInfo");

    let peers = num(&info, "peers").unwrap_or(0);
    if peers == 0 {
        assert!(
            !info.contains("\"bestKnownHeight\":") || info.contains("\"bestKnownHeight\":null"),
            "with no peers there is no best known height to report: {info}"
        );
    }

    let notes = rpc(node.rpc, "author_getNotes", "[]").expect("author_getNotes");
    assert!(notes.contains("\"total\":0"), "a fresh chain holds no announcements: {notes}");
    let cp = rpc(node.rpc, "checkpoint_getStatus", "[]").expect("checkpoint_getStatus");
    assert!(cp.contains("\"keySource\":\"embedded\""), "{cp}");

    assert!(
        cp.contains("0741b159"),
        "a default-configured node must verify checkpoints under the production key: {cp}"
    );
    assert!(
        !cp.to_ascii_uppercase().contains("PLACEHOLDER"),
        "the checkpoint status still names a placeholder: {cp}"
    );

    let b = rpc(node.rpc, "node_getBudgets", "[]").expect("node_getBudgets");
    assert!(
        num(&b, "cpuPoolThreads").unwrap_or(0) >= 2,
        "P = clamp(cores/2, 2, 8) is at least 2: {b}"
    );
}
