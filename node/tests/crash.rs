#[path = "common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;

#[test]
fn hard_kill_restarts_same_tip() {
    let dir = scratch("crash");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_201, 20_202, 20_203, &[]);

    let (before_height, before_hash) = {
        let mut node = start("first", &dir, &cfg, 20_201, 20_202, 20_203);

        let h = mine_to(&node, 2, Duration::from_secs(300));
        assert!(
            h >= 1,
            "the miner produced no block in 300 s; without a chain there is nothing to crash \
             mid-way through. Node log:\n{}",
            std::fs::read_to_string(&node.log).unwrap_or_default()
        );
        let hash = tip_hash(node.rpc).expect("tip");

        hard_kill(&mut node);
        (h, hash)
    };

    std::thread::sleep(Duration::from_millis(500));
    let node = start("second", &dir, &cfg, 20_201, 20_202, 20_203);
    let after = height(node.rpc).expect("height after restart");

    assert!(
        after + plaine_noded_ring_max() >= before_height,
        "after a hard kill the node came back at {after}, more than the unsealed window below \
         {before_height}"
    );

    if after == before_height {
        assert_eq!(
            tip_hash(node.rpc).as_deref(),
            Some(before_hash.as_str()),
            "same height, different hash after a restart is a fork, not a recovery"
        );
    }

    let g = rpc(node.rpc, "chain_getBlockByHeight", "[0,0]").expect("genesis still readable");
    assert!(g.contains("\"height\":0"), "{g}");

    for h in 0..=after {
        assert!(
            rpc(node.rpc, "chain_getBlockByHeight", &format!("[{h},0]")).is_some(),
            "the node claims height {after} but cannot serve block {h}"
        );
    }
}

#[test]
fn restart_reloads_not_recreates() {
    let dir = scratch("crash-reload");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_211, 20_212, 20_213, &[]);
    let first_hash = {
        let mut node = start("first", &dir, &cfg, 20_211, 20_212, 20_213);
        let h = tip_hash(node.rpc).expect("tip");
        hard_kill(&mut node);
        h
    };
    std::thread::sleep(Duration::from_millis(500));
    let node = start("second", &dir, &cfg, 20_211, 20_212, 20_213);
    let log = std::fs::read_to_string(&node.log).unwrap_or_default();
    assert!(
        log.contains("loaded the main chain"),
        "the second start must LOAD, and say so. Log:\n{log}"
    );
    assert!(
        !log.contains("created the main genesis"),
        "the second start must not create a second genesis. Log:\n{log}"
    );
    assert_eq!(tip_hash(node.rpc).as_deref(), Some(first_hash.as_str()));
}

fn plaine_noded_ring_max() -> u64 {
    256
}
