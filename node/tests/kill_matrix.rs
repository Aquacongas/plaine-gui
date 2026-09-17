#[path = "common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;

const RING_MAX_BLOCKS: u64 = 256;

const COMMIT_TRIALS: usize = 3;

const MINE_BUDGET: Duration = Duration::from_secs(420);

const ORDERED_STAGES: [&str; 5] = [
    "stratum: miners told to disconnect",
    "p2p: peers closed, engine joined",
    "validator joined",
    "storage sealed and fsynced",
    "clean exit",
];

#[test]
fn chain_checker_not_vacuous() {
    let h = |n: u8| format!("{n:02}").repeat(32);

    let dup = vec![(0u64, h(0)), (1, h(1)), (2, h(1))];
    assert!(
        std::panic::catch_unwind(|| {
            let mut seen = std::collections::HashSet::new();
            for (_, hash) in &dup {
                assert!(seen.insert(hash.clone()), "duplicate");
            }
        })
        .is_err(),
        "the duplicate-hash check passed a chain with a repeated hash"
    );

    let hole = vec![(0u64, h(0)), (1, h(1)), (3, h(3))];
    assert!(
        std::panic::catch_unwind(|| {
            for w in hole.windows(2) {
                assert_eq!(w[1].0, w[0].0 + 1, "hole");
            }
        })
        .is_err(),
        "the contiguity check passed a chain with a hole at height 2"
    );
}

fn wait_for_height_change(port: u16, from: u64, within: Duration) -> Option<u64> {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < within {
        if let Some(h) = height(port) {
            if h != from {
                return Some(h);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn clean_stop_midblock_loses_nothing() {
    ensure_console();
    let dir = scratch("kill-term");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_401, 20_402, 20_403, &[]);

    let (log, height_at_signal) = {
        let mut node = start("first", &dir, &cfg, 20_401, 20_402, 20_403);

        let miner = mine_background(&node, MINE_BUDGET);
        let h = wait_for_height_change(node.rpc, 0, MINE_BUDGET).unwrap_or_else(|| {
            panic!(
                "no block was mined within {MINE_BUDGET:?}; a stop cannot be tested mid-block \
                 on a chain with no blocks. Node log:\n{}",
                std::fs::read_to_string(&node.log).unwrap_or_default()
            )
        });

        let h = wait_for_height_change(node.rpc, h, MINE_BUDGET).unwrap_or(h);

        request_stop(&node).expect("deliver a stop signal to the node");
        let code = wait_exit(&mut node, Duration::from_secs(60));

        drop(miner);

        let log = std::fs::read_to_string(&node.log).unwrap_or_default();
        assert_eq!(
            code,
            Some(0),
            "a stop signal that arrives while the node is committing must still be handled. \
             exit {code:?}. Node log:\n{log}"
        );
        (log, h)
    };

    assert!(
        log.contains("received; stopping cleanly"),
        "the node exited 0 but never logged receiving a signal. Node log:\n{log}"
    );
    let mut at = 0usize;
    for stage in ORDERED_STAGES {
        match log[at..].find(stage) {
            Some(i) => at += i + stage.len(),
            None => panic!(
                "shutdown stage `{stage}` is missing or out of order under load. Sealing before \
                 the validator has joined seals a write transaction another thread is still \
                 using, and load is exactly when that races. Node log:\n{log}"
            ),
        }
    }

    let durable: u64 = log
        .split("clean stop at height ")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("the stop never named a durable height. Node log:\n{log}"));
    assert!(
        durable >= height_at_signal,
        "the node reported being durable at {durable} but was already advertising \
         {height_at_signal} before the signal was even sent"
    );

    let node = start("second", &dir, &cfg, 20_401, 20_402, 20_403);
    assert_eq!(
        height(node.rpc),
        Some(durable),
        "a CLEAN stop lost heights under load. It sealed at {durable} and came back lower; \
         that is the difference between this test and the hard-kill cases below, which are \
         allowed a {RING_MAX_BLOCKS}-block window because they run no flush."
    );
    let chain = walk_chain(node.rpc);
    assert_eq!(chain.len() as u64, durable + 1);
    assert_chain_intact(node.rpc, &chain);
    eprintln!(
        "CLEAN STOP MID-BLOCK: advertising {height_at_signal} at the signal, sealed at          {durable}, restarted at {durable}, {} heights walked and linked",
        chain.len()
    );
}

#[test]
fn hard_kill_midblock_no_torn_chain() {
    let dir = scratch("kill-9-midblock");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_411, 20_412, 20_413, &[]);

    let before = {
        let mut node = start("first", &dir, &cfg, 20_411, 20_412, 20_413);
        let miner = mine_background(&node, MINE_BUDGET);
        let h = wait_for_height_change(node.rpc, 0, MINE_BUDGET).unwrap_or_else(|| {
            panic!(
                "no block within {MINE_BUDGET:?}. Node log:\n{}",
                std::fs::read_to_string(&node.log).unwrap_or_default()
            )
        });
        let h = wait_for_height_change(node.rpc, h, MINE_BUDGET).unwrap_or(h);

        hard_kill(&mut node);
        drop(miner);
        h
    };

    std::thread::sleep(Duration::from_millis(500));
    let node = start("second", &dir, &cfg, 20_411, 20_412, 20_413);
    let after = height(node.rpc).expect("height after restart");
    assert!(
        after + RING_MAX_BLOCKS >= before,
        "after a hard kill the node came back at {after}, more than the {RING_MAX_BLOCKS}-block \
         unsealed window below the {before} it was advertising"
    );
    let chain = walk_chain(node.rpc);
    assert_chain_intact(node.rpc, &chain);
    eprintln!(
        "HARD KILL MID-BLOCK: {before} before the kill, {after} after, {} heights walked and linked (window {RING_MAX_BLOCKS})",
        chain.len()
    );

    for (h, _) in &chain {
        assert!(
            rpc(node.rpc, "chain_getBlockByHeight", &format!("[{h},0]")).is_some(),
            "height {h} has a header but no body after a mid-block hard kill"
        );
    }
}

#[test]
fn hard_kill_at_commit_window_survived() {
    for trial in 0..COMMIT_TRIALS {
        let dir = scratch(&format!("kill-commit-{trial}"));
        let data = dir.join("data");
        let port = 20_421 + (trial as u16 * 10);
        let cfg = write_config(&dir, &data, port, port + 1, port + 2, &[]);

        let before = {
            let mut node = start("first", &dir, &cfg, port, port + 1, port + 2);
            let miner = mine_background(&node, MINE_BUDGET);

            let h = wait_for_height_change(node.rpc, 0, MINE_BUDGET).unwrap_or_else(|| {
                panic!(
                    "trial {trial}: no block within {MINE_BUDGET:?}. Node log:\n{}",
                    std::fs::read_to_string(&node.log).unwrap_or_default()
                )
            });

            let h2 = wait_for_height_change(node.rpc, h, MINE_BUDGET)
                .unwrap_or_else(|| panic!("trial {trial}: the chain stopped advancing at {h}"));
            hard_kill(&mut node);
            drop(miner);
            h2
        };

        std::thread::sleep(Duration::from_millis(500));
        let node = start("second", &dir, &cfg, port, port + 1, port + 2);
        let after = height(node.rpc)
            .unwrap_or_else(|| panic!("trial {trial}: the node did not come back at all"));
        assert!(
            after + RING_MAX_BLOCKS >= before,
            "trial {trial}: came back at {after}, more than {RING_MAX_BLOCKS} below {before}"
        );

        let chain = walk_chain(node.rpc);
        assert_chain_intact(node.rpc, &chain);
        assert_eq!(
            chain.len() as u64,
            after + 1,
            "trial {trial}: the node claims height {after} but served {} heights",
            chain.len()
        );
        eprintln!(
            "COMMIT-WINDOW KILL trial {trial}: {before} before, {after} after, {} heights walked and linked",
            chain.len()
        );

        let log = std::fs::read_to_string(&node.log).unwrap_or_default();
        assert!(
            !log.contains("created the test genesis"),
            "trial {trial}: the restart created a second genesis instead of loading the chain. \
             Node log:\n{log}"
        );
    }
}
