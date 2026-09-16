#[path = "common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;

const ORDERED_STAGES: [&str; 5] = [
    "stratum: miners told to disconnect",
    "p2p: peers closed, engine joined",
    "validator joined",
    "storage sealed and fsynced",
    "clean exit",
];

#[test]
fn sigterm_ordered_shutdown_loses_nothing() {
    ensure_console();

    let dir = scratch("sigterm");
    let data = dir.join("data");
    let cfg = write_config(&dir, &data, 20_221, 20_222, 20_223, &[]);

    let (height_before, hash_before, log) = {
        let mut node = start("first", &dir, &cfg, 20_221, 20_222, 20_223);

        let h = mine_to(&node, 2, Duration::from_secs(300));
        assert!(
            h >= 1,
            "the miner produced no block in 300 s; with nothing above genesis this test would \
             assert that a stop preserves a block the node created at startup and flushed \
             immediately, which proves nothing about the stop. Node log:\n{}",
            std::fs::read_to_string(&node.log).unwrap_or_default()
        );

        let hash = tip_hash(node.rpc).expect("tip");

        request_stop(&node).expect(
            "could not deliver a stop signal to the node. On Windows this is \
             GenerateConsoleCtrlEvent, which needs this process to have a console and the node to \
             be in its own process group - `common::ensure_console` and the CREATE_NEW_PROCESS_GROUP \
             flag in `common::start` are both required for it.",
        );

        let code = wait_exit(&mut node, Duration::from_secs(60));
        let log = std::fs::read_to_string(&node.log).unwrap_or_default();
        assert_eq!(
            code,
            Some(0),
            "the node did not exit cleanly after a real stop signal (exit {code:?}). `None` means \
             it never exited at all and was killed by this harness; a non-zero code means the \
             handler ran and the shutdown failed. Node log:\n{log}"
        );
        (h, hash, log)
    };

    assert!(
        log.contains("received; stopping cleanly"),
        "the node exited 0 but never logged receiving a signal, so something other than the \
         handler stopped it. Node log:\n{log}"
    );

    let mut at = 0usize;
    for stage in ORDERED_STAGES {
        match log[at..].find(stage) {
            Some(i) => at += i + stage.len(),
            None => panic!(
                "the shutdown stage `{stage}` is missing, or came out of order - every stage \
                 before it was found earlier in the log. The order is the argument: sealing \
                 before the validator has joined seals a write transaction another thread is \
                 still using. Node log:\n{log}"
            ),
        }
    }

    let node = start("second", &dir, &cfg, 20_221, 20_222, 20_223);
    assert_eq!(
        height(node.rpc),
        Some(height_before),
        "a CLEAN stop lost heights. It was advertising {height_before} when it was signalled, and \
         a stop that ends in CommitSink::flush() must lose none - that is exactly the difference \
         between this test and crash.rs, which is allowed a {} block window because a SIGKILL \
         runs no flush.",
        plaine_noded_ring_max()
    );
    assert_eq!(
        tip_hash(node.rpc).as_deref(),
        Some(hash_before.as_str()),
        "same height, different hash after a clean stop is a fork, not a recovery"
    );

    assert!(
        log.contains(&format!("clean stop at height {height_before}, durable")),
        "the shutdown line did not name the height it made durable. Node log:\n{log}"
    );

    assert!(
        !log.contains("This run wrote 0 block(s)"),
        "the final flush reported writing no blocks, but the node mined to height \
         {height_before}. Node log:\n{log}"
    );

    for h in 0..=height_before {
        assert!(
            rpc(node.rpc, "chain_getBlockByHeight", &format!("[{h},0]")).is_some(),
            "the restarted node claims height {height_before} but cannot serve block {h}"
        );
    }
}

fn plaine_noded_ring_max() -> u64 {
    256
}
