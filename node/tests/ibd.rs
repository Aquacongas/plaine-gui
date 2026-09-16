#[path = "common/mod.rs"]
mod common;

use common::*;
use std::time::{Duration, Instant};

#[test]
fn fresh_node_syncs_and_follows() {
    let dir_a = scratch("ibd-a");
    let data_a = dir_a.join("data");
    let cfg_a = write_config(&dir_a, &data_a, 20_301, 20_302, 20_303, &[]);
    let a = start("a", &dir_a, &cfg_a, 20_301, 20_302, 20_303);

    let mined = mine_to(&a, 2, Duration::from_secs(300));
    assert!(
        mined >= 1,
        "A produced no block in 300 s, so there is nothing for B to sync. A's log:\n{}",
        std::fs::read_to_string(&a.log).unwrap_or_default()
    );
    let a_tip = tip_hash(a.rpc).expect("A's tip");

    let dir_b = scratch("ibd-b");
    let data_b = dir_b.join("data");
    let cfg_b = write_config(
        &dir_b,
        &data_b,
        20_311,
        20_312,
        20_313,
        &["127.0.0.1:20301".to_string()],
    );
    let b = start("b", &dir_b, &cfg_b, 20_311, 20_312, 20_313);

    let linked = |a: &Node, b: &Node| -> Result<(), String> {
        if height(a.rpc).is_none() {
            return Err("A stopped answering RPC".into());
        }
        match height(b.rpc) {
            None => return Err("B stopped answering RPC".into()),
            Some(_) => {}
        }
        if peers(b.rpc) < 1 {
            return Err("B lost its peer, so nothing can reach it".into());
        }
        Ok(())
    };
    assert_eq!(height(b.rpc), Some(0), "B starts empty");

    let t0 = Instant::now();
    wait_until(
        "B connects to A at all",
        Duration::from_secs(60),
        || peers(b.rpc),
        |p| *p >= 1,
    );

    let reached = wait_until_healthy(
        "B reaches A's height",
        STALL_CEILING,
        || linked(&a, &b),
        || height(b.rpc).unwrap_or(0),
        |h| *h >= mined,
    );
    let secs = t0.elapsed().as_secs_f64();

    assert_eq!(reached, mined, "B synced to A's height");
    assert_eq!(
        tip_hash(b.rpc).as_deref(),
        Some(a_tip.as_str()),
        "same height, different tip: the headers that crossed the socket are not the headers A \
         holds"
    );

    for h in 0..=reached {
        let ra = rpc(a.rpc, "chain_getBlockByHeight", &format!("[{h},0]"));
        let rb = rpc(b.rpc, "chain_getBlockByHeight", &format!("[{h},0]"));
        assert!(rb.is_some(), "B claims height {reached} but cannot serve block {h}");
        assert_eq!(ra, rb, "block {h} differs between A and B");
    }

    println!(
        "IBD: {} headers + bodies in {:.1}s = {:.1} blocks/s (validator-serial interpreter path)",
        reached + 1,
        secs,
        (reached + 1) as f64 / secs.max(1e-9)
    );

    let extended = mine_to(&a, mined + 1, Duration::from_secs(300));
    assert!(
        extended > mined,
        "A did not extend its own chain in 300 s (was {mined}, is {extended}). A's log:\n{}",
        std::fs::read_to_string(&a.log).unwrap_or_default()
    );
    let a_tip2 = tip_hash(a.rpc).expect("A tip");

    let followed = wait_until_healthy(
        "B follows A's new block",
        STALL_CEILING,
        || linked(&a, &b),
        || height(b.rpc).unwrap_or(0),
        |h| *h >= extended,
    );
    assert_eq!(followed, extended);
    assert_eq!(
        tip_hash(b.rpc).as_deref(),
        Some(a_tip2.as_str()),
        "B followed to the right height on the wrong block"
    );

    assert!(
        rpc(b.rpc, "chain_getBlockByHeight", &format!("[{extended},0]")).is_some(),
        "B followed the header of block {extended} without its body"
    );
}

fn peers(port: u16) -> u64 {
    let Some(info) = rpc(port, "chain_getInfo", "[]") else {
        return 0;
    };
    if let Some(reason) = text(&info, "stallReason") {
        if let Some(rest) = reason.strip_prefix("no new block for ") {
            if let Some(i) = rest.find("s while ") {
                if let Some(n) = rest[i + 8..].split(' ').next().and_then(|s| s.parse().ok()) {
                    return n;
                }
            }
        }
        if reason.contains("no peers connected") {
            return 0;
        }
    }

    1
}

#[test]
fn unhealthy_wait_ends_with_reason() {
    let polls = std::cell::Cell::new(0u32);
    let t0 = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_until_healthy(
            "something that can never happen",
            STALL_CEILING,
            || {
                polls.set(polls.get() + 1);
                if polls.get() >= 3 {
                    Err("the peer went away".into())
                } else {
                    Ok(())
                }
            },
            || 0u64,
            |_| false,
        )
    }))
    .expect_err("a wait whose health fails must panic, not return");

    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();

    assert!(
        msg.contains("the peer went away"),
        "the health reason must reach the operator, not be swallowed: {msg}"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(30),
        "gave up after {:?}, which means health did not end the wait and this is just a slower timeout",
        t0.elapsed()
    );
}

#[test]
fn healthy_wait_returns_on_condition() {
    let n = std::cell::Cell::new(0u64);
    let got = wait_until_healthy(
        "a condition that becomes true",
        STALL_CEILING,
        || Ok(()),
        || {
            n.set(n.get() + 1);
            n.get()
        },
        |v| *v >= 3,
    );
    assert_eq!(got, 3, "it must return the observation, not a later one");
}
