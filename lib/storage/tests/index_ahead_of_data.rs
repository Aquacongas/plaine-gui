mod common;

use common::{serial, Chain, Scratch};
use plaine_storage::{open, DurabilityMode, StoreConfig, StoreError};

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.ibd_batch_blocks = Some(512);
    c
}

#[test]
fn headers_below_undo_floor_refused() {
    let _g = serial();
    let s = Scratch::new("index-ahead");

    let (mut c, r, _) = open(cfg_of(&s)).unwrap_or_else(|e| {
        panic!(
            "FIXTURE, not a finding: could not open a fresh store at {}: {e}. If this is ENOSPC, the box ran out of space building the fixture and the refusal below was never exercised.",
            s.0.display()
        )
    });
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(2_000, 1);
    c.extend(&common::commits(&bs)).unwrap_or_else(|e| {
        panic!(
            "FIXTURE, not a finding: committing the 2,000-block seed failed: {e}. Same reading as above: the refusal this test exists for was never reached."
        )
    });
    c.flush().unwrap_or_else(|e| panic!("FIXTURE, not a finding: the seed flush failed: {e}"));
    let tip = r.tip().height;
    let floor = r.undo_floor();
    drop(c);
    drop(r);
    assert!(tip > 0, "the seed committed nothing");
    assert!(
        floor > 0,
        "the undo ring already reaches height 0, so this store cannot express the case"
    );

    let dir = s.0.join("segments").join("hdr");
    let mut removed = 0u32;
    for e in std::fs::read_dir(&dir).expect("hdr dir") {
        let p = e.unwrap().path();
        std::fs::remove_file(&p).unwrap();
        removed += 1;
    }

    assert!(removed > 0, "no header segment was removed; nothing was injected");

    match open(cfg_of(&s)) {
        Ok((_c, r2, _)) => panic!(
            "a store whose entire header stream is gone OPENED, at tip {} - this is the \
             silently-short outcome the lane exists to prevent",
            r2.tip().height
        ),
        Err(e @ StoreError::StateBehindHeaders { .. }) => {
            let msg = e.to_string();
            assert!(
                msg.contains("headers reach") && msg.contains("undo floor"),
                "the refusal does not name what is missing: {msg}"
            );
            println!("  {removed} header segment(s) removed, state at {tip}: {msg}");
        }
        Err(other) => panic!(
            "index-ahead-of-data was reported as {other:?}. It must be \
             StateBehindHeaders, because that is the variant an operator's runbook \
             and the power-loss harness both key on."
        ),
    }
}
