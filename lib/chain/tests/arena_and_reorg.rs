mod support;

use plaine_chain::index::NO_PARENT;
use plaine_chain::mempool::{Mempool, SigProof};
use plaine_chain::mock::{BuiltBlock, PowMode, Scenario};
use plaine_chain::types::{Account, Address, ChainParams, MempoolParams};
use plaine_chain::{Progress, Reject, Store};
use plaine_consensus::constants::MAX_HEADERS_PER_MSG;
use support::*;

fn sibling_with_hash(chain: &Scenario, miner: Address, pivot: [u8; 32], below: bool) -> BuiltBlock {
    let at = chain.height() - 1;
    for k in 0..1_000_000u64 {
        let mut f = chain.fork_at(at).with_miner(miner);
        let b = f.push_block_with(&[], move |mut h| {
            h.nonce = k;
            h
        });
        if (b.rec.hash < pivot) == below {
            return b;
        }
    }
    panic!("no sibling on the wanted side of the pivot");
}

#[test]
fn reorg_rolls_nonce_back_tx_mineable() {
    let p = params();
    let miner = addr_of(&user_key(0x41));
    let sender = user_key(0x81);
    let s_addr = addr_of(&sender);
    let recipient = addr_of(&user_key(0x82));

    let honest = Scenario::genesis(&p, T0).with_miner(miner).extend(20);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    r.store.set_account(
        s_addr,
        Account {
            balance: 50_000_000,
            nonce: 0,
        },
    );
    let s_before = r.store.account(&s_addr);
    assert_eq!(s_before.nonce, 0);

    let xfer = signed_transfer(&sender, recipient, 1_000, 2_000_000, 0);
    let mut branch_a = honest.fork_at(20).with_miner(miner);
    branch_a.push_block(&[xfer]);
    r.offer(3, &blocks_above(&branch_a, 20));
    r.cm.advance().expect("adopted");
    assert_eq!(r.height(), 21);
    assert_eq!(r.store.account(&s_addr).nonce, 1, "the transfer was mined");

    let branch_b = honest.fork_at(20).with_miner(miner).spacing(1).extend(3);
    r.offer(4, &blocks_above(&branch_b, 20));
    r.cm.advance().expect("reorged");
    assert_eq!(r.cm.tip().hash, branch_b.tip().hash);

    let after = r.store.account(&s_addr);
    assert_eq!(after.balance, s_before.balance, "balance restored");
    assert_eq!(after.nonce, s_before.nonce, "the nonce restored");
    assert_eq!(after, s_before);

    assert_eq!(
        r.cm.mempool().len(),
        1,
        "the disconnected transfer came back"
    );
    let id = r.cm.mempool().executable_ids();
    assert_eq!(id.len(), 1, "it is mineable, not stranded as stale");
}

#[test]
fn partial_rollback_restores_nonce() {
    let p = params();
    let miner = addr_of(&user_key(0x41));
    let sender = user_key(0x86);
    let s_addr = addr_of(&sender);
    let to = addr_of(&user_key(0x87));

    let honest = Scenario::genesis(&p, T0).with_miner(miner).extend(20);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    r.store.set_account(
        s_addr,
        Account {
            balance: 50_000_000,
            nonce: 0,
        },
    );

    let mut branch_a = honest.fork_at(20).with_miner(miner);
    branch_a.push_block(&[signed_transfer(&sender, to, 1_000, 2_000_000, 0)]);
    branch_a.push_block(&[signed_transfer(&sender, to, 3_000, 2_000_000, 1)]);
    r.offer(3, &blocks_above(&branch_a, 20));
    r.cm.advance().expect("adopted");
    assert_eq!(r.store.account(&s_addr).nonce, 2);

    let branch_b = branch_a.fork_at(21).with_miner(miner).spacing(1).extend(3);
    r.offer(4, &blocks_above(&branch_b, 21));
    r.cm.advance().expect("reorged");
    assert_eq!(r.cm.tip().hash, branch_b.tip().hash);

    assert_eq!(
        r.store.account(&s_addr).nonce,
        1,
        "rolling away the second transfer restores nonce 1, never 0"
    );
    assert_eq!(
        r.store.account(&s_addr).balance,
        50_000_000 - 1_000 - 2_000_000,
        "only the second transfer's value came back"
    );
}

#[test]
fn competing_branch_reuses_rolled_nonce() {
    let p = params();
    let miner = addr_of(&user_key(0x41));
    let sender = user_key(0x83);
    let s_addr = addr_of(&sender);

    let honest = Scenario::genesis(&p, T0).with_miner(miner).extend(20);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    r.store.set_account(
        s_addr,
        Account {
            balance: 50_000_000,
            nonce: 0,
        },
    );

    let mut branch_a = honest.fork_at(20).with_miner(miner);
    branch_a.push_block(&[signed_transfer(
        &sender,
        addr_of(&user_key(0x84)),
        1_000,
        2_000_000,
        0,
    )]);
    r.offer(3, &blocks_above(&branch_a, 20));
    r.cm.advance().expect("adopted");
    assert_eq!(r.store.account(&s_addr).nonce, 1);

    let mut branch_b = honest.fork_at(20).with_miner(miner).spacing(1);
    branch_b.push_block(&[signed_transfer(
        &sender,
        addr_of(&user_key(0x85)),
        7_000,
        2_000_000,
        0,
    )]);
    let branch_b = branch_b.extend(2);
    r.offer(4, &blocks_above(&branch_b, 20));
    r.cm.advance().expect("the competing branch must validate");
    assert_eq!(
        r.cm.tip().hash,
        branch_b.tip().hash,
        "the heavier branch was adopted"
    );
    assert_eq!(
        r.store.account(&s_addr).nonce,
        1,
        "B's transfer consumed nonce 0"
    );
    assert_eq!(
        r.store.account(&s_addr).balance,
        50_000_000 - 7_000 - 2_000_000,
        "it moved B's amount, not A's"
    );
    assert_eq!(
        r.store.account(&addr_of(&user_key(0x84))).balance,
        0,
        "A's payee is unpaid"
    );
    assert_eq!(r.store.account(&addr_of(&user_key(0x85))).balance, 7_000);
}

#[test]
fn child_of_invalid_born_poisoned() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);

    let side = honest.fork_at(15).spacing(1).extend(8);
    r.clock.set_unix(side.tip().time.max(honest.tip().time));
    let side_blocks = blocks_above(&side, 15);
    let raws: Vec<[u8; 132]> = side_blocks.iter().map(|b| b.rec.raw).collect();
    r.cm.submit_headers_solicited(5, &raws).expect("headers");
    let mid = side_blocks[3].rec.hash;
    assert!(
        r.cm.index().get(&mid).is_some(),
        "the side branch is in the arena"
    );

    r.cm.invalidate(&mid);
    let validated_before = r.cm.stats().bodies_validated;

    let mut deeper = side.clone();
    let child = deeper.push_block(&[]);
    r.cm.submit_headers_solicited(5, &[child.rec.raw])
        .expect("headers");
    let node = r.cm.index().get(&child.rec.hash).expect("connected");
    assert!(
        node.invalid(),
        "a child of a poisoned ancestor is born poisoned"
    );

    assert_eq!(r.cm.advance().expect("no error"), Progress::NoChange);
    assert_eq!(
        r.cm.stats().bodies_validated,
        validated_before,
        "the counter assertion is the load-bearing half"
    );
}

#[test]
fn staged_terminal_is_lower_hash_sibling() {
    for reversed in [false, true] {
        let p = params();
        let honest = Scenario::genesis(&p, T0).extend(20);
        let mut r = Rig::new(&honest, p);
        r.sync(&honest, 1);
        let tip = r.tip_hash();

        let winner = sibling_with_hash(&honest, addr_of(&user_key(0x91)), tip, true);
        let loser = sibling_with_hash(&honest, addr_of(&user_key(0x92)), tip, false);
        assert!(winner.rec.hash < tip && loser.rec.hash > tip);

        let mut batch = vec![winner.rec.raw, loser.rec.raw];
        if reversed {
            batch.reverse();
        }
        let a = r.cm.submit_headers(6, &batch).expect("not halted");
        assert_eq!(
            a.connected, 2,
            "both siblings connect in arrival order {reversed}, because the terminal \
             that clears S6 is the lower-hash one either way"
        );

        r.cm.submit_block(&winner.rec.hash, winner.body.clone())
            .expect("admissible");
        assert!(matches!(r.cm.advance(), Ok(Progress::Advanced { .. })));
        assert_eq!(
            r.tip_hash(),
            winner.rec.hash,
            "the lower-hash sibling is adopted"
        );
    }
}

#[test]
fn headers_from_respects_cap() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(MAX_HEADERS_PER_MSG as u64 + 100);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    assert!(r.height() > MAX_HEADERS_PER_MSG as u64);

    assert_eq!(r.cm.headers_from(0, 100_000).len(), MAX_HEADERS_PER_MSG);
    assert_eq!(
        r.cm.headers_from(0, 10).len(),
        10,
        "a smaller request is honoured"
    );
}

#[test]
fn over_length_batch_refused() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(5);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let one = chain.blocks[3].rec.raw;
    let over: Vec<[u8; 132]> = (0..=MAX_HEADERS_PER_MSG).map(|_| one).collect();
    assert_eq!(
        r.cm.submit_headers(8, &over),
        Err(Reject::BatchTooLong {
            got: MAX_HEADERS_PER_MSG + 1,
            cap: MAX_HEADERS_PER_MSG
        })
    );
    assert!(r.cm.submit_headers(8, &over[..MAX_HEADERS_PER_MSG]).is_ok());
}

#[test]
fn every_arena_entry_is_pow_verified() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(30);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let side = honest.fork_at(20).spacing(30).extend(15);
    r.offer(4, &blocks_above(&side, 20));
    r.cm.advance().expect("reorged");
    let deeper = honest.fork_at(10).spacing(20).extend(30);
    r.offer(5, &blocks_above(&deeper, 10));
    let _ = r.cm.advance();

    let idx = r.cm.index();
    assert!(
        idx.len() > 60,
        "the fixture must actually populate the arena"
    );
    for i in idx.indices() {
        assert!(
            idx.node(i).pow_ok(),
            "arena entry {i} was never PoW-verified"
        );
    }
    assert_eq!(
        r.cm.pow_verified_floor(),
        0,
        "which is why the floor is genesis"
    );
}

#[test]
fn branch_base_matches_walk_after_reorg() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(30);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let branch = honest.fork_at(20).spacing(30).extend(15);
    r.offer(4, &blocks_above(&branch, 20));
    r.cm.advance().expect("reorged");

    let idx = r.cm.index();
    for i in idx.indices() {
        let n = idx.node(i);

        let mut cur = i;
        let expected = loop {
            let c = idx.node(cur);
            if c.prev == NO_PARENT {
                break c.height;
            }
            let par = idx.node(c.prev);
            if idx.is_canonical(c.prev) {
                break par.height;
            }
            cur = c.prev;
        };
        assert_eq!(
            n.branch_base_height, expected,
            "node {i} at height {} carries a stale fork point",
            n.height
        );
    }
}

#[test]
fn depth_one_tie_break_after_reorg() {
    let p = params();
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&honest, p);
    r.sync(&honest, 1);
    let branch = honest.fork_at(15).spacing(30).extend(10);
    r.offer(4, &blocks_above(&branch, 15));
    r.cm.advance().expect("reorged");
    assert_eq!(r.tip_hash(), branch.tip().hash);

    let rival = sibling_with_hash(&branch, addr_of(&user_key(0x93)), r.tip_hash(), true);
    let a =
        r.cm.submit_headers(7, &[rival.rec.raw])
            .expect("not halted");
    assert_eq!(
        a.connected, 1,
        "a depth-1 sibling of the new tip must still be reachable"
    );
    r.cm.submit_block(&rival.rec.hash, rival.body.clone())
        .expect("admissible");
    assert!(matches!(r.cm.advance(), Ok(Progress::Advanced { .. })));
    assert_eq!(r.tip_hash(), rival.rec.hash);
}

#[test]
fn resplit_forward_nonce_drops_consumed() {
    let floor = 1_000_000u128;
    let mut pool = Mempool::new(MempoolParams {
        relay_fee_floor: floor,
        ..Default::default()
    });
    let mut ob = |_: plaine_chain::error::Condition| {};
    let key = [0x77u8; 32];
    let sender = plaine_consensus::crypto::address_payload(&key);
    let to: Address = [0xAA; 20];

    let each = floor + 1_000;
    let budget = each * 5;
    for n in 0..5u64 {
        pool.submit(
            plaine_chain::mock::unsigned_transfer(key, to, 1_000, floor, n),
            Account {
                balance: budget,
                nonce: 0,
            },
            budget,
            0,
            SigProof::from_validated_block(),
            &mut ob,
        )
        .unwrap_or_else(|e| panic!("nonce {n}: {e:?}"));
    }
    assert_eq!(pool.sender_len(&sender), 5);

    let mut acct = |_: &Address| Account {
        balance: budget,
        nonce: 2,
    };
    pool.resplit_all(&mut acct);
    assert_eq!(pool.sender_len(&sender), 3, "the consumed nonces are gone");

    pool.submit(
        plaine_chain::mock::unsigned_transfer(key, to, 1_000, floor, 5),
        Account {
            balance: budget,
            nonce: 2,
        },
        budget,
        0,
        SigProof::from_validated_block(),
        &mut ob,
    )
    .expect("the dead entries stopped counting against pending_outlay");
    assert_eq!(pool.sender_len(&sender), 4);
}

#[test]
fn side_header_cap_does_not_stall() {
    let p = ChainParams {
        max_side_headers: 2,
        ..params()
    };
    let honest = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::with_mode(&honest, p, PowMode::AlwaysOk);
    r.sync(&honest, 1);

    let side = honest.fork_at(20).spacing(1).extend(5);
    r.offer(4, &blocks_above(&side, 20));

    assert!(
        r.cm.side_header_count() <= 2,
        "{} side headers held against a cap of 2",
        r.cm.side_header_count()
    );

    for tick in 0..10 {
        match r.cm.advance() {
            Ok(Progress::NoChange)
            | Ok(Progress::NeedBodies(_))
            | Ok(Progress::Advanced { .. }) => {}
            Err(e) => panic!("tick {tick} returned a hard error: {e:?}"),
        }
    }

    let hashes: Vec<[u8; 32]> = {
        let idx = r.cm.index();
        idx.indices().map(|i| idx.node(i).hash).collect()
    };
    for h in hashes {
        assert!(
            r.cm.header_raw(&h).is_some(),
            "an arena node whose 132 bytes we cannot produce"
        );
    }
    assert!(r.cm.halted().is_none(), "the node is not halted");
}

#[test]
fn known_hash_is_value_not_assertion() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(2);
    let mut idx = plaine_chain::index::HeaderIndex::new();
    let w1 = plaine_chain::types::Work::ONE;
    let w2 = w1.checked_add(&w1).expect("no overflow");

    idx.insert_genesis(&chain.blocks[0].rec, w1);
    let first = idx.insert(&chain.blocks[1].rec, 0, w2, true);
    assert_eq!(idx.len(), 2);
    let again = idx.insert(&chain.blocks[1].rec, 0, w2, true);
    assert_eq!(again, first, "a known hash returns its existing index");
    assert_eq!(idx.len(), 2, "inserts nothing");
    assert_eq!(idx.index_of(&chain.blocks[1].rec.hash), Some(first));
}
