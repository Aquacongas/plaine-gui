use plaine_p2p::addr::persist::{decode, encode, PeersError, PEERS_DIGEST_BYTES, PEERS_HEADER_BYTES};
use plaine_p2p::addr::{AddrMan, Table};
use plaine_p2p::constants::*;
use plaine_p2p::rng::Rng;

const NOW: u64 = 1_800_000_000;

fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[10] = 0xff;
    o[11] = 0xff;
    o[12] = a;
    o[13] = b;
    o[14] = c;
    o[15] = d;
    o
}

fn grp(a: u8, b: u8) -> [u8; 4] {
    [a, b, 0, 0]
}

fn flooded_by(source: [u8; 4], n: usize) -> AddrMan {
    let mut am = AddrMan::new();
    for i in 0..n {
        am.add_from_peer(
            v4(5, (i / 250) as u8, (i % 250) as u8, 9),
            9256,
            0,
            NOW,
            source,
            NOW,
            false,
        );
    }
    am
}

fn round_trip(am: &AddrMan, into: &mut AddrMan, allow_local: bool) {
    let bytes = encode(am.entries(), CHAIN_ID);
    let recs = decode(&bytes, CHAIN_ID).expect("our own file must decode");
    into.restore(&recs, NOW, allow_local, &mut Rng::new(0x5EED));
}

#[test]
fn learned_addr_survives_restart() {
    let mut live = AddrMan::new();
    live.add(v4(185, 199, 108, 1), 9256, true, NOW);
    for i in 1..=8u8 {
        live.add_from_peer(v4(45, i, 0, 7), 9256, 0, NOW, grp(198, 51), NOW, false);
    }
    assert_eq!(live.len(), 9);

    let mut restarted = AddrMan::new();
    restarted.add(v4(185, 199, 108, 1), 9256, true, NOW);
    round_trip(&live, &mut restarted, false);

    let gossiped = (1..=8u8)
        .filter(|i| restarted.get(&v4(45, *i, 0, 7), 9256).is_some())
        .count();
    assert_eq!(
        gossiped, 8,
        "a restart threw away every address the node had learned by talking"
    );

    assert_eq!(restarted.len(), 9);
    assert!(
        restarted
            .get(&v4(185, 199, 108, 1), 9256)
            .expect("the seed")
            .from_seed,
        "the config seed lost the status its config gave it"
    );
}

#[test]
fn tried_peer_dialled_first_after_restart() {
    let mut live = AddrMan::new();
    live.add_from_peer(v4(88, 51, 100, 9), 9256, 0, NOW, grp(198, 51), NOW, false);
    live.on_handshake_ok(&v4(88, 51, 100, 9), 9256, 1);
    for i in 0..40u8 {
        live.add_from_peer(v4(93, 184, 1, i), 9256, 0, NOW, grp(198, 51), NOW, false);
    }
    assert_eq!(live.count(Table::Tried), 1);

    let mut restarted = AddrMan::new();
    round_trip(&live, &mut restarted, false);
    assert_eq!(
        restarted.count(Table::Tried),
        1,
        "the one address we had actually handshaken came back as hearsay"
    );
    let first = restarted
        .select_dial(1, &[], Mono0, false)
        .first()
        .copied()
        .expect("something to dial");
    assert_eq!(
        first,
        (v4(88, 51, 100, 9), 9256),
        "the reload put an unverified address ahead of one we had handshaken"
    );
}

#[allow(non_upper_case_globals)]
const Mono0: plaine_p2p::traits::Mono = plaine_p2p::traits::Mono(0);

#[test]
fn restart_does_not_launder_quota() {
    let live = flooded_by(grp(203, 0), ADDR_PER_SOURCE_GROUP_MAX * 2);
    assert_eq!(
        live.count_new_from(grp(203, 0)),
        ADDR_PER_SOURCE_GROUP_MAX,
        "the live quota did not bind, so this test proves nothing about reload"
    );

    let mut restarted = AddrMan::new();
    round_trip(&live, &mut restarted, false);
    assert_eq!(
        restarted.count_new_from(grp(203, 0)),
        ADDR_PER_SOURCE_GROUP_MAX,
        "the reload gave one source /16 more than its quota"
    );

    let mut added = 0;
    for i in 0..500 {
        if restarted.add_from_peer(
            v4(77, (i / 250) as u8, (i % 250) as u8, 9),
            9256,
            0,
            NOW,
            grp(203, 0),
            NOW,
            false,
        ) == plaine_p2p::addr::addrman::Ingest::Added
        {
            added += 1;
        }
    }
    assert_eq!(
        added, 0,
        "a restart bought the flooder {added} fresh slots it had already spent"
    );
    assert_eq!(restarted.count_new_from(grp(203, 0)), ADDR_PER_SOURCE_GROUP_MAX);
}

#[test]
fn the_file_cannot_grant_seed_status() {
    let mut live = AddrMan::new();
    live.add(v4(185, 199, 108, 1), 9256, true, NOW);
    assert!(live.get(&v4(185, 199, 108, 1), 9256).expect("seed").from_seed);

    let mut restarted = AddrMan::new();
    round_trip(&live, &mut restarted, false);
    let e = restarted.get(&v4(185, 199, 108, 1), 9256).expect("restored");
    assert!(
        !e.from_seed,
        "the file granted seed privilege to an address the current config does not name"
    );

    assert_eq!(
        restarted.reap_expired(NOW + ADDR_MAX_AGE_SECS + 1),
        1,
        "the restored address was immortal"
    );
}

#[test]
fn file_cannot_make_undialable() {
    let mut live = AddrMan::new();
    live.add_from_peer(v4(88, 51, 100, 9), 9256, 0, NOW, grp(203, 0), NOW, false);
    live.mark_foreign(&v4(88, 51, 100, 9), 9256, Mono0);
    live.on_failure(&v4(88, 51, 100, 9), 9256, true);
    assert!(!live
        .get(&v4(88, 51, 100, 9), 9256)
        .expect("live")
        .dialable(Mono0));

    let mut restarted = AddrMan::new();
    round_trip(&live, &mut restarted, false);
    let e = restarted.get(&v4(88, 51, 100, 9), 9256).expect("restored");
    assert!(e.dialable(Mono0), "the file carried a refusal to dial");
    assert_eq!(e.failures, 0, "the file carried a strike count");
    assert_eq!(e.protocol_deaths, 0, "the file carried a strike count");
}

#[test]
fn private_book_rejected_by_public() {
    let mut live = AddrMan::new();
    for a in [v4(10, 44, 0, 1), v4(127, 0, 0, 1), v4(192, 168, 1, 1)] {
        live.add_from_peer(a, 9256, 0, NOW, grp(10, 44), NOW, true);
    }
    live.add_from_peer(v4(88, 51, 100, 9), 9256, 0, NOW, grp(10, 44), NOW, true);
    assert_eq!(live.len(), 4, "the private book did not build");

    let mut public = AddrMan::new();
    round_trip(&live, &mut public, false);
    assert_eq!(
        public.len(),
        1,
        "a public node loaded the private deployment's mesh addresses"
    );
    assert!(public.get(&v4(88, 51, 100, 9), 9256).is_some());

    let mut private = AddrMan::new();
    round_trip(&live, &mut private, true);
    assert_eq!(private.len(), 4);
}

#[test]
fn aged_record_not_reloaded() {
    let mut live = AddrMan::new();
    live.add_from_peer(v4(185, 199, 108, 1), 9256, 0, NOW, grp(203, 0), NOW, false);
    live.add_from_peer(v4(185, 199, 108, 2), 9256, 0, NOW, grp(203, 0), NOW, false);

    let mut later = AddrMan::new();
    let bytes = encode(live.entries(), CHAIN_ID);
    let recs = decode(&bytes, CHAIN_ID).expect("decode");
    later.restore(&recs, NOW + ADDR_MAX_AGE_SECS + 86_400, false, &mut Rng::new(1));
    assert_eq!(later.len(), 0, "a week-old book came back whole");

    let mut forged = recs.clone();
    forged[0].last_seen = NOW + 10 * ADDR_MAX_AGE_SECS;
    let mut clamped = AddrMan::new();
    clamped.restore(&forged, NOW, false, &mut Rng::new(2));
    assert_eq!(
        clamped.get(&v4(185, 199, 108, 1), 9256).expect("kept").last_seen,
        NOW,
        "a future-dated record kept its own timestamp"
    );
}

#[test]
fn reload_keeps_operator_addrs() {
    let mut restarted = AddrMan::new();
    restarted.add(v4(185, 199, 108, 1), 9256, true, NOW);
    let live = flooded_by(grp(203, 0), ADDR_PER_SOURCE_GROUP_MAX);
    round_trip(&live, &mut restarted, false);
    assert!(
        restarted.get(&v4(185, 199, 108, 1), 9256).is_some(),
        "the file displaced a config seed"
    );
    assert!(restarted.counters_consistent());
}

#[test]
fn full_book_refuses_file() {
    let mut live = AddrMan::new();
    for g in 0..16u8 {
        for i in 0..ADDR_PER_SOURCE_GROUP_MAX {
            live.add_from_peer(
                v4(g + 20, (i / 250) as u8, ((i / 25) % 10) as u8, (i % 25) as u8),
                9256,
                0,
                NOW,
                grp(g + 100, 0),
                NOW,
                false,
            );
        }
    }
    assert_eq!(live.count(Table::New), ADDR_NEW_MAX);

    let mut restarted = AddrMan::new();
    round_trip(&live, &mut restarted, false);
    assert!(
        restarted.count(Table::New) <= ADDR_NEW_MAX,
        "the reload overflowed `new` to {}",
        restarted.count(Table::New)
    );
    assert!(restarted.counters_consistent());
}

#[test]
fn file_order_not_dial_order() {
    let live = flooded_by(grp(203, 0), 64);
    let bytes = encode(live.entries(), CHAIN_ID);
    let recs = decode(&bytes, CHAIN_ID).expect("decode");
    let file_order: Vec<[u8; 16]> = recs.iter().map(|r| r.ip).collect();

    let order_with = |seed: u64| -> Vec<[u8; 16]> {
        let mut am = AddrMan::new();
        am.restore(&recs, NOW, false, &mut Rng::new(seed));
        am.entries().iter().map(|e| e.ip).collect()
    };
    let a = order_with(1);
    let b = order_with(2);
    assert_eq!(a.len(), 64);

    assert_ne!(a, file_order, "the reload preserved the attacker's own ordering");
    assert_ne!(a, b, "the reload is not drawing from the per-node stream at all");

    let mut sorted_a = a.clone();
    let mut sorted_f = file_order.clone();
    sorted_a.sort();
    sorted_f.sort();
    assert_eq!(sorted_a, sorted_f, "the shuffle changed the set, not just the order");
}

#[test]
fn corrupt_file_yields_nothing() {
    let live = flooded_by(grp(203, 0), 20);
    let good = encode(live.entries(), CHAIN_ID);
    assert_eq!(decode(&good, CHAIN_ID).expect("decode").len(), 20);

    let cut = good.len() - PEERS_DIGEST_BYTES - 35;
    assert!(matches!(
        decode(&good[..cut], CHAIN_ID),
        Err(PeersError::BadLength) | Err(PeersError::BadDigest) | Err(PeersError::TooShort)
    ));

    let mut tampered = good.clone();
    tampered[PEERS_HEADER_BYTES + 15] ^= 0xff;
    assert_eq!(decode(&tampered, CHAIN_ID), Err(PeersError::BadDigest));

    let other = encode(live.entries(), FOREIGN_CHAIN_ID);
    assert!(matches!(
        decode(&other, CHAIN_ID),
        Err(PeersError::ForeignChain(_))
    ));

    for bad in [&good[..cut], &tampered[..], &other[..]] {
        let mut am = AddrMan::new();
        am.add(v4(185, 199, 108, 1), 9256, true, NOW);
        if let Ok(recs) = decode(bad, CHAIN_ID) {
            am.restore(&recs, NOW, false, &mut Rng::new(3));
        }
        assert_eq!(am.len(), 1, "a bad file changed the book");
    }
}

#[test]
fn reload_refuses_port_zero() {
    let mut recs = {
        let mut live = AddrMan::new();
        live.add_from_peer(v4(185, 199, 108, 1), 9256, 0, NOW, grp(203, 0), NOW, false);
        decode(&encode(live.entries(), CHAIN_ID), CHAIN_ID).expect("decode")
    };
    recs[0].port = 0;
    let mut am = AddrMan::new();
    let st = am.restore(&recs, NOW, false, &mut Rng::new(4));
    assert_eq!(am.len(), 0);
    assert_eq!(st.filtered, 1);
}

fn recs_from(source: [u8; 4], n: usize, table: Table) -> Vec<plaine_p2p::addr::PeerRec> {
    (0..n)
        .map(|i| plaine_p2p::addr::PeerRec {
            ip: v4(45, (i / 250) as u8, (i % 250) as u8, 9),
            port: 9256 + (i / 62_500) as u16,
            services: 0,
            last_seen: NOW,
            table,
            source_group: source,
        })
        .collect()
}

#[test]
fn file_cut_to_source_quota() {
    let recs = recs_from(grp(203, 0), ADDR_PER_SOURCE_GROUP_MAX * 3, Table::New);
    let mut am = AddrMan::new();
    let st = am.restore(&recs, NOW, false, &mut Rng::new(7));
    assert_eq!(
        am.count_new_from(grp(203, 0)),
        ADDR_PER_SOURCE_GROUP_MAX,
        "one source /16 owns {} of `new` after a reload",
        am.count_new_from(grp(203, 0))
    );
    assert_eq!(st.loaded as usize, ADDR_PER_SOURCE_GROUP_MAX);
    assert_eq!(st.over_quota as usize, ADDR_PER_SOURCE_GROUP_MAX * 2);
    assert!(am.counters_consistent());
}

#[test]
fn file_cut_to_table() {
    let mut recs: Vec<plaine_p2p::addr::PeerRec> = Vec::new();
    for g in 0..24u8 {
        recs.extend(recs_from(grp(100 + g, 0), ADDR_PER_SOURCE_GROUP_MAX, Table::New));
    }

    for (i, r) in recs.iter_mut().enumerate() {
        r.ip = v4(45, (i / 60_000) as u8, ((i / 240) % 250) as u8, (i % 240) as u8);
        r.port = 9256 + (i / 15_000) as u16;
    }
    let mut am = AddrMan::new();
    am.restore(&recs, NOW, false, &mut Rng::new(8));
    assert_eq!(am.count(Table::New), ADDR_NEW_MAX, "`new` overflowed to {}", am.count(Table::New));

    let mut tried: Vec<plaine_p2p::addr::PeerRec> = Vec::new();
    for i in 0..(ADDR_TRIED_MAX * 2) {
        tried.push(plaine_p2p::addr::PeerRec {
            ip: v4(88, (i / 250) as u8, (i % 250) as u8, 3),
            port: 9256,
            services: 0,
            last_seen: NOW,
            table: Table::Tried,
            source_group: grp(88, 0),
        });
    }
    let mut am2 = AddrMan::new();
    am2.restore(&tried, NOW, false, &mut Rng::new(9));
    assert_eq!(
        am2.count(Table::Tried),
        ADDR_TRIED_MAX,
        "`tried` overflowed to {}",
        am2.count(Table::Tried)
    );
    assert!(am2.counters_consistent());
}

#[test]
fn trailing_bytes_refused() {
    let live = flooded_by(grp(203, 0), 6);
    let good = encode(live.entries(), CHAIN_ID);
    assert!(decode(&good, CHAIN_ID).is_ok());
    let mut long = good.clone();
    long.extend_from_slice(b"and then some");
    assert_eq!(decode(&long, CHAIN_ID), Err(PeersError::BadLength));

    let mut long2 = good;
    long2.extend_from_slice(&[0u8; 35]);
    assert_eq!(decode(&long2, CHAIN_ID), Err(PeersError::BadLength));
}
