use plaine_p2p::constants::*;
use plaine_p2p::gate::Budgets;
use plaine_p2p::mock::{Duplex, Rng};
use plaine_p2p::traits::Mono;
use plaine_p2p::wire::frame::encode_frame;
use plaine_p2p::wire::msg::*;
use plaine_p2p::wire::{Cmd, WireError};

fn hello(nonce: u64, height: u64) -> Msg {
    Msg::Hello(Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: [0x50, 0x4C, 0x4E, 0x45],
        services: SERVICE_FULL_RELAY,
        nonce,
        time: 1_800_000_000,
        height,
        tip_hash: [1u8; 32],
        cum_work: [2u8; 32],
        listen_port: PORT_P2P,
        user_agent: b"plaine/0.1".to_vec(),
    })
}

#[test]
fn nodes_handshake_over_wire() {
    let mut d = Duplex::new(MAGIC_MAIN);

    let at_b = d.a_to_b(&hello(1, 100)).expect("A->B hello");
    assert_eq!(at_b.len(), 1);
    let at_a = d.b_to_a(&hello(2, 200)).expect("B->A hello");
    assert_eq!(at_a.len(), 1);
    d.b_to_a(&Msg::HelloAck).expect("ack");
    d.a_to_b(&Msg::HelloAck).expect("ack");
    assert_eq!(d.b.count_in(Cmd::Hello), 1);
    assert_eq!(d.a.count_in(Cmd::HelloAck), 1);
}

#[test]
fn full_sync_over_wire() {
    let mut d = Duplex::new(MAGIC_MAIN);
    d.a_to_b(&hello(1, 0)).unwrap();
    d.b_to_a(&hello(2, 5_000)).unwrap();

    let locator: Vec<[u8; 32]> = (0..LOCATOR_MAX).map(|i| [i as u8; 32]).collect();
    d.a_to_b(&Msg::GetHeaders {
        locator,
        stop: [0u8; 32],
    })
    .unwrap();
    let hdrs = Msg::Headers(vec![[3u8; HEADER_BYTES]; MAX_HEADERS_PER_MSG]);
    let got = d.b_to_a(&hdrs).unwrap();
    assert_eq!(got, vec![hdrs]);

    let items: Vec<InvItem> = (0..64)
        .map(|i| InvItem {
            kind: InvKind::Block,
            hash: [i as u8; 32],
        })
        .collect();
    d.b_to_a(&Msg::Inv(items.clone())).unwrap();
    d.a_to_b(&Msg::GetData(items)).unwrap();
    let block = Msg::Block(vec![9u8; CAP_BLOCK]);
    assert_eq!(d.b_to_a(&block).unwrap(), vec![block]);

    assert_eq!(d.a.count_in(Cmd::Headers), 1);
    assert_eq!(d.a.count_in(Cmd::Block), 1);
}

#[test]
fn malformed_frame_kills_stream() {
    let mut d = Duplex::new(MAGIC_MAIN);
    let mut bad = encode_frame(&MAGIC_MAIN, Cmd::Ping, &8u64.to_le_bytes());
    bad[5] = 0x01;
    assert_eq!(d.raw_to_b(&bad).unwrap_err(), WireError::NonZeroFlags(0x01));

    let mut d2 = Duplex::new(MAGIC_MAIN);
    let wrong = encode_frame(&FOREIGN_MAGIC, Cmd::Ping, &8u64.to_le_bytes());
    assert_eq!(d2.raw_to_b(&wrong).unwrap_err(), WireError::BadMagic);
}

#[test]
fn partial_frame_buffered() {
    let mut d = Duplex::new(MAGIC_MAIN);
    let bytes = d.a.send(&Msg::Headers(vec![[1u8; HEADER_BYTES]; 500]));

    for i in 0..bytes.len() - 1 {
        assert!(d.b.recv(&bytes[i..i + 1]).unwrap().is_empty());
    }
    let out = d.b.recv(&bytes[bytes.len() - 1..]).unwrap();
    assert_eq!(out.len(), 1);
    match &out[0] {
        Msg::Headers(v) => assert_eq!(v.len(), 500),
        other => panic!("wrong message: {:?}", other),
    }
}

#[test]
fn random_bytes_no_panic() {
    for seed in 0..256u64 {
        let mut rng = Rng::new(seed | 1);
        let mut d = Duplex::new(MAGIC_MAIN);
        let mut junk = vec![0u8; 1 + rng.below(200) as usize];
        rng.fill(&mut junk);
        if seed % 3 == 0 && junk.len() >= 4 {
            junk[..4].copy_from_slice(&MAGIC_MAIN);
        }
        let _ = d.raw_to_b(&junk);
    }
}

#[test]
fn gate_cpu_bounded_under_flood() {
    let mut b = Budgets::new(Mono(0));
    let chunk = 64 * 1024u64;
    let mut admitted_flood = 0u64;
    let mut admitted_sync = 0u64;
    let now = Mono(1_000);

    loop {
        if !b.admit_read(chunk, now) || !b.admit_ingest(chunk, false, now) {
            break;
        }
        admitted_flood += chunk;
        if admitted_flood > 64 * 1024 * 1024 {
            panic!("ingest budget never bound");
        }
    }

    while b.admit_ingest(chunk, true, now) {
        admitted_sync += chunk;
        if admitted_sync > SYNC_PEER_RESERVE_BYTES_PER_SEC {
            break;
        }
    }

    assert!(
        admitted_flood <= INGEST_GLOBAL_BYTES_PER_SEC,
        "the flood was admitted {} bytes in one second, above INGEST_GLOBAL",
        admitted_flood
    );
    assert_eq!(
        admitted_sync, SYNC_PEER_RESERVE_BYTES_PER_SEC,
        "the sync peer's reserve did not survive a full header flood"
    );

    let hdrs = INGEST_GLOBAL_BYTES_PER_SEC / HEADER_BYTES as u64;
    let millicores = hdrs * GATE_NS_PER_HEADER / 1_000_000;
    assert!(millicores < 500, "gate work is {} millicores", millicores);
}

#[test]
fn read_global_bounds_framing() {
    let mut b = Budgets::new(Mono(0));
    let chunk = 64 * 1024u64;
    let mut admitted = 0u64;
    let now = Mono(1_000);
    while b.admit_read(chunk, now) {
        admitted += chunk;
        if admitted > 256 * 1024 * 1024 {
            panic!("READ_GLOBAL never bound");
        }
    }
    assert!(admitted <= READ_GLOBAL_BYTES_PER_SEC);

    let millicores = admitted / READ_PEER_BYTES_PER_SEC * 20;
    assert!(
        millicores <= 340,
        "framing work is {} millicores, above the stated 320",
        millicores
    );

    let honest_peak = 9 * READ_PEER_BYTES_PER_SEC;
    assert!(honest_peak < READ_GLOBAL_BYTES_PER_SEC);
}

#[test]
fn token_bucket_no_partial_spend() {
    use plaine_p2p::gate::TokenBucket;
    let mut t = TokenBucket::new(1_000, 1_000, Mono(0));
    assert!(!t.take(1_001, Mono(0)));
    assert_eq!(t.level(Mono(0)), 1_000, "a refused take spent tokens anyway");
    assert!(t.take(1_000, Mono(0)));
    assert_eq!(t.level(Mono(0)), 0);

    assert_eq!(t.level(Mono(500)), 500);
    assert_eq!(t.level(Mono(5_000)), 1_000, "refill exceeded capacity");
}
