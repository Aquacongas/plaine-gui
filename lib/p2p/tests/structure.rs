use plaine_p2p::constants::*;

const SYNC_SOURCES: &[(&str, &str)] = &[
    ("sync/mod.rs", include_str!("../src/sync/mod.rs")),
    (
        "sync/header_track.rs",
        include_str!("../src/sync/header_track.rs"),
    ),
    (
        "sync/body_track.rs",
        include_str!("../src/sync/body_track.rs"),
    ),
    ("sync/staging.rs", include_str!("../src/sync/staging.rs")),
    ("sync/stall.rs", include_str!("../src/sync/stall.rs")),
    ("sync/rotation.rs", include_str!("../src/sync/rotation.rs")),
    ("sync/recovery.rs", include_str!("../src/sync/recovery.rs")),
    ("sync/tree.rs", include_str!("../src/sync/tree.rs")),
    ("sync/tx_relay.rs", include_str!("../src/sync/tx_relay.rs")),
    ("gate/g0_dedup.rs", include_str!("../src/gate/g0_dedup.rs")),
    (
        "gate/g1_structure.rs",
        include_str!("../src/gate/g1_structure.rs"),
    ),
    (
        "gate/g2_context.rs",
        include_str!("../src/gate/g2_context.rs"),
    ),
    (
        "gate/g3_admission.rs",
        include_str!("../src/gate/g3_admission.rs"),
    ),
    (
        "gate/g4_budget.rs",
        include_str!("../src/gate/g4_budget.rs"),
    ),
    ("peer/score.rs", include_str!("../src/peer/score.rs")),
    ("peer/session.rs", include_str!("../src/peer/session.rs")),
    ("peer/inbox.rs", include_str!("../src/peer/inbox.rs")),
];

fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_lock_is_held_across_network_io() {
    const FORBIDDEN: &[&str] = &[
        "Mutex", "RwLock", "RefCell", "Cell<", ".await", "async fn", "lock()", "spawn", "join",
        "thread::",
    ];
    for (name, src) in SYNC_SOURCES {
        let code = code_only(src);
        for pat in FORBIDDEN {
            assert!(
                !code.contains(pat),
                "{} contains `{}` - the sync engine stays a synchronous, \
                 lock-free, single-owner state machine; this puts a lock or a \
                 thread across network I/O",
                name,
                pat
            );
        }
    }
}

#[test]
fn no_barrier_over_peers() {
    const BARRIERS: &[&str] = &[
        "join_all",
        "JoinSet",
        "WaitGroup",
        "Barrier",
        "wait()",
        "block_on",
    ];
    for (name, src) in SYNC_SOURCES {
        let code = code_only(src);
        for pat in BARRIERS {
            assert!(!code.contains(pat), "{} contains a barrier `{}`", name, pat);
        }
    }
}

#[test]
fn the_crate_forbids_unsafe_code() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.contains("#![forbid(unsafe_code)]"),
        "crate-level forbid(unsafe_code) was removed"
    );
}

#[test]
fn tokio_is_the_only_added_dependency() {
    let manifest = include_str!("../Cargo.toml");
    let deps: Vec<&str> = manifest
        .lines()
        .filter(|l| l.contains('=') && !l.trim_start().starts_with('#'))
        .filter(|l| {
            let name = l.split('=').next().unwrap_or("").trim();
            !name.is_empty()
                && !name.starts_with('[')
                && !name.contains('.')
                && name != "name"
                && name != "description"
                && name != "features"
                && name != "version"
                && name != "default-features"
        })
        .collect();
    for line in &deps {
        let name = line.split('=').next().unwrap_or("").trim();
        assert!(
            matches!(name, "plaine-consensus" | "tokio"),
            "unexpected dependency `{}` - the policy allows tokio and \
             plaine-consensus only, dev-dependencies included",
            name
        );
    }

    let code: String = manifest
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "serde",
        "bytes ",
        "anyhow",
        "tracing",
        "proptest",
        "rand ",
        "arbitrary",
        "parking_lot",
        "futures",
        "blake3",
        "hex",
        "redb",
        "ed25519",
    ] {
        assert!(
            !code.contains(banned),
            "banned dependency `{}` appeared in Cargo.toml",
            banned
        );
    }
}

#[test]
fn chain_id_is_the_frozen_value() {
    assert_eq!(
        plaine_consensus::constants::CHAIN_ID,
        [0x50, 0x4C, 0x4E, 0x45],
        "CHAIN_ID must be 0x504C4E45 ('PLNE') before genesis"
    );
}

#[test]
fn chain_id_placeholder_unchanged() {
    let id = plaine_consensus::constants::CHAIN_ID;
    assert!(
        id == [0, 0, 0, 0] || id == [0x50, 0x4C, 0x4E, 0x45],
        "CHAIN_ID is {:02X?}, which is neither the known placeholder nor the \
         frozen 0x504C4E45",
        id
    );
}

#[test]
fn p2p_constants_match_the_frozen_numbers() {
    use plaine_consensus::constants as spec;
    assert_eq!(spec::MAX_HEADERS_PER_MSG, 2_000);
    assert_eq!(spec::MAX_P2P_MSG_BYTES, 8 * 1024 * 1024);

    assert_eq!(spec::MAX_REORG_DEPTH, 30);
    assert_eq!(
        spec::COINBASE_MATURITY,
        2 * spec::MAX_REORG_DEPTH,
        "SPEC: maturity is twice the rollback limit - shipping them equal leaves no margin"
    );
    assert_eq!(spec::MAX_PEERS, 128);
    assert_eq!(spec::CHECKPOINT_SUNSET_HEIGHT, 525_960);
    assert_eq!(spec::HEADER_BYTES, 132);
    assert_eq!(spec::PORT_P2P, 9256);
    assert_eq!(spec::MAGIC_MAIN, [0xB7, 0x4E, 0xD3, 0x21]);
    assert_eq!(spec::BLOCK_TIME_SECS, 60);
    assert_eq!(spec::BLOCKS_PER_YEAR, 525_960);
    assert_eq!(spec::SYNC_WINDOW_SECS, 720);
    assert_eq!(spec::MAX_FUTURE_DRIFT_SECS, 600);

    assert_eq!(MAX_HEADERS_PER_MSG, spec::MAX_HEADERS_PER_MSG);
    assert_eq!(MAX_P2P_MSG_BYTES, spec::MAX_P2P_MSG_BYTES);
    assert_eq!(MAX_REORG_DEPTH, spec::MAX_REORG_DEPTH);
    assert_eq!(HEADER_BYTES, spec::HEADER_BYTES);
    assert_eq!(PORT_P2P, spec::PORT_P2P);
}

#[test]
fn gate_cpu_ceiling_recomputes() {
    let uncapped_hdr_per_sec = MAX_PEERS as u64 * READ_PEER_BYTES_PER_SEC / HEADER_BYTES as u64;
    let uncapped_cores = uncapped_hdr_per_sec * GATE_NS_PER_HEADER / 1_000_000_000;
    assert!(
        (4..=5).contains(&uncapped_cores),
        "uncapped gate work recomputed to {} cores, not the stated ~4.47",
        uncapped_cores
    );

    let capped_hdr_per_sec = INGEST_GLOBAL_BYTES_PER_SEC / HEADER_BYTES as u64;
    let capped_millicores = capped_hdr_per_sec * GATE_NS_PER_HEADER / 1_000_000;
    assert!(
        (250..=310).contains(&capped_millicores),
        "capped gate work recomputed to {} millicores, not the stated 280",
        capped_millicores
    );
}

#[test]
fn header_verify_recomputes_vs_arch() {
    let above_anchor = 5_200_000u64 - 525_960;
    assert_eq!(above_anchor, 4_674_040);

    let haircut = 100 - VERIFY_BANDWIDTH_HAIRCUT_PCT;
    let min_minutes =
        above_anchor * HEADER_VERIFY_US_MIN / VERIFY_WORKERS_REFERENCE * 100 / haircut / 60_000_000;
    let max_minutes =
        above_anchor * HEADER_VERIFY_US_MAX / VERIFY_WORKERS_REFERENCE * 100 / haircut / 60_000_000;
    assert!(
        (58..=62).contains(&min_minutes),
        "low end recomputed to {} min, not the stated ~60",
        min_minutes
    );
    assert!(
        (135..=140).contains(&max_minutes),
        "high end recomputed to {} min, not the stated ~138",
        max_minutes
    );

    let hdr_per_sec = VERIFY_WORKERS_REFERENCE * 1_000_000 / 2_000 * haircut / 100;
    assert_eq!(hdr_per_sec, 850);
}

#[test]
fn one_sync_peer_is_scheduling_choice() {
    let verify_bytes_per_sec = 850u64 * HEADER_BYTES as u64;
    let pct_of_one_peer = verify_bytes_per_sec * 100 / READ_PEER_BYTES_PER_SEC;
    assert!(
        pct_of_one_peer <= 6,
        "header verification consumes {}% of one peer's read cap, so the \
         single-designee argument no longer holds",
        pct_of_one_peer
    );
}

#[test]
fn ibd_rate_floor_bounds_sync() {
    let worst_hours = 5_200_000u64 * 10 / SYNC_MIN_RATE_IBD_PER_10S / 3_600;
    assert!(
        worst_hours <= 8,
        "worst-case peer-bound IBD is {} h, which is not a bound worth having",
        worst_hours
    );

    let floor_per_sec = SYNC_MIN_RATE_IBD_PER_10S / 10;
    assert!(
        floor_per_sec * 4 < 850,
        "the floor is too close to our own rate"
    );

    assert_eq!(SYNC_MIN_RATE_TRACKING_PER_10S, 0);
}

#[test]
fn fast_forward_sampling_is_cheap() {
    let sub_anchor = CHECKPOINT_SUNSET_HEIGHT;
    let calls = sub_anchor / FF_SAMPLE_RATE;
    let seconds = calls * 2 / 1_000;
    assert!(
        seconds < 10,
        "sampling costs {} s, which is not negligible",
        seconds
    );
    let naive_bytes = sub_anchor * HEADER_BYTES as u64;
    let sampled_bytes = FF_SAMPLE_RATE * HEADER_BYTES as u64;
    assert!(
        naive_bytes / sampled_bytes > 3_000,
        "sampling improves detection by only {}x",
        naive_bytes / sampled_bytes
    );
}

#[test]
fn presync_lead_buffers_rotation() {
    assert_eq!(PRESYNC_LEAD_BYTES, 8_650_752);
    let buffer_secs = PRESYNC_LEAD_HEADERS / 850;
    assert!(
        buffer_secs > LOCATE_TIMEOUT_MS / 1_000 + 30,
        "staging buffers only {} s of verification, less than a rotation",
        buffer_secs
    );
}

const NET_SOURCES: &[(&str, &str)] = &[
    ("net/mod.rs", include_str!("../src/net/mod.rs")),
    ("net/conn.rs", include_str!("../src/net/conn.rs")),
    ("net/limits.rs", include_str!("../src/net/limits.rs")),
    ("net/node.rs", include_str!("../src/net/node.rs")),
    ("net/sock.rs", include_str!("../src/net/sock.rs")),
];

const NON_ASYNC_SOURCES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("config.rs", include_str!("../src/config.rs")),
    ("constants.rs", include_str!("../src/constants.rs")),
    ("metrics.rs", include_str!("../src/metrics.rs")),
    ("rng.rs", include_str!("../src/rng.rs")),
    ("tip.rs", include_str!("../src/tip.rs")),
    ("traits.rs", include_str!("../src/traits.rs")),
    ("engine/mod.rs", include_str!("../src/engine/mod.rs")),
    ("engine/fd.rs", include_str!("../src/engine/fd.rs")),
    ("engine/host.rs", include_str!("../src/engine/host.rs")),
    ("engine/serve.rs", include_str!("../src/engine/serve.rs")),
    ("addr/mod.rs", include_str!("../src/addr/mod.rs")),
    ("addr/addrman.rs", include_str!("../src/addr/addrman.rs")),
    ("addr/routable.rs", include_str!("../src/addr/routable.rs")),
    ("gate/mod.rs", include_str!("../src/gate/mod.rs")),
    ("mock/mod.rs", include_str!("../src/mock/mod.rs")),
    ("mock/chain.rs", include_str!("../src/mock/chain.rs")),
    ("mock/clock.rs", include_str!("../src/mock/clock.rs")),
    ("mock/scenario.rs", include_str!("../src/mock/scenario.rs")),
    (
        "mock/transport.rs",
        include_str!("../src/mock/transport.rs"),
    ),
    ("peer/mod.rs", include_str!("../src/peer/mod.rs")),
    ("peer/ban.rs", include_str!("../src/peer/ban.rs")),
    (
        "peer/handshake.rs",
        include_str!("../src/peer/handshake.rs"),
    ),
    ("wire/mod.rs", include_str!("../src/wire/mod.rs")),
    ("wire/cmd.rs", include_str!("../src/wire/cmd.rs")),
    ("wire/codec.rs", include_str!("../src/wire/codec.rs")),
    ("wire/frame.rs", include_str!("../src/wire/frame.rs")),
    ("wire/msg.rs", include_str!("../src/wire/msg.rs")),
];

#[test]
fn socket_driver_only_async() {
    for (name, src) in NON_ASYNC_SOURCES.iter().chain(SYNC_SOURCES.iter()) {
        let code = code_only(src);
        for pat in [".await", "async fn"] {
            assert!(
                !code.contains(pat),
                "{} contains `{}`; only src/net/ may be async (PoW checks block the reactor)",
                name,
                pat
            );
        }
    }
}

#[test]
fn consensus_seams_off_reactor() {
    for (name, src) in NET_SOURCES {
        let code = code_only(src);
        for pat in [
            "ChainView",
            "PowVerifier",
            "BlockSink",
            "plaine_consensus::",
        ] {
            assert!(
                !code.contains(pat),
                "{} names `{}`. The seams belong to src/engine/; a reactor task \
                 that can reach one is a reactor task that can spend 3 ms in it.",
                name,
                pat
            );
        }
    }
}

#[test]
fn descriptors_opened_in_one_file() {
    let everything: Vec<(&str, &str)> = NET_SOURCES
        .iter()
        .chain(NON_ASYNC_SOURCES.iter())
        .chain(SYNC_SOURCES.iter())
        .filter(|(n, _)| *n != "net/sock.rs")
        .copied()
        .collect();
    for (name, src) in &everything {
        let code = code_only(src);
        for pat in ["TcpListener::bind", ".accept()", "TcpStream::connect"] {
            assert!(
                !code.contains(pat),
                "{} opens a socket with `{}`. Every descriptor must come from \
                 src/net/sock.rs holding an FdLease, or the 4.5 budget is \
                 arithmetic again instead of a bound.",
                name,
                pat
            );
        }
    }
}

#[test]
fn net_inline_work_is_under_100us() {
    use plaine_p2p::wire::codec::encode;
    use plaine_p2p::wire::frame::{encode_frame, parse_frame_header, ReadArena};
    use plaine_p2p::wire::msg::{AddrRec, InvItem, InvKind, Msg};
    use plaine_p2p::wire::Cmd;
    use std::time::Instant;

    const REPS: u32 = 2_000;

    let hdr = {
        let f = encode_frame(&MAGIC_MAIN, Cmd::Ping, &7u64.to_le_bytes());
        let mut h = [0u8; FRAME_HEADER_BYTES];
        h.copy_from_slice(&f[..FRAME_HEADER_BYTES]);
        h
    };
    let t = Instant::now();
    for _ in 0..REPS {
        assert!(parse_frame_header(&hdr, &MAGIC_MAIN).is_ok());
    }
    let parse_ns = t.elapsed().as_nanos() as u64 / REPS as u64;

    let mut arena = ReadArena::new();
    let t = Instant::now();
    for _ in 0..REPS {
        let b = arena.take(ARENA_MAX);
        arena.give(b);
    }
    let arena_ns = t.elapsed().as_nanos() as u64 / REPS as u64;

    let t = Instant::now();
    for i in 0..REPS {
        let m = Msg::Pong(i as u64);
        let f = encode_frame(&MAGIC_MAIN, m.cmd(), &encode(&m));
        assert_eq!(f.len(), FRAME_HEADER_BYTES + CAP_PONG);
    }
    let pong_ns = t.elapsed().as_nanos() as u64 / REPS as u64;

    let recs: Vec<AddrRec> = (0..ADDR_MSG_MAX)
        .map(|i| AddrRec {
            time: i as u64,
            services: SERVICE_FULL_RELAY,
            ip: [i as u8; 16],
            port: PORT_P2P,
        })
        .collect();
    let m = Msg::Addr(recs);
    let t = Instant::now();
    for _ in 0..REPS {
        let f = encode_frame(&MAGIC_MAIN, m.cmd(), &encode(&m));
        assert_eq!(f.len(), FRAME_HEADER_BYTES + CAP_ADDR);
    }
    let addr_ns = t.elapsed().as_nanos() as u64 / REPS as u64;

    let items: Vec<InvItem> = (0..INV_MAX)
        .map(|i| InvItem {
            kind: if i % 2 == 0 {
                InvKind::Block
            } else {
                InvKind::Tx
            },
            hash: [i as u8; 32],
        })
        .collect();
    let t = Instant::now();
    let mut sunk = 0usize;
    for _ in 0..REPS {
        let blocks: Vec<[u8; 32]> = items
            .iter()
            .filter(|i| i.kind == InvKind::Block)
            .take(INV_BLOCKS_PER_MSG_MAX)
            .map(|i| i.hash)
            .collect();
        sunk += blocks.len();
    }
    let inv_filter_ns = t.elapsed().as_nanos() as u64 / REPS as u64;
    assert_eq!(sunk, REPS as usize * INV_BLOCKS_PER_MSG_MAX);

    const DEBUG_SLOWDOWN: u64 = 20;
    let allow = if cfg!(debug_assertions) {
        NET_INLINE_BUDGET_NS * DEBUG_SLOWDOWN
    } else {
        NET_INLINE_BUDGET_NS
    };
    for (what, ns) in [
        ("parse_frame_header", parse_ns),
        ("ReadArena take/give", arena_ns),
        ("build a PONG", pong_ns),
        ("encode a full ADDR", addr_ns),
        ("filter a full INV", inv_filter_ns),
    ] {
        eprintln!("inline {what:>22}: {ns:>8} ns (allowed {allow})");
        assert!(
            ns < allow,
            "{} costs {} ns inline, above the {} ns a reactor thread may spend. \
             Route it to the serve pool or to the engine.",
            what,
            ns,
            allow
        );
    }

    assert!(
        parse_ns + arena_ns + pong_ns + addr_ns + inv_filter_ns < HEADER_VERIFY_US_MIN * 1_000,
        "the entire inline table costs more than one interpreter call; there is \
         nothing left of the boundary"
    );

    #[allow(clippy::assertions_on_constants)]
    {
        assert!(CAP_HEADERS > 200_000 && CAP_BLOCK >= 1024 * 1024);
    }
    let inv_lookup_ns = INV_MAX as u64 * 50;
    assert!(
        inv_lookup_ns > NET_INLINE_BUDGET_NS,
        "a full INV recomputes to {} ns, which would make it legal inline - \
         re-derive the routing decision rather than keeping the comment",
        inv_lookup_ns
    );
}

#[test]
fn fd_budget_includes_handshake() {
    assert_eq!(
        FD_INBOUND_HANDSHAKE,
        ACCEPT_BURST as u64 + ACCEPT_RATE_PER_SEC as u64 * HANDSHAKE_TIMEOUT_MS / 1_000
    );
    assert_eq!(FD_INBOUND_HANDSHAKE, 112);
    assert_eq!(
        FD_TOTAL,
        FD_PEERS
            + FD_INBOUND_HANDSHAKE
            + FD_TRANSIENT_DIALS
            + FD_LISTENERS
            + FD_RPC
            + FD_STORAGE
            + FD_SERVICE
    );
    assert_eq!(FD_TOTAL, 690);

    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            FD_TOTAL < FD_CEILING,
            "{} descriptors against a ceiling of {}",
            FD_TOTAL,
            FD_CEILING
        );

        assert!(FD_TRANSIENT_DIALS >= COLDSTART_DIAL_CONCURRENT as u64);
    }
}

const CONN_SRC: &str = include_str!("../src/net/conn.rs");

#[test]
fn body_identity_from_bytes() {
    let code = code_only(CONN_SRC);
    let arm = code
        .split("Msg::Block(bytes) =>")
        .nth(1)
        .and_then(|s| s.split("Msg::").next())
        .expect("conn.rs handles Msg::Block");
    assert!(
        arm.contains("block_ident(&bytes)"),
        "the `Msg::Block` arm no longer derives the body's identity from its own bytes"
    );
    assert!(
        arm.contains("hash,") && arm.contains("height,"),
        "the `Msg::Block` arm no longer forwards the computed hash and height"
    );
}
