use plaine_p2p::constants::*;
use plaine_p2p::mock::Rng;
use plaine_p2p::wire::codec::{decode, encode};
use plaine_p2p::wire::frame::{encode_frame, parse_frame_header, FrameReader, ReadArena};
use plaine_p2p::wire::msg::*;
use plaine_p2p::wire::{Cmd, WireError};

fn h32(n: u8) -> [u8; 32] {
    [n; 32]
}

fn sample(cmd: Cmd) -> Msg {
    match cmd {
        Cmd::Hello => Msg::Hello(Hello {
            proto_ver: PROTO_VER,
            min_proto: MIN_PROTO,
            chain_id: [0x50, 0x4C, 0x4E, 0x45],
            services: SERVICE_FULL_RELAY | SERVICE_ARCHIVE,
            nonce: 0x0123_4567_89AB_CDEF,
            time: 1_700_000_000,
            height: 5_200_000,
            tip_hash: h32(0xAA),
            cum_work: h32(0xBB),
            listen_port: PORT_P2P,
            user_agent: vec![b'x'; UA_MAX],
        }),
        Cmd::HelloAck => Msg::HelloAck,
        Cmd::Ping => Msg::Ping(42),
        Cmd::Pong => Msg::Pong(42),
        Cmd::GetAddr => Msg::GetAddr,
        Cmd::Addr => Msg::Addr(
            (0..ADDR_MSG_MAX)
                .map(|i| AddrRec {
                    time: 1_700_000_000 + i as u64,
                    services: SERVICE_FULL_RELAY,
                    ip: [i as u8; 16],
                    port: 9256,
                })
                .collect(),
        ),
        Cmd::Inv | Cmd::GetData | Cmd::NotFound => {
            let items: Vec<InvItem> = (0..INV_MAX)
                .map(|i| InvItem {
                    kind: if i % 2 == 0 {
                        InvKind::Tx
                    } else {
                        InvKind::Block
                    },
                    hash: h32(i as u8),
                })
                .collect();
            match cmd {
                Cmd::Inv => Msg::Inv(items),
                Cmd::GetData => Msg::GetData(items),
                _ => Msg::NotFound(items),
            }
        }
        Cmd::GetHeaders => Msg::GetHeaders {
            locator: (0..LOCATOR_MAX).map(|i| h32(i as u8)).collect(),
            stop: h32(0xFF),
        },
        Cmd::Headers => Msg::Headers(vec![[7u8; HEADER_BYTES]; MAX_HEADERS_PER_MSG]),
        Cmd::Block => Msg::Block(vec![3u8; HEADER_BYTES + 4]),
        Cmd::Tx => Msg::Tx(vec![9u8; 157]),
        Cmd::Mempool => Msg::Mempool,
        Cmd::FeeFilter => Msg::FeeFilter(u128::MAX),
        Cmd::Checkpoint => Msg::Checkpoint(CheckpointMsg {
            height: 400_000,
            hash: h32(0xCC),
            sigs: (0..CHECKPOINT_SIGS_MAX)
                .map(|i| (i as u8, [i as u8; 64]))
                .collect(),
        }),
        Cmd::GetCheckpoint => Msg::GetCheckpoint,
    }
}

#[test]
fn max_size_round_trips() {
    for cmd in Cmd::ALL {
        let m = sample(cmd);
        let payload = encode(&m);
        assert!(
            payload.len() <= cmd.payload_cap(),
            "{} encoded {} bytes over its {} cap",
            cmd.name(),
            payload.len(),
            cmd.payload_cap()
        );
        let back = decode(cmd, &payload).unwrap_or_else(|e| panic!("{}: {:?}", cmd.name(), e));
        assert_eq!(back, m, "{} did not round-trip", cmd.name());

        assert_eq!(encode(&back), payload, "{} is not canonical", cmd.name());
    }
}

#[test]
fn frame_round_trips() {
    let mut r = FrameReader::new(MAGIC_MAIN);
    let mut wire = Vec::new();
    for cmd in Cmd::ALL {
        wire.extend_from_slice(&encode_frame(&MAGIC_MAIN, cmd, &encode(&sample(cmd))));
    }

    let mut got = Vec::new();
    for chunk in wire.chunks(7) {
        got.extend(r.push(chunk).expect("framing"));
    }
    assert_eq!(got.len(), Cmd::ALL.len());
    for ((cmd, payload), expect) in got.iter().zip(Cmd::ALL) {
        assert_eq!(*cmd, expect);
        assert_eq!(decode(*cmd, payload).unwrap(), sample(expect));
    }
    assert_eq!(r.buffered(), 0);
}

#[test]
fn bad_magic_rejected_not_scored() {
    let mut hdr = [0u8; FRAME_HEADER_BYTES];
    hdr[..4].copy_from_slice(&FOREIGN_MAGIC);
    hdr[4] = Cmd::Ping.code();
    let e = parse_frame_header(&hdr, &MAGIC_MAIN).unwrap_err();
    assert_eq!(e, WireError::BadMagic);

    assert!(e.is_silent_drop());
}

#[test]
fn unknown_command_scored() {
    let mut hdr = [0u8; FRAME_HEADER_BYTES];
    hdr[..4].copy_from_slice(&MAGIC_MAIN);
    hdr[4] = 0x19;
    assert_eq!(
        parse_frame_header(&hdr, &MAGIC_MAIN).unwrap_err(),
        WireError::UnknownCommand(0x19)
    );
    hdr[4] = 0x7F;
    let e = parse_frame_header(&hdr, &MAGIC_MAIN).unwrap_err();
    assert_eq!(e.points(), 20);
    assert!(Cmd::from_code(0x19).is_none(), "0x19 must stay reserved");
}

#[test]
fn non_zero_mbz_flags_are_rejected() {
    for bit in 0..8u32 {
        let mut hdr = [0u8; FRAME_HEADER_BYTES];
        hdr[..4].copy_from_slice(&MAGIC_MAIN);
        hdr[4] = Cmd::Ping.code();
        hdr[5] = 1u8 << bit;
        assert_eq!(
            parse_frame_header(&hdr, &MAGIC_MAIN).unwrap_err(),
            WireError::NonZeroFlags(1u8 << bit)
        );
    }
}

#[test]
fn oversize_length_allocates_nothing() {
    let mut hdr = [0u8; FRAME_HEADER_BYTES];
    hdr[..4].copy_from_slice(&MAGIC_MAIN);
    hdr[4] = Cmd::Ping.code();
    hdr[6..10].copy_from_slice(&(MAX_P2P_MSG_BYTES as u32).to_le_bytes());
    let e = parse_frame_header(&hdr, &MAGIC_MAIN).unwrap_err();
    assert!(matches!(e, WireError::Oversize { cmd: Cmd::Ping, .. }));
    assert_eq!(e.points(), 100);

    hdr[4] = Cmd::Block.code();
    hdr[6..10].copy_from_slice(&(MAX_P2P_MSG_BYTES as u32 + 1).to_le_bytes());
    assert!(matches!(
        parse_frame_header(&hdr, &MAGIC_MAIN).unwrap_err(),
        WireError::OversizeAbsolute(_)
    ));

    let mut r = FrameReader::new(MAGIC_MAIN);
    assert!(r.push(&hdr).is_err());
    assert!(r.buffered() <= FRAME_HEADER_BYTES);
}

#[test]
fn truncated_payloads_rejected() {
    for cmd in Cmd::ALL {
        if matches!(cmd, Cmd::Tx | Cmd::Block) {
            continue;
        }
        let full = encode(&sample(cmd));
        if full.is_empty() {
            continue;
        }
        for cut in [0usize, full.len() / 2, full.len() - 1] {
            let r = decode(cmd, &full[..cut]);
            assert!(
                r.is_err(),
                "{} accepted a {}-byte truncation of {} bytes",
                cmd.name(),
                cut,
                full.len()
            );
        }
    }
}

#[test]
fn undersized_block_rejected() {
    for n in [0usize, 1, HEADER_BYTES, HEADER_BYTES + 3] {
        assert!(
            decode(Cmd::Block, &vec![0u8; n]).is_err(),
            "BLOCK accepted {} bytes",
            n
        );
    }
    assert!(decode(Cmd::Block, &[0u8; HEADER_BYTES + 4]).is_ok());
    assert!(decode(Cmd::Tx, &[]).is_err(), "empty TX must be rejected");
}

#[test]
fn trailing_bytes_are_rejected() {
    for cmd in Cmd::ALL {
        if matches!(cmd, Cmd::Block | Cmd::Tx) {
            continue;
        }
        let mut full = encode(&sample(cmd));
        if full.len() + 1 > cmd.payload_cap() {
            continue;
        }
        full.push(0);
        assert!(
            decode(cmd, &full).is_err(),
            "{} accepted trailing bytes",
            cmd.name()
        );
    }
}

#[test]
fn absurd_count_no_alloc() {
    for cmd in [
        Cmd::Inv,
        Cmd::GetData,
        Cmd::NotFound,
        Cmd::Headers,
        Cmd::Addr,
        Cmd::GetHeaders,
    ] {
        let payload = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
        let e = decode(cmd, &payload).unwrap_err();
        assert!(
            matches!(e, WireError::TooManyItems { .. }),
            "{} gave {:?}",
            cmd.name(),
            e
        );
    }
}

#[test]
fn arena_bounded() {
    let mut a = ReadArena::new();
    let big = a.take(CAP_BLOCK);
    assert_eq!(big.len(), CAP_BLOCK);
    a.give(big);
    assert!(
        a.retained() <= ARENA_MAX,
        "arena retained {} bytes, ceiling is {}",
        a.retained(),
        ARENA_MAX
    );
    let small = a.take(1024);
    a.give(small);
    assert!(a.retained() <= ARENA_MAX);
}

#[test]
fn frame_fuzz_no_panic() {
    let mut checked = 0u64;
    for seed in 0..512u64 {
        let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9) | 1);
        for cmd in Cmd::ALL {
            let mut buf = encode(&sample(cmd));
            if buf.is_empty() {
                buf = vec![0u8; 8];
            }
            let flips = 1 + rng.below(6) as usize;
            for _ in 0..flips {
                let i = rng.below(buf.len() as u64) as usize;
                buf[i] ^= 1u8 << (rng.below(8) as u32);
            }

            if rng.below(4) == 0 && !buf.is_empty() {
                let n = rng.below(buf.len() as u64) as usize;
                buf.truncate(n);
            }
            checked += 1;
            match decode(cmd, &buf) {
                Err(_) => {}
                Ok(m) => {
                    assert_eq!(
                        encode(&m),
                        buf,
                        "{} accepted a frame its encoder could not produce (seed {})",
                        cmd.name(),
                        seed
                    );
                    assert!(encode(&m).len() <= cmd.payload_cap());
                }
            }
        }
    }
    assert!(checked > 8_000, "fuzz sweep was too small: {}", checked);
}

#[test]
fn frame_header_fuzz_never_panics() {
    for seed in 0..2048u64 {
        let mut rng = Rng::new(seed | 1);
        let mut hdr = [0u8; FRAME_HEADER_BYTES];
        rng.fill(&mut hdr);

        if seed % 2 == 0 {
            hdr[..4].copy_from_slice(&MAGIC_MAIN);
        }
        let _ = parse_frame_header(&hdr, &MAGIC_MAIN);
    }
}

#[test]
fn message_caps_match_the_p2p_table() {
    assert_eq!(Cmd::Hello.payload_cap(), 167);
    assert_eq!(Cmd::GetHeaders.payload_cap(), 2_084);
    assert_eq!(Cmd::Headers.payload_cap(), 264_004);
    assert_eq!(Cmd::Checkpoint.payload_cap(), 1_016);
    assert_eq!(Cmd::Inv.payload_cap(), 135_172);
    assert_eq!(Cmd::Addr.payload_cap(), 15_364);

    assert_eq!(Cmd::Block.payload_cap(), 1_048_576);
    for cmd in Cmd::ALL {
        assert!(cmd.payload_cap() <= MAX_P2P_MSG_BYTES);
        assert_eq!(Cmd::from_code(cmd.code()), Some(cmd));
    }
}
