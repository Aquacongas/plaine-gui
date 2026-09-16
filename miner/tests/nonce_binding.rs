use plaine_pow_mine::client::work;
use plaine_stratum::nonce::{self, E1};

#[test]
fn miner_composes_accepted_nonces() {
    for e1 in [0u32, 1, 0x00A3F2, 0x7FFFFF, 0xFFFFFF] {
        for x in [0u64, 1, 42, (3u64 << 32) | 42, (1 << 40) - 1] {
            let mine = work::compose(e1, x);
            let theirs = E1(e1).compose(x);
            assert_eq!(mine, theirs, "composition differs at e1={e1:#x} x={x:#x}");
            assert!(
                E1(e1).owns(mine),
                "the server would refuse this miner's own nonce with error 25"
            );
            assert_eq!(work::owns(e1, mine), E1(e1).owns(mine));
        }
    }
}

#[test]
fn wire_encoding_round_trips() {
    for x in [0u64, 42, (7u64 << 32) | 0xDEAD_BEEF, (1 << 40) - 1] {
        let n = work::compose(0x00A3F2, x);
        let hex = work::nonce_hex(n);
        assert_eq!(hex.len(), 16);
        assert_eq!(nonce::parse_nonce_hex(&hex), Some(n), "wire round trip failed for {hex}");
        assert_eq!(hex, nonce::nonce_to_hex(n));
    }
}

#[test]
fn miner_and_server_hash_same_header() {
    let prefix = [0xABu8; 124];
    for x in [0u64, 1, (5u64 << 32) | 99] {
        let n = work::compose(0x112233, x);
        assert_eq!(work::assemble(&prefix, n), nonce::assemble_header(&prefix, n));
    }
}

#[test]
fn foreign_share_is_not_claimable() {
    let victim = 0x00A3F2u32;
    let thief = 0x112233u32;
    let n = work::compose(victim, 42);
    assert!(work::owns(victim, n));
    assert!(!work::owns(thief, n));
    assert!(!E1(thief).owns(n));
}

#[test]
fn miner_and_server_share_target() {
    for bits in [
        plaine_consensus::constants::GENESIS_BITS,
        0x1f00_ffff,
        0x1e00_ffff,
        0x1d00_ffff,
    ] {
        let mut prefix = [0u8; plaine_stratum::limits::JOB_PREFIX_BYTES];
        prefix[work::BITS_OFFSET..work::BITS_OFFSET + 4].copy_from_slice(&bits.to_le_bytes());
        let mine = work::network_target_from_prefix(&prefix);
        let theirs = plaine_stratum::target::Target::from_compact(bits).map(|t| t.0);
        assert_eq!(mine, theirs, "network target differs at bits {bits:#010x}");
    }
}

#[test]
fn difficulty_matches_server_arithmetic() {
    for d in [0u64, 1, 2, 3, 8_192, 60_000, 65_536, 1 << 40, u64::MAX] {
        assert_eq!(
            work::target_from_difficulty(d),
            plaine_stratum::target::Target::from_difficulty(d).0,
            "difficulty {d} converts to a different target than the server's"
        );
    }
}

#[test]
fn job_and_grace_limits_match_server() {
    assert_eq!(work::JOB_SLOTS, plaine_stratum::limits::JOB_SLOTS);
    assert_eq!(work::STALE_CREDIT_GRACE, plaine_stratum::limits::STALE_CREDIT_GRACE);

    assert_eq!(work::SERVER_JOB_REFRESH, plaine_stratum::limits::TEMPLATE_REFRESH);
    assert!(
        plaine_pow_mine::client::SERVER_SILENCE_DEADLINE
            >= work::SERVER_JOB_REFRESH * 4,
        "the silence deadline must survive several missed refreshes"
    );
}

#[test]
fn miner_rolls_only_allowed_bytes() {
    assert_eq!(work::X_BYTES, plaine_stratum::limits::MINER_ROLLABLE_BYTES);
    assert_eq!(work::X_BITS, plaine_stratum::limits::X_BITS);
    assert_eq!(work::E1_BITS, plaine_stratum::limits::E1_BITS);
    assert_eq!(work::PREFIX_BYTES, plaine_stratum::limits::JOB_PREFIX_BYTES);
}

fn legal_widths() -> Vec<(u32, u32)> {
    (work::X_BYTES_MIN..=work::X_BYTES)
        .map(|bytes| {
            let x_bits = (bytes * 8) as u32;
            (x_bits, plaine_stratum::limits::X_BITS - x_bits)
        })
        .collect()
}

#[test]
fn legal_windows_match_server_slices() {
    let w = legal_widths();
    assert_eq!(w, vec![(32, 8), (40, 0)], "the legal window set moved: {w:?}");
}

#[test]
fn narrowed_window_nonces_bind() {
    for (x_bits, sub_bits) in legal_widths() {
        let subs: Vec<u32> = if sub_bits == 0 {
            vec![0]
        } else {
            let m = (1u32 << sub_bits) - 1;
            vec![0, 1, m / 2, m]
        };
        for e1 in [0u32, 1, 0x00A3F2, 0xFFFFFF] {
            for sub in subs.iter().copied() {
                let fixed = nonce::slice_fixed(E1(e1), sub, sub_bits);
                assert!(
                    fixed < work::e1_limit(x_bits),
                    "the server cut a fixed part {fixed:#x} that does not fit the \
                     {x_bits}-bit window it announced beside it"
                );

                let e1_prime = u32::try_from(fixed).expect("the fixed part must fit a u32");

                for x in [0u64, 1, 42, (1u64 << (x_bits - 1)) | 7, (1u64 << x_bits) - 1] {
                    let n = work::compose_in(e1_prime, x, x_bits);
                    assert!(
                        nonce::slice_owns(E1(e1), sub, sub_bits, n),
                        "the server would refuse this nonce with error 25: \
                         e1={e1:#x} sub={sub} sub_bits={sub_bits} x={x:#x}"
                    );
                    assert!(work::owns_in(e1_prime, n, x_bits), "the miner disowns its own nonce");

                    assert!(E1(e1).owns(n), "the pool's upstream slice was destroyed by the split");
                }
            }
        }
    }
}

#[test]
fn sibling_slice_is_refused() {
    let (x_bits, sub_bits) = (32u32, 8u32);
    let e1 = 0x00A3F2u32;
    let (mine, theirs) = (7u32, 8u32);
    let my_e1 = nonce::slice_fixed(E1(e1), mine, sub_bits) as u32;
    let their_e1 = nonce::slice_fixed(E1(e1), theirs, sub_bits) as u32;
    assert_ne!(my_e1, their_e1);

    let n = work::compose_in(my_e1, 0xDEAD_BEEF, x_bits);
    assert!(nonce::slice_owns(E1(e1), mine, sub_bits, n));
    assert!(!nonce::slice_owns(E1(e1), theirs, sub_bits, n), "the server confused two sub-slices");
    assert!(!work::owns_in(their_e1, n, x_bits), "the miner confused two sub-slices");
    assert!(
        E1(e1).owns(n),
        "the upstream check cannot separate them, which is the whole reason the \
         sub-slice check has to"
    );
}

#[test]
fn narrowed_slice_hex_round_trips() {
    for (x_bits, sub_bits) in legal_widths() {
        let sub = if sub_bits == 0 { 0 } else { 0xA5 };
        let e1 = 0x00A3F2u32;
        let mut out = Vec::new();
        plaine_stratum::proto::write_subscribe_result(&mut out, Some(1), E1(e1), sub, sub_bits);
        let line = String::from_utf8(out).expect("utf8");
        let msg = plaine_pow_mine::client::json::parse(line.trim_end()).expect("the client parses it");

        let hex = msg.str_at(1).expect("extranonce1");
        assert_eq!(
            hex.len(),
            ((work::E1_BITS + sub_bits) / 4) as usize,
            "the hex width does not describe the fixed part: {hex}"
        );
        let parsed = u32::from_str_radix(hex, 16).expect("hex");
        assert_eq!(u64::from(parsed), nonce::slice_fixed(E1(e1), sub, sub_bits));

        let bytes = msg.num_at(2).expect("rollable bytes");
        assert_eq!(bytes * 8, u64::from(x_bits));
    }
}
