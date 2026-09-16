use crate::config::Network;
use plaine_consensus::constants::HEADER_BYTES;
use plaine_wallet::genesis::{self as wg, Genesis};

// Block 0 is compiled in - never read from disk or the network. That is what
// makes every node agree on genesis by construction.
pub const MAINNET_INPUT: &str = include_str!("genesis/mainnet.input");

pub const MAINNET_NOTE: &[u8] = include_bytes!("genesis/mainnet.note");

const POW_VERIFIER: wg::PowVerifier = wg::PowVerifier::Caller("plaine_noded::genesis::verify_pow");

#[derive(Debug)]
pub enum GenesisError {
    Refused(String),
    PowFailed,

    WrongNetwork {
        found: [u8; 32],
        expected: [u8; 32],
    },
}

impl core::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GenesisError::Refused(m) => write!(f, "{m}"),
            GenesisError::PowFailed => write!(
                f,
                "the embedded genesis nonce does not meet its own target. This binary's genesis \
                 is not minable-consistent and it would produce a chain no other node accepts."
            ),
            GenesisError::WrongNetwork { found, expected } => write!(
                f,
                "this data directory holds genesis {} but this binary expects {}. It is another \
                 network's chain; point --data-dir somewhere else rather than mixing them.",
                plaine_consensus::hex::encode(found),
                plaine_consensus::hex::encode(expected)
            ),
        }
    }
}

pub fn mainnet() -> Result<Genesis, GenesisError> {
    // Order is deliberate: parse, then the clock-invariant launch refusals, then
    // build, then verify. A bad note or nonce gets caught before the block reaches
    // the rest of the node.
    let input = wg::parse_input(MAINNET_INPUT).map_err(|e| GenesisError::Refused(e.to_string()))?;
    wg::check_launch_refusals_by(&input, MAINNET_NOTE, POW_VERIFIER)
        .map_err(|e| GenesisError::Refused(e.to_string()))?;
    let g = wg::build(&input, MAINNET_NOTE).map_err(|e| GenesisError::Refused(e.to_string()))?;
    wg::verify(&g).map_err(|e| GenesisError::Refused(e.to_string()))?;
    Ok(g)
}

// derived from the block we actually build, never a hardcoded constant - the
// expected hash cannot drift away from the embedded input.
pub fn mainnet_genesis_hash() -> [u8; 32] {
    static CELL: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *CELL.get_or_init(|| mainnet().expect("the embedded mainnet genesis must build").block_hash)
}

// Create-path only. The single check here that consults a wall clock, so it stays
// off the load path; a late launch would otherwise pin difficulty at POW_LIMIT.
#[allow(dead_code)]
pub fn refuse_outside_launch_window(time: u64, now: u64) -> Result<(), String> {
    match plaine_wallet::genesis::launch_window(time, now) {
        plaine_wallet::genesis::LaunchWindow::InWindow => Ok(()),
        w => Err(format!(
            "refused: {} Fix `genesis/mainnet.input`'s `time` and run this again. It is the one \
             field in block 0 with no compiled refusal on the load path; \
             `check_launch_refusals_by` stays invariant to the clock.",
            w.explain()
        )),
    }
}

pub fn for_network(n: Network) -> Result<Genesis, GenesisError> {
    match n {
        Network::Main => mainnet(),
    }
}

pub fn expected_hash(n: Network) -> Option<[u8; 32]> {
    match n {
        Network::Main => Some(mainnet_genesis_hash()),
    }
}

pub fn verify_pow(interp: &crate::wire::pow::Interp, header: &[u8; HEADER_BYTES]) -> bool {
    interp.verify_header(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_hash_matches_built() {
        let g = mainnet().expect("builds");
        assert_eq!(mainnet_genesis_hash(), g.block_hash);
        assert_eq!(expected_hash(Network::Main), Some(g.block_hash));
    }

    #[test]
    #[ignore = "operator tool: run with --ignored --release after editing mainnet.input"]
    fn regrind_the_mainnet_genesis_nonce() {
        let input = wg::parse_input(MAINNET_INPUT).expect("mainnet.input parses");
        wg::check_launch_refusals_by(&input, MAINNET_NOTE, POW_VERIFIER)
            .expect("mainnet.input passes the launch refusals");

        if let Err(why) = super::refuse_outside_launch_window(
            input.time,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the system clock is after 1970")
                .as_secs(),
        ) {
            panic!("{why}");
        }
        let g = wg::build(&input, MAINNET_NOTE).expect("builds");
        let interp = crate::wire::pow::Interp::new().expect("hardware AES");
        let mut h = g.header_bytes;
        for nonce in 0u64..5_000_000 {
            h[124..132].copy_from_slice(&nonce.to_le_bytes());
            if interp.verify_header(&h) {
                println!("MAINNET_GENESIS_NONCE = {nonce}");
                println!(
                    "MAINNET_GENESIS_HASH  = {}",
                    plaine_consensus::hex::encode(&plaine_consensus::crypto::header_hash(&h))
                );
                return;
            }
        }
        panic!("no nonce found in 5,000,000 tries");
    }

    #[test]
    fn free_field_refused_outside_window() {
        use plaine_consensus::constants::ASERT_HALF_LIFE_SECS;
        let half = ASERT_HALF_LIFE_SECS as u64;
        let now = 1_800_000_000u64;

        for t in [now, now - half, now + half] {
            assert!(
                super::refuse_outside_launch_window(t, now).is_ok(),
                "{t} is inside the window"
            );
        }

        let err = super::refuse_outside_launch_window(now - half - 1, now)
            .expect_err("one half-life plus a second early must be refused");
        assert!(err.starts_with("refused"), "{err}");
        assert!(err.contains("before"), "{err}");
        assert!(err.contains("POW_LIMIT"), "the cost must be named: {err}");

        let err = super::refuse_outside_launch_window(now + half + 1, now)
            .expect_err("one half-life plus a second late must be refused");
        assert!(err.contains("after"), "{err}");

        let err = super::refuse_outside_launch_window(now - 86_400, now)
            .expect_err("a day early must be refused");
        assert!(err.contains("86400"), "{err}");

        assert!(super::refuse_outside_launch_window(0, now).is_err());
    }

    #[test]
    fn launch_refusals_ignore_clock() {
        let input = wg::parse_input(MAINNET_INPUT).expect("mainnet.input parses");
        let a = wg::check_launch_refusals_by(&input, MAINNET_NOTE, POW_VERIFIER);

        let b = wg::check_launch_refusals_by(&input, MAINNET_NOTE, POW_VERIFIER);
        assert_eq!(a.is_ok(), b.is_ok());
        let src = include_str!("genesis.rs");
        let body = src
            .split("pub fn refuse_outside_launch_window")
            .next()
            .expect("the file has a prefix");
        assert!(
            !body.contains(&format!("{}{}", "launch_", "window(")),
            "the launch window must not be reachable from the load path; it \
             belongs on the CREATE path only"
        );
    }

    #[test]
    fn genesis_nonce_meets_target() {
        let g = mainnet().expect("builds");
        let interp = crate::wire::pow::Interp::new().expect("hardware AES");
        assert!(verify_pow(&interp, &g.header_bytes));
    }

    #[test]
    fn placeholder_note_refused() {
        let input = wg::parse_input(MAINNET_INPUT).expect("mainnet.input parses");
        let placeholder = b"PLACEHOLDER - replace me".as_slice();
        let err = wg::check_launch_refusals(&input, placeholder)
            .expect_err("a genesis carrying the placeholder note must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains(wg::PLACEHOLDER_MARKER),
            "the refusal must name the placeholder, got: {msg}"
        );
    }

    #[test]
    fn mainnet_genesis_matches_built() {
        let g = for_network(Network::Main).expect("this binary must carry a mainnet genesis");
        assert_eq!(
            plaine_consensus::hex::encode(&g.block_hash),
            "055127ff681c6cee34889e9206de4c4a796b9fb4c4017ee3e89ef50f5e2192d6",
            "the mainnet genesis moved. A one-byte change to mainnet.note or mainnet.input \
             changes tx_root and therefore the block hash; a change to plaine-pow's kernel \
             parameters invalidates the mined nonce, which also moves it. If this was \
             deliberate, re-mine with `regrind_the_mainnet_genesis_nonce` and update both \
             mainnet.input and this test. Every node already on the old chain will refuse the \
             new one as another network's data directory."
        );
        assert_eq!(g.header.height, 0);
        assert_eq!(g.header.time, 1_789_556_400, "the genesis timestamp is frozen");
        assert_eq!(g.header.nonce, 66_048, "the mined nonce is frozen");
        assert_eq!(g.header.bits, plaine_consensus::constants::GENESIS_BITS);

        assert_eq!(expected_hash(Network::Main), Some(g.block_hash));
    }

    #[test]
    fn mainnet_note_is_frozen() {
        assert_eq!(MAINNET_NOTE, wg::MAINNET_GENESIS_NOTE.as_bytes());
        assert!(!MAINNET_NOTE.ends_with(b"\n"));
        assert_eq!(MAINNET_NOTE.len(), 51);
    }
}
