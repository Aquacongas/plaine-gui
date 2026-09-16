// not "PLN": that is the zloty's ISO-4217 code and a taken ticker.
pub const TICKER: &str = "PLNE";

// high-entropy bytes, kept well away from ascii so a stray text frame can't
// look like a valid p2p header.
pub const MAGIC_MAIN: [u8; 4] = [0xB7, 0x4E, 0xD3, 0x21];

// the four ascii bytes of PLNE. enters every tx and announcement signature
// from block 0, so a signature from another chain can never replay here.
pub const CHAIN_ID: [u8; 4] = *b"PLNE";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    Main,
}

impl Network {
    pub const ALL: [Network; 1] = [Network::Main];

    #[inline]
    pub const fn chain_id(self) -> [u8; 4] {
        CHAIN_ID
    }

    #[inline]
    pub const fn magic(self) -> [u8; 4] {
        MAGIC_MAIN
    }

    #[inline]
    pub const fn as_str(self) -> &'static str {
        "main"
    }

    pub fn from_name(s: &str) -> Option<Network> {
        match s {
            "main" => Some(Network::Main),
            _ => None,
        }
    }
}

impl core::fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const PORT_P2P: u16 = 9256;

pub const PORT_RPC: u16 = 9257;

// mining is stratum-only from genesis; there is no native getwork port.
pub const PORT_STRATUM: u16 = 9258;

pub const PORT_STRATUM_TLS: u16 = 9259;

pub const ADDRESS_HRP: &str = "plne";

pub const ADDRESS_PAYLOAD_BYTES: usize = 20;

pub const DECIMALS: u32 = 6;

pub const MILE_PER_PLNE: u128 = 1_000_000;

pub const BLOCK_TIME_SECS: u64 = 60;

pub const BLOCKS_PER_YEAR: u64 = 525_960;

// Flat 0.2 PLNE from block 1, forever: no halving, no cap. The absolute subsidy
// stays put while the inflation rate falls toward zero. Genesis pays nothing.
pub const BLOCK_SUBSIDY: u128 = 200_000;

pub const HEADER_BYTES: usize = 132;

pub const VERSION_BASE: u32 = 0x2000_0000;

pub const TX_TYPE_COINBASE: u8 = 0x00;

pub const TX_TYPE_TRANSFER: u8 = 0x01;

pub const TX_TYPE_ANNOUNCEMENT: u8 = 0x02;

pub const TX_TRANSFER_BYTES: usize = 157;

pub const TX_TRANSFER_BYTES_UNSIGNED: usize = 93;

pub const PUBKEY_BYTES: usize = 32;

pub const SIG_BYTES: usize = 64;

pub const HASH_BYTES: usize = 32;

pub const AUTHOR_NOTE_HEADER_BYTES: usize = 4;

pub const ANNOUNCEMENT_MIN_PAYLOAD_BYTES: usize = 1;

pub const ANNOUNCEMENT_MAX_PAYLOAD_BYTES: usize = 1024;

pub const TX_ANNOUNCEMENT_PREFIX_BYTES: usize = 60;

pub const TX_ANNOUNCEMENT_OVERHEAD_BYTES: usize = TX_ANNOUNCEMENT_PREFIX_BYTES + SIG_BYTES;

pub const TX_ANN_OFF_TYPE: usize = 0;

pub const TX_ANN_OFF_FROM_PUB: usize = 1;

pub const TX_ANN_OFF_FEE: usize = 33;

pub const TX_ANN_OFF_NONCE: usize = 49;

pub const TX_ANN_OFF_ENCODING: usize = 57;

pub const TX_ANN_OFF_LENGTH: usize = 58;

pub const TX_ANN_OFF_PAYLOAD: usize = 60;

pub const COINBASE_PREFIX_BYTES: usize = 61;

pub const TX_CB_OFF_HEIGHT: usize = 1;

pub const TX_CB_OFF_TO: usize = 9;

pub const TX_CB_OFF_REWARD: usize = 29;

pub const TX_CB_OFF_FEES: usize = 45;

pub const TX_CB_OFF_NOTE: usize = 61;

pub const BODY_COUNT_BYTES: usize = 4;

pub const BODY_TXLEN_BYTES: usize = 4;

pub const BODY_MIN_RECORD_BYTES: usize = BODY_TXLEN_BYTES + 1;

pub const MERKLE_FLAG_PAIR: u8 = 0x00;

// the dup flag on an odd-level self-pairing is what keeps list -> root
// injective and closes CVE-2012-2459.
pub const MERKLE_FLAG_DUP: u8 = 0x01;

// an empty body is rejected by a separate rule before we ever get here; this
// value only exists so the root function is total on hostile input.
pub const TX_ROOT_EMPTY: [u8; HASH_BYTES] = [0u8; HASH_BYTES];

pub const MERKLE_MAX_DEPTH: usize = 12;

pub const FEE_FLOOR_MILE: u128 = 1;

// must stay strictly above MAX_REORG_DEPTH: if the block holding a reward is
// reorged away the reward stops existing, so nothing may spend it until it is
// buried deeper than any reorg we allow. protects the third party who received
// the coins, not the miner.
pub const COINBASE_MATURITY: u64 = 60;

pub const DOMAIN_TX_SIGN: &[u8] = b"PLNE-tx-v1";

// distinct from DOMAIN_TX_SIGN so the two tags are prefix-free: no transfer
// message can ever equal a note message, even at equal preimage length.
pub const DOMAIN_NOTE_SIGN: &[u8] = b"PLNE-note-v1";

pub const DOMAIN_TXID: &[u8] = b"PLNE-txid";

pub const DOMAIN_MERKLE_LEAF: &[u8] = b"PLNE-leaf";

pub const DOMAIN_MERKLE_NODE: &[u8] = b"PLNE-node";

// The isochron params below mirror plaine_pow. We take no dependency on it, so
// keep the two in step by hand: a copy that silently drifts is worse than none.
pub const POW_SCRATCH_BYTES: usize = 65_536;

pub const POW_SCRATCH_MASK: u64 = (POW_SCRATCH_BYTES as u64) - 8;

pub const POW_PROG_INSTR: usize = 512;

pub const POW_LOOPS: usize = 1024;

pub const POW_ADDR_MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

pub const POW_ADDR_C1: u64 = 0x6A09_E667;

pub const POW_ADDR_C2: u64 = 0xBB67_AE85;

pub const ASERT_HALF_LIFE_SECS: i64 = 3600;

pub const ASERT_TARGET_SPACING_SECS: i64 = 60;

pub const ASERT_ANCHOR_INTERVAL: u64 = 100_000;

pub const POW_LIMIT_LIMBS: [u64; 4] = [u64::MAX, u64::MAX, u64::MAX, (1u64 << 48) - 1];

// easiest target the chain admits, on purpose: a stall from too-hard genesis
// is unrecoverable, a few fast early blocks are not. derived from POW_LIMIT
// rather than typed so the two can't drift into a chain-split shape. note
// 2^240-1 has no exact compact encoding, so this sits just below the ceiling.
pub const GENESIS_BITS: u32 = crate::asert::POW_LIMIT.to_compact();

pub const MAX_FUTURE_DRIFT_SECS: u64 = 600;

pub const MEDIAN_TIME_SPAN: usize = 11;

pub const MAX_REORG_DEPTH: u64 = 30;

pub const SYNC_WINDOW_SECS: u64 = 720;

// the authority key is config-loaded, never a source constant: a hardcoded
// authority key in a public tree is a leaked admin key by construction.
pub const CHECKPOINT_MSG_PREFIX: &[u8] = b"plaine-checkpoint-v1|";

pub const CHECKPOINT_SUNSET_HEIGHT: u64 = 525_960;

pub const AUTHOR_NOTE_RECORD_VERSION: u8 = 0x01;

// payload is opaque bytes with no content validation. validating utf-8 in
// consensus would be a chain-split vector; the encoding byte is a display hint.
pub const AUTHOR_NOTE_MAX_BYTES: usize = 256;

pub const MAX_BLOCK_BYTES: usize = 1_048_576;

pub const MAX_TX_BYTES: usize = 8_192;

pub const MAX_TXS_PER_BLOCK: usize = 4_096;

pub const MAX_P2P_MSG_BYTES: usize = 8_388_608;

pub const MAX_P2P_RESP_BYTES: usize = 33_554_432;

pub const MAX_PEERS: usize = 128;

pub const MAX_MEMPOOL_TXS: usize = 20_000;

pub const MAX_MEMPOOL_NONCE_GAP: u64 = 256;

pub const MAX_MEMPOOL_TXS_PER_SENDER: usize = 4_096;

pub const MAX_HEADERS_PER_MSG: usize = 2_000;

pub const LIMIT_NOFILE: u64 = 65_536;

pub const BIP8_SIGNAL_WINDOW: u64 = 10_080;

pub const BIP8_SIGNAL_THRESHOLD_PERCENT: u64 = 80;

pub const BIP8_LOCKIN_GRACE: u64 = 1_440;

pub const BIP8_TIMEOUT_BLOCKS: u64 = 129_600;

const _: () = assert!(
    CHAIN_ID[0] == b'P' && CHAIN_ID[1] == b'L' && CHAIN_ID[2] == b'N' && CHAIN_ID[3] == b'E',
    "SPEC 1: CHAIN_ID is frozen to the four ASCII bytes of PLNE"
);
const _: () = assert!(
    !(CHAIN_ID[0] == 0 && CHAIN_ID[1] == 0 && CHAIN_ID[2] == 0 && CHAIN_ID[3] == 0),
    "CHAIN_ID must never again be the all-zero placeholder"
);

const _: () = assert!(
    Network::Main.chain_id()[3] == b'E' && Network::Main.chain_id()[0] == b'P',
    "Network::Main must sign under PLNE"
);
const _: () = assert!(
    Network::Main.magic()[0] == MAGIC_MAIN[0],
    "Network::Main must carry the mainnet magic"
);
const _: () = assert!(
    POW_LIMIT_LIMBS[0] == u64::MAX
        && POW_LIMIT_LIMBS[1] == u64::MAX
        && POW_LIMIT_LIMBS[2] == u64::MAX
        && POW_LIMIT_LIMBS[3] == (1u64 << 48) - 1,
    "SPEC 1/6: POW_LIMIT is 2^240 - 1"
);
const _: () = assert!(
    GENESIS_BITS == 0x1F00_FFFF,
    "SPEC 1: genesis bits are the compact encoding of POW_LIMIT = 0x1F00FFFF. \
     If this fires, either POW_LIMIT moved or to_compact changed; 2^240-1 has no \
     exact compact encoding and this is the greatest representable target below it."
);

const _: () = assert!(
    COINBASE_MATURITY > MAX_REORG_DEPTH,
    "SPEC 4: maturity must be strictly greater than the reorg limit"
);
const _: () = assert!(
    POW_SCRATCH_BYTES.is_power_of_two(),
    "SPEC 5.1: scratchpad must be a power of two (mask coverage)"
);
const _: () = assert!(
    TX_TRANSFER_BYTES == TX_TRANSFER_BYTES_UNSIGNED + 64,
    "SPEC 4: transfer = unsigned body + ed25519 signature"
);
const _: () = assert!(
    TX_ANNOUNCEMENT_OVERHEAD_BYTES == TX_ANNOUNCEMENT_PREFIX_BYTES + SIG_BYTES,
    "SPEC 4.1: announcement = unsigned prefix + payload + ed25519 signature"
);
const _: () = assert!(
    TX_ANN_OFF_PAYLOAD == TX_ANNOUNCEMENT_PREFIX_BYTES,
    "SPEC 4.1: the payload starts exactly where the unsigned prefix ends"
);
const _: () = assert!(
    TX_ANN_OFF_LENGTH + 2 == TX_ANN_OFF_PAYLOAD
        && TX_ANN_OFF_ENCODING + 1 == TX_ANN_OFF_LENGTH
        && TX_ANN_OFF_NONCE + 8 == TX_ANN_OFF_ENCODING
        && TX_ANN_OFF_FEE + 16 == TX_ANN_OFF_NONCE
        && TX_ANN_OFF_FROM_PUB + PUBKEY_BYTES == TX_ANN_OFF_FEE
        && TX_ANN_OFF_TYPE + 1 == TX_ANN_OFF_FROM_PUB,
    "SPEC 4.1: announcement field offsets must tile the prefix with no gaps"
);
const _: () = assert!(
    TX_ANNOUNCEMENT_OVERHEAD_BYTES + ANNOUNCEMENT_MAX_PAYLOAD_BYTES <= MAX_TX_BYTES,
    "SPEC 10: the largest announcement must fit MAX_TX_BYTES"
);
const _: () = assert!(
    TX_CB_OFF_NOTE == COINBASE_PREFIX_BYTES
        && TX_CB_OFF_FEES + 16 == TX_CB_OFF_NOTE
        && TX_CB_OFF_REWARD + 16 == TX_CB_OFF_FEES
        && TX_CB_OFF_TO + ADDRESS_PAYLOAD_BYTES == TX_CB_OFF_REWARD
        && TX_CB_OFF_HEIGHT + 8 == TX_CB_OFF_TO,
    "SPEC 4.2: coinbase field offsets must tile the prefix with no gaps"
);
const _: () = assert!(
    COINBASE_PREFIX_BYTES + AUTHOR_NOTE_HEADER_BYTES + AUTHOR_NOTE_MAX_BYTES <= MAX_TX_BYTES,
    "SPEC 10: the largest coinbase must fit MAX_TX_BYTES"
);
const _: () = assert!(
    HEADER_BYTES + BODY_COUNT_BYTES + MAX_TXS_PER_BLOCK * BODY_MIN_RECORD_BYTES
        <= MAX_BLOCK_BYTES,
    "SPEC 10/4.3: a maximally-populated body envelope must fit MAX_BLOCK_BYTES"
);
const _: () = assert!(
    (1usize << MERKLE_MAX_DEPTH) >= MAX_TXS_PER_BLOCK,
    "SPEC 3: MERKLE_MAX_DEPTH must cover MAX_TXS_PER_BLOCK leaves"
);
const _: () = assert!(
    MERKLE_FLAG_PAIR != MERKLE_FLAG_DUP,
    "SPEC 3: the duplication flag is what makes list -> root injective"
);
