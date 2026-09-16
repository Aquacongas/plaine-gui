use crate::error::{Result, WalletError};
use plaine_consensus::asert::{Target, POW_LIMIT};
use plaine_consensus::codec::{AuthorNote, BlockBody, CoinbaseTx, Header};
use plaine_consensus::constants::{
    ASERT_HALF_LIFE_SECS,
    AUTHOR_NOTE_MAX_BYTES, CHAIN_ID, GENESIS_BITS, HEADER_BYTES, VERSION_BASE,
};
use plaine_consensus::{crypto, emission, merkle, tx};

pub const CAN_VERIFY_POW: bool = cfg!(feature = "pow");

#[cfg(feature = "pow")]
compile_error!(
    "the `pow` feature is not wired yet. To enable genesis PoW verification: add \
     `plaine-pow-sys` as an optional dependency of plaine-wallet, make this feature \
     enable it, and replace this compile_error with a call that runs the Isochron core \
     over `g.header_bytes` and compares the digest against `Target::from_compact(bits)` \
     in `genesis::verify`. Until then a mainnet genesis cannot be produced by this build."
);

pub const PLACEHOLDER_MARKER: &str = "PLACEHOLDER";

pub const MAINNET_GENESIS_NOTE: &str = "We were told the altitude. We never saw the ground.";

pub const MAINNET_GENESIS_NOTE_ENCODING: u8 = 0x01;

const _: () = assert!(
    MAINNET_GENESIS_NOTE.len() == 51,
    "SPEC 8: the frozen genesis message is 51 bytes"
);
const _: () = {
    let b = MAINNET_GENESIS_NOTE.as_bytes();
    let mut i = 0;
    while i < b.len() {
        assert!(b[i] < 0x80, "SPEC 8: the frozen genesis message is ASCII");
        assert!(b[i] != b'\n', "SPEC 8: no newline, trailing or otherwise");
        i += 1;
    }
};

pub const INPUT_FORMAT: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisInput {
    pub format: u64,
    pub chain_id: [u8; 4],
    pub version: u32,
    pub time: u64,
    pub bits: u32,
    pub prev_hash: [u8; 32],
    pub ext_root: [u8; 32],
    pub nonce: u64,
    pub coinbase_to: String,
    pub note_encoding: u8,
    pub note_text_file: String,
    pub author_pubkey: [u8; 32],
    pub checkpoint_pubkey: [u8; 32],
}

const KEYS: [&str; 13] = [
    "format",
    "chain_id",
    "version",
    "time",
    "bits",
    "prev_hash",
    "ext_root",
    "nonce",
    "coinbase_to",
    "note_encoding",
    "note_text_file",
    "author_pubkey",
    "checkpoint_pubkey",
];

pub fn parse_input(text: &str) -> Result<GenesisInput> {
    let mut pairs: Vec<(String, String, usize)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(WalletError::format(format!(
                "genesis input line {lineno}: expected `key = value`, found {raw:?}"
            )));
        };
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        if !KEYS.contains(&k.as_str()) {
            return Err(WalletError::format(format!(
                "genesis input line {lineno}: unknown key {k:?}"
            )));
        }
        if pairs.iter().any(|(pk, _, _)| *pk == k) {
            return Err(WalletError::format(format!(
                "genesis input line {lineno}: duplicate key {k:?}"
            )));
        }
        if v.is_empty() {
            return Err(WalletError::format(format!(
                "genesis input line {lineno}: {k} has no value; nothing consensus-visible \
                 has a default"
            )));
        }
        pairs.push((k, v, lineno));
    }
    for k in KEYS {
        if !pairs.iter().any(|(pk, _, _)| pk == k) {
            return Err(WalletError::format(format!(
                "genesis input is missing the required key {k:?}"
            )));
        }
    }
    let get = |k: &str| -> &str {
        pairs
            .iter()
            .find(|(pk, _, _)| pk == k)
            .map(|(_, v, _)| v.as_str())
            .expect("presence checked above")
    };
    let num_u64 = |k: &str| -> Result<u64> {
        get(k)
            .parse::<u64>()
            .map_err(|_| WalletError::format(format!("genesis input: {k} must be a decimal integer")))
    };
    let num_u32 = |k: &str| -> Result<u32> {
        let v = get(k);
        let r = if let Some(h) = v.strip_prefix("0x") {
            u32::from_str_radix(h, 16)
        } else {
            v.parse::<u32>()
        };
        r.map_err(|_| {
            WalletError::format(format!(
                "genesis input: {k} must be a decimal or 0x-hex 32-bit integer, got {v:?}"
            ))
        })
    };
    let bytes = |k: &str, n: usize| -> Result<Vec<u8>> {
        let b = plaine_consensus::hex::decode(get(k))
            .map_err(|e| WalletError::format(format!("genesis input: {k}: {e}")))?;
        if b.len() != n {
            return Err(WalletError::format(format!(
                "genesis input: {k} must be {n} bytes ({} hex digits), got {}",
                n * 2,
                b.len()
            )));
        }
        Ok(b)
    };

    let format = num_u64("format")?;
    if format != INPUT_FORMAT {
        return Err(WalletError::format(format!(
            "genesis input format {format}, this build understands {INPUT_FORMAT}"
        )));
    }
    let note_encoding = {
        let b = bytes("note_encoding", 1)?;
        b[0]
    };
    Ok(GenesisInput {
        format,
        chain_id: bytes("chain_id", 4)?.as_slice().try_into().expect("4"),
        version: num_u32("version")?,
        time: num_u64("time")?,
        bits: num_u32("bits")?,
        prev_hash: bytes("prev_hash", 32)?.as_slice().try_into().expect("32"),
        ext_root: bytes("ext_root", 32)?.as_slice().try_into().expect("32"),
        nonce: num_u64("nonce")?,
        coinbase_to: get("coinbase_to").to_string(),
        note_encoding,
        note_text_file: get("note_text_file").to_string(),
        author_pubkey: bytes("author_pubkey", 32)?.as_slice().try_into().expect("32"),
        checkpoint_pubkey: bytes("checkpoint_pubkey", 32)?
            .as_slice()
            .try_into()
            .expect("32"),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genesis {
    pub header: Header,
    pub header_bytes: [u8; HEADER_BYTES],
    pub coinbase: CoinbaseTx,
    pub coinbase_bytes: Vec<u8>,
    pub body: Vec<u8>,
    pub tx_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub note_payload: Vec<u8>,
}

pub fn check_bits(bits: u32) -> Result<Target> {
    let target = Target::from_compact(bits).map_err(|e| {
        WalletError::format(format!(
            "genesis input: bits 0x{bits:08x} is not a valid compact encoding: {e}"
        ))
    })?;
    if target.is_zero() {
        return Err(WalletError::refused(format!(
            "genesis input: bits 0x{bits:08x} decodes to target 0, which is outside \
             SPEC 6's clamp range [1, POW_LIMIT]. No header can ever satisfy it."
        )));
    }
    if target > POW_LIMIT {
        return Err(WalletError::refused(format!(
            "genesis input: bits 0x{bits:08x} decodes to a target above POW_LIMIT \
             (2^240 - 1), outside SPEC 6's clamp range [1, POW_LIMIT].\n  target    {}\n  \
             POW_LIMIT {}",
            target.to_be_hex(),
            POW_LIMIT.to_be_hex()
        )));
    }
    if bits != GENESIS_BITS {
        return Err(WalletError::refused(format!(
            "genesis input: bits 0x{bits:08x} is not the frozen genesis value \
             0x{GENESIS_BITS:08x}.\n  A harder genesis risks stalling the chain if hash rate \
             is lower than expected, and ASERT reaches the real level within the first \
             hour regardless."
        )));
    }
    Ok(target)
}

pub fn build(input: &GenesisInput, note: &[u8]) -> Result<Genesis> {
    check_bits(input.bits)?;
    if note.len() > AUTHOR_NOTE_MAX_BYTES {
        return Err(WalletError::refused(format!(
            "genesis note is {} bytes; SPEC 8 caps the coinbase author note at \
             {AUTHOR_NOTE_MAX_BYTES} (this is not the 1024-byte announcement limit)",
            note.len()
        )));
    }
    let to = crypto::decode_address(&input.coinbase_to).map_err(|e| {
        WalletError::format(format!("genesis input: coinbase_to is not a valid address: {e}"))
    })?;

    let note_record = AuthorNote {
        encoding: input.note_encoding,
        payload: note.to_vec(),
    };
    let coinbase = CoinbaseTx {
        height: 0,
        to,
        reward: emission::block_reward(0),
        fees: 0,
        note: note_record,
    };
    let coinbase_bytes = coinbase
        .encode()
        .map_err(|e| WalletError::format(format!("genesis coinbase does not encode: {e}")))?;
    let body = BlockBody::encode(&[coinbase_bytes.as_slice()])
        .map_err(|e| WalletError::format(format!("genesis body does not encode: {e}")))?;
    let tx_root = merkle::tx_root(&[coinbase_bytes.as_slice()]);

    let header = Header {
        version: input.version,
        height: 0,
        prev_hash: input.prev_hash,
        tx_root,
        ext_root: input.ext_root,
        time: input.time,
        bits: input.bits,
        author_note_len: note.len() as u32,
        nonce: input.nonce,
    };
    let header_bytes = header.encode();
    let block_hash = header.hash();

    Ok(Genesis {
        header,
        header_bytes,
        coinbase,
        coinbase_bytes,
        body,
        tx_root,
        block_hash,
        note_payload: note.to_vec(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchWindow {
    InWindow,

    TooEarly {
        by_secs: u64,
    },

    TooLate {
        by_secs: u64,
    },
}

impl LaunchWindow {
    pub fn explain(&self) -> String {
        let (by, direction, cost) = match self {
            LaunchWindow::InWindow => return String::new(),
            LaunchWindow::TooEarly { by_secs } => (
                *by_secs,
                "before",
                "ASERT measures elapsed time against `height * BLOCK_TIME_SECS` from the anchor, so block 1 arriving this late leaves the chain permanently behind schedule by a constant - the error does not decay. GENESIS_BITS is POW_LIMIT, so difficulty on a fresh chain can only go up, and the whole offset is spent holding the chain at the floor",
            ),
            LaunchWindow::TooLate { by_secs } => (
                *by_secs,
                "after",
                "block 1 must carry a timestamp above the genesis stamp and inside MAX_FUTURE_DRIFT_SECS of the miner's clock, so a genesis stamped this far ahead cannot be built on until the wall clock catches up. Until then the chain does not start, and it does not say why",
            ),
        };
        let halvings = by / ASERT_HALF_LIFE_SECS as u64;
        format!(
            "genesis `time` is {by} seconds {direction} the moment this was run, which is more than one ASERT half-life ({} s). {cost}. Difficulty leaves the floor only once real hash rate has grown by 2^({by}/{}) = 2^{halvings}. A chain pinned at POW_LIMIT produces a flat line, not a visible collapse, and can run for thousands of blocks before the stall is obvious.",
            ASERT_HALF_LIFE_SECS, ASERT_HALF_LIFE_SECS
        )
    }
}

// Genesis time must sit within one ASERT half-life of now. A late launch pins
// difficulty at the floor and the offset never decays; that is why this is a
// hard gate, not a warning.
pub fn launch_window(time: u64, now: u64) -> LaunchWindow {
    let half = ASERT_HALF_LIFE_SECS as u64;
    if time + half < now {
        LaunchWindow::TooEarly { by_secs: now - time }
    } else if time > now + half {
        LaunchWindow::TooLate { by_secs: time - now }
    } else {
        LaunchWindow::InWindow
    }
}

pub fn check_launch_refusals(input: &GenesisInput, note: &[u8]) -> Result<()> {
    check_launch_refusals_by(input, note, PowVerifier::ThisCrate)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowVerifier {
    ThisCrate,
    Caller(&'static str),
}

impl PowVerifier {
    fn can(&self) -> bool {
        match self {
            PowVerifier::ThisCrate => CAN_VERIFY_POW,
            PowVerifier::Caller(_) => true,
        }
    }
}

pub fn check_launch_refusals_by(
    input: &GenesisInput,
    note: &[u8],
    pow: PowVerifier,
) -> Result<()> {
    if input.chain_id == [0, 0, 0, 0] {
        return Err(WalletError::refused(format!(
            "chain_id is the all-zero placeholder. CHAIN_ID is frozen to the \
             ASCII bytes of PLNE = {}, and it enters every signature from block 0; a chain \
             launched under the placeholder makes every signature void.",
            plaine_consensus::hex::encode(&CHAIN_ID),
        )));
    }
    if input.chain_id != CHAIN_ID {
        return Err(WalletError::refused(format!(
            "chain_id {} does not match the compiled-in CHAIN_ID, which is \
             {} ({}). A genesis built under a chain id no binary will ever use produces a \
             chain nothing can sign for.",
            plaine_consensus::hex::encode(&input.chain_id),
            plaine_consensus::hex::encode(&CHAIN_ID),
            String::from_utf8_lossy(&CHAIN_ID)
        )));
    }

    if String::from_utf8_lossy(note).contains(PLACEHOLDER_MARKER) {
        return Err(WalletError::refused(format!(
            "the genesis note still contains the placeholder marker \
             {PLACEHOLDER_MARKER:?}, which belongs to a note file written before SPEC 8's \
             message was enforced here.\n\n{FROZEN_NOTE_RULE}"
        )));
    }
    if note.is_empty() {
        return Err(WalletError::refused(format!(
            "the genesis note is empty.\n\n{FROZEN_NOTE_RULE}"
        )));
    }

    if note != MAINNET_GENESIS_NOTE.as_bytes() {
        return Err(WalletError::refused(format!(
            "the genesis note is not the message SPEC 8 freezes.\n  expected {} bytes: \
             {:?}\n  got      {} bytes: {:?}\n\n{FROZEN_NOTE_RULE}",
            MAINNET_GENESIS_NOTE.len(),
            MAINNET_GENESIS_NOTE,
            note.len(),
            String::from_utf8_lossy(note),
        )));
    }
    if input.note_encoding != MAINNET_GENESIS_NOTE_ENCODING {
        return Err(WalletError::refused(format!(
            "note_encoding is 0x{:02x}; SPEC 8 pins the genesis note's encoding byte to \
             0x{:02x} (assumed UTF-8). Consensus never checks this byte, so nothing \
             downstream would flag it. It is part of block 0 and part of the block hash.",
            input.note_encoding, MAINNET_GENESIS_NOTE_ENCODING
        )));
    }

    if !pow.can() {
        return Err(WalletError::refused(
            "this build cannot verify genesis PoW (built without the `pow` feature, and the \
             caller named no verifier of its own - see PowVerifier), and a genesis may not \
             be produced by a build that cannot check its own nonce. The genesis header \
             must satisfy proof of work at GENESIS_BITS; there is no height-0 exemption. \
             Genesis is pinned by its hash, not by skipping the check. Rebuild with \
             `--features pow`, or supply a PowVerifier of your own.",
        ));
    }
    Ok(())
}

pub const FROZEN_NOTE_RULE: &str = "\
SPEC section 8 freezes the genesis message. It is not decided at launch and it is
not chosen by this tool: the note file must hold exactly these 51 ASCII bytes,
with no trailing newline, and note_encoding must be 0x01.

  We were told the altitude. We never saw the ground.

Its meaning is not published anywhere - not the README, not the site, not a reply
to the community.

There is deliberately no dateline from the launch day's press in the string. The
proof that the chain was not mined in secret beforehand is in code instead: no
premine, no presale, no fund, no developer fee, readable in emission.rs and
confirmed at any height by the emission_audit RPC.";

pub fn verify(g: &Genesis) -> Result<()> {
    let fail = |m: String| -> WalletError { WalletError::crypto(m) };

    if g.header_bytes.len() != HEADER_BYTES {
        return Err(fail(format!(
            "header is {} bytes, must be {HEADER_BYTES}",
            g.header_bytes.len()
        )));
    }
    let header = Header::decode(&g.header_bytes)
        .map_err(|e| fail(format!("header does not decode: {e}")))?;
    if header != g.header {
        return Err(fail("header does not round-trip through its wire form".into()));
    }
    if header.height != 0 {
        return Err(fail(format!("genesis height is {}, must be 0", header.height)));
    }
    if header.prev_hash != [0u8; 32] {
        return Err(fail("genesis prev_hash must be all zero".into()));
    }
    if header.ext_root != [0u8; 32] {
        return Err(fail("ext_root must be all zero".into()));
    }
    if header.version & 0xE000_0000 != VERSION_BASE {
        return Err(fail(format!(
            "header version 0x{:08x}: top three bits must be 001 (VERSION_BASE 0x{VERSION_BASE:08x})",
            header.version
        )));
    }

    let target = Target::from_compact(header.bits)
        .map_err(|e| fail(format!("header bits 0x{:08x}: {e}", header.bits)))?;
    if target.is_zero() || target > POW_LIMIT {
        return Err(fail(format!(
            "header bits 0x{:08x} decode outside SPEC 6's clamp range [1, POW_LIMIT]",
            header.bits
        )));
    }
    if header.bits != GENESIS_BITS {
        return Err(fail(format!(
            "header bits 0x{:08x} are not the frozen genesis bits 0x{GENESIS_BITS:08x}",
            header.bits
        )));
    }

    let _ = target;

    let body = BlockBody::parse(&g.body).map_err(|e| fail(format!("body does not parse: {e}")))?;
    if body.len() != 1 {
        return Err(fail(format!(
            "genesis body holds {} transactions, must hold exactly 1",
            body.len()
        )));
    }
    if body.tx_root() != header.tx_root {
        return Err(fail("body tx_root does not equal the header tx_root".into()));
    }
    let txs = tx::decode_body(&body).map_err(|e| fail(format!("body record: {e}")))?;
    let cb = tx::check_body_structure(&txs)
        .map_err(|e| fail(format!("body structure: {e}")))?;

    tx::check_coinbase(cb, 0, header.author_note_len, 0)
        .map_err(|e| fail(format!("check_coinbase rejected the genesis coinbase: {e}")))?;

    if emission::block_reward(0) != 0 {
        return Err(fail(
            "emission::block_reward(0) is not zero; the no-premine property is broken".into(),
        ));
    }
    if cb.reward != 0 || cb.fees != 0 {
        return Err(fail(format!(
            "genesis coinbase pays reward {} fees {}, both must be 0",
            cb.reward, cb.fees
        )));
    }
    if cb.note.payload != g.note_payload {
        return Err(fail("the decoded note is not the note that was supplied".into()));
    }
    if header.author_note_len as usize != g.note_payload.len() {
        return Err(fail("author_note_len does not equal the note length".into()));
    }
    if g.block_hash != crypto::header_hash(&g.header_bytes) {
        return Err(fail("the published block hash is not the hash of the header bytes".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> String {
        crypto::address_from_pubkey(&plaine_consensus::blake3::hash(b"genesis recipient"))
    }

    fn input_text(chain_id: &str) -> String {
        format!(
            "# plaine genesis input, v1\n\
             format            = 1\n\
             chain_id          = {chain_id}\n\
             version           = 0x20000000\n\
             time              = 1765432100\n\
             bits              = 0x1f00ffff\n\
             prev_hash         = {zeros}\n\
             ext_root          = {zeros}\n\
             nonce             = 0\n\
             coinbase_to       = {addr}\n\
             note_encoding     = 01\n\
             note_text_file    = genesis-note.txt\n\
             author_pubkey     = {k}\n\
             checkpoint_pubkey = {k2}\n",
            zeros = "0".repeat(64),
            addr = address(),
            k = plaine_consensus::hex::encode(&plaine_consensus::blake3::hash(b"author")),
            k2 = plaine_consensus::hex::encode(&plaine_consensus::blake3::hash(b"checkpoint")),
        )
    }

    #[test]
    fn input_parses_and_comments_are_ignored() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        assert_eq!(i.format, 1);
        assert_eq!(i.chain_id, [0x50, 0x4c, 0x4e, 0x45]);
        assert_eq!(i.version, 0x2000_0000);
        assert_eq!(i.bits, 0x1f00_ffff);
        assert_eq!(i.note_encoding, 0x01);
    }

    #[test]
    fn input_parser_is_strict() {
        let base = input_text("504c4e45");
        assert!(parse_input(&base.replace("nonce             = 0\n", "")).is_err(), "missing key");
        assert!(parse_input(&format!("{base}nonce = 1\n")).is_err(), "duplicate key");
        assert!(parse_input(&format!("{base}extra = 1\n")).is_err(), "unknown key");
        assert!(parse_input(&base.replace("time              = 1765432100", "time =")).is_err(), "empty value");
        assert!(parse_input(&base.replace("format            = 1", "format            = 2")).is_err());
        assert!(parse_input(&base.replace("chain_id          = 504c4e45", "chain_id          = 504c")).is_err());
    }

    #[test]
    fn genesis_is_accepted_by_consensus() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        let note = b"Plaine genesis. The Times 03/Jan/2009 Chancellor on brink";
        let g = build(&i, note).unwrap();
        verify(&g).expect("consensus must accept the genesis block");
        assert_eq!(g.header_bytes.len(), 132);
        assert_eq!(g.coinbase.reward, 0, "no premine");
        assert_eq!(g.header.author_note_len as usize, note.len());
    }

    #[test]
    fn construction_is_deterministic() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        let a = build(&i, b"same note").unwrap();
        let b = build(&i, b"same note").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.block_hash, b.block_hash);
    }

    #[test]
    fn every_input_moves_the_block_hash() {
        let base = input_text("504c4e45");
        let i = parse_input(&base).unwrap();
        let g = build(&i, b"the note").unwrap();

        let t = parse_input(&base.replace("time              = 1765432100", "time              = 1765432101")).unwrap();
        assert_ne!(build(&t, b"the note").unwrap().block_hash, g.block_hash, "time");

        let n = build(&i, b"the notf").unwrap();
        assert_ne!(n.block_hash, g.block_hash, "one note byte");

        let nl = build(&i, b"the note\n").unwrap();
        assert_ne!(nl.block_hash, g.block_hash, "trailing newline");
        assert_eq!(nl.header.author_note_len, 9);

        let b = parse_input(&base.replace("bits              = 0x1f00ffff", "bits              = 0x1f00fffe")).unwrap();
        let err = build(&b, b"the note").unwrap_err();
        assert!(err.to_string().contains("bits"), "{err}");
    }

    #[test]
    fn mainnet_refusals_each_name_their_reason() {
        let placeholder_chain = parse_input(&input_text("00000000")).unwrap();
        let err = check_launch_refusals(&placeholder_chain, b"real note").unwrap_err();
        assert!(err.to_string().contains("chain_id"), "{err}");
        assert!(err.to_string().contains("placeholder"), "{err}");

        let wrong = parse_input(&input_text("504c4e46")).unwrap();
        let err = check_launch_refusals(&wrong, b"real note").unwrap_err();
        assert!(err.to_string().contains("504c4e46"), "{err}");
        assert!(err.to_string().contains("504c4e45"), "must name the expected value: {err}");

        let good = parse_input(&input_text("504c4e45")).unwrap();
        let err = check_launch_refusals(&good, b"PLACEHOLDER - replace me").unwrap_err();
        assert!(err.to_string().contains("PLACEHOLDER"), "{err}");

        assert!(err.to_string().contains(MAINNET_GENESIS_NOTE), "{err}");

        assert!(check_launch_refusals(&good, b"").is_err(), "empty note");

        let r = check_launch_refusals(&good, MAINNET_GENESIS_NOTE.as_bytes());
        if CAN_VERIFY_POW {
            assert!(r.is_ok());
        } else {
            assert!(r.unwrap_err().to_string().contains("`pow` feature"));
        }
    }

    #[test]
    fn genesis_requires_the_pow_feature() {
        let main = parse_input(&input_text("504c4e45")).unwrap();
        let note = MAINNET_GENESIS_NOTE.as_bytes();
        if CAN_VERIFY_POW {
            assert!(check_launch_refusals(&main, note).is_ok());
        } else {
            let err = check_launch_refusals(&main, note).unwrap_err();
            assert!(err.to_string().contains("`pow` feature"), "must name the feature: {err}");
            assert!(err.to_string().contains("nonce"), "must name what is unchecked: {err}");
            assert!(
                err.to_string().contains("height-0 exemption")
                    || err.to_string().contains("no height-0"),
                "must state the decision, not just the limitation: {err}"
            );
        }
    }

    #[test]
    fn mainnet_note_must_be_the_frozen_bytes() {
        let main = parse_input(&input_text("504c4e45")).unwrap();
        let frozen = MAINNET_GENESIS_NOTE.as_bytes();

        for wrong in [
            format!("{MAINNET_GENESIS_NOTE}\n"),
            format!(" {MAINNET_GENESIS_NOTE}"),
            MAINNET_GENESIS_NOTE.replace("ground.", "ground"),
            MAINNET_GENESIS_NOTE.to_uppercase(),
            "We were told the altitude. We never saw the earth.".to_string(),
            "The Times 03/Jan/2009 Chancellor on brink of second bailout".to_string(),
        ] {
            let err = check_launch_refusals(&main, wrong.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("SPEC") && err.contains(MAINNET_GENESIS_NOTE),
                "a note of {wrong:?} must be refused naming the frozen string, got: {err}"
            );
        }

        let bad_enc = parse_input(
            &input_text("504c4e45").replace("note_encoding     = 01", "note_encoding     = 00"),
        )
        .unwrap();
        let err = check_launch_refusals(&bad_enc, frozen).unwrap_err().to_string();
        assert!(err.contains("note_encoding"), "{err}");

        let r = check_launch_refusals(&main, frozen);
        if CAN_VERIFY_POW {
            assert!(r.is_ok(), "{:?}", r.err());
        } else {
            assert!(r.unwrap_err().to_string().contains("`pow` feature"));
        }
    }

    #[test]
    fn the_frozen_note_is_51_ascii_bytes() {
        assert_eq!(MAINNET_GENESIS_NOTE.len(), 51);
        assert!(MAINNET_GENESIS_NOTE.is_ascii());
        assert!(!MAINNET_GENESIS_NOTE.contains('\n'));
        assert_eq!(MAINNET_GENESIS_NOTE_ENCODING, 0x01);
    }

    #[test]
    fn genesis_input_with_wrong_bits_is_refused() {
        for (bad, why) in [
            (0x1f00_fffeu32, "one off the frozen value"),
            (0x2000_ffff, "decodes above POW_LIMIT"),
            (0x1d00_ffff, "bitcoin's genesis bits, far too hard"),
            (0x0000_0000, "zero mantissa: target 0, unsatisfiable"),
            (0x0180_0001, "negative encoding"),
            (0x2300_0001, "overflows 256 bits"),
        ] {
            let err = check_bits(bad).unwrap_err();
            assert!(err.to_string().contains("bits"), "{why}: {err}");

            let text = input_text("504c4e45")
                .replace("bits              = 0x1f00ffff", &format!("bits              = 0x{bad:08x}"));
            let i = parse_input(&text).unwrap();
            assert!(build(&i, b"the note").is_err(), "{why} must fail build");
        }

        let t = check_bits(GENESIS_BITS).unwrap();
        assert!(!t.is_zero() && t <= POW_LIMIT);
        assert_eq!(t, Target::from_compact(0x1f00_ffff).unwrap());
    }

    #[test]
    fn the_fixtures_use_the_frozen_constants() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        assert_eq!(i.chain_id, CHAIN_ID);
        assert_eq!(i.bits, GENESIS_BITS);
        assert_eq!(GENESIS_BITS, 0x1f00_ffff);
    }

    #[test]
    fn over_long_note_refused_at_coinbase_limit() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        assert!(build(&i, &[0x41u8; 256]).is_ok(), "256 is the limit");
        let err = build(&i, &[0x41u8; 257]).unwrap_err();
        assert!(err.to_string().contains("256"), "{err}");
        assert!(err.to_string().contains("not the 1024"), "{err}");
    }

    #[test]
    fn verify_catches_every_tamper() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        let g = build(&i, b"the note").unwrap();
        verify(&g).unwrap();

        for (field, name) in ["height", "prev_hash", "ext_root", "tx_root", "author_note_len", "version_top_bits"]
            .into_iter()
            .enumerate()
        {
            let mut t = g.clone();
            match field {
                0 => t.header.height = 1,
                1 => t.header.prev_hash[0] ^= 1,
                2 => t.header.ext_root[0] ^= 1,
                3 => t.header.tx_root[0] ^= 1,
                4 => t.header.author_note_len += 1,
                _ => t.header.version ^= 0x2000_0000,
            }

            t.header_bytes = t.header.encode();
            t.block_hash = t.header.hash();
            assert!(verify(&t).is_err(), "{name} tamper must be caught");
        }
    }

    #[test]
    fn verify_catches_bytes_mismatching_header() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        let g = build(&i, b"the note").unwrap();

        for byte in 0..g.header_bytes.len() {
            let mut t = g.clone();
            t.header_bytes[byte] ^= 0x01;
            assert!(
                verify(&t).is_err(),
                "a flipped bit at header byte {byte} must be caught"
            );
        }

        let mut t = g.clone();
        t.block_hash[0] ^= 0x01;
        let err = verify(&t).unwrap_err();
        assert!(err.to_string().contains("block hash"), "{err}");
    }

    #[test]
    fn verify_catches_body_mismatching_header() {
        let i = parse_input(&input_text("504c4e45")).unwrap();
        let g = build(&i, b"the note").unwrap();
        let mut t = g.clone();
        let last = t.body.len() - 1;
        t.body[last] ^= 0x01;
        assert!(verify(&t).is_err());
    }
}
