use crate::codec::{AnnouncementTx, CodecError, TransferTx, HASH_BYTES, PUBKEY_BYTES, SIG_BYTES};
use crate::constants::{
    ADDRESS_HRP, ADDRESS_PAYLOAD_BYTES, ANNOUNCEMENT_MAX_PAYLOAD_BYTES,
    ANNOUNCEMENT_MIN_PAYLOAD_BYTES, DOMAIN_MERKLE_LEAF, DOMAIN_MERKLE_NODE, DOMAIN_NOTE_SIGN,
    DOMAIN_TXID, DOMAIN_TX_SIGN, HEADER_BYTES, MERKLE_FLAG_DUP, MERKLE_FLAG_PAIR, Network,
};
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    NotBech32m,
    WrongHrp,
    WrongPayloadLength { got: usize },
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressError::NotBech32m => write!(f, "not a valid bech32m string"),
            AddressError::WrongHrp => write!(f, "wrong HRP, expected \"{ADDRESS_HRP}\""),
            AddressError::WrongPayloadLength { got } => {
                write!(f, "address payload is {got} bytes, expected {ADDRESS_PAYLOAD_BYTES}")
            }
        }
    }
}

impl std::error::Error for AddressError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    InvalidPubkey,
    InvalidSignature,
}

impl core::fmt::Display for SigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SigError::InvalidPubkey => write!(f, "invalid ed25519 public key"),
            SigError::InvalidSignature => write!(f, "ed25519 strict verification failed"),
        }
    }
}

impl std::error::Error for SigError {}

pub fn header_hash(header_bytes: &[u8; HEADER_BYTES]) -> [u8; HASH_BYTES] {
    crate::blake3::hash(header_bytes)
}

pub fn txid(canonical_unsigned: &[u8]) -> [u8; HASH_BYTES] {
    let mut h = crate::blake3::Hasher::new();
    h.update(DOMAIN_TXID);
    h.update(canonical_unsigned);
    h.finalize()
}

pub(crate) fn signing_message_with_chain_id(
    chain_id: &[u8; 4],
    from_pub: &[u8; PUBKEY_BYTES],
    to: &[u8; ADDRESS_PAYLOAD_BYTES],
    amount: u128,
    fee: u128,
    nonce: u64,
) -> [u8; HASH_BYTES] {
    let mut h = crate::blake3::Hasher::new();
    h.update(DOMAIN_TX_SIGN);
    h.update(chain_id);
    h.update(from_pub);
    h.update(to);
    h.update(&amount.to_le_bytes());
    h.update(&fee.to_le_bytes());
    h.update(&nonce.to_le_bytes());
    h.finalize()
}

pub fn signing_message(
    network: Network,
    from_pub: &[u8; PUBKEY_BYTES],
    to: &[u8; ADDRESS_PAYLOAD_BYTES],
    amount: u128,
    fee: u128,
    nonce: u64,
) -> [u8; HASH_BYTES] {
    signing_message_with_chain_id(&network.chain_id(), from_pub, to, amount, fee, nonce)
}

pub fn transfer_signing_message(network: Network, tx: &TransferTx) -> [u8; HASH_BYTES] {
    signing_message(network, &tx.from_pub, &tx.to, tx.amount, tx.fee, tx.nonce)
}

pub fn merkle_leaf(tx_bytes: &[u8]) -> [u8; HASH_BYTES] {
    let mut h = crate::blake3::Hasher::new();
    h.update(DOMAIN_MERKLE_LEAF);
    h.update(tx_bytes);
    h.finalize()
}

pub fn merkle_node(
    left: &[u8; HASH_BYTES],
    right: &[u8; HASH_BYTES],
    duplicated: bool,
) -> [u8; HASH_BYTES] {
    let mut h = crate::blake3::Hasher::new();
    h.update(DOMAIN_MERKLE_NODE);
    h.update(&[if duplicated { MERKLE_FLAG_DUP } else { MERKLE_FLAG_PAIR }]);
    h.update(left);
    h.update(right);
    h.finalize()
}

pub(crate) fn announcement_signing_message_explicit_length(
    chain_id: &[u8; 4],
    from_pub: &[u8; PUBKEY_BYTES],
    fee: u128,
    nonce: u64,
    encoding: u8,
    length: u16,
    payload: &[u8],
) -> [u8; HASH_BYTES] {
    let mut h = crate::blake3::Hasher::new();
    h.update(DOMAIN_NOTE_SIGN);
    h.update(chain_id);
    h.update(from_pub);
    h.update(&fee.to_le_bytes());
    h.update(&nonce.to_le_bytes());
    h.update(&[encoding]);
    // Length is committed explicitly as an LE u16, not left implicit in
    // payload.len(): a decoder that trusts the field over the actual bytes must
    // still land on a different message for a mismatched pair.
    h.update(&length.to_le_bytes());
    h.update(payload);
    h.finalize()
}

pub(crate) fn announcement_signing_message_with_chain_id(
    chain_id: &[u8; 4],
    from_pub: &[u8; PUBKEY_BYTES],
    fee: u128,
    nonce: u64,
    encoding: u8,
    payload: &[u8],
) -> Result<[u8; HASH_BYTES], CodecError> {
    let len = payload.len();
    if !(ANNOUNCEMENT_MIN_PAYLOAD_BYTES..=ANNOUNCEMENT_MAX_PAYLOAD_BYTES).contains(&len) {
        return Err(CodecError::AnnouncementLength { len });
    }
    Ok(announcement_signing_message_explicit_length(
        chain_id, from_pub, fee, nonce, encoding, len as u16, payload,
    ))
}

pub fn announcement_signing_message(
    network: Network,
    from_pub: &[u8; PUBKEY_BYTES],
    fee: u128,
    nonce: u64,
    encoding: u8,
    payload: &[u8],
) -> Result<[u8; HASH_BYTES], CodecError> {
    announcement_signing_message_with_chain_id(
        &network.chain_id(),
        from_pub,
        fee,
        nonce,
        encoding,
        payload,
    )
}

pub fn announcement_message_of(
    network: Network,
    tx: &AnnouncementTx,
) -> Result<[u8; HASH_BYTES], CodecError> {
    announcement_signing_message(network, &tx.from_pub, tx.fee, tx.nonce, tx.encoding, &tx.payload)
}

pub fn verify_announcement_signature(
    network: Network,
    tx: &AnnouncementTx,
) -> Result<(), SigError> {
    let msg = announcement_message_of(network, tx).map_err(|_| SigError::InvalidSignature)?;
    verify_signature(&tx.from_pub, &msg, &tx.sig)
}

// first 20 bytes of blake3(pubkey), later bech32m-encoded
pub fn address_payload(pubkey: &[u8; PUBKEY_BYTES]) -> [u8; ADDRESS_PAYLOAD_BYTES] {
    let digest = crate::blake3::hash(pubkey);
    let mut p = [0u8; ADDRESS_PAYLOAD_BYTES];
    p.copy_from_slice(&digest[..ADDRESS_PAYLOAD_BYTES]);
    p
}

pub fn encode_address(payload: &[u8; ADDRESS_PAYLOAD_BYTES]) -> String {
    crate::bech32m::encode_bytes(ADDRESS_HRP, payload)
        .expect("static HRP and 20-byte payload always encode")
}

pub fn address_from_pubkey(pubkey: &[u8; PUBKEY_BYTES]) -> String {
    encode_address(&address_payload(pubkey))
}

pub fn decode_address(s: &str) -> Result<[u8; ADDRESS_PAYLOAD_BYTES], AddressError> {
    let (hrp, bytes) =
        crate::bech32m::decode_bytes(s).map_err(|_| AddressError::NotBech32m)?;
    if hrp != ADDRESS_HRP {
        return Err(AddressError::WrongHrp);
    }
    let got = bytes.len();
    let payload: [u8; ADDRESS_PAYLOAD_BYTES] =
        bytes.try_into().map_err(|_| AddressError::WrongPayloadLength { got })?;
    Ok(payload)
}

pub fn verify_signature(
    pubkey: &[u8; PUBKEY_BYTES],
    message: &[u8],
    sig: &[u8; SIG_BYTES],
) -> Result<(), SigError> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| SigError::InvalidPubkey)?;
    let sig = Signature::from_bytes(sig);
    // verify_strict, never verify: rejecting non-canonical S and small-order
    // keys leaves each tx exactly one valid signature, hence one txid.
    vk.verify_strict(message, &sig).map_err(|_| SigError::InvalidSignature)
}

pub fn verify_transfer_signature(network: Network, tx: &TransferTx) -> Result<(), SigError> {
    verify_signature(&tx.from_pub, &transfer_signing_message(network, tx), &tx.sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CHAIN_ID, TICKER};
    use ed25519_dalek::{Signer, SigningKey};

    const FOREIGN_CHAIN_ID: [u8; 4] = [CHAIN_ID[0], CHAIN_ID[1], CHAIN_ID[2], CHAIN_ID[3] ^ 0x11];

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn signed_transfer(chain_id: &[u8; 4]) -> TransferTx {
        let sk = test_signing_key();
        let from_pub = sk.verifying_key().to_bytes();
        let to = address_payload(&[0x24; 32]);
        let (amount, fee, nonce) = (1_000_000_000_000_000_000u128, 1u128, 7u64);
        let msg = signing_message_with_chain_id(chain_id, &from_pub, &to, amount, fee, nonce);
        let sig = sk.sign(&msg).to_bytes();
        TransferTx { from_pub, to, amount, fee, nonce, sig }
    }

    #[test]
    fn address_roundtrip() {
        let pubkey = [0x42u8; 32];
        let payload = address_payload(&pubkey);
        assert_eq!(payload, crate::blake3::hash(&pubkey)[..20]);
        let addr = address_from_pubkey(&pubkey);
        assert!(addr.starts_with("plne1"), "got {addr}");
        assert_eq!(addr.len(), 43, "SPEC 1: encoded address is 43 chars");
        assert_eq!(decode_address(&addr).unwrap(), payload);

        assert_eq!(decode_address(&addr.to_uppercase()).unwrap(), payload);
    }

    #[test]
    fn address_rejects_plain_bech32_checksum() {
        let payload = address_payload(&[0x42u8; 32]);
        let non_m = crate::bech32m::encode_fes_bech32(
            ADDRESS_HRP,
            &crate::bech32m::convert_8_to_5(&payload),
        )
        .unwrap();
        assert_eq!(non_m, "plne1hnl3rkhhmwuv0zdhhnzwg55cqstxd7f08d9fp2");
        assert_eq!(decode_address(&non_m), Err(AddressError::NotBech32m));
    }

    #[test]
    fn address_rejects_wrong_hrp() {
        let payload = address_payload(&[0x42u8; 32]);
        let wrong = crate::bech32m::encode_bytes("test", &payload).unwrap();
        assert_eq!(decode_address(&wrong), Err(AddressError::WrongHrp));

        let near = crate::bech32m::encode_bytes("plnee", &payload).unwrap();
        assert_eq!(decode_address(&near), Err(AddressError::WrongHrp));
    }

    #[test]
    fn address_rejects_wrong_payload_length() {
        for len in [19usize, 21, 32] {
            let s = crate::bech32m::encode_bytes(ADDRESS_HRP, &vec![0x55u8; len]).unwrap();
            assert_eq!(decode_address(&s), Err(AddressError::WrongPayloadLength { got: len }));
        }
    }

    #[test]
    fn address_rejects_corruption() {
        let addr = address_from_pubkey(&[0x42u8; 32]);

        let mut chars: Vec<char> = addr.chars().collect();
        let i = addr.len() - 10;
        chars[i] = if chars[i] == 'q' { 'p' } else { 'q' };
        let corrupt: String = chars.into_iter().collect();
        assert_eq!(decode_address(&corrupt), Err(AddressError::NotBech32m));

        let mixed = format!("plne1{}", addr[5..].to_uppercase());
        assert_eq!(decode_address(&mixed), Err(AddressError::NotBech32m));
        assert_eq!(decode_address(""), Err(AddressError::NotBech32m));
        assert_eq!(decode_address("plne1"), Err(AddressError::NotBech32m));
    }

    #[test]
    fn tx_dies_under_foreign_chain_id() {
        let tx = signed_transfer(&CHAIN_ID);
        assert_eq!(verify_transfer_signature(Network::Main, &tx), Ok(()));

        assert_eq!(CHAIN_ID[..3], FOREIGN_CHAIN_ID[..3]);
        assert_ne!(CHAIN_ID[3], FOREIGN_CHAIN_ID[3]);
        let foreign = signed_transfer(&FOREIGN_CHAIN_ID);
        assert_eq!(foreign.encode_unsigned(), tx.encode_unsigned(), "same tx body");
        assert_ne!(foreign.sig, tx.sig, "different chain id, different signature");
        assert_eq!(
            verify_transfer_signature(Network::Main, &foreign),
            Err(SigError::InvalidSignature),
            "a transfer signed under a foreign chain id must not verify"
        );

        let msg_foreign = signing_message_with_chain_id(
            &FOREIGN_CHAIN_ID, &tx.from_pub, &tx.to, tx.amount, tx.fee, tx.nonce,
        );
        assert_eq!(
            verify_signature(&tx.from_pub, &msg_foreign, &tx.sig),
            Err(SigError::InvalidSignature)
        );

        for other_chain in [
            { let mut c = CHAIN_ID; c[0] ^= 0x01; c },
            { let mut c = CHAIN_ID; c[3] ^= 0x80; c },
            [0u8; 4],
        ] {
            let foreign = signed_transfer(&other_chain);
            assert_eq!(foreign.encode_unsigned(), tx.encode_unsigned(), "same tx body");
            assert_eq!(
                verify_transfer_signature(Network::Main, &foreign),
                Err(SigError::InvalidSignature),
                "chain id {other_chain:02x?}"
            );
        }
    }

    #[test]
    fn announcement_dies_under_foreign_chain_id() {
        let sk = test_signing_key();
        let from_pub = sk.verifying_key().to_bytes();
        let (fee, nonce, enc, payload) = (5u128, 3u64, 0x01u8, b"launch".as_slice());

        let msg_main =
            announcement_signing_message_with_chain_id(&CHAIN_ID, &from_pub, fee, nonce, enc, payload)
                .unwrap();
        let msg_foreign = announcement_signing_message_with_chain_id(
            &FOREIGN_CHAIN_ID, &from_pub, fee, nonce, enc, payload,
        )
        .unwrap();
        assert_ne!(msg_main, msg_foreign, "chain id must change the message");

        let tx = AnnouncementTx {
            from_pub,
            fee,
            nonce,
            encoding: enc,
            payload: payload.to_vec(),
            sig: sk.sign(&msg_main).to_bytes(),
        };
        assert_eq!(verify_announcement_signature(Network::Main, &tx), Ok(()));

        let mut foreign = tx.clone();
        foreign.sig = sk.sign(&msg_foreign).to_bytes();
        assert_eq!(
            verify_announcement_signature(Network::Main, &foreign),
            Err(SigError::InvalidSignature)
        );
    }

    #[test]
    fn chain_id_is_ascii_plne() {
        assert_eq!(&CHAIN_ID, b"PLNE");
        assert_eq!(CHAIN_ID, [0x50, 0x4C, 0x4E, 0x45]);

        assert_eq!(core::str::from_utf8(&CHAIN_ID).unwrap(), TICKER);
        assert_ne!(CHAIN_ID, [0u8; 4], "the all-zero placeholder is dead");
    }

    #[test]
    fn chain_id_in_signing_preimage() {
        let from_pub = [0xABu8; PUBKEY_BYTES];
        let to = [0xCDu8; ADDRESS_PAYLOAD_BYTES];
        let (amount, fee, nonce) = (12u128, 34u128, 56u64);

        let mut pre = Vec::new();
        pre.extend_from_slice(DOMAIN_TX_SIGN);
        pre.extend_from_slice(&CHAIN_ID);
        pre.extend_from_slice(&from_pub);
        pre.extend_from_slice(&to);
        pre.extend_from_slice(&amount.to_le_bytes());
        pre.extend_from_slice(&fee.to_le_bytes());
        pre.extend_from_slice(&nonce.to_le_bytes());
        assert_eq!(DOMAIN_TX_SIGN.len(), 10);
        assert_eq!(&pre[10..14], &CHAIN_ID);
        assert_eq!(&pre[..10], b"PLNE-tx-v1");
        assert_eq!(
            crate::blake3::hash(&pre),
            signing_message(Network::Main, &from_pub, &to, amount, fee, nonce),
            "hand-built preimage must match signing_message"
        );

        let payload = b"note".as_slice();
        let mut npre = Vec::new();
        npre.extend_from_slice(DOMAIN_NOTE_SIGN);
        npre.extend_from_slice(&CHAIN_ID);
        npre.extend_from_slice(&from_pub);
        npre.extend_from_slice(&fee.to_le_bytes());
        npre.extend_from_slice(&nonce.to_le_bytes());
        npre.push(0x01);
        npre.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        npre.extend_from_slice(payload);
        assert_eq!(DOMAIN_NOTE_SIGN.len(), 12);
        assert_eq!(&npre[12..16], &CHAIN_ID);
        assert_eq!(
            crate::blake3::hash(&npre),
            announcement_signing_message(Network::Main, &from_pub, fee, nonce, 0x01, payload).unwrap()
        );
    }

    fn vector_key(label: &[u8]) -> SigningKey {
        SigningKey::from_bytes(&crate::blake3::hash(label))
    }

    #[test]
    #[ignore = "emitter, not a check: run with --ignored --nocapture to regenerate"]
    fn emit_signature_vectors() {
        let sk = vector_key(b"plaine vector signer 1");
        let from_pub = sk.verifying_key().to_bytes();
        let to = address_payload(&crate::blake3::hash(b"plaine vector recipient 1"));
        let (amount, fee, nonce) = (1_234_567_890_123_456_789u128, 1u128, 42u64);
        println!("CHAIN_ID          {}", crate::hex::encode(&CHAIN_ID));
        println!("from_pub          {}", crate::hex::encode(&from_pub));
        println!("to                {}", crate::hex::encode(&to));
        let msg = signing_message(Network::Main, &from_pub, &to, amount, fee, nonce);
        println!("transfer msg      {}", crate::hex::encode(&msg));
        println!("transfer sig      {}", crate::hex::encode(&sk.sign(&msg).to_bytes()));
        let tx = TransferTx { from_pub, to, amount, fee, nonce, sig: sk.sign(&msg).to_bytes() };
        println!("transfer txid     {}", crate::hex::encode(&tx.txid()));

        let payload = b"Plaine launch announcement, vector 1".as_slice();
        let nmsg = announcement_signing_message(Network::Main, &from_pub, 7, 3, 0x01, payload).unwrap();
        println!("note msg          {}", crate::hex::encode(&nmsg));
        println!("note sig          {}", crate::hex::encode(&sk.sign(&nmsg).to_bytes()));
        let ann = AnnouncementTx {
            from_pub, fee: 7, nonce: 3, encoding: 0x01,
            payload: payload.to_vec(), sig: sk.sign(&nmsg).to_bytes(),
        };
        println!("note txid         {}", crate::hex::encode(&ann.txid().unwrap()));

        let dsep =
            announcement_signing_message(Network::Main, &[0x42u8; 32], 7, 9, 0x01, &[0x55u8; 31])
                .unwrap();
        println!("domain-sep note   {}", crate::hex::encode(&dsep));
        for n in [949usize, 950, 1024] {
            let m =
                announcement_signing_message(Network::Main, &[0x42u8; 32], 1, 0, 0x01, &vec![0x5Au8; n])
                    .unwrap();
            println!("chunk n={n:<4}      {}", crate::hex::encode(&m));
        }
    }

    const V1_FROM_PUB: &str = "24cfa2235ff129e9f72870c121d6b05a3ff6accdaae62c88b3501eff87504acd";
    const V1_TO: &str = "4412c35cce0313fdb6ff8a5c18658da12084dd83";
    const V1_TX_MSG: &str = "05b0e24d34488914cee716cd0591b0e440b183f16b12d546b2e9adb787584b23";
    const V1_TX_SIG: &str = "d4181c33952a0eba296d5797d603cc30cd8a6ee6362c62375f8db26b466dc05e\
                             16385c0b137a4cb95351c1629b5a3aba8777821f250d60b31bdfee05a9325c06";
    const V1_TXID: &str = "e05413462c4ea7751145951187428ff4b7deedc206bdc3f60f6bf87093c68465";
    const V1_NOTE_MSG: &str = "549ca364389664bab79efacc75b66930738c29ab8f7b272f64de3dcc791cdbbe";
    const V1_NOTE_SIG: &str = "652ad2cb0f8c464dbd2968379f232e61a9deb1fc1e52f317598e038de449d0c0\
                               dc03609919d954db99910910c2ab237de99f727db50f3c9243c782eef57d270e";
    const V1_NOTE_TXID: &str = "1e172d58d62bd66023e921744b3bf8ad4452f1eed24c02f92085aafb6c17a0ef";

    fn vectors_were_generated_under_plne() {
        assert_eq!(
            &CHAIN_ID, b"PLNE",
            "these vectors were generated under CHAIN_ID = PLNE. If this \
             line fails, the vectors below are void, not wrong - do not regenerate \
             them to match a new chain id without deciding that the chain id changed."
        );
    }

    #[test]
    fn transfer_signing_vectors() {
        vectors_were_generated_under_plne();
        let sk = vector_key(b"plaine vector signer 1");
        let from_pub = sk.verifying_key().to_bytes();
        let to = address_payload(&crate::blake3::hash(b"plaine vector recipient 1"));
        let (amount, fee, nonce) = (1_234_567_890_123_456_789u128, 1u128, 42u64);

        assert_eq!(crate::hex::encode(&from_pub), V1_FROM_PUB);
        assert_eq!(crate::hex::encode(&to), V1_TO);

        let msg = signing_message(Network::Main, &from_pub, &to, amount, fee, nonce);
        assert_eq!(crate::hex::encode(&msg), V1_TX_MSG);

        let sig = sk.sign(&msg).to_bytes();
        assert_eq!(crate::hex::encode(&sig), V1_TX_SIG);

        let tx = TransferTx { from_pub, to, amount, fee, nonce, sig };
        assert_eq!(crate::hex::encode(&tx.txid()), V1_TXID);
        assert_eq!(verify_transfer_signature(Network::Main, &tx), Ok(()));

        let msg_foreign =
            signing_message_with_chain_id(&FOREIGN_CHAIN_ID, &from_pub, &to, amount, fee, nonce);
        assert_ne!(msg_foreign, msg);
        assert_eq!(
            verify_signature(&from_pub, &msg_foreign, &sig),
            Err(SigError::InvalidSignature)
        );
    }

    #[test]
    fn note_signing_vectors() {
        vectors_were_generated_under_plne();
        let sk = vector_key(b"plaine vector signer 1");
        let from_pub = sk.verifying_key().to_bytes();
        let payload = b"Plaine launch announcement, vector 1".as_slice();
        let (fee, nonce, encoding) = (7u128, 3u64, 0x01u8);

        let msg = announcement_signing_message(Network::Main, &from_pub, fee, nonce, encoding, payload)
            .unwrap();
        assert_eq!(crate::hex::encode(&msg), V1_NOTE_MSG);

        let sig = sk.sign(&msg).to_bytes();
        assert_eq!(crate::hex::encode(&sig), V1_NOTE_SIG);

        let ann = AnnouncementTx {
            from_pub,
            fee,
            nonce,
            encoding,
            payload: payload.to_vec(),
            sig,
        };
        assert_eq!(crate::hex::encode(&ann.txid().unwrap()), V1_NOTE_TXID);
        assert_eq!(verify_announcement_signature(Network::Main, &ann), Ok(()));

        let msg_foreign = announcement_signing_message_with_chain_id(
            &FOREIGN_CHAIN_ID, &from_pub, fee, nonce, encoding, payload,
        )
        .unwrap();
        assert_ne!(msg_foreign, msg);
        assert_eq!(
            verify_signature(&from_pub, &msg_foreign, &sig),
            Err(SigError::InvalidSignature)
        );
    }

    #[test]
    fn tampered_fields_invalidate_signature() {
        let mut tx = signed_transfer(&CHAIN_ID);
        tx.amount += 1;
        assert_eq!(
            verify_transfer_signature(Network::Main, &tx),
            Err(SigError::InvalidSignature)
        );

        let mut tx = signed_transfer(&CHAIN_ID);
        tx.to[0] ^= 0xFF;
        assert_eq!(
            verify_transfer_signature(Network::Main, &tx),
            Err(SigError::InvalidSignature)
        );

        let mut tx = signed_transfer(&CHAIN_ID);
        tx.sig[0] ^= 0x01;
        assert_eq!(
            verify_transfer_signature(Network::Main, &tx),
            Err(SigError::InvalidSignature)
        );
    }

    #[test]
    fn malleable_sig_rejected() {
        let tx = signed_transfer(&CHAIN_ID);
        assert_eq!(verify_transfer_signature(Network::Main, &tx), Ok(()));

        const L_LE: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut mall = tx;

        let mut carry = 0u16;
        for (i, l) in L_LE.iter().enumerate() {
            let sum = mall.sig[32 + i] as u16 + *l as u16 + carry;
            mall.sig[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + L fits in 256 bits since s < L < 2^253");
        assert_ne!(mall.sig, tx.sig);
        assert_eq!(
            verify_transfer_signature(Network::Main, &mall),
            Err(SigError::InvalidSignature)
        );
    }

    #[test]
    fn invalid_pubkey_rejected() {
        let bad_pub = [0x02; 32];
        let sig = [0u8; 64];
        assert_eq!(verify_signature(&bad_pub, b"msg", &sig), Err(SigError::InvalidPubkey));
    }

    #[test]
    fn tx_and_note_domains_separate() {
        let from_pub = [0x42u8; 32];
        let (fee, nonce) = (7u128, 9u64);

        let payload = vec![0x55u8; 31];
        let note = announcement_signing_message(Network::Main, &from_pub, fee, nonce, 0x01, &payload)
            .unwrap();
        let transfer = signing_message(Network::Main, &from_pub, &[0x55u8; 20], 0, fee, nonce);
        assert_ne!(note, transfer);

        vectors_were_generated_under_plne();
        assert_eq!(
            crate::hex::encode(&note),
            "0636e30805bde6c33833a94bfc03a0c118a5b90154009e05925d9598652f5e5c",
        );
    }

    #[test]
    fn announcement_length_is_le_u16() {
        let from_pub = [0x11u8; 32];
        let payload = vec![0xA5u8; 258];
        let real = announcement_signing_message(Network::Main, &from_pub, 1, 0, 0, &payload).unwrap();

        let swapped = announcement_signing_message_explicit_length(
            &CHAIN_ID, &from_pub, 1, 0, 0, 0x0201, &payload,
        );
        assert_ne!(real, swapped, "the length is hashed as LE, not BE");

        assert_eq!(258u16.to_le_bytes(), [0x02, 0x01]);
    }

    #[test]
    fn out_of_range_payload_no_message() {
        let from_pub = [0x11u8; 32];
        assert_eq!(
            announcement_signing_message(Network::Main, &from_pub, 1, 0, 0, &[]),
            Err(CodecError::AnnouncementLength { len: 0 })
        );
        assert_eq!(
            announcement_signing_message(Network::Main, &from_pub, 1, 0, 0, &vec![0u8; 1025]),
            Err(CodecError::AnnouncementLength { len: 1025 })
        );
    }

    #[test]
    fn announcement_crosses_chunk_boundary() {
        const PREFIX: usize = 75;

        vectors_were_generated_under_plne();
        let from_pub = [0x42u8; 32];
        for (n, want) in [

            (949usize, "bf8a0df46fdf70d33fb23bb492fafcd2386d7ca0b47a34acfb7c5f57626b76f6"),
            (950, "feab942d73698643e103f65c34e008514540eb95592cb36450ca51b4569db8f2"),
            (1024, "48da2ad612c464886a85b1ee08a9c1b74072216f88649787146cbdb746e3bfd2"),
        ] {
            let payload = vec![0x5Au8; n];
            let msg =
                announcement_signing_message(Network::Main, &from_pub, 1, 0, 0x01, &payload).unwrap();
            assert!(PREFIX + n >= 1024, "n = {n} must reach the chunk boundary");
            assert_eq!(crate::hex::encode(&msg), want, "n = {n}");
        }

        assert_eq!(PREFIX + 949, 1024);
    }

    #[test]
    fn merkle_leaf_max_tx_multi_chunk() {
        let tx = vec![0xC3u8; 8192];
        let leaf = merkle_leaf(&tx);
        assert_eq!(crate::hex::encode(&leaf), "7fffea447f561728649ed62bb7422c7d7f12ac1330d8bde1c84f2056f93679b1");
    }

    #[test]
    fn merkle_node_flag_in_preimage() {
        let a = merkle_leaf(b"a");
        let b = merkle_leaf(b"b");
        assert_ne!(merkle_node(&a, &b, false), merkle_node(&a, &b, true));
        assert_ne!(merkle_node(&a, &a, false), merkle_node(&a, &a, true));

        let mut cat = Vec::new();
        cat.extend_from_slice(&a);
        cat.extend_from_slice(&b);
        assert_ne!(merkle_leaf(&cat), merkle_node(&a, &b, false));
    }

    #[test]
    fn txid_ignores_sig() {
        let tx = signed_transfer(&CHAIN_ID);
        let mut resigned = tx;
        resigned.sig = [0xAA; 64];
        assert_eq!(tx.txid(), resigned.txid(), "txid covers the unsigned body only");
        assert_ne!(tx.txid(), [0u8; 32]);

        let unsigned = tx.encode_unsigned();
        assert_ne!(tx.txid(), crate::blake3::hash(&unsigned));

        assert_eq!(
            crate::hex::encode(&tx.txid()),
            "7e8f023022c179694a6e50895480b3bd7e4ddc1585c93d83581cef3c41cef05f"
        );
    }
}
