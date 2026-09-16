use plaine_consensus::constants::Network;
use plaine_consensus::crypto::{self, SigError};
use plaine_consensus::ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use plaine_consensus::hex;

const VECTOR_MESSAGE: &[u8] = b"plaine adversary";

const SMALL_ORDER_VECTORS: [(&str, &str, u8); 9] = [
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        0,
    ),
    (
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0100000000000000000000000000000000000000000000000000000000000000",
        0,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        0,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        0,
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
    ),
    (
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
    ),
    (
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
    ),
    (
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        0,
    ),
    (
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        0,
    ),
];

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

fn sig_bytes(r: &str, s: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h32(r));
    out[32] = s;
    out
}

#[test]
fn small_order_vectors_are_refused() {
    let msg = VECTOR_MESSAGE;
    for (i, (a, r, s)) in SMALL_ORDER_VECTORS.iter().enumerate() {
        let pk = h32(a);
        let sig = sig_bytes(r, *s);

        assert_eq!(
            crypto::verify_signature(&pk, msg, &sig),
            Err(SigError::InvalidSignature),
            "vector {i}: consensus accepted a small-order signature"
        );

        let vk = VerifyingKey::from_bytes(&pk).expect("vector A is a curve point");
        let s = Signature::from_bytes(&sig);
        assert!(
            vk.verify(msg, &s).is_ok(),
            "vector {i} must verify under lax, or it cannot tell strict from lax"
        );
    }
}

#[test]
fn identity_key_verifies_under_lax() {
    let (a, r, s) = SMALL_ORDER_VECTORS[0];
    let pk = h32(a);
    let sig = sig_bytes(r, s);
    let vk = VerifyingKey::from_bytes(&pk).expect("the identity point decompresses");
    let parsed = Signature::from_bytes(&sig);

    for msg in [
        b"".as_slice(),
        b"pay alice 1 PLNE".as_slice(),
        b"pay mallory 1000000 PLNE".as_slice(),
        &crypto::signing_message(Network::Main, &pk, &[0x11; 20], u128::MAX, 1, 0),
    ] {
        assert!(
            vk.verify(msg, &parsed).is_ok(),
            "premise: lax accepts this signature for every message"
        );
        assert_eq!(
            crypto::verify_signature(&pk, msg, &sig),
            Err(SigError::InvalidSignature),
            "consensus must refuse it for every message"
        );
    }

    let addr = crypto::address_from_pubkey(&pk);
    assert!(addr.starts_with("plne1"), "the small-order key has an ordinary address: {addr}");
}

#[test]
fn strict_rejects_s_plus_l() {
    const L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let pk = sk.verifying_key().to_bytes();
    let msg = b"s plus L";
    let good = sk.sign(msg).to_bytes();
    assert_eq!(crypto::verify_signature(&pk, msg, &good), Ok(()));

    let mut mall = good;
    let mut carry = 0u16;
    for (i, l) in L_LE.iter().enumerate() {
        let sum = mall[32 + i] as u16 + *l as u16 + carry;
        mall[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "s + L fits in 256 bits");
    assert_ne!(mall, good);

    assert_eq!(crypto::verify_signature(&pk, msg, &mall), Err(SigError::InvalidSignature));

    let vk = VerifyingKey::from_bytes(&pk).expect("real key");
    assert!(
        vk.verify(msg, &Signature::from_bytes(&mall)).is_err(),
        "lax must reject s+L too, or this vector proves nothing about strict"
    );
}

#[test]
fn ordinary_sig_verifies() {
    let sk = SigningKey::from_bytes(&[0x07; 32]);
    let pk = sk.verifying_key().to_bytes();
    let msg = crypto::signing_message(Network::Main, &pk, &[0x22; 20], 5, 1, 0);
    let sig = sk.sign(&msg).to_bytes();
    assert_eq!(crypto::verify_signature(&pk, &msg, &sig), Ok(()));

    let other = crypto::signing_message(Network::Main, &pk, &[0x22; 20], 6, 1, 0);
    assert_eq!(crypto::verify_signature(&pk, &other, &sig), Err(SigError::InvalidSignature));
}
