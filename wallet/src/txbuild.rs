use crate::error::{Result, WalletError};
use crate::secret::Secret32;
use crate::sig;
use plaine_consensus::codec::{AnnouncementTx, TransferTx};
use plaine_consensus::constants::{Network, FEE_FLOOR_MILE};
use plaine_consensus::crypto;
use plaine_consensus::tx;

pub fn check_fee(fee: u128) -> Result<()> {
    if fee < FEE_FLOOR_MILE {
        return Err(WalletError::refused(format!(
            "fee {fee} mile is below the consensus floor of {FEE_FLOOR_MILE} mile"
        )));
    }
    Ok(())
}

pub fn fee_is_at_the_floor(fee: u128) -> bool {
    fee <= FEE_FLOOR_MILE
}

pub fn build_transfer(
    network: Network,
    seed: &Secret32,
    to: &str,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> Result<TransferTx> {
    build_transfer_signed_by(
        network,
        sig::public_key_of(seed),
        &|msg| sig::sign(seed, msg),
        to,
        amount,
        fee,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_transfer_signed_by(
    network: Network,
    from_pub: [u8; 32],
    sign: &dyn Fn(&[u8; 32]) -> [u8; 64],
    to: &str,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> Result<TransferTx> {
    check_fee(fee)?;
    let to = crypto::decode_address(to)
        .map_err(|e| WalletError::format(format!("--to is not a valid Plaine address: {e}")))?;
    amount
        .checked_add(fee)
        .ok_or_else(|| WalletError::usage("amount + fee overflows u128".to_string()))?;

    let msg = crypto::signing_message(network, &from_pub, &to, amount, fee, nonce);
    let sig_bytes = sign(&msg);
    let tx = TransferTx {
        from_pub,
        to,
        amount,
        fee,
        nonce,
        sig: sig_bytes,
    };

    // self-check before returning: a broken signer fails here, not on-chain
    crypto::verify_transfer_signature(network, &tx).map_err(|e| {
        WalletError::crypto(format!(
            "self-verification of the new transfer failed on {network}: {e}"
        ))
    })?;
    let encoded = tx.encode();
    let decoded = TransferTx::decode(&encoded)
        .map_err(|e| WalletError::crypto(format!("the new transfer does not decode: {e}")))?;
    if decoded != tx {
        return Err(WalletError::crypto(
            "the new transfer does not round-trip through its own wire form",
        ));
    }
    Ok(tx)
}

pub fn build_announcement(
    network: Network,
    seed: &Secret32,
    author_pubkey: &[u8; 32],
    payload: &[u8],
    encoding: u8,
    fee: u128,
    nonce: u64,
) -> Result<AnnouncementTx> {
    build_announcement_signed_by(
        network,
        sig::public_key_of(seed),
        &|msg| sig::sign(seed, msg),
        author_pubkey,
        payload,
        encoding,
        fee,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_announcement_signed_by(
    network: Network,
    from_pub: [u8; 32],
    sign: &dyn Fn(&[u8; 32]) -> [u8; 64],
    author_pubkey: &[u8; 32],
    payload: &[u8],
    encoding: u8,
    fee: u128,
    nonce: u64,
) -> Result<AnnouncementTx> {
    check_fee(fee)?;
    if !sig::is_valid_pubkey(author_pubkey) {
        return Err(WalletError::usage(
            "--author-pubkey is not a valid ed25519 public key",
        ));
    }
    if &from_pub != author_pubkey {
        return Err(WalletError::refused(format!(
            "this key is not the author key.\n  signing key: {}\n  --author-pubkey: {}\n\
             SPEC 4.1 rule 1 makes a block carrying an announcement from a non-matching \
             key invalid, so a miner who included this would lose the whole block and your \
             message would never land.",
            plaine_consensus::hex::encode(&from_pub),
            plaine_consensus::hex::encode(author_pubkey)
        )));
    }

    let msg =
        crypto::announcement_signing_message(network, &from_pub, fee, nonce, encoding, payload)
            .map_err(|e| WalletError::format(format!("announcement payload rejected: {e}")))?;
    let sig_bytes = sign(&msg);
    let tx = AnnouncementTx {
        from_pub,
        fee,
        nonce,
        encoding,
        payload: payload.to_vec(),
        sig: sig_bytes,
    };

    tx::check_announcement_stateless(network, &tx, author_pubkey).map_err(|e| {
        WalletError::crypto(format!(
            "self-verification of the new announcement failed on {network}: {e}"
        ))
    })?;
    let encoded = tx
        .encode()
        .map_err(|e| WalletError::crypto(format!("the new announcement does not encode: {e}")))?;
    let decoded = AnnouncementTx::decode(&encoded)
        .map_err(|e| WalletError::crypto(format!("the new announcement does not decode: {e}")))?;
    if decoded != tx {
        return Err(WalletError::crypto(
            "the new announcement does not round-trip through its own wire form",
        ));
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plaine_consensus::constants::CHAIN_ID;

    const MAIN: Network = Network::Main;

    fn seed(tag: &[u8]) -> Secret32 {
        Secret32::from_bytes(plaine_consensus::blake3::hash(tag))
    }

    #[test]
    fn transfer_is_accepted_by_consensus() {
        let sk = seed(b"txbuild transfer");
        let to = crypto::address_from_pubkey(&[0x24u8; 32]);
        let tx = build_transfer(MAIN, &sk, &to, 1_000, 7, 3).unwrap();
        crypto::verify_transfer_signature(MAIN, &tx).unwrap();
        assert_eq!(tx.encode().len(), 157);
        assert_eq!(tx.encode_unsigned().len(), 93);
    }

    #[test]
    fn transfer_refuses_bad_address_and_zero_fee() {
        let sk = seed(b"txbuild refuse");
        let good = crypto::address_from_pubkey(&[0x24u8; 32]);
        assert!(build_transfer(MAIN, &sk, "plne1notanaddress", 1, 1, 0).is_err());

        assert!(build_transfer(MAIN, &sk, &"11".repeat(20), 1, 1, 0).is_err());
        assert!(build_transfer(MAIN, &sk, &good, 1, 0, 0).is_err(), "fee 0");
        assert!(build_transfer(MAIN, &sk, &good, 1, 1, 0).is_ok());
    }

    #[test]
    fn wallet_signs_for_the_one_network() {
        assert_eq!(&CHAIN_ID, b"PLNE");
        let sk = seed(b"txbuild chainid");
        let to = crypto::address_from_pubkey(&[0x24u8; 32]);

        let net = Network::Main;
        let tx = build_transfer(net, &sk, &to, 1, 1, 0).unwrap();
        crypto::verify_transfer_signature(net, &tx).unwrap();

        let author = sig::public_key_of(&sk);
        let ann = build_announcement(net, &sk, &author, b"x", 0x01, 1, 0).unwrap();
        tx::check_announcement_stateless(net, &ann, &author).unwrap();

        let other = build_transfer(net, &sk, &to, 2, 1, 0).unwrap();
        assert_ne!(tx.sig, other.sig);
    }

    #[test]
    fn every_signed_transfer_field_is_covered() {
        let sk = seed(b"txbuild coverage");
        let to = crypto::address_from_pubkey(&[0x24u8; 32]);
        let tx = build_transfer(MAIN, &sk, &to, 1_000, 7, 3).unwrap();

        let mut m = tx;
        m.amount += 1;
        assert!(
            crypto::verify_transfer_signature(MAIN, &m).is_err(),
            "amount"
        );
        let mut m = tx;
        m.fee += 1;
        assert!(crypto::verify_transfer_signature(MAIN, &m).is_err(), "fee");
        let mut m = tx;
        m.nonce += 1;
        assert!(
            crypto::verify_transfer_signature(MAIN, &m).is_err(),
            "nonce"
        );
        let mut m = tx;
        m.to[0] ^= 1;
        assert!(crypto::verify_transfer_signature(MAIN, &m).is_err(), "to");
        let mut m = tx;
        m.sig[0] ^= 1;
        assert!(crypto::verify_transfer_signature(MAIN, &m).is_err(), "sig");
    }

    #[test]
    fn author_announcement_accepted_by_consensus() {
        let sk = seed(b"txbuild author");
        let author = sig::public_key_of(&sk);
        let tx = build_announcement(MAIN, &sk, &author, b"hello", 0x01, 5, 0).unwrap();
        tx::check_announcement_stateless(MAIN, &tx, &author).unwrap();
        crypto::verify_announcement_signature(MAIN, &tx).unwrap();
        assert_eq!(tx.encode().unwrap().len(), 124 + 5);
    }

    #[test]
    fn non_author_announcement_refused_before_signing() {
        let mine = seed(b"txbuild not author");
        let author = sig::public_key_of(&seed(b"txbuild the real author"));
        let err = build_announcement(MAIN, &mine, &author, b"hello", 0x01, 5, 0).unwrap_err();
        assert_eq!(err.kind(), "refused");
        assert!(err.to_string().contains("not the author key"));
        assert!(
            err.to_string().contains("block"),
            "must state the real cost"
        );
    }

    #[test]
    fn forced_non_author_announcement_rejected_by_consensus() {
        let mine = seed(b"txbuild forced");
        let mine_pub = sig::public_key_of(&mine);
        let author = sig::public_key_of(&seed(b"txbuild other author"));
        let tx = build_announcement(MAIN, &mine, &mine_pub, b"hello", 0x01, 5, 0).unwrap();
        assert_eq!(
            tx::check_announcement_stateless(MAIN, &tx, &author),
            Err(tx::TxError::NotAuthorKey)
        );
    }

    #[test]
    fn payload_bounds_enforced_before_signing() {
        let sk = seed(b"txbuild bounds");
        let author = sig::public_key_of(&sk);
        assert!(
            build_announcement(MAIN, &sk, &author, b"", 0, 1, 0).is_err(),
            "0 bytes"
        );
        assert!(
            build_announcement(MAIN, &sk, &author, &[0x41; 1], 0, 1, 0).is_ok(),
            "1 byte"
        );
        assert!(
            build_announcement(MAIN, &sk, &author, &[0x41; 1024], 0, 1, 0).is_ok(),
            "1024"
        );
        assert!(
            build_announcement(MAIN, &sk, &author, &[0x41; 1025], 0, 1, 0).is_err(),
            "1025"
        );
    }

    #[test]
    fn every_signed_announcement_field_is_covered() {
        let sk = seed(b"txbuild ann coverage");
        let author = sig::public_key_of(&sk);
        let tx = build_announcement(MAIN, &sk, &author, b"emergency", 0x01, 9, 4).unwrap();

        let mut m = tx.clone();
        m.fee += 1;
        assert!(
            crypto::verify_announcement_signature(MAIN, &m).is_err(),
            "fee"
        );
        let mut m = tx.clone();
        m.nonce += 1;
        assert!(
            crypto::verify_announcement_signature(MAIN, &m).is_err(),
            "nonce"
        );
        let mut m = tx.clone();
        m.encoding ^= 1;
        assert!(
            crypto::verify_announcement_signature(MAIN, &m).is_err(),
            "encoding"
        );
        let mut m = tx.clone();
        m.payload[0] ^= 1;
        assert!(
            crypto::verify_announcement_signature(MAIN, &m).is_err(),
            "payload"
        );
        let mut m = tx.clone();
        m.payload.push(0x41);
        assert!(
            crypto::verify_announcement_signature(MAIN, &m).is_err(),
            "length"
        );
        let mut m = tx.clone();
        m.sig[63] ^= 1;
        assert!(
            crypto::verify_announcement_signature(MAIN, &m).is_err(),
            "sig"
        );
    }

    #[test]
    fn builder_refuses_a_garbage_signer() {
        let sk = seed(b"txbuild broken signer");
        let from_pub = sig::public_key_of(&sk);
        let to = crypto::address_from_pubkey(&[0x24u8; 32]);

        let wrong_message = |_: &[u8; 32]| sig::sign(&sk, &[0x77u8; 32]);
        let err =
            build_transfer_signed_by(MAIN, from_pub, &wrong_message, &to, 1_000, 7, 3).unwrap_err();
        assert_eq!(err.kind(), "crypto");
        assert!(err.to_string().contains("self-verification"), "{err}");

        let zeros = |_: &[u8; 32]| [0u8; 64];
        let err = build_transfer_signed_by(MAIN, from_pub, &zeros, &to, 1_000, 7, 3).unwrap_err();
        assert_eq!(err.kind(), "crypto");

        let flipped = |m: &[u8; 32]| {
            let mut s = sig::sign(&sk, m);
            s[0] ^= 0x01;
            s
        };
        assert!(build_transfer_signed_by(MAIN, from_pub, &flipped, &to, 1_000, 7, 3).is_err());

        let err =
            build_announcement_signed_by(MAIN, from_pub, &wrong_message, &from_pub, b"x", 1, 5, 0)
                .unwrap_err();
        assert_eq!(err.kind(), "crypto");
        assert!(err.to_string().contains("self-verification"), "{err}");
        assert!(
            build_announcement_signed_by(MAIN, from_pub, &zeros, &from_pub, b"x", 1, 5, 0).is_err()
        );
        assert!(
            build_announcement_signed_by(MAIN, from_pub, &flipped, &from_pub, b"x", 1, 5, 0)
                .is_err()
        );

        let good = |m: &[u8; 32]| sig::sign(&sk, m);
        let tx = build_transfer_signed_by(MAIN, from_pub, &good, &to, 1_000, 7, 3).unwrap();
        crypto::verify_transfer_signature(MAIN, &tx).unwrap();
        let ann =
            build_announcement_signed_by(MAIN, from_pub, &good, &from_pub, b"x", 1, 5, 0).unwrap();
        tx::check_announcement_stateless(MAIN, &ann, &from_pub).unwrap();
    }

    #[test]
    fn invalid_author_pubkey_is_refused() {
        let sk = seed(b"txbuild bad author key");

        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        let err = build_announcement(MAIN, &sk, &not_a_point, b"x", 0, 1, 0).unwrap_err();
        assert_eq!(err.kind(), "usage");

        let other = sig::public_key_of(&seed(b"txbuild some other author"));
        let err = build_announcement(MAIN, &sk, &other, b"x", 0, 1, 0).unwrap_err();
        assert_eq!(err.kind(), "refused");
    }
}
