use crate::codec::{AnnouncementTx, CoinbaseTx, CodecError, Tx};
use crate::constants::{
    AUTHOR_NOTE_MAX_BYTES, FEE_FLOOR_MILE, Network, PUBKEY_BYTES, TX_TYPE_COINBASE,
};
use crate::crypto;
use crate::emission;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    NotAuthorKey,
    BadSignature,
    AnnouncementLength { len: usize },
    FeeBelowFloor { fee: u128 },
    BadNonce { expected: u64, got: u64 },
    InsufficientBalance { need: u128, have: u128 },
    AmountOverflow,
    FeeSumOverflow,
    RecordDoesNotDecode { index: usize, err: CodecError },
    MissingCoinbase,
    MisplacedCoinbase { index: usize },
    CoinbaseHeightMismatch { header: u64, coinbase: u64 },
    CoinbaseRewardMismatch { expected: u128, got: u128 },
    CoinbaseFeesMismatch { expected: u128, got: u128 },
    AuthorNoteLenMismatch { header: u32, coinbase: usize },
    AuthorNoteTooLong { len: usize },
}

impl core::fmt::Display for TxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TxError::NotAuthorKey => {
                write!(f, "announcement from_pub does not equal AUTHOR_PUBKEY")
            }
            TxError::BadSignature => write!(f, "signature verification failed"),
            TxError::AnnouncementLength { len } => {
                write!(f, "announcement payload length {len} outside 1..=1024")
            }
            TxError::FeeBelowFloor { fee } => {
                write!(f, "fee {fee} below the consensus floor of {FEE_FLOOR_MILE} mile")
            }
            TxError::BadNonce { expected, got } => {
                write!(f, "nonce {got}, account expects {expected}")
            }
            TxError::InsufficientBalance { need, have } => {
                write!(f, "needs {need} mile, spendable balance is {have}")
            }
            TxError::AmountOverflow => write!(f, "amount + fee overflows u128"),
            TxError::FeeSumOverflow => write!(f, "block fee total overflows u128"),
            TxError::RecordDoesNotDecode { index, err } => {
                write!(f, "body record {index} does not decode: {err}")
            }
            TxError::MissingCoinbase => write!(f, "body index 0 is not a coinbase"),
            TxError::MisplacedCoinbase { index } => {
                write!(f, "coinbase at body index {index}, must be index 0 only")
            }
            TxError::CoinbaseHeightMismatch { header, coinbase } => {
                write!(f, "coinbase height {coinbase} != header height {header}")
            }
            TxError::CoinbaseRewardMismatch { expected, got } => {
                write!(f, "coinbase reward {got} mile, schedule says {expected}")
            }
            TxError::CoinbaseFeesMismatch { expected, got } => {
                write!(f, "coinbase fees {got} mile, body sums to {expected}")
            }
            TxError::AuthorNoteLenMismatch { header, coinbase } => {
                write!(f, "header author_note_len {header} != coinbase note length {coinbase}")
            }
            TxError::AuthorNoteTooLong { len } => {
                write!(f, "author-note length {len} exceeds {AUTHOR_NOTE_MAX_BYTES}")
            }
        }
    }
}

impl std::error::Error for TxError {}

pub fn check_announcement_stateless(
    network: Network,
    tx: &AnnouncementTx,
    author_pubkey: &[u8; PUBKEY_BYTES],
) -> Result<(), TxError> {
    // The announcement channel is the author's alone. A valid signature under
    // any other key is still rejected here.
    if tx.from_pub != *author_pubkey {
        return Err(TxError::NotAuthorKey);
    }
    tx.check_payload_len().map_err(|_| TxError::AnnouncementLength { len: tx.payload.len() })?;
    crypto::verify_announcement_signature(network, tx).map_err(|_| TxError::BadSignature)
}

pub fn check_announcement_stateful(
    tx: &AnnouncementTx,
    acct: &AccountState,
    spendable: u128,
) -> Result<(), TxError> {
    if tx.fee < FEE_FLOOR_MILE {
        return Err(TxError::FeeBelowFloor { fee: tx.fee });
    }

    if tx.nonce != acct.nonce {
        return Err(TxError::BadNonce { expected: acct.nonce, got: tx.nonce });
    }
    if spendable < tx.fee {
        return Err(TxError::InsufficientBalance { need: tx.fee, have: spendable });
    }
    Ok(())
}

pub fn apply_announcement(
    acct: &AccountState,
    tx: &AnnouncementTx,
) -> Result<AccountState, TxError> {
    let balance = acct
        .balance
        .checked_sub(tx.fee)
        .ok_or(TxError::InsufficientBalance { need: tx.fee, have: acct.balance })?;
    let nonce = acct.nonce.checked_add(1).ok_or(TxError::AmountOverflow)?;
    Ok(AccountState { balance, nonce })
}

pub fn block_fee_total<'a>(txs: impl IntoIterator<Item = &'a Tx>) -> Result<u128, TxError> {
    let mut total: u128 = 0;
    for tx in txs {
        total = total.checked_add(tx.fee()).ok_or(TxError::FeeSumOverflow)?;
    }
    Ok(total)
}

pub fn check_body_structure(txs: &[Tx]) -> Result<&CoinbaseTx, TxError> {
    let Some(Tx::Coinbase(cb)) = txs.first() else {
        return Err(TxError::MissingCoinbase);
    };
    // one coinbase, at index 0 only; a second one anywhere would mint twice
    for (i, tx) in txs.iter().enumerate().skip(1) {
        if tx.type_byte() == TX_TYPE_COINBASE {
            return Err(TxError::MisplacedCoinbase { index: i });
        }
    }
    Ok(cb)
}

pub fn decode_body(body: &crate::codec::BlockBody<'_>) -> Result<Vec<Tx>, TxError> {
    (0..body.len())
        .map(|i| {
            crate::codec::decode_tx(body.tx_bytes(i).expect("i < len"))
                .map_err(|err| TxError::RecordDoesNotDecode { index: i, err })
        })
        .collect()
}

pub fn check_coinbase(
    cb: &CoinbaseTx,
    header_height: u64,
    header_author_note_len: u32,
    fee_total: u128,
) -> Result<(), TxError> {
    if cb.height != header_height {
        return Err(TxError::CoinbaseHeightMismatch {
            header: header_height,
            coinbase: cb.height,
        });
    }

    // Exact match, not a ceiling: under-claiming is rejected too, so issuance
    // stays a pure function of height.
    let expected = emission::block_reward(header_height);
    if cb.reward != expected {
        return Err(TxError::CoinbaseRewardMismatch { expected, got: cb.reward });
    }

    if cb.fees != fee_total {
        return Err(TxError::CoinbaseFeesMismatch { expected: fee_total, got: cb.fees });
    }

    let note_len = cb.note.payload.len();
    if note_len > AUTHOR_NOTE_MAX_BYTES {
        return Err(TxError::AuthorNoteTooLong { len: note_len });
    }
    if header_author_note_len as usize != note_len {
        return Err(TxError::AuthorNoteLenMismatch {
            header: header_author_note_len,
            coinbase: note_len,
        });
    }
    Ok(())
}

pub fn coinbase_credit(cb: &CoinbaseTx) -> Result<u128, TxError> {
    cb.reward.checked_add(cb.fees).ok_or(TxError::AmountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{AuthorNote, BlockBody, TransferTx};
    use crate::constants::{ANNOUNCEMENT_MAX_PAYLOAD_BYTES, CHAIN_ID};
    use crate::constants::Network;
    use ed25519_dalek::{Signer, SigningKey};

    fn author_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }
    fn impostor_key() -> SigningKey {
        SigningKey::from_bytes(&[0x99; 32])
    }

    fn signed_announcement(
        sk: &SigningKey,
        chain_id: &[u8; 4],
        fee: u128,
        nonce: u64,
        encoding: u8,
        payload: Vec<u8>,
    ) -> AnnouncementTx {
        let from_pub = sk.verifying_key().to_bytes();
        let msg = crypto::announcement_signing_message_with_chain_id(
            chain_id, &from_pub, fee, nonce, encoding, &payload,
        )
        .expect("payload length in range");
        let sig = sk.sign(&msg).to_bytes();
        AnnouncementTx { from_pub, fee, nonce, encoding, payload, sig }
    }

    fn sample_announcement() -> AnnouncementTx {
        signed_announcement(&author_key(), &CHAIN_ID, 1, 0, 0x01, b"Plaine: ASIC fork at 0".to_vec())
    }

    fn author_pub() -> [u8; 32] {
        author_key().verifying_key().to_bytes()
    }

    #[test]
    fn non_author_key_rejected() {
        let forged = signed_announcement(&impostor_key(), &CHAIN_ID, 1, 0, 0x01, b"hi".to_vec());

        assert_eq!(crypto::verify_announcement_signature(Network::Main, &forged), Ok(()));

        assert_eq!(
            check_announcement_stateless(Network::Main, &forged, &author_pub()),
            Err(TxError::NotAuthorKey)
        );

        let ok = sample_announcement();
        assert_eq!(check_announcement_stateless(Network::Main, &ok, &author_pub()), Ok(()));

        let mut stolen = ok.clone();
        stolen.sig = forged.sig;
        assert_eq!(
            check_announcement_stateless(Network::Main, &stolen, &author_pub()),
            Err(TxError::BadSignature)
        );
    }

    #[test]
    fn all_signed_fields_covered() {
        let base = sample_announcement();
        assert_eq!(check_announcement_stateless(Network::Main, &base, &author_pub()), Ok(()));

        let mut t = base.clone();
        t.sig[0] ^= 0x01;
        assert_eq!(check_announcement_stateless(Network::Main, &t, &author_pub()), Err(TxError::BadSignature));

        let mut t = base.clone();
        t.fee += 1;
        assert_eq!(check_announcement_stateless(Network::Main, &t, &author_pub()), Err(TxError::BadSignature));

        let mut t = base.clone();
        t.nonce += 1;
        assert_eq!(check_announcement_stateless(Network::Main, &t, &author_pub()), Err(TxError::BadSignature));

        let mut t = base.clone();
        t.encoding ^= 0xFF;
        assert_eq!(check_announcement_stateless(Network::Main, &t, &author_pub()), Err(TxError::BadSignature));

        let mut t = base.clone();
        t.payload[0] ^= 0xFF;
        assert_eq!(check_announcement_stateless(Network::Main, &t, &author_pub()), Err(TxError::BadSignature));

        let mut t = base.clone();
        t.payload.push(0x00);
        assert_eq!(check_announcement_stateless(Network::Main, &t, &author_pub()), Err(TxError::BadSignature));
    }

    #[test]
    fn announcement_wrong_chain_id_rejected() {
        let mut other = CHAIN_ID;
        other[0] ^= 0x01;
        let ours = sample_announcement();
        let foreign = signed_announcement(
            &author_key(),
            &other,
            1,
            0,
            0x01,
            b"Plaine: ASIC fork at 0".to_vec(),
        );
        assert_eq!(
            foreign.encode_unsigned().unwrap(),
            ours.encode_unsigned().unwrap(),
            "same body bytes, only the chain id in the preimage differs"
        );
        assert_ne!(foreign.sig, ours.sig);
        assert_eq!(
            check_announcement_stateless(Network::Main, &foreign, &author_pub()),
            Err(TxError::BadSignature)
        );

        let msg_foreign = crypto::announcement_signing_message_with_chain_id(
            &other,
            &ours.from_pub,
            ours.fee,
            ours.nonce,
            ours.encoding,
            &ours.payload,
        )
        .unwrap();
        assert_eq!(
            crypto::verify_signature(&ours.from_pub, &msg_foreign, &ours.sig),
            Err(crate::crypto::SigError::InvalidSignature)
        );
    }

    #[test]
    fn announcement_length_bounds() {
        for n in [1usize, ANNOUNCEMENT_MAX_PAYLOAD_BYTES] {
            let tx = signed_announcement(&author_key(), &CHAIN_ID, 1, 0, 0x00, vec![0x5A; n]);
            assert_eq!(check_announcement_stateless(Network::Main, &tx, &author_pub()), Ok(()));
            assert_eq!(tx.wire_len(), 124 + n);
            let enc = tx.encode().unwrap();
            assert_eq!(enc.len(), 124 + n);
            assert_eq!(AnnouncementTx::decode(&enc).unwrap(), tx);
        }

        let empty = AnnouncementTx {
            from_pub: author_pub(),
            fee: 1,
            nonce: 0,
            encoding: 0,
            payload: vec![],
            sig: [0u8; 64],
        };
        assert_eq!(
            check_announcement_stateless(Network::Main, &empty, &author_pub()),
            Err(TxError::AnnouncementLength { len: 0 })
        );

        let long = AnnouncementTx { payload: vec![0u8; 1025], ..empty.clone() };
        assert_eq!(
            check_announcement_stateless(Network::Main, &long, &author_pub()),
            Err(TxError::AnnouncementLength { len: 1025 })
        );
    }

    #[test]
    fn fee_floor_and_balance_rules() {
        let acct = AccountState { balance: 100, nonce: 0 };
        let free = signed_announcement(&author_key(), &CHAIN_ID, 0, 0, 0x01, b"free?".to_vec());
        assert_eq!(
            check_announcement_stateful(&free, &acct, 100),
            Err(TxError::FeeBelowFloor { fee: 0 }),
            "a leaked key must not be a free spam channel"
        );
        let paid = signed_announcement(&author_key(), &CHAIN_ID, 1, 0, 0x01, b"paid".to_vec());
        assert_eq!(check_announcement_stateful(&paid, &acct, 100), Ok(()));

        let dear = signed_announcement(&author_key(), &CHAIN_ID, 500, 0, 0x01, b"dear".to_vec());
        assert_eq!(
            check_announcement_stateful(&dear, &acct, 100),
            Err(TxError::InsufficientBalance { need: 500, have: 100 })
        );

        let spendable = crate::rules::spendable_balance(acct.balance, 100);
        assert_eq!(spendable, 0);
        assert_eq!(
            check_announcement_stateful(&paid, &acct, spendable),
            Err(TxError::InsufficientBalance { need: 1, have: 0 })
        );
    }

    #[test]
    fn replay_stopped_by_nonce() {
        let tx = signed_announcement(&author_key(), &CHAIN_ID, 1, 5, 0x01, b"note".to_vec());
        let acct = AccountState { balance: 10, nonce: 5 };
        assert_eq!(check_announcement_stateful(&tx, &acct, 10), Ok(()));
        let after = apply_announcement(&acct, &tx).unwrap();
        assert_eq!(after, AccountState { balance: 9, nonce: 6 });

        assert_eq!(
            check_announcement_stateful(&tx, &after, 9),
            Err(TxError::BadNonce { expected: 6, got: 5 })
        );
    }

    #[test]
    fn dup_announcement_in_block_is_replay() {
        let tx = signed_announcement(&author_key(), &CHAIN_ID, 1, 5, 0x01, b"note".to_vec());
        let snapshot = AccountState { balance: 10, nonce: 5 };

        assert_eq!(check_announcement_stateful(&tx, &snapshot, 10), Ok(()));

        let mut acct = snapshot;
        assert_eq!(check_announcement_stateful(&tx, &acct, acct.balance), Ok(()));
        acct = apply_announcement(&acct, &tx).unwrap();
        assert_eq!(
            check_announcement_stateful(&tx, &acct, acct.balance),
            Err(TxError::BadNonce { expected: 6, got: 5 })
        );
    }

    #[test]
    fn apply_announcement_no_panic() {
        let acct = AccountState { balance: 0, nonce: u64::MAX };
        let tx = signed_announcement(&author_key(), &CHAIN_ID, u128::MAX, 0, 0, b"x".to_vec());
        assert_eq!(
            apply_announcement(&acct, &tx),
            Err(TxError::InsufficientBalance { need: u128::MAX, have: 0 })
        );
        let tx0 = signed_announcement(&author_key(), &CHAIN_ID, 0, 0, 0, b"x".to_vec());
        assert_eq!(apply_announcement(&acct, &tx0), Err(TxError::AmountOverflow));
    }

    #[test]
    fn invalid_utf8_payload_accepted() {
        let payload: Vec<u8> = vec![
            0xFF, 0xFE,
            0x80,
            0xED, 0xA0, 0x80,
            0xF4, 0x90, 0x80, 0x80,
            0x00,
        ];
        assert!(core::str::from_utf8(&payload).is_err(), "the vector really is invalid UTF-8");

        let tx = signed_announcement(&author_key(), &CHAIN_ID, 1, 0, 0x01, payload.clone());
        assert_eq!(check_announcement_stateless(Network::Main, &tx, &author_pub()), Ok(()));
        let acct = AccountState { balance: 10, nonce: 0 };
        assert_eq!(check_announcement_stateful(&tx, &acct, 10), Ok(()));

        let enc = tx.encode().unwrap();
        let back = AnnouncementTx::decode(&enc).unwrap();
        assert_eq!(back, tx);
        assert_eq!(back.payload, payload);
        assert_eq!(back.encode().unwrap(), enc);
    }

    #[test]
    fn encoding_byte_is_never_validated() {
        for e in 0u8..=255 {
            let tx = signed_announcement(&author_key(), &CHAIN_ID, 1, 0, e, b"https://x".to_vec());
            assert_eq!(check_announcement_stateless(Network::Main, &tx, &author_pub()), Ok(()), "encoding {e}");
            assert_eq!(AnnouncementTx::decode(&tx.encode().unwrap()).unwrap(), tx);
        }
    }

    fn transfer_with_fee(fee: u128) -> Tx {
        Tx::Transfer(TransferTx {
            from_pub: [0x01; 32],
            to: [0x02; 20],
            amount: 0,
            fee,
            nonce: 0,
            sig: [0x03; 64],
        })
    }

    #[test]
    fn block_fee_total_skips_coinbase() {
        let cb = Tx::Coinbase(CoinbaseTx {
            height: 1,
            to: [0; 20],
            reward: 500,
            fees: 0,
            note: AuthorNote { encoding: 0, payload: vec![] },
        });
        let ann = Tx::Announcement(sample_announcement());
        let txs = [cb, transfer_with_fee(7), ann];
        assert_eq!(block_fee_total(txs.iter().skip(1)).unwrap(), 8);

        assert_eq!(block_fee_total(txs.iter()).unwrap(), 8);
    }

    #[test]
    fn block_fee_total_overflow_rejected() {
        let half = u128::MAX / 2 + 1;
        let txs = [transfer_with_fee(half), transfer_with_fee(half)];
        assert_eq!(block_fee_total(txs.iter()), Err(TxError::FeeSumOverflow));
    }

    fn coinbase_at(height: u64, note_len: usize) -> CoinbaseTx {
        CoinbaseTx {
            height,
            to: [0x77; 20],
            reward: emission::block_reward(height),
            fees: 0,
            note: AuthorNote { encoding: 0x01, payload: vec![0x41; note_len] },
        }
    }

    #[test]
    fn coinbase_rules_reject_every_mismatch() {
        let h = 100_000u64;
        let cb = coinbase_at(h, 5);
        assert_eq!(check_coinbase(&cb, h, 5, 0), Ok(()));

        assert_eq!(
            check_coinbase(&cb, h + 1, 5, 0),
            Err(TxError::CoinbaseHeightMismatch { header: h + 1, coinbase: h })
        );

        let expected = emission::block_reward(h);
        let mut over = cb.clone();
        over.reward = expected + 1;
        assert_eq!(
            check_coinbase(&over, h, 5, 0),
            Err(TxError::CoinbaseRewardMismatch { expected, got: expected + 1 })
        );
        let mut under = cb.clone();
        under.reward = expected - 1;
        assert_eq!(
            check_coinbase(&under, h, 5, 0),
            Err(TxError::CoinbaseRewardMismatch { expected, got: expected - 1 }),
            "under-claiming is rejected too: issuance is a function of height"
        );

        assert_eq!(
            check_coinbase(&cb, h, 5, 9),
            Err(TxError::CoinbaseFeesMismatch { expected: 9, got: 0 })
        );

        assert_eq!(
            check_coinbase(&cb, h, 4, 0),
            Err(TxError::AuthorNoteLenMismatch { header: 4, coinbase: 5 })
        );
    }

    #[test]
    fn coinbase_txid_is_unique_per_height() {
        let a = CoinbaseTx { height: 100, ..coinbase_at(100, 3) };
        let b = CoinbaseTx { height: 101, ..coinbase_at(100, 3) };
        assert_eq!(a.reward, b.reward);
        assert_ne!(a.txid().unwrap(), b.txid().unwrap());
    }

    #[test]
    fn body_structure_rules() {
        let cb = Tx::Coinbase(coinbase_at(7, 0));
        let t = transfer_with_fee(1);
        assert!(check_body_structure(&[cb.clone(), t.clone()]).is_ok());
        assert_eq!(check_body_structure(std::slice::from_ref(&t)), Err(TxError::MissingCoinbase));
        assert_eq!(check_body_structure(&[]), Err(TxError::MissingCoinbase));
        assert_eq!(
            check_body_structure(&[cb.clone(), t, cb.clone()]),
            Err(TxError::MisplacedCoinbase { index: 2 })
        );
    }

    #[test]
    fn full_body_end_to_end() {
        let h = 250_000u64;
        let ann = sample_announcement();
        let mut cb = coinbase_at(h, 0);
        cb.fees = ann.fee;
        let cb_bytes = cb.encode().unwrap();
        let ann_bytes = ann.encode().unwrap();
        let raw = BlockBody::encode(&[&cb_bytes, &ann_bytes]).unwrap();

        let body = BlockBody::parse(&raw).unwrap();
        assert_eq!(body.len(), 2);
        let txs = decode_body(&body).unwrap();
        let parsed_cb = check_body_structure(&txs).unwrap();
        let fees = block_fee_total(txs.iter().skip(1)).unwrap();
        assert_eq!(fees, 1);
        assert_eq!(check_coinbase(parsed_cb, h, 0, fees), Ok(()));
        assert_eq!(coinbase_credit(parsed_cb).unwrap(), cb.reward + 1);

        assert_eq!(body.tx_root(), crate::merkle::tx_root(&[&cb_bytes, &ann_bytes]));
    }

    #[test]
    fn unknown_type_parses_then_consensus_rejects() {
        let cb_bytes = coinbase_at(1, 0).encode().unwrap();
        let unknown = vec![0x7Fu8; 40];
        let raw = BlockBody::encode(&[&cb_bytes, &unknown]).unwrap();
        let body = BlockBody::parse(&raw).unwrap();
        assert_eq!(body.len(), 2);
        assert_eq!(
            decode_body(&body),
            Err(TxError::RecordDoesNotDecode {
                index: 1,
                err: CodecError::ReservedTxType { got: 0x7F }
            })
        );
    }
}
