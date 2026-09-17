use plaine_consensus::codec::{BlockBody, Header, Tx};
use plaine_consensus::constants::FEE_FLOOR_MILE;
use plaine_consensus::crypto;
use plaine_consensus::tx as ctx;

use crate::error::Reject;
use crate::state::{CoinbaseLedger, Overlay};
use crate::traits::Store;
use crate::types::{Address, ChainParams, Hash32, StateDelta, Trust, UndoRec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedBlock {
    pub deltas: Vec<StateDelta>,
    pub undo: Vec<UndoRec>,
    pub issued_delta: u128,
    pub coinbase_to: Address,
    pub coinbase_credit: u128,
    pub txids: Vec<Hash32>,
    pub spent_nonces: Vec<(Address, u64)>,
    pub non_coinbase_bytes: Vec<Vec<u8>>,
}

pub fn validate_block_body<S: Store + ?Sized>(
    overlay: &mut Overlay<'_, S>,
    ledger: &mut CoinbaseLedger,
    header: &Header,
    raw_body: &[u8],
    params: &ChainParams,
    trust: Trust,
) -> Result<ValidatedBlock, Reject> {
    let body = BlockBody::parse(raw_body).map_err(|_| Reject::BodyStructure {
        detail: "body envelope",
    })?;

    let txs = ctx::decode_body(&body).map_err(|e| {
        let index = match e {
            ctx::TxError::RecordDoesNotDecode { index, .. } => index,
            _ => 0,
        };
        Reject::Tx { index, err: e }
    })?;

    let cb = ctx::check_body_structure(&txs)
        .map_err(|e| Reject::Tx { index: 0, err: e })?
        .clone();

    if body.tx_root() != header.tx_root {
        return Err(Reject::TxRootMismatch);
    }

    // Untrusted branches: verify every signature. Our own store was checked on
    // first accept, so re-check only the author key here.
    if trust == Trust::Untrusted {
        for (i, tx) in txs.iter().enumerate() {
            match tx {
                Tx::Coinbase(_) => {}
                Tx::Transfer(t) => {
                    crypto::verify_transfer_signature(params.network, t)
                        .map_err(|_| Reject::BadTransferSignature { index: i })?;
                }
                Tx::Announcement(a) => {
                    ctx::check_announcement_stateless(params.network, a, &params.author_pubkey)
                        .map_err(|err| Reject::Tx { index: i, err })?;
                }
            }
        }
    } else {
        for (i, tx) in txs.iter().enumerate() {
            if let Tx::Announcement(a) = tx {
                if a.from_pub != params.author_pubkey {
                    return Err(Reject::Tx {
                        index: i,
                        err: ctx::TxError::NotAuthorKey,
                    });
                }
            }
        }
    }

    let fee_total =
        ctx::block_fee_total(txs.iter()).map_err(|e| Reject::Tx { index: 0, err: e })?;
    ctx::check_coinbase(&cb, header.height, header.author_note_len, fee_total)
        .map_err(|e| Reject::Tx { index: 0, err: e })?;
    let credit = ctx::coinbase_credit(&cb).map_err(|e| Reject::Tx { index: 0, err: e })?;

    overlay.begin_block();
    overlay.credit(&cb.to, credit)?;
    ledger.push(header.height, cb.to, credit);

    let mut txids = Vec::with_capacity(txs.len());
    let mut spent_nonces = Vec::new();
    let mut non_coinbase_bytes = Vec::new();
    txids.push(cb.txid().map_err(|_| Reject::BodyStructure {
        detail: "coinbase txid",
    })?);

    for (i, tx) in txs.iter().enumerate().skip(1) {
        let raw = body.tx_bytes(i).expect("i < len").to_vec();
        match tx {
            Tx::Coinbase(_) => unreachable!("check_body_structure rejected a misplaced coinbase"),
            Tx::Transfer(t) => {
                if t.fee < FEE_FLOOR_MILE {
                    return Err(Reject::FeeBelowFloor { index: i });
                }
                let from = crypto::address_payload(&t.from_pub);
                let acct = overlay.get(&from);
                if acct.nonce != t.nonce {
                    return Err(Reject::BadNonce {
                        index: i,
                        expected: acct.nonce,
                        got: t.nonce,
                    });
                }
                let outlay = t
                    .amount
                    .checked_add(t.fee)
                    .ok_or(Reject::ArithmeticOverflow)?;
                let spendable = ledger.spendable(&from, acct.balance, header.height);
                if spendable < outlay {
                    return Err(Reject::InsufficientBalance {
                        index: i,
                        need: outlay,
                        have: spendable,
                    });
                }
                let mut updated = acct;
                updated.balance = acct
                    .balance
                    .checked_sub(outlay)
                    .ok_or(Reject::ArithmeticOverflow)?;
                updated.nonce = acct
                    .nonce
                    .checked_add(1)
                    .ok_or(Reject::ArithmeticOverflow)?;
                overlay.set(&from, updated);
                overlay.credit(&t.to, t.amount)?;
                txids.push(t.txid());
                spent_nonces.push((from, t.nonce));
                non_coinbase_bytes.push(raw);
            }
            Tx::Announcement(a) => {
                let from = crypto::address_payload(&a.from_pub);
                let acct = overlay.get(&from);
                let spendable = ledger.spendable(&from, acct.balance, header.height);
                let cs = plaine_consensus::tx::AccountState {
                    balance: acct.balance,
                    nonce: acct.nonce,
                };
                ctx::check_announcement_stateful(a, &cs, spendable)
                    .map_err(|err| Reject::Tx { index: i, err })?;
                let next =
                    ctx::apply_announcement(&cs, a).map_err(|err| Reject::Tx { index: i, err })?;
                overlay.set(
                    &from,
                    crate::types::Account {
                        balance: next.balance,
                        nonce: next.nonce,
                    },
                );
                txids.push(
                    a.txid()
                        .map_err(|_| Reject::BodyStructure { detail: "ann txid" })?,
                );
                spent_nonces.push((from, a.nonce));
                non_coinbase_bytes.push(raw);
            }
        }
    }

    Ok(ValidatedBlock {
        undo: overlay.undo_records(),
        deltas: overlay.deltas(),
        issued_delta: cb.reward,
        coinbase_to: cb.to,
        coinbase_credit: credit,
        txids,
        spent_nonces,
        non_coinbase_bytes,
    })
}
