use plaine_consensus::constants::COINBASE_MATURITY;

use crate::body::validate_block_body;
use crate::error::{Condition, Reject};
use crate::state::{CoinbaseLedger, Overlay};
use crate::traits::Store;
use crate::types::{ChainParams, CommitBlock, HeaderRec, Trust};

pub type ValidatedBranch = (Vec<CommitBlock>, Vec<(crate::types::Address, u64)>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    UndoWindow,

    DeepReplay {
        rewind_to: u64,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn rewind_to_fork<S: Store + ?Sized>(
    store: &S,
    overlay: &mut Overlay<'_, S>,
    ledger: &mut CoinbaseLedger,
    tip_height: u64,
    fork_height: u64,
    params: &ChainParams,
    chainwork_at: &dyn Fn(u64) -> crate::types::Work,
    replayed_out: &mut Vec<CommitBlock>,
    observe: &mut dyn FnMut(Condition),
) -> Result<Base, Reject> {
    let mut base = Base::UndoWindow;

    // Fast path: replay undo records if we hold them all back to the fork.
    // Otherwise snapshot-and-replay from a checkpoint below it, far more expensive.
    let mut have_all_undo = true;
    for h in ((fork_height + 1)..=tip_height).rev() {
        if store.undo_at(h).is_none() {
            have_all_undo = false;
            break;
        }
    }

    if have_all_undo {
        for h in ((fork_height + 1)..=tip_height).rev() {
            let recs = store.undo_at(h).expect("checked above");
            overlay.apply_undo(&recs);
        }
    } else {
        let rewind_to = store.checkpoint_at_or_below(fork_height).ok_or(
            Reject::ResyncRequired { fork_height, replay_floor: store.replay_floor() },
        )?;
        if rewind_to < store.replay_floor() {
            observe(Condition::ResyncRequired {
                fork_height,
                replay_floor: store.replay_floor(),
            });
            return Err(Reject::ResyncRequired {
                fork_height,
                replay_floor: store.replay_floor(),
            });
        }
        let snapshot = store.state_snapshot(rewind_to).ok_or(Reject::ResyncRequired {
            fork_height,
            replay_floor: store.replay_floor(),
        })?;
        overlay.seed(snapshot);

        let mut replayed = 0u64;
        for h in (rewind_to + 1)..=fork_height {
            let raw = store.body_at(h).ok_or(Reject::ResyncRequired {
                fork_height,
                replay_floor: store.replay_floor(),
            })?;
            let hdr = store
                .header_at(h)
                .ok_or(Reject::ResyncRequired {
                    fork_height,
                    replay_floor: store.replay_floor(),
                })?
                .header();
            let mut throwaway = CoinbaseLedger::new();
            let rec = store.header_at(h).expect("checked above");
            let v = validate_block_body(overlay, &mut throwaway, &hdr, &raw, params, Trust::OurStore)
                .map_err(|e| Reject::BranchInvalid {
                    height: h,
                    hash: rec.hash,
                    cause: Box::new(e),
                })?;
            replayed_out.push(CommitBlock {
                header_raw: rec.raw,
                hash: rec.hash,
                height: h,
                body: raw,
                deltas: v.deltas,
                undo: v.undo,
                issued_delta: v.issued_delta,
                chainwork: chainwork_at(h),
                txids: v.txids,
            });
            replayed += 1;
        }
        observe(Condition::DeepReplay {
            from: rewind_to,
            to: fork_height,
            blocks: replayed,
        });
        base = Base::DeepReplay { rewind_to };
    }

    *ledger = build_ledger(store, fork_height)?;
    Ok(base)
}

pub fn build_ledger<S: Store + ?Sized>(store: &S, at: u64) -> Result<CoinbaseLedger, Reject> {
    let mut ledger = CoinbaseLedger::new();
    // Only the last maturity window can still be immature at `at`.
    let from = at.saturating_sub(COINBASE_MATURITY - 1);
    for h in from..=at {
        let Some(raw) = store.body_at(h) else { continue };
        let Ok(body) = plaine_consensus::codec::BlockBody::parse(&raw) else { continue };
        let Some(Ok(plaine_consensus::codec::Tx::Coinbase(cb))) = body.decode_tx(0) else {
            continue;
        };
        let credit = plaine_consensus::tx::coinbase_credit(&cb)
            .map_err(|_| Reject::ArithmeticOverflow)?;
        ledger.push(h, cb.to, credit);
    }
    Ok(ledger)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_branch<S: Store + ?Sized>(
    overlay: &mut Overlay<'_, S>,
    ledger: &mut CoinbaseLedger,
    branch: &[(HeaderRec, Vec<u8>)],
    base_chainwork_of: &dyn Fn(usize) -> crate::types::Work,
    params: &ChainParams,
    observe: &mut dyn FnMut(Condition),
) -> Result<ValidatedBranch, Reject> {
    let mut out = Vec::with_capacity(branch.len());
    let mut spent: Vec<(crate::types::Address, u64)> = Vec::new();
    let mut reported = false;
    for (i, (rec, raw)) in branch.iter().enumerate() {
        let hdr = rec.header();
        let v = validate_block_body(overlay, ledger, &hdr, raw, params, Trust::Untrusted).map_err(
            |cause| {
                observe(Condition::BranchInvalidAt { height: rec.height, hash: rec.hash });
                Reject::BranchInvalid {
                    height: rec.height,
                    hash: rec.hash,
                    cause: Box::new(cause),
                }
            },
        )?;
        if overlay.exhausted() && !reported {
            reported = true;
            observe(Condition::ReorgOverlayExhausted { accounts: overlay.len() });
        }
        debug_assert_eq!(
            v.deltas.len(),
            v.undo.len(),
            "deltas and undo must be equal-length and address-aligned"
        );
        spent.extend_from_slice(&v.spent_nonces);
        out.push(CommitBlock {
            header_raw: rec.raw,
            hash: rec.hash,
            height: rec.height,
            body: raw.clone(),
            deltas: v.deltas,
            undo: v.undo,
            issued_delta: v.issued_delta,
            chainwork: base_chainwork_of(i),
            txids: v.txids,
        });
    }
    Ok((out, spent))
}
