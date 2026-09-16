use std::collections::HashMap;

use plaine_consensus::constants::COINBASE_MATURITY;
use plaine_consensus::rules::spendable_balance;

use crate::error::Reject;
use crate::traits::Store;
use crate::types::{Account, Address, StateDelta, UndoRec};

pub struct Overlay<'a, S: Store + ?Sized> {
    store: &'a S,
    accounts: HashMap<Address, Account>,
    undo: HashMap<Address, UndoRec>,
    order: Vec<Address>,
    max_accounts: usize,
}

impl<'a, S: Store + ?Sized> Overlay<'a, S> {
    pub fn new(store: &'a S, max_accounts: usize) -> Overlay<'a, S> {
        Overlay {
            store,
            accounts: HashMap::new(),
            undo: HashMap::new(),
            order: Vec::new(),
            max_accounts,
        }
    }

    pub fn seed(&mut self, rows: Vec<(Address, Account)>) {
        self.accounts.clear();
        self.accounts.extend(rows);
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    // The overlay holds a reorg's touched accounts in memory; past this bound we
    // report exhaustion instead of blowing up RSS.
    pub fn exhausted(&self) -> bool {
        self.accounts.len() > self.max_accounts
    }

    pub fn get(&mut self, addr: &Address) -> Account {
        if let Some(a) = self.accounts.get(addr) {
            return *a;
        }
        let a = self.store.account(addr);
        self.accounts.insert(*addr, a);
        a
    }

    pub fn begin_block(&mut self) {
        self.undo.clear();
        self.order.clear();
    }

    fn capture(&mut self, addr: &Address) {
        if self.undo.contains_key(addr) {
            return;
        }
        let prev = self.get(addr);
        self.undo.insert(
            *addr,
            UndoRec {
                addr: *addr,
                prev_balance: prev.balance,
                prev_nonce: prev.nonce,
                existed: !prev.is_absent(),
            },
        );
        self.order.push(*addr);
    }

    pub fn set(&mut self, addr: &Address, acct: Account) {
        self.capture(addr);
        self.accounts.insert(*addr, acct);
    }

    pub fn credit(&mut self, addr: &Address, amount: u128) -> Result<(), Reject> {
        let mut a = self.get(addr);
        a.balance = a.balance.checked_add(amount).ok_or(Reject::ArithmeticOverflow)?;
        self.set(addr, a);
        Ok(())
    }

    pub fn undo_records(&self) -> Vec<UndoRec> {
        self.order.iter().map(|a| self.undo[a]).collect()
    }

    pub fn deltas(&mut self) -> Vec<StateDelta> {
        let order = self.order.clone();
        order
            .iter()
            .map(|a| {
                let acct = self.get(a);
                StateDelta { addr: *a, balance: acct.balance, nonce: acct.nonce }
            })
            .collect()
    }

    pub fn apply_undo(&mut self, recs: &[UndoRec]) {
        for r in recs {
            self.accounts
                .insert(r.addr, Account { balance: r.prev_balance, nonce: r.prev_nonce });
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoinbaseLedger {
    entries: Vec<(u64, Address, u128)>,
}

impl CoinbaseLedger {
    pub fn new() -> CoinbaseLedger {
        CoinbaseLedger::default()
    }

    pub fn push(&mut self, height: u64, addr: Address, credit: u128) {
        self.entries.push((height, addr, credit));
    }

    pub fn truncate_from(&mut self, height: u64) {
        self.entries.retain(|(h, _, _)| *h < height);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn immature_at(&self, addr: &Address, spend_height: u64) -> u128 {
        self.entries
            .iter()
            .filter(|(h, a, _)| a == addr && !mature(*h, spend_height))
            .map(|(_, _, c)| *c)
            .fold(0u128, |acc, c| acc.saturating_add(c))
    }

    pub fn spendable(&self, addr: &Address, balance: u128, spend_height: u64) -> u128 {
        spendable_balance(balance, self.immature_at(addr, spend_height))
    }
}

// Maturity is deeper than the reorg cap, so a matured reward can't be undone.
pub fn mature(coinbase_height: u64, spend_height: u64) -> bool {
    plaine_consensus::rules::coinbase_is_mature(coinbase_height, spend_height)
}

pub fn immature_window_start(spend_height: u64) -> u64 {
    spend_height.saturating_sub(COINBASE_MATURITY - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maturity_deeper_than_reorg_cap() {
        let cap = plaine_consensus::constants::MAX_REORG_DEPTH;
        let m = COINBASE_MATURITY;
        assert!(m > cap);
        let spend_height = 1_000u64;
        let deepest_reorgable = spend_height - cap;
        assert!(!mature(deepest_reorgable, spend_height));
        assert!(mature(spend_height - m, spend_height));
        assert!(!mature(spend_height - m + 1, spend_height));
    }

    #[test]
    fn ledger_sums_immature_per_address() {
        let a: Address = [1u8; 20];
        let b: Address = [2u8; 20];
        let spend = 1_000u64;
        let m = COINBASE_MATURITY;
        let mut l = CoinbaseLedger::new();

        l.push(spend - m, a, 10);
        l.push(spend - m + 1, a, 20);
        l.push(spend - m + 1, b, 40);
        l.push(spend - 1, a, 5);
        assert_eq!(l.immature_at(&a, spend), 25);
        assert_eq!(l.immature_at(&b, spend), 40);
        assert_eq!(l.spendable(&a, 100, spend), 75);

        assert_eq!(l.spendable(&a, 10, spend), 0);
    }

    #[test]
    fn immature_window_start_saturates_near_genesis() {
        let m = COINBASE_MATURITY;
        assert_eq!(immature_window_start(1_000), 1_000 - (m - 1));

        assert_eq!(immature_window_start(0), 0);
        assert_eq!(immature_window_start(m - 1), 0);
        assert_eq!(immature_window_start(m), 1);
    }
}
