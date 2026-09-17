use plaine_consensus::constants::Network;
use std::collections::{BTreeMap, HashMap, VecDeque};

use plaine_consensus::codec::{decode_tx, Tx};
use plaine_consensus::constants::{FEE_FLOOR_MILE, MAX_TX_BYTES, TX_TYPE_COINBASE};
use plaine_consensus::crypto;

use crate::error::{BudgetClass, Condition, EvictReason, Reject};
use crate::types::{Account, Address, ChainParams, Hash32, MempoolParams, SourceId, TX_COST_MILLI};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigProof(Provenance);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provenance {
    Verified,
    ValidatedBlock,
}

impl SigProof {
    pub fn verify(network: Network, tx: &Tx, author_pubkey: &[u8; 32]) -> Result<SigProof, Reject> {
        match tx {
            Tx::Transfer(t) => crypto::verify_transfer_signature(network, t)
                .map_err(|_| Reject::BadTransferSignature { index: 0 })?,
            Tx::Announcement(a) => {
                plaine_consensus::tx::check_announcement_stateless(network, a, author_pubkey)
                    .map_err(|err| Reject::Tx { index: 0, err })?;
            }
            Tx::Coinbase(_) => return Err(Reject::TxTypeNotRelayable { type_byte: 0x00 }),
        }
        Ok(SigProof(Provenance::Verified))
    }

    pub fn from_validated_block() -> SigProof {
        SigProof(Provenance::ValidatedBlock)
    }

    pub fn is_freshly_verified(&self) -> bool {
        self.0 == Provenance::Verified
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AuthorRule<'a> {
    Enforce(&'a [u8; 32]),
    AlreadyHeld,
}

#[derive(Clone, Debug)]
pub struct Prepared {
    raw: Vec<u8>,
    tx: Tx,
    txid: Hash32,
    sender: Address,
    nonce: u64,
    fee: u128,
    amount: u128,
    next: u64,
    replaces: Option<Hash32>,
}

impl Prepared {
    pub fn tx(&self) -> &Tx {
        &self.tx
    }

    pub fn txid(&self) -> Hash32 {
        self.txid
    }

    pub fn sender(&self) -> Address {
        self.sender
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolTx {
    pub txid: Hash32,
    pub sender: Address,
    pub nonce: u64,
    pub fee: u128,
    pub amount: u128,
    pub bytes: Vec<u8>,
    pub arrived: u64,
    pub sig_verified: bool,
    pub executable: bool,
}

impl PoolTx {
    pub fn fee_per_byte(&self) -> u128 {
        self.fee / self.bytes.len().max(1) as u128
    }
}

#[derive(Debug, Default)]
pub struct Mempool {
    params: MempoolParams,
    txs: HashMap<Hash32, PoolTx>,
    by_sender: HashMap<Address, BTreeMap<u64, Hash32>>,
    next_nonce: HashMap<Address, u64>,
    arrival: VecDeque<Hash32>,
    total_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub txid: Hash32,
    pub executable: bool,
    pub promoted: Vec<Hash32>,
    pub removed: Vec<Hash32>,
}

impl Mempool {
    pub fn new(params: MempoolParams) -> Mempool {
        Mempool {
            params,
            ..Default::default()
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn get(&self, txid: &Hash32) -> Option<&PoolTx> {
        self.txs.get(txid)
    }

    pub fn sender_len(&self, s: &Address) -> usize {
        self.by_sender.get(s).map_or(0, |m| m.len())
    }

    pub fn sender_txs(&self, s: &Address) -> Vec<PoolTx> {
        self.by_sender
            .get(s)
            .map(|m| {
                m.values()
                    .filter_map(|id| self.txs.get(id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn executable_len(&self) -> usize {
        self.txs.values().filter(|t| t.executable).count()
    }

    pub fn executable_ids(&self) -> Vec<Hash32> {
        let mut v: Vec<&PoolTx> = self.txs.values().filter(|t| t.executable).collect();
        v.sort_by(|a, b| {
            b.fee_per_byte()
                .cmp(&a.fee_per_byte())
                .then(a.sender.cmp(&b.sender))
                .then(a.nonce.cmp(&b.nonce))
        });
        v.into_iter().map(|t| t.txid).collect()
    }

    pub fn effective_per_sender(&self) -> usize {
        self.params.effective_per_sender()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &mut self,
        raw: Vec<u8>,
        acct: Account,
        spendable: u128,
        now: u64,
        proof: SigProof,
        observe: &mut dyn FnMut(Condition),
    ) -> Result<Admitted, Reject> {
        let mut fixed = |_: &Address| (acct, spendable);

        let prepared = self.check(raw, AuthorRule::AlreadyHeld, &mut fixed)?;
        self.commit(prepared, proof, now, observe)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_verified(
        &mut self,
        network: Network,
        raw: Vec<u8>,
        lookup: &mut dyn FnMut(&Address) -> (Account, u128),
        now: u64,
        author_pubkey: &[u8; 32],
        observe: &mut dyn FnMut(Condition),
    ) -> Result<Admitted, Reject> {
        let prepared = self.check(raw, AuthorRule::Enforce(author_pubkey), lookup)?;

        let proof = SigProof::verify(network, prepared.tx(), author_pubkey)?;
        self.commit(prepared, proof, now, observe)
    }

    fn check(
        &self,
        raw: Vec<u8>,
        author: AuthorRule<'_>,
        lookup: &mut dyn FnMut(&Address) -> (Account, u128),
    ) -> Result<Prepared, Reject> {
        if raw.len() > MAX_TX_BYTES {
            return Err(Reject::TxTooLarge { got: raw.len() });
        }

        let type_byte = *raw.first().ok_or(Reject::TxDecode)?;
        if type_byte == TX_TYPE_COINBASE {
            return Err(Reject::TxTypeNotRelayable { type_byte });
        }
        let tx = decode_tx(&raw).map_err(|_| Reject::TxDecode)?;
        let (sender_pub, nonce, fee, amount, txid) = match &tx {
            Tx::Transfer(t) => (t.from_pub, t.nonce, t.fee, t.amount, t.txid()),
            Tx::Announcement(a) => (
                a.from_pub,
                a.nonce,
                a.fee,
                0u128,
                a.txid().map_err(|_| Reject::TxDecode)?,
            ),
            Tx::Coinbase(_) => return Err(Reject::TxTypeNotRelayable { type_byte }),
        };
        let sender = crypto::address_payload(&sender_pub);

        if let (Tx::Announcement(a), AuthorRule::Enforce(key)) = (&tx, author) {
            if a.from_pub != *key {
                return Err(Reject::Tx {
                    index: 0,
                    err: plaine_consensus::tx::TxError::NotAuthorKey,
                });
            }
        }

        if fee < FEE_FLOOR_MILE {
            return Err(Reject::BelowRelayFloor {
                fee,
                floor: FEE_FLOOR_MILE,
            });
        }
        if fee < self.params.relay_fee_floor {
            return Err(Reject::BelowRelayFloor {
                fee,
                floor: self.params.relay_fee_floor,
            });
        }

        if self.txs.contains_key(&txid) {
            return Err(Reject::TxKnown);
        }

        let (acct, spendable) = lookup(&sender);
        let next = acct.nonce;
        if nonce < next {
            return Err(Reject::TxStale { next, got: nonce });
        }
        if nonce > next.saturating_add(self.params.max_nonce_gap) {
            return Err(Reject::NonceGapTooLarge { next, got: nonce });
        }

        let replaces = self
            .by_sender
            .get(&sender)
            .and_then(|m| m.get(&nonce).copied());
        let mut displaced_outlay = 0u128;
        if let Some(old_id) = replaces {
            let old = &self.txs[&old_id];
            displaced_outlay = old.amount.saturating_add(old.fee);

            // Replace-by-fee wants +25%, floored at 1 so a zero-quarter fee can't
            // churn the slot for free.
            let bump = (old.fee / 4).max(1);
            let need = old
                .fee
                .checked_add(bump)
                .ok_or(Reject::ArithmeticOverflow)?;
            if fee < need {
                return Err(Reject::ReplacementUnderpriced { need, got: fee });
            }
        }

        let outlay = amount.checked_add(fee).ok_or(Reject::ArithmeticOverflow)?;
        let pending = self
            .pending_outlay(&sender)
            .saturating_sub(displaced_outlay);
        let total = pending
            .checked_add(outlay)
            .ok_or(Reject::ArithmeticOverflow)?;
        if total > spendable {
            return Err(Reject::InsufficientBalance {
                index: 0,
                need: total,
                have: spendable,
            });
        }

        let held = self.sender_len(&sender) - usize::from(replaces.is_some());
        if held >= self.effective_per_sender() {
            return Err(Reject::SenderCap {
                cap: self.effective_per_sender(),
            });
        }
        Ok(Prepared {
            raw,
            tx,
            txid,
            sender,
            nonce,
            fee,
            amount,
            next,
            replaces,
        })
    }

    fn commit(
        &mut self,
        p: Prepared,
        proof: SigProof,
        now: u64,
        observe: &mut dyn FnMut(Condition),
    ) -> Result<Admitted, Reject> {
        let Prepared {
            raw,
            tx: _,
            txid,
            sender,
            nonce,
            fee,
            amount,
            next,
            replaces,
        } = p;

        let expired = self.sweep_expired(now);
        if !expired.is_empty() {
            observe(Condition::MempoolEvicted {
                count: expired.len(),
                reason: EvictReason::Expired,
            });
        }
        let mut removed = Vec::new();

        let displaced = replaces.and_then(|old_id| self.remove(&old_id));
        let incoming_fpb = fee / raw.len().max(1) as u128;
        while self.txs.len() >= self.params.max_txs
            || self.total_bytes + raw.len() > self.params.max_bytes
        {
            let candidate = self.eviction_candidate();
            // Don't evict for a newcomer paying less per byte than the victim.
            let refuse = match candidate {
                None => true,
                Some((victim, _)) => incoming_fpb < self.txs[&victim].fee_per_byte(),
            };
            if refuse {
                if let Some(old) = displaced {
                    self.insert(old);
                    self.resplit(&sender, next);
                }
                return Err(Reject::PoolFull);
            }
            let (victim, reason) = candidate.expect("checked");
            self.remove(&victim);
            removed.push(victim);
            observe(Condition::MempoolEvicted { count: 1, reason });
        }
        if let Some(old_id) = replaces {
            removed.insert(0, old_id);
        }

        self.next_nonce.insert(sender, next);
        let pt = PoolTx {
            txid,
            sender,
            nonce,
            fee,
            amount,
            bytes: raw,
            arrived: now,
            sig_verified: {
                let _ = proof;
                true
            },
            executable: false,
        };
        self.insert(pt);
        let mut promoted = self.resplit(&sender, next);

        promoted.retain(|id| *id != txid);
        let executable = self.txs[&txid].executable;
        Ok(Admitted {
            txid,
            executable,
            promoted,
            removed,
        })
    }

    pub fn tracked_senders(&self) -> usize {
        self.next_nonce.len()
    }

    pub fn sweep_expired(&mut self, now: u64) -> Vec<Hash32> {
        let ttl = self.params.ttl_secs;
        let dead: Vec<Hash32> = self
            .txs
            .values()
            .filter(|t| now.saturating_sub(t.arrived) > ttl)
            .map(|t| t.txid)
            .collect();
        let mut senders: Vec<Address> = Vec::new();
        for id in &dead {
            if let Some(t) = self.txs.get(id) {
                senders.push(t.sender);
            }
            self.remove(id);
        }
        senders.sort_unstable();
        senders.dedup();
        for s in senders {
            let next = self.next_nonce.get(&s).copied().unwrap_or(0);
            self.resplit(&s, next);
        }
        dead
    }

    pub fn on_block_connected(
        &mut self,
        spent: &[(Address, u64)],
        account_nonce: &mut dyn FnMut(&Address) -> Account,
    ) -> usize {
        let mut senders: Vec<Address> = Vec::new();
        let mut n = 0usize;
        for (sender, nonce) in spent {
            if let Some(id) = self
                .by_sender
                .get(sender)
                .and_then(|m| m.get(nonce).copied())
            {
                self.remove(&id);
                n += 1;
            }
            senders.push(*sender);
        }
        senders.sort_unstable();
        senders.dedup();
        for s in senders {
            let next = account_nonce(&s).nonce;
            self.next_nonce.insert(s, next);
            self.drop_below_nonce(&s, next);
            self.resplit(&s, next);
        }
        n
    }

    pub fn on_reorg_reinject(
        &mut self,
        disconnected: &[(u64, Vec<Vec<u8>>)],
        now: u64,
        lookup: &mut dyn FnMut(&Address) -> (Account, u128),
        observe: &mut dyn FnMut(Condition),
    ) -> (usize, usize) {
        let mut ordered: Vec<(u64, &Vec<Vec<u8>>)> =
            disconnected.iter().map(|(h, v)| (*h, v)).collect();

        // Newest disconnected blocks first: likeliest to still be valid on the new tip.
        ordered.sort_by_key(|(h, _)| std::cmp::Reverse(*h));
        let mut taken = 0usize;
        let mut dropped = 0usize;
        let cap = self.params.reorg_reinject_cap;
        for (_, txs) in ordered {
            for raw in txs {
                if taken >= cap {
                    dropped += 1;
                    continue;
                }
                let Ok(tx) = decode_tx(raw) else {
                    dropped += 1;
                    continue;
                };
                let from_pub = match &tx {
                    Tx::Transfer(t) => t.from_pub,
                    Tx::Announcement(a) => a.from_pub,
                    Tx::Coinbase(_) => {
                        continue;
                    }
                };
                let sender = crypto::address_payload(&from_pub);
                let (acct, spendable) = lookup(&sender);

                match self.submit(
                    raw.clone(),
                    acct,
                    spendable,
                    now,
                    SigProof::from_validated_block(),
                    observe,
                ) {
                    Ok(_) => taken += 1,
                    Err(_) => dropped += 1,
                }
            }
        }
        if dropped > 0 {
            observe(Condition::MempoolEvicted {
                count: dropped,
                reason: EvictReason::ReorgOverflow,
            });
        }
        (taken, dropped)
    }

    pub fn resplit_all(&mut self, account: &mut dyn FnMut(&Address) -> Account) {
        let senders: Vec<Address> = self.by_sender.keys().copied().collect();
        for s in senders {
            let next = account(&s).nonce;
            self.next_nonce.insert(s, next);
            self.drop_below_nonce(&s, next);
            self.resplit(&s, next);
        }
    }

    pub fn template(&self, max_txs: usize, max_bytes: usize) -> Vec<Vec<u8>> {
        let mut by_sender: HashMap<Address, Vec<&PoolTx>> = HashMap::new();
        for t in self.txs.values().filter(|t| t.executable) {
            by_sender.entry(t.sender).or_default().push(t);
        }
        let mut chains: Vec<Vec<&PoolTx>> = by_sender.into_values().collect();
        for c in &mut chains {
            c.sort_by_key(|t| t.nonce);
        }
        chains.sort_by(|a, b| {
            b[0].fee_per_byte()
                .cmp(&a[0].fee_per_byte())
                .then(a[0].sender.cmp(&b[0].sender))
        });
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for c in chains {
            for t in c {
                if out.len() >= max_txs || bytes + t.bytes.len() > max_bytes {
                    return out;
                }
                bytes += t.bytes.len();
                out.push(t.bytes.clone());
            }
        }
        out
    }

    fn insert(&mut self, t: PoolTx) {
        self.total_bytes += t.bytes.len();
        self.arrival.push_back(t.txid);
        self.by_sender
            .entry(t.sender)
            .or_default()
            .insert(t.nonce, t.txid);
        self.txs.insert(t.txid, t);
    }

    fn remove(&mut self, id: &Hash32) -> Option<PoolTx> {
        let t = self.txs.remove(id)?;
        self.total_bytes -= t.bytes.len();
        if let Some(m) = self.by_sender.get_mut(&t.sender) {
            m.remove(&t.nonce);
            if m.is_empty() {
                self.by_sender.remove(&t.sender);

                self.next_nonce.remove(&t.sender);
            }
        }
        // TODO: O(n) scan of the arrival queue on every remove.
        self.arrival.retain(|x| x != id);
        Some(t)
    }

    fn drop_below_nonce(&mut self, sender: &Address, next: u64) {
        let stale: Vec<Hash32> = self
            .by_sender
            .get(sender)
            .map(|m| m.range(..next).map(|(_, id)| *id).collect())
            .unwrap_or_default();
        for id in stale {
            self.remove(&id);
        }
    }

    // Executable = the nonce continues the run from the account's next. First gap
    // stops promotion; the rest stay queued until it fills.
    fn resplit(&mut self, sender: &Address, next: u64) -> Vec<Hash32> {
        let Some(map) = self.by_sender.get(sender) else {
            return Vec::new();
        };
        let ids: Vec<(u64, Hash32)> = map.iter().map(|(n, id)| (*n, *id)).collect();
        let mut want = next;
        let mut promoted = Vec::new();
        for (n, id) in ids {
            let exec = n == want;
            if exec {
                want += 1;
            }
            let t = self.txs.get_mut(&id).expect("index and map agree");
            if exec && !t.executable {
                promoted.push(id);
            }
            t.executable = exec;
        }
        promoted
    }

    // Sum of amount+fee a sender has pooled, so admission bounds it against
    // spendable, not per-tx.
    fn pending_outlay(&self, sender: &Address) -> u128 {
        self.by_sender
            .get(sender)
            .map(|m| {
                m.values()
                    .filter_map(|id| self.txs.get(id))
                    .map(|t| t.amount.saturating_add(t.fee))
                    .fold(0u128, |a, b| a.saturating_add(b))
            })
            .unwrap_or(0)
    }

    // Drop a queued tx before an executable one, and within a sender the tail,
    // never the head.
    fn eviction_candidate(&self) -> Option<(Hash32, EvictReason)> {
        let queued = self
            .txs
            .values()
            .filter(|t| !t.executable)
            .min_by(|a, b| {
                a.fee_per_byte()
                    .cmp(&b.fee_per_byte())
                    .then(b.arrived.cmp(&a.arrived))
                    .then(b.txid.cmp(&a.txid))
            })
            .map(|t| t.txid);
        if let Some(id) = queued {
            return Some((id, EvictReason::QueuedLowFee));
        }

        let head = self.txs.values().filter(|t| t.executable).min_by(|a, b| {
            a.fee_per_byte()
                .cmp(&b.fee_per_byte())
                .then(a.sender.cmp(&b.sender))
        })?;
        let sender = head.sender;
        let tail = self.by_sender.get(&sender)?.values().next_back().copied()?;
        Some((tail, EvictReason::ExecutableTail))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct IngressSource {
    own: u64,
    own_last_ms: u64,
    reserve: u64,
    reserve_last_ms: u64,
    primed: bool,
}

#[derive(Clone, Debug)]
pub struct Ingress {
    sources: HashMap<SourceId, IngressSource>,
    shared: u64,
    shared_last_ms: u64,
    primed: bool,
}

impl Ingress {
    pub fn new(_params: &ChainParams) -> Ingress {
        Ingress {
            sources: HashMap::new(),
            shared: 0,
            shared_last_ms: 0,
            primed: false,
        }
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn forget(&mut self, source: SourceId) {
        self.sources.remove(&source);
    }

    pub fn admit(
        &mut self,
        source: SourceId,
        params: &ChainParams,
        mono_ms: u64,
    ) -> Result<(), Reject> {
        let mp = &params.mempool;
        if !self.primed {
            self.primed = true;
            self.shared = mp.ingress_shared_burst_milli();
            self.shared_last_ms = mono_ms;
        } else {
            let elapsed = mono_ms.saturating_sub(self.shared_last_ms);
            let refill = elapsed.saturating_mul(mp.ingress_shared_rate_milli()) / 1_000;
            if refill > 0 {
                self.shared = self
                    .shared
                    .saturating_add(refill)
                    .min(mp.ingress_shared_burst_milli());
                self.shared_last_ms = mono_ms;
            }
        }
        if !self.sources.contains_key(&source) && self.sources.len() >= params.max_sources {
            let reserve_burst = mp.ingress_reserve_burst_milli();
            let own_burst = mp.ingress_source_burst_milli();
            let mut victim = None;
            for (id, s) in self.sources.iter_mut() {
                s.refill(params, mono_ms);
                if victim.is_none() && s.own >= own_burst && s.reserve >= reserve_burst {
                    victim = Some(*id);
                }
            }
            match victim {
                Some(id) => {
                    self.sources.remove(&id);
                }
                None => {
                    return Err(Reject::TooManySources {
                        source,
                        cap: params.max_sources,
                    })
                }
            }
        }
        let st = self.sources.entry(source).or_default();
        st.refill(params, mono_ms);
        if st.own < TX_COST_MILLI {
            return Err(Reject::BudgetExhausted { source });
        }

        // Shared pool first, then the per-source reserve.
        if self.shared >= TX_COST_MILLI {
            self.shared -= TX_COST_MILLI;
        } else if st.reserve >= TX_COST_MILLI {
            st.reserve -= TX_COST_MILLI;
        } else {
            return Err(Reject::BudgetExhausted { source });
        }
        st.own -= TX_COST_MILLI;
        Ok(())
    }
}

impl IngressSource {
    fn refill(&mut self, params: &ChainParams, mono_ms: u64) {
        let mp = &params.mempool;
        if !self.primed {
            self.primed = true;
            self.own = mp.ingress_source_burst_milli();
            self.reserve = mp.ingress_reserve_burst_milli();
            self.own_last_ms = mono_ms;
            self.reserve_last_ms = mono_ms;
            return;
        }
        let elapsed = mono_ms.saturating_sub(self.own_last_ms);
        let refill = elapsed.saturating_mul(mp.ingress_source_rate_milli()) / 1_000;
        if refill > 0 {
            self.own = self
                .own
                .saturating_add(refill)
                .min(mp.ingress_source_burst_milli());
            self.own_last_ms = mono_ms;
        }
        let elapsed = mono_ms.saturating_sub(self.reserve_last_ms);
        let refill =
            elapsed.saturating_mul(mp.ingress_reserve_rate_milli(params.max_peers)) / 1_000;
        if refill > 0 {
            self.reserve = self
                .reserve
                .saturating_add(refill)
                .min(mp.ingress_reserve_burst_milli());
            self.reserve_last_ms = mono_ms;
        }
    }
}

pub fn tx_ingress_exhausted(source: SourceId) -> Condition {
    Condition::BudgetExhausted {
        source,
        class: BudgetClass::TxIngress,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixture::*;

    mod fixture {
        pub use super::super::*;
        use plaine_consensus::codec::TransferTx;

        pub fn transfer(pubkey_byte: u8, nonce: u64, fee: u128, amount: u128) -> Vec<u8> {
            TransferTx {
                from_pub: [pubkey_byte; 32],
                to: [0xAA; 20],
                amount,
                fee,
                nonce,
                sig: [0u8; 64],
            }
            .encode()
            .to_vec()
        }

        pub fn sender_of(pubkey_byte: u8) -> Address {
            plaine_consensus::crypto::address_payload(&[pubkey_byte; 32])
        }

        pub fn rich() -> Account {
            Account {
                balance: u128::MAX / 4,
                nonce: 0,
            }
        }

        pub fn pool() -> Mempool {
            Mempool::new(MempoolParams {
                relay_fee_floor: 1_000_000,
                ..Default::default()
            })
        }

        pub fn noop() -> impl FnMut(Condition) {
            |_| {}
        }

        pub fn proof() -> SigProof {
            SigProof::from_validated_block()
        }
    }

    const FLOOR: u128 = 1_000_000;

    #[test]
    fn nonce_gap_queues_then_promotes_run() {
        let mut p = pool();
        let mut ob = noop();
        let acct = rich();
        for n in [3u64, 2, 1] {
            let a = p
                .submit(
                    transfer(1, n, FLOOR, 1),
                    acct,
                    u128::MAX / 4,
                    0,
                    proof(),
                    &mut ob,
                )
                .expect("queued, not dropped");
            assert!(
                !a.executable,
                "nonce {n} must be queued while the gap is open"
            );
        }
        assert_eq!(p.len(), 3);
        let a = p
            .submit(
                transfer(1, 0, FLOOR, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .expect("the gap filler");
        assert!(a.executable);
        assert_eq!(a.promoted.len(), 3, "whole run promotes at once");
        assert_eq!(p.len(), 4);
        for n in 0..4u64 {
            let id = p.by_sender[&sender_of(1)][&n];
            assert!(
                p.get(&id).unwrap().executable,
                "nonce {n} should be executable"
            );
        }
    }

    #[test]
    fn stale_below_next_gap_beyond_window() {
        let mut p = pool();
        let mut ob = noop();
        let acct = Account {
            balance: u128::MAX / 4,
            nonce: 5,
        };
        assert_eq!(
            p.submit(
                transfer(1, 4, FLOOR, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::TxStale { next: 5, got: 4 })
        );

        assert!(p
            .submit(
                transfer(1, 5 + 256, FLOOR, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            )
            .is_ok());
        assert_eq!(
            p.submit(
                transfer(1, 5 + 257, FLOOR, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::NonceGapTooLarge { next: 5, got: 262 })
        );
    }

    #[test]
    fn effective_per_sender_cap_is_257() {
        let mut p = pool();
        let mut ob = noop();
        let acct = rich();
        assert_eq!(p.effective_per_sender(), 257);
        for n in 0..257u64 {
            p.submit(
                transfer(1, n, FLOOR, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap_or_else(|e| panic!("nonce {n} rejected: {e:?}"));
        }
        assert_eq!(p.sender_len(&sender_of(1)), 257);

        assert!(matches!(
            p.submit(
                transfer(1, 257, FLOOR, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::NonceGapTooLarge { .. })
        ));
    }

    #[test]
    fn replacement_needs_25pct_min_one() {
        let mut p = pool();
        let mut ob = noop();
        let acct = rich();
        let old = 1_000_000u128;
        p.submit(
            transfer(1, 0, old, 1),
            acct,
            u128::MAX / 4,
            0,
            proof(),
            &mut ob,
        )
        .unwrap();
        let bump = old / 4;
        assert_eq!(
            p.submit(
                transfer(1, 0, old + bump - 1, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::ReplacementUnderpriced {
                need: old + bump,
                got: old + bump - 1
            })
        );
        assert!(p
            .submit(
                transfer(1, 0, old + bump, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            )
            .is_ok());
        assert_eq!(p.len(), 1, "one tx per (sender, nonce)");
    }

    #[test]
    fn replacement_floor_stops_free_rotation() {
        let mut params = MempoolParams {
            relay_fee_floor: 1,
            ..Default::default()
        };
        params.max_txs = 100;
        let mut p = Mempool::new(params);
        let mut ob = noop();
        let acct = rich();
        p.submit(
            transfer(1, 0, 3, 1),
            acct,
            u128::MAX / 4,
            0,
            proof(),
            &mut ob,
        )
        .unwrap();
        assert_eq!(
            p.submit(
                transfer(1, 0, 3, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::TxKnown),
            "identical bytes are a duplicate, not a replacement"
        );
        assert_eq!(
            p.submit(
                transfer(1, 0, 3, 2),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::ReplacementUnderpriced { need: 4, got: 3 })
        );
        assert!(p
            .submit(
                transfer(1, 0, 4, 2),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            )
            .is_ok());
    }

    #[test]
    fn full_pool_still_admits_floor_priced() {
        let mut params = MempoolParams {
            max_txs: 20,
            relay_fee_floor: FLOOR,
            ..Default::default()
        };
        params.max_bytes = 1 << 20;
        let mut p = Mempool::new(params);
        let mut ob = noop();
        let acct = rich();

        for n in 1..=20u64 {
            p.submit(
                transfer(1, n, FLOOR, 1),
                acct,
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        }
        assert_eq!(p.len(), 20);

        let a = p
            .submit(
                transfer(2, 0, FLOOR, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .expect("tie evicts a queued tx");
        assert!(a.executable);
        assert_eq!(a.removed.len(), 1);
        assert_eq!(p.len(), 20);

        assert_eq!(
            p.submit(
                transfer(3, 0, FLOOR - 1, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::BelowRelayFloor {
                fee: FLOOR - 1,
                floor: FLOOR
            })
        );

        let mut cheap = Mempool::new(MempoolParams {
            max_txs: 2,
            relay_fee_floor: 1,
            max_bytes: 1 << 20,
            ..Default::default()
        });
        cheap
            .submit(
                transfer(1, 1, 1_000, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        cheap
            .submit(
                transfer(1, 2, 1_000, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        assert_eq!(
            cheap.submit(
                transfer(2, 0, 10, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::PoolFull)
        );
    }

    #[test]
    fn eviction_never_takes_an_executable_head() {
        const B: u128 = 157;
        let mut params = MempoolParams {
            max_txs: 6,
            relay_fee_floor: 1,
            max_bytes: 1 << 20,
            ..Default::default()
        };
        params.max_nonce_gap = 256;
        let mut p = Mempool::new(params);
        let mut ob = noop();

        for n in 0..4u64 {
            p.submit(
                transfer(1, n, 10 * B, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        }

        for n in 5..7u64 {
            p.submit(
                transfer(2, n, B, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        }
        assert_eq!(p.len(), 6);

        let a = p
            .submit(
                transfer(3, 0, 100 * B, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        assert_eq!(a.removed.len(), 1);
        let gone = a.removed[0];
        assert_eq!(p.get(&gone), None);
        assert_eq!(
            p.sender_len(&sender_of(1)),
            4,
            "the executable chain is untouched"
        );

        let b = p
            .submit(
                transfer(4, 0, 100 * B, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        assert_eq!(b.removed.len(), 1);
        assert_eq!(
            p.sender_len(&sender_of(2)),
            0,
            "queued go before executable"
        );
        assert_eq!(p.sender_len(&sender_of(1)), 4);
        let c = p
            .submit(
                transfer(5, 0, 100 * B, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        assert_eq!(c.removed.len(), 1);

        let s1 = &p.by_sender[&sender_of(1)];
        assert!(s1.contains_key(&0), "the head must survive");
        assert!(!s1.contains_key(&3), "the tail is what goes");
        assert_eq!(s1.len(), 3);
    }

    #[test]
    fn ttl_sweep_is_independent_of_pressure() {
        let mut params = MempoolParams {
            ttl_secs: 100,
            relay_fee_floor: 1,
            ..Default::default()
        };
        params.max_txs = 1000;
        let mut p = Mempool::new(params);
        let mut ob = noop();
        p.submit(
            transfer(1, 0, 10, 1),
            rich(),
            u128::MAX / 4,
            0,
            proof(),
            &mut ob,
        )
        .unwrap();
        assert_eq!(p.sweep_expired(100), Vec::<Hash32>::new());
        assert_eq!(p.sweep_expired(101).len(), 1);
        assert!(p.is_empty());
    }

    #[test]
    fn connected_block_removes_by_sender_nonce() {
        let mut p = pool();
        let mut ob = noop();
        for n in 0..4u64 {
            p.submit(
                transfer(1, n, FLOOR, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        }
        let s = sender_of(1);
        let mut acct = |_: &Address| Account {
            balance: u128::MAX / 4,
            nonce: 2,
        };
        let n = p.on_block_connected(&[(s, 0), (s, 1)], &mut acct);
        assert_eq!(n, 2);
        assert_eq!(p.len(), 2);
        let id2 = p.by_sender[&s][&2];
        assert!(p.get(&id2).unwrap().executable);
    }

    #[test]
    fn reorg_backwards_requeues_without_loss() {
        let mut p = pool();
        let mut ob = noop();
        let s = sender_of(1);

        for n in 5..9u64 {
            p.submit(
                transfer(1, n, FLOOR, 1),
                Account {
                    balance: u128::MAX / 4,
                    nonce: 5,
                },
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        }
        assert_eq!(p.txs.values().filter(|t| t.executable).count(), 4);

        let mut acct = |_: &Address| Account {
            balance: u128::MAX / 4,
            nonce: 3,
        };
        p.resplit_all(&mut acct);
        assert_eq!(p.len(), 4);
        assert_eq!(p.txs.values().filter(|t| t.executable).count(), 0);
        assert_eq!(p.sender_len(&s), 4);

        let mut acct5 = |_: &Address| Account {
            balance: u128::MAX / 4,
            nonce: 5,
        };
        p.resplit_all(&mut acct5);
        assert_eq!(p.txs.values().filter(|t| t.executable).count(), 4);
    }

    #[test]
    fn reinject_capped_highest_heights_first() {
        let mut params = MempoolParams {
            reorg_reinject_cap: 3,
            relay_fee_floor: 1,
            max_txs: 1000,
            ..Default::default()
        };
        params.max_bytes = 1 << 20;
        let mut p = Mempool::new(params);
        let mut ob = noop();

        let low = (10u64, vec![transfer(1, 0, 10, 1), transfer(1, 1, 10, 1)]);
        let high = (11u64, vec![transfer(2, 0, 10, 1), transfer(2, 1, 10, 1)]);
        let mut lookup = |_: &Address| {
            (
                Account {
                    balance: u128::MAX / 4,
                    nonce: 0,
                },
                u128::MAX / 4,
            )
        };
        let (taken, dropped) = p.on_reorg_reinject(&[low, high], 0, &mut lookup, &mut ob);
        assert_eq!(taken, 3, "the cap binds");
        assert_eq!(dropped, 1);

        assert_eq!(
            p.sender_len(&sender_of(2)),
            2,
            "the newest block is re-injected whole"
        );
        assert_eq!(p.sender_len(&sender_of(1)), 1);

        for t in p.txs.values() {
            assert!(t.sig_verified);
        }
    }

    #[test]
    fn reinject_runs_balance_check() {
        let mut params = MempoolParams {
            reorg_reinject_cap: 10,
            relay_fee_floor: 1,
            ..Default::default()
        };
        params.max_txs = 100;
        let mut p = Mempool::new(params);
        let mut ob = noop();

        let mut lookup = |_: &Address| {
            (
                Account {
                    balance: 0,
                    nonce: 0,
                },
                0u128,
            )
        };
        let (taken, dropped) = p.on_reorg_reinject(
            &[(9u64, vec![transfer(1, 0, 10, 1_000)])],
            0,
            &mut lookup,
            &mut ob,
        );
        assert_eq!((taken, dropped), (0, 1));
        assert!(p.is_empty());
    }

    #[test]
    fn coinbase_is_never_pooled() {
        let mut p = pool();
        let mut ob = noop();
        assert_eq!(
            p.submit(vec![0x00, 1, 2, 3], rich(), u128::MAX, 0, proof(), &mut ob),
            Err(Reject::TxTypeNotRelayable { type_byte: 0x00 })
        );
        assert_eq!(
            p.submit(vec![0x7F, 1, 2, 3], rich(), u128::MAX, 0, proof(), &mut ob),
            Err(Reject::TxDecode)
        );
    }

    #[test]
    fn consensus_fee_floor_below_policy() {
        let mut p = pool();
        let mut ob = noop();
        assert!(matches!(
            p.submit(
                transfer(1, 0, 0, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::BelowRelayFloor { fee: 0, floor: 1 })
        ));
        assert!(matches!(
            p.submit(
                transfer(1, 0, 999_999, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob
            ),
            Err(Reject::BelowRelayFloor {
                fee: 999_999,
                floor: 1_000_000
            })
        ));
    }

    #[test]
    fn pending_outlay_bounds_sender() {
        let mut params = MempoolParams {
            relay_fee_floor: 1,
            ..Default::default()
        };
        params.max_txs = 100;
        let mut p = Mempool::new(params);
        let mut ob = noop();
        let acct = Account {
            balance: 100,
            nonce: 0,
        };
        p.submit(transfer(1, 0, 1, 60), acct, 100, 0, proof(), &mut ob)
            .unwrap();

        assert!(matches!(
            p.submit(transfer(1, 1, 1, 39), acct, 100, 0, proof(), &mut ob),
            Err(Reject::InsufficientBalance {
                index: 0,
                need: 101,
                have: 100
            })
        ));
        assert!(p
            .submit(transfer(1, 1, 1, 38), acct, 100, 0, proof(), &mut ob)
            .is_ok());
    }

    #[test]
    fn byte_cap_cannot_bind_via_admission() {
        let params = MempoolParams::default();
        let worst = 257 * 1_148 + (params.max_txs - 257) * 157;
        assert!(
            worst < params.max_bytes,
            "reachable worst case {worst} vs cap {}",
            params.max_bytes
        );
        let mut p = Mempool::new(params);
        let mut ob = noop();
        p.submit(
            transfer(1, 0, FLOOR, 1),
            rich(),
            u128::MAX / 4,
            0,
            proof(),
            &mut ob,
        )
        .unwrap();
        assert_eq!(p.bytes(), 157);
        p.sweep_expired(u64::MAX);
        assert_eq!(p.bytes(), 0, "byte accounting returns to zero");
    }

    #[test]
    fn template_greedy_fpb_respects_nonce() {
        let mut params = MempoolParams {
            relay_fee_floor: 1,
            ..Default::default()
        };
        params.max_txs = 100;
        let mut p = Mempool::new(params);
        let mut ob = noop();
        for n in 0..3u64 {
            p.submit(
                transfer(1, n, 10, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        }
        for n in 0..2u64 {
            p.submit(
                transfer(2, n, 1_000, 1),
                rich(),
                u128::MAX / 4,
                0,
                proof(),
                &mut ob,
            )
            .unwrap();
        }
        let t = p.template(4_096, 1 << 20);
        assert_eq!(t.len(), 5);

        let first = decode_tx(&t[0]).unwrap();
        match first {
            Tx::Transfer(x) => {
                assert_eq!(x.fee, 1_000);
                assert_eq!(x.nonce, 0);
            }
            _ => panic!("expected a transfer"),
        }
    }
}
