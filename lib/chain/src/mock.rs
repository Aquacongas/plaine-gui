use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use plaine_consensus::codec::{AuthorNote, BlockBody, CoinbaseTx, Header, TransferTx};
use plaine_consensus::constants::{BLOCK_TIME_SECS, HEADER_BYTES, VERSION_BASE};
use plaine_consensus::crypto;
use plaine_consensus::emission;
use plaine_consensus::merkle;
use plaine_consensus::rules::work_from_target;

use crate::traits::{Clock, PowVerifier, Sink, SinkError, Store};
use crate::types::{
    Account, Address, ChainParams, CommitBlock, DeepReorgCommit, Hash32, HeaderRec, Receipt,
    ReorgCommit, SideHeaderRec, SignedCheckpoint, TipRef, UndoRec, Work,
};
use crate::work::{expand_bits, target_to_be};

#[derive(Default)]
struct Inner {
    canonical: Vec<HeaderRec>,
    chainwork: Vec<Work>,
    issued_at: Vec<u128>,
    bodies: HashMap<Hash32, Vec<u8>>,
    side: HashMap<Hash32, HeaderRec>,
    accounts: HashMap<Address, Account>,
    undo: BTreeMap<u64, Vec<UndoRec>>,
    snapshots: BTreeMap<u64, Vec<(Address, Account)>>,
    invalid: HashSet<Hash32>,
    anchor_record: Option<Vec<u8>>,
    fail_next_anchor: Option<SinkError>,
    issued: u128,
    undo_window: u64,
    replay_floor: u64,
    snapshot_interval: u64,
    fail_next_commit: Option<SinkError>,
    tip_regression: u64,
    commits: u64,
    side_headers_written: u64,
    hide_side_headers: bool,
}

pub struct MemStore {
    inner: Mutex<Inner>,
}

impl MemStore {
    pub fn with_genesis(rec: HeaderRec, body: Vec<u8>, params: &ChainParams) -> MemStore {
        let w = expand_bits(rec.bits, &params.pow_limit)
            .map(|t| work_from_target(&target_to_be(&t)))
            .expect("genesis bits are a legal target");
        let mut inner = Inner {
            undo_window: 256,
            snapshot_interval: 0,
            ..Default::default()
        };
        inner.bodies.insert(rec.hash, body);
        inner.canonical.push(rec);
        inner.chainwork.push(w);
        inner.issued_at.push(0);
        MemStore {
            inner: Mutex::new(inner),
        }
    }

    pub fn commit_count(&self) -> u64 {
        self.inner.lock().expect("mock lock").commits
    }

    pub fn side_headers_written(&self) -> u64 {
        self.inner.lock().expect("mock lock").side_headers_written
    }

    pub fn anchor_record(&self) -> Option<Vec<u8>> {
        self.inner.lock().expect("mock lock").anchor_record.clone()
    }

    pub fn fail_next_anchor(&self, e: SinkError) {
        self.inner.lock().expect("mock lock").fail_next_anchor = Some(e);
    }

    pub fn poison_anchor_record(&self) {
        self.inner.lock().expect("mock lock").anchor_record = Some(b"POISON".to_vec());
    }

    pub fn hide_side_headers(&self) {
        self.inner.lock().expect("mock lock").hide_side_headers = true;
    }

    pub fn evict_side_below(&self, height: u64) {
        self.inner
            .lock()
            .expect("mock lock")
            .side
            .retain(|_, r| r.height >= height);
    }

    pub fn fail_next_commit(&self, e: SinkError) {
        self.inner.lock().expect("mock lock").fail_next_commit = Some(e);
    }

    pub fn set_tip_regression(&self, n: u64) {
        self.inner.lock().expect("mock lock").tip_regression = n;
    }

    pub fn set_undo_window(&self, n: u64) {
        let mut g = self.inner.lock().expect("mock lock");
        g.undo_window = n;
        let tip = g.canonical.len().saturating_sub(1) as u64;
        let floor = tip.saturating_sub(n);
        g.undo.retain(|h, _| *h > floor);
    }

    pub fn set_account(&self, addr: Address, acct: Account) {
        self.inner
            .lock()
            .expect("mock lock")
            .accounts
            .insert(addr, acct);
    }

    pub fn set_snapshot_interval(&self, n: u64) {
        self.inner.lock().expect("mock lock").snapshot_interval = n;
    }

    pub fn set_replay_floor(&self, n: u64) {
        self.inner.lock().expect("mock lock").replay_floor = n;
    }

    pub fn snapshot_now(&self, height: u64) {
        let mut g = self.inner.lock().expect("mock lock");
        let rows: Vec<(Address, Account)> = g.accounts.iter().map(|(a, b)| (*a, *b)).collect();
        g.snapshots.insert(height, rows);
    }

    pub fn account_table(&self) -> BTreeMap<Address, Account> {
        self.inner
            .lock()
            .expect("mock lock")
            .accounts
            .iter()
            .filter(|(_, a)| !a.is_absent())
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    pub fn canonical_hashes(&self) -> Vec<Hash32> {
        self.inner
            .lock()
            .expect("mock lock")
            .canonical
            .iter()
            .map(|r| r.hash)
            .collect()
    }

    pub fn stored_chainwork(&self) -> Vec<Work> {
        self.inner.lock().expect("mock lock").chainwork.clone()
    }

    fn apply_commit(g: &mut Inner, b: &CommitBlock) {
        debug_assert_eq!(
            b.deltas.len(),
            b.undo.len(),
            "deltas and undo must be aligned"
        );
        for d in &b.deltas {
            let acct = Account {
                balance: d.balance,
                nonce: d.nonce,
            };
            if acct.is_absent() {
                g.accounts.remove(&d.addr);
            } else {
                g.accounts.insert(d.addr, acct);
            }
        }
        g.undo.insert(b.height, b.undo.clone());
        g.bodies.insert(b.hash, b.body.clone());
        g.side.remove(&b.hash);
        let rec = HeaderRec::from_raw(b.header_raw);
        if b.height as usize == g.canonical.len() {
            g.canonical.push(rec);
            g.chainwork.push(b.chainwork);
            g.issued_at.push(b.issued_delta);
        } else {
            g.canonical[b.height as usize] = rec;
            g.chainwork[b.height as usize] = b.chainwork;
            g.issued_at[b.height as usize] = b.issued_delta;
        }
        g.issued = g.issued.saturating_add(b.issued_delta);
        if g.snapshot_interval > 0 && b.height % g.snapshot_interval == 0 {
            let rows: Vec<(Address, Account)> = g.accounts.iter().map(|(a, b)| (*a, *b)).collect();
            g.snapshots.insert(b.height, rows);
        }
        // Keep only the last undo_window heights, like a store that prunes deep history.
        let tip = g.canonical.len().saturating_sub(1) as u64;
        let floor = tip.saturating_sub(g.undo_window);
        g.undo.retain(|h, _| *h > floor);
    }

    fn rollback_one(g: &mut Inner, height: u64) -> Result<(), SinkError> {
        let recs = g
            .undo
            .remove(&height)
            .ok_or(SinkError::Invalid("undo records pruned for that height"))?;
        for r in &recs {
            let prev = Account {
                balance: r.prev_balance,
                nonce: r.prev_nonce,
            };
            if !r.existed && prev.is_absent() {
                g.accounts.remove(&r.addr);
            } else {
                g.accounts.insert(r.addr, prev);
            }
        }
        if let Some(rec) = g.canonical.pop() {
            g.side.insert(rec.hash, rec);
        }
        g.chainwork.pop();
        if let Some(i) = g.issued_at.pop() {
            g.issued = g.issued.saturating_sub(i);
        }
        Ok(())
    }

    fn take_failure(g: &mut Inner) -> Option<SinkError> {
        g.fail_next_commit.take()
    }
}

impl Store for MemStore {
    fn tip(&self) -> TipRef {
        let g = self.inner.lock().expect("mock lock");
        let real = g.canonical.len().saturating_sub(1) as u64;
        let h = real.saturating_sub(g.tip_regression);
        let rec = g.canonical[h as usize];
        TipRef {
            height: h,
            hash: rec.hash,
            time: rec.time,
            chainwork: g.chainwork[h as usize],
        }
    }
    fn header_at(&self, height: u64) -> Option<HeaderRec> {
        self.inner
            .lock()
            .expect("mock lock")
            .canonical
            .get(height as usize)
            .copied()
    }
    fn header_by_hash(&self, h: &Hash32) -> Option<HeaderRec> {
        let g = self.inner.lock().expect("mock lock");
        g.canonical
            .iter()
            .find(|r| r.hash == *h)
            .copied()
            .or_else(|| g.side.get(h).copied())
    }
    fn hash_at(&self, height: u64) -> Option<Hash32> {
        self.header_at(height).map(|r| r.hash)
    }
    fn body_at(&self, height: u64) -> Option<Vec<u8>> {
        let g = self.inner.lock().expect("mock lock");
        let rec = g.canonical.get(height as usize)?;
        g.bodies.get(&rec.hash).cloned()
    }
    fn body_by_hash(&self, h: &Hash32) -> Option<Vec<u8>> {
        self.inner.lock().expect("mock lock").bodies.get(h).cloned()
    }
    fn account(&self, addr: &Address) -> Account {
        self.inner
            .lock()
            .expect("mock lock")
            .accounts
            .get(addr)
            .copied()
            .unwrap_or_default()
    }
    fn undo_at(&self, height: u64) -> Option<Vec<UndoRec>> {
        self.inner
            .lock()
            .expect("mock lock")
            .undo
            .get(&height)
            .cloned()
    }
    fn undo_floor(&self) -> u64 {
        let g = self.inner.lock().expect("mock lock");
        g.undo.keys().next().copied().unwrap_or(0)
    }
    fn replay_floor(&self) -> u64 {
        self.inner.lock().expect("mock lock").replay_floor
    }
    fn checkpoint_at_or_below(&self, height: u64) -> Option<u64> {
        self.inner
            .lock()
            .expect("mock lock")
            .snapshots
            .range(..=height)
            .next_back()
            .map(|(h, _)| *h)
    }
    fn state_snapshot(&self, height: u64) -> Option<Vec<(Address, Account)>> {
        self.inner
            .lock()
            .expect("mock lock")
            .snapshots
            .get(&height)
            .cloned()
    }
    fn issued(&self) -> u128 {
        self.inner.lock().expect("mock lock").issued
    }
    fn is_invalid(&self, h: &Hash32) -> bool {
        self.inner.lock().expect("mock lock").invalid.contains(h)
    }
    fn headers_range(&self, from: u64, max: usize) -> Vec<[u8; HEADER_BYTES]> {
        let g = self.inner.lock().expect("mock lock");
        g.canonical
            .iter()
            .skip(from as usize)
            .take(max)
            .map(|r| r.raw)
            .collect()
    }

    fn side_headers_from(&self, from: u64, max: usize) -> Vec<HeaderRec> {
        let g = self.inner.lock().expect("mock lock");
        if g.hide_side_headers {
            return Vec::new();
        }
        let mut v: Vec<HeaderRec> = g
            .side
            .values()
            .filter(|r| r.height >= from)
            .copied()
            .collect();
        v.sort_by_key(|r| (r.height, r.hash));
        v.truncate(max);
        v
    }
}

impl Sink for MemStore {
    fn commit_block(&self, b: &CommitBlock) -> Result<Receipt, SinkError> {
        let mut g = self.inner.lock().expect("mock lock");
        if let Some(e) = MemStore::take_failure(&mut g) {
            return Err(e);
        }
        MemStore::apply_commit(&mut g, b);
        g.commits += 1;
        let h = g.canonical.len() - 1;
        Ok(Receipt {
            tip: TipRef {
                height: h as u64,
                hash: g.canonical[h].hash,
                time: g.canonical[h].time,
                chainwork: g.chainwork[h],
            },
        })
    }

    fn commit_reorg(&self, p: &ReorgCommit) -> Result<Receipt, SinkError> {
        let mut g = self.inner.lock().expect("mock lock");
        if let Some(e) = MemStore::take_failure(&mut g) {
            return Err(e);
        }

        for w in p.rollback.windows(2) {
            assert!(w[0] > w[1], "rollback heights must be strictly descending");
        }
        for h in &p.rollback {
            MemStore::rollback_one(&mut g, *h)?;
        }
        for b in &p.apply {
            MemStore::apply_commit(&mut g, b);
        }
        g.commits += 1;
        let h = g.canonical.len() - 1;
        Ok(Receipt {
            tip: TipRef {
                height: h as u64,
                hash: g.canonical[h].hash,
                time: g.canonical[h].time,
                chainwork: g.chainwork[h],
            },
        })
    }

    fn commit_deep_reorg(&self, p: &DeepReorgCommit) -> Result<Receipt, SinkError> {
        let mut g = self.inner.lock().expect("mock lock");
        if let Some(e) = MemStore::take_failure(&mut g) {
            return Err(e);
        }
        let rows = g
            .snapshots
            .get(&p.rewind_to)
            .cloned()
            .ok_or(SinkError::Invalid("no state snapshot at rewind_to"))?;
        g.accounts.clear();
        g.accounts.extend(rows);
        while g.canonical.len() as u64 > p.rewind_to + 1 {
            if let Some(rec) = g.canonical.pop() {
                g.side.insert(rec.hash, rec);
            }
            g.chainwork.pop();
            if let Some(i) = g.issued_at.pop() {
                g.issued = g.issued.saturating_sub(i);
            }
        }
        g.undo.retain(|h, _| *h <= p.rewind_to);
        for b in &p.apply {
            MemStore::apply_commit(&mut g, b);
        }
        g.commits += 1;
        let h = g.canonical.len() - 1;
        Ok(Receipt {
            tip: TipRef {
                height: h as u64,
                hash: g.canonical[h].hash,
                time: g.canonical[h].time,
                chainwork: g.chainwork[h],
            },
        })
    }

    fn store_side_header(&self, h: &SideHeaderRec) -> Result<(), SinkError> {
        let mut g = self.inner.lock().expect("mock lock");
        g.side.insert(h.rec.hash, h.rec);
        g.side_headers_written += 1;
        Ok(())
    }

    fn mark_invalid(&self, h: &Hash32) -> Result<(), SinkError> {
        self.inner.lock().expect("mock lock").invalid.insert(*h);
        Ok(())
    }

    fn put_anchor(&self, cp: &SignedCheckpoint) -> Result<(), SinkError> {
        let mut g = self.inner.lock().expect("mock lock");
        if let Some(e) = g.fail_next_anchor.take() {
            return Err(e);
        }

        g.anchor_record = Some(plaine_consensus::checkpoint_record::encode(cp));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowMode {
    AlwaysOk,
    AlwaysFail,
    AllButListed,
}

pub struct CountingPow {
    mode: Mutex<PowMode>,
    reject: Mutex<HashSet<Hash32>>,
    calls: AtomicU64,
    cost: AtomicU64,
}

impl CountingPow {
    pub fn new(mode: PowMode) -> CountingPow {
        CountingPow {
            mode: Mutex::new(mode),
            reject: Mutex::new(HashSet::new()),
            calls: AtomicU64::new(0),
            cost: AtomicU64::new(3_000),
        }
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.calls.store(0, Ordering::SeqCst);
    }

    pub fn set_mode(&self, m: PowMode) {
        *self.mode.lock().expect("mock lock") = m;
    }

    pub fn reject_hash(&self, h: Hash32) {
        self.reject.lock().expect("mock lock").insert(h);
    }

    pub fn set_cost_micros(&self, c: u64) {
        self.cost.store(c, Ordering::SeqCst);
    }
}

impl PowVerifier for CountingPow {
    fn verify(&self, hdr: &[u8; HEADER_BYTES]) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mode = *self.mode.lock().expect("mock lock");
        match mode {
            PowMode::AlwaysOk => true,
            PowMode::AlwaysFail => false,
            PowMode::AllButListed => !self
                .reject
                .lock()
                .expect("mock lock")
                .contains(&crypto::header_hash(hdr)),
        }
    }
    fn cost_micros(&self) -> u64 {
        self.cost.load(Ordering::SeqCst)
    }
}

pub struct MockClock {
    unix: AtomicU64,
    mono: AtomicU64,
}

impl MockClock {
    pub fn new(unix: u64) -> MockClock {
        MockClock {
            unix: AtomicU64::new(unix),
            mono: AtomicU64::new(0),
        }
    }

    pub fn set_unix(&self, t: u64) {
        self.unix.store(t, Ordering::SeqCst);
    }

    pub fn advance_ms(&self, d: u64) {
        self.mono.fetch_add(d, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now_unix(&self) -> u64 {
        self.unix.load(Ordering::SeqCst)
    }
    fn mono_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug)]
pub struct BuiltBlock {
    pub rec: HeaderRec,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct Scenario {
    pub blocks: Vec<BuiltBlock>,
    params: ChainParams,
    pub miner: Address,
    spacing: u64,
}

pub fn miner_addr() -> Address {
    crypto::address_payload(&[0x33; 32])
}

impl Scenario {
    pub fn genesis(params: &ChainParams, t0: u64) -> Scenario {
        let mut s = Scenario {
            blocks: Vec::new(),
            params: params.clone(),
            miner: miner_addr(),
            spacing: BLOCK_TIME_SECS,
        };
        let body = s.body_for(0, &[], 0);
        let tx_root = body_root(&body);
        let hdr = Header {
            version: VERSION_BASE,
            height: 0,
            prev_hash: [0u8; 32],
            tx_root,
            ext_root: [0u8; 32],
            time: t0,
            bits: params.genesis_bits,
            author_note_len: 0,
            nonce: 0,
        };
        s.blocks.push(BuiltBlock {
            rec: HeaderRec::from_raw(hdr.encode()),
            body,
        });
        s
    }

    pub fn genesis_rec(&self) -> HeaderRec {
        self.blocks[0].rec
    }

    pub fn tip(&self) -> HeaderRec {
        self.blocks.last().expect("genesis always exists").rec
    }

    pub fn height(&self) -> u64 {
        self.tip().height
    }

    pub fn fork_at(&self, at: u64) -> Scenario {
        let mut s = self.clone();
        s.blocks.truncate(at as usize + 1);
        s
    }

    pub fn spacing(mut self, secs: u64) -> Scenario {
        self.spacing = secs;
        self
    }

    pub fn extend(mut self, n: u64) -> Scenario {
        for _ in 0..n {
            self.push_block(&[]);
        }
        self
    }

    pub fn push_block(&mut self, txs: &[Vec<u8>]) -> BuiltBlock {
        self.push_block_with(txs, |h| h)
    }

    pub fn push_block_with(
        &mut self,
        txs: &[Vec<u8>],
        tweak: impl Fn(Header) -> Header,
    ) -> BuiltBlock {
        let parent = self.tip();
        let height = parent.height + 1;
        let fees: u128 = txs.iter().filter_map(|t| tx_fee(t)).sum();
        let body = self.body_for(height, txs, fees);
        let tx_root = body_root(&body);
        let bits = self.expected_bits(parent.height);
        let hdr = tweak(Header {
            version: VERSION_BASE,
            height,
            prev_hash: parent.hash,
            tx_root,
            ext_root: [0u8; 32],
            time: parent.time + self.spacing,
            bits,
            author_note_len: 0,
            nonce: 0,
        });
        let b = BuiltBlock {
            rec: HeaderRec::from_raw(hdr.encode()),
            body,
        };
        self.blocks.push(b.clone());
        b
    }

    pub fn corrupt_tip_body(&mut self, body: Vec<u8>) {
        self.blocks.last_mut().expect("genesis exists").body = body;
    }

    pub fn push_body(&mut self, body: Vec<u8>) -> BuiltBlock {
        self.push_body_with(body, |h| h)
    }

    pub fn push_body_with(
        &mut self,
        body: Vec<u8>,
        tweak: impl Fn(Header) -> Header,
    ) -> BuiltBlock {
        let parent = self.tip();
        let height = parent.height + 1;
        let tx_root = body_root(&body);
        let bits = self.expected_bits(parent.height);
        let hdr = tweak(Header {
            version: VERSION_BASE,
            height,
            prev_hash: parent.hash,
            tx_root,
            ext_root: [0u8; 32],
            time: parent.time + self.spacing,
            bits,
            author_note_len: 0,
            nonce: 0,
        });
        let b = BuiltBlock {
            rec: HeaderRec::from_raw(hdr.encode()),
            body,
        };
        self.blocks.push(b.clone());
        b
    }

    pub fn with_miner(mut self, m: Address) -> Scenario {
        self.miner = m;
        self
    }

    pub fn coinbase_bytes(
        height: u64,
        to: Address,
        reward: u128,
        fees: u128,
        note: Vec<u8>,
    ) -> Vec<u8> {
        CoinbaseTx {
            height,
            to,
            reward,
            fees,
            note: AuthorNote {
                encoding: 0,
                payload: note,
            },
        }
        .encode()
        .expect("note length is the caller's business")
    }

    pub fn normal_coinbase(&self, height: u64, fees: u128) -> Vec<u8> {
        Scenario::coinbase_bytes(
            height,
            self.miner,
            emission::block_reward(height),
            fees,
            Vec::new(),
        )
    }

    pub fn encode_body(txs: &[&[u8]]) -> Vec<u8> {
        BlockBody::encode(txs).expect("test body fits")
    }

    pub fn expected_bits(&self, parent_height: u64) -> u32 {
        let interval = self.params.asert_anchor_interval;
        let ah = crate::work::anchor_height_for(parent_height, interval);
        let anchor = self.blocks[ah as usize].rec;
        let anchor_parent_time = if ah == 0 {
            self.blocks[0].rec.time.saturating_sub(BLOCK_TIME_SECS)
        } else {
            self.blocks[ah as usize - 1].rec.time
        };
        let parent = self.blocks[parent_height as usize].rec;
        crate::work::expected_child_bits(
            anchor.bits,
            ah,
            anchor_parent_time,
            parent.height,
            parent.time,
            &self.params.pow_limit,
        )
        .expect("anchor is at or below the parent")
    }

    pub fn raw_headers(&self) -> Vec<[u8; HEADER_BYTES]> {
        self.blocks.iter().map(|b| b.rec.raw).collect()
    }

    pub fn raw_headers_from(&self, from: u64) -> Vec<[u8; HEADER_BYTES]> {
        self.blocks
            .iter()
            .skip(from as usize)
            .map(|b| b.rec.raw)
            .collect()
    }

    fn body_for(&self, height: u64, txs: &[Vec<u8>], fees: u128) -> Vec<u8> {
        let cb = CoinbaseTx {
            height,
            to: self.miner,
            reward: emission::block_reward(height),
            fees,
            note: AuthorNote {
                encoding: 0,
                payload: Vec::new(),
            },
        };
        let cb_bytes = cb.encode().expect("note is empty");
        let mut all: Vec<&[u8]> = vec![&cb_bytes];
        for t in txs {
            all.push(t);
        }
        BlockBody::encode(&all).expect("body fits")
    }
}

pub fn body_root(raw: &[u8]) -> Hash32 {
    let body = BlockBody::parse(raw).expect("we just encoded it");
    body.tx_root()
}

fn tx_fee(raw: &[u8]) -> Option<u128> {
    plaine_consensus::codec::decode_tx(raw)
        .ok()
        .map(|t| t.fee())
}

pub fn root_of(txs: &[&[u8]]) -> Hash32 {
    merkle::tx_root(txs)
}

pub fn unsigned_transfer(
    from_pub: [u8; 32],
    to: Address,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> Vec<u8> {
    TransferTx {
        from_pub,
        to,
        amount,
        fee,
        nonce,
        sig: [0u8; 64],
    }
    .encode()
    .to_vec()
}
