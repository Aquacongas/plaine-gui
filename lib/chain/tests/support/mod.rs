#![allow(dead_code)]

pub const TEST_NETWORK: plaine_consensus::constants::Network =
    plaine_consensus::constants::Network::Main;

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};

use plaine_chain::error::Condition;
use plaine_chain::mock::{CountingPow, MemStore, MockClock, PowMode, Scenario};
use plaine_chain::types::{Address, ChainParams, HeaderRec};
#[allow(unused_imports)]
pub use plaine_chain::{ChainManager, Clock, Solicitation, Store, TxOrigin};

pub struct Rig {
    pub store: Arc<MemStore>,
    pub pow: Arc<CountingPow>,
    pub clock: Arc<MockClock>,
    pub cm: ChainManager<MemStore, MemStore, CountingPow, MockClock>,
    pub conds: Arc<Mutex<Vec<Condition>>>,
    pub params: ChainParams,
}

pub const T0: u64 = 1_700_000_000;

pub fn params() -> ChainParams {
    let mut p = ChainParams {
        author_pubkey: author_key().verifying_key().to_bytes(),
        authority_keys: vec![authority_key().verifying_key().to_bytes()],
        checkpoint_threshold: 1,
        ..ChainParams::default()
    };
    // the budget and ingress tests use fee-1 transfers as a marker that a tx
    // cleared the earlier gates and then bounced off the relay floor, so the
    // harness pins a floor above 1. The shipped default is 1 (the consensus
    // floor); that is exercised by the mempool unit tests instead.
    p.mempool.relay_fee_floor = 1_000_000;
    p
}

pub fn author_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

pub fn impostor_key() -> SigningKey {
    SigningKey::from_bytes(&[0x99; 32])
}

pub fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[0x55; 32])
}

pub fn user_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn addr_of(k: &SigningKey) -> Address {
    plaine_consensus::crypto::address_payload(&k.verifying_key().to_bytes())
}

impl Rig {
    pub fn new(chain: &Scenario, p: ChainParams) -> Rig {
        Rig::with_mode(chain, p, PowMode::AlwaysOk)
    }

    pub fn with_mode(chain: &Scenario, p: ChainParams, mode: PowMode) -> Rig {
        let g = chain.blocks[0].clone();
        let store = Arc::new(MemStore::with_genesis(g.rec, g.body, &p));
        let pow = Arc::new(CountingPow::new(mode));
        let clock = Arc::new(MockClock::new(T0));
        let conds: Arc<Mutex<Vec<Condition>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = conds.clone();
        let cm = ChainManager::new(
            store.clone(),
            store.clone(),
            pow.clone(),
            clock.clone(),
            p.clone(),
            Some(Box::new(move |c| sink.lock().expect("cond lock").push(c))),
        )
        .expect("boot invariants hold");
        Rig { store, pow, clock, cm, conds, params: p }
    }

    pub fn sync(&mut self, chain: &Scenario, from: u64) {
        self.clock.set_unix(chain.tip().time.max(T0));
        let raws = chain.raw_headers_from(from);

        for part in raws.chunks(plaine_consensus::constants::MAX_HEADERS_PER_MSG) {
            self.cm.submit_headers_solicited(1, part).expect("headers ingest");
        }
        for b in chain.blocks.iter().skip(from as usize) {
            let _ = self.cm.submit_block(&b.rec.hash, b.body.clone());
        }
        while let Ok(plaine_chain::Progress::Advanced { .. }) = self.cm.advance() {}
    }

    pub fn offer(&mut self, source: u32, blocks: &[plaine_chain::mock::BuiltBlock]) -> plaine_chain::Accepted {
        let raws: Vec<[u8; 132]> = blocks.iter().map(|b| b.rec.raw).collect();
        let a = self.cm.submit_headers_solicited(source, &raws).expect("not halted");
        for b in blocks {
            let _ = self.cm.submit_block(&b.rec.hash, b.body.clone());
        }
        a
    }

    pub fn restart(&mut self) {
        let p = self.params.clone();
        self.restart_with(p);
    }

    pub fn restart_with(&mut self, p: ChainParams) {
        let sink = self.conds.clone();
        self.params = p;
        self.cm = ChainManager::new(
            self.store.clone(),
            self.store.clone(),
            self.pow.clone(),
            self.clock.clone(),
            self.params.clone(),
            Some(Box::new(move |c| sink.lock().expect("cond lock").push(c))),
        )
        .expect("boot invariants hold on the second boot too");
    }

    pub fn conditions(&self) -> Vec<Condition> {
        self.conds.lock().expect("cond lock").clone()
    }

    pub fn observed(&self, f: impl Fn(&Condition) -> bool) -> bool {
        self.conditions().iter().any(f)
    }

    pub fn height(&self) -> u64 {
        self.cm.tip().height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.cm.tip().hash
    }
}

pub fn blocks_above(chain: &Scenario, from: u64) -> Vec<plaine_chain::mock::BuiltBlock> {
    chain.blocks.iter().skip(from as usize + 1).cloned().collect()
}

pub fn signed_transfer(
    sk: &SigningKey,
    to: Address,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> Vec<u8> {
    let mut tx = plaine_consensus::codec::TransferTx {
        from_pub: sk.verifying_key().to_bytes(),
        to,
        amount,
        fee,
        nonce,
        sig: [0u8; 64],
    };
    let msg = plaine_consensus::crypto::transfer_signing_message(TEST_NETWORK, &tx);
    tx.sig = sk.sign(&msg).to_bytes();
    tx.encode().to_vec()
}

pub fn signed_announcement(sk: &SigningKey, payload: &[u8], fee: u128, nonce: u64) -> Vec<u8> {
    let mut tx = plaine_consensus::codec::AnnouncementTx {
        from_pub: sk.verifying_key().to_bytes(),
        fee,
        nonce,
        encoding: 0x01,
        payload: payload.to_vec(),
        sig: [0u8; 64],
    };
    let msg =
        plaine_consensus::crypto::announcement_message_of(TEST_NETWORK, &tx).expect("payload length is legal");
    tx.sig = sk.sign(&msg).to_bytes();
    tx.encode().expect("payload length is legal")
}

pub fn signed_checkpoint(
    sk: &SigningKey,
    height: u64,
    hash: [u8; 32],
) -> plaine_consensus::rules::SignedCheckpoint {
    let msg = plaine_consensus::rules::checkpoint_message(height, &hash);
    plaine_consensus::rules::SignedCheckpoint {
        height,
        hash,
        sigs: vec![plaine_consensus::rules::CheckpointSig {
            pubkey: sk.verifying_key().to_bytes(),
            sig: sk.sign(&msg).to_bytes(),
        }],
    }
}

pub fn rec(raw: [u8; 132]) -> HeaderRec {
    HeaderRec::from_raw(raw)
}
