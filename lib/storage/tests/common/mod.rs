#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use plaine_consensus::constants::HEADER_BYTES;
use plaine_consensus::crypto::header_hash;
use plaine_storage::{
    AcceptUnverified, Account, BlockToCommit, StateDelta, StoreConfig, StoreError, StoreReader,
    UndoRec,
};

pub fn body(r: &StoreReader, h: u64, out: &mut Vec<u8>) -> usize {
    match r.body_at(h, out).expect("body_at") {
        Some(b) => b.any_provenance(AcceptUnverified::because(
            "test harness: provenance is asserted separately",
        )),
        None => 0,
    }
}

pub fn body_res(r: &StoreReader, h: u64, out: &mut Vec<u8>) -> Result<usize, StoreError> {
    Ok(match r.body_at(h, out)? {
        Some(b) => b.any_provenance(AcceptUnverified::because("test harness")),
        None => 0,
    })
}

pub fn body_verified(r: &StoreReader, h: u64, out: &mut Vec<u8>) -> usize {
    r.body_at(h, out)
        .expect("body_at")
        .unwrap_or_else(|| panic!("no body at {h}"))
        .verified()
        .unwrap_or_else(|(c, _)| panic!("body {h} is unverifiable: {c:?}"))
}

pub fn serial() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    match L.get_or_init(|| Mutex::new(())).lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

pub fn quiet() -> bool {
    std::env::var("PLAINE_AUDIT_QUIET").as_deref() == Ok("1")
}

pub fn tag() -> &'static str {
    if quiet() {
        "  "
    } else {
        "  NOT QUIET - DO NOT QUOTE | "
    }
}

pub fn machine_note(scenario: &str) {
    println!(
        "\n=== {scenario}\n    machine: {} {} cores | PLAINE_AUDIT_QUIET={} | build: {}",
        std::env::consts::OS,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        if quiet() { "1 (operator asserts the box is idle)" } else { "unset - figures below are LOWER BOUNDS" },
        if cfg!(debug_assertions) { "debug" } else { "release" }
    );
}

pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("plaine-storage-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch dir");
        Self(p)
    }

    pub fn at(p: PathBuf) -> Self {
        std::fs::create_dir_all(&p).expect("scratch dir");
        Self(p)
    }
    pub fn cfg(&self) -> StoreConfig {
        let mut c = StoreConfig::new(self.0.clone(), plaine_storage::Network::Main);
        c.page_cache_bytes = 8 * 1024 * 1024;
        c.ibd_batch_blocks = Some(2_048);
        c
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn dir_bytes(p: &std::path::Path) -> u64 {
    let mut total = 0;
    let Ok(rd) = std::fs::read_dir(p) else {
        return 0;
    };
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if md.is_dir() {
            total += dir_bytes(&e.path());
        } else {
            total += md.len();
        }
    }
    total
}

pub fn file_bytes(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

pub fn addr(i: u64) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[0..8].copy_from_slice(&i.to_le_bytes());
    a
}

pub struct Block {
    pub header: [u8; HEADER_BYTES],
    pub hash: [u8; 32],
    pub height: u64,
    pub body: Vec<u8>,
    pub deltas: Vec<StateDelta>,
    pub undo: Vec<UndoRec>,
    pub issued: u128,
    pub chainwork: [u8; 32],
}

impl Block {
    pub fn to_commit(&self) -> BlockToCommit<'_> {
        BlockToCommit {
            header: &self.header,
            hash: self.hash,
            height: self.height,
            body: &self.body,
            deltas: &self.deltas,
            undo: &self.undo,
            issued_delta: self.issued,
            chainwork: self.chainwork,
            txids: None,
        }
    }
}

pub fn commits(bs: &[Block]) -> Vec<BlockToCommit<'_>> {
    bs.iter().map(|b| b.to_commit()).collect()
}

pub struct Chain {
    pub state: HashMap<[u8; 20], Account>,
    pub prev: [u8; 32],
    pub height: u64,
    pub issued: u128,
    pub accounts: u64,
    pub body_len: usize,
    pub writes_per_block: usize,
}

impl Chain {
    pub fn new(accounts: u64, body_len: usize, writes_per_block: usize) -> Self {
        Self {
            state: HashMap::new(),
            prev: [0u8; 32],
            height: 0,
            issued: 0,
            accounts,
            body_len,
            writes_per_block,
        }
    }

    pub fn build(&mut self, n: u64, variant: u64) -> Vec<Block> {
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            out.push(self.build_one(variant));
        }
        out
    }

    pub fn build_one(&mut self, variant: u64) -> Block {
        let h = self.height;
        let mut rng = Rng(h.wrapping_mul(0x0100_0000_01B3) ^ variant.wrapping_mul(0x9E37_79B9));
        let mut deltas = Vec::with_capacity(self.writes_per_block);
        let mut undo = Vec::with_capacity(self.writes_per_block);
        let mut seen = Vec::new();
        for _ in 0..self.writes_per_block {
            let mut a = addr(rng.below(self.accounts));
            while seen.contains(&a) {
                a = addr(rng.below(self.accounts));
            }
            seen.push(a);
            let prev = self.state.get(&a).copied();
            undo.push(UndoRec {
                addr: a,
                prev_balance: prev.map(|p| p.balance).unwrap_or(0),
                prev_nonce: prev.map(|p| p.nonce).unwrap_or(0),
                existed: prev.is_some(),
            });
            let next = Account {
                balance: prev.map(|p| p.balance).unwrap_or(0) + 1_000 + h as u128,
                nonce: prev.map(|p| p.nonce).unwrap_or(0) + 1,
            };
            deltas.push(StateDelta {
                addr: a,
                balance: next.balance,
                nonce: next.nonce,
            });
            self.state.insert(a, next);
        }

        let mut header = [0u8; HEADER_BYTES];
        header[0..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
        header[4..12].copy_from_slice(&h.to_le_bytes());
        header[12..44].copy_from_slice(&self.prev);
        header[44..76].copy_from_slice(&[(h % 251) as u8; 32]);
        header[108..116].copy_from_slice(&(1_700_000_000u64 + h * 60).to_le_bytes());
        header[116..120].copy_from_slice(&0x1F00_FFFFu32.to_le_bytes());
        header[124..132].copy_from_slice(&(variant.wrapping_mul(1_000_003) ^ h).to_le_bytes());
        let hash = header_hash(&header);

        let mut body = vec![0u8; self.body_len];
        for (i, b) in body.iter_mut().enumerate() {
            *b = ((h as usize + i + variant as usize) % 251) as u8;
        }

        let issued = 137_672u128;
        self.issued += issued;
        let mut chainwork = [0u8; 32];
        chainwork[24..32].copy_from_slice(&(h + 1).to_be_bytes());

        self.prev = hash;
        self.height = h + 1;
        Block {
            header,
            hash,
            height: h,
            body,
            deltas,
            undo,
            issued,
            chainwork,
        }
    }

    pub fn rewind(&mut self, blocks: &[Block], to_height: u64, prev_hash: [u8; 32]) {
        for b in blocks.iter().rev() {
            if b.height <= to_height {
                continue;
            }
            for u in b.undo.iter().rev() {
                if u.existed {
                    self.state.insert(
                        u.addr,
                        Account {
                            balance: u.prev_balance,
                            nonce: u.prev_nonce,
                        },
                    );
                } else {
                    self.state.remove(&u.addr);
                }
            }
            self.issued -= b.issued;
        }
        self.height = to_height + 1;
        self.prev = prev_hash;
    }
}
