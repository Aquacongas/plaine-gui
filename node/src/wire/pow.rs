use std::sync::Mutex;

use plaine_consensus::asert::Target;
use plaine_consensus::constants::HEADER_BYTES;
use plaine_consensus::{crypto, pow};
use plaine_pow::{Isochron, Scratch};

pub const INTERPRETER_COST_MICROS: u64 = 2_000;

pub const POW_LRU_ENTRIES: usize = 65_536;

pub struct Interp {
    iso: Isochron,
    pads: Mutex<Vec<Box<Scratch>>>,
    lru: Mutex<Lru>,
    calls: std::sync::atomic::AtomicU64,
    hits: std::sync::atomic::AtomicU64,
}

impl Interp {
    pub fn new() -> Result<Interp, plaine_pow::PowError> {
        plaine_pow::platform_self_check()?;
        Ok(Interp {
            iso: Isochron::new()?,
            pads: Mutex::new(Vec::new()),
            lru: Mutex::new(Lru::new(POW_LRU_ENTRIES)),
            calls: std::sync::atomic::AtomicU64::new(0),
            hits: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn digest(&self, header: &[u8; HEADER_BYTES]) -> [u8; 32] {
        let mut pad = self.take_pad();
        let seed = pow::seed(header);
        let d = self.iso.verify_hash(&mut pad, seed);
        self.give_pad(pad);
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        pow::pow_hash(header, d)
    }

    pub fn verify_header(&self, header: &[u8; HEADER_BYTES]) -> bool {
        let key = crypto::header_hash(header);
        if self.lru.lock().expect("pow lru").contains(&key) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        let bits = u32::from_le_bytes([header[116], header[117], header[118], header[119]]);
        let Ok(target) = Target::from_compact(bits) else {
            return false;
        };
        // reject an illegal target before running the interpreter - a junk header
        // costs no pow time.
        if target.is_zero() || target > plaine_consensus::asert::POW_LIMIT {
            return false;
        }
        let d = self.digest(header);
        let ok = pow::meets(&d, &target_be(&target));
        // Cache passes only. Caching a miss would hand an attacker a free way to slip
        // a header that never met its target past this gate on the next call.
        if ok {
            self.lru.lock().expect("pow lru").insert(key);
        }
        ok
    }

    fn take_pad(&self) -> Box<Scratch> {
        self.pads
            .lock()
            .expect("pad pool")
            .pop()
            .unwrap_or_else(|| Box::new(Scratch::new()))
    }

    fn give_pad(&self, p: Box<Scratch>) {
        let mut g = self.pads.lock().expect("pad pool");

        // scratchpad is large - cap the reuse pool rather than keep one per thread
        // that ever verified.
        if g.len() < 32 {
            g.push(p);
        }
    }
}

pub fn target_be(t: &Target) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in t.0.iter().enumerate() {
        let off = 24 - i * 8;
        out[off..off + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

impl plaine_chain::traits::PowVerifier for Interp {
    fn verify(&self, hdr: &[u8; HEADER_BYTES]) -> bool {
        self.verify_header(hdr)
    }
    fn cost_micros(&self) -> u64 {
        INTERPRETER_COST_MICROS
    }
}

impl plaine_p2p::traits::PowVerifier for Interp {
    fn verify(&self, hdr: &[u8; HEADER_BYTES]) -> bool {
        self.verify_header(hdr)
    }
    fn cost_ms(&self) -> u64 {
        INTERPRETER_COST_MICROS.div_ceil(1_000)
    }
}

impl plaine_stratum::verify::PowHasher for Interp {
    fn digest(&self, header: &[u8; 132]) -> [u8; 32] {
        Interp::digest(self, header)
    }
}

struct Lru {
    set: std::collections::HashSet<[u8; 32]>,
    order: std::collections::VecDeque<[u8; 32]>,
    cap: usize,
}

impl Lru {
    fn new(cap: usize) -> Lru {
        Lru {
            set: std::collections::HashSet::with_capacity(cap / 4),
            order: std::collections::VecDeque::with_capacity(cap / 4),
            cap,
        }
    }
    fn contains(&self, k: &[u8; 32]) -> bool {
        self.set.contains(k)
    }
    fn insert(&mut self, k: [u8; 32]) {
        if self.set.insert(k) {
            self.order.push_back(k);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

pub struct Bits {
    pow_limit: Target,
}

impl Default for Bits {
    fn default() -> Self {
        Bits { pow_limit: plaine_consensus::asert::POW_LIMIT }
    }
}

impl plaine_p2p::gate::g2_context::BitsRule for Bits {
    fn expected_bits(&self, _parent: &plaine_p2p::traits::HeaderRec) -> Option<u32> {
        None
    }
    fn expand(&self, bits: u32) -> Option<[u8; 32]> {
        let t = Target::from_compact(bits).ok()?;
        if t.is_zero() || t > self.pow_limit {
            return None;
        }
        Some(target_be(&t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plaine_chain::traits::PowVerifier as _;

    fn interp() -> Interp {
        Interp::new().expect("this machine must have hardware AES")
    }

    #[test]
    fn cost_is_unchanged_by_cache_hits() {
        let i = interp();
        let before = i.cost_micros();
        let mut h = [0u8; HEADER_BYTES];
        h[116..120].copy_from_slice(&plaine_consensus::constants::GENESIS_BITS.to_le_bytes());
        for n in 0..3u64 {
            h[124..].copy_from_slice(&n.to_le_bytes());
            let _ = i.verify_header(&h);
            let _ = i.verify_header(&h);
        }
        assert_eq!(i.cost_micros(), before);
        assert_eq!(i.cost_micros(), INTERPRETER_COST_MICROS);
    }

    #[test]
    fn only_passes_are_cached() {
        let i = interp();
        let mut h = [0u8; HEADER_BYTES];
        h[116..120].copy_from_slice(&0x0300_0001u32.to_le_bytes());
        let first = i.calls();
        assert!(!i.verify_header(&h));
        assert!(i.calls() > first, "a legal target must reach the interpreter");
        let calls = i.calls();
        assert!(!i.verify_header(&h));
        assert!(
            i.calls() > calls,
            "a failure must never be cached: a cached negative is a free way to \
             poison a header past both gates"
        );
    }

    #[test]
    fn frozen_genesis_verifies_then_cached() {
        let g = crate::genesis::mainnet().expect("the embedded genesis must build");
        let i = interp();
        assert!(i.verify_header(&g.header_bytes), "the frozen genesis nonce must meet its own target");
        let calls = i.calls();
        assert!(i.verify_header(&g.header_bytes));
        assert_eq!(i.calls(), calls, "the second verification of the same bytes is an LRU hit");
        assert!(i.hits() >= 1);
    }

    #[test]
    fn illegal_target_refused_before_interp() {
        let i = interp();
        let mut h = [0u8; HEADER_BYTES];

        h[116..120].copy_from_slice(&0x2100_ffffu32.to_le_bytes());
        let calls = i.calls();
        assert!(!i.verify_header(&h));
        assert_eq!(i.calls(), calls, "an illegal target must cost zero interpreter time");
    }
}
