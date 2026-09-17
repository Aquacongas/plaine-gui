use crate::constants::HEADER_BYTES;
use crate::gate::g2_context::BitsRule;
use crate::traits::*;
use plaine_consensus::codec::Header;
use plaine_consensus::constants::VERSION_BASE;
use plaine_consensus::crypto::header_hash;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const MOCK_BITS: u32 = 0x1f00_ffff;

pub fn build_chain_repeating_a_second(
    start_height: u64,
    n: u64,
    prev: Hash32,
    base_time: u64,
    salt: u64,
    repeat_at: u64,
) -> Vec<HeaderRec> {
    let mut out = build_chain(start_height, n, prev, base_time, salt);
    let idx = (repeat_at.saturating_sub(start_height)) as usize;
    assert!(
        idx > 0 && idx < out.len(),
        "repeat_at must be inside the range and not first"
    );

    out[idx].time = out[idx - 1].time;

    for i in idx..out.len() {
        let mut h = Header::decode(&out[i].raw).expect("mock header decodes");
        h.time = out[i].time;
        h.prev_hash = if i == idx {
            out[i].prev_hash
        } else {
            out[i - 1].hash
        };
        out[i].prev_hash = h.prev_hash;
        out[i].raw = h.encode();
        out[i].hash = header_hash(&out[i].raw);
    }
    out
}

pub fn build_chain(
    start_height: u64,
    n: u64,
    prev: Hash32,
    base_time: u64,
    salt: u64,
) -> Vec<HeaderRec> {
    let mut out = Vec::with_capacity(n as usize);
    let mut parent = prev;
    for i in 0..n {
        let height = start_height + i;
        let h = Header {
            version: VERSION_BASE,
            height,
            prev_hash: parent,
            tx_root: {
                let mut r = [0u8; 32];
                r[..8].copy_from_slice(&salt.to_le_bytes());
                r[8..16].copy_from_slice(&height.to_le_bytes());
                r
            },
            ext_root: [0u8; 32],
            time: base_time + height * 60,
            bits: MOCK_BITS,
            author_note_len: 0,
            nonce: salt ^ height,
        };
        let raw = h.encode();
        let hash = header_hash(&raw);
        out.push(HeaderRec {
            height,
            hash,
            prev_hash: parent,
            time: h.time,
            bits: MOCK_BITS,
            target: [0xff; 32],
            raw,
        });
        parent = hash;
    }
    out
}

struct Inner {
    headers: Vec<HeaderRec>,
    bodies: HashMap<Hash32, Vec<u8>>,
    accepted_headers: u64,
    accepted_blocks: u64,
    regress: u64,
    frozen: bool,
    fatal: Option<&'static str>,
    cap_blocks: u64,
    cap_bytes: u64,
    anchor: Option<Anchor>,
    anchor_record: Option<SignedCheckpoint>,
    checkpoints: Vec<(u64, Hash32)>,
    pow_floor: u64,
    tip_time_override: Option<u64>,
    reject_at_or_above: Option<u64>,
    swallow_at_or_above: Option<u64>,
    defer_refusal: bool,
    pending_refusal: Option<(u64, &'static str)>,
    park_at_or_above: Option<u64>,
    pending_held: Option<crate::traits::Held>,
    strict_canonical: bool,
    applied_tip: bool,
    forget_side_headers: bool,
    mempool: Vec<(Hash32, Vec<u8>)>,
    relayable: bool,
    checkpoints_seen: u64,
    checkpoint_sigs: usize,
    wanted_bodies: Vec<Hash32>,
    submissions: Vec<(u64, u64, &'static str)>,
}

pub struct MockChain {
    inner: Mutex<Inner>,
}

impl MockChain {
    pub fn linear(n: u64, base_time: u64, salt: u64) -> MockChain {
        let headers = build_chain(0, n, [0u8; 32], base_time, salt);
        let bodies = headers
            .iter()
            .map(|h| (h.hash, vec![0u8; 256]))
            .collect::<HashMap<_, _>>();
        MockChain {
            inner: Mutex::new(Inner {
                headers,
                bodies,
                accepted_headers: 0,
                accepted_blocks: 0,
                regress: 0,
                frozen: false,
                fatal: None,
                cap_blocks: 16,
                cap_bytes: 16 * 1024 * 1024,
                anchor: None,
                anchor_record: None,
                checkpoints: Vec::new(),
                pow_floor: 0,
                tip_time_override: None,
                reject_at_or_above: None,
                swallow_at_or_above: None,
                defer_refusal: false,
                pending_refusal: None,
                park_at_or_above: None,
                pending_held: None,
                strict_canonical: false,
                applied_tip: false,
                forget_side_headers: false,
                mempool: Vec::new(),
                relayable: true,
                wanted_bodies: Vec::new(),
                submissions: Vec::new(),
                checkpoints_seen: 0,
                checkpoint_sigs: 0,
            }),
        }
    }

    pub fn add_local_tx(&self, txid: Hash32, bytes: Vec<u8>) {
        let mut g = self.inner.lock().expect("mock lock");
        if !g.mempool.iter().any(|(h, _)| *h == txid) {
            g.mempool.push((txid, bytes));
        }
    }

    pub fn checkpoints_seen(&self) -> u64 {
        self.inner.lock().expect("mock lock").checkpoints_seen
    }

    pub fn checkpoint_sigs(&self) -> usize {
        self.inner.lock().expect("mock lock").checkpoint_sigs
    }

    pub fn forget_body(&self, h: &Hash32) {
        self.inner.lock().expect("mock lock").bodies.remove(h);
    }

    pub fn applied_tip(&self, on: bool) {
        self.inner.lock().expect("mock lock").applied_tip = on;
    }

    pub fn submissions(&self) -> Vec<(u64, u64, &'static str)> {
        self.inner.lock().expect("mock lock").submissions.clone()
    }

    pub fn clear_submissions(&self) {
        self.inner.lock().expect("mock lock").submissions.clear();
    }

    pub fn set_wanted_bodies(&self, hs: Vec<Hash32>) {
        self.inner.lock().expect("mock lock").wanted_bodies = hs;
    }

    pub fn mempool_ids(&self) -> Vec<Hash32> {
        let g = self.inner.lock().expect("mock lock");
        g.mempool.iter().map(|(h, _)| *h).collect()
    }

    pub fn has_tx(&self, txid: &Hash32) -> bool {
        let g = self.inner.lock().expect("mock lock");
        g.mempool.iter().any(|(h, _)| h == txid)
    }

    pub fn set_relayable(&self, on: bool) {
        self.inner.lock().expect("mock lock").relayable = on;
    }

    pub fn strict_canonical(&self, on: bool) {
        self.inner.lock().expect("mock lock").strict_canonical = on;
    }

    pub fn forget_side_headers(&self, on: bool) {
        self.inner.lock().expect("mock lock").forget_side_headers = on;
    }

    pub fn reject_headers_from(&self, height: u64) {
        self.inner.lock().expect("mock lock").reject_at_or_above = Some(height);
    }

    pub fn park_headers_from(&self, height: u64) {
        self.inner.lock().expect("mock lock").park_at_or_above = Some(height);
    }

    pub fn stop_parking(&self) {
        let mut g = self.inner.lock().expect("mock lock");
        g.park_at_or_above = None;
        g.pending_held = None;
    }

    pub fn swallow_headers_from(&self, height: u64) {
        self.inner.lock().expect("mock lock").swallow_at_or_above = Some(height);
    }

    pub fn refuse_headers_from(&self, height: u64) {
        let mut g = self.inner.lock().expect("mock lock");
        g.swallow_at_or_above = Some(height);
        g.defer_refusal = true;
    }

    pub fn keep_all_headers(&self) {
        let mut g = self.inner.lock().expect("mock lock");
        g.swallow_at_or_above = None;
        g.defer_refusal = false;
        g.pending_refusal = None;
    }

    pub fn accept_all_headers(&self) {
        self.inner.lock().expect("mock lock").reject_at_or_above = None;
    }

    pub fn accepted_headers(&self) -> u64 {
        self.inner.lock().expect("mock lock").accepted_headers
    }

    pub fn accepted_blocks(&self) -> u64 {
        self.inner.lock().expect("mock lock").accepted_blocks
    }

    pub fn freeze_sink(&self, on: bool) {
        self.inner.lock().expect("mock lock").frozen = on;
    }

    pub fn set_fatal(&self, m: Option<&'static str>) {
        self.inner.lock().expect("mock lock").fatal = m;
    }

    pub fn regress_tip(&self, n: u64) {
        self.inner.lock().expect("mock lock").regress = n;
    }

    pub fn set_tip_time(&self, t: Option<u64>) {
        self.inner.lock().expect("mock lock").tip_time_override = t;
    }

    pub fn set_anchor(&self, a: Option<Anchor>) {
        self.inner.lock().expect("mock lock").anchor = a;
    }

    pub fn set_anchor_record(&self, cp: Option<SignedCheckpoint>) {
        self.inner.lock().expect("mock lock").anchor_record = cp;
    }

    pub fn drop_bodies(&self) {
        self.inner.lock().expect("mock lock").bodies.clear();
    }

    pub fn extend(&self, hs: &[HeaderRec], with_bodies: bool) {
        let mut g = self.inner.lock().expect("mock lock");
        for h in hs {
            g.headers.push(*h);
            if with_bodies {
                g.bodies.insert(h.hash, vec![0u8; 256]);
            }
        }
    }

    pub fn headers(&self) -> Vec<HeaderRec> {
        self.inner.lock().expect("mock lock").headers.clone()
    }
}

fn applied_tip(g: &Inner) -> Option<HeaderRec> {
    let genesis = *g.headers.first()?;
    let mut children: HashMap<Hash32, Vec<HeaderRec>> = HashMap::new();
    for h in g.headers.iter().skip(1) {
        children.entry(h.prev_hash).or_default().push(*h);
    }
    let mut best = genesis;
    let mut stack = vec![genesis];
    while let Some(cur) = stack.pop() {
        if cur.height > best.height {
            best = cur;
        }
        for c in children.get(&cur.hash).into_iter().flatten() {
            if g.bodies.contains_key(&c.hash) {
                stack.push(*c);
            }
        }
    }
    Some(best)
}

impl ChainView for MockChain {
    fn wanted_bodies(&self) -> Vec<Hash32> {
        self.inner.lock().expect("mock lock").wanted_bodies.clone()
    }

    fn mempool_txids(&self) -> Vec<Hash32> {
        let g = self.inner.lock().expect("mock lock");
        if !g.relayable {
            return Vec::new();
        }
        g.mempool.iter().map(|(h, _)| *h).collect()
    }

    fn tx_bytes(&self, txid: &Hash32) -> Option<Vec<u8>> {
        let g = self.inner.lock().expect("mock lock");
        g.mempool
            .iter()
            .find(|(h, _)| h == txid)
            .map(|(_, b)| b.clone())
    }

    fn tip(&self) -> TipSnapshot {
        let g = self.inner.lock().expect("mock lock");

        if g.applied_tip {
            if let Some(h) = applied_tip(&g) {
                return TipSnapshot {
                    height: h.height,
                    hash: h.hash,
                    cum_work: {
                        let mut w = [0u8; 32];
                        w[..8].copy_from_slice(&h.height.to_le_bytes());
                        w
                    },
                    time: g.tip_time_override.unwrap_or(h.time),
                };
            }
        }

        let idx = g
            .headers
            .len()
            .saturating_sub(1)
            .saturating_sub(g.regress as usize);
        let h = g.headers.get(idx).copied().unwrap_or(HeaderRec {
            height: 0,
            hash: [0u8; 32],
            prev_hash: [0u8; 32],
            time: 0,
            bits: MOCK_BITS,
            target: [0xff; 32],
            raw: [0u8; HEADER_BYTES],
        });
        TipSnapshot {
            height: h.height,
            hash: h.hash,
            cum_work: {
                let mut w = [0u8; 32];
                w[..8].copy_from_slice(&h.height.to_le_bytes());
                w
            },
            time: g.tip_time_override.unwrap_or(h.time),
        }
    }

    fn header_at(&self, height: u64) -> Option<HeaderRec> {
        let g = self.inner.lock().expect("mock lock");
        let rec = g.headers.get(height as usize).copied()?;
        if g.strict_canonical && height > 0 && !g.bodies.contains_key(&rec.hash) {
            return None;
        }
        Some(rec)
    }

    fn header_by_hash(&self, h: &Hash32) -> Option<HeaderRec> {
        let g = self.inner.lock().expect("mock lock");
        let rec = g.headers.iter().find(|x| x.hash == *h).copied()?;
        if g.forget_side_headers && rec.height > 0 && !g.bodies.contains_key(&rec.hash) {
            return None;
        }
        Some(rec)
    }

    fn ancestor_at(&self, _tip: &Hash32, height: u64) -> Option<Hash32> {
        self.header_at(height).map(|h| h.hash)
    }

    fn locator(&self) -> Vec<Hash32> {
        let g = self.inner.lock().expect("mock lock");
        let mut out = Vec::new();
        let n = g.headers.len();
        if n == 0 {
            return out;
        }
        let mut step = 1usize;
        let mut i = n - 1;
        let mut count = 0;
        loop {
            out.push(g.headers[i].hash);
            count += 1;
            if i == 0 || out.len() >= crate::constants::LOCATOR_MAX {
                break;
            }
            if count > 12 {
                step *= 2;
            }
            i = i.saturating_sub(step);
        }
        out
    }

    fn headers_from(&self, loc: &[Hash32], _stop: &Hash32, max: usize) -> Vec<[u8; HEADER_BYTES]> {
        let g = self.inner.lock().expect("mock lock");
        let start = loc
            .iter()
            .filter_map(|h| g.headers.iter().position(|x| x.hash == *h))
            .max()
            .map(|i| i + 1)
            .unwrap_or(0);
        g.headers
            .iter()
            .skip(start)
            .take(max)
            .map(|h| h.raw)
            .collect()
    }

    fn have_body(&self, h: &Hash32) -> bool {
        self.inner.lock().expect("mock lock").bodies.contains_key(h)
    }

    fn body_bytes(&self, h: &Hash32) -> Option<Vec<u8>> {
        self.inner.lock().expect("mock lock").bodies.get(h).cloned()
    }

    fn anchor(&self) -> Option<Anchor> {
        self.inner.lock().expect("mock lock").anchor
    }

    fn anchor_record(&self) -> Option<SignedCheckpoint> {
        self.inner.lock().expect("mock lock").anchor_record.clone()
    }

    fn checkpoints(&self) -> Vec<(u64, Hash32)> {
        self.inner.lock().expect("mock lock").checkpoints.clone()
    }

    fn pow_verified_floor(&self) -> u64 {
        self.inner.lock().expect("mock lock").pow_floor
    }
}

impl BlockSink for MockChain {
    fn submit_headers(&self, b: HeaderBatch) -> Result<Accepted, SinkError> {
        let mut g = self.inner.lock().expect("mock lock");

        let span = (
            b.headers.first().map(|h| h.height).unwrap_or(0),
            b.headers.last().map(|h| h.height).unwrap_or(0),
        );
        if let Some(m) = g.fatal {
            g.submissions.push((span.0, span.1, "fatal"));
            return Err(SinkError::Fatal(m));
        }
        if g.frozen {
            g.submissions.push((span.0, span.1, "full"));
            return Err(SinkError::Full);
        }

        if let Some((height, why)) = g.pending_refusal.take() {
            g.submissions.push((span.0, span.1, "refused"));
            return Err(SinkError::RefusedAt { height, why });
        }
        if let Some(floor) = g.reject_at_or_above {
            if b.headers.iter().any(|h| h.height >= floor) {
                g.submissions.push((span.0, span.1, "invalid"));
                return Err(SinkError::Invalid("mock: refused by consensus"));
            }
        }
        g.submissions.push((span.0, span.1, "ok"));
        let n = b.headers.len() as u64;
        g.accepted_headers += n;
        let held = g.pending_held.take();
        let swallow = g.swallow_at_or_above;
        let defer = g.defer_refusal;
        let park = g.park_at_or_above;
        for h in &b.headers {
            if park.is_some_and(|floor| h.height >= floor) {
                let lower = match g.pending_held {
                    Some(x) if x.height <= h.height => x,
                    _ => crate::traits::Held {
                        hash: h.hash,
                        height: h.height,
                    },
                };
                g.pending_held = Some(lower);
                continue;
            }

            if swallow.is_some_and(|floor| h.height >= floor) {
                if defer {
                    let holds_parent = g.headers.iter().any(|x| x.hash == h.prev_hash);
                    let br = if holds_parent {
                        h.height
                    } else {
                        h.height.saturating_sub(1)
                    };
                    let lower = match g.pending_refusal {
                        Some((x, _)) if x <= br => x,
                        _ => br,
                    };
                    g.pending_refusal = Some((lower, "mock: the chain kept nothing"));
                }
                continue;
            }
            if !g.headers.iter().any(|x| x.hash == h.hash) {
                g.headers.push(*h);
            }
        }
        let vh = b.headers.last().map(|h| h.height).unwrap_or(0);
        Ok(Accepted {
            connected: n,
            verified_height: vh,
            held,
        })
    }

    fn submit_block(&self, hash: Hash32, bytes: Vec<u8>) -> Result<(), SinkError> {
        let mut g = self.inner.lock().expect("mock lock");
        if let Some(m) = g.fatal {
            return Err(SinkError::Fatal(m));
        }
        if g.frozen {
            return Err(SinkError::Full);
        }

        if g.park_at_or_above.is_some_and(|floor| {
            g.pending_held.is_some_and(|h| h.hash == hash)
                || !g.headers.iter().any(|x| x.hash == hash) && floor > 0
        }) && !g.headers.iter().any(|x| x.hash == hash)
        {
            return Err(SinkError::Invalid(
                "mock: no connected header for this body",
            ));
        }
        g.accepted_blocks += 1;
        g.bodies.insert(hash, bytes);
        Ok(())
    }

    fn submit_tx(&self, txid: Hash32, bytes: Vec<u8>) -> Result<(), SinkError> {
        let mut g = self.inner.lock().expect("mock lock");
        if g.frozen {
            return Err(SinkError::Full);
        }

        if !g.mempool.iter().any(|(h, _)| *h == txid) {
            g.mempool.push((txid, bytes));
        }
        Ok(())
    }

    fn submit_checkpoint(&self, cp: SignedCheckpoint) -> Result<AnchorUpdate, SinkError> {
        let mut g = self.inner.lock().expect("mock lock");

        g.checkpoints_seen += 1;

        g.checkpoint_sigs = cp.sigs.len();
        let held = g.headers.iter().find(|h| h.height == cp.height).copied();
        match held {
            Some(h) if h.hash != cp.hash => Ok(AnchorUpdate::Contradicts {
                height: cp.height,
                hash: cp.hash,
            }),
            _ => {
                let a = Anchor {
                    height: cp.height,
                    hash: cp.hash,
                };
                let sup = plaine_consensus::rules::anchor_supersedes(g.anchor.as_ref(), &a);
                if sup {
                    g.anchor = Some(a);
                    Ok(AnchorUpdate::Advanced(a))
                } else {
                    Ok(AnchorUpdate::Unchanged)
                }
            }
        }
    }

    fn capacity(&self) -> SinkCapacity {
        let g = self.inner.lock().expect("mock lock");
        if g.frozen {
            return SinkCapacity {
                blocks: 0,
                bytes: 0,
            };
        }
        SinkCapacity {
            blocks: g.cap_blocks,
            bytes: g.cap_bytes,
        }
    }
}

#[derive(Debug, Default)]
pub struct MockPow {
    invalid: Mutex<HashSet<Hash32>>,
    pub cost_ms: u64,
    calls: Mutex<u64>,
}

impl MockPow {
    pub fn all_valid() -> MockPow {
        MockPow::default()
    }

    pub fn with_cost(cost_ms: u64) -> MockPow {
        MockPow {
            cost_ms,
            ..MockPow::default()
        }
    }

    pub fn poison(&self, h: Hash32) {
        self.invalid.lock().expect("mock lock").insert(h);
    }

    pub fn poison_all(&self, hs: &[HeaderRec]) {
        let mut g = self.invalid.lock().expect("mock lock");
        for h in hs {
            g.insert(h.hash);
        }
    }

    pub fn calls(&self) -> u64 {
        *self.calls.lock().expect("mock lock")
    }
}

impl PowVerifier for MockPow {
    fn verify(&self, hdr: &[u8; HEADER_BYTES]) -> bool {
        *self.calls.lock().expect("mock lock") += 1;
        let h = header_hash(hdr);
        !self.invalid.lock().expect("mock lock").contains(&h)
    }
    fn cost_ms(&self) -> u64 {
        self.cost_ms
    }
}

#[derive(Debug, Default)]
pub struct MockBits;

impl BitsRule for MockBits {
    fn expected_bits(&self, _parent: &HeaderRec) -> Option<u32> {
        Some(MOCK_BITS)
    }
    fn expand(&self, _bits: u32) -> Option<Hash32> {
        Some([0xff; 32])
    }
}
