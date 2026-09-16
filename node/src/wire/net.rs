use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use plaine_p2p::traits::{
    Accepted, AnchorUpdate, BlockSink, ChainView, Hash32, HeaderBatch, HeaderRec, SignedCheckpoint,
    SinkCapacity, SinkError, TipSnapshot,
};

use crate::validator::{Cmd, Solicit};
use crate::wire::rpcview::Ask;
use crate::wire::store::NodeStore;
use crate::wire::tip::TipCell;

// backpressure bounds on the validator inbox. cap both the item count and the
// bytes in flight; a peer flood must not be able to grow the queue without limit.
pub const QUEUE_ITEMS: u64 = 1_024;

pub const QUEUE_BYTES: u64 = 32 * 1024 * 1024;

pub struct NodeView {
    tip: TipCell,
    store: Arc<NodeStore>,
    genesis: Hash32,
    wanted_bodies: Arc<Mutex<Arc<Vec<Hash32>>>>,
    mempool_ids: Arc<Mutex<Arc<Vec<Hash32>>>>,
    tx: tokio::sync::mpsc::Sender<Cmd>,
    anchor: Arc<Mutex<Option<plaine_p2p::traits::Anchor>>>,
    enforced: Arc<Mutex<Arc<Vec<(u64, Hash32)>>>>,
    anchor_record: Arc<Mutex<Option<plaine_p2p::traits::SignedCheckpoint>>>,
}

impl NodeView {
    pub fn new(
        tip: TipCell,
        store: Arc<NodeStore>,
        genesis: Hash32,
        tx: tokio::sync::mpsc::Sender<Cmd>,
    ) -> NodeView {
        NodeView {
            tip,
            store,
            genesis,
            wanted_bodies: Arc::new(Mutex::new(Arc::new(Vec::new()))),
            mempool_ids: Arc::new(Mutex::new(Arc::new(Vec::new()))),
            tx,
            anchor: Arc::new(Mutex::new(None)),
            enforced: Arc::new(Mutex::new(Arc::new(Vec::new()))),
            anchor_record: Arc::new(Mutex::new(None)),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn anchor_cells(&self) -> crate::validator::AnchorCells {
        (
            Arc::clone(&self.anchor),
            Arc::clone(&self.enforced),
            Arc::clone(&self.anchor_record),
        )
    }

    pub fn wanted_bodies_cell(&self) -> Arc<Mutex<Arc<Vec<Hash32>>>> {
        Arc::clone(&self.wanted_bodies)
    }

    pub fn mempool_ids_cell(&self) -> Arc<Mutex<Arc<Vec<Hash32>>>> {
        Arc::clone(&self.mempool_ids)
    }

    fn rec(&self, r: plaine_chain::types::HeaderRec) -> HeaderRec {
        let target = plaine_consensus::asert::Target::from_compact(r.bits)
            .map(|t| crate::wire::pow::target_be(&t))
            .unwrap_or([0xff; 32]);
        HeaderRec {
            height: r.height,
            hash: r.hash,
            prev_hash: r.prev_hash,
            time: r.time,
            bits: r.bits,
            target,
            raw: r.raw,
        }
    }
}

impl ChainView for NodeView {
    fn mempool_txids(&self) -> Vec<Hash32> {
        let v = {
            let g = self.mempool_ids.lock().expect("mempool ids");
            Arc::clone(&g)
        };
        v.as_ref().clone()
    }

    fn tx_bytes(&self, txid: &Hash32) -> Option<Vec<u8>> {
        Ask::new(self.tx.clone())
            .ask(
                |r| crate::validator::Query::Tx(*txid, r),
                std::time::Duration::from_millis(500),
            )
            .flatten()
    }

    fn wanted_bodies(&self) -> Vec<Hash32> {
        let v = {
            let g = self.wanted_bodies.lock().expect("wanted bodies");
            Arc::clone(&g)
        };
        v.as_ref().clone()
    }

    fn tip(&self) -> TipSnapshot {
        let t = self.tip.get();
        TipSnapshot {
            height: t.height,
            hash: t.hash,
            cum_work: t.chainwork,
            time: t.time,
        }
    }

    fn header_at(&self, height: u64) -> Option<HeaderRec> {
        use plaine_chain::traits::Store;
        self.store.header_at(height).map(|r| self.rec(r))
    }

    fn header_by_hash(&self, h: &Hash32) -> Option<HeaderRec> {
        use plaine_chain::traits::Store;
        self.store.header_by_hash(h).map(|r| self.rec(r))
    }

    fn ancestor_at(&self, tip: &Hash32, height: u64) -> Option<Hash32> {
        use plaine_chain::traits::Store;

        let mut cur = self.store.header_by_hash(tip)?;
        if cur.height < height {
            return None;
        }

        // Fast path: if the requested tip is our own, the height is on the main
        // chain and a direct index lookup does it. Otherwise walk the parent links,
        // bounded - a bogus tip should not be able to spin us.
        if self.tip.get().hash == *tip {
            return self.store.hash_at(height);
        }
        let mut guard = 0u64;
        while cur.height > height {
            cur = self.store.header_by_hash(&cur.prev_hash)?;
            guard += 1;
            if guard > plaine_consensus::constants::MAX_HEADERS_PER_MSG as u64 * 4 {
                return None;
            }
        }
        (cur.height == height).then_some(cur.hash)
    }

    // Block locator. Dense for the first dozen heights below the tip, then the step
    // doubles and it thins toward genesis. Always ends at genesis, so a peer on any
    // fork can still find a common ancestor.
    fn locator(&self) -> Vec<Hash32> {
        use plaine_chain::traits::Store;
        let mut out = Vec::new();
        let tip = self.tip.get().height;
        let mut h = tip as i64;
        let mut step = 1i64;
        while h >= 0 && out.len() < 64 {
            if let Some(hash) = self.store.hash_at(h as u64) {
                out.push(hash);
            }
            if out.len() >= 12 {
                step = step.saturating_mul(2);
            }
            h -= step;
        }
        if out.last() != Some(&self.genesis) {
            out.push(self.genesis);
        }
        out
    }

    fn headers_from(
        &self,
        loc: &[Hash32],
        _stop: &Hash32,
        max: usize,
    ) -> Vec<[u8; plaine_p2p::constants::HEADER_BYTES]> {
        use plaine_chain::traits::Store;

        let mut from = 0u64;
        for h in loc {
            if let Some(r) = self.store.header_by_hash(h) {
                if self.store.hash_at(r.height) == Some(*h) {
                    from = r.height + 1;
                    break;
                }
            }
        }
        let out = self.store.headers_range(from, max);
        crate::log::debug(
            "serve",
            format!("headers_from: locator {} entries -> from {from}, serving {}", loc.len(), out.len()),
        );
        out
    }

    fn have_body(&self, h: &Hash32) -> bool {
        self.store.body_by_hash_inner(h).is_some()
    }

    fn body_bytes(&self, h: &Hash32) -> Option<Vec<u8>> {
        use plaine_chain::traits::Store;
        let (_, header) = self.store.header_raw_by_hash(h)?;
        let body = self.store.body_by_hash_inner(h)?;
        let _ = Store::tip(&*self.store);
        let mut out = Vec::with_capacity(header.len() + body.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
        crate::log::debug(
            "serve",
            format!("block {} -> {} bytes", plaine_consensus::hex::encode(&h[..8]), out.len()),
        );
        Some(out)
    }

    fn anchor(&self) -> Option<plaine_p2p::traits::Anchor> {
        *self.anchor.lock().expect("anchor")
    }

    fn anchor_record(&self) -> Option<plaine_p2p::traits::SignedCheckpoint> {
        self.anchor_record.lock().expect("anchor record").clone()
    }

    fn checkpoints(&self) -> Vec<(u64, Hash32)> {
        let v = {
            let g = self.enforced.lock().expect("enforced");
            Arc::clone(&g)
        };
        v.as_ref().clone()
    }

    fn pow_verified_floor(&self) -> u64 {
        0
    }
}

pub struct ValidatorSink {
    tx: tokio::sync::mpsc::Sender<Cmd>,
    tip: TipCell,
    queued_bytes: Arc<AtomicU64>,
    ibd: Arc<std::sync::atomic::AtomicBool>,
    refusal: Arc<Mutex<Option<Break>>>,
    held: Arc<Mutex<Option<plaine_p2p::traits::Held>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Break {
    pub height: u64,
    pub why: &'static str,
}

impl ValidatorSink {
    pub fn new(tx: tokio::sync::mpsc::Sender<Cmd>, tip: TipCell) -> ValidatorSink {
        ValidatorSink {
            tx,
            tip,
            queued_bytes: Arc::new(AtomicU64::new(0)),
            ibd: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            refusal: Arc::new(Mutex::new(None)),
            held: Arc::new(Mutex::new(None)),
        }
    }

    pub fn refusal_cell(&self) -> Arc<Mutex<Option<Break>>> {
        Arc::clone(&self.refusal)
    }

    // keep the lowest pending break. repair restarts from the earliest point the
    // chain refused; a later break must not overwrite an earlier one.
    pub fn refuse(cell: &Mutex<Option<Break>>, b: Break) {
        let mut g = cell.lock().expect("refusal cell");
        match *g {
            Some(old) if old.height <= b.height => {}
            _ => *g = Some(b),
        }
    }

    pub fn held_cell(&self) -> Arc<Mutex<Option<plaine_p2p::traits::Held>>> {
        Arc::clone(&self.held)
    }

    pub fn hold(cell: &Mutex<Option<plaine_p2p::traits::Held>>, h: plaine_p2p::traits::Held) {
        let mut g = cell.lock().expect("held cell");
        match *g {
            Some(old) if old.height <= h.height => {}
            _ => *g = Some(h),
        }
    }

    pub fn byte_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.queued_bytes)
    }

    pub fn ibd_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.ibd)
    }

    fn reserve(&self, bytes: u64) -> Result<(), SinkError> {
        let cap = self.capacity();
        if !cap.admits(bytes) {
            return Err(SinkError::Full);
        }
        self.queued_bytes.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }

    fn push(&self, cmd: Cmd, bytes: u64) -> Result<(), SinkError> {
        match self.tx.try_send(cmd) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.queued_bytes.fetch_sub(bytes, Ordering::Relaxed);
                Err(SinkError::Full)
            }
        }
    }
}

impl BlockSink for ValidatorSink {
    fn submit_headers(&self, b: HeaderBatch) -> Result<Accepted, SinkError> {
        {
            let mut g = self.refusal.lock().expect("refusal cell");
            if let Some(brk) = g.take() {
                return Err(SinkError::RefusedAt { height: brk.height, why: brk.why });
            }
        }
        let bytes = (b.headers.len() * plaine_p2p::constants::HEADER_BYTES) as u64;
        self.reserve(bytes)?;

        let raws: Vec<[u8; plaine_p2p::constants::HEADER_BYTES]> =
            b.headers.iter().map(|h| h.raw).collect();

        let solicitation = match b.door {
            plaine_p2p::traits::Door::Announced => Solicit::Unsolicited,
            plaine_p2p::traits::Door::Requested if self.ibd.load(Ordering::Relaxed) => Solicit::Ibd,
            plaine_p2p::traits::Door::Requested => Solicit::Steady,
        };
        self.push(
            Cmd::Headers { source: b.source.0 as u32, raws, solicitation },
            bytes,
        )?;

        // connected is 0 on purpose - the batch is only queued here. nothing has
        // validated it yet, so claiming a header connected would be a lie.
        let held = self.held.lock().expect("held cell").take();
        Ok(Accepted { connected: 0, verified_height: self.tip.height(), held })
    }

    fn submit_block(&self, hash: Hash32, bytes: Vec<u8>) -> Result<(), SinkError> {
        let n = bytes.len() as u64;
        if bytes.len() < plaine_p2p::constants::HEADER_BYTES {
            return Err(SinkError::Invalid("block shorter than its header"));
        }
        let mut raw = [0u8; plaine_p2p::constants::HEADER_BYTES];
        raw.copy_from_slice(&bytes[..plaine_p2p::constants::HEADER_BYTES]);
        // check the body's header hashes to the id we asked for, before reserving or
        // queueing. a mismatched block then never reaches the validator or the budget.
        if plaine_consensus::crypto::header_hash(&raw) != hash {
            return Err(SinkError::Invalid("block header does not hash to the requested id"));
        }
        self.reserve(n)?;
        let body = bytes[plaine_p2p::constants::HEADER_BYTES..].to_vec();
        self.push(Cmd::Block { hash, bytes: body }, n)
    }

    fn submit_tx(&self, _txid: Hash32, bytes: Vec<u8>) -> Result<(), SinkError> {
        let n = bytes.len() as u64;
        self.reserve(n)?;
        self.push(
            Cmd::Tx {
                origin: plaine_chain::types::TxOrigin::Peer(0),
                bytes,
                reply: None,
            },
            n,
        )
    }

    fn submit_checkpoint(&self, cp: SignedCheckpoint) -> Result<AnchorUpdate, SinkError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.tx
            .try_send(Cmd::Checkpoint { cp: Box::new(cp), reply: tx })
            .map_err(|_| SinkError::Full)?;
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .map(|v| v.anchor_update())
            .map_err(|_| SinkError::Full)
    }

    fn capacity(&self) -> SinkCapacity {
        let used = self.queued_bytes.load(Ordering::Relaxed);
        SinkCapacity {
            blocks: self.tx.capacity() as u64,
            bytes: QUEUE_BYTES.saturating_sub(used.min(QUEUE_BYTES)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_queue_reports_zero_capacity() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Cmd>(2);
        let s = ValidatorSink::new(tx, TipCell::default());
        assert!(s.capacity().admits(1_000));

        s.byte_counter().store(QUEUE_BYTES, Ordering::Relaxed);
        assert_eq!(s.capacity().bytes, 0);
        assert!(!s.capacity().admits(1));
    }

    fn block(nonce: u64) -> (Hash32, Vec<u8>) {
        let mut raw = [0u8; plaine_p2p::constants::HEADER_BYTES];
        raw[124..].copy_from_slice(&nonce.to_le_bytes());
        let hash = plaine_consensus::crypto::header_hash(&raw);
        let mut b = raw.to_vec();
        b.extend_from_slice(&[0u8; 8]);
        (hash, b)
    }

    fn shared_store() -> Arc<NodeStore> {
        static STORE: std::sync::OnceLock<Arc<NodeStore>> = std::sync::OnceLock::new();
        Arc::clone(STORE.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("plaine-seam-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let cfg = plaine_storage::StoreConfig::new(dir, plaine_storage::Network::Main);

            let (_committer, reader) = crate::wire::store::tests::open_for_test(cfg);
            Arc::new(NodeStore::new(reader, crate::wire::store::new_ring()))
        }))
    }

    fn view_with(tx: tokio::sync::mpsc::Sender<Cmd>) -> NodeView {
        NodeView::new(TipCell::default(), shared_store(), [0u8; 32], tx)
    }

    #[test]
    fn relay_seams_are_implemented() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Cmd>(8);
        let view = view_with(tx);

        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        *view.mempool_ids_cell().lock().expect("cell") = Arc::new(vec![a, b]);
        assert_eq!(
            ChainView::mempool_txids(&view),
            vec![a, b],
            "the node relays nothing it originated: `mempool_txids` is the trait default"
        );

        let answerer = std::thread::spawn(move || {
            let cmd = loop {
                match rx.try_recv() {
                    Ok(c) => break c,
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(2)),
                }
            };
            match cmd {
                Cmd::Ask(crate::validator::Query::Tx(id, r)) => {
                    assert_eq!(id, a);
                    let _ = r.send(Some(vec![0xAB, 0xCD]));
                }
                _ => panic!("expected a Query::Tx on the validator inbox"),
            }
        });
        assert_eq!(
            ChainView::tx_bytes(&view, &a),
            Some(vec![0xAB, 0xCD]),
            "tx_bytes must answer with the tx the validator holds, not notfound"
        );
        answerer.join().expect("the answering thread");
    }

    #[test]
    fn anchor_and_checkpoints_from_chain() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Cmd>(4);
        let view = view_with(tx);
        let (anchor, enforced, _record) = view.anchor_cells();
        assert_eq!(ChainView::anchor(&view), None, "an empty chain has no anchor");
        assert!(ChainView::checkpoints(&view).is_empty());

        let a = plaine_p2p::traits::Anchor { height: 4_242, hash: [0xC1; 32] };
        *anchor.lock().expect("anchor") = Some(a);
        *enforced.lock().expect("enforced") = Arc::new(vec![(1u64, [2u8; 32]), (3u64, [4u8; 32])]);

        assert_eq!(
            ChainView::anchor(&view).map(|x| x.height),
            Some(4_242),
            "the transport cannot see the anchor the chain holds"
        );
        assert_eq!(ChainView::checkpoints(&view).len(), 2);
        drop(rx);
    }

    #[test]
    fn missing_tx_is_notfound_not_wait() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Cmd>(1);
        let view = view_with(tx);
        let t0 = std::time::Instant::now();
        assert_eq!(ChainView::tx_bytes(&view, &[0x99u8; 32]), None);
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(3),
            "a silent validator held the serve pool for {:?}",
            t0.elapsed()
        );
        drop(rx);
    }

    #[test]
    fn mismatched_block_refused_before_validator() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Cmd>(4);
        let s = ValidatorSink::new(tx, TipCell::default());
        let (_, bytes) = block(1);
        assert_eq!(
            s.submit_block([0xAAu8; 32], bytes),
            Err(SinkError::Invalid("block header does not hash to the requested id"))
        );
        assert!(rx.try_recv().is_err(), "a mismatched block must not reach the validator");
        assert_eq!(s.byte_counter().load(Ordering::Relaxed), 0, "and must reserve nothing");
    }

    fn header_batch() -> HeaderBatch {
        HeaderBatch {
            headers: vec![HeaderRec {
                height: 42,
                hash: [1u8; 32],
                prev_hash: [0u8; 32],
                time: 1,
                bits: 0x2100_ffff,
                target: [0xff; 32],
                raw: [0u8; plaine_p2p::constants::HEADER_BYTES],
            }],
            source: plaine_p2p::traits::PeerId(1),
            door: plaine_p2p::traits::Door::Requested,
        }
    }

    fn chosen(door: plaine_p2p::traits::Door, ibd: bool) -> Solicit {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Cmd>(4);
        let s = ValidatorSink::new(tx, TipCell::default());
        s.ibd_flag().store(ibd, Ordering::Relaxed);
        let mut b = header_batch();
        b.door = door;
        s.submit_headers(b).expect("queued");
        match rx.try_recv().expect("the batch was queued") {
            Cmd::Headers { solicitation, .. } => solicitation,
            _ => panic!("the sink queued something other than a header batch"),
        }
    }

    #[test]
    fn announced_batch_is_unsolicited() {
        use plaine_p2p::traits::Door;

        assert_eq!(chosen(Door::Announced, true), Solicit::Unsolicited);
        assert_eq!(chosen(Door::Announced, false), Solicit::Unsolicited);
    }

    #[test]
    fn requested_batch_follows_ibd_flag() {
        use plaine_p2p::traits::Door;

        assert_eq!(chosen(Door::Requested, true), Solicit::Ibd);
        assert_eq!(chosen(Door::Requested, false), Solicit::Steady);
    }

    #[test]
    fn no_connected_claim_before_chain_sees() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Cmd>(4);
        let s = ValidatorSink::new(tx, TipCell::default());
        let a = s.submit_headers(header_batch()).expect("queued");
        assert_eq!(
            a.connected, 0,
            "the sink claimed {} headers connected while the batch was still queued",
            a.connected
        );
        assert!(rx.try_recv().is_ok(), "the batch must still be queued");
    }

    #[test]
    fn refusal_returns_on_next_call() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Cmd>(8);
        let s = ValidatorSink::new(tx, TipCell::default());
        assert!(s.submit_headers(header_batch()).is_ok());

        ValidatorSink::refuse(&s.refusal_cell(), Break { height: 42, why: "test" });
        assert_eq!(
            s.submit_headers(header_batch()),
            Err(SinkError::RefusedAt { height: 42, why: "test" })
        );

        assert!(s.submit_headers(header_batch()).is_ok());
        drop(rx.try_recv());
    }

    #[test]
    fn hold_returns_once_on_next_call() {
        use plaine_p2p::traits::Held;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Cmd>(8);
        let s = ValidatorSink::new(tx, TipCell::default());
        assert_eq!(s.submit_headers(header_batch()).expect("queued").held, None);
        ValidatorSink::hold(&s.held_cell(), Held { hash: [7u8; 32], height: 148 });
        assert_eq!(
            s.submit_headers(header_batch()).expect("queued").held,
            Some(Held { hash: [7u8; 32], height: 148 })
        );

        assert_eq!(s.submit_headers(header_batch()).expect("queued").held, None);
        while rx.try_recv().is_ok() {}
    }

    #[test]
    fn break_does_not_discard_hold() {
        use plaine_p2p::traits::Held;

        let (tx, _rx) = tokio::sync::mpsc::channel::<Cmd>(8);
        let s = ValidatorSink::new(tx, TipCell::default());
        ValidatorSink::refuse(&s.refusal_cell(), Break { height: 42, why: "test" });
        ValidatorSink::hold(&s.held_cell(), Held { hash: [7u8; 32], height: 40 });
        assert_eq!(
            s.submit_headers(header_batch()),
            Err(SinkError::RefusedAt { height: 42, why: "test" })
        );
        assert_eq!(
            s.submit_headers(header_batch()).expect("queued").held,
            Some(Held { hash: [7u8; 32], height: 40 }),
            "the hold was dropped by the call that answered the break"
        );
    }

    #[test]
    fn lowest_hold_reported() {
        use plaine_p2p::traits::Held;

        let (tx, _rx) = tokio::sync::mpsc::channel::<Cmd>(8);
        let s = ValidatorSink::new(tx, TipCell::default());
        let cell = s.held_cell();
        ValidatorSink::hold(&cell, Held { hash: [9u8; 32], height: 90 });
        ValidatorSink::hold(&cell, Held { hash: [5u8; 32], height: 50 });
        ValidatorSink::hold(&cell, Held { hash: [7u8; 32], height: 70 });
        assert_eq!(
            s.submit_headers(header_batch()).expect("queued").held.map(|h| h.height),
            Some(50)
        );
    }

    #[test]
    fn lowest_break_reported() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Cmd>(8);
        let s = ValidatorSink::new(tx, TipCell::default());
        let cell = s.refusal_cell();
        ValidatorSink::refuse(&cell, Break { height: 77, why: "later" });
        ValidatorSink::refuse(&cell, Break { height: 42, why: "the break" });
        ValidatorSink::refuse(&cell, Break { height: 90, why: "later still" });
        assert_eq!(
            s.submit_headers(header_batch()),
            Err(SinkError::RefusedAt { height: 42, why: "the break" })
        );
    }

    #[test]
    fn break_reserves_and_queues_nothing() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Cmd>(8);
        let s = ValidatorSink::new(tx, TipCell::default());
        ValidatorSink::refuse(&s.refusal_cell(), Break { height: 42, why: "test" });
        assert!(s.submit_headers(header_batch()).is_err());
        assert_eq!(s.byte_counter().load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_err(), "nothing may be queued behind a break");
    }

    #[test]
    fn refused_push_returns_bytes() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Cmd>(1);
        let s = ValidatorSink::new(tx, TipCell::default());
        let (h1, b1) = block(1);
        let n = b1.len() as u64;
        assert!(s.submit_block(h1, b1).is_ok());
        assert_eq!(s.byte_counter().load(Ordering::Relaxed), n);
        let (h2, b2) = block(2);
        assert_eq!(s.submit_block(h2, b2), Err(SinkError::Full));
        assert_eq!(
            s.byte_counter().load(Ordering::Relaxed),
            n,
            "the failed push must not keep its reservation"
        );
        drop(rx);
    }
}
