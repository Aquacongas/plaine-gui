use crate::job::{SealOutcome, Template};
use crate::target::Target;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

pub type ConnId = u64;

pub trait PowHasher: Send + Sync + 'static {
    fn digest(&self, header: &[u8; 132]) -> [u8; 32];
}

#[derive(Debug)]
pub struct ShareWork {
    pub conn: ConnId,
    pub request_id: Option<u64>,
    pub seq: u64,
    pub header: [u8; 132],
    pub share_target: Target,
    pub served_difficulty: u64,
    pub eligible_for_block: bool,
    pub template: Arc<Template>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted { block: Option<SealOutcome> },
    LowDifficulty,
    InternalError,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyResult {
    pub conn: ConnId,
    pub request_id: Option<u64>,
    pub seq: u64,
    pub verdict: Verdict,
    pub served_difficulty: u64,
}

pub type ResultSink = Arc<dyn Fn(VerifyResult) + Send + Sync>;

pub trait ShareVerifier: Send + Sync + 'static {
    fn enqueue(&self, work: ShareWork) -> bool;
}

pub fn verify_one(pow: &dyn PowHasher, w: &ShareWork) -> Verdict {
    let digest = pow.digest(&w.header);
    if !w.share_target.accepts(&digest) {
        return Verdict::LowDifficulty;
    }

    // a share must beat the difficulty it was served at; it only becomes a block
    // if it is still eligible (not stale-credited) and also beats the network target.
    let block = if w.eligible_for_block && w.template.network_target.accepts(&digest) {
        Some(w.template.body.seal(extract_nonce(&w.header)))
    } else {
        None
    };
    Verdict::Accepted { block }
}

// isolate the interpreter: a panic on one malformed header costs that one share
// an InternalError, not the whole verification thread.
pub fn verify_one_isolated(pow: &dyn PowHasher, w: &ShareWork) -> Verdict {
    let hushed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_one(pow, w)));
    match hushed {
        Ok(v) => v,
        Err(_) => Verdict::InternalError,
    }
}

fn extract_nonce(header: &[u8; 132]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&header[124..132]);
    u64::from_le_bytes(b)
}

struct Inner {
    queue: Mutex<VecDeque<ShareWork>>,
    cv: Condvar,
    stop: AtomicBool,
    cap: usize,
}

pub struct ThreadPoolVerifier {
    inner: Arc<Inner>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl ThreadPoolVerifier {
    pub fn new(
        threads: usize,
        queue_cap: usize,
        pow: Arc<dyn PowHasher>,
        sink: ResultSink,
    ) -> ThreadPoolVerifier {
        let inner = Arc::new(Inner {
            queue: Mutex::new(VecDeque::with_capacity(queue_cap.min(4096))),
            cv: Condvar::new(),
            stop: AtomicBool::new(false),
            cap: queue_cap,
        });
        let mut handles = Vec::with_capacity(threads);
        for i in 0..threads {
            let inner = Arc::clone(&inner);
            let pow = Arc::clone(&pow);
            let sink = Arc::clone(&sink);
            handles.push(
                std::thread::Builder::new()
                    .name(format!("plaine-share-verify-{i}"))
                    .spawn(move || loop {
                        let work = {
                            let mut q = inner.queue.lock().unwrap_or_else(|e| e.into_inner());
                            loop {
                                if inner.stop.load(Ordering::Relaxed) {
                                    return;
                                }
                                if let Some(w) = q.pop_front() {
                                    break w;
                                }

                                let (g, _) = inner
                                    .cv
                                    .wait_timeout(q, std::time::Duration::from_millis(100))
                                    .unwrap_or_else(|e| e.into_inner());
                                q = g;
                            }
                        };
                        let verdict = verify_one_isolated(pow.as_ref(), &work);
                        sink(VerifyResult {
                            conn: work.conn,
                            request_id: work.request_id,
                            seq: work.seq,
                            verdict,
                            served_difficulty: work.served_difficulty,
                        });
                    })
                    .expect("spawning a verification thread"),
            );
        }
        ThreadPoolVerifier {
            inner,
            threads: handles,
        }
    }

    pub fn queue_len(&self) -> usize {
        self.inner
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn shutdown(self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        self.inner.cv.notify_all();
        for h in self.threads {
            let _ = h.join();
        }
    }
}

impl ShareVerifier for ThreadPoolVerifier {
    fn enqueue(&self, work: ShareWork) -> bool {
        let mut q = self.inner.queue.lock().unwrap_or_else(|e| e.into_inner());
        // refuse rather than block when the queue is full; the caller turns a
        // false into a server-busy answer and refunds the admission slot.
        if q.len() >= self.inner.cap {
            return false;
        }
        q.push_back(work);
        self.inner.cv.notify_one();
        true
    }
}

#[derive(Debug, Default)]
pub struct Admission {
    in_flight: bool,
    queued: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    Now,
    Queue,
    Busy,
}

// One in flight plus one queued bounds a single connection's interpreter cost.
// However many submits it fires, it never has more than two in the system.
impl Admission {
    pub fn request(&mut self) -> Admitted {
        if !self.in_flight {
            self.in_flight = true;
            Admitted::Now
        } else if !self.queued {
            self.queued = true;
            Admitted::Queue
        } else {
            Admitted::Busy
        }
    }

    pub fn complete(&mut self) -> bool {
        self.in_flight = false;
        if self.queued {
            self.queued = false;
            self.in_flight = true;
            true
        } else {
            false
        }
    }

    pub fn outstanding(&self) -> usize {
        usize::from(self.in_flight) + usize::from(self.queued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockBody, MockPow};
    use std::sync::atomic::AtomicUsize;

    fn work(conn: ConnId, target: Target, digest_hint: u8) -> ShareWork {
        let mut header = [0u8; 132];
        header[0] = digest_hint;
        ShareWork {
            conn,
            request_id: Some(1),
            seq: 0,
            header,
            share_target: target,
            served_difficulty: 8_192,
            eligible_for_block: true,
            template: Arc::new(Template {
                id: 1,
                prefix: [0u8; 124],
                height: 1,
                network_target: Target::from_difficulty(u64::MAX / 2),
                new_tip: false,
                body: Arc::new(MockBody::new()),
            }),
        }
    }

    #[test]
    fn admission_is_one_plus_one() {
        let mut a = Admission::default();
        assert_eq!(a.request(), Admitted::Now);
        assert_eq!(a.request(), Admitted::Queue);
        assert_eq!(a.request(), Admitted::Busy);
        assert_eq!(a.request(), Admitted::Busy);
        assert_eq!(a.outstanding(), 2);
        assert!(a.complete(), "the queued share must be released");
        assert_eq!(a.outstanding(), 1);
        assert_eq!(a.request(), Admitted::Queue);
        assert!(a.complete());
        assert!(!a.complete());
        assert_eq!(a.outstanding(), 0);
    }

    #[test]
    fn low_share_never_seals() {
        let pow = MockPow::new();
        let w = work(1, Target::from_difficulty(u64::MAX), 7);
        assert_eq!(verify_one(&pow, &w), Verdict::LowDifficulty);
    }

    #[test]
    fn network_hit_seals_once() {
        let pow = MockPow::new();
        let body = Arc::new(MockBody::new());
        let mut w = work(1, Target::MAX, 3);
        w.template = Arc::new(Template {
            id: 1,
            prefix: [0u8; 124],
            height: 9,
            network_target: Target::MAX,
            new_tip: false,
            body: body.clone(),
        });
        match verify_one(&pow, &w) {
            Verdict::Accepted { block } => assert_eq!(block, Some(SealOutcome::Accepted)),
            other => panic!("{other:?}"),
        }
        assert_eq!(body.sealed(), 1);
    }

    #[test]
    fn stale_credited_accepted_not_sealed() {
        let pow = MockPow::new();
        let body = Arc::new(MockBody::new());
        let mut w = work(1, Target::MAX, 3);
        w.eligible_for_block = false;
        w.template = Arc::new(Template {
            id: 1,
            prefix: [0u8; 124],
            height: 9,
            network_target: Target::MAX,
            new_tip: false,
            body: body.clone(),
        });
        assert_eq!(verify_one(&pow, &w), Verdict::Accepted { block: None });
        assert_eq!(body.sealed(), 0, "a stale share must never build a block");
    }

    #[test]
    fn sealed_nonce_from_header() {
        let pow = MockPow::new();
        let body = Arc::new(MockBody::new());
        let mut w = work(1, Target::MAX, 3);
        w.header[124..].copy_from_slice(&0x00A3_F203_0000_002Au64.to_le_bytes());
        w.template = Arc::new(Template {
            id: 1,
            prefix: [0u8; 124],
            height: 9,
            network_target: Target::MAX,
            new_tip: false,
            body: body.clone(),
        });
        let _ = verify_one(&pow, &w);
        assert_eq!(body.last_nonce(), Some(0x00A3_F203_0000_002A));
    }

    #[test]
    fn pool_reports_every_share() {
        let done = Arc::new(AtomicUsize::new(0));
        let d2 = Arc::clone(&done);
        let v = ThreadPoolVerifier::new(
            2,
            1024,
            Arc::new(MockPow::new()),
            Arc::new(move |_r: VerifyResult| {
                d2.fetch_add(1, Ordering::SeqCst);
            }),
        );
        for i in 0..200 {
            assert!(v.enqueue(work(i, Target::MAX, (i % 251) as u8)));
        }
        let start = std::time::Instant::now();
        while done.load(Ordering::SeqCst) < 200 && start.elapsed().as_secs() < 10 {
            std::thread::yield_now();
        }
        assert_eq!(done.load(Ordering::SeqCst), 200);
        v.shutdown();
    }

    struct PanickingPow;
    impl PowHasher for PanickingPow {
        fn digest(&self, header: &[u8; 132]) -> [u8; 32] {
            assert_ne!(header[0], 0xDE, "the bad header");
            [0u8; 32]
        }
    }

    #[test]
    fn panic_costs_one_share() {
        let bad = work(1, Target::MAX, 0xDE);
        assert_eq!(
            verify_one_isolated(&PanickingPow, &bad),
            Verdict::InternalError
        );

        let good = work(1, Target::MAX, 0x01);
        assert!(matches!(
            verify_one_isolated(&PanickingPow, &good),
            Verdict::Accepted { .. }
        ));
    }

    #[test]
    fn bad_header_does_not_wedge_pool() {
        let seen = Arc::new(Mutex::new(Vec::<Verdict>::new()));
        let s2 = Arc::clone(&seen);
        let v = ThreadPoolVerifier::new(
            2,
            64,
            Arc::new(PanickingPow),
            Arc::new(move |r: VerifyResult| {
                s2.lock().unwrap_or_else(|e| e.into_inner()).push(r.verdict);
            }),
        );
        for i in 0..20 {
            let hint = if i % 2 == 0 { 0xDE } else { 0x01 };
            assert!(v.enqueue(work(i, Target::MAX, hint)));
        }
        let start = std::time::Instant::now();
        loop {
            let n = seen.lock().unwrap_or_else(|e| e.into_inner()).len();
            if n == 20 || start.elapsed().as_secs() > 10 {
                break;
            }
            std::thread::yield_now();
        }
        let got = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(got.len(), 20, "the pool stopped answering");
        assert_eq!(
            got.iter().filter(|v| **v == Verdict::InternalError).count(),
            10
        );

        assert!(v.enqueue(work(99, Target::MAX, 1)));
        v.shutdown();
    }

    #[test]
    fn full_queue_refuses() {
        let v = ThreadPoolVerifier::new(0, 4, Arc::new(MockPow::new()), Arc::new(|_| {}));
        for _ in 0..4 {
            assert!(v.enqueue(work(1, Target::MAX, 1)));
        }
        assert!(
            !v.enqueue(work(1, Target::MAX, 1)),
            "enqueue must never block the caller"
        );
        v.shutdown();
    }
}
