use crate::job::{JobError, JobSource, SealOutcome, Template, TemplateBody};
use crate::limits::JOB_PREFIX_BYTES;
use crate::login::AddressBytes;
use crate::target::Target;
use crate::verify::PowHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct MockBody {
    sealed: AtomicU64,
    last_nonce: AtomicU64,
    pub outcome: Mutex<SealOutcome>,
}

impl MockBody {
    pub fn new() -> MockBody {
        MockBody {
            sealed: AtomicU64::new(0),
            last_nonce: AtomicU64::new(u64::MAX),
            outcome: Mutex::new(SealOutcome::Accepted),
        }
    }

    pub fn sealed(&self) -> u64 {
        self.sealed.load(Ordering::SeqCst)
    }

    pub fn last_nonce(&self) -> Option<u64> {
        match self.last_nonce.load(Ordering::SeqCst) {
            u64::MAX => None,
            n => Some(n),
        }
    }
}

impl Default for MockBody {
    fn default() -> Self {
        MockBody::new()
    }
}

impl TemplateBody for MockBody {
    fn seal(&self, nonce: u64) -> SealOutcome {
        self.sealed.fetch_add(1, Ordering::SeqCst);
        self.last_nonce.store(nonce, Ordering::SeqCst);
        *self.outcome.lock().expect("mock body poisoned")
    }
}

#[derive(Debug, Default)]
pub struct MockPow;

impl MockPow {
    pub fn new() -> MockPow {
        MockPow
    }
}

impl PowHasher for MockPow {
    fn digest(&self, header: &[u8; 132]) -> [u8; 32] {
        plaine_consensus::blake3::hash(header)
    }
}

pub struct MockJobSource {
    inner: Mutex<Inner>,
}

struct Inner {
    prefix: [u8; JOB_PREFIX_BYTES],
    height: u64,
    network_target: Target,
    generation: u64,
    next_id: u64,
    new_tip: bool,
    per_recipient: bool,
    ready: bool,
    bodies: Vec<Arc<MockBody>>,
}

impl MockJobSource {
    pub fn new(height: u64, network_target: Target) -> MockJobSource {
        MockJobSource {
            inner: Mutex::new(Inner {
                prefix: [0u8; JOB_PREFIX_BYTES],
                height,
                network_target,
                generation: 1,
                next_id: 1,
                new_tip: true,
                per_recipient: false,
                ready: true,
                bodies: Vec::new(),
            }),
        }
    }

    pub fn per_recipient(self, on: bool) -> Self {
        self.inner.lock().expect("mock poisoned").per_recipient = on;
        self
    }

    pub fn set_ready(&self, ready: bool) {
        self.inner.lock().expect("mock poisoned").ready = ready;
    }

    pub fn new_tip(&self, height: u64) {
        let mut i = self.inner.lock().expect("mock poisoned");
        i.height = height;
        i.generation += 1;
        i.new_tip = true;
        i.prefix[0] = i.prefix[0].wrapping_add(1);
    }

    pub fn refresh(&self) {
        let mut i = self.inner.lock().expect("mock poisoned");
        i.generation += 1;
        i.new_tip = false;
        i.prefix[1] = i.prefix[1].wrapping_add(1);
    }

    pub fn set_network_target(&self, t: Target) {
        self.inner.lock().expect("mock poisoned").network_target = t;
    }

    pub fn blocks_sealed(&self) -> u64 {
        self.inner
            .lock()
            .expect("mock poisoned")
            .bodies
            .iter()
            .map(|b| b.sealed())
            .sum()
    }
}

impl JobSource for MockJobSource {
    fn current(&self, recipient: &AddressBytes) -> Result<Arc<Template>, JobError> {
        let mut i = self.inner.lock().expect("mock poisoned");
        if !i.ready {
            return Err(JobError::NotReady);
        }
        let mut prefix = i.prefix;
        if i.per_recipient {
            prefix[44..64].copy_from_slice(recipient);
        }
        let body = Arc::new(MockBody::new());
        i.bodies.push(Arc::clone(&body));
        let id = i.next_id;
        i.next_id += 1;
        Ok(Arc::new(Template {
            id,
            prefix,
            height: i.height,
            network_target: i.network_target,
            new_tip: i.new_tip,
            body,
        }))
    }

    fn generation(&self) -> u64 {
        self.inner.lock().expect("mock poisoned").generation
    }
}

pub struct InlineVerifier {
    pow: Arc<dyn PowHasher>,
    sink: crate::verify::ResultSink,
    pub refuse: std::sync::atomic::AtomicBool,
}

impl InlineVerifier {
    pub fn new(pow: Arc<dyn PowHasher>, sink: crate::verify::ResultSink) -> InlineVerifier {
        InlineVerifier {
            pow,
            sink,
            refuse: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl crate::verify::ShareVerifier for InlineVerifier {
    fn enqueue(&self, work: crate::verify::ShareWork) -> bool {
        if self.refuse.load(Ordering::SeqCst) {
            return false;
        }

        let verdict = crate::verify::verify_one_isolated(self.pow.as_ref(), &work);
        (self.sink)(crate::verify::VerifyResult {
            conn: work.conn,
            request_id: work.request_id,
            seq: work.seq,
            verdict,
            served_difficulty: work.served_difficulty,
        });
        true
    }
}
