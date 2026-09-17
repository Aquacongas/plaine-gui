use crate::limits::{DEDUP_PER_JOB, JOB_PREFIX_BYTES, JOB_SLOTS};
use crate::login::AddressBytes;
use crate::target::Target;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealOutcome {
    Accepted,
    Obsolete,
    Rejected,
}

pub trait TemplateBody: Send + Sync + 'static {
    fn seal(&self, nonce: u64) -> SealOutcome;
}

pub struct Template {
    pub id: u64,
    pub prefix: [u8; JOB_PREFIX_BYTES],
    pub height: u64,
    pub network_target: Target,
    pub new_tip: bool,
    pub body: Arc<dyn TemplateBody>,
}

impl core::fmt::Debug for Template {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Template")
            .field("id", &self.id)
            .field("height", &self.height)
            .field("new_tip", &self.new_tip)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobError {
    NotReady,
}

pub trait JobSource: Send + Sync + 'static {
    fn current(&self, recipient: &AddressBytes) -> Result<Arc<Template>, JobError>;

    fn generation(&self) -> u64;
}

pub struct Job {
    pub job_id: u32,
    pub template: Arc<Template>,
    pub served_target: Target,
    pub served_difficulty: u64,
    pub pushed_at_ms: u64,
    dedup: Option<Box<Dedup>>,
}

impl Job {
    fn check_and_record(&mut self, nonce: u64) -> bool {
        let d = self.dedup.get_or_insert_with(|| Box::new(Dedup::new()));
        d.check_and_record(nonce)
    }
}

struct Dedup {
    nonces: [u64; DEDUP_PER_JOB],
    len: u16,
}

impl Dedup {
    fn new() -> Dedup {
        Dedup {
            nonces: [0u64; DEDUP_PER_JOB],
            len: 0,
        }
    }

    fn check_and_record(&mut self, nonce: u64) -> bool {
        let n = self.len as usize;
        // linear scan; n is <= 256 and this is cold, so a set would only cost memory.
        if self.nonces[..n].contains(&nonce) {
            return true;
        }
        // Once full we stop recording instead of overwriting; forgetting a
        // nonce would open a replay. The cap sits well above the per-job submit
        // ceiling, so at protocol rate we never reach it anyway.
        if n < DEDUP_PER_JOB {
            self.nonces[n] = nonce;
            self.len += 1;
        }

        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobRef {
    Live(usize),
    Previous,
}

pub fn dedup_bytes() -> usize {
    core::mem::size_of::<Dedup>()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobLookup {
    Live(usize),
    StaleCredited,
    Stale,
    Unknown,
}

impl JobLookup {
    pub fn job_ref(self) -> Option<JobRef> {
        match self {
            JobLookup::Live(i) => Some(JobRef::Live(i)),
            JobLookup::StaleCredited => Some(JobRef::Previous),
            _ => None,
        }
    }
}

pub struct JobSlots {
    ring: Vec<Option<Job>>,
    next_id: u32,
    head: usize,
    previous: Option<Job>,
    last_clean_ms: u64,
}

impl Default for JobSlots {
    fn default() -> Self {
        Self::new()
    }
}

impl JobSlots {
    pub fn new() -> JobSlots {
        let mut ring = Vec::with_capacity(JOB_SLOTS);
        for _ in 0..JOB_SLOTS {
            ring.push(None);
        }
        JobSlots {
            ring,
            next_id: 0,
            head: 0,
            previous: None,
            last_clean_ms: 0,
        }
    }

    pub fn push(
        &mut self,
        template: Arc<Template>,
        served_target: Target,
        served_difficulty: u64,
        clean: bool,
        now_ms: u64,
    ) -> u32 {
        if clean {
            // a new tip retires every current job. keep only the old head as
            // `previous`, credited for a short grace window; a solution to any
            // other pre-clean job is refused rather than sealed on a stale tip.
            self.previous = self.ring[self.head].take();
            self.last_clean_ms = now_ms;
            for slot in self.ring.iter_mut() {
                *slot = None;
            }
            self.head = 0;
        } else {
            self.head = (self.head + 1) % JOB_SLOTS;
        }
        let job_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.ring[self.head] = Some(Job {
            job_id,
            template,
            served_target,
            served_difficulty,
            pushed_at_ms: now_ms,
            dedup: None,
        });
        job_id
    }

    pub fn newest(&self) -> Option<&Job> {
        self.ring[self.head].as_ref()
    }

    pub fn lookup(&self, job_id: u32, now_ms: u64) -> JobLookup {
        for (i, slot) in self.ring.iter().enumerate() {
            if let Some(j) = slot {
                if j.job_id == job_id {
                    return JobLookup::Live(i);
                }
            }
        }
        if self.previous.as_ref().map(|j| j.job_id) == Some(job_id) {
            if now_ms.saturating_sub(self.last_clean_ms)
                <= crate::limits::STALE_CREDIT_GRACE.as_millis() as u64
            {
                return JobLookup::StaleCredited;
            }
            return JobLookup::Stale;
        }

        // once-issued-but-gone is stale; never-issued is unknown. scored apart.
        if job_id < self.next_id {
            JobLookup::Stale
        } else {
            JobLookup::Unknown
        }
    }

    pub fn get(&self, r: JobRef) -> Option<&Job> {
        match r {
            JobRef::Live(i) => self.ring.get(i).and_then(|s| s.as_ref()),
            JobRef::Previous => self.previous.as_ref(),
        }
    }

    pub fn check_duplicate(&mut self, r: JobRef, nonce: u64) -> bool {
        let job = match r {
            JobRef::Live(i) => self.ring.get_mut(i).and_then(|s| s.as_mut()),
            JobRef::Previous => self.previous.as_mut(),
        };
        match job {
            Some(j) => j.check_and_record(nonce),
            None => false,
        }
    }

    pub fn resident_bytes(&self) -> usize {
        let base = (JOB_SLOTS + 1) * core::mem::size_of::<Option<Job>>();
        let dedup: usize = self
            .ring
            .iter()
            .chain(core::iter::once(&self.previous))
            .filter(|s| s.as_ref().is_some_and(|j| j.dedup.is_some()))
            .count()
            * core::mem::size_of::<Dedup>();
        base + dedup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockBody;

    fn tmpl(id: u64, new_tip: bool) -> Arc<Template> {
        Arc::new(Template {
            id,
            prefix: [0u8; JOB_PREFIX_BYTES],
            height: 100 + id,
            network_target: Target::from_difficulty(1_000_000),
            new_tip,
            body: Arc::new(MockBody::new()),
        })
    }

    #[test]
    fn job_ids_are_per_connection_and_monotonic() {
        let mut s = JobSlots::new();
        let a = s.push(tmpl(1, false), Target::MAX, 1, false, 0);
        let b = s.push(tmpl(1, false), Target::MAX, 1, false, 0);
        assert_eq!((a, b), (0, 1), "not the tip hash: a per-connection counter");
    }

    #[test]
    fn four_jobs_stay_live_without_clean() {
        let mut s = JobSlots::new();
        let ids: Vec<u32> = (0..4)
            .map(|_| s.push(tmpl(1, false), Target::MAX, 1, false, 0))
            .collect();
        for id in &ids {
            assert!(matches!(s.lookup(*id, 0), JobLookup::Live(_)));
        }

        let fifth = s.push(tmpl(1, false), Target::MAX, 1, false, 0);
        assert!(matches!(s.lookup(ids[0], 0), JobLookup::Stale));
        assert!(matches!(s.lookup(fifth, 0), JobLookup::Live(_)));
    }

    #[test]
    fn clean_credits_previous_tip() {
        let mut s = JobSlots::new();
        let old = s.push(tmpl(1, false), Target::MAX, 1, false, 0);
        s.push(tmpl(2, true), Target::MAX, 1, true, 10_000);
        assert_eq!(s.lookup(old, 10_100), JobLookup::StaleCredited);
        assert_eq!(s.lookup(old, 15_000), JobLookup::StaleCredited);
        assert_eq!(s.lookup(old, 15_001), JobLookup::Stale);
    }

    #[test]
    fn previous_job_survives_clean_push() {
        let mut s = JobSlots::new();
        let old = s.push(
            tmpl(1, false),
            Target::from_difficulty(4_096),
            4_096,
            false,
            0,
        );
        s.push(tmpl(2, true), Target::MAX, 1, true, 1_000);
        let r = s
            .lookup(old, 1_500)
            .job_ref()
            .expect("a job to verify against");
        let job = s.get(r).expect("the previous job is still here");
        assert_eq!(job.job_id, old);
        assert_eq!(job.served_difficulty, 4_096);
        assert_eq!(job.served_target, Target::from_difficulty(4_096));
        assert_eq!(job.template.height, 101);

        assert!(!s.check_duplicate(r, 7));
        assert!(s.check_duplicate(r, 7));
    }

    #[test]
    fn unknown_versus_stale_are_distinguished() {
        let mut s = JobSlots::new();
        let id = s.push(tmpl(1, false), Target::MAX, 1, false, 0);
        assert!(matches!(s.lookup(id, 0), JobLookup::Live(_)));
        assert!(matches!(s.lookup(999, 0), JobLookup::Unknown));
    }

    #[test]
    fn duplicates_caught_array_is_lazy() {
        let mut s = JobSlots::new();
        let id = s.push(tmpl(1, false), Target::MAX, 1, false, 0);
        let idx = s.lookup(id, 0).job_ref().expect("live");

        let empty = (JOB_SLOTS + 1) * core::mem::size_of::<Option<Job>>();
        assert_eq!(s.resident_bytes(), empty);
        assert!(!s.check_duplicate(idx, 42));
        assert!(s.check_duplicate(idx, 42));
        assert!(!s.check_duplicate(idx, 43));
        assert!(s.resident_bytes() > empty);
    }

    #[test]
    fn dedup_cap_is_unreachable_at_the_protocol_rate() {
        let admitted = crate::limits::SUBMIT_BURST + crate::limits::SUBMIT_RATE_PER_SEC * 60.0;
        assert!(
            admitted < DEDUP_PER_JOB as f64,
            "{admitted} submits possible against a cap of {DEDUP_PER_JOB}"
        );
    }

    #[test]
    fn dedup_is_eight_kib_for_four_jobs() {
        assert_eq!(core::mem::size_of::<Dedup>(), 2_048 + 8);
    }

    #[test]
    fn clean_push_invalidates_all_older_jobs() {
        let mut s = JobSlots::new();
        let target = Target::from_difficulty(8_192);

        let mut ids = Vec::new();
        for _ in 0..JOB_SLOTS {
            ids.push(s.push(tmpl(1, false), target, 8_192, false, 1_000));
        }
        for id in &ids {
            assert!(
                matches!(s.lookup(*id, 1_000), JobLookup::Live(_)),
                "job {id} should be live before the tip changes"
            );
        }

        let fresh = s.push(tmpl(2, true), target, 8_192, true, 2_000);
        assert!(matches!(s.lookup(fresh, 2_000), JobLookup::Live(_)));

        let head = *ids.last().expect("ids");
        assert_eq!(s.lookup(head, 2_000), JobLookup::StaleCredited);

        for id in &ids[..ids.len() - 1] {
            assert_eq!(
                s.lookup(*id, 2_000),
                JobLookup::Stale,
                "job {id} predates the clean push and is still Live: a solution \
                 for it would be sealed into a block on a template the chain has \
                 already moved past"
            );
        }
    }

    #[test]
    fn full_dedup_stops_recording() {
        let mut d = Dedup::new();
        for n in 0..DEDUP_PER_JOB as u64 {
            assert!(!d.check_and_record(n), "nonce {n} is new");
        }

        assert!(!d.check_and_record(9_999));

        assert!(
            d.check_and_record(0),
            "nonce 0 was forgotten, which is a replay"
        );
        assert!(
            d.check_and_record(1),
            "nonce 1 was forgotten, which is a replay"
        );
        assert!(
            d.check_and_record(DEDUP_PER_JOB as u64 - 1),
            "the newest recorded nonce was forgotten"
        );
    }
}
