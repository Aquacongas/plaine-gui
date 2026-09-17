use crate::abuse::{BanTable, DiffCache, Severity, TokenBucket};
use crate::job::{JobLookup, JobRef, JobSlots, JobSource, SealOutcome};
use crate::json::Doc;
use crate::limits::*;
use crate::login::{parse_login, Login};
use crate::metrics::Metrics;
use crate::nonce::{assemble_header, E1};
use crate::proto::{self, ErrorCode, Request, Verb};
use crate::target::Target;
use crate::verify::{Admitted, ConnId, ShareVerifier, ShareWork, Verdict, VerifyResult};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub struct Shared {
    pub bans: Mutex<BanTable>,
    pub e1: Arc<dyn crate::nonce::SliceSource>,
    pub diffs: Mutex<DiffCache>,
    pub accept: Mutex<TokenBucket>,
    pub jobs: Arc<dyn JobSource>,
    pub verifier: Arc<dyn ShareVerifier>,
    pub metrics: Metrics,
    pub caps: Caps,
    pub cfg: ServerConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub mode: Mode,
    pub address_hrp: String,
    pub setpoint_secs: f64,
    pub max_line_pre_auth: usize,
    pub max_line_post_auth: usize,
    pub tick_ms: u64,
    pub auth_deadline_ms: u64,
    pub idle_evict_ms: u64,
    pub read_deadline_ms: u64,
    pub write_timeout_ms: u64,
    pub out_buf_cap: usize,
    pub rates: RatePolicy,
    pub cadence: Cadence,
    pub diff: DiffPolicy,
    pub bans: BanPolicy,
    pub vardiff_enabled: bool,
    pub vardiff_fixed_diff: u64,
    pub vardiff_max_diff: u64,
}

impl ServerConfig {
    pub fn for_mode(mode: Mode) -> ServerConfig {
        ServerConfig {
            mode,
            address_hrp: plaine_consensus::constants::ADDRESS_HRP.to_string(),
            setpoint_secs: VARDIFF_SETPOINT_SECS,
            max_line_pre_auth: MAX_LINE_PRE_AUTH,
            max_line_post_auth: MAX_LINE_POST_AUTH,
            tick_ms: VARDIFF_TICK.as_millis() as u64,
            auth_deadline_ms: AUTH_DEADLINE.as_millis() as u64,
            idle_evict_ms: IDLE_EVICT.as_millis() as u64,
            read_deadline_ms: READ_DEADLINE.as_millis() as u64,
            write_timeout_ms: WRITE_TIMEOUT.as_millis() as u64,
            out_buf_cap: OUT_BUF_CAP,
            rates: RatePolicy::DEFAULT,
            cadence: Cadence::DEFAULT,
            diff: DiffPolicy::DEFAULT,
            bans: BanPolicy::DEFAULT,
            vardiff_enabled: true,
            vardiff_fixed_diff: 0,
            vardiff_max_diff: 0,
        }
    }
}

fn build_bucket(enabled: bool, rate_per_sec: f64, burst: f64, now_ms: u64) -> TokenBucket {
    // disabled, or a zero rate, means "no limit" rather than a bucket that refuses
    // everything; that is how an operator turns a rate limit off from config.
    if !enabled || rate_per_sec <= 0.0 {
        TokenBucket::unlimited()
    } else {
        TokenBucket::new(rate_per_sec, burst, now_ms)
    }
}

fn vardiff_fixed(cfg: &ServerConfig) -> u64 {
    if cfg.vardiff_fixed_diff > 0 {
        cfg.vardiff_fixed_diff
    } else {
        cfg.diff.start_diff
    }
}

fn vardiff_ceiling(cfg: &ServerConfig, network: u64) -> u64 {
    if cfg.vardiff_max_diff > 0 {
        network.min(cfg.vardiff_max_diff)
    } else {
        network
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    GarbageBeforeAuth,
    BadMessageAfterAuth,
    AuthTimeout,
    Idle,
    Banned,
    SlowClient,
    LineFlood,
    ReadTimeout,
    SliceRevoked,
    Shutdown,
}

#[derive(Debug)]
pub enum Action {
    Verify(Box<ShareWork>),
    Close(CloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Subscribed,
    Authorized,
}

pub struct Session {
    pub id: ConnId,
    pub ip: IpAddr,
    pub outbuf: Vec<u8>,
    pub actions: Vec<Action>,
    phase: Phase,
    e1: Option<E1>,
    sub: u32,
    login: Option<Login>,
    doc: Doc,
    jobs: JobSlots,
    vardiff: crate::vardiff::Vardiff,
    admission: crate::verify::Admission,
    submits: TokenBucket,
    lines: TokenBucket,
    pending: Option<Box<ShareWork>>,
    seq: u64,
    storm_floor: Option<u64>,
    shares_at_current_diff: u64,
    accepted_at_ms: u64,
    last_push_ms: u64,
    last_generation: u64,
    last_clean_gen: u64,
    last_target_sent: Option<Target>,
    first_job_ms: Option<u64>,
    last_accepted_share_ms: u64,
    last_tick_ms: u64,
    throttle_windows: u32,
    throttle_window_start_ms: u64,
    throttled_in_window: bool,
    pub accepted_shares: u64,
    pub accepted_difficulty: u128,
}

// A read-only snapshot of one live session, for the node's introspection RPC.
// Times are in the server's monotonic-ms domain; the reader turns them into
// ages against the same clock. Never carries a key or a share payload.
#[derive(Debug, Clone)]
pub struct SessionCard {
    pub id: ConnId,
    pub ip: IpAddr,
    pub connected_ms: u64,
    pub authorized: bool,
    pub worker: String,
    pub address: String,
    pub rig: String,
    pub accepted_shares: u64,
    pub accepted_difficulty: u128,
    pub last_share_ms: u64,
    pub had_share: bool,
    pub difficulty: u64,
}

impl Session {
    pub fn card(&self) -> SessionCard {
        let (worker, address, rig) = match &self.login {
            Some(l) => (l.worker_id(), l.address.clone(), l.rig.clone()),
            None => (String::new(), String::new(), String::new()),
        };
        SessionCard {
            id: self.id,
            ip: self.ip,
            connected_ms: self.accepted_at_ms,
            authorized: self.is_authorized(),
            worker,
            address,
            rig,
            accepted_shares: self.accepted_shares,
            accepted_difficulty: self.accepted_difficulty,
            last_share_ms: self.last_accepted_share_ms,
            had_share: self.accepted_shares > 0,
            difficulty: self.difficulty(),
        }
    }
}

impl Session {
    pub fn new(id: ConnId, ip: IpAddr, now_ms: u64, sh: &Shared) -> Session {
        let mut vardiff = crate::vardiff::Vardiff::new(
            sh.cfg.diff.start_diff,
            sh.cfg.diff.min_diff,
            vardiff_ceiling(&sh.cfg, u64::MAX),
            sh.cfg.setpoint_secs,
            now_ms,
        );
        vardiff.set_cadence(sh.cfg.cadence);
        if !sh.cfg.vardiff_enabled {
            vardiff.pin(vardiff_fixed(&sh.cfg));
        }
        Session {
            id,
            ip,
            outbuf: Vec::with_capacity(512),
            actions: Vec::new(),
            phase: Phase::Fresh,
            e1: None,
            sub: 0,
            login: None,
            doc: Doc::new(),
            jobs: JobSlots::new(),
            vardiff,
            admission: crate::verify::Admission::default(),
            submits: build_bucket(
                sh.cfg.rates.submit_enabled,
                sh.cfg.rates.submit_per_sec,
                sh.cfg.rates.submit_burst,
                now_ms,
            ),
            lines: build_bucket(
                sh.cfg.rates.line_enabled,
                sh.cfg.rates.line_per_sec,
                sh.cfg.rates.line_burst,
                now_ms,
            ),
            pending: None,
            seq: 0,
            storm_floor: None,
            shares_at_current_diff: 0,
            accepted_at_ms: now_ms,
            last_push_ms: 0,
            last_generation: 0,
            last_clean_gen: u64::MAX,
            last_target_sent: None,
            first_job_ms: None,
            last_accepted_share_ms: now_ms,
            last_tick_ms: now_ms,
            throttle_windows: 0,
            throttle_window_start_ms: now_ms,
            throttled_in_window: false,
            accepted_shares: 0,
            accepted_difficulty: 0,
        }
    }

    pub fn is_authorized(&self) -> bool {
        self.phase == Phase::Authorized
    }

    pub fn login(&self) -> Option<&Login> {
        self.login.as_ref()
    }

    pub fn difficulty(&self) -> u64 {
        self.vardiff.current()
    }

    pub fn e1(&self) -> Option<E1> {
        self.e1
    }

    pub fn line_limit(&self, cfg: &ServerConfig) -> usize {
        if self.phase == Phase::Authorized {
            cfg.max_line_post_auth
        } else {
            cfg.max_line_pre_auth
        }
    }

    pub fn charge_line(&mut self, now_ms: u64, sh: &Shared) -> bool {
        if self.lines.take(now_ms) {
            return true;
        }
        Metrics::inc(&sh.metrics.closed_line_flood);
        self.score(50, Severity::Hard, now_ms, sh);
        self.close(CloseReason::LineFlood);
        false
    }

    pub fn on_line(&mut self, line: &[u8], now_ms: u64, sh: &Shared) {
        if !self.charge_line(now_ms, sh) {
            return;
        }
        let limit = self.line_limit(&sh.cfg);

        let parsed = proto::parse_verb(&mut self.doc, line, limit);
        let req = match parsed {
            Ok(r) => r,
            Err(e) => {
                Metrics::inc(&sh.metrics.bad_json);
                if self.phase == Phase::Authorized {
                    self.reject_and_score(None, ErrorCode::BadMessage, now_ms, sh);
                    self.close(CloseReason::BadMessageAfterAuth);
                } else {
                    let _ = e;
                    if let Ok(mut b) = sh.bans.lock() {
                        b.throttle(self.ip, now_ms);
                    }
                    self.close(CloseReason::GarbageBeforeAuth);
                }
                return;
            }
        };

        match req {
            Verb::KeepAlive { id } => self.on_keepalive(id, sh),
            Verb::Request(Request::Subscribe { id, .. }) => self.on_subscribe(id, now_ms, sh),
            Verb::Request(Request::Authorize { id, login }) => {
                self.on_authorize(id, &login, now_ms, sh)
            }
            Verb::Request(Request::Submit {
                id, job_id, nonce, ..
            }) => self.on_submit(id, job_id, nonce, now_ms, sh),
            Verb::Request(Request::Unknown { id }) => {
                self.reject_and_score(id, ErrorCode::UnknownMethod, now_ms, sh);
            }
        }
    }

    fn on_keepalive(&mut self, id: Option<u64>, sh: &Shared) {
        Metrics::inc(&sh.metrics.keepalives);
        proto::write_ok_true(&mut self.outbuf, id);
    }

    fn on_subscribe(&mut self, id: Option<u64>, now_ms: u64, sh: &Shared) {
        if self.phase != Phase::Fresh {
            self.reject_and_score(id, ErrorCode::UnknownMethod, now_ms, sh);
            return;
        }
        let (e1, sub) = match sh.e1.acquire() {
            Some(pair) => pair,
            None => {
                self.reject_and_score(id, ErrorCode::ServerBusy, now_ms, sh);
                return;
            }
        };
        self.e1 = Some(e1);
        self.sub = sub;
        self.phase = Phase::Subscribed;
        proto::write_subscribe_result(&mut self.outbuf, id, e1, sub, sh.e1.sub_bits());
        Metrics::inc(&sh.metrics.subscribes);
    }

    fn on_authorize(&mut self, id: Option<u64>, raw: &str, now_ms: u64, sh: &Shared) {
        if self.phase != Phase::Subscribed {
            self.reject_and_score(id, ErrorCode::Unauthorized, now_ms, sh);
            return;
        }
        let login = match parse_login(raw, &sh.cfg.address_hrp) {
            Ok(l) => l,
            Err(_) => {
                Metrics::inc(&sh.metrics.authorizes_bad);
                self.reject_and_score(id, ErrorCode::Unauthorized, now_ms, sh);
                return;
            }
        };

        let (start, storm_floor) = {
            let mut d = sh.diffs.lock().unwrap_or_else(|e| e.into_inner());
            let (start, floor) = d.start_for(&login.address_bytes, now_ms);
            let floor2 = d.note_login(&login.address_bytes, start, now_ms);
            (start, floor.or(floor2))
        };
        let network_diff = self.network_difficulty(sh);

        self.storm_floor = storm_floor.map(|f| f.max(sh.cfg.diff.min_diff));
        let min = self.vardiff_min(sh);
        let max = vardiff_ceiling(&sh.cfg, network_diff);
        self.vardiff = crate::vardiff::Vardiff::new(start, min, max, sh.cfg.setpoint_secs, now_ms);
        self.vardiff.set_cadence(sh.cfg.cadence);
        if !sh.cfg.vardiff_enabled {
            self.vardiff.pin(vardiff_fixed(&sh.cfg));
        }
        if let Some(pin) = login.pinned_difficulty {
            self.vardiff.pin(pin);
        }

        self.login = Some(login);
        self.phase = Phase::Authorized;
        proto::write_ok_true(&mut self.outbuf, id);
        Metrics::inc(&sh.metrics.authorizes_ok);

        self.push_job(now_ms, sh, true);
    }

    fn on_submit(&mut self, id: Option<u64>, job_id: u32, nonce: u64, now_ms: u64, sh: &Shared) {
        Metrics::inc(&sh.metrics.shares_submitted);
        if self.phase != Phase::Authorized {
            self.reject_and_score(id, ErrorCode::Unauthorized, now_ms, sh);
            return;
        }

        let (slot, eligible_for_block) = match self.jobs.lookup(job_id, now_ms) {
            JobLookup::Live(i) => (JobRef::Live(i), true),
            // inside the grace window after a new tip: credit the share to the
            // miner but mark it ineligible so it can never be sealed into a block
            // on a template the chain has already moved past.
            JobLookup::StaleCredited => {
                Metrics::inc(&sh.metrics.rej_stale_credited);
                (JobRef::Previous, false)
            }
            JobLookup::Stale => {
                Metrics::inc(&sh.metrics.rej_stale);
                self.reject_and_score(id, ErrorCode::StaleShare, now_ms, sh);
                return;
            }
            JobLookup::Unknown => {
                Metrics::inc(&sh.metrics.rej_unknown_job);
                self.reject_and_score(id, ErrorCode::UnknownJob, now_ms, sh);
                return;
            }
        };

        let e1 = match self.e1 {
            Some(e) => e,
            None => {
                self.reject_and_score(id, ErrorCode::Unauthorized, now_ms, sh);
                return;
            }
        };

        // Check order matters here. An out-of-slice nonce is the client's fault
        // and is scored; a slice we no longer hold is our upstream's fault and
        // is not. Both settle before we spend a submit token or touch dedup.
        if !crate::nonce::slice_owns(e1, self.sub, sh.e1.sub_bits(), nonce) {
            Metrics::inc(&sh.metrics.rej_out_of_slice);
            self.reject_and_score(id, ErrorCode::NonceOutOfSlice, now_ms, sh);
            return;
        }

        if !sh.e1.holds(e1, self.sub) {
            self.revoke(id, sh);
            return;
        }

        if !self.submits.take(now_ms) {
            Metrics::inc(&sh.metrics.rej_throttled);
            self.note_throttled(now_ms, sh);
            proto::write_error(&mut self.outbuf, id, ErrorCode::Throttled);
            return;
        }

        if self.jobs.check_duplicate(slot, nonce) {
            Metrics::inc(&sh.metrics.rej_duplicate);
            self.reject_and_score(id, ErrorCode::DuplicateShare, now_ms, sh);
            return;
        }

        let job = match self.jobs.get(slot) {
            Some(j) => j,
            None => return,
        };
        self.seq += 1;
        let work = Box::new(ShareWork {
            conn: self.id,
            request_id: id,
            seq: self.seq,
            header: assemble_header(&job.template.prefix, nonce),
            share_target: job.served_target,
            served_difficulty: job.served_difficulty,
            eligible_for_block,
            template: Arc::clone(&job.template),
        });

        match self.admission.request() {
            Admitted::Now => self.dispatch(work, sh),
            Admitted::Queue => self.pending = Some(work),
            Admitted::Busy => {
                Metrics::inc(&sh.metrics.rej_server_busy);
                proto::write_error(&mut self.outbuf, id, ErrorCode::ServerBusy);
            }
        }
    }

    fn dispatch(&mut self, work: Box<ShareWork>, sh: &Shared) {
        Metrics::inc(&sh.metrics.shares_verified);
        self.actions.push(Action::Verify(work));
    }

    pub fn on_verify_result(&mut self, r: VerifyResult, now_ms: u64, sh: &Shared) {
        if r.conn != self.id || r.seq > self.seq {
            return;
        }
        match r.verdict {
            Verdict::Accepted { block } => {
                Metrics::inc(&sh.metrics.shares_accepted);
                Metrics::add(&sh.metrics.shares_accepted_difficulty, r.served_difficulty);
                self.accepted_shares += 1;
                self.accepted_difficulty += r.served_difficulty as u128;
                self.last_accepted_share_ms = now_ms;
                if let Some(outcome) = block {
                    if outcome == SealOutcome::Accepted {
                        Metrics::inc(&sh.metrics.blocks_found);
                    }
                }

                proto::write_ok_true(&mut self.outbuf, r.request_id);

                // only cache a difficulty the miner actually earned at, and only
                // after enough shares, so a pinned or one-off value never becomes
                // another connection's warm-up start. pinned diffs are skipped.
                if r.served_difficulty == self.vardiff.current() && !self.vardiff.is_pinned() {
                    self.shares_at_current_diff += 1;
                    let n = self.shares_at_current_diff;

                    if n == DIFF_CACHE_MIN_SHARES || (n > DIFF_CACHE_MIN_SHARES && n % 64 == 0) {
                        self.remember_difficulty(r.served_difficulty, now_ms, sh);
                    }
                }

                if let Some(newd) = self.vardiff.on_share(r.served_difficulty, now_ms) {
                    self.retarget(newd, now_ms, sh);
                }
            }
            Verdict::LowDifficulty => {
                Metrics::inc(&sh.metrics.rej_low_difficulty);
                self.reject_and_score(r.request_id, ErrorCode::LowDifficulty, now_ms, sh);
            }
            Verdict::InternalError => {
                Metrics::inc(&sh.metrics.verify_internal_errors);
                Metrics::inc(&sh.metrics.rej_server_busy);
                proto::write_error(&mut self.outbuf, r.request_id, ErrorCode::ServerBusy);
            }
        }

        if self.admission.complete() {
            if let Some(w) = self.pending.take() {
                self.dispatch(w, sh);
            }
        }
    }

    pub fn on_verify_refused(&mut self, request_id: Option<u64>, sh: &Shared) {
        Metrics::inc(&sh.metrics.rej_server_busy);
        proto::write_error(&mut self.outbuf, request_id, ErrorCode::ServerBusy);
        if self.admission.complete() {
            if let Some(w) = self.pending.take() {
                self.dispatch(w, sh);
            }
        }
    }

    pub fn on_tick(&mut self, now_ms: u64, sh: &Shared) {
        self.last_tick_ms = now_ms;

        if self.phase != Phase::Authorized
            && sh.cfg.auth_deadline_ms != 0
            && now_ms.saturating_sub(self.accepted_at_ms) > sh.cfg.auth_deadline_ms
        {
            Metrics::inc(&sh.metrics.closed_auth_timeout);
            self.close(CloseReason::AuthTimeout);
            return;
        }

        if !self.check_slice(sh) {
            return;
        }

        if self.phase != Phase::Authorized {
            return;
        }

        if let Some(newd) = self.vardiff.on_tick(now_ms) {
            self.retarget(newd, now_ms, sh);
        }

        let gen = sh.jobs.generation();
        let refresh_due =
            now_ms.saturating_sub(self.last_push_ms) >= TEMPLATE_REFRESH.as_millis() as u64;
        if gen != self.last_generation || refresh_due {
            self.push_job(now_ms, sh, false);
        }

        // the idle clock only starts once a first job went out, so miners waiting
        // on a still-syncing node are never evicted for being idle.
        if sh.cfg.idle_evict_ms != 0 {
            if let Some(first) = self.first_job_ms {
                let since = now_ms.saturating_sub(self.last_accepted_share_ms.max(first));
                if since > sh.cfg.idle_evict_ms {
                    Metrics::inc(&sh.metrics.closed_idle);
                    self.close(CloseReason::Idle);
                    return;
                }
            }
        }

        if now_ms.saturating_sub(self.throttle_window_start_ms) >= 10_000 {
            // one throttled 10 s window is just backpressure. three in a row is
            // the point where it starts to look deliberate, so small score then.
            if self.throttled_in_window {
                self.throttle_windows += 1;
                if self.throttle_windows >= 3 {
                    self.score(5, Severity::Hard, now_ms, sh);
                }
            } else {
                self.throttle_windows = 0;
            }
            self.throttled_in_window = false;
            self.throttle_window_start_ms = now_ms;
        }

        if sh.cfg.out_buf_cap != 0 && self.outbuf.len() > sh.cfg.out_buf_cap {
            Metrics::inc(&sh.metrics.closed_slow_client);
            self.close(CloseReason::SlowClient);
        }
    }

    pub fn push_job(&mut self, now_ms: u64, sh: &Shared, force_target: bool) {
        let login = match &self.login {
            Some(l) => l,
            None => return,
        };
        let template = match sh.jobs.current(&login.address_bytes) {
            Ok(t) => t,
            Err(_) => return,
        };

        let network_diff = template.network_target.to_difficulty();
        let min = self.vardiff_min(sh);
        let max = vardiff_ceiling(&sh.cfg, network_diff);
        self.vardiff.set_bounds(min, max);

        let diff = self.vardiff.current();
        let target = Target::from_difficulty(diff);
        if force_target || self.last_target_sent != Some(target) {
            proto::write_set_target(&mut self.outbuf, &target);
            self.last_target_sent = Some(target);
            Metrics::inc(&sh.metrics.set_targets);
        }

        let gen = sh.jobs.generation();
        let clean = template.new_tip && self.last_clean_gen != gen;
        if clean {
            self.last_clean_gen = gen;
        }
        let height = template.height;
        let prefix = template.prefix;
        let job_id = self.jobs.push(template, target, diff, clean, now_ms);
        proto::write_notify(&mut self.outbuf, job_id, height, &prefix, clean);
        Metrics::inc(&sh.metrics.notifies);

        self.last_push_ms = now_ms;
        self.last_generation = gen;
        if self.first_job_ms.is_none() {
            self.first_job_ms = Some(now_ms);
        }
    }

    fn remember_difficulty(&mut self, diff: u64, now_ms: u64, sh: &Shared) {
        if let Some(l) = &self.login {
            let mut d = sh.diffs.lock().unwrap_or_else(|e| e.into_inner());
            d.record(&l.address_bytes, diff, now_ms);
        }
    }

    fn retarget(&mut self, _new_diff: u64, now_ms: u64, sh: &Shared) {
        Metrics::inc(&sh.metrics.retargets);

        self.shares_at_current_diff = 0;

        self.push_job(now_ms, sh, true);
    }

    fn vardiff_min(&self, sh: &Shared) -> u64 {
        let floor = sh.cfg.diff.min_diff;
        self.storm_floor.unwrap_or(floor).max(floor)
    }

    fn network_difficulty(&self, sh: &Shared) -> u64 {
        let zero = [0u8; 20];
        let addr = self.login.as_ref().map(|l| l.address_bytes).unwrap_or(zero);
        match sh.jobs.current(&addr) {
            Ok(t) => t.network_target.to_difficulty(),
            Err(_) => u64::MAX,
        }
    }

    fn reject_and_score(&mut self, id: Option<u64>, e: ErrorCode, now_ms: u64, sh: &Shared) {
        proto::write_error(&mut self.outbuf, id, e);
        let (points, severity) = e.penalty();
        if points > 0 {
            self.score(points, severity, now_ms, sh);
        }
        if e == ErrorCode::Unauthorized {
            Metrics::inc(&sh.metrics.rej_unauthorized);
        }
    }

    fn score(&mut self, points: u32, severity: Severity, now_ms: u64, sh: &Shared) {
        let banned = sh
            .bans
            .lock()
            .ok()
            .and_then(|mut b| b.penalise(self.ip, points, severity, now_ms))
            .is_some();
        if banned {
            Metrics::inc(&sh.metrics.bans);
            proto::write_error(&mut self.outbuf, None, ErrorCode::Banned);
            self.close(CloseReason::Banned);
        }
    }

    pub fn check_slice(&mut self, sh: &Shared) -> bool {
        let e1 = match self.e1 {
            Some(e) => e,
            None => return true,
        };
        if sh.e1.holds(e1, self.sub) {
            return true;
        }
        self.revoke(None, sh);
        false
    }

    // The slice moved under us: our upstream changed, not anything the miner
    // did. Send the reason, close, but never score the ip for it.
    fn revoke(&mut self, id: Option<u64>, sh: &Shared) {
        Metrics::inc(&sh.metrics.closed_slice_revoked);
        proto::write_error(&mut self.outbuf, id, ErrorCode::SliceRevoked);
        self.close(CloseReason::SliceRevoked);
    }

    fn note_throttled(&mut self, now_ms: u64, _sh: &Shared) {
        self.throttled_in_window = true;
        let _ = now_ms;
    }

    fn close(&mut self, reason: CloseReason) {
        self.actions.push(Action::Close(reason));
    }

    pub fn release(&mut self, now_ms: u64, sh: &Shared) {
        // first_job_ms tells the source whether this sub-slice was ever mined; a
        // mined one is quarantined before reuse, an untouched one can go straight back.
        if let Some(e1) = self.e1.take() {
            sh.e1.release(e1, self.sub, self.first_job_ms.is_some());
        }
        if let Ok(mut b) = sh.bans.lock() {
            b.release(self.ip, now_ms);
        }
    }

    pub fn send_reconnect(&mut self, host: &str, port: u16, wait_secs: u64) {
        proto::write_reconnect(&mut self.outbuf, host, port, wait_secs);
    }

    pub fn take_actions(&mut self) -> Vec<Action> {
        core::mem::take(&mut self.actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{InlineVerifier, MockJobSource, MockPow};
    use crate::nonce::E1Allocator;
    use plaine_consensus::bech32m;
    use plaine_consensus::constants::ADDRESS_HRP;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;

    thread_local! {
        static RESULTS: RefCell<Vec<VerifyResult>> = const { RefCell::new(Vec::new()) };
    }

    struct Harness {
        alloc: Arc<Mutex<E1Allocator>>,
        sh: Arc<Shared>,
        src: Arc<MockJobSource>,
        verifier: Arc<InlineVerifier>,
    }

    fn addr(seed: u8) -> String {
        bech32m::encode_bytes(ADDRESS_HRP, &[seed; 20]).unwrap()
    }

    fn harness(mode: Mode, network_diff: u64) -> Harness {
        let alloc = Arc::new(Mutex::new(E1Allocator::new()));
        let src = Arc::new(MockJobSource::new(
            184_602,
            Target::from_difficulty(network_diff),
        ));
        let sink: crate::verify::ResultSink = Arc::new(|r: VerifyResult| {
            RESULTS.with(|v| v.borrow_mut().push(r));
        });
        let verifier = Arc::new(InlineVerifier::new(Arc::new(MockPow::new()), sink));
        let caps = Caps::for_mode(mode);
        let sh = Arc::new(Shared {
            bans: Mutex::new(BanTable::new()),
            e1: alloc.clone(),
            diffs: Mutex::new(DiffCache::new()),
            accept: Mutex::new(TokenBucket::new(
                caps.global_accept_per_sec as f64,
                caps.global_accept_per_sec as f64,
                0,
            )),
            jobs: src.clone(),
            verifier: verifier.clone(),
            metrics: Metrics::default(),
            caps,
            cfg: ServerConfig::for_mode(mode),
        });
        RESULTS.with(|v| v.borrow_mut().clear());
        Harness {
            sh,
            src,
            verifier,
            alloc,
        }
    }

    fn feed(s: &mut Session, h: &Harness, line: &str, now: u64) -> String {
        s.outbuf.clear();
        s.on_line(line.as_bytes(), now, &h.sh);
        pump(s, h, now);
        String::from_utf8(core::mem::take(&mut s.outbuf)).unwrap()
    }

    fn pump(s: &mut Session, h: &Harness, now: u64) {
        for _ in 0..8 {
            let actions = s.take_actions();
            if actions.is_empty() {
                break;
            }
            let mut verified = 0;
            for a in actions {
                match a {
                    Action::Verify(w) => {
                        verified += 1;
                        crate::verify::ShareVerifier::enqueue(h.verifier.as_ref(), *w);
                    }

                    other => s.actions.push(other),
                }
            }
            if verified == 0 {
                break;
            }
            let results: Vec<VerifyResult> = RESULTS.with(|v| v.borrow_mut().drain(..).collect());
            for r in results {
                s.on_verify_result(r, now, &h.sh);
            }
        }
    }

    fn closed(s: &mut Session) -> Option<CloseReason> {
        s.actions.iter().find_map(|a| match a {
            Action::Close(r) => Some(*r),
            _ => None,
        })
    }

    fn session(h: &Harness, ip: u8, now: u64) -> Session {
        Session::new(1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)), now, &h.sh)
    }

    fn subscribe_and_authorize(s: &mut Session, h: &Harness, seed: u8, now: u64) -> String {
        feed(
            s,
            h,
            r#"{"id":1,"method":"mining.subscribe","params":["plaine-miner/1.0"]}"#,
            now,
        );
        feed(
            s,
            h,
            &format!(
                r#"{{"id":2,"method":"mining.authorize","params":["{}.rig1","x"]}}"#,
                addr(seed)
            ),
            now,
        )
    }

    fn mine(prefix: &[u8; 124], e1: E1, target: &Target) -> u64 {
        mine_from(prefix, e1, target, 0)
    }

    fn mine_from(prefix: &[u8; 124], e1: E1, target: &Target, from: u64) -> u64 {
        search(prefix, e1, target, from, 4_000_000).expect("no share found")
    }

    #[test]
    #[should_panic(expected = "target too hard for the search budget")]
    fn test_miner_refuses_unmeetable_target() {
        let prefix = [0u8; 124];

        let _ = mine(&prefix, E1(1), &Target::from_difficulty(u64::MAX));
    }

    fn search(prefix: &[u8; 124], e1: E1, target: &Target, from: u64, budget: u64) -> Option<u64> {
        use crate::verify::PowHasher;

        let need = target.to_difficulty();
        assert!(
            need <= budget,
            "target too hard for the search budget: difficulty {need}, budget {budget}"
        );
        let pow = MockPow::new();
        for x in from..from + budget {
            let n = e1.compose(x);
            if target.accepts(&pow.digest(&assemble_header(prefix, n))) {
                return Some(n);
            }
        }
        None
    }

    #[test]
    fn handshake_on_the_wire() {
        let h = harness(Mode::Solo, 1_000_000);
        let mut s = session(&h, 1, 0);

        let sub = feed(
            &mut s,
            &h,
            r#"{"id":1,"method":"mining.subscribe","params":["plaine-miner/1.0"]}"#,
            0,
        );
        assert_eq!(
            sub,
            "{\"id\":1,\"result\":[[\"mining.notify\",\"mining.set_target\"],\"000000\",5],\"error\":null}\n"
        );

        let auth = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":2,"method":"mining.authorize","params":["{}.rig1","x"]}}"#,
                addr(1)
            ),
            10,
        );
        let mut lines = auth.lines();
        assert_eq!(
            lines.next().unwrap(),
            r#"{"id":2,"result":true,"error":null}"#
        );

        assert!(lines.next().unwrap().contains("mining.set_target"));
        let notify = lines.next().unwrap();
        assert!(notify.contains("mining.notify"));
        assert!(notify.contains("184602"));
        assert!(notify.ends_with("true]}"), "first job is clean: {notify}");
        assert!(s.is_authorized());
        assert_eq!(s.login().unwrap().rig, "rig1");
    }

    #[test]
    fn subscribe_must_come_first_and_only_once() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 2, 0);
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":1,"method":"mining.authorize","params":["{}","x"]}}"#,
                addr(2)
            ),
            0,
        );
        assert!(out.contains("\"error\":[24"), "{out}");
        assert!(!s.is_authorized());

        feed(
            &mut s,
            &h,
            r#"{"id":2,"method":"mining.subscribe","params":[]}"#,
            0,
        );
        let again = feed(
            &mut s,
            &h,
            r#"{"id":3,"method":"mining.subscribe","params":[]}"#,
            0,
        );
        assert!(
            again.contains("\"error\":["),
            "re-subscribe must not hand out a second slice: {again}"
        );
    }

    #[test]
    fn bad_address_is_error_24() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 3, 0);
        feed(
            &mut s,
            &h,
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
            0,
        );
        let out = feed(
            &mut s,
            &h,
            r#"{"id":2,"method":"mining.authorize","params":["plne1notanaddress","x"]}"#,
            0,
        );
        assert!(out.contains("\"error\":[24"), "{out}");
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 0), 25);
    }

    #[test]
    fn submit_before_authorize_not_verified() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 4, 0);
        let out = feed(
            &mut s,
            &h,
            r#"{"id":9,"method":"mining.submit","params":["x","00000000","0000000000000000"]}"#,
            0,
        );
        assert!(out.contains("\"error\":[24"), "{out}");
        assert_eq!(Metrics::get(&h.sh.metrics.shares_verified), 0);
    }

    #[test]
    fn accepted_share_credits_difficulty() {
        let h = harness(Mode::Solo, u64::MAX / 2);
        let mut s = session(&h, 5, 0);
        subscribe_and_authorize(&mut s, &h, 5, 0);
        let job = s.jobs.newest().unwrap();
        let (jid, prefix, target, served) = (
            job.job_id,
            job.template.prefix,
            job.served_target,
            job.served_difficulty,
        );
        let n = mine(&prefix, s.e1().unwrap(), &target);
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(n)
            ),
            1_000,
        );
        assert!(out.contains("\"result\":true"), "{out}");
        assert_eq!(s.accepted_shares, 1);
        assert_eq!(s.accepted_difficulty, served as u128);
    }

    #[test]
    fn share_judged_at_its_job_target() {
        let h = harness(Mode::Solo, u64::MAX / 2);
        let mut s = session(&h, 6, 0);
        subscribe_and_authorize(&mut s, &h, 6, 0);
        let job = s.jobs.newest().unwrap();
        let (jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
        let n = mine(&prefix, s.e1().unwrap(), &target);

        s.vardiff.pin(u64::MAX / 4);
        h.src.refresh();
        s.push_job(500, &h.sh, true);

        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(n)
            ),
            1_000,
        );
        assert!(
            out.contains("\"result\":true"),
            "share must be judged at its served target: {out}"
        );
    }

    #[test]
    fn out_of_slice_nonce_not_verified() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 7, 0);
        subscribe_and_authorize(&mut s, &h, 7, 0);
        let jid = s.jobs.newest().unwrap().job_id;
        let foreign = E1(0x00A3F2).compose(42);
        assert!(!s.e1().unwrap().owns(foreign));
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(foreign)
            ),
            100,
        );
        assert!(out.contains("\"error\":[25"), "{out}");
        assert_eq!(Metrics::get(&h.sh.metrics.shares_verified), 0);
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 100), 50);
    }

    #[test]
    fn two_out_of_slice_shares_ban() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 8, 0);
        subscribe_and_authorize(&mut s, &h, 8, 0);
        let jid = s.jobs.newest().unwrap().job_id;
        let foreign = E1(0x00A3F2).compose(42);
        let line = format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
            jid,
            crate::nonce::nonce_to_hex(foreign)
        );
        feed(&mut s, &h, &line, 100);
        let out = feed(&mut s, &h, &line, 200);
        assert!(
            out.contains("\"error\":[27"),
            "expected a ban notice: {out}"
        );
        assert_eq!(closed(&mut s), Some(CloseReason::Banned));
    }

    #[test]
    fn duplicates_refused_after_bucket() {
        let h = harness(Mode::Solo, u64::MAX / 2);
        let mut s = session(&h, 9, 0);
        subscribe_and_authorize(&mut s, &h, 9, 0);
        let job = s.jobs.newest().unwrap();
        let (jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
        let n = mine(&prefix, s.e1().unwrap(), &target);
        let line = format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
            jid,
            crate::nonce::nonce_to_hex(n)
        );
        assert!(feed(&mut s, &h, &line, 1_000).contains("\"result\":true"));
        let out = feed(&mut s, &h, &line, 1_100);
        assert!(out.contains("\"error\":[22"), "{out}");
    }

    #[test]
    fn submit_rate_limit_no_score() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 10, 0);
        subscribe_and_authorize(&mut s, &h, 10, 0);
        let jid = s.jobs.newest().unwrap().job_id;
        let e1 = s.e1().unwrap();
        let mut throttled = 0;
        for i in 0..30u64 {
            let out = feed(
                &mut s,
                &h,
                &format!(
                    r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                    jid,
                    crate::nonce::nonce_to_hex(e1.compose(i))
                ),
                1_000,
            );
            if out.contains("\"error\":[26") {
                throttled += 1;
            }
        }
        assert_eq!(throttled, 20, "10 burst tokens, then refusals");

        let score = h.sh.bans.lock().unwrap().score(s.ip, 1_000);
        assert!(score < BAN_THRESHOLD, "score {score}");
    }

    #[test]
    fn server_busy_never_scores() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 11, 0);
        subscribe_and_authorize(&mut s, &h, 11, 0);
        h.verifier.refuse.store(true, Ordering::SeqCst);
        let jid = s.jobs.newest().unwrap().job_id;
        let e1 = s.e1().unwrap();

        for i in 0..2u64 {
            s.outbuf.clear();
            s.on_line(
                format!(
                    r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                    jid,
                    crate::nonce::nonce_to_hex(e1.compose(i))
                )
                .as_bytes(),
                1_000,
                &h.sh,
            );
            s.take_actions();
        }
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(e1.compose(99))
            ),
            1_000,
        );
        assert!(out.contains("\"error\":[28"), "{out}");
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 1_000), 0);
    }

    #[test]
    fn new_tip_clean_and_old_credited() {
        let h = harness(Mode::Solo, u64::MAX / 2);
        let mut s = session(&h, 12, 0);
        subscribe_and_authorize(&mut s, &h, 12, 0);
        let job = s.jobs.newest().unwrap();
        let (old_jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
        let n = mine(&prefix, s.e1().unwrap(), &target);

        h.src.new_tip(184_603);
        s.outbuf.clear();
        s.on_tick(20_000, &h.sh);
        let pushed = String::from_utf8(core::mem::take(&mut s.outbuf)).unwrap();
        assert!(
            pushed.contains("true]}"),
            "clean_jobs must be true: {pushed}"
        );

        let line = format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
            old_jid,
            crate::nonce::nonce_to_hex(n)
        );

        let out = feed(&mut s, &h, &line, 22_000);
        assert!(out.contains("\"result\":true"), "{out}");
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 22_000), 0);

        let out = feed(&mut s, &h, &line, 26_000);
        assert!(out.contains("\"error\":[21"), "{out}");
    }

    #[test]
    fn refresh_is_the_keepalive() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 13, 0);
        subscribe_and_authorize(&mut s, &h, 13, 0);
        s.outbuf.clear();
        s.on_tick(5_000, &h.sh);
        assert!(s.outbuf.is_empty(), "nothing to say yet");
        s.on_tick(16_000, &h.sh);
        let out = String::from_utf8(core::mem::take(&mut s.outbuf)).unwrap();
        assert!(out.contains("mining.notify"), "{out}");
        assert!(out.contains("false]}"), "a refresh is not clean: {out}");
    }

    #[test]
    fn garbage_before_auth_throttles() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 14, 0);
        s.on_line(b"GET / HTTP/1.1", 0, &h.sh);
        assert_eq!(closed(&mut s), Some(CloseReason::GarbageBeforeAuth));
        let mut accept = TokenBucket::new(1000.0, 1000.0, 0);
        assert_eq!(
            h.sh.bans
                .lock()
                .unwrap()
                .admit(s.ip, 100, &h.sh.caps, 0, &mut accept),
            crate::abuse::Admit::Throttled
        );
    }

    #[test]
    fn garbage_after_auth_scores_and_closes() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 15, 0);
        subscribe_and_authorize(&mut s, &h, 15, 0);
        s.on_line(b"\x16\x03\x01\x00\xa5", 100, &h.sh);
        assert_eq!(closed(&mut s), Some(CloseReason::BadMessageAfterAuth));
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 100), 50);
    }

    #[test]
    fn oversized_line_refused() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 16, 0);
        let big = vec![b'x'; MAX_LINE_PRE_AUTH + 1];
        s.on_line(&big, 0, &h.sh);
        assert_eq!(closed(&mut s), Some(CloseReason::GarbageBeforeAuth));
    }

    #[test]
    fn unknown_method_scores_stays_connected() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 17, 0);
        subscribe_and_authorize(&mut s, &h, 17, 0);
        let out = feed(
            &mut s,
            &h,
            r#"{"id":5,"method":"mining.extranonce.subscribe","params":[]}"#,
            100,
        );
        assert!(out.contains("\"error\":[29"), "{out}");
        assert_eq!(closed(&mut s), None);
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 100), 5);
    }

    #[test]
    fn auth_deadline_closes_silent_conn() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 18, 0);
        s.on_tick(9_000, &h.sh);
        assert_eq!(closed(&mut s), None);
        s.on_tick(10_001, &h.sh);
        assert_eq!(closed(&mut s), Some(CloseReason::AuthTimeout));
    }

    #[test]
    fn idle_slot_evicted() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 19, 0);
        subscribe_and_authorize(&mut s, &h, 19, 0);
        s.on_tick(29 * 60_000, &h.sh);
        assert_eq!(closed(&mut s), None);
        s.on_tick(30 * 60_000 + 1, &h.sh);
        assert_eq!(closed(&mut s), Some(CloseReason::Idle));
    }

    #[test]
    fn syncing_node_no_idle_clock() {
        let h = harness(Mode::Solo, 1_000_000);
        h.src.set_ready(false);
        let mut s = session(&h, 20, 0);
        subscribe_and_authorize(&mut s, &h, 20, 0);
        assert!(s.jobs.newest().is_none(), "no job while syncing");
        s.on_tick(40 * 60_000, &h.sh);
        assert_eq!(
            closed(&mut s),
            None,
            "miners waiting for a syncing node must not be evicted"
        );
    }

    #[test]
    fn release_returns_slice() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 21, 0);
        subscribe_and_authorize(&mut s, &h, 21, 0);
        assert_eq!(h.alloc.lock().unwrap().live(), 1);
        s.release(0, &h.sh);
        assert_eq!(
            h.alloc.lock().unwrap().live(),
            0,
            "a slice is freed on close, never at GC"
        );
    }

    #[test]
    fn pinned_login_disables_vardiff() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 22, 0);
        feed(
            &mut s,
            &h,
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
            0,
        );
        feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":2,"method":"mining.authorize","params":["{}.rig+120000","x"]}}"#,
                addr(22)
            ),
            0,
        );
        assert_eq!(s.difficulty(), 120_000);
        for t in 1..200 {
            s.on_tick(t * 2_000, &h.sh);
        }
        assert_eq!(s.difficulty(), 120_000);
    }

    #[test]
    fn cache_skips_warmup_on_reconnect() {
        let h = harness(Mode::Pool, 1_000_000);
        h.sh.diffs.lock().unwrap().record(&[23u8; 20], 250_000, 0);
        let mut s = session(&h, 23, 1_000);
        subscribe_and_authorize(&mut s, &h, 23, 1_000);
        assert_eq!(s.difficulty(), 250_000);
    }

    #[test]
    fn max_diff_is_the_network_difficulty() {
        let h = harness(Mode::Pool, 50_000);
        let mut s = session(&h, 24, 0);
        subscribe_and_authorize(&mut s, &h, 24, 0);
        assert!(
            s.difficulty() <= 50_000,
            "difficulty {} above the network's",
            s.difficulty()
        );
    }

    #[test]
    fn slow_client_closed_not_buffered() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 25, 0);
        subscribe_and_authorize(&mut s, &h, 25, 0);

        s.outbuf.resize(OUT_BUF_CAP + 1, b' ');
        s.on_tick(20_000, &h.sh);
        assert_eq!(closed(&mut s), Some(CloseReason::SlowClient));
    }

    #[test]
    fn job_push_bounded_for_dead_client() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 26, 0);
        subscribe_and_authorize(&mut s, &h, 26, 0);
        s.outbuf.clear();
        let mut t = 0u64;
        for _ in 0..100 {
            h.src.refresh();
            t += 100;
            s.on_tick(t, &h.sh);
        }
        assert!(
            s.outbuf.len() < 100 * 340,
            "queued {} bytes for a client that read nothing",
            s.outbuf.len()
        );
    }

    #[test]
    fn solo_template_per_address() {
        let src =
            Arc::new(MockJobSource::new(1, Target::from_difficulty(1_000_000)).per_recipient(true));
        let sink: crate::verify::ResultSink = Arc::new(|_| {});
        let verifier = Arc::new(InlineVerifier::new(Arc::new(MockPow::new()), sink));
        let sh = Arc::new(Shared {
            bans: Mutex::new(BanTable::new()),
            e1: Arc::new(Mutex::new(E1Allocator::new())),
            diffs: Mutex::new(DiffCache::new()),
            accept: Mutex::new(TokenBucket::new(50.0, 50.0, 0)),
            jobs: src.clone(),
            verifier,
            metrics: Metrics::default(),
            caps: Caps::SOLO,
            cfg: ServerConfig::for_mode(Mode::Solo),
        });
        let h = Harness {
            sh,
            src,
            alloc: Arc::new(Mutex::new(E1Allocator::new())),
            verifier: Arc::new(InlineVerifier::new(
                Arc::new(MockPow::new()),
                Arc::new(|_| {}),
            )),
        };
        let mut a = Session::new(1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0, &h.sh);
        let mut b = Session::new(2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 0, &h.sh);
        subscribe_and_authorize(&mut a, &h, 30, 0);
        subscribe_and_authorize(&mut b, &h, 31, 0);
        assert_ne!(
            a.jobs.newest().unwrap().template.prefix,
            b.jobs.newest().unwrap().template.prefix,
            "changing the coinbase address changes tx_root"
        );
    }

    #[test]
    fn winning_share_seals_once() {
        let h = harness(Mode::Solo, 2);
        let mut s = session(&h, 27, 0);
        subscribe_and_authorize(&mut s, &h, 27, 0);
        let job = s.jobs.newest().unwrap();
        let (jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
        let n = mine(&prefix, s.e1().unwrap(), &target);
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(n)
            ),
            1_000,
        );
        assert!(out.contains("\"result\":true"), "{out}");
        assert_eq!(h.src.blocks_sealed(), 1);
        assert_eq!(Metrics::get(&h.sh.metrics.blocks_found), 1);
    }

    #[test]
    fn reconnect_wait_is_clamped() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 28, 0);
        s.send_reconnect("eu.pool.example", 9259, 9_999);
        let out = String::from_utf8(core::mem::take(&mut s.outbuf)).unwrap();
        assert!(out.contains(",9259,60]"), "{out}");
    }

    #[test]
    fn stale_credited_share_is_slice_bound() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 40, 0);
        subscribe_and_authorize(&mut s, &h, 40, 0);
        let old_jid = s.jobs.newest().unwrap().job_id;
        h.src.new_tip(184_603);
        s.on_tick(1_000, &h.sh);
        s.take_actions();

        let foreign = E1(0x00A3F2).compose(7);
        assert!(!s.e1().unwrap().owns(foreign));
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                old_jid,
                crate::nonce::nonce_to_hex(foreign)
            ),
            1_100,
        );
        assert!(
            out.contains("\"error\":[25"),
            "the grace window must not exempt a share from slice binding: {out}"
        );
        assert_eq!(Metrics::get(&h.sh.metrics.shares_verified), 0);
        assert_eq!(s.accepted_shares, 0);
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 1_100), 50);
    }

    #[test]
    fn stale_credited_share_is_credited() {
        let h = harness(Mode::Solo, 2);
        let mut s = session(&h, 41, 0);
        subscribe_and_authorize(&mut s, &h, 41, 0);
        let job = s.jobs.newest().unwrap();
        let (old_jid, prefix, target, served) = (
            job.job_id,
            job.template.prefix,
            job.served_target,
            job.served_difficulty,
        );
        let n = mine(&prefix, s.e1().unwrap(), &target);

        h.src.new_tip(184_603);
        s.outbuf.clear();
        s.on_tick(1_000, &h.sh);
        s.take_actions();

        let line = format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
            old_jid,
            crate::nonce::nonce_to_hex(n)
        );
        let out = feed(&mut s, &h, &line, 1_100);
        assert!(out.contains("\"result\":true"), "{out}");
        assert_eq!(s.accepted_shares, 1, "acked but credited to nobody");
        assert_eq!(s.accepted_difficulty, served as u128);
        assert_eq!(Metrics::get(&h.sh.metrics.shares_verified), 1);

        assert_eq!(h.src.blocks_sealed(), 0, "a stale share built a block");
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 1_100), 0);

        let again = feed(&mut s, &h, &line, 1_200);
        assert!(again.contains("\"error\":[22"), "{again}");
        assert_eq!(s.accepted_shares, 1);
    }

    #[test]
    fn stale_credited_flood_rate_limited() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 42, 0);
        subscribe_and_authorize(&mut s, &h, 42, 0);
        let old_jid = s.jobs.newest().unwrap().job_id;
        h.src.new_tip(184_603);
        s.on_tick(1_000, &h.sh);
        s.take_actions();

        let e1 = s.e1().unwrap();
        let mut throttled = 0;
        for i in 0..40u64 {
            let out = feed(
                &mut s,
                &h,
                &format!(
                    r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                    old_jid,
                    crate::nonce::nonce_to_hex(e1.compose(i))
                ),
                1_100,
            );
            if out.contains("\"error\":[26") {
                throttled += 1;
            }
        }
        assert!(throttled > 0, "the grace window had no rate limit at all");
    }

    #[test]
    fn duplicate_and_stale_are_classified_separately() {
        let h = harness(Mode::Solo, u64::MAX / 2);
        let mut s = session(&h, 43, 0);
        subscribe_and_authorize(&mut s, &h, 43, 0);
        let job = s.jobs.newest().unwrap();
        let (jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
        let n = mine(&prefix, s.e1().unwrap(), &target);
        let line = format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
            jid,
            crate::nonce::nonce_to_hex(n)
        );
        assert!(feed(&mut s, &h, &line, 1_000).contains("\"result\":true"));

        assert!(feed(&mut s, &h, &line, 1_100).contains("\"error\":[22"));

        h.src.new_tip(184_603);
        s.on_tick(2_000, &h.sh);
        s.take_actions();
        let out = feed(&mut s, &h, &line, 9_000);
        assert!(out.contains("\"error\":[21"), "{out}");
        assert_eq!(Metrics::get(&h.sh.metrics.rej_duplicate), 1);
        assert_eq!(Metrics::get(&h.sh.metrics.rej_stale), 1);

        let never = format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","ffffffff","{}"]}}"#,
            crate::nonce::nonce_to_hex(n)
        );
        assert!(feed(&mut s, &h, &never, 9_100).contains("\"error\":[20"));
        assert_eq!(Metrics::get(&h.sh.metrics.rej_unknown_job), 1);
    }

    #[test]
    fn pinned_login_no_cache_poison() {
        let h = harness(Mode::Pool, 5_000_000);
        let victim_seed = 44u8;
        let mut attacker = session(&h, 90, 0);
        feed(
            &mut attacker,
            &h,
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
            0,
        );
        feed(
            &mut attacker,
            &h,
            &format!(
                r#"{{"id":2,"method":"mining.authorize","params":["{}+5000000","x"]}}"#,
                addr(victim_seed)
            ),
            0,
        );
        assert_eq!(
            attacker.difficulty(),
            5_000_000,
            "the pin itself is honoured"
        );
        attacker.release(0, &h.sh);

        let mut victim = session(&h, 45, 1_000);
        subscribe_and_authorize(&mut victim, &h, victim_seed, 1_000);
        assert_eq!(
            victim.difficulty(),
            START_DIFF,
            "an unearned difficulty was written to another miner's cache entry"
        );
    }

    #[test]
    fn pinned_earning_no_cache_poison() {
        let h = harness(Mode::Pool, 5_000_000);
        let victim_seed = 78u8;
        let mut s = session(&h, 91, 0);
        feed(
            &mut s,
            &h,
            r#"{"id":1,"method":"mining.subscribe","params":["plaine-miner/1.0"]}"#,
            0,
        );
        feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":2,"method":"mining.authorize","params":["{}.rig1+{}","x"]}}"#,
                addr(victim_seed),
                MIN_DIFF
            ),
            0,
        );

        assert_eq!(s.difficulty(), MIN_DIFF, "the pin itself is honoured");

        let mut now = 1_000u64;
        let mut from = 0u64;
        for _ in 0..(DIFF_CACHE_MIN_SHARES + 2) {
            let job = s.jobs.newest().unwrap();
            let (jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
            let n = mine_from(&prefix, s.e1().unwrap(), &target, from);
            from = (n & ((1 << 40) - 1)) + 1;
            let out = feed(
                &mut s,
                &h,
                &format!(
                    r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                    jid,
                    crate::nonce::nonce_to_hex(n)
                ),
                now,
            );
            assert!(out.contains("\"result\":true"), "share refused: {out}");
            now += 1_000;
        }
        assert!(s.accepted_shares >= DIFF_CACHE_MIN_SHARES);

        let cached =
            h.sh.diffs
                .lock()
                .unwrap()
                .start_for(&[victim_seed; 20], now)
                .0;
        assert_eq!(
            cached, START_DIFF,
            "a pinned difficulty ({cached}) leaked into the address cache"
        );
    }

    #[test]
    fn only_earned_difficulty_is_remembered() {
        let h = harness(Mode::Solo, MIN_DIFF);
        let mut s = session(&h, 46, 0);
        subscribe_and_authorize(&mut s, &h, 46, 0);
        let mut now = 1_000u64;
        for i in 0..DIFF_CACHE_MIN_SHARES {
            let job = s.jobs.newest().unwrap();
            let (jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
            let n = mine_from(&prefix, s.e1().unwrap(), &target, i * 100_000);
            let cached = h.sh.diffs.lock().unwrap().start_for(&[46u8; 20], now).0;
            assert_eq!(
                cached, START_DIFF,
                "difficulty {cached} was cached after only {i} accepted shares"
            );
            feed(
                &mut s,
                &h,
                &format!(
                    r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                    jid,
                    crate::nonce::nonce_to_hex(n)
                ),
                now,
            );
            now += 1_000;
        }
        assert_eq!(s.accepted_shares, DIFF_CACHE_MIN_SHARES);
        let cached = h.sh.diffs.lock().unwrap().start_for(&[46u8; 20], now).0;
        assert_eq!(
            cached,
            s.difficulty(),
            "earned difficulty must be remembered"
        );
    }

    #[test]
    fn storm_floor_survives_first_push() {
        let h = harness(Mode::Pool, 10_000_000);
        let a = [47u8; 20];
        {
            let mut d = h.sh.diffs.lock().unwrap();
            let mut now = 0u64;
            for _ in 0..6 {
                for _ in 0..5 {
                    d.note_login(&a, 250_000, now);
                    now += 1_000;
                }
                now += 60_000;
            }
        }
        let mut s = session(&h, 47, 400_000);
        subscribe_and_authorize(&mut s, &h, 47, 400_000);
        assert!(s.difficulty() >= 250_000, "started at {}", s.difficulty());

        let mut t = 400_000u64;
        for _ in 0..600 {
            t += 2_000;
            s.on_tick(t, &h.sh);
        }
        assert!(
            s.difficulty() >= 250_000,
            "the floor was discarded: {}",
            s.difficulty()
        );
    }

    #[test]
    fn empty_line_flood_not_free() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 48, 0);
        let mut closed_at = None;
        for i in 0..(LINE_BURST as u64 + 20) {
            if !s.charge_line(0, &h.sh) {
                closed_at = Some(i);
                break;
            }
        }
        assert_eq!(
            closed_at,
            Some(LINE_BURST as u64),
            "an empty-line stream was free"
        );
        assert_eq!(closed(&mut s), Some(CloseReason::LineFlood));
    }

    #[test]
    fn ordinary_miner_under_line_budget() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 49, 0);
        subscribe_and_authorize(&mut s, &h, 49, 0);
        for i in 0..10_000u64 {
            assert!(
                s.charge_line(i * 333, &h.sh),
                "a legitimate submit rate hit the line budget at line {i}"
            );
        }
    }

    #[test]
    fn panicking_verify_is_error_28() {
        struct PanickingPow;
        impl crate::verify::PowHasher for PanickingPow {
            fn digest(&self, _h: &[u8; 132]) -> [u8; 32] {
                panic!("plaine-pow died on this header");
            }
        }
        let src = Arc::new(MockJobSource::new(1, Target::from_difficulty(1_000_000)));
        let sink: crate::verify::ResultSink = Arc::new(|r: VerifyResult| {
            RESULTS.with(|v| v.borrow_mut().push(r));
        });
        let verifier = Arc::new(InlineVerifier::new(Arc::new(PanickingPow), sink));
        let sh = Arc::new(Shared {
            bans: Mutex::new(BanTable::new()),
            e1: Arc::new(Mutex::new(E1Allocator::new())),
            diffs: Mutex::new(DiffCache::new()),
            accept: Mutex::new(TokenBucket::new(50.0, 50.0, 0)),
            jobs: src.clone(),
            verifier: verifier.clone(),
            metrics: Metrics::default(),
            caps: Caps::POOL,
            cfg: ServerConfig::for_mode(Mode::Pool),
        });
        RESULTS.with(|v| v.borrow_mut().clear());
        let h = Harness {
            sh,
            src,
            alloc: Arc::new(Mutex::new(E1Allocator::new())),
            verifier,
        };
        let mut s = session(&h, 50, 0);
        subscribe_and_authorize(&mut s, &h, 50, 0);
        let jid = s.jobs.newest().unwrap().job_id;
        let e1 = s.e1().unwrap();
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(e1.compose(1))
            ),
            1_000,
        );
        assert!(out.contains("\"error\":[28"), "{out}");
        assert_eq!(h.sh.bans.lock().unwrap().score(s.ip, 1_000), 0);
        assert_eq!(Metrics::get(&h.sh.metrics.verify_internal_errors), 1);

        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":8,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(e1.compose(2))
            ),
            1_100,
        );
        assert!(out.contains("\"error\":[28"), "{out}");
        assert_eq!(Metrics::get(&h.sh.metrics.verify_internal_errors), 2);
    }

    #[test]
    fn solo_pool_same_wire() {
        fn transcript(mode: Mode) -> Vec<String> {
            let h = harness(mode, u64::MAX / 2);
            let mut s = session(&h, 60, 0);
            let mut out = Vec::new();
            out.push(subscribe_and_authorize(&mut s, &h, 60, 0));
            let job = s.jobs.newest().unwrap();
            let (jid, prefix, target) = (job.job_id, job.template.prefix, job.served_target);
            let n = mine(&prefix, s.e1().unwrap(), &target);
            let share = format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(n)
            );
            out.push(feed(&mut s, &h, &share, 1_000));
            out.push(feed(&mut s, &h, &share, 1_100));
            out.push(feed(
                &mut s,
                &h,
                &format!(
                    r#"{{"id":8,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                    jid,
                    crate::nonce::nonce_to_hex(E1(0x00A3F2).compose(9))
                ),
                1_200,
            ));
            out.push(feed(
                &mut s,
                &h,
                r#"{"id":9,"method":"mining.configure","params":[]}"#,
                1_300,
            ));
            out
        }
        let solo = transcript(Mode::Solo);
        let pool = transcript(Mode::Pool);
        assert_eq!(solo, pool, "the two modes produced different wire bytes");

        assert_ne!(Caps::SOLO.max_connections, Caps::POOL.max_connections);
        assert_ne!(Caps::SOLO.max_per_ip, Caps::POOL.max_per_ip);
        let (a, b) = (
            ServerConfig::for_mode(Mode::Solo),
            ServerConfig::for_mode(Mode::Pool),
        );
        assert_eq!(a.setpoint_secs, b.setpoint_secs);
        assert_eq!(a.max_line_pre_auth, b.max_line_pre_auth);
        assert_eq!(a.max_line_post_auth, b.max_line_post_auth);
        assert_eq!(a.auth_deadline_ms, b.auth_deadline_ms);
        assert_eq!(a.idle_evict_ms, b.idle_evict_ms);
    }

    struct SimPow;

    impl SimPow {
        fn mix(z: u64) -> u64 {
            let mut x = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^ (x >> 31)
        }
    }

    impl crate::verify::PowHasher for SimPow {
        fn digest(&self, header: &[u8; 132]) -> [u8; 32] {
            let mut acc = 0xC0FF_EE00_1234_5678u64;
            for chunk in header.chunks(8) {
                let mut b = [0u8; 8];
                b[..chunk.len()].copy_from_slice(chunk);
                acc = SimPow::mix(acc ^ u64::from_le_bytes(b));
            }
            let mut out = [0u8; 32];
            for (i, w) in out.chunks_mut(8).enumerate() {
                w.copy_from_slice(&SimPow::mix(acc ^ i as u64).to_le_bytes());
            }
            out
        }
    }

    fn sim_search(
        prefix: &[u8; 124],
        e1: E1,
        target: &Target,
        from: u64,
        budget: u64,
    ) -> Option<u64> {
        use crate::verify::PowHasher;
        for x in from..from + budget {
            let n = e1.compose(x);
            if target.accepts(&SimPow.digest(&assemble_header(prefix, n))) {
                return Some(n);
            }
        }
        None
    }

    struct PacedVerifier {
        queue: Mutex<std::collections::VecDeque<ShareWork>>,
        cap: usize,
    }

    impl PacedVerifier {
        fn new(cap: usize) -> PacedVerifier {
            PacedVerifier {
                queue: Mutex::new(std::collections::VecDeque::new()),
                cap,
            }
        }

        fn run(&self, n: usize) -> Vec<VerifyResult> {
            let mut out = Vec::new();
            for _ in 0..n {
                let w = match self.queue.lock().unwrap().pop_front() {
                    Some(w) => w,
                    None => break,
                };
                let verdict = crate::verify::verify_one_isolated(&SimPow, &w);
                out.push(VerifyResult {
                    conn: w.conn,
                    request_id: w.request_id,
                    seq: w.seq,
                    verdict,
                    served_difficulty: w.served_difficulty,
                });
            }
            out
        }
    }

    impl ShareVerifier for PacedVerifier {
        fn enqueue(&self, work: ShareWork) -> bool {
            let mut q = self.queue.lock().unwrap();
            if q.len() >= self.cap {
                return false;
            }
            q.push_back(work);
            true
        }
    }

    #[test]
    fn honest_survives_bad_peers() {
        const STEP_MS: u64 = 100;
        const STEPS: u64 = 600;
        const SHARES_PER_STEP: usize = 3;
        const HONEST_DEADLINE_MS: u64 = 2_000;
        const FLOODERS: usize = 8;

        let src = Arc::new(MockJobSource::new(
            184_602,
            Target::from_difficulty(MIN_DIFF),
        ));
        let verifier = Arc::new(PacedVerifier::new(4_096));
        let mut cfg = ServerConfig::for_mode(Mode::Pool);

        cfg.auth_deadline_ms = 3_000;
        cfg.idle_evict_ms = 40_000;
        let sh = Arc::new(Shared {
            bans: Mutex::new(BanTable::new()),
            e1: Arc::new(Mutex::new(E1Allocator::new())),
            diffs: Mutex::new(DiffCache::new()),
            accept: Mutex::new(TokenBucket::new(500.0, 500.0, 0)),
            jobs: src.clone(),
            verifier: verifier.clone(),
            metrics: Metrics::default(),
            caps: Caps::POOL,
            cfg,
        });

        let mk =
            |id: u64, ip: u8| Session::new(id, IpAddr::V4(Ipv4Addr::new(10, 1, 0, ip)), 0, &sh);
        let mut honest = mk(1, 1);
        let mut slow = mk(2, 2);
        let mut silent = mk(3, 3);
        let mut floods: Vec<Session> = (0..FLOODERS)
            .map(|i| mk(10 + i as u64, 10 + i as u8))
            .collect();

        let hello = |s: &mut Session, seed: u8, now: u64| {
            s.on_line(
                br#"{"id":1,"method":"mining.subscribe","params":["sim"]}"#,
                now,
                &sh,
            );
            s.on_line(
                format!(
                    r#"{{"id":2,"method":"mining.authorize","params":["{}.rig","x"]}}"#,
                    addr(seed)
                )
                .as_bytes(),
                now,
                &sh,
            );
            s.take_actions();
            s.outbuf.clear();
        };

        hello(&mut honest, 1, 0);
        hello(&mut slow, 2, 0);
        for (i, f) in floods.iter_mut().enumerate() {
            hello(f, 20 + i as u8, 0);
        }
        assert!(honest.is_authorized() && slow.is_authorized());

        let mut x = 0u64;
        let mut outstanding: Option<u64> = None;
        let mut worst_latency = 0u64;
        let mut honest_acks = 0u64;
        let mut honest_rejects = 0u64;
        let mut first_reject = String::new();
        let mut flood_x = 0u64;
        let mut honest_closed: Option<CloseReason> = None;
        let mut slow_closed: Option<CloseReason> = None;
        let mut silent_closed: Option<CloseReason> = None;
        let mut flood_closed: Vec<Option<CloseReason>> = vec![None; FLOODERS];

        for step in 1..=STEPS {
            let now = step * STEP_MS;

            if step % 10 == 0 {
                src.new_tip(184_602 + step / 10);
            }

            if honest_closed.is_none() && outstanding.is_none() && step % 10 == 0 {
                if let Some(job) = honest.jobs.newest() {
                    let (jid, prefix, target) =
                        (job.job_id, job.template.prefix, job.served_target);
                    if let Some(n) = sim_search(&prefix, honest.e1().unwrap(), &target, x, 60_000) {
                        x = (n & ((1u64 << 40) - 1)) + 1;
                        honest.on_line(
                            format!(
                                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                                jid,
                                crate::nonce::nonce_to_hex(n)
                            )
                            .as_bytes(),
                            now,
                            &sh,
                        );
                        outstanding = Some(now);
                    }
                }
            }

            for (i, f) in floods.iter_mut().enumerate() {
                if flood_closed[i].is_some() {
                    continue;
                }
                for _ in 0..5 {
                    let (jid, e1) = match (f.jobs.newest(), f.e1()) {
                        (Some(j), Some(e)) => (j.job_id, e),
                        _ => break,
                    };
                    flood_x += 1;
                    f.on_line(
                        format!(
                            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                            jid,
                            crate::nonce::nonce_to_hex(e1.compose(flood_x))
                        )
                        .as_bytes(),
                        now,
                        &sh,
                    );
                }
                f.outbuf.clear();
            }

            if honest_closed.is_none() {
                honest.on_tick(now, &sh);
            }
            if slow_closed.is_none() {
                slow.on_tick(now, &sh);
            }
            if silent_closed.is_none() {
                silent.on_tick(now, &sh);
            }
            for (i, f) in floods.iter_mut().enumerate() {
                if flood_closed[i].is_none() {
                    f.on_tick(now, &sh);
                }
            }

            let collect = |s: &mut Session, closed: &mut Option<CloseReason>| {
                for a in s.take_actions() {
                    match a {
                        Action::Verify(w) => {
                            let rid = w.request_id;
                            if !verifier.enqueue(*w) {
                                s.on_verify_refused(rid, &sh);
                            }
                        }
                        Action::Close(r) => *closed = closed.or(Some(r)),
                    }
                }
            };
            collect(&mut honest, &mut honest_closed);
            collect(&mut slow, &mut slow_closed);
            collect(&mut silent, &mut silent_closed);
            for i in 0..floods.len() {
                let mut c = flood_closed[i];
                collect(&mut floods[i], &mut c);
                flood_closed[i] = c;
            }

            for r in verifier.run(SHARES_PER_STEP) {
                if r.conn == honest.id {
                    honest.on_verify_result(r, now, &sh);
                } else if let Some(f) = floods.iter_mut().find(|f| f.id == r.conn) {
                    f.on_verify_result(r, now, &sh);
                    f.outbuf.clear();
                }
            }

            let ack = String::from_utf8(core::mem::take(&mut honest.outbuf)).unwrap();

            let refused = ack.contains("\"error\":[");
            if ack.contains("\"result\":true") || refused {
                if refused {
                    honest_rejects += 1;
                    if first_reject.is_empty() {
                        first_reject = ack.clone();
                    }
                }
                if let Some(sent) = outstanding.take() {
                    worst_latency = worst_latency.max(now - sent);
                    honest_acks += 1;
                }
            }
        }

        assert_eq!(
            honest_closed, None,
            "the honest miner was disconnected ({honest_closed:?})"
        );
        assert_eq!(
            honest_rejects, 0,
            "an honest share was refused: {first_reject}"
        );
        assert!(
            honest_acks >= 20,
            "the honest miner got only {honest_acks} answers in 60 s"
        );
        assert!(
            honest.accepted_shares >= 20,
            "only {} accepted shares survived the flood",
            honest.accepted_shares
        );
        assert!(
            worst_latency <= HONEST_DEADLINE_MS,
            "worst honest answer took {worst_latency} ms, deadline {HONEST_DEADLINE_MS} ms"
        );
        assert_eq!(
            silent_closed,
            Some(CloseReason::AuthTimeout),
            "a peer that said nothing kept its slot"
        );
        assert_eq!(
            slow_closed,
            Some(CloseReason::SlowClient),
            "a peer that never drained its socket kept its slot"
        );
        assert!(
            flood_closed.iter().all(|c| *c == Some(CloseReason::Banned)),
            "flooders survived: {flood_closed:?}"
        );
        assert!(
            Metrics::get(&sh.metrics.bans) >= FLOODERS as u64,
            "bans: {}",
            Metrics::get(&sh.metrics.bans)
        );
    }

    #[test]
    fn every_byte_string_is_survivable() {
        let h = harness(Mode::Pool, 1_000_000);
        for seed in 0u16..=255 {
            let mut s = session(&h, 200, 0);
            let junk = [seed as u8; 37];
            s.on_line(&junk, 0, &h.sh);
            s.on_tick(1, &h.sh);
            s.release(1, &h.sh);
        }
    }

    #[test]
    fn line_past_budget_not_parsed() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 41, 0);
        subscribe_and_authorize(&mut s, &h, 41, 0);
        let job = s.jobs.newest().unwrap();
        let jid = job.job_id;
        let nonce = s.e1().unwrap().compose(1);

        let mut spent = false;
        for _ in 0..10_000 {
            if !s.charge_line(0, &h.sh) {
                spent = true;
                break;
            }
        }
        assert!(spent, "the line budget is not finite; the rig is wrong");

        let before = Metrics::get(&h.sh.metrics.shares_submitted);
        s.on_line(
            format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                crate::nonce::nonce_to_hex(nonce)
            )
            .as_bytes(),
            0,
            &h.sh,
        );
        assert_eq!(
            Metrics::get(&h.sh.metrics.shares_submitted),
            before,
            "a line past the flood budget was parsed and dispatched anyway"
        );
    }

    #[test]
    fn foreign_or_unissued_verdict_ignored() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 42, 0);
        subscribe_and_authorize(&mut s, &h, 42, 0);
        assert_eq!(s.accepted_shares, 0);

        let foreign = VerifyResult {
            conn: s.id + 1_000,
            request_id: Some(1),
            seq: 1,
            verdict: Verdict::Accepted { block: None },
            served_difficulty: 1_000_000,
        };
        s.on_verify_result(foreign, 100, &h.sh);
        assert_eq!(
            (s.accepted_shares, s.accepted_difficulty),
            (0, 0),
            "another connection's verdict was credited to this one"
        );

        let unissued = VerifyResult {
            conn: s.id,
            request_id: Some(1),
            seq: s.seq + 5,
            verdict: Verdict::Accepted { block: None },
            served_difficulty: 1_000_000,
        };
        s.on_verify_result(unissued, 100, &h.sh);
        assert_eq!(
            (s.accepted_shares, s.accepted_difficulty),
            (0, 0),
            "a verdict for a sequence this session never issued was credited"
        );
    }

    struct RecordingSource {
        inner: Arc<Mutex<E1Allocator>>,
        released_searched: Mutex<Vec<bool>>,
    }

    impl RecordingSource {
        fn new() -> Arc<RecordingSource> {
            Arc::new(RecordingSource {
                inner: Arc::new(Mutex::new(E1Allocator::new())),
                released_searched: Mutex::new(Vec::new()),
            })
        }
    }

    impl crate::nonce::SliceSource for RecordingSource {
        fn acquire(&self) -> Option<(E1, u32)> {
            self.inner.lock().ok()?.acquire().map(|e| (e, 0))
        }
        fn release(&self, e1: E1, _sub: u32, searched: bool) {
            self.released_searched
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(searched);
            if let Ok(mut a) = self.inner.lock() {
                a.release(e1);
            }
        }
        fn live(&self) -> usize {
            self.inner.lock().map(|a| a.live()).unwrap_or(usize::MAX)
        }
    }

    fn harness_with_source(src: Arc<dyn crate::nonce::SliceSource>) -> Arc<Shared> {
        let jobs = Arc::new(MockJobSource::new(
            184_602,
            Target::from_difficulty(1_000_000),
        ));
        let sink: crate::verify::ResultSink = Arc::new(|r: VerifyResult| {
            RESULTS.with(|v| v.borrow_mut().push(r));
        });
        let verifier = Arc::new(InlineVerifier::new(Arc::new(MockPow::new()), sink));
        let caps = Caps::for_mode(Mode::Pool);
        RESULTS.with(|v| v.borrow_mut().clear());
        Arc::new(Shared {
            bans: Mutex::new(BanTable::new()),
            e1: src,
            diffs: Mutex::new(DiffCache::new()),
            accept: Mutex::new(TokenBucket::new(500.0, 500.0, 0)),
            jobs,
            verifier,
            metrics: Metrics::default(),
            caps,
            cfg: ServerConfig::for_mode(Mode::Pool),
        })
    }

    #[test]
    fn only_mined_subslice_quarantined() {
        let src = RecordingSource::new();
        let sh = harness_with_source(src.clone() as Arc<dyn crate::nonce::SliceSource>);
        let mut s = Session::new(1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 51)), 0, &sh);
        s.on_line(
            br#"{"id":1,"method":"mining.subscribe","params":["t"]}"#,
            0,
            &sh,
        );
        assert!(s.e1().is_some(), "the rig failed to hand out a slice");
        s.release(1, &sh);
        assert_eq!(
            *src.released_searched.lock().unwrap(),
            vec![false],
            "a sub-slice nobody ever mined must not be quarantined"
        );

        let src = RecordingSource::new();
        let sh = harness_with_source(src.clone() as Arc<dyn crate::nonce::SliceSource>);
        let mut s = Session::new(2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 52)), 0, &sh);
        s.on_line(
            br#"{"id":1,"method":"mining.subscribe","params":["t"]}"#,
            0,
            &sh,
        );
        s.on_line(
            format!(
                r#"{{"id":2,"method":"mining.authorize","params":["{}.rig","x"]}}"#,
                addr(52)
            )
            .as_bytes(),
            0,
            &sh,
        );
        assert!(s.first_job_ms.is_some(), "the rig failed to push a job");
        s.release(1, &sh);
        assert_eq!(
            *src.released_searched.lock().unwrap(),
            vec![true],
            "a sub-slice that was mined must be quarantined, not reissued at once"
        );
    }

    #[test]
    fn closing_returns_per_ip_slot() {
        let h = harness(Mode::Pool, 1_000_000);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
        {
            let mut b = h.sh.bans.lock().unwrap();
            let mut accept = TokenBucket::new(500.0, 500.0, 0);
            assert_eq!(
                b.admit(ip, 0, &h.sh.caps, 0, &mut accept),
                crate::abuse::Admit::Ok
            );
            assert_eq!(b.conns(ip, 0), 1, "the rig failed to seat the connection");
        }
        let mut s = Session::new(9, ip, 0, &h.sh);
        s.release(1, &h.sh);
        assert_eq!(
            h.sh.bans.lock().unwrap().conns(ip, 1),
            0,
            "a closed connection was not returned to its ip's count"
        );
    }

    #[test]
    fn one_throttle_window_not_offence() {
        let h = harness(Mode::Pool, 1_000_000);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 54));
        let mut s = Session::new(7, ip, 0, &h.sh);
        subscribe_and_authorize(&mut s, &h, 54, 0);

        let score = |now: u64| h.sh.bans.lock().unwrap().score(ip, now);

        s.throttled_in_window = true;
        s.on_tick(10_001, &h.sh);
        assert_eq!(score(10_001), 0, "one window is not an offence");
        s.throttled_in_window = true;
        s.on_tick(20_002, &h.sh);
        assert_eq!(score(20_002), 0, "two windows are not an offence either");

        s.throttled_in_window = true;
        s.on_tick(30_003, &h.sh);
        assert!(
            score(30_003) > 0,
            "three sustained windows must escalate; the ladder never fires"
        );
    }

    #[test]
    fn storm_floor_never_below_min_diff() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 55, 0);
        s.storm_floor = Some(1);
        assert_eq!(
            s.vardiff_min(&h.sh),
            MIN_DIFF,
            "the storm floor escaped MIN_DIFF"
        );
        s.storm_floor = Some(MIN_DIFF * 4);
        assert_eq!(
            s.vardiff_min(&h.sh),
            MIN_DIFF * 4,
            "the floor must still be honoured when it is above the minimum"
        );
    }

    #[test]
    fn retarget_resets_share_count() {
        let h = harness(Mode::Pool, 1_000_000);
        let mut s = session(&h, 56, 0);
        subscribe_and_authorize(&mut s, &h, 56, 0);
        s.shares_at_current_diff = 7;
        s.retarget(s.vardiff.current(), 1_000, &h.sh);
        assert_eq!(
            s.shares_at_current_diff, 0,
            "evidence for the old difficulty was carried into the new one"
        );
    }
}
