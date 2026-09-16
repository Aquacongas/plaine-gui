use plaine_stratum::abuse::{BanTable, DiffCache, TokenBucket};
use plaine_stratum::job::{JobError, JobSource, SealOutcome, Template, TemplateBody};
use plaine_stratum::limits::JOB_PREFIX_BYTES;
use plaine_stratum::login::AddressBytes;
use plaine_stratum::metrics::Metrics;
use plaine_stratum::nonce::E1Allocator;
use plaine_stratum::session::{Action, ServerConfig, Session, Shared};
use plaine_stratum::target::Target;
use plaine_stratum::verify::{
    verify_one_isolated, PowHasher, ShareVerifier, ShareWork, VerifyResult,
};
use plaine_stratum::{Caps, Mode};

use plaine_pow_mine::client::json::{Framed, Lines};
use plaine_pow_mine::pad;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use plaine_pow_mine::client::{self, Args};

struct Interpreter;

impl PowHasher for Interpreter {
    fn digest(&self, header: &[u8; 132]) -> [u8; 32] {
        let iso = plaine_pow::Isochron::new().expect("the interpreter is available");
        let mut pad = plaine_pow::Scratch::new();

        let seed = plaine_consensus::pow::seed(header);
        let raw = iso.verify_hash(&mut pad, seed);
        plaine_consensus::pow::pow_hash(header, raw)
    }
}

struct InlineVerifier {
    pow: Arc<Interpreter>,
    out: Mutex<mpsc::Sender<VerifyResult>>,
}

impl ShareVerifier for InlineVerifier {
    fn enqueue(&self, work: ShareWork) -> bool {
        let verdict = verify_one_isolated(self.pow.as_ref(), &work);
        let r = VerifyResult {
            conn: work.conn,
            request_id: work.request_id,
            seq: work.seq,
            verdict,
            served_difficulty: work.served_difficulty,
        };
        self.out.lock().expect("verifier sink").send(r).is_ok()
    }
}

#[derive(Debug, Default)]
struct TestBody {
    sealed: AtomicU64,
}

impl TemplateBody for TestBody {
    fn seal(&self, _nonce: u64) -> SealOutcome {
        self.sealed.fetch_add(1, Ordering::SeqCst);
        SealOutcome::Accepted
    }
}

struct TestSource {
    prefix: [u8; JOB_PREFIX_BYTES],
    network_target: Target,
    height: u64,
    next_id: AtomicU64,
    bodies: Mutex<Vec<Arc<TestBody>>>,
}

impl TestSource {
    fn new() -> TestSource {
        let mut prefix = [0u8; JOB_PREFIX_BYTES];
        let bits = plaine_consensus::constants::GENESIS_BITS;
        prefix[116..120].copy_from_slice(&bits.to_le_bytes());
        TestSource {
            prefix,
            network_target: Target::from_compact(bits).expect("GENESIS_BITS decodes"),
            height: 1,
            next_id: AtomicU64::new(1),
            bodies: Mutex::new(Vec::new()),
        }
    }

    fn blocks_sealed(&self) -> u64 {
        self.bodies.lock().expect("bodies").iter().map(|b| b.sealed.load(Ordering::SeqCst)).sum()
    }
}

impl JobSource for TestSource {
    fn current(&self, recipient: &AddressBytes) -> Result<Arc<Template>, JobError> {
        let body = Arc::new(TestBody::default());
        self.bodies.lock().expect("bodies").push(Arc::clone(&body));
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut prefix = self.prefix;

        prefix[44..64].copy_from_slice(recipient);

        prefix[100..108].copy_from_slice(&id.to_le_bytes());
        Ok(Arc::new(Template {
            id,
            prefix,
            height: self.height,
            network_target: self.network_target,
            new_tip: true,
            body,
        }))
    }

    fn generation(&self) -> u64 {
        1
    }
}

struct World {
    shared: Arc<Shared>,
    src: Arc<TestSource>,
    results: Mutex<mpsc::Receiver<VerifyResult>>,
    t0: Instant,
    accepts: AtomicU64,
    observed_e1: AtomicU64,
}

const BURNED_SLICES: u32 = 0xA3;

impl World {
    fn new() -> Arc<World> {
        let src = Arc::new(TestSource::new());
        let (tx, rx) = mpsc::channel();
        let verifier = Arc::new(InlineVerifier {
            pow: Arc::new(Interpreter),
            out: Mutex::new(tx),
        });
        let mut cfg = ServerConfig::for_mode(Mode::Solo);

        cfg.tick_ms = 200;
        let shared = Arc::new(Shared {
            bans: Mutex::new(BanTable::new()),
            e1: Arc::new(Mutex::new(E1Allocator::new())),
            diffs: Mutex::new(DiffCache::new()),
            accept: Mutex::new(TokenBucket::new(500.0, 500.0, 0)),
            jobs: Arc::clone(&src) as Arc<dyn JobSource>,
            verifier,
            metrics: Metrics::default(),
            caps: Caps::for_mode(Mode::Solo),
            cfg,
        });

        for _ in 0..BURNED_SLICES {
            shared.e1.acquire().expect("a free slice");
        }
        Arc::new(World {
            shared,
            src,
            results: Mutex::new(rx),
            t0: Instant::now(),
            accepts: AtomicU64::new(0),
            observed_e1: AtomicU64::new(0),
        })
    }

    fn accepts(&self) -> u64 {
        self.accepts.load(Ordering::SeqCst)
    }

    fn observed_e1(&self) -> u64 {
        self.observed_e1.load(Ordering::SeqCst)
    }

    fn now_ms(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }

    fn accepted(&self) -> u64 {
        self.shared.metrics.shares_accepted.load(Ordering::SeqCst)
    }

    fn listen(self: &Arc<Self>, port: u16) -> Rig {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let world = Arc::clone(self);
        let s = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut conn_id = 0u64;
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        conn_id += 1;
                        world.accepts.fetch_add(1, Ordering::SeqCst);
                        serve_one(&world, sock, conn_id, &s);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Rig { port, stop, handle: Some(handle) }
    }
}

struct Rig {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Rig {
    fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve_one(world: &Arc<World>, sock: TcpStream, id: u64, stop: &Arc<AtomicBool>) {
    let peer = match sock.peer_addr() {
        Ok(p) => p,
        Err(_) => return,
    };
    sock.set_nodelay(true).ok();

    sock.set_nonblocking(false).expect("blocking");
    sock.set_read_timeout(Some(Duration::from_millis(25))).expect("read timeout");
    let mut w = sock.try_clone().expect("clone");
    let mut r = Lines::new(sock, world.shared.cfg.max_line_post_auth);
    let mut sess = Session::new(id, peer.ip(), world.now_ms(), &world.shared);

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let now = world.now_ms();
        sess.on_tick(now, &world.shared);

        while let Ok(v) = world.results.lock().expect("results").try_recv() {
            sess.on_verify_result(v, now, &world.shared);
        }

        let mut closing = false;
        for action in sess.take_actions() {
            match action {
                Action::Verify(work) => {
                    let request_id = work.request_id;
                    if !world.shared.verifier.enqueue(*work) {
                        sess.on_verify_refused(request_id, &world.shared);
                    }
                }
                Action::Close(_) => closing = true,
            }
        }

        if !sess.outbuf.is_empty() {
            if w.write_all(&sess.outbuf).is_err() || w.flush().is_err() {
                break;
            }
            sess.outbuf.clear();
        }
        if closing {
            break;
        }

        let raw = match r.next() {
            Ok(Framed::Line(l)) => l,
            Ok(Framed::Idle) => continue,
            Ok(Framed::Eof) | Ok(Framed::TooLong) | Err(_) => break,
        };
        if raw.is_empty() {
            if !sess.charge_line(world.now_ms(), &world.shared) {
                break;
            }
            continue;
        }

        sess.on_line(&raw, world.now_ms(), &world.shared);
        if let Some(e1) = sess.e1() {
            world.observed_e1.store(e1.0 as u64, Ordering::SeqCst);
        }
    }

    let now = world.now_ms();
    while let Ok(v) = world.results.lock().expect("results").try_recv() {
        sess.on_verify_result(v, now, &world.shared);
    }
    if !sess.outbuf.is_empty() {
        let _ = w.write_all(&sess.outbuf);
        let _ = w.flush();
    }
    sess.release(now, &world.shared);
}

fn faucet_login(rig_name: &str) -> String {
    let pk = plaine_consensus::blake3::hash(b"PLAINE FAUCET v1");
    let addr = plaine_consensus::crypto::address_from_pubkey(&pk);

    format!("{addr}.{rig_name}+8192")
}

fn wait_for(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out after {:?} waiting for {what}", t0.elapsed());
}

static PADS_ALONE: Mutex<()> = Mutex::new(());

fn pads_alone() -> std::sync::MutexGuard<'static, ()> {
    PADS_ALONE.lock().unwrap_or_else(|e| e.into_inner())
}

struct Hostile {
    port: u16,
    seen: Arc<AtomicU64>,
    heard: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Hostile {
    fn start(reply: String) -> Hostile {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicU64::new(0));
        let heard = Arc::new(Mutex::new(Vec::new()));
        let (s, n, h) = (Arc::clone(&stop), Arc::clone(&seen), Arc::clone(&heard));
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        n.fetch_add(1, Ordering::SeqCst);
                        sock.set_nonblocking(false).ok();
                        sock.set_read_timeout(Some(Duration::from_millis(25))).ok();
                        let mut w = sock.try_clone().expect("clone");

                        let mut r = Lines::new(sock, 4096);
                        let mut replied = false;

                        let until = Instant::now() + Duration::from_millis(600);
                        while Instant::now() < until {
                            match r.next() {
                                Ok(Framed::Line(l)) => {
                                    h.lock().expect("heard").push(String::from_utf8_lossy(&l).into_owned());
                                    if !replied {
                                        replied = true;
                                        if w.write_all(reply.as_bytes()).is_err() || w.flush().is_err() {
                                            break;
                                        }
                                    }
                                }
                                Ok(Framed::Idle) => continue,
                                _ => break,
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Hostile { port, seen, heard, stop, handle: Some(handle) }
    }

    fn connections(&self) -> u64 {
        self.seen.load(Ordering::SeqCst)
    }

    fn heard(&self) -> Vec<String> {
        self.heard.lock().expect("heard").clone()
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn miner_args(port: u16) -> Args {
    Args {
        stratum: format!("127.0.0.1:{port}"),
        login: faucet_login("rig1"),
        threads: std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(2),
        status_secs: 1,
        ..Args::default()
    }
}

#[test]
fn jit_share_accepted_by_server() {
    let _alone = pads_alone();
    let world = World::new();
    let rig = world.listen(0);
    let args = Args { max_shares: 1, deadline_secs: 240, ..miner_args(rig.port) };

    let report = client::run(&args).expect("the miner ran");

    assert!(report.accepted >= 1, "the miner saw no share accepted: {report:?}");
    assert_eq!(report.rejected, 0, "the server refused a share: {report:?}");
    assert!(report.hashes > 0, "no hashing happened at all");

    let m = &world.shared.metrics;
    assert!(
        m.shares_accepted.load(Ordering::SeqCst) >= 1,
        "the server's own counter did not record an accepted share"
    );
    assert!(m.shares_verified.load(Ordering::SeqCst) >= 1, "no share reached the interpreter");
    assert_eq!(m.authorizes_ok.load(Ordering::SeqCst), 1);
    assert_eq!(m.authorizes_bad.load(Ordering::SeqCst), 0);

    assert_eq!(
        m.rej_low_difficulty.load(Ordering::SeqCst),
        0,
        "the interpreter disagreed with the JIT about a share the miner had verified"
    );

    assert!(
        world.observed_e1() != 0,
        "the miner was issued slice 0, where the slice-binding check below cannot fail"
    );
    assert_eq!(world.observed_e1(), BURNED_SLICES as u64, "an unexpected slice was issued");
    assert_eq!(m.rej_out_of_slice.load(Ordering::SeqCst), 0, "error 25: nonce slice mismatch");
    assert_eq!(m.rej_unknown_job.load(Ordering::SeqCst), 0, "submitted against a job we invented");
    assert_eq!(m.rej_duplicate.load(Ordering::SeqCst), 0, "two workers mined the same nonce");
    assert_eq!(m.rej_stale.load(Ordering::SeqCst), 0, "submitted a job the server had retired");

    assert!(
        world.src.blocks_sealed() <= report.blocks,
        "the server sealed a block the miner never recognised as one: {} sealed, {} claimed",
        world.src.blocks_sealed(),
        report.blocks
    );
    assert_eq!(
        world.src.blocks_sealed(),
        m.blocks_found.load(Ordering::SeqCst),
        "a block was sealed that the server did not count"
    );

    rig.stop();
}

#[test]
fn miner_survives_server_bounce() {
    let _alone = pads_alone();
    let world = World::new();
    let rig = world.listen(0);
    let port = rig.port;

    assert_eq!(
        pad::observed_now().total(),
        0,
        "another test in this binary is holding pads; the tallies are process-wide"
    );

    let args = Args { max_shares: 0, deadline_secs: 25, ..miner_args(port) };
    let threads = args.threads;
    let w = Arc::clone(&world);
    let miner = std::thread::spawn(move || client::run(&args).expect("the miner ran"));

    wait_for("the first share", Duration::from_secs(240), || w.accepted() >= 1);

    let first_session = pad::observed_now();
    assert_eq!(
        first_session.total(),
        threads,
        "a {threads}-thread miner is mining over {} pad regions",
        first_session.total()
    );

    rig.stop();
    assert!(!miner.is_finished(), "the miner gave up the moment the server dropped");

    std::thread::sleep(Duration::from_millis(1500));
    assert!(!miner.is_finished(), "the miner exited while the server was down");

    let rig = world.listen(port);
    assert_eq!(rig.port, port, "the server came back somewhere else");

    let before_restart = w.accepted();
    wait_for("one share accepted after the restart", Duration::from_secs(200), || {
        w.accepted() > before_restart
    });

    let mut peak_live = 0usize;
    let mut field_at_peak = String::new();
    wait_for("two shares accepted after the restart", Duration::from_secs(200), || {
        let live = pad::observed_now().total();
        if live > peak_live {
            peak_live = live;
            field_at_peak = pad::status_field();
        }
        w.accepted() >= before_restart + 2
    });
    assert_eq!(
        peak_live, threads,
        "after one reconnect a {threads}-thread miner reports {peak_live} live pad regions; \
         the status line is describing regions that no longer exist"
    );

    let words: Vec<&str> = field_at_peak.split_whitespace().collect();
    assert_eq!(words.len(), 3, "the status field is three words: {field_at_peak:?}");
    assert_eq!(words[0], "pads", "the label a rig script scans for has moved: {field_at_peak:?}");
    assert!(
        words[2].ends_with(&format!("/{threads}")),
        "the status line after a reconnect reads {field_at_peak:?} for {threads} workers"
    );

    let report = miner.join().expect("the miner thread did not panic");
    assert!(report.accepted >= before_restart + 2, "{report:?}");
    assert!(
        report.connections >= 2,
        "the miner never re-authorized, so it did not really reconnect: {report:?}"
    );
    assert_eq!(report.rejected, 0, "a share was refused across the reconnect: {report:?}");

    let m = &world.shared.metrics;

    assert!(m.subscribes.load(Ordering::SeqCst) >= 2, "the second connection did not subscribe");
    assert_eq!(m.rej_out_of_slice.load(Ordering::SeqCst), 0, "stale extranonce1 after reconnect");
    assert_eq!(m.rej_low_difficulty.load(Ordering::SeqCst), 0);

    assert_eq!(
        pad::observed_now().total(),
        0,
        "the run has ended and its pad regions are still counted as live"
    );
    let ever = pad::observed_ever().total();
    assert!(
        ever >= report.connections as usize * threads,
        "{} connections x {threads} workers were mapped over this run and the lifetime tally \
         says {ever}",
        report.connections
    );
    assert!(
        ever > threads,
        "the reconnect mapped a second set of regions and the lifetime tally did not see them"
    );
    eprintln!("real_server: {ever} pad regions mapped over the run, 0 live at the end");

    rig.stop();
}

const WINDOW_SECS: u64 = 8;

#[test]
fn refused_login_retries_on_slow_ladder() {
    let _alone = pads_alone();
    let world = World::new();
    let rig = world.listen(0);

    let args = Args {
        login: "not-an-address.rig1".into(),
        deadline_secs: WINDOW_SECS,
        ..miner_args(rig.port)
    };

    let t0 = Instant::now();
    let miner = std::thread::spawn(move || client::run(&args).expect("a refused login is not an io error"));

    std::thread::sleep(Duration::from_secs(3));
    assert!(!miner.is_finished(), "the miner exited when the pool refused its login");

    let report = miner.join().expect("the miner thread did not panic");
    assert!(
        t0.elapsed() >= Duration::from_secs(WINDOW_SECS - 1),
        "the run ended after {:?}, before its own deadline: a refusal stopped it",
        t0.elapsed()
    );
    assert_eq!(report.accepted, 0);
    assert_eq!(report.connections, 0, "it never authorized, so nothing here is about mining");

    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        world.accepts(),
        1,
        "the server accepted {} connections from this miner in {WINDOW_SECS}s over one \
         refused login",
        world.accepts()
    );

    let m = &world.shared.metrics;
    assert_eq!(
        m.authorizes_bad.load(Ordering::SeqCst),
        1,
        "the server was asked to refuse the same login {} times in {WINDOW_SECS}s; \
         at +25 banscore each that is an IP ban",
        m.authorizes_bad.load(Ordering::SeqCst)
    );
    assert_eq!(
        m.subscribes.load(Ordering::SeqCst),
        1,
        "it reconnected on the fast ladder after an authorization failure"
    );

    rig.stop();
}

#[test]
fn malformed_subscribe_does_not_end_run() {
    let _alone = pads_alone();
    let cases: Vec<(&str, String)> = vec![
        (
            "no extranonce1",
            "{\"id\":1,\"result\":[[\"mining.notify\"],null,5],\"error\":null}\n".to_string(),
        ),
        (
            "extranonce1 is not hex",
            "{\"id\":1,\"result\":[[\"mining.notify\"],\"zzzzzz\",5],\"error\":null}\n".to_string(),
        ),
        (

            "a rollable window narrower than this miner will roll",
            "{\"id\":1,\"result\":[[\"mining.notify\"],\"00a3f2\",3],\"error\":null}\n".to_string(),
        ),
        (
            "a rollable window wider than the nonce has room for",
            "{\"id\":1,\"result\":[[\"mining.notify\"],\"00a3f2\",6],\"error\":null}\n".to_string(),
        ),
        (

            "an extranonce1 too wide for its window",
            "{\"id\":1,\"result\":[[\"mining.notify\"],\"01000000\",5],\"error\":null}\n".to_string(),
        ),
        ("a line longer than MAX_LINE", "x".repeat(client::MAX_LINE + 2048)),
    ];

    for (what, reply) in cases {
        let peer = Hostile::start(reply);
        let args = Args { deadline_secs: WINDOW_SECS, ..miner_args(peer.port) };

        let t0 = Instant::now();
        let report = client::run(&args).unwrap_or_else(|e| panic!("{what}: the run failed: {e}"));

        assert!(
            t0.elapsed() >= Duration::from_secs(WINDOW_SECS - 1),
            "{what}: the run ended after {:?}, before its own deadline",
            t0.elapsed()
        );

        assert!(
            peer.connections() >= 3,
            "{what}: the peer saw {} connections in {WINDOW_SECS}s; the miner stopped coming back",
            peer.connections()
        );
        assert_eq!(report.connections, 0, "{what}: nothing here ever authorized");
        assert_eq!(report.hashes, 0, "{what}: nothing here ever mined");

        let heard = peer.heard();
        assert!(
            heard.iter().any(|l| l.contains("mining.subscribe")),
            "{what}: the miner never subscribed at all: {heard:?}"
        );
        assert!(
            !heard.iter().any(|l| l.contains("mining.authorize")),
            "{what}: the miner accepted a subscribe response it cannot mine against and \
             carried on to authorize: {heard:?}"
        );
        peer.stop();
    }
}

#[test]
fn absent_server_retried_then_abandoned() {
    let _alone = pads_alone();

    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let args = Args { max_reconnects: 2, deadline_secs: 30, ..miner_args(port) };

    let t0 = Instant::now();
    let report = client::run(&args).expect("connection refused is not a hard error when retrying");

    assert_eq!(report.accepted, 0);
    assert_eq!(report.connections, 0);

    assert!(t0.elapsed() >= Duration::from_secs(1), "it did not back off at all");
    assert!(t0.elapsed() < Duration::from_secs(25), "it never gave up: {:?}", t0.elapsed());
}

#[test]
fn narrow_window_session_continues() {
    let _alone = pads_alone();

    let peer = Hostile::start(
        "{\"id\":1,\"result\":[[\"mining.notify\",\"mining.set_target\"],\"a3f205\",4],\"error\":null}\n"
            .to_string(),
    );
    let args = Args { deadline_secs: 4, ..miner_args(peer.port) };

    let report = client::run(&args).expect("a narrow window is not an error");

    let heard = peer.heard();
    assert!(
        heard.iter().any(|l| l.contains("mining.subscribe")),
        "the miner never subscribed: {heard:?}"
    );
    assert!(
        heard.iter().any(|l| l.contains("mining.authorize")),
        "the miner refused a {}-byte rollable window and never authorized: {heard:?}",
        4
    );

    assert_eq!(report.connections, 0);
    assert_eq!(report.hashes, 0);
    peer.stop();
}

#[cfg(target_os = "linux")]
fn allowed_list(tid: &str) -> Option<String> {
    let st = std::fs::read_to_string(format!("/proc/self/task/{tid}/status")).ok()?;
    st.lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(|v| v.trim().to_string())
}

#[cfg(target_os = "linux")]
fn threads_by_name() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else { return out };
    for e in dir.flatten() {
        let tid = e.file_name().to_string_lossy().to_string();
        if let Ok(name) = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")) {
            out.push((name.trim().to_string(), tid));
        }
    }
    out
}

#[cfg(target_os = "linux")]
#[test]
fn workers_pinned_socket_thread_free() {
    let _alone = pads_alone();
    let world = World::new();
    let rig = world.listen(0);

    let allowed = plaine_pow_mine::client::args::cpu::allowed_cpus()
        .unwrap_or_else(|| (0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)).collect());
    if allowed.len() < 2 {
        eprintln!("only {} CPU(s) available; nothing to place", allowed.len());
        return;
    }
    let picked: Vec<usize> = allowed.iter().copied().take(2).collect();

    let main_before = allowed_list("self").or_else(|| {
        let me = std::fs::read_link("/proc/thread-self").ok()?;
        allowed_list(me.file_name()?.to_str()?)
    });

    let args = Args {
        threads: picked.len(),
        pins: Some(picked.iter().map(|&c| (c, 0u16)).collect()),
        deadline_secs: 30,
        ..miner_args(rig.port)
    };

    let miner = std::thread::spawn(move || client::run(&args));

    let single_cpu = |l: &str| !l.contains(',') && !l.contains('-');
    let mut pinned: Vec<(usize, String)> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        pinned = threads_by_name()
            .into_iter()
            .filter_map(|(n, tid)| {
                let idx: usize = n.strip_prefix("plaine-miner-")?.parse().ok()?;
                let list = allowed_list(&tid)?;
                single_cpu(&list).then_some((idx, list))
            })
            .collect();
        if pinned.len() >= picked.len() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    assert_eq!(
        pinned.len(),
        picked.len(),
        "expected {} single-CPU worker threads, the kernel reports {:?}",
        picked.len(),
        pinned
    );

    for (idx, list) in &pinned {
        let want = picked
            .get(*idx)
            .unwrap_or_else(|| panic!("worker index {idx} is outside the pin list"));
        assert_eq!(
            list,
            &want.to_string(),
            "worker {idx} should be on cpu {want} alone; the kernel says {list}"
        );
    }

    let main_after = allowed_list("self").or_else(|| {
        let me = std::fs::read_link("/proc/thread-self").ok()?;
        allowed_list(me.file_name()?.to_str()?)
    });
    assert_eq!(
        main_before, main_after,
        "the socket thread was confined; --cpu-affinity must place only the workers"
    );

    rig.stop();
    let _ = miner.join();
    drop(world);
}
