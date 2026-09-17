use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use plaine_stratum::abuse::{BanTable, DiffCache, TokenBucket};
use plaine_stratum::limits::{Caps, Mode, IDLE_EVICT, LINE_BURST};
use plaine_stratum::metrics::Metrics;
use plaine_stratum::mock::{InlineVerifier, MockJobSource, MockPow};
use plaine_stratum::nonce::{
    assemble_header, nonce_to_hex, slice_fixed, E1Allocator, SliceSource, E1,
};
use plaine_stratum::session::{Action, CloseReason, ServerConfig, Session, Shared};
use plaine_stratum::target::Target;
use plaine_stratum::verify::{PowHasher, ResultSink, ShareVerifier, VerifyResult};

use plaine_consensus::bech32m;
use plaine_consensus::constants::ADDRESS_HRP;

struct OneSocket {
    held: Mutex<Option<E1>>,
    out: Mutex<Vec<(u32, u32)>>,
    next_sub: AtomicU32,
    sub_bits: u32,
}

impl OneSocket {
    fn new(e1: E1, sub_bits: u32) -> Arc<OneSocket> {
        Arc::new(OneSocket {
            held: Mutex::new(Some(e1)),
            out: Mutex::new(Vec::new()),
            next_sub: AtomicU32::new(0),
            sub_bits,
        })
    }

    fn rebind(&self, e1: E1) {
        *self.held.lock().unwrap() = Some(e1);
        self.next_sub.store(0, Ordering::SeqCst);
    }

    fn down(&self) {
        *self.held.lock().unwrap() = None;
    }
}

impl SliceSource for OneSocket {
    fn acquire(&self) -> Option<(E1, u32)> {
        let e1 = (*self.held.lock().unwrap())?;
        let sub = self.next_sub.fetch_add(1, Ordering::SeqCst);
        self.out.lock().unwrap().push((e1.0, sub));
        Some((e1, sub))
    }
    fn release(&self, e1: E1, sub: u32, _searched: bool) {
        self.out.lock().unwrap().retain(|p| *p != (e1.0, sub));
    }
    fn sub_bits(&self) -> u32 {
        self.sub_bits
    }
    fn live(&self) -> usize {
        self.out.lock().unwrap().len()
    }
    fn holds(&self, e1: E1, sub: u32) -> bool {
        *self.held.lock().unwrap() == Some(e1) && self.out.lock().unwrap().contains(&(e1.0, sub))
    }
}

struct Harness {
    sh: Arc<Shared>,
    src: Arc<MockJobSource>,
    verifier: Arc<InlineVerifier>,
    results: Arc<Mutex<Vec<VerifyResult>>>,
}

fn addr(seed: u8) -> String {
    bech32m::encode_bytes(ADDRESS_HRP, &[seed; 20]).unwrap()
}

fn harness(e1: Arc<dyn SliceSource>, network_diff: u64) -> Harness {
    let src = Arc::new(MockJobSource::new(
        184_602,
        Target::from_difficulty(network_diff),
    ));
    let results = Arc::new(Mutex::new(Vec::new()));
    let r2 = results.clone();
    let sink: ResultSink = Arc::new(move |r: VerifyResult| r2.lock().unwrap().push(r));
    let verifier = Arc::new(InlineVerifier::new(Arc::new(MockPow::new()), sink));
    let caps = Caps::for_mode(Mode::Pool);
    let sh = Arc::new(Shared {
        bans: Mutex::new(BanTable::new()),
        e1,
        diffs: Mutex::new(DiffCache::new()),
        accept: Mutex::new(TokenBucket::new(500.0, 500.0, 0)),
        jobs: src.clone(),
        verifier: verifier.clone(),
        metrics: Metrics::default(),
        caps,
        cfg: ServerConfig::for_mode(Mode::Pool),
    });
    Harness {
        sh,
        src,
        verifier,
        results,
    }
}

fn session(h: &Harness, ip: u8, now: u64) -> Session {
    Session::new(1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)), now, &h.sh)
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
                    ShareVerifier::enqueue(h.verifier.as_ref(), *w);
                }
                other => s.actions.push(other),
            }
        }
        if verified == 0 {
            break;
        }
        let results: Vec<VerifyResult> = h.results.lock().unwrap().drain(..).collect();
        for r in results {
            s.on_verify_result(r, now, &h.sh);
        }
    }
}

fn closed(s: &Session) -> Option<CloseReason> {
    s.actions.iter().find_map(|a| match a {
        Action::Close(r) => Some(*r),
        _ => None,
    })
}

fn verifies_requested(s: &Session) -> usize {
    s.actions
        .iter()
        .filter(|a| matches!(a, Action::Verify(_)))
        .count()
}

fn notify_job_id(wire: &str) -> u32 {
    let anchor = "\"mining.notify\",\"params\":[\"";
    let start = wire.find(anchor).expect("a notify") + anchor.len();
    u32::from_str_radix(&wire[start..start + 8], 16).expect("job id")
}

fn submit(s: &mut Session, h: &Harness, job: u32, nonce: u64, now: u64) -> String {
    feed(
        s,
        h,
        &format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{job:08x}","{}"]}}"#,
            nonce_to_hex(nonce)
        ),
        now,
    )
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

fn mine_in_sub(
    prefix: &[u8; 124],
    e1: E1,
    sub: u32,
    sub_bits: u32,
    target: &Target,
    from: u64,
) -> u64 {
    let need = target.to_difficulty();
    assert!(
        need <= 4_000_000,
        "target too hard for the search budget: difficulty {{need}}, budget 4_000_000"
    );
    let pow = MockPow::new();
    let fixed = slice_fixed(e1, sub, sub_bits);
    let xbits = 40 - sub_bits;
    for x in from..from + 4_000_000 {
        let n = (fixed << xbits) | (x & ((1u64 << xbits) - 1));
        if target.accepts(&pow.digest(&assemble_header(prefix, n))) {
            return n;
        }
    }
    panic!("no share found");
}

fn prefix_of(h: &Harness, seed: u8) -> [u8; 124] {
    let a: [u8; 20] = [seed; 20];
    h.sh.jobs.current(&a).expect("template").prefix
}

fn score(h: &Harness, ip: u8, now: u64) -> u32 {
    h.sh.bans
        .lock()
        .unwrap()
        .score(IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)), now)
}

#[test]
fn seated_session_closed_on_revoke() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src.clone() as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    let sub = subscribe_and_authorize(&mut s, &h, 1, 0);
    assert!(sub.contains("mining.notify"), "{sub}");
    assert_eq!(src.live(), 1);

    for t in 1..=10u64 {
        s.on_tick(t * 2_000, &h.sh);
        assert_eq!(closed(&s), None, "tick {t} closed a healthy session");
    }

    src.rebind(E1(0x000000));

    s.outbuf.clear();
    s.on_tick(30_000, &h.sh);
    assert_eq!(
        closed(&s),
        Some(CloseReason::SliceRevoked),
        "a rig seated on a slice the pool no longer owns was left mining it"
    );
    let wire = String::from_utf8(core::mem::take(&mut s.outbuf)).unwrap();
    assert_eq!(
        wire.trim_end(),
        r#"{"id":null,"result":null,"error":[31,"slice revoked",null]}"#,
        "the reason must be on the wire, not inferred from a bare FIN"
    );
    assert_eq!(
        score(&h, 1, 30_000),
        0,
        "our upstream moved; the miner did nothing and must not be scored for it"
    );
    assert_eq!(Metrics::get(&h.sh.metrics.closed_slice_revoked), 1);
}

#[test]
fn revoked_slice_submit_refused() {
    let net = 1u64 << 18;
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src.clone() as Arc<dyn SliceSource>, net);
    let mut s = session(&h, 1, 0);
    let job = notify_job_id(&subscribe_and_authorize(&mut s, &h, 1, 0));
    let (e1, sub) = (E1(0x0001b5), 0u32);
    let prefix = prefix_of(&h, 1);
    let win = mine_in_sub(&prefix, e1, sub, 8, &Target::from_difficulty(net), 0);

    src.rebind(E1(0x000000));

    let out = submit(&mut s, &h, job, win, 1_000);
    assert!(
        out.contains(r#""error":[31,"slice revoked""#),
        "the submit must be answered, and answered with the reason: {out}"
    );
    assert_eq!(
        verifies_requested(&s),
        0,
        "a share on a slice we do not own must never reach the interpreter, \
         let alone the sealer"
    );
    assert_eq!(
        h.src.blocks_sealed(),
        0,
        "the pool sealed a block it could not present"
    );
    assert_eq!(closed(&s), Some(CloseReason::SliceRevoked));
    assert_eq!(
        score(&h, 1, 1_000),
        0,
        "a lost slice is never the rig's fault"
    );
}

#[test]
fn revoked_session_releases_and_resumes() {
    let net = 1u64 << 18;
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src.clone() as Arc<dyn SliceSource>, net);

    let mut s = session(&h, 1, 0);
    subscribe_and_authorize(&mut s, &h, 1, 0);
    assert_eq!(src.live(), 1);

    src.rebind(E1(0x000000));
    s.on_tick(2_000, &h.sh);
    assert_eq!(closed(&s), Some(CloseReason::SliceRevoked));

    s.release(2_000, &h.sh);
    assert_eq!(
        src.live(),
        0,
        "a hung-up session must not keep its sub-slice"
    );

    let mut s2 = session(&h, 1, 3_000);
    let out = subscribe_and_authorize(&mut s2, &h, 1, 3_000);
    assert!(out.contains("mining.notify"), "{out}");
    let job2 = notify_job_id(&out);
    let e1 = s2.e1().expect("re-seated");
    assert_eq!(e1, E1(0x000000), "on the node's NEW slice");
    let prefix = prefix_of(&h, 1);
    let win = mine_in_sub(&prefix, e1, 0, 8, &Target::from_difficulty(net), 0);
    let out = submit(&mut s2, &h, job2, win, 3_100);
    assert!(out.contains(r#""result":true"#), "{out}");
    assert_eq!(closed(&s2), None);
    assert_eq!(
        h.src.blocks_sealed(),
        1,
        "the rig reconnected and its block landed"
    );
}

#[test]
fn subscribed_only_session_revoked() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src.clone() as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    feed(
        &mut s,
        &h,
        r#"{"id":1,"method":"mining.subscribe","params":["plaine-miner/1.0"]}"#,
        0,
    );
    assert_eq!(src.live(), 1);
    assert!(!s.is_authorized());

    src.down();
    s.on_tick(2_000, &h.sh);
    assert_eq!(closed(&s), Some(CloseReason::SliceRevoked));
    s.release(2_000, &h.sh);
    assert_eq!(src.live(), 0);
}

#[test]
fn default_holds_never_revokes() {
    struct Minimal(Mutex<u32>);
    impl SliceSource for Minimal {
        fn acquire(&self) -> Option<(E1, u32)> {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Some((E1(*n), 0))
        }
        fn release(&self, _e1: E1, _sub: u32, _searched: bool) {}
        fn live(&self) -> usize {
            0
        }
    }
    let src = Arc::new(Minimal(Mutex::new(0)));
    assert!(src.holds(E1(1), 0));
    assert!(src.holds(E1(0xFFFFFF), 255));

    let h = harness(src as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    subscribe_and_authorize(&mut s, &h, 1, 0);
    for t in 1..=100u64 {
        s.outbuf.clear();
        s.on_tick(t * 2_000, &h.sh);
        assert_ne!(
            closed(&s),
            Some(CloseReason::SliceRevoked),
            "the default answer to `holds` closed a healthy session at tick {t}"
        );
    }
    assert_eq!(Metrics::get(&h.sh.metrics.closed_slice_revoked), 0);
}

#[test]
fn node_never_revokes_solo_miners() {
    let alloc: Arc<Mutex<E1Allocator>> = Arc::new(Mutex::new(E1Allocator::new()));
    let h = harness(alloc.clone() as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    subscribe_and_authorize(&mut s, &h, 1, 0);
    for t in 1..=18_000u64 {
        s.outbuf.clear();
        s.on_tick(t * 2_000, &h.sh);
        if let Some(r) = closed(&s) {
            assert_ne!(r, CloseReason::SliceRevoked, "the node revoked a slice");

            assert_eq!(r, CloseReason::Idle);
            break;
        }
    }
    assert_eq!(Metrics::get(&h.sh.metrics.closed_slice_revoked), 0);
}

#[test]
fn revoked_submit_costs_no_token_or_dedup() {
    let net = 1u64 << 18;
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src.clone() as Arc<dyn SliceSource>, net);
    let mut s = session(&h, 1, 0);
    let job = notify_job_id(&subscribe_and_authorize(&mut s, &h, 1, 0));
    let prefix = prefix_of(&h, 1);
    let n = mine_in_sub(
        &prefix,
        E1(0x0001b5),
        0,
        8,
        &Target::from_difficulty(60_000),
        0,
    );
    src.down();

    let before = Metrics::get(&h.sh.metrics.rej_throttled);
    let out = submit(&mut s, &h, job, n, 500);
    assert!(out.contains(r#""error":[31,"slice revoked""#), "{out}");
    assert_eq!(Metrics::get(&h.sh.metrics.rej_throttled), before);
    assert_eq!(Metrics::get(&h.sh.metrics.rej_duplicate), 0);
    assert_eq!(Metrics::get(&h.sh.metrics.shares_verified), 0);
}

#[test]
fn garbage_nonce_refused_before_source() {
    struct Counting {
        inner: Arc<OneSocket>,
        asked: AtomicU32,
    }
    impl SliceSource for Counting {
        fn acquire(&self) -> Option<(E1, u32)> {
            self.inner.acquire()
        }
        fn release(&self, e1: E1, sub: u32, searched: bool) {
            self.inner.release(e1, sub, searched)
        }
        fn sub_bits(&self) -> u32 {
            self.inner.sub_bits()
        }
        fn live(&self) -> usize {
            self.inner.live()
        }
        fn holds(&self, e1: E1, sub: u32) -> bool {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.inner.holds(e1, sub)
        }
    }
    let inner = OneSocket::new(E1(0x0001b5), 8);
    let src = Arc::new(Counting {
        inner: inner.clone(),
        asked: AtomicU32::new(0),
    });
    let h = harness(src.clone() as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    let job = notify_job_id(&subscribe_and_authorize(&mut s, &h, 1, 0));
    let base = src.asked.load(Ordering::SeqCst);

    let out = submit(&mut s, &h, job, 0xDEAD_BEEF_CAFE_1234, 500);
    assert!(out.contains(r#""error":[25,"nonce out of slice""#), "{out}");
    assert_eq!(
        src.asked.load(Ordering::SeqCst),
        base,
        "an out-of-slice nonce reached the source's lock"
    );
}

#[test]
fn keepalive_answered_scores_nothing() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    subscribe_and_authorize(&mut s, &h, 1, 0);
    let out = feed(&mut s, &h, r#"{"id":9,"method":"mining.keepalive"}"#, 1_000);
    assert_eq!(out, "{\"id\":9,\"result\":true,\"error\":null}\n");
    assert_eq!(closed(&s), None);
    assert_eq!(score(&h, 1, 1_000), 0);
    assert_eq!(Metrics::get(&h.sh.metrics.keepalives), 1);

    assert_eq!(Metrics::get(&h.sh.metrics.bad_json), 0);
    assert!(!out.contains("29"), "{out}");
}

#[test]
fn keepalive_only_still_idle_evicted() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    subscribe_and_authorize(&mut s, &h, 1, 0);

    let evict = IDLE_EVICT.as_millis() as u64;
    let mut now = 0u64;

    while now < evict + 400_000 {
        now += 200_000;
        let out = feed(&mut s, &h, r#"{"id":9,"method":"mining.keepalive"}"#, now);
        assert!(out.contains("true") || closed(&s).is_some(), "{out}");
        s.on_tick(now, &h.sh);
        if closed(&s).is_some() {
            break;
        }
    }
    assert_eq!(
        closed(&s),
        Some(CloseReason::Idle),
        "a connection that only ever sent heartbeats outlived idle eviction"
    );
    assert!(
        now <= evict + 400_000,
        "evicted at {now} ms against a {evict} ms window"
    );
}

#[test]
fn keepalive_does_not_hold_auth_deadline() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    let mut now = 0u64;
    while now < 30_000 {
        now += 1_000;
        feed(&mut s, &h, r#"{"id":9,"method":"mining.keepalive"}"#, now);
        s.on_tick(now, &h.sh);
        if closed(&s).is_some() {
            break;
        }
    }
    assert_eq!(closed(&s), Some(CloseReason::AuthTimeout));
    assert!(
        now <= 12_000,
        "a peer keeping a socket warm with heartbeats survived {now} ms \
         against a 10 000 ms authorization deadline"
    );
}

#[test]
fn keepalive_charged_line_budget() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    subscribe_and_authorize(&mut s, &h, 1, 0);
    let mut sent = 0u32;
    for _ in 0..(LINE_BURST as u32 + 20) {
        feed(&mut s, &h, r#"{"id":9,"method":"mining.keepalive"}"#, 1_000);
        sent += 1;
        if closed(&s).is_some() {
            break;
        }
    }
    assert_eq!(closed(&s), Some(CloseReason::LineFlood));
    assert!(
        sent <= LINE_BURST as u32 + 2,
        "the keep-alive escaped the line budget: {sent} accepted"
    );
    assert!(score(&h, 1, 1_000) >= 50);
}

#[test]
fn keepalive_moves_no_regulator() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    subscribe_and_authorize(&mut s, &h, 1, 0);
    let before = s.difficulty();
    let retargets = Metrics::get(&h.sh.metrics.retargets);
    for i in 1..=20u64 {
        feed(
            &mut s,
            &h,
            r#"{"id":9,"method":"mining.keepalive"}"#,
            i * 1_000,
        );
    }
    assert_eq!(s.accepted_shares, 0);
    assert_eq!(s.accepted_difficulty, 0);
    assert_eq!(s.difficulty(), before);
    assert_eq!(Metrics::get(&h.sh.metrics.retargets), retargets);
    assert_eq!(Metrics::get(&h.sh.metrics.shares_submitted), 0);
}

#[test]
fn keepalive_before_subscribe_no_auth() {
    let src = OneSocket::new(E1(0x0001b5), 8);
    let h = harness(src as Arc<dyn SliceSource>, 1 << 30);
    let mut s = session(&h, 1, 0);
    let out = feed(&mut s, &h, r#"{"id":9,"method":"mining.keepalive"}"#, 0);
    assert_eq!(out, "{\"id\":9,\"result\":true,\"error\":null}\n");
    assert!(!s.is_authorized());
    assert!(s.e1().is_none(), "a heartbeat must not take a nonce slice");

    let out = feed(
        &mut s,
        &h,
        r#"{"id":7,"method":"mining.submit","params":["w","00000001","0000000000000000"]}"#,
        10,
    );
    assert!(out.contains(r#""error":[24,"unauthorized""#), "{out}");
}
