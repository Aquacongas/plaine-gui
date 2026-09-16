use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use plaine_stratum::abuse::{BanTable, DiffCache, TokenBucket};
use plaine_stratum::limits::{Caps, Mode, DIFF_CACHE_MIN_SHARES, MIN_DIFF, START_DIFF};
use plaine_stratum::metrics::Metrics;
use plaine_stratum::mock::{InlineVerifier, MockJobSource, MockPow};
use plaine_stratum::nonce::{assemble_header, nonce_to_hex, E1Allocator, E1};
use plaine_stratum::session::{Action, ServerConfig, Session, Shared};
use plaine_stratum::target::Target;
use plaine_stratum::verify::{PowHasher, ResultSink, ShareVerifier, VerifyResult};

use plaine_consensus::bech32m;
use plaine_consensus::constants::ADDRESS_HRP;

struct Harness {
    sh: Arc<Shared>,
    #[allow(dead_code)]
    src: Arc<MockJobSource>,
    results: Arc<Mutex<Vec<VerifyResult>>>,
}

fn addr(seed: u8) -> String {
    bech32m::encode_bytes(ADDRESS_HRP, &[seed; 20]).unwrap()
}

fn harness(mode: Mode, network_diff: u64) -> Harness {
    let src = Arc::new(MockJobSource::new(184_602, Target::from_difficulty(network_diff)));
    let results = Arc::new(Mutex::new(Vec::new()));
    let r2 = results.clone();
    let sink: ResultSink = Arc::new(move |r: VerifyResult| r2.lock().unwrap().push(r));
    let verifier = Arc::new(InlineVerifier::new(Arc::new(MockPow::new()), sink));
    let caps = Caps::for_mode(mode);
    let sh = Arc::new(Shared {
        bans: Mutex::new(BanTable::new()),
        e1: Arc::new(Mutex::new(E1Allocator::new())),
        diffs: Mutex::new(DiffCache::new()),
        accept: Mutex::new(TokenBucket::new(
            caps.global_accept_per_sec as f64,
            caps.global_accept_per_sec as f64,
            0,
        )),
        jobs: src.clone(),
        verifier,
        metrics: Metrics::default(),
        caps,
        cfg: ServerConfig::for_mode(mode),
    });
    Harness { sh, src, results }
}

fn session(h: &Harness, ip: u8, now: u64) -> Session {
    Session::new(1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)), now, &h.sh)
}

fn feed(s: &mut Session, h: &Harness, line: &str, now: u64) -> String {
    s.outbuf.clear();
    s.on_line(line.as_bytes(), now, &h.sh);
    for _ in 0..4 {
        let actions = s.take_actions();
        let mut any = false;
        for a in actions {
            if let Action::Verify(w) = a {
                any = true;
                let rid = w.request_id;
                if !ShareVerifier::enqueue(h.sh.verifier.as_ref(), *w) {
                    s.on_verify_refused(rid, &h.sh);
                }
            } else {
                s.actions.push(a);
            }
        }
        let results: Vec<VerifyResult> = std::mem::take(&mut *h.results.lock().unwrap());
        for r in results {
            s.on_verify_result(r, now, &h.sh);
        }
        if !any {
            break;
        }
    }
    String::from_utf8(std::mem::take(&mut s.outbuf)).unwrap()
}

fn notify_job_id(wire: &str) -> Option<u32> {
    let anchor = "\"mining.notify\",\"params\":[\"";
    let start = wire.find(anchor)? + anchor.len();
    u32::from_str_radix(&wire[start..start + 8], 16).ok()
}

fn mine(prefix: &[u8; 124], e1: E1, target: &Target, from: u64) -> u64 {
    let need = target.to_difficulty();
    assert!(
        need <= 8_000_000,
        "target too hard for the search budget: difficulty {{need}}, budget 8_000_000"
    );
    let pow = MockPow::new();
    for x in from..from + 8_000_000 {
        let n = e1.compose(x);
        if target.accepts(&pow.digest(&assemble_header(prefix, n))) {
            return n;
        }
    }
    panic!("no share in budget");
}

fn notify_prefix(wire: &str) -> [u8; 124] {
    let anchor = "\"mining.notify\",\"params\":[\"";
    let start = wire.find(anchor).unwrap() + anchor.len();

    let after_job = &wire[start + 8..];

    let q1 = after_job.find(",\"").unwrap() + 2;
    let hex = &after_job[q1..q1 + 248];
    let mut out = [0u8; 124];
    for i in 0..124 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn pinned_shares_never_poison_cache() {
    let h = harness(Mode::Pool, u64::MAX / 2);
    let victim = 77u8;
    let mut s = session(&h, 1, 0);
    feed(&mut s, &h, r#"{"id":1,"method":"mining.subscribe","params":["m"]}"#, 0);
    let auth = feed(
        &mut s,
        &h,
        &format!(
            r#"{{"id":2,"method":"mining.authorize","params":["{}.rig+{}","x"]}}"#,
            addr(victim),
            MIN_DIFF
        ),
        0,
    );
    assert_eq!(s.difficulty(), MIN_DIFF, "the pin is honoured");
    let e1 = s.e1().unwrap();
    let mut jid = notify_job_id(&auth).unwrap();
    let mut prefix = notify_prefix(&auth);
    let target = Target::from_difficulty(MIN_DIFF);

    let mut now = 1_000u64;
    let mut from = 0u64;
    for _ in 0..(DIFF_CACHE_MIN_SHARES + 2) {
        let n = mine(&prefix, e1, &target, from);
        from = (n & ((1 << 40) - 1)) + 1;
        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                nonce_to_hex(n)
            ),
            now,
        );
        assert!(out.contains("\"result\":true"), "share should be accepted: {out}");
        now += 1_000;

        if let Some(j) = notify_job_id(&out) {
            jid = j;
            prefix = notify_prefix(&out);
        }
    }
    assert!(s.accepted_shares >= DIFF_CACHE_MIN_SHARES);

    let cached = h.sh.diffs.lock().unwrap().start_for(&[victim; 20], now).0;
    assert_eq!(
        cached, START_DIFF,
        "a PINNED difficulty leaked into the address cache (cached={cached})"
    );
}

#[test]
fn interpreter_cost_capped_by_admission() {
    let src = Arc::new(MockJobSource::new(184_602, Target::from_difficulty(1_000_000)));
    let sink: ResultSink = Arc::new(|_r| {});
    let verifier = Arc::new(InlineVerifier::new(Arc::new(MockPow::new()), sink));
    verifier.refuse.store(false, std::sync::atomic::Ordering::SeqCst);
    let sh = Arc::new(Shared {
        bans: Mutex::new(BanTable::new()),
        e1: Arc::new(Mutex::new(E1Allocator::new())),
        diffs: Mutex::new(DiffCache::new()),
        accept: Mutex::new(TokenBucket::new(500.0, 500.0, 0)),
        jobs: src.clone(),
        verifier: verifier.clone(),
        metrics: Metrics::default(),
        caps: Caps::POOL,
        cfg: ServerConfig::for_mode(Mode::Pool),
    });
    let h = Harness { sh, src, results: Arc::new(Mutex::new(Vec::new())) };

    let mut s = session(&h, 9, 0);
    feed(&mut s, &h, r#"{"id":1,"method":"mining.subscribe","params":["m"]}"#, 0);
    let auth = feed(
        &mut s,
        &h,
        &format!(r#"{{"id":2,"method":"mining.authorize","params":["{}.r","x"]}}"#, addr(9)),
        0,
    );
    let jid = notify_job_id(&auth).unwrap();
    let e1 = s.e1().unwrap();

    let mut verified_now = 0u64;
    let mut busy = 0u64;
    let mut throttled = 0u64;
    for i in 0..12u64 {
        s.outbuf.clear();
        s.on_line(
            format!(
                r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
                jid,
                nonce_to_hex(e1.compose(i))
            )
            .as_bytes(),
            0,
            &h.sh,
        );
        for a in s.take_actions() {
            if let Action::Verify(w) = a {
                verified_now += 1;
                let _ = ShareVerifier::enqueue(h.sh.verifier.as_ref(), *w);
            }
        }
        let out = String::from_utf8(std::mem::take(&mut s.outbuf)).unwrap();
        if out.contains("\"error\":[28") {
            busy += 1;
        }
        if out.contains("\"error\":[26") {
            throttled += 1;
        }
    }

    assert_eq!(
        verified_now, 1,
        "a 12-deep single-connection burst dispatched {verified_now} to the interpreter; \
         admission must cap in-flight at 1 regardless of message rate"
    );

    assert_eq!(busy, 8, "expected 8 server-busy refusals, got {busy}");
    assert_eq!(throttled, 2, "the submit burst of 10 throttles the last 2");

    assert_eq!(
        h.sh.bans.lock().unwrap().score(s.ip, 0),
        0,
        "server-busy refusals must never ban the flooder (that would DoS ourselves)"
    );
}
