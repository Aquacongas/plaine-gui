use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use plaine_stratum::abuse::{BanTable, DiffCache, TokenBucket};
use plaine_stratum::limits::{Caps, Mode};
use plaine_stratum::metrics::Metrics;
use plaine_stratum::mock::{InlineVerifier, MockJobSource, MockPow};
use plaine_stratum::nonce::{nonce_to_hex, E1Allocator};
use plaine_stratum::session::{Action, ServerConfig, Session, Shared};
use plaine_stratum::target::Target;
use plaine_stratum::verify::{ResultSink, ShareVerifier, VerifyResult};

use plaine_consensus::bech32m;
use plaine_consensus::constants::ADDRESS_HRP;

struct Harness {
    sh: Arc<Shared>,
    alloc: Arc<Mutex<E1Allocator>>,

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
    let alloc = Arc::new(Mutex::new(E1Allocator::new()));
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
        verifier,
        metrics: Metrics::default(),
        caps,
        cfg: ServerConfig::for_mode(mode),
    });
    Harness { sh, src, results, alloc }
}

fn session(h: &Harness, ip: u8, now: u64) -> Session {
    Session::new(1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)), now, &h.sh)
}

fn feed(s: &mut Session, h: &Harness, line: &str, now: u64) -> String {
    s.outbuf.clear();
    s.on_line(line.as_bytes(), now, &h.sh);

    let actions = s.take_actions();
    for a in actions {
        match a {
            Action::Verify(w) => {
                let rid = w.request_id;
                if !ShareVerifier::enqueue(h.sh.verifier.as_ref(), *w) {
                    s.on_verify_refused(rid, &h.sh);
                }
            }
            other => s.actions.push(other),
        }
    }
    let results: Vec<VerifyResult> = std::mem::take(&mut *h.results.lock().unwrap());
    for r in results {
        s.on_verify_result(r, now, &h.sh);
    }
    String::from_utf8(std::mem::take(&mut s.outbuf)).unwrap()
}

fn closed(s: &Session) -> bool {
    s.actions.iter().any(|a| matches!(a, Action::Close(_)))
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

fn notify_job_id(wire: &str) -> Option<u32> {
    let anchor = "\"mining.notify\",\"params\":[\"";
    let start = wire.find(anchor)? + anchor.len();
    let hex = &wire[start..start + 8];
    u32::from_str_radix(hex, 16).ok()
}

#[test]
fn malformed_frame_is_error_30_disconnect() {
    let h = harness(Mode::Pool, 1_000_000);
    let mut s = session(&h, 1, 0);
    let _ = subscribe_and_authorize(&mut s, &h, 1, 0);

    let out = feed(
        &mut s,
        &h,
        &format!(
            r#"{{"id":7,"method":"mining.submit","params":["{}","probe","00"]}}"#,
            addr(1)
        ),
        1_000,
    );

    assert!(
        out.contains("\"error\":[30"),
        "probe should be a malformed-frame error 30, got: {out}"
    );
    assert!(!out.contains("\"error\":[23"), "it can never be the 23 it is judged on");
    assert!(!out.contains("\"error\":[20"), "the comment's claimed 20 is wrong");
    assert!(!out.contains("\"error\":[25"), "the comment's claimed 25 is wrong");
    assert!(
        closed(&s),
        "a bad frame from an authorized peer DISCONNECTS the probe every round"
    );

    let score = h.sh.bans.lock().unwrap().score(s.ip, 1_000);
    assert_eq!(score, 50, "the probe pays +50 hard banscore per round");
}

#[test]
fn three_bad_frame_rounds_ban_source() {
    let h = harness(Mode::Pool, 1_000_000);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

    let round_ms: u64 = 120_000;

    let mut scores = Vec::new();
    let mut banned_at = None;
    for round in 0..3u64 {
        let now = round * round_ms;

        let mut s = Session::new(round + 1, ip, now, &h.sh);
        let _ = feed(&mut s, &h, r#"{"id":1,"method":"mining.subscribe","params":["wt"]}"#, now);
        let _ = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":2,"method":"mining.authorize","params":["{}.wt+8192","x"]}}"#,
                addr(9)
            ),
            now,
        );

        let out = feed(
            &mut s,
            &h,
            &format!(
                r#"{{"id":7,"method":"mining.submit","params":["{}","probe","00"]}}"#,
                addr(9)
            ),
            now,
        );
        assert!(out.contains("\"error\":[30"), "round {round}: {out}");

        let mut bans = h.sh.bans.lock().unwrap();
        let score = bans.score(ip, now);
        scores.push(score);
        if bans.is_banned(ip, now) && banned_at.is_none() {
            banned_at = Some(round);
        }
        println!(
            "round {round} at t={:>3}s  score={score:<4} banned={}",
            now / 1000,
            bans.is_banned(ip, now)
        );
    }

    assert_eq!(scores[0], 50, "one probe is +50 hard: {scores:?}");
    assert_eq!(scores[1], 80, "50 - 20 decayed + 50: {scores:?}");
    assert_eq!(
        banned_at,
        Some(2),
        "the third probe must cross BAN_THRESHOLD (100): scores {scores:?}"
    );

    let mut bans = h.sh.bans.lock().unwrap();
    assert!(
        bans.is_banned(ip, 2 * round_ms + 599_000),
        "the first ban is ten minutes, far longer than the 120 s probe interval"
    );
    assert_eq!(bans.bans_issued, 1);
}

#[test]
fn well_formed_low_share_is_error_23() {
    let h = harness(Mode::Pool, 1_000_000);
    let mut s = session(&h, 2, 0);
    feed(&mut s, &h, r#"{"id":1,"method":"mining.subscribe","params":["wt"]}"#, 0);

    let auth = feed(
        &mut s,
        &h,
        &format!(
            r#"{{"id":2,"method":"mining.authorize","params":["{}.wt+1000000","x"]}}"#,
            addr(2)
        ),
        0,
    );
    let e1 = s.e1().expect("subscribed, so a slice is assigned");
    let jid = notify_job_id(&auth).expect("a live job was pushed");

    let nonce = e1.compose(1);
    let out = feed(
        &mut s,
        &h,
        &format!(
            r#"{{"id":7,"method":"mining.submit","params":["{}","{:08x}","{}"]}}"#,
            addr(2),
            jid,
            nonce_to_hex(nonce)
        ),
        1_000,
    );
    assert!(
        out.contains("\"error\":[23"),
        "a well-formed in-slice sub-target share is the judged error 23: {out}"
    );
    assert_eq!(
        h.sh.bans.lock().unwrap().score(s.ip, 1_000),
        10,
        "error 23 is +10 hard; the probe must budget for it, not +50"
    );
    assert!(!closed(&s), "a low-difficulty share does not disconnect");
}

#[test]
fn foreign_slice_refused_slices_unique() {
    let h = harness(Mode::Pool, 1_000_000);
    let mut a = session(&h, 3, 0);
    let mut b = Session::new(2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), 0, &h.sh);
    let _ = subscribe_and_authorize(&mut a, &h, 3, 0);
    let bwire = subscribe_and_authorize(&mut b, &h, 4, 0);

    let ea = a.e1().unwrap();
    let eb = b.e1().unwrap();
    assert_ne!(ea, eb, "two live connections must never share a slice");

    let jid = notify_job_id(&bwire).unwrap();
    let stolen = ea.compose(7);
    assert!(!eb.owns(stolen));
    let out = feed(
        &mut b,
        &h,
        &format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
            jid,
            nonce_to_hex(stolen)
        ),
        100,
    );
    assert!(out.contains("\"error\":[25"), "a sniffed foreign-slice share must be 25: {out}");
    assert_eq!(Metrics::get(&h.sh.metrics.shares_verified), 0);
}

#[test]
fn reconnect_cannot_keep_old_slice() {
    let h = harness(Mode::Pool, 1_000_000);
    let mut s = session(&h, 5, 0);
    let _ = subscribe_and_authorize(&mut s, &h, 5, 0);
    let old = s.e1().unwrap();
    s.release(1_000, &h.sh);
    assert_eq!(h.alloc.lock().unwrap().live(), 0, "slice freed on close");

    let mut s2 = session(&h, 5, 2_000);
    let s2wire = subscribe_and_authorize(&mut s2, &h, 5, 2_000);
    let new = s2.e1().unwrap();
    assert_ne!(old, new, "monotonic-with-skip allocator does not immediately reuse");

    let jid = notify_job_id(&s2wire).unwrap();
    let stale = old.compose(3);
    assert!(!new.owns(stale));
    let out = feed(
        &mut s2,
        &h,
        &format!(
            r#"{{"id":7,"method":"mining.submit","params":["w","{:08x}","{}"]}}"#,
            jid,
            nonce_to_hex(stale)
        ),
        2_100,
    );
    assert!(out.contains("\"error\":[25"), "old-slice share after reconnect must be 25: {out}");
}
