use plaine_pow_mine::client::{self, Args, Ended, Ladder, Report};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

fn alone() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

const D: u64 = 6_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    Mute,
    AnswerKeepalive,
    Error29ToKeepalive,
    Chatty,
}

struct Fake {
    port: u16,
    keepalives: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn prefix_hex() -> String {
    let mut p = [0u8; 124];
    p[0] = 1;
    p.iter().map(|b| format!("{b:02x}")).collect()
}

fn fake_server(after: After) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let keepalives = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (k, s) = (Arc::clone(&keepalives), Arc::clone(&stop));

    std::thread::spawn(move || {
        let (sock, _) = match l.accept() {
            Ok(v) => v,
            Err(_) => return,
        };
        sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let mut w: TcpStream = sock.try_clone().expect("clone");
        let mut r = BufReader::new(sock);
        let mut line = String::new();
        let mut seated = false;
        let target_hex = format!("{}01", "00".repeat(31));
        while !s.load(Ordering::SeqCst) {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) => return,
                Ok(_) => {}

                Err(_) => {
                    if after == After::Chatty && seated {
                        let _ = writeln!(
                            w,
                            "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"00000001\",7,\"{}\",false]}}",
                            prefix_hex()
                        );
                    }
                    continue;
                }
            }
            let id = line
                .split("\"id\":")
                .nth(1)
                .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).find(|x| !x.is_empty()))
                .and_then(|d| d.parse::<u64>().ok())
                .unwrap_or(0);
            if line.contains("mining.subscribe") {
                let _ = writeln!(
                    w,
                    "{{\"id\":{id},\"result\":[[\"mining.notify\",\"mining.set_target\"],\"00a3f2\",5],\"error\":null}}"
                );
            } else if line.contains("mining.authorize") {
                let _ = writeln!(w, "{{\"id\":{id},\"result\":true,\"error\":null}}");
                let _ = writeln!(
                    w,
                    "{{\"id\":null,\"method\":\"mining.set_target\",\"params\":[\"{target_hex}\"]}}"
                );
                let _ = writeln!(
                    w,
                    "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"00000001\",7,\"{}\",true]}}",
                    prefix_hex()
                );
                seated = true;
            } else if line.contains("mining.keepalive") {
                k.fetch_add(1, Ordering::SeqCst);
                match after {
                    After::Mute => {}
                    After::AnswerKeepalive => {
                        let _ = writeln!(w, "{{\"id\":{id},\"result\":true,\"error\":null}}");
                    }
                    After::Chatty => {
                        let _ = writeln!(w, "{{\"id\":{id},\"result\":true,\"error\":null}}");
                    }
                    After::Error29ToKeepalive => {
                        let _ = writeln!(
                            w,
                            "{{\"id\":{id},\"result\":null,\"error\":[29,\"unknown method\",null]}}"
                        );
                    }
                }
            }
        }
    });

    Fake { port, keepalives, stop }
}

fn args_for(port: u16, silence_ms: u64) -> Args {
    Args {
        stratum: format!("127.0.0.1:{port}"),
        login: "plne1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq.rig1".into(),
        threads: 1,
        status_secs: 0,
        silence_deadline_ms: silence_ms,
        ..Args::default()
    }
}

fn session_within(args: Args, cap: Duration) -> Option<(Ended, Duration)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let start = Instant::now();
        let mut totals = Report::default();
        let out = client::session(&args, start, &mut totals);
        let _ = tx.send((out, start.elapsed()));
    });
    match rx.recv_timeout(cap) {
        Ok((Ok(e), took)) => Some((e, took)),
        Ok((Err(e), took)) => panic!("session failed with an io error after {took:?}: {e}"),
        Err(_) => None,
    }
}

#[test]
fn silent_server_ends_session() {
    let _alone = alone();
    let f = fake_server(After::Mute);

    let r = session_within(args_for(f.port, D), Duration::from_secs(60));

    let (ended, took) = r.expect(
        "the miner never returned: it is still hashing against a server that has said nothing \
         since it seated it. This is the defect - see the module header.",
    );
    match ended {
        Ended::Retry(Ladder::Connection, why) => {
            assert!(
                why.contains("silent"),
                "the reason must name the silence, so an operator reading one line knows what \
                 happened: {why:?}"
            );
        }
        other => panic!("wrong end: {other:?}"),
    }

    assert!(
        took >= Duration::from_millis(D),
        "gave up after {took:?}, before the deadline it was given"
    );
    assert!(took < Duration::from_millis(D * 4), "took {took:?} to notice");
    assert!(
        f.keepalives.load(Ordering::SeqCst) >= 1,
        "the miner gave up without ever asking: a probe is what separates a server that is \
         gone from a server that merely has no work"
    );
}

#[test]
fn pulse_without_work_stays_up() {
    let _alone = alone();

    let f = fake_server(After::AnswerKeepalive);
    let r = session_within(args_for(f.port, D), Duration::from_millis(D * 3));
    let n = f.keepalives.load(Ordering::SeqCst);
    assert!(
        r.is_none(),
        "the miner hung up on a server that was answering it: {r:?}. That is a reconnect \
         storm against a node that is merely syncing."
    );
    assert!(
        n >= 3,
        "only {n} probes in {}s at a {}s deadline; the probe timer is not running",
        D * 3 / 1000,
        D / 1000
    );
}

#[test]
fn probe_refusal_counts_as_pulse() {
    let _alone = alone();

    let f = fake_server(After::Error29ToKeepalive);
    let r = session_within(args_for(f.port, D), Duration::from_millis(D * 3));
    assert!(r.is_none(), "an error 29 is a line, and a line is proof of life: {r:?}");
}

#[test]
fn idle_miner_keeps_read_deadline_fed() {
    let _alone = alone();

    let f = fake_server(After::Chatty);
    let r = session_within(args_for(f.port, D), Duration::from_millis(D * 3));
    let n = f.keepalives.load(Ordering::SeqCst);
    assert!(r.is_none(), "the miner ended a session with a server that never stopped talking: {r:?}");
    assert!(
        n >= 2,
        "{n} keepalives in {}s at a {}s probe interval: an idle rig is not feeding the read deadline",
        D * 3 / 1000,
        D / 3000
    );
}
