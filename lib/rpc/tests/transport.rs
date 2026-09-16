use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use plaine_rpc::mock::MockNode;
use plaine_rpc::server::{RpcConfig, RpcServer, Shutdown};

struct Harness {
    addr: SocketAddr,
    shutdown: Shutdown,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn start(cfg: RpcConfig) -> Harness {
        let shutdown = Shutdown::new();
        let server =
            RpcServer::bind(cfg, MockNode::synced().with_notes().into_node(), shutdown.clone())
                .expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || server.serve());
        Harness { addr, shutdown, handle: Some(handle) }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.trigger();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn base_cfg() -> RpcConfig {
    let mut cfg = RpcConfig::loopback(0);
    cfg.bind = "127.0.0.1:0".parse().expect("addr");
    cfg
}

fn head_for(addr: &SocketAddr, len: usize, keep_alive: bool) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\n\
         Connection: {}\r\nContent-Length: {len}\r\n\r\n",
        addr.port(),
        if keep_alive { "keep-alive" } else { "close" },
    )
}

fn read_all(sock: &mut TcpStream) -> String {
    sock.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn brief_pause_before_request_still_answered() {
    let mut cfg = base_cfg();
    cfg.read_timeout = Duration::from_secs(10);
    cfg.idle_timeout = Duration::from_secs(30);
    let h = Harness::start(cfg);

    let payload = r#"{"jsonrpc":"2.0","method":"chain_getInfo","id":1}"#;
    let request = format!("{}{payload}", head_for(&h.addr, payload.len(), false));

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");

    std::thread::sleep(Duration::from_millis(300));
    let _ = sock.write_all(request.as_bytes());

    let response = read_all(&mut sock);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "a 300 ms pause before the request was treated as a hangup. \
         idle_timeout was 30 s and the server answered: {response:?}"
    );
}

#[test]
fn accepted_socket_is_blocking() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let _client = TcpStream::connect(addr).expect("connect");

    let mut stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    };

    stream.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    let started = Instant::now();
    let mut buf = [0u8; 64];
    let inherited = matches!(stream.read(&mut buf), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock)
        && started.elapsed() < Duration::from_millis(100);
    println!(
        "accepted socket inherited the listener's non-blocking flag: {inherited} \
         (true on Windows, false on Linux)"
    );

    stream.set_nonblocking(false).expect("clear the inherited flag");
    stream.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");

    let started = Instant::now();
    let r = stream.read(&mut buf);
    let waited = started.elapsed();

    assert!(
        waited >= Duration::from_millis(1_500),
        "read() returned after {waited:?} with {r:?} despite a 2 s SO_RCVTIMEO set after \
         set_nonblocking(false) - the socket is still non-blocking, so the read timeouts are dead"
    );
}

#[test]
fn segmented_body_still_answered() {
    let h = Harness::start(base_cfg());

    let raw_hex = "ab".repeat(4_096);
    let payload = format!(r#"{{"jsonrpc":"2.0","method":"tx_sendRaw","params":["{raw_hex}"],"id":1}}"#);
    let head = head_for(&h.addr, payload.len(), false);

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");
    sock.write_all(head.as_bytes()).expect("head");

    let bytes = payload.as_bytes();
    for chunk in bytes.chunks(1_400) {
        let _ = sock.write_all(chunk);
        std::thread::sleep(Duration::from_millis(3));
    }

    let response = read_all(&mut sock);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a segmented tx_sendRaw body was dropped mid-body with no reply: {response:?}"
    );
}

#[test]
fn keep_alive_survives_second_request() {
    let h = Harness::start(base_cfg());

    let payload = r#"{"jsonrpc":"2.0","method":"fee_suggest","id":1}"#;
    let request = format!("{}{payload}", head_for(&h.addr, payload.len(), true));

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");
    sock.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    sock.write_all(request.as_bytes()).expect("first request");

    let mut buf = [0u8; 8192];
    let n = sock.read(&mut buf).expect("first response");
    let first = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(first.starts_with("HTTP/1.1 200"), "first request failed: {first}");
    assert!(first.contains("Connection: keep-alive"), "server did not promise keep-alive: {first}");

    std::thread::sleep(Duration::from_millis(300));
    let second = sock.write_all(request.as_bytes()).and_then(|_| {
        let mut b = [0u8; 8192];
        let n = sock.read(&mut b)?;
        Ok(String::from_utf8_lossy(&b[..n]).into_owned())
    });
    let second = second.unwrap_or_else(|e| format!("<socket error: {e}>"));
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "the server advertised Connection: keep-alive and then closed the socket before the \
         second request: {second}"
    );
}

#[test]
fn concurrency_cap_refuses_then_recovers() {
    let mut cfg = base_cfg();
    cfg.max_connections = 2;

    cfg.idle_timeout = Duration::from_secs(5);
    let h = Harness::start(cfg);

    let holders: Vec<TcpStream> =
        (0..2).map(|_| TcpStream::connect(h.addr).expect("connect")).collect();
    std::thread::sleep(Duration::from_millis(300));

    let payload = r#"{"jsonrpc":"2.0","method":"fee_suggest","id":1}"#;
    let request = format!("{}{payload}", head_for(&h.addr, payload.len(), false));

    let mut over = TcpStream::connect(h.addr).expect("connect");
    over.set_nodelay(true).expect("nodelay");
    let _ = over.write_all(request.as_bytes());
    let refused = read_all(&mut over);
    assert!(
        refused.starts_with("HTTP/1.1 503"),
        "the third caller against max_connections = 2 was not refused: {refused:?}"
    );
    assert!(refused.contains("Retry-After: 1"), "503 carried no Retry-After: {refused}");

    drop(holders);
    std::thread::sleep(Duration::from_millis(300));
    let mut ok = TcpStream::connect(h.addr).expect("connect");
    ok.set_nodelay(true).expect("nodelay");
    ok.write_all(request.as_bytes()).expect("write");
    let after = read_all(&mut ok);
    assert!(after.starts_with("HTTP/1.1 200"), "the slots did not come back: {after:?}");
}

#[test]
fn socket_bounded_by_max_requests() {
    let mut cfg = base_cfg();
    cfg.http.max_requests_per_conn = 2;
    let h = Harness::start(cfg);

    let payload = r#"{"jsonrpc":"2.0","method":"fee_suggest","id":1}"#;
    let request = format!("{}{payload}", head_for(&h.addr, payload.len(), true));

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");
    sock.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");

    for i in 1..=2 {
        sock.write_all(request.as_bytes()).unwrap_or_else(|e| panic!("request {i}: {e}"));
        let mut buf = [0u8; 8192];
        let n = sock.read(&mut buf).unwrap_or_else(|e| panic!("response {i}: {e}"));
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"), "request {i} of 2: {text}");
    }

    let third = sock.write_all(request.as_bytes()).and_then(|_| {
        let mut b = [0u8; 8192];
        let n = sock.read(&mut b)?;
        Ok(String::from_utf8_lossy(&b[..n]).into_owned())
    });
    let third = third.unwrap_or_default();
    assert!(
        !third.starts_with("HTTP/1.1 200"),
        "max_requests_per_conn = 2 served a third request on the same socket: {third}"
    );
}

#[test]
fn stalled_body_answered_408() {
    let mut cfg = base_cfg();
    cfg.read_timeout = Duration::from_millis(700);
    let h = Harness::start(cfg);

    let payload = r#"{"jsonrpc":"2.0","method":"fee_suggest","id":1}"#;
    let head = head_for(&h.addr, payload.len(), false);

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");

    sock.write_all(head.as_bytes()).expect("head");
    sock.write_all(&payload.as_bytes()[..10]).expect("half a body");

    let response = read_all(&mut sock);
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "a half-delivered body got {response:?} instead of a 408. `Err(_) => return` cannot tell \
         a read timeout from a hangup, which is why 408 was unreachable"
    );
    assert!(response.contains(r#""status":408"#), "{response}");
}

#[test]
fn stalled_head_answered_408() {
    let mut cfg = base_cfg();
    cfg.read_timeout = Duration::from_millis(700);
    cfg.idle_timeout = Duration::from_secs(5);
    let h = Harness::start(cfg);

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");

    sock.write_all(format!("POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n", h.addr.port()).as_bytes())
        .expect("partial head");

    let response = read_all(&mut sock);
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "a half-delivered HEAD got {response:?} instead of a 408"
    );
}

#[test]
fn slow_drip_hits_read_timeout() {
    let mut cfg = base_cfg();
    cfg.read_timeout = Duration::from_millis(700);
    cfg.idle_timeout = Duration::from_secs(30);
    let h = Harness::start(cfg);

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");
    sock.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    sock.write_all(b"POST / HTTP/1.1\r\n").expect("request line");

    let started = Instant::now();

    let mut wrote = 0;
    for _ in 0..20 {
        if sock.write_all(b"X").is_err() {
            break;
        }
        wrote += 1;
        std::thread::sleep(Duration::from_millis(150));
    }
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(2_000),
        "a one-byte-every-150ms drip held the connection {elapsed:?} ({wrote} bytes in) against a \
         700 ms read_timeout; the whole-request deadline never fired"
    );
    assert!(
        wrote < 20,
        "all 20 drip bytes were accepted over {elapsed:?}; the request budget never fired"
    );
    let response = read_all(&mut sock);
    if !response.is_empty() {
        assert!(response.starts_with("HTTP/1.1 408"), "unexpected answer to a drip: {response:?}");
    }
}

#[test]
fn idle_connection_closed_silently() {
    let mut cfg = base_cfg();
    cfg.idle_timeout = Duration::from_millis(500);
    cfg.read_timeout = Duration::from_secs(10);
    let h = Harness::start(cfg);

    let mut sock = TcpStream::connect(h.addr).expect("connect");
    sock.set_nodelay(true).expect("nodelay");
    let started = Instant::now();
    let response = read_all(&mut sock);
    let waited = started.elapsed();

    assert!(response.is_empty(), "an idle socket was sent {response:?}");
    assert!(
        waited >= Duration::from_millis(300) && waited < Duration::from_secs(3),
        "idle_timeout was 500 ms; the socket closed after {waited:?}. Either the timeout is not \
         applied or it is not the one configured"
    );
}
