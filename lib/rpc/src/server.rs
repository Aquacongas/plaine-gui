use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::http::{
    self, AuthPolicy, HeadProgress, HeadVerdict, HttpContext, HttpFail, HttpLimits, HttpResponse,
};
use crate::json::{self, Json, JsonLimits};
use crate::jsonrpc::{self, ErrorCode, RpcError, MAX_BATCH};
use crate::methods;
use crate::views::Node;

#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub bind: SocketAddr,
    pub token: Option<String>,
    pub http: HttpLimits,
    pub json: JsonLimits,
    pub max_connections: usize,
    pub read_timeout: Duration,
    pub idle_timeout: Duration,
}

impl RpcConfig {
    pub fn loopback(port: u16) -> RpcConfig {
        RpcConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], port)),
            token: None,
            http: HttpLimits::default(),
            json: JsonLimits::request(),
            max_connections: 128,
            read_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub enum BindError {
    PublicWithoutToken { addr: SocketAddr },
    TokenTooShort { len: usize, min: usize },
    Io(std::io::Error),
}

// a public listener needs a token this long; shorter gets guessed
pub const MIN_TOKEN_LEN: usize = 32;

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BindError::PublicWithoutToken { addr } => write!(
                f,
                "rpc.listen = \"{addr}\" is not a loopback address and rpc.token is empty.\n\
                 \n\
                 An RPC port reachable from the network with no authentication lets anyone who \n\
                 can route a packet to it read every address balance this node knows and submit \n\
                 transactions through it. The node will not start this way.\n\
                 \n\
                 Pick one:\n\
                 \n\
                   1. Keep it local (recommended). In noded.toml:\n\
                 \n\
                         [rpc]\n\
                         listen = \"127.0.0.1:{port}\"\n\
                 \n\
                     and reach it from another machine over an SSH tunnel:\n\
                     ssh -L {port}:127.0.0.1:{port} user@host\n\
                 \n\
                  2. Expose it deliberately, with a token:\n\
                 \n\
                         [rpc]\n\
                         listen = \"{addr}\"\n\
                         token  = \"<at least {MIN_TOKEN_LEN} random characters>\"\n\
                 \n\
                     Clients then send `Authorization: Bearer <token>`. There is no TLS in the\n\
                     node: put a reverse proxy in front of it, or the token\n\
                     travels in clear text.",
                port = addr.port()
            ),
            BindError::TokenTooShort { len, min } => write!(
                f,
                "rpc.token is {len} characters; the minimum is {min}. A short token on a public \
                 interface gets guessed. Generate one you did not choose yourself."
            ),
            BindError::Io(e) => write!(f, "could not bind the RPC listener: {e}"),
        }
    }
}

impl std::error::Error for BindError {}

pub fn is_loopback(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

pub fn check_bind_policy(cfg: &RpcConfig) -> Result<(), BindError> {
    match (&cfg.token, is_loopback(&cfg.bind)) {
        (None, false) => Err(BindError::PublicWithoutToken { addr: cfg.bind }),
        (Some(t), false) if t.chars().count() < MIN_TOKEN_LEN => Err(BindError::TokenTooShort {
            len: t.chars().count(),
            min: MIN_TOKEN_LEN,
        }),
        _ => Ok(()),
    }
}

pub fn handle_body(node: &Node, body: &[u8], limits: JsonLimits) -> Option<Vec<u8>> {
    let value = match json::parse(body, limits) {
        Ok(v) => v,
        Err(e) => {
            let err = jsonrpc::error_from_json(&e);
            return Some(jsonrpc::failure(Json::Null, &err).to_string().into_bytes());
        }
    };
    match &value {
        Json::Arr(items) => {
            if items.is_empty() {
                let err =
                    RpcError::detail(ErrorCode::InvalidRequest, "an empty batch is not a request");
                return Some(jsonrpc::failure(Json::Null, &err).to_string().into_bytes());
            }
            if items.len() > MAX_BATCH {
                let err = RpcError::detail(
                    ErrorCode::LimitExceeded,
                    format!(
                        "batch of {} requests, the limit is {MAX_BATCH}",
                        items.len()
                    ),
                );
                return Some(jsonrpc::failure(Json::Null, &err).to_string().into_bytes());
            }
            let mut out: Vec<Json> = Vec::new();
            for item in items {
                if let Some(resp) = handle_one(node, item) {
                    out.push(resp);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(Json::Arr(out).to_string().into_bytes())
            }
        }
        _ => handle_one(node, &value).map(|r| r.to_string().into_bytes()),
    }
}

fn handle_one(node: &Node, value: &Json) -> Option<Json> {
    let req = match jsonrpc::parse_request(value) {
        Ok(r) => r,
        Err(e) => {
            let id = value.get("id").cloned().unwrap_or(Json::Null);
            return Some(jsonrpc::failure(id, &e));
        }
    };
    let result = methods::dispatch(node, &req);
    let id = req.id?;
    Some(match result {
        Ok(v) => jsonrpc::success(&id, v),
        Err(e) => jsonrpc::failure(id, &e),
    })
}

#[derive(Clone, Default)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    pub fn new() -> Shutdown {
        Shutdown(Arc::new(AtomicBool::new(false)))
    }

    pub fn trigger(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_triggered(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub struct RpcMetrics {
    pub in_flight: AtomicUsize,
    pub rejected_busy: AtomicU64,
    pub served: AtomicU64,
}

pub struct RpcServer {
    listener: TcpListener,
    cfg: RpcConfig,
    node: Arc<Node>,
    metrics: Arc<RpcMetrics>,
    shutdown: Shutdown,
}

impl RpcServer {
    pub fn bind(cfg: RpcConfig, node: Node, shutdown: Shutdown) -> Result<RpcServer, BindError> {
        check_bind_policy(&cfg)?;
        let listener = TcpListener::bind(cfg.bind).map_err(BindError::Io)?;
        listener.set_nonblocking(true).map_err(BindError::Io)?;
        Ok(RpcServer {
            listener,
            cfg,
            node: Arc::new(node),
            metrics: Arc::new(RpcMetrics::default()),
            shutdown,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn metrics(&self) -> Arc<RpcMetrics> {
        self.metrics.clone()
    }

    pub fn serve(&self) {
        let ctx = HttpContext {
            limits: self.cfg.http,
            auth: match &self.cfg.token {
                Some(t) => AuthPolicy::BearerToken(t.clone()),
                None => AuthPolicy::LoopbackNoToken,
            },
            loopback: is_loopback(&self.cfg.bind),
            port: self
                .local_addr()
                .map(|a| a.port())
                .unwrap_or(self.cfg.bind.port()),
        };
        while !self.shutdown.is_triggered() {
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    // a freshly accepted socket can inherit the listener's non-blocking flag
                    // (Windows); clear it or the read timeouts below do nothing.
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    let in_flight = self.metrics.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    if in_flight > self.cfg.max_connections {
                        self.metrics.in_flight.fetch_sub(1, Ordering::SeqCst);
                        self.metrics.rejected_busy.fetch_add(1, Ordering::SeqCst);
                        refuse_busy(stream, self.cfg.max_connections);
                        continue;
                    }
                    let node = self.node.clone();
                    let cfg = self.cfg.clone();
                    let ctx = ctx.clone();
                    let metrics = self.metrics.clone();
                    let shutdown = self.shutdown.clone();

                    if std::thread::Builder::new()
                        .name("plaine-rpc-conn".into())
                        .stack_size(256 * 1024)
                        .spawn(move || {
                            // Drop guard so a panicking handler still returns its slot on unwind.
                            let _slot = InFlightGuard(metrics.clone());
                            serve_connection(stream, &node, &cfg, &ctx, &metrics, &shutdown);
                        })
                        .is_err()
                    {
                        self.metrics.in_flight.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

struct InFlightGuard(Arc<RpcMetrics>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

enum ReadOutcome {
    Bytes(usize),
    Eof,
    TimedOut,
    Broken,
}

fn read_once(stream: &mut TcpStream, chunk: &mut [u8]) -> ReadOutcome {
    loop {
        match stream.read(chunk) {
            Ok(0) => return ReadOutcome::Eof,
            Ok(n) => return ReadOutcome::Bytes(n),
            Err(e) => match e.kind() {
                ErrorKind::Interrupted => continue,

                // a timeout, not a hangup - a stalled body can then answer 408 rather than vanish
                ErrorKind::WouldBlock | ErrorKind::TimedOut => return ReadOutcome::TimedOut,
                _ => return ReadOutcome::Broken,
            },
        }
    }
}

fn timeout_fail(budget: Duration) -> HttpFail {
    HttpFail {
        status: 408,
        detail: format!(
            "the whole request must arrive within {} ms of its first byte; that budget expired \
             with the request incomplete. Send the request, then read the response.",
            budget.as_millis()
        ),
        extra_headers: Vec::new(),
    }
}

fn arm_read(stream: &TcpStream, deadline: Option<Instant>, cfg: &RpcConfig) -> bool {
    let window = match deadline {
        None => cfg.idle_timeout,
        Some(d) => {
            let left = d.saturating_duration_since(Instant::now());

            if left.is_zero() {
                return false;
            }
            left.min(cfg.read_timeout)
        }
    };
    let _ = stream.set_read_timeout(Some(window));
    true
}

fn refuse_busy(mut stream: TcpStream, cap: usize) {
    let fail = HttpFail {
        status: 503,
        detail: format!("the RPC concurrency budget of {cap} requests is full; retry"),
        extra_headers: vec![("Retry-After".into(), "1".into())],
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = stream.write_all(&HttpResponse::from_fail(&fail).to_bytes());
}

fn serve_connection(
    mut stream: TcpStream,
    node: &Node,
    cfg: &RpcConfig,
    ctx: &HttpContext,
    metrics: &RpcMetrics,
    shutdown: &Shutdown,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(cfg.read_timeout));
    let mut requests = 0u32;
    let mut buf: Vec<u8> = Vec::with_capacity(2048);

    loop {
        if shutdown.is_triggered() || requests >= cfg.http.max_requests_per_conn {
            return;
        }

        // one deadline for the whole request, not per read(): SO_RCVTIMEO resets on every byte,
        // so a slow drip would hold the connection open forever.
        let mut deadline: Option<Instant> =
            (!buf.is_empty()).then(|| Instant::now() + cfg.read_timeout);

        let head = match read_head_bounded(&mut stream, &mut buf, cfg, shutdown, &mut deadline) {
            Ok(Some(h)) => h,
            Ok(None) => return,
            Err(fail) => {
                let _ = stream.write_all(&HttpResponse::from_fail(&fail).to_bytes());
                return;
            }
        };

        let (content_length, keep_alive) = match http::validate_head(&head, ctx) {
            HeadVerdict::Accept {
                content_length,
                keep_alive,
            } => (content_length, keep_alive),
            HeadVerdict::Refuse(fail) => {
                let _ = stream.write_all(&HttpResponse::from_fail(&fail).to_bytes());
                return;
            }
        };

        buf.drain(..head.head_len);
        while buf.len() < content_length {
            if !arm_read(&stream, deadline, cfg) {
                let fail = timeout_fail(cfg.read_timeout);
                let _ = stream.write_all(&HttpResponse::from_fail(&fail).to_bytes());
                return;
            }
            let mut chunk = [0u8; 8192];
            match read_once(&mut stream, &mut chunk) {
                ReadOutcome::Bytes(n) => buf.extend_from_slice(&chunk[..n]),
                ReadOutcome::Eof | ReadOutcome::Broken => return,

                ReadOutcome::TimedOut => {
                    let fail = timeout_fail(cfg.read_timeout);
                    let _ = stream.write_all(&HttpResponse::from_fail(&fail).to_bytes());
                    return;
                }
            }
        }
        let body: Vec<u8> = buf.drain(..content_length).collect();

        metrics.served.fetch_add(1, Ordering::Relaxed);
        let response = match handle_body(node, &body, cfg.json) {
            Some(bytes) => HttpResponse::ok_json(bytes, keep_alive),
            None => HttpResponse::no_content(keep_alive),
        };
        if stream.write_all(&response.to_bytes()).is_err() {
            return;
        }
        requests += 1;
        if !keep_alive {
            return;
        }
    }
}

fn read_head_bounded(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    cfg: &RpcConfig,
    shutdown: &Shutdown,
    deadline: &mut Option<Instant>,
) -> Result<Option<http::RequestHead>, HttpFail> {
    loop {
        match http::read_head(buf, cfg.http) {
            HeadProgress::Done(h) => return Ok(Some(h)),
            HeadProgress::Fail(f) => return Err(f),
            HeadProgress::NeedMore => {}
        }
        if shutdown.is_triggered() {
            return Ok(None);
        }
        if !arm_read(stream, *deadline, cfg) {
            return Err(timeout_fail(cfg.read_timeout));
        }
        let mut chunk = [0u8; 2048];
        match read_once(stream, &mut chunk) {
            ReadOutcome::Bytes(n) => {
                buf.extend_from_slice(&chunk[..n]);

                if deadline.is_none() {
                    *deadline = Some(Instant::now() + cfg.read_timeout);
                }
            }
            ReadOutcome::Eof | ReadOutcome::Broken => return Ok(None),
            ReadOutcome::TimedOut => {
                return if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(timeout_fail(cfg.read_timeout))
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockNode;

    fn body(s: &str) -> Option<String> {
        let node = MockNode::synced().with_notes().into_node();
        handle_body(&node, s.as_bytes(), JsonLimits::request())
            .map(|b| String::from_utf8(b).expect("utf8"))
    }

    #[test]
    fn normal_call_round_trips() {
        let out = body(r#"{"jsonrpc":"2.0","method":"chain_getInfo","id":1}"#).unwrap();
        assert!(out.contains(r#""jsonrpc":"2.0""#));
        assert!(out.contains(r#""sync":"synced""#));
        assert!(out.ends_with(r#""id":1}"#));
    }

    #[test]
    fn notification_produces_no_body() {
        assert!(body(r#"{"jsonrpc":"2.0","method":"chain_getInfo"}"#).is_none());
        assert!(body(
            r#"[{"jsonrpc":"2.0","method":"chain_getInfo"},{"jsonrpc":"2.0","method":"fee_suggest"}]"#
        )
        .is_none());
    }

    #[test]
    fn batch_answers_only_ids() {
        let out = body(
            r#"[{"jsonrpc":"2.0","method":"chain_getInfo","id":1},
                {"jsonrpc":"2.0","method":"fee_suggest"},
                {"jsonrpc":"2.0","method":"mempool_getInfo","id":"b"}]"#,
        )
        .unwrap();
        assert!(out.starts_with('['));
        assert_eq!(out.matches(r#""jsonrpc":"2.0""#).count(), 2);
        assert!(out.contains(r#""id":"b""#));
    }

    #[test]
    fn oversized_batch_is_limit_error() {
        let one = r#"{"jsonrpc":"2.0","method":"chain_getInfo","id":1}"#;
        let big = format!("[{}]", vec![one; MAX_BATCH + 1].join(","));
        let out = body(&big).unwrap();
        assert!(out.contains("-32005"), "{out}");
        assert!(out.contains(&format!("the limit is {MAX_BATCH}")));
    }

    #[test]
    fn empty_batch_is_invalid_request() {
        let out = body("[]").expect("an empty batch must produce a response");
        assert!(out.contains("-32600"), "{out}");
        assert!(out.contains(r#""id":null"#), "{out}");
    }

    #[test]
    fn garbage_is_parse_error_null_id() {
        let out = body("not json at all").unwrap();
        assert!(out.contains("-32700"));
        assert!(out.contains(r#""id":null"#));
    }

    #[test]
    fn one_bad_member_does_not_poison_batch() {
        let out = body(
            r#"[{"jsonrpc":"2.0","method":"chain_getInfo","id":1},
                {"jsonrpc":"2.0","method":"nope","id":2}]"#,
        )
        .unwrap();
        assert!(out.contains(r#""result""#));
        assert!(out.contains("-32601"));
    }

    #[test]
    fn bind_refuses_public_without_token() {
        let mut cfg = RpcConfig::loopback(9257);
        cfg.bind = "0.0.0.0:9257".parse().expect("addr");
        let e = check_bind_policy(&cfg).unwrap_err();
        let msg = e.to_string();

        assert!(msg.contains("ssh -L"), "{msg}");
        assert!(msg.contains("[rpc]"));
        assert!(msg.contains("token"));

        cfg.token = Some("short".into());
        assert!(matches!(
            check_bind_policy(&cfg),
            Err(BindError::TokenTooShort { .. })
        ));
        cfg.token = Some("x".repeat(MIN_TOKEN_LEN));
        assert!(check_bind_policy(&cfg).is_ok());
    }

    #[test]
    fn loopback_needs_no_token() {
        assert!(check_bind_policy(&RpcConfig::loopback(9257)).is_ok());
        let mut cfg = RpcConfig::loopback(9257);
        cfg.bind = "[::1]:9257".parse().expect("addr");
        assert!(check_bind_policy(&cfg).is_ok());
    }

    #[test]
    fn end_to_end_over_a_socket() {
        let mut cfg = RpcConfig::loopback(0);
        cfg.bind = "127.0.0.1:0".parse().expect("addr");
        let shutdown = Shutdown::new();
        let server = RpcServer::bind(
            cfg,
            MockNode::synced().with_notes().into_node(),
            shutdown.clone(),
        )
        .expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            server.serve();
            server
        });

        let payload = r#"{"jsonrpc":"2.0","method":"author_getNotes","id":1}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            addr.port(),
            payload.len(),
        );

        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        sock.write_all(request.as_bytes()).expect("write");
        let mut response = String::new();
        sock.read_to_string(&mut response).expect("read");

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("Content-Type: application/json"));
        assert!(response.contains("X-Content-Type-Options: nosniff"));
        assert!(!response.to_ascii_lowercase().contains("access-control"));
        assert!(
            response.contains("Isochron v2"),
            "notes must be served: {response}"
        );

        shutdown.trigger();
        let server = handle.join().expect("join");
        assert!(server.metrics().served.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn checkpoint_status_on_wire_claims_no_protection() {
        let mut cfg = RpcConfig::loopback(0);
        cfg.bind = "127.0.0.1:0".parse().expect("addr");
        let shutdown = Shutdown::new();

        let node = MockNode::synced()
            .with_checkpoint_ingest_severed()
            .into_node();
        let server = RpcServer::bind(cfg, node, shutdown.clone()).expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || server.serve());

        let payload = r#"{"jsonrpc":"2.0","method":"checkpoint_getStatus","id":1}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            addr.port(),
            payload.len(),
        );
        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        sock.write_all(request.as_bytes()).expect("write");
        let mut response = String::new();
        sock.read_to_string(&mut response).expect("read");
        shutdown.trigger();
        handle.join().expect("join");

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.contains(r#""enabled":false"#),
            "a node that cannot receive a checkpoint reported protection on the wire: {response}"
        );
        assert!(response.contains(r#""configured":true"#), "{response}");
        assert!(response.contains(r#""ingest":"severed""#), "{response}");
        assert!(response.contains(r#""lastAnchor":null"#), "{response}");
        assert!(response.contains(r#""enforcedCount":0"#), "{response}");
        assert!(response.contains("cannot receive one"), "{response}");

        assert!(response.contains("not in use"), "{response}");
    }

    #[test]
    fn get_over_socket_is_405() {
        let mut cfg = RpcConfig::loopback(0);
        cfg.bind = "127.0.0.1:0".parse().expect("addr");
        let shutdown = Shutdown::new();
        let server =
            RpcServer::bind(cfg, MockNode::synced().into_node(), shutdown.clone()).expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || server.serve());

        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        sock.write_all(
            format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", addr.port()).as_bytes(),
        )
        .expect("write");
        let mut response = String::new();
        sock.read_to_string(&mut response).expect("read");
        assert!(response.starts_with("HTTP/1.1 405"), "{response}");
        assert!(response.contains("Allow: POST"));

        shutdown.trigger();
        handle.join().expect("join");
    }
}
