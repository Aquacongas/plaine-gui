use crate::json::Json;

#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    pub max_head_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
    pub max_requests_per_conn: u32,
}

impl Default for HttpLimits {
    fn default() -> Self {
        // small caps: this endpoint only ever sees short JSON-RPC POSTs.
        HttpLimits {
            max_head_bytes: 8 * 1024,
            max_headers: 64,
            max_body_bytes: 1024 * 1024,
            max_requests_per_conn: 1_000,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub http11: bool,
    pub headers: Vec<(String, String)>,
    pub head_len: usize,
}

impl RequestHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn header_count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(k, _)| k == name).count()
    }

    pub fn wants_keep_alive(&self) -> bool {
        match self.header("connection") {
            Some(v) if v.eq_ignore_ascii_case("close") => false,
            Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
            _ => self.http11,
        }
    }
}

#[derive(Clone, Debug)]
pub enum HeadProgress {
    NeedMore,
    Done(RequestHead),
    Fail(HttpFail),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpFail {
    pub status: u16,
    pub detail: String,
    pub extra_headers: Vec<(String, String)>,
}

impl HttpFail {
    fn new(status: u16, detail: impl Into<String>) -> Self {
        HttpFail {
            status,
            detail: detail.into(),
            extra_headers: Vec::new(),
        }
    }
}

pub fn read_head(buf: &[u8], limits: HttpLimits) -> HeadProgress {
    let Some(end) = find_head_end(buf) else {
        if buf.len() > limits.max_head_bytes {
            return HeadProgress::Fail(HttpFail::new(
                431,
                format!(
                    "request head exceeds {} bytes with no terminator",
                    limits.max_head_bytes
                ),
            ));
        }
        return HeadProgress::NeedMore;
    };
    if end > limits.max_head_bytes {
        return HeadProgress::Fail(HttpFail::new(
            431,
            format!(
                "request head is {end} bytes, limit is {}",
                limits.max_head_bytes
            ),
        ));
    }
    let head = &buf[..end];

    for (i, b) in head.iter().enumerate() {
        match *b {
            b'\r' => {
                if head.get(i + 1) != Some(&b'\n') {
                    return HeadProgress::Fail(HttpFail::new(
                        400,
                        "a bare CR in the request head; lines are terminated by CRLF",
                    ));
                }
            }
            b'\n' => {
                if i == 0 || head[i - 1] != b'\r' {
                    return HeadProgress::Fail(HttpFail::new(
                        400,
                        "a bare LF in the request head; lines are terminated by CRLF. An LF that \
                         splits a header here but not in a proxy in front of this node is a \
                         request-smuggling vector.",
                    ));
                }
            }
            b'\t' => {}
            // whole C0/C1 range, not just >= 0x80 - a stray NUL or LF desyncs us from a front proxy
            b if b >= 0x80 => {
                return HeadProgress::Fail(HttpFail::new(400, "non-ASCII byte in the request head"))
            }
            b if b < 0x20 || b == 0x7f => {
                return HeadProgress::Fail(HttpFail::new(
                    400,
                    "a control byte in the request head; only printable ASCII, HTAB and the CRLF \
                     line terminators are allowed",
                ))
            }
            _ => {}
        }
    }
    let text = match core::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => return HeadProgress::Fail(HttpFail::new(400, "request head is not valid ASCII")),
    };
    let mut lines = text.split("\r\n");
    let Some(request_line) = lines.next() else {
        return HeadProgress::Fail(HttpFail::new(400, "empty request"));
    };
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return HeadProgress::Fail(HttpFail::new(400, "malformed request line"));
    };
    if parts.next().is_some() {
        return HeadProgress::Fail(HttpFail::new(400, "malformed request line"));
    }
    let http11 = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        other => {
            return HeadProgress::Fail(HttpFail::new(
                505,
                format!("unsupported HTTP version {other:?}; this server speaks 1.0 and 1.1"),
            ))
        }
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if headers.len() + 1 > limits.max_headers {
            return HeadProgress::Fail(HttpFail::new(
                431,
                format!("more than {} header lines", limits.max_headers),
            ));
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            return HeadProgress::Fail(HttpFail::new(400, "obsolete line folding in headers"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return HeadProgress::Fail(HttpFail::new(400, "header line without a colon"));
        };

        if name.is_empty() || name.ends_with(' ') || name.ends_with('\t') {
            return HeadProgress::Fail(HttpFail::new(400, "whitespace before a header colon"));
        }
        if !name.bytes().all(is_tchar) {
            return HeadProgress::Fail(HttpFail::new(400, "illegal character in a header name"));
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }

    HeadProgress::Done(RequestHead {
        method: method.to_ascii_uppercase(),
        target: target.to_string(),
        http11,
        headers,
        head_len: end,
    })
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[derive(Clone, Debug)]
pub enum AuthPolicy {
    LoopbackNoToken,
    BearerToken(String),
}

#[derive(Clone, Debug)]
pub struct HttpContext {
    pub limits: HttpLimits,
    pub auth: AuthPolicy,
    pub loopback: bool,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub enum HeadVerdict {
    Accept {
        content_length: usize,
        keep_alive: bool,
    },
    Refuse(HttpFail),
}

pub fn validate_head(head: &RequestHead, ctx: &HttpContext) -> HeadVerdict {
    if head.method != "POST" {
        let mut fail = HttpFail::new(
            405,
            format!(
                "{} is not allowed; JSON-RPC is POST-only. There is no browsable interface here \
                 and no getblocktemplate.",
                head.method
            ),
        );
        fail.extra_headers.push(("Allow".into(), "POST".into()));
        return HeadVerdict::Refuse(fail);
    }

    if head.target != "/" {
        return HeadVerdict::Refuse(HttpFail::new(
            404,
            format!(
                "no such endpoint {:?}; the only endpoint is POST /",
                head.target
            ),
        ));
    }

    if head.header_count("host") > 1 {
        return HeadVerdict::Refuse(HttpFail::new(
            400,
            "more than one Host header; only the first would be consulted.",
        ));
    }
    if head.header_count("authorization") > 1 {
        return HeadVerdict::Refuse(HttpFail::new(400, "more than one Authorization header"));
    }

    // on loopback the Host pin is the only guard against a DNS-rebinding page, so pin it exactly.
    if ctx.loopback {
        match head.header("host") {
            Some(h) if host_is_loopback(h, ctx.port) => {}
            Some(h) => {
                return HeadVerdict::Refuse(HttpFail::new(
                    403,
                    format!(
                        "Host {h:?} is not a loopback name. This listener is bound to loopback and \
                         only answers to 127.0.0.1, [::1] or localhost."
                    ),
                ))
            }

            None => {
                return HeadVerdict::Refuse(HttpFail::new(
                    400,
                    "a Host header is required. This listener is bound to loopback and pins Host \
                     to 127.0.0.1, [::1] or localhost.",
                ))
            }
        }
    }

    if head.header("transfer-encoding").is_some() {
        return HeadVerdict::Refuse(HttpFail::new(
            501,
            "Transfer-Encoding is not implemented; send Content-Length.",
        ));
    }
    if head.header_count("content-length") > 1 {
        return HeadVerdict::Refuse(HttpFail::new(400, "more than one Content-Length header"));
    }
    let content_length = match head.header("content-length") {
        Some(v) if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) => {
            return HeadVerdict::Refuse(HttpFail::new(
                400,
                "Content-Length must be decimal digits and nothing else (RFC 7230: 1*DIGIT); no \
                 sign, no whitespace, no list",
            ))
        }
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                return HeadVerdict::Refuse(HttpFail::new(
                    400,
                    "Content-Length does not fit in this platform's usize",
                ))
            }
        },
        None => {
            return HeadVerdict::Refuse(HttpFail::new(
                411,
                "Content-Length is required (no chunked bodies)",
            ))
        }
    };
    if content_length > ctx.limits.max_body_bytes {
        return HeadVerdict::Refuse(HttpFail::new(
            413,
            format!(
                "body is {content_length} bytes, the limit is {}",
                ctx.limits.max_body_bytes
            ),
        ));
    }

    match head.header("content-type") {
        Some(v) => {
            let media = v.split(';').next().unwrap_or("").trim();
            if !media.eq_ignore_ascii_case("application/json") {
                return HeadVerdict::Refuse(HttpFail::new(
                    415,
                    format!(
                        "Content-Type must be application/json, got {media:?}. A browser form \
                         cannot send application/json, so requiring it keeps a cross-origin form \
                         POST from reaching a method."
                    ),
                ));
            }
        }
        None => {
            return HeadVerdict::Refuse(HttpFail::new(
                415,
                "Content-Type: application/json is required",
            ))
        }
    }

    if let AuthPolicy::BearerToken(expected) = &ctx.auth {
        let supplied = head.header("authorization").unwrap_or("");
        let Some(token) = supplied
            .strip_prefix("Bearer ")
            .or_else(|| supplied.strip_prefix("bearer "))
        else {
            return HeadVerdict::Refuse(HttpFail::new(
                401,
                "this listener is not on loopback and requires `Authorization: Bearer <rpc.token>`",
            ));
        };
        if !constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            return HeadVerdict::Refuse(HttpFail::new(401, "bad bearer token"));
        }
    }

    HeadVerdict::Accept {
        content_length,
        keep_alive: head.wants_keep_alive(),
    }
}

fn host_is_loopback(host: &str, port: u16) -> bool {
    let host = host.trim();

    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inside, tail)) => {
                if !tail.is_empty() && !port_matches(tail, port) {
                    return false;
                }
                inside.to_string()
            }
            None => return false,
        }
    } else {
        match host.rsplit_once(':') {
            Some((h, p)) => {
                if !port_matches(&format!(":{p}"), port) {
                    return false;
                }
                h.to_string()
            }
            None => host.to_string(),
        }
    };
    let n = name.to_ascii_lowercase();
    n == "localhost" || n == "127.0.0.1" || n == "::1" || n == "0:0:0:0:0:0:0:1"
}

fn port_matches(colon_port: &str, port: u16) -> bool {
    match colon_port.strip_prefix(':') {
        Some(p) => p.parse::<u16>().map(|v| v == port).unwrap_or(false),
        None => false,
    }
}

// compare every byte; short-circuiting on the first mismatch leaks the prefix length by timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub keep_alive: bool,
    pub extra_headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn ok_json(body: Vec<u8>, keep_alive: bool) -> Self {
        HttpResponse {
            status: 200,
            body,
            keep_alive,
            extra_headers: Vec::new(),
        }
    }

    pub fn no_content(keep_alive: bool) -> Self {
        HttpResponse {
            status: 204,
            body: Vec::new(),
            keep_alive,
            extra_headers: Vec::new(),
        }
    }

    pub fn from_fail(fail: &HttpFail) -> Self {
        let body = Json::Obj(vec![
            ("error".to_string(), Json::str(reason_phrase(fail.status))),
            ("status".to_string(), Json::Int(fail.status as i64)),
            ("detail".to_string(), Json::str(fail.detail.clone())),
        ])
        .to_string()
        .into_bytes();
        HttpResponse {
            status: fail.status,
            body,
            keep_alive: false,
            extra_headers: fail.extra_headers.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status,
            reason_phrase(self.status)
        );
        out.push_str("Content-Type: application/json\r\n");
        out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));

        // nosniff and no CORS/Server line: nothing here is meant to be reached from a browser.
        out.push_str("X-Content-Type-Options: nosniff\r\n");

        out.push_str(if self.keep_alive {
            "Connection: keep-alive\r\n"
        } else {
            "Connection: close\r\n"
        });
        for (k, v) in &self.extra_headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> HttpContext {
        HttpContext {
            limits: HttpLimits::default(),
            auth: AuthPolicy::LoopbackNoToken,
            loopback: true,
            port: 9257,
        }
    }

    fn head(raw: &str) -> RequestHead {
        match read_head(raw.as_bytes(), HttpLimits::default()) {
            HeadProgress::Done(h) => h,
            other => panic!("expected a head, got {other:?}"),
        }
    }

    const GOOD: &str = "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n";

    #[test]
    fn normal_request_is_accepted() {
        match validate_head(&head(GOOD), &ctx()) {
            HeadVerdict::Accept {
                content_length,
                keep_alive,
            } => {
                assert_eq!(content_length, 2);
                assert!(keep_alive);
            }
            HeadVerdict::Refuse(f) => panic!("refused: {f:?}"),
        }
    }

    #[test]
    fn partial_input_needs_more() {
        assert!(matches!(
            read_head(b"POST / HTTP/1.1\r\nHost: local", HttpLimits::default()),
            HeadProgress::NeedMore
        ));
    }

    #[test]
    fn endless_head_refused_at_limit() {
        let flood = format!("POST / HTTP/1.1\r\n{}", "X: y\r\n".repeat(4000));
        match read_head(flood.as_bytes(), HttpLimits::default()) {
            HeadProgress::Fail(f) => assert_eq!(f.status, 431),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn head_bounded_in_bytes_and_headers() {
        let limits = HttpLimits::default();

        let huge = format!(
            "POST / HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
            "p".repeat(limits.max_head_bytes + 100)
        );
        match read_head(huge.as_bytes(), limits) {
            HeadProgress::Fail(f) => assert_eq!(f.status, 431, "{}", f.detail),
            other => panic!(
                "a terminated {}-byte head was accepted: {other:?}",
                huge.len()
            ),
        }

        let many = format!(
            "POST / HTTP/1.1\r\n{}\r\n",
            "X: y\r\n".repeat(limits.max_headers + 1)
        );
        assert!(
            many.len() < limits.max_head_bytes,
            "fixture must not trip the byte cap"
        );
        match read_head(many.as_bytes(), limits) {
            HeadProgress::Fail(f) => assert_eq!(f.status, 431, "{}", f.detail),
            other => panic!(
                "{} header lines were accepted: {other:?}",
                limits.max_headers + 1
            ),
        }

        let at_limit = format!(
            "POST / HTTP/1.1\r\n{}\r\n",
            "X: y\r\n".repeat(limits.max_headers - 1)
        );
        assert!(matches!(
            read_head(at_limit.as_bytes(), limits),
            HeadProgress::Done(_)
        ));
    }

    #[test]
    fn get_is_405_with_allow() {
        let h = head("GET / HTTP/1.1\r\nHost: localhost:9257\r\n\r\n");
        match validate_head(&h, &ctx()) {
            HeadVerdict::Refuse(f) => {
                assert_eq!(f.status, 405);
                assert!(f
                    .extra_headers
                    .iter()
                    .any(|(k, v)| k == "Allow" && v == "POST"));
                assert!(f.detail.contains("getblocktemplate"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn dns_rebinding_host_refused() {
        let h = head("POST / HTTP/1.1\r\nHost: evil.example\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n");
        match validate_head(&h, &ctx()) {
            HeadVerdict::Refuse(f) => {
                assert_eq!(f.status, 403);
                assert!(f.detail.contains("loopback"));
            }
            other => panic!("{other:?}"),
        }

        for host in [
            "127.0.0.1:9257",
            "localhost:9257",
            "[::1]:9257",
            "localhost",
            "LOCALHOST:9257",
        ] {
            let raw = format!("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n");
            assert!(
                matches!(
                    validate_head(&head(&raw), &ctx()),
                    HeadVerdict::Accept { .. }
                ),
                "rejected legitimate host {host}"
            );
        }

        let wrong = "POST / HTTP/1.1\r\nHost: 127.0.0.1:80\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n".to_string();
        assert!(matches!(
            validate_head(&head(&wrong), &ctx()),
            HeadVerdict::Refuse(_)
        ));
    }

    #[test]
    fn missing_host_refused_every_version() {
        for version in ["HTTP/1.1", "HTTP/1.0"] {
            let raw = format!(
                "POST / {version}\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n"
            );
            match validate_head(&head(&raw), &ctx()) {
                HeadVerdict::Refuse(f) => {
                    assert_eq!(f.status, 400, "{version}");
                    assert!(f.detail.contains("Host"), "{version}: {}", f.detail);
                }
                other => panic!("{version} skipped the Host pin: {other:?}"),
            }
        }
    }

    #[test]
    fn browser_form_content_type_refused() {
        for ct in [
            "application/x-www-form-urlencoded",
            "text/plain",
            "multipart/form-data",
        ] {
            let raw = format!("POST / HTTP/1.1\r\nHost: localhost:9257\r\nContent-Type: {ct}\r\nContent-Length: 2\r\n\r\n");
            match validate_head(&head(&raw), &ctx()) {
                HeadVerdict::Refuse(f) => assert_eq!(f.status, 415, "{ct}"),
                other => panic!("{ct} was accepted: {other:?}"),
            }
        }

        let raw = "POST / HTTP/1.1\r\nHost: localhost:9257\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 2\r\n\r\n";
        assert!(matches!(
            validate_head(&head(raw), &ctx()),
            HeadVerdict::Accept { .. }
        ));
    }

    #[test]
    fn smuggling_shapes_refused() {
        let dup = "POST / HTTP/1.1\r\nHost: localhost:9257\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n";
        assert!(matches!(
            validate_head(&head(dup), &ctx()),
            HeadVerdict::Refuse(_)
        ));

        let te = "POST / HTTP/1.1\r\nHost: localhost:9257\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
        match validate_head(&head(te), &ctx()) {
            HeadVerdict::Refuse(f) => assert_eq!(f.status, 501),
            other => panic!("{other:?}"),
        }

        for raw in [
            "POST / HTTP/1.1\r\nContent-Length : 2\r\n\r\n",
            "POST / HTTP/1.1\r\nX-A: b\r\n  continued\r\n\r\n",
        ] {
            assert!(matches!(
                read_head(raw.as_bytes(), HttpLimits::default()),
                HeadProgress::Fail(_)
            ));
        }
    }

    #[test]
    fn oversize_body_refused_by_length() {
        let raw = "POST / HTTP/1.1\r\nHost: localhost:9257\r\nContent-Type: application/json\r\nContent-Length: 99999999\r\n\r\n";
        match validate_head(&head(raw), &ctx()) {
            HeadVerdict::Refuse(f) => assert_eq!(f.status, 413),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bearer_token_required_and_constant_time() {
        let c = HttpContext {
            auth: AuthPolicy::BearerToken("s3cret-token-of-known-length-0000".into()),
            loopback: false,
            ..ctx()
        };
        let base = "POST / HTTP/1.1\r\nHost: node.example\r\nContent-Type: application/json\r\nContent-Length: 2\r\n";

        match validate_head(&head(&format!("{base}\r\n")), &c) {
            HeadVerdict::Refuse(f) => assert_eq!(f.status, 401),
            other => panic!("{other:?}"),
        }

        let bad = format!("{base}Authorization: Bearer wrong\r\n\r\n");
        assert!(matches!(
            validate_head(&head(&bad), &c),
            HeadVerdict::Refuse(_)
        ));

        let same_len = "S3CRET-TOKEN-OF-KNOWN-LENGTH-0000";
        assert_eq!(same_len.len(), "s3cret-token-of-known-length-0000".len());
        let bad = format!("{base}Authorization: Bearer {same_len}\r\n\r\n");
        assert!(
            matches!(validate_head(&head(&bad), &c), HeadVerdict::Refuse(_)),
            "a wrong token of the right length was accepted"
        );

        let mut last = "s3cret-token-of-known-length-0000".to_string();
        last.pop();
        last.push('1');
        let bad = format!("{base}Authorization: Bearer {last}\r\n\r\n");
        assert!(matches!(
            validate_head(&head(&bad), &c),
            HeadVerdict::Refuse(_)
        ));

        let good = format!("{base}Authorization: Bearer s3cret-token-of-known-length-0000\r\n\r\n");
        assert!(matches!(
            validate_head(&head(&good), &c),
            HeadVerdict::Accept { .. }
        ));
    }

    #[test]
    fn responses_carry_no_cors_or_banner() {
        let bytes = HttpResponse::ok_json(b"{}".to_vec(), true).to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.to_ascii_lowercase().contains("access-control"));
        assert!(!text.to_ascii_lowercase().contains("server:"));
        assert!(text.contains("X-Content-Type-Options: nosniff"));
        assert!(text.contains("Content-Length: 2"));
    }

    #[test]
    fn refusals_are_json_and_close() {
        let fail = HttpFail::new(415, "Content-Type must be application/json");
        let r = HttpResponse::from_fail(&fail);
        assert!(!r.keep_alive);
        let text = String::from_utf8(r.to_bytes()).unwrap();
        assert!(text.contains("Connection: close"));
        assert!(text.contains(r#""status":415"#));
        assert!(text.contains("Unsupported Media Type"));
    }
}
