use plaine_rpc::http::{
    read_head, validate_head, AuthPolicy, HeadProgress, HeadVerdict, HttpContext, HttpLimits,
    RequestHead,
};

fn ctx_loopback() -> HttpContext {
    HttpContext {
        limits: HttpLimits::default(),
        auth: AuthPolicy::LoopbackNoToken,
        loopback: true,
        port: 9257,
    }
}

fn ctx_token(tok: &str) -> HttpContext {
    HttpContext {
        limits: HttpLimits::default(),
        auth: AuthPolicy::BearerToken(tok.to_string()),
        loopback: false,
        port: 9257,
    }
}

fn head(raw: &str) -> RequestHead {
    match read_head(raw.as_bytes(), HttpLimits::default()) {
        HeadProgress::Done(h) => h,
        other => panic!("expected a head, got {other:?}"),
    }
}

fn try_head(raw: &str) -> HeadProgress {
    read_head(raw.as_bytes(), HttpLimits::default())
}

#[test]
fn bare_lf_cannot_hide_a_header() {
    let raw = "POST / HTTP/1.1\r\n\
               Host: 127.0.0.1:9257\r\n\
               Content-Type: application/json\r\n\
               Content-Length: 5\r\n\
               X-Junk: junk\nTransfer-Encoding: chunked\r\n\
               \r\n";

    let lf_lines = raw.matches("Transfer-Encoding").count();
    assert_eq!(lf_lines, 1, "fixture is wrong");

    match try_head(raw) {
        HeadProgress::Fail(f) => {
            assert_eq!(f.status, 400);
            assert!(f.detail.contains("LF"), "the refusal does not name the reason: {}", f.detail);
        }
        HeadProgress::NeedMore => panic!("a terminated head asked for more bytes"),
        HeadProgress::Done(h) => {
            let te = h.header("transfer-encoding").is_some();
            let smuggled = h.header("x-junk").unwrap_or("");
            panic!(
                "a bare LF survived the head parser (x-junk={smuggled:?}, te={te}); \
                 that is the CL.TE desync the ASCII check is meant to stop"
            );
        }
    }
}

#[test]
fn raw_control_bytes_refused_in_head() {
    for (name, raw) in [
        ("ESC", "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nX-Ua: v1\u{1b}[2Jcleared\r\n\r\n"),
        ("NUL", "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nX-Ua: v1\u{0}x\r\n\r\n"),
        ("DEL", "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nX-Ua: v1\u{7f}x\r\n\r\n"),
        ("bare CR", "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nX-Ua: v1\rx\r\n\r\n"),
        ("vertical tab", "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nX-Ua: v1\u{b}x\r\n\r\n"),
    ] {
        match try_head(raw) {
            HeadProgress::Fail(f) => assert_eq!(f.status, 400, "{name}"),
            other => panic!("raw {name} survived read_head: {other:?}"),
        }
    }

    match try_head("POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nX-Ua: v1\tv2\r\n\r\n") {
        HeadProgress::Done(h) => assert_eq!(h.header("x-ua"), Some("v1\tv2")),
        other => panic!("HTAB inside a header value was refused: {other:?}"),
    }
}

#[test]
fn content_length_must_be_digits() {
    let raw = "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nContent-Type: application/json\r\n\
               Content-Length: +5\r\n\r\n";
    match validate_head(&head(raw), &ctx_loopback()) {
        HeadVerdict::Accept { content_length, .. } => panic!(
            "`Content-Length: +5` accepted as {content_length}; RFC 7230 is 1*DIGIT"
        ),
        HeadVerdict::Refuse(f) => assert_eq!(f.status, 400),
    }
}

#[test]
fn second_host_header_refused() {
    let raw = "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nHost: evil.example\r\n\
               Content-Type: application/json\r\nContent-Length: 2\r\n\r\n";
    let h = head(raw);
    assert_eq!(h.header_count("host"), 2, "fixture is wrong");
    match validate_head(&h, &ctx_loopback()) {
        HeadVerdict::Refuse(_) => {}
        HeadVerdict::Accept { .. } => {
            panic!("two Host headers accepted; only the first is consulted, so the pin is bypassed")
        }
    }
}

#[test]
fn second_authorization_header_refused() {
    let tok = "T".repeat(40);
    let raw = format!(
        "POST / HTTP/1.1\r\nHost: node.example\r\nContent-Type: application/json\r\n\
         Authorization: Bearer {tok}\r\nAuthorization: Bearer wrong\r\nContent-Length: 2\r\n\r\n"
    );
    let h = head(&raw);
    assert_eq!(h.header_count("authorization"), 2, "fixture is wrong");
    match validate_head(&h, &ctx_token(&tok)) {
        HeadVerdict::Refuse(_) => {}
        HeadVerdict::Accept { .. } => {
            panic!("two Authorization headers accepted; front-end and back-end would disagree on the caller")
        }
    }
}

#[test]
fn off_loopback_auth_is_mandatory() {
    let tok = "s3cret-token-of-known-length-0000";
    let c = ctx_token(tok);
    let base = "POST / HTTP/1.1\r\nHost: node.example\r\nContent-Type: application/json\r\n\
                Content-Length: 2\r\n";

    let refusals = [
        format!("{base}\r\n"),
        format!("{base}Authorization: \r\n\r\n"),
        format!("{base}Authorization: Bearer\r\n\r\n"),
        format!("{base}Authorization: Bearer \r\n\r\n"),
        format!("{base}Authorization: Bearer {tok}x\r\n\r\n"),
        format!("{base}Authorization: Bearer {}\r\n\r\n", &tok[..tok.len() - 1]),
        format!("{base}Authorization: Bearer {}\r\n\r\n", tok.to_uppercase()),
        format!("{base}Authorization: Basic {tok}\r\n\r\n"),
        format!("{base}Authorization: Bearer  {tok}\r\n\r\n"),
        format!("{base}Authorization: Bearer {tok}\u{0}\r\n\r\n"),
        format!("{base}Authorization: Bearer {}\r\n\r\n", &tok[..4]),
    ];
    for raw in refusals {
        let h = match read_head(raw.as_bytes(), HttpLimits::default()) {
            HeadProgress::Done(h) => h,
            HeadProgress::Fail(f) => {
                assert_eq!(f.status, 400, "{raw:?}");
                continue;
            }
            HeadProgress::NeedMore => panic!("a terminated head asked for more: {raw:?}"),
        };
        match validate_head(&h, &c) {
            HeadVerdict::Refuse(f) => {
                assert_eq!(f.status, 401, "{raw:?}");

                assert!(!f.detail.contains(tok), "the refusal echoed the token: {}", f.detail);
                assert!(
                    !f.detail.contains(&tok.len().to_string()),
                    "the refusal disclosed the token length: {}", f.detail
                );
            }
            HeadVerdict::Accept { .. } => panic!("AUTH BYPASS with head {raw:?}"),
        }
    }

    let ok = format!("{base}Authorization: bearer {tok}\r\n\r\n");
    assert!(matches!(validate_head(&head(&ok), &c), HeadVerdict::Accept { .. }));
}

#[test]
fn only_post_reaches_a_handler() {
    for m in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "CONNECT", "post"] {
        let raw = format!(
            "{m} / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nContent-Type: application/json\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let verdict = validate_head(&head(&raw), &ctx_loopback());
        if m == "post" {
            assert!(matches!(verdict, HeadVerdict::Accept { .. }));
        } else {
            match verdict {
                HeadVerdict::Refuse(f) => assert_eq!(f.status, 405, "{m}"),
                other => panic!("{m} was accepted: {other:?}"),
            }
        }
    }
}

#[test]
fn host_pin_rejects_fake_loopback() {
    for host in [
        "evil.example",
        "127.0.0.1.evil.example",
        "localhost.evil.example",
        "evil.example:9257",
        "user@localhost:9257",
        "127.0.0.1:80",
        "localhost:9258",
        "[::1]:80",
        "127.0.0.2:9257",
        "127.1:9257",
        "[::ffff:127.0.0.1]:9257",
        "0.0.0.0:9257",
        "LOCALHOST.EVIL:9257",
        " localhost.evil:9257",
        "localhost:9257extra",
        "[::1",
        "",
    ] {
        let raw = format!(
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: 0\r\n\r\n"
        );
        match validate_head(&head(&raw), &ctx_loopback()) {
            HeadVerdict::Refuse(f) => assert!(
                f.status == 403 || f.status == 400,
                "{host} refused with {}",
                f.status
            ),
            HeadVerdict::Accept { .. } => panic!("DNS-REBINDING HOST ACCEPTED: {host:?}"),
        }
    }
}

#[test]
fn target_must_be_exactly_slash() {
    for target in [
        "/?x=1",
        "//",
        "/.",
        "/../",
        "http://localhost:9257/",
        "*",
        "/%2e",
        "/\u{7f}",
        "/;",
    ] {
        let raw = format!(
            "POST {target} HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nContent-Type: application/json\r\n\
             Content-Length: 0\r\n\r\n"
        );
        match read_head(raw.as_bytes(), HttpLimits::default()) {
            HeadProgress::Done(h) => match validate_head(&h, &ctx_loopback()) {
                HeadVerdict::Refuse(f) => assert_eq!(f.status, 404, "{target}"),
                other => panic!("{target} was accepted: {other:?}"),
            },
            HeadProgress::Fail(_) => {}
            HeadProgress::NeedMore => panic!("{target} needed more"),
        }
    }
}

#[test]
fn head_parser_refuses_smuggling_shapes() {
    for raw in [

        "POST / HTTP/1.1\r\nX-A: b\r\n\tcont\r\n\r\n",
        "POST / HTTP/1.1\r\nContent-Length : 2\r\n\r\n",
        "POST / HTTP/1.1\r\nCon(tent)-Length: 2\r\n\r\n",
        "POST / HTTP/1.1\r\n: 2\r\n\r\n",
        "POST / HTTP/1.1\r\nJustAName\r\n\r\n",
        "POST / HTTP/1.1 extra\r\n\r\n",
        "POST /\r\n\r\n",
        "PRI * HTTP/2.0\r\n\r\n",
    ] {
        assert!(
            matches!(try_head(raw), HeadProgress::Fail(_)),
            "the head parser accepted {raw:?}"
        );
    }

    let dup = "POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nContent-Type: application/json\r\n\
               Content-Length: 2\r\nContent-Length: 3\r\n\r\n";
    assert!(matches!(validate_head(&head(dup), &ctx_loopback()), HeadVerdict::Refuse(_)));
}

#[test]
fn refusal_body_leaks_nothing() {
    let tok = "T".repeat(40);
    let heads = [
        ("GET / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\n\r\n", ctx_loopback()),
        ("POST /secret HTTP/1.1\r\nHost: 127.0.0.1:9257\r\n\r\n", ctx_loopback()),
        ("POST / HTTP/1.1\r\nHost: evil.example\r\n\r\n", ctx_loopback()),
        ("POST / HTTP/1.1\r\nHost: 127.0.0.1:9257\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\n", ctx_loopback()),
        ("POST / HTTP/1.1\r\nHost: n.example\r\nContent-Type: application/json\r\nContent-Length: 1\r\nAuthorization: Bearer nope\r\n\r\n", ctx_token(&tok)),
    ];
    for (raw, c) in heads {
        if let HeadVerdict::Refuse(f) = validate_head(&head(raw), &c) {
            let body = String::from_utf8(
                plaine_rpc::http::HttpResponse::from_fail(&f).to_bytes(),
            )
            .expect("utf8");
            for forbidden in [&tok[..], "C:\\", "/home/", "src\\", "HttpFail", "Bech32Error", "\\u{"] {
                assert!(!body.contains(forbidden), "{forbidden:?} leaked into: {body}");
            }
        }
    }
}
