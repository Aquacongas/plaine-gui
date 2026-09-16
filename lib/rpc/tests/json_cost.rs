use std::time::Instant;

use plaine_rpc::json::{self, JsonLimits};
use plaine_rpc::mock::MockNode;
use plaine_rpc::server::handle_body;

fn quadratic_body() -> Vec<u8> {
    let n = 4_096usize;
    let key_len = 250usize;
    let mut s = String::with_capacity(n * (key_len + 6) + 4);
    s.push('{');
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        s.push('"');

        for _ in 0..(key_len - 6) {
            s.push('a');
        }
        s.push_str(&format!("{i:06}"));
        s.push_str("\":0");
    }
    s.push('}');
    s.into_bytes()
}

fn benign_body() -> Vec<u8> {
    let filler = "b".repeat(1_048_000);
    format!(r#"{{"jsonrpc":"2.0","method":"chain_getInfo","params":["{filler}"],"id":1}}"#)
        .into_bytes()
}

fn time_parse(body: &[u8]) -> std::time::Duration {
    let limits = JsonLimits::request();
    let start = Instant::now();
    let _ = json::parse(body, limits);
    start.elapsed()
}

#[test]
fn no_body_costs_wildly_more() {
    let evil = quadratic_body();
    let good = benign_body();
    assert!(evil.len() <= 1024 * 1024, "fixture exceeds the body cap: {}", evil.len());
    assert!(good.len() <= 1024 * 1024);

    let _ = time_parse(&good);

    let t_good = time_parse(&good);
    let t_evil = time_parse(&evil);
    let ratio = t_evil.as_secs_f64() / t_good.as_secs_f64().max(1e-9);

    println!(
        "benign 1 MiB body: {t_good:?}   duplicate-key-scan 1 MiB body: {t_evil:?}   ratio {ratio:.0}x"
    );

    assert!(
        ratio < 10.0,
        "a 1 MiB body of distinct keys cost {ratio:.0}x an ordinary one ({t_evil:?} vs {t_good:?}); \
         the dup-key scan in Parser::object is going quadratic"
    );
}

#[test]
fn amplifier_reachable_through_handle_body() {
    let node = MockNode::synced().into_node();
    let evil = quadratic_body();
    let good = benign_body();

    let _ = handle_body(&node, &good, JsonLimits::request());

    let start = Instant::now();
    let _ = handle_body(&node, &good, JsonLimits::request());
    let t_good = start.elapsed();

    let start = Instant::now();
    let out = handle_body(&node, &evil, JsonLimits::request()).expect("a response");
    let t_evil = start.elapsed();

    let response = String::from_utf8(out).expect("utf8");

    assert!(response.contains("-32600"), "{response}");
    let ratio = t_evil.as_secs_f64() / t_good.as_secs_f64().max(1e-9);
    println!(
        "handle_body: ordinary 1 MiB body {t_good:?}, quadratic 1 MiB body {t_evil:?} \
         ({ratio:.1}x), answered {} bytes",
        response.len()
    );
    assert!(
        ratio < 10.0,
        "handle_body spent {ratio:.0}x on a 1 MiB non-request body ({t_evil:?} vs {t_good:?}); \
         answered {} bytes",
        response.len()
    );
}

#[test]
fn flat_width_bomb_refused_fast() {
    let mut wide = String::from("[0");
    while wide.len() < 1024 * 1024 - 1 {
        wide.push_str(",0");
    }
    wide.push(']');
    let t = time_parse(wide.as_bytes());
    println!("1 MiB flat array: {t:?}");
    assert!(t < std::time::Duration::from_millis(5), "{t:?}");
}

#[test]
fn depth_bomb_refused_fast() {
    let deep = format!("{}{}", "[".repeat(524_288), "]".repeat(524_288));
    let t = time_parse(deep.as_bytes());
    println!("1 MiB depth bomb: {t:?}");
    assert!(t < std::time::Duration::from_millis(5), "{t:?}");
}

#[test]
fn full_batch_is_bounded() {
    let node = MockNode::synced().with_notes().into_node();
    let one = r#"{"jsonrpc":"2.0","method":"chain_getBlockByHeight","params":[1,2],"id":1}"#;
    let batch = format!("[{}]", vec![one; 32].join(","));
    let start = Instant::now();
    let out = handle_body(&node, batch.as_bytes(), JsonLimits::request()).expect("response");
    println!("MAX_BATCH of getBlockByHeight v2: {:?}, {} bytes out", start.elapsed(), out.len());

    let over = format!("[{}]", vec![one; 33].join(","));
    let out = handle_body(&node, over.as_bytes(), JsonLimits::request()).expect("response");
    assert!(String::from_utf8(out).expect("utf8").contains("-32005"));
}

#[test]
fn giant_method_name_is_bounded() {
    let node = MockNode::synced().into_node();
    let name = "z".repeat(900_000);
    let body = format!(r#"{{"jsonrpc":"2.0","method":"{name}","id":1}}"#);

    let baseline_body =
        format!(r#"{{"jsonrpc":"2.0","method":"tx_get","params":["{name}"],"id":1}}"#);
    let _ = handle_body(&node, baseline_body.as_bytes(), JsonLimits::request());
    let start = Instant::now();
    let _ = handle_body(&node, baseline_body.as_bytes(), JsonLimits::request());
    let baseline = start.elapsed();

    let start = Instant::now();
    let out = handle_body(&node, body.as_bytes(), JsonLimits::request()).expect("response");
    let elapsed = start.elapsed();
    let ratio = elapsed.as_secs_f64() / baseline.as_secs_f64().max(1e-9);
    println!(
        "900 KiB method name: {elapsed:?} against {baseline:?} for the same string as a \
         parameter ({ratio:.1}x), {} bytes out",
        out.len()
    );
    assert!(out.len() < 2_000, "the name was echoed: {} bytes", out.len());
    assert!(
        ratio < 5.0,
        "a 900 KiB method name cost {ratio:.0}x the same string as a parameter ({elapsed:?} vs \
         {baseline:?}); the fuzzy matcher is running on the whole name"
    );
}

#[test]
fn notifications_and_null_ids_answer_nothing() {
    let node = MockNode::synced().into_node();

    let all_notes = r#"[{"jsonrpc":"2.0","method":"fee_suggest"},{"jsonrpc":"2.0","method":"fee_suggest"}]"#;
    assert!(handle_body(&node, all_notes.as_bytes(), JsonLimits::request()).is_none());

    let null_id = r#"{"jsonrpc":"2.0","method":"fee_suggest","id":null}"#;
    assert!(handle_body(&node, null_id.as_bytes(), JsonLimits::request()).is_none());

    let nested = r#"[[{"jsonrpc":"2.0","method":"fee_suggest","id":1}]]"#;
    let out = handle_body(&node, nested.as_bytes(), JsonLimits::request()).expect("response");
    assert!(String::from_utf8(out).expect("utf8").contains("-32600"));
}

#[test]
fn boundary_numbers_do_not_wrap_or_panic() {
    let node = MockNode::synced().into_node();
    for n in [
        "9223372036854775807",
        "9223372036854775808",
        "18446744073709551615",
        "18446744073709551616",
        "340282366920938463463374607431768211455",
        "-9223372036854775808",
        "-9223372036854775809",
        "-1",
        "0",
    ] {
        for method in ["chain_getHeaderByHeight", "chain_getBlockByHeight", "emission_audit"] {
            let body = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":[{n}],"id":1}}"#);
            let out = handle_body(&node, body.as_bytes(), JsonLimits::request())
                .expect("a response, not a panic");
            let text = String::from_utf8(out).expect("utf8");

            if n.parse::<i64>().is_err() {
                assert!(text.contains("-32700"), "{method}({n}) -> {text}");
                assert!(text.contains(r#""id":null"#), "{method}({n}) -> {text}");
            } else {
                assert!(text.contains(r#""id":1"#), "{method}({n}) -> {text}");
                if n.starts_with('-') {
                    assert!(text.contains("-32602"), "{method}({n}) -> {text}");
                }
            }
        }

        let body =
            format!(r#"{{"jsonrpc":"2.0","method":"author_getNotes","params":[null,null,{n}],"id":1}}"#);
        assert!(handle_body(&node, body.as_bytes(), JsonLimits::request()).is_some());
    }

    let addr = MockNode::sample_address();
    let body =
        format!(r#"{{"jsonrpc":"2.0","method":"account_get","params":["{addr}"],"id":1}}"#);
    let out = String::from_utf8(
        handle_body(&node, body.as_bytes(), JsonLimits::request()).expect("response"),
    )
    .expect("utf8");
    assert!(out.contains(r#""balance":"4200000000000000000""#), "{out}");
}

#[test]
fn hostile_hash_and_address_never_panic() {
    let node = MockNode::synced().with_txindex().into_node();
    let hostile: Vec<String> = vec![
        String::new(),
        "0x".into(),
        "0x0".into(),
        "f".repeat(63),
        "f".repeat(64),
        "f".repeat(65),
        "0x".to_owned() + &"f".repeat(64),
        "\u{1f600}".repeat(16),
        "\u{e9}".repeat(32),
        "zz zz zz".into(),
        "plne1".into(),
        "plne1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .into(),
    ];
    for hostile in &hostile {
        for method in ["tx_get", "chain_getHeaderByHash", "chain_getBlockByHash"] {
            let escaped = plaine_rpc::json::Json::str(hostile).to_string();
            let body =
                format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":[{escaped}],"id":1}}"#);
            assert!(
                handle_body(&node, body.as_bytes(), JsonLimits::request()).is_some(),
                "{method}({hostile:?}) produced no response"
            );
        }
        for method in ["account_get", "mempool_getBySender"] {
            let escaped = plaine_rpc::json::Json::str(hostile).to_string();
            let body =
                format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":[{escaped}],"id":1}}"#);
            assert!(handle_body(&node, body.as_bytes(), JsonLimits::request()).is_some());
        }
    }
}
