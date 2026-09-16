use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use plaine_rpc::json::JsonLimits;
use plaine_rpc::mock::MockNode;
use plaine_rpc::server::{handle_body, RpcConfig, RpcServer, Shutdown};
use plaine_rpc::views::{
    Address20, FeeSuggestion, Hash32, MempoolInfo, MempoolView, Node, SubmitError, TxRecord,
};

#[test]
fn submit_error_human_never_overflows() {
    let e = SubmitError::NonceOutOfRange { got: 3, next: u64::MAX, max_gap: 16 };
    let msg = std::panic::catch_unwind(|| e.human());
    assert!(msg.is_ok(), "human() overflowed on next+max_gap near u64::MAX");
}

struct TopOfNonceSpacePool;

impl MempoolView for TopOfNonceSpacePool {
    fn info(&self) -> MempoolInfo {
        MempoolInfo::default()
    }
    fn by_sender(&self, _addr: &Address20) -> Vec<TxRecord> {
        Vec::new()
    }
    fn fee_suggest(&self) -> FeeSuggestion {
        FeeSuggestion::default()
    }
    fn submit(&self, _raw: &[u8]) -> Result<Hash32, SubmitError> {
        Err(SubmitError::NonceOutOfRange { got: 1, next: u64::MAX, max_gap: 16 })
    }
}

fn node_with_boom_pool() -> Node {
    let base = MockNode::synced().into_node();
    Node {
        chain: base.chain,
        mempool: Arc::new(TopOfNonceSpacePool),
        net: base.net,
        stratum: base.stratum,
        policy: base.policy,
        budgets: base.budgets,
    }
}

fn request(port: u16, payload: &str) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n{payload}",
        payload.len()
    )
}

fn speak(addr: std::net::SocketAddr, payload: &str) -> String {
    let req = request(addr.port(), payload);
    let mut sock = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => return format!("<connect failed: {e}>"),
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    if sock.write_all(req.as_bytes()).is_err() {
        return "<write failed>".into();
    }
    let mut out = String::new();
    let _ = sock.read_to_string(&mut out);
    out
}

struct PanickingPool;

impl MempoolView for PanickingPool {
    fn info(&self) -> MempoolInfo {
        MempoolInfo::default()
    }
    fn by_sender(&self, _addr: &Address20) -> Vec<TxRecord> {
        Vec::new()
    }
    fn fee_suggest(&self) -> FeeSuggestion {
        FeeSuggestion::default()
    }
    fn submit(&self, _raw: &[u8]) -> Result<Hash32, SubmitError> {
        panic!("a handler panicked; the concurrency slot must still come back")
    }
}

#[test]
fn panicking_handler_costs_one_connection() {
    let mut cfg = RpcConfig::loopback(0);
    cfg.bind = "127.0.0.1:0".parse().expect("addr");

    cfg.max_connections = 1;
    let shutdown = Shutdown::new();
    let base = MockNode::synced().into_node();
    let node = Node {
        chain: base.chain,
        mempool: Arc::new(PanickingPool),
        net: base.net,
        stratum: base.stratum,
        policy: base.policy,
        budgets: base.budgets,
    };
    let server = RpcServer::bind(cfg, node, shutdown.clone()).expect("bind");
    let addr = server.local_addr().expect("addr");
    let metrics = server.metrics();
    let handle = std::thread::spawn(move || server.serve());

    for _ in 0..3 {
        let _ = speak(addr, r#"{"jsonrpc":"2.0","method":"tx_sendRaw","params":["00"],"id":1}"#);
        std::thread::sleep(Duration::from_millis(150));
    }

    let leaked = metrics.in_flight.load(Ordering::SeqCst);
    let after = speak(addr, r#"{"jsonrpc":"2.0","method":"fee_suggest","id":2}"#);

    shutdown.trigger();
    let _ = handle.join();

    assert_eq!(leaked, 0, "in_flight is stuck at {leaked} with no connection open");
    assert!(
        after.starts_with("HTTP/1.1 200"),
        "three panicking requests wedged the interface: {}. the slot decrement must be a Drop \
         guard, not a statement after serve_connection() that unwind skips",
        after.lines().next().unwrap_or("<nothing>")
    );
}

#[test]
fn panicking_request_frees_its_slot() {
    let mut cfg = RpcConfig::loopback(0);
    cfg.bind = "127.0.0.1:0".parse().expect("addr");

    cfg.max_connections = 1;
    let shutdown = Shutdown::new();
    let server = RpcServer::bind(cfg, node_with_boom_pool(), shutdown.clone()).expect("bind");
    let addr = server.local_addr().expect("addr");
    let metrics = server.metrics();
    let handle = std::thread::spawn(move || server.serve());

    let ok = speak(addr, r#"{"jsonrpc":"2.0","method":"fee_suggest","id":1}"#);
    assert!(ok.starts_with("HTTP/1.1 200"), "baseline: {ok}");

    let _ = speak(addr, r#"{"jsonrpc":"2.0","method":"tx_sendRaw","params":["00"],"id":1}"#);
    std::thread::sleep(Duration::from_millis(300));

    let leaked = metrics.in_flight.load(Ordering::SeqCst);
    let after = speak(addr, r#"{"jsonrpc":"2.0","method":"fee_suggest","id":2}"#);

    shutdown.trigger();
    let _ = handle.join();

    assert!(
        !after.starts_with("HTTP/1.1 503") && leaked == 0,
        "one panicking request ate the whole concurrency budget: in_flight stuck at {leaked}, \
         later requests answered {}",
        after.lines().next().unwrap_or("<nothing>")
    );
}

fn call(node: &Node, payload: &str) -> String {
    String::from_utf8(handle_body(node, payload.as_bytes(), JsonLimits::request()).expect("body"))
        .expect("utf8")
}

#[test]
fn refusal_never_prints_foreign_debug() {
    let node = MockNode::synced().into_node();

    let hex = call(&node, r#"{"jsonrpc":"2.0","method":"tx_sendRaw","params":["zz"],"id":1}"#);
    assert!(
        !hex.contains("InvalidChar") && !hex.contains("byte:"),
        "tx_sendRaw leaked HexError Debug instead of its Display: {hex}"
    );

    let addr = call(
        &node,
        r#"{"jsonrpc":"2.0","method":"account_get","params":["plne1qqqqqqqqbad"],"id":1}"#,
    );
    assert!(
        !addr.contains("BadChecksum")
            && !addr.contains("Padding")
            && !addr.contains("DataChar")
            && !addr.contains("MixedCase"),
        "account_get leaked Bech32Error Debug instead of its Display: {addr}"
    );
}

#[test]
fn closed_list_exposes_no_key_or_control() {
    let node = MockNode::synced().with_notes().into_node();

    for method in ["checkpoint_getStatus", "author_getNotes"] {
        let out = call(&node, &format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":1}}"#));
        assert!(!out.contains("privkey") && !out.contains("secret") && !out.contains("seed"));
        let v = plaine_rpc::json::parse(out.as_bytes(), JsonLimits::default()).expect("json");
        let result = v.get("result").expect("result");

        if let Some(fps) = result.get("keyFingerprints").and_then(|f| f.as_arr()) {
            for f in fps {
                assert!(f.as_str().expect("str").len() < 32, "full key emitted: {f:?}");
            }
        }
        if let Some(k) = result.get("authorKey") {
            let fp = k.get("fingerprint").and_then(|f| f.as_str()).expect("fingerprint");
            assert!(fp.len() < 32, "full author key emitted: {fp}");
        }
    }

    for forbidden in [
        "getblocktemplate", "getwork", "submitblock", "setgenerate", "generatetoaddress",
        "node_shutdown", "stop", "net_addPeer", "net_ban", "net_disconnect", "wallet_sign",
        "dumpprivkey", "importprivkey", "author_publish", "checkpoint_add", "config_set",
        "chain_reindex", "chain_invalidateBlock",
    ] {
        let out = call(&node, &format!(r#"{{"jsonrpc":"2.0","method":"{forbidden}","id":1}}"#));
        assert!(out.contains("-32601"), "{forbidden} was not a MethodNotFound: {out}");
    }
}

#[test]
fn hostile_note_and_agent_stay_in_json() {
    let node = MockNode::synced().with_hostile_note().with_hostile_peer().into_node();
    for method in ["author_getNotes", "net_getPeerInfo"] {
        let out = call(&node, &format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":1}}"#));
        for raw in ['\u{1b}', '\r', '\n', '\u{2028}', '\u{2029}', '\u{202e}'] {
            assert!(!out.contains(raw), "{method} emitted a raw {raw:?}");
        }

        assert!(plaine_rpc::json::parse(out.as_bytes(), JsonLimits::default()).is_ok(), "{out}");
    }
}

#[test]
fn erroring_notification_answers_nothing() {
    let node = MockNode::synced().into_node();
    for payload in [
        r#"{"jsonrpc":"2.0","method":"nope"}"#,
        r#"{"jsonrpc":"2.0","method":"tx_sendRaw","params":["zz"]}"#,
        r#"{"jsonrpc":"2.0","method":"account_get","params":["bad"],"id":null}"#,
    ] {
        assert!(
            handle_body(&node, payload.as_bytes(), JsonLimits::request()).is_none(),
            "{payload} produced a response"
        );
    }
}
