use plaine_rpc::json::Json;
use plaine_rpc::jsonrpc::{ErrorCode, Request};
use plaine_rpc::mock::MockNode;
use plaine_rpc::views::{
    AuthorKeyStatus, CheckpointLink, CheckpointStatus, CheckpointSubmit, KeySource, Node,
    PolicyView,
};

fn ask(node: &Node, params: Vec<Json>) -> Result<Json, plaine_rpc::jsonrpc::RpcError> {
    plaine_rpc::methods::dispatch(
        node,
        &Request {
            method: "checkpoint_submit".into(),
            params: Json::Arr(params),
            id: None,
        },
    )
}

fn hexed(bytes: &[u8]) -> Json {
    Json::str(plaine_consensus::hex::encode(bytes))
}

struct Fixed(CheckpointSubmit);

impl PolicyView for Fixed {
    fn checkpoint_status(&self) -> CheckpointStatus {
        CheckpointStatus {
            enabled: true,
            key_source: KeySource::Config,
            key_fingerprints: vec!["deadbeef".into()],
            threshold: 1,
            last_anchor: None,
            enforced_count: 0,
            sunset_height: plaine_consensus::constants::CHECKPOINT_SUNSET_HEIGHT,
            blocks_until_sunset: Some(1),
            sunset_passed: false,
        }
    }
    fn checkpoint_link(&self) -> CheckpointLink {
        CheckpointLink::Live {
            last_anchor: None,
            enforced: 0,
        }
    }
    fn checkpoint_submit(
        &self,
        _cp: &plaine_consensus::rules::SignedCheckpoint,
    ) -> CheckpointSubmit {
        self.0
    }
    fn author_key_status(&self) -> AuthorKeyStatus {
        AuthorKeyStatus {
            enabled: true,
            key_source: KeySource::Embedded,
            fingerprint: "0badf00d".into(),
            show_in_log: false,
        }
    }
}

fn with(out: CheckpointSubmit) -> Node {
    let me = std::sync::Arc::new(MockNode::synced());
    Node {
        chain: me.clone(),
        mempool: me.clone(),
        net: me.clone(),
        stratum: me.clone(),
        policy: std::sync::Arc::new(Fixed(out)),
        budgets: me,
    }
}

fn record(height: u64, sigs: usize) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&[0x33; 32]);
    v.push(sigs as u8);
    for i in 0..sigs {
        v.extend_from_slice(&[0x40 + i as u8; 32]);
        v.extend_from_slice(&[0x80 + i as u8; 64]);
    }
    v
}

#[test]
fn busy_chain_says_retry_not_rebuild() {
    let e = ask(&with(CheckpointSubmit::Busy), vec![hexed(&record(900, 1))]).unwrap_err();

    assert_eq!(
        e.code,
        ErrorCode::NotReady,
        "a busy chain must be retryable; FeatureDisabled and CheckpointRejected are both terminal"
    );
    assert_eq!(e.data.as_ref().and_then(|d| d.as_str()), Some("busy"));

    let d = e.detail.as_deref().unwrap_or("").to_lowercase();
    assert!(
        d.contains("retry"),
        "the operator must be told to retry: {d}"
    );
    assert!(
        d.contains("not looked at") || d.contains("not verified"),
        "it must say the record was never examined, or the operator goes to the signer: {d}"
    );

    assert!(
        !d.contains("no configuration fixes"),
        "sends the operator to rebuild a binary: {d}"
    );
    assert!(
        !d.contains("does not verify"),
        "sends the operator to the offline signer: {d}"
    );
    assert!(
        !d.contains("signer that produced it"),
        "same, by another route: {d}"
    );
}

#[test]
fn real_refusal_is_terminal_and_distinct() {
    for (out, code) in [
        (CheckpointSubmit::Unverified, ErrorCode::CheckpointRejected),
        (
            CheckpointSubmit::GenesisImmutable,
            ErrorCode::CheckpointRejected,
        ),
        (CheckpointSubmit::NotConfigured, ErrorCode::FeatureDisabled),
        (CheckpointSubmit::Severed, ErrorCode::FeatureDisabled),
    ] {
        let e = ask(&with(out), vec![hexed(&record(900, 1))]).unwrap_err();
        assert_eq!(e.code, code, "{out:?}");
        assert_ne!(
            e.code,
            ErrorCode::NotReady,
            "{out:?} must not read as retryable"
        );
        assert_eq!(e.data.as_ref().and_then(|d| d.as_str()), Some(out.tag()));
    }

    let tags: Vec<&str> = [
        CheckpointSubmit::Advanced {
            height: 1,
            enforced: 0,
            enforcing: false,
        },
        CheckpointSubmit::Unchanged,
        CheckpointSubmit::GenesisImmutable,
        CheckpointSubmit::Unverified,
        CheckpointSubmit::NotConfigured,
        CheckpointSubmit::Severed,
        CheckpointSubmit::Busy,
    ]
    .iter()
    .map(|o| o.tag())
    .collect();
    let mut sorted = tags.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        tags.len(),
        "two outcomes share a machine-readable tag: {tags:?}"
    );
}

#[test]
fn oversized_record_dies_on_length_check() {
    struct Exploding;
    impl PolicyView for Exploding {
        fn checkpoint_status(&self) -> CheckpointStatus {
            Fixed(CheckpointSubmit::Unchanged).checkpoint_status()
        }
        fn checkpoint_link(&self) -> CheckpointLink {
            CheckpointLink::Live {
                last_anchor: None,
                enforced: 0,
            }
        }
        fn checkpoint_submit(
            &self,
            _cp: &plaine_consensus::rules::SignedCheckpoint,
        ) -> CheckpointSubmit {
            panic!("the dispatcher passed an oversized record through to the chain");
        }
        fn author_key_status(&self) -> AuthorKeyStatus {
            Fixed(CheckpointSubmit::Unchanged).author_key_status()
        }
    }
    let me = std::sync::Arc::new(MockNode::synced());
    let node = Node {
        chain: me.clone(),
        mempool: me.clone(),
        net: me.clone(),
        stratum: me.clone(),
        policy: std::sync::Arc::new(Exploding),
        budgets: me,
    };

    let over = "00".repeat(plaine_consensus::checkpoint_record::MAX_BYTES + 1);
    let e = ask(&node, vec![Json::str(over)]).unwrap_err();
    assert_eq!(e.code, ErrorCode::LimitExceeded);

    let flood = "ab".repeat(500_000);
    let e = ask(&node, vec![Json::str(flood)]).unwrap_err();
    assert_eq!(e.code, ErrorCode::LimitExceeded);
}

#[test]
fn lying_sig_count_never_allocates() {
    let node = with(CheckpointSubmit::Unchanged);
    let mut r = record(900, 1);
    r[41] = 255;
    let e = ask(&node, vec![hexed(&r)]).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidParams);
    assert_eq!(e.data.as_ref().and_then(|d| d.as_str()), Some("malformed"));

    let d = e.detail.as_deref().unwrap_or("");
    assert!(d.contains("too many signatures"), "{d}");
}

#[test]
fn unverified_refusal_is_not_an_oracle() {
    let e = ask(
        &with(CheckpointSubmit::Unverified),
        vec![hexed(&record(900, 1))],
    )
    .unwrap_err();
    let all = format!(
        "{} {}",
        e.detail.as_deref().unwrap_or(""),
        e.data.as_ref().and_then(|d| d.as_str()).unwrap_or("")
    )
    .to_lowercase();
    for oracle in [
        "threshold not met",
        "zero hash",
        "sunset reached",
        "too many signatures",
        "unknown key",
        "signature 0",
    ] {
        assert!(
            !all.contains(oracle),
            "the refusal names the failing check ({oracle}): {all}"
        );
    }
}

#[test]
fn refusal_never_echoes_bytes() {
    let node = with(CheckpointSubmit::Unverified);
    let marker = 0xEDu8;
    let mut r = record(0xDEAD_BEEF, 1);
    for b in r.iter_mut().skip(42) {
        *b = marker;
    }
    let hex = plaine_consensus::hex::encode(&r);
    for params in [
        vec![Json::str(hex.clone())],
        vec![Json::str(hex[..hex.len() - 8].to_string())],
    ] {
        let e = ask(&node, params).unwrap_err();
        let all = format!("{} {:?}", e.detail.as_deref().unwrap_or(""), e.data);
        assert!(!all.contains(&hex), "the whole record came back");
        assert!(
            !all.contains("edededed"),
            "signature bytes came back: {all}"
        );
        assert!(
            !all.contains("3735928559"),
            "the decoded height came back: {all}"
        );
    }
}

#[test]
fn param_shape_checked_before_content() {
    let node = with(CheckpointSubmit::Unchanged);
    for params in [
        vec![],
        vec![Json::str("00".repeat(42)), Json::str("extra".to_string())],
        vec![Json::u64(1234)],
        vec![Json::Null],
        vec![Json::Arr(vec![Json::str("00".repeat(42))])],
    ] {
        let e = ask(&node, params).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidParams);
    }
}

#[test]
fn only_real_advance_is_reported() {
    let v = ask(
        &with(CheckpointSubmit::Unchanged),
        vec![hexed(&record(900, 1))],
    )
    .expect("200");
    assert_eq!(v.get("anchorAdvanced").unwrap().as_bool(), Some(false));
    assert_eq!(v.get("result").unwrap().as_str(), Some("unchanged"));

    let v = ask(
        &with(CheckpointSubmit::Advanced {
            height: 900,
            enforced: 2,
            enforcing: true,
        }),
        vec![hexed(&record(900, 1))],
    )
    .expect("200");
    assert_eq!(v.get("anchorAdvanced").unwrap().as_bool(), Some(true));
    assert_eq!(v.get("height").unwrap().as_int(), Some(900));
}
