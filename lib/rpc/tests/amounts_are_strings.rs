use plaine_rpc::json::Json;
use plaine_rpc::jsonrpc::Request;
use plaine_rpc::methods::{dispatch, METHODS};
use plaine_rpc::mock::MockNode;
use plaine_rpc::views::Node;

const NAMED_AMOUNTS: &[&str] = &[
    "balance",
    "immature",
    "spendable",
    "amount",
    "fee",
    "reward",
    "fees",
];

fn is_decimal_integer(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn kind_of(v: &Json) -> &'static str {
    match v {
        Json::Int(_) => "a JSON NUMBER",
        Json::Null => "null",
        Json::Bool(_) => "a bool",
        Json::Arr(_) => "an array",
        Json::Obj(_) => "an object",
        Json::Str(_) => "a string",
    }
}

fn walk(whose: &str, key: Option<&str>, v: &Json, seen: &mut Vec<String>) {
    if let Some(k) = key {
        let suffixed = k.ends_with("Mile") || k.ends_with("mile");
        if suffixed || NAMED_AMOUNTS.contains(&k) {
            seen.push(format!("{whose}.{k}"));
            match v {
                Json::Str(s) => assert!(
                    is_decimal_integer(s),
                    "{whose}: `{k}` is a string but not a decimal integer: {s:?}"
                ),

                Json::Null => {}
                other => panic!(
                    "{whose}: `{k}` is an amount published as {}, not a decimal string: {}",
                    kind_of(other),
                    other
                ),
            }
        }
    }
    match v {
        Json::Obj(members) => {
            for (k, child) in members {
                walk(whose, Some(k), child, seen);
            }
        }
        Json::Arr(items) => {
            for child in items {
                walk(whose, key, child, seen);
            }
        }
        _ => {}
    }
}

fn call(node: &Node, method: &str, params: Vec<Json>) -> Option<Json> {
    dispatch(
        node,
        &Request {
            method: method.into(),
            params: Json::Arr(params),
            id: Some(Json::Int(1)),
        },
    )
    .ok()
}

#[test]
fn no_amount_is_a_json_number() {
    let addr = MockNode::sample_address();
    let mut seen: Vec<String> = Vec::new();
    let mut answers = 0usize;

    let nodes: Vec<(&str, Node)> = vec![
        ("synced", MockNode::synced().into_node()),
        ("txindex", MockNode::synced().with_txindex().into_node()),
        ("notes", MockNode::synced().with_notes().into_node()),
        ("stalled", MockNode::stalled().into_node()),
        ("pruned", MockNode::synced().pruned_at(5).into_node()),
        (
            "no-checkpoints",
            MockNode::synced().with_checkpoints_disabled().into_node(),
        ),
    ];

    for (tag, node) in &nodes {
        for m in METHODS {
            let param_sets: Vec<Vec<Json>> = match *m {
                "chain_getHeaderByHeight" | "chain_getBlockByHeight" => {
                    vec![vec![Json::Int(0)], vec![Json::Int(1)], vec![Json::Int(2)]]
                }
                "account_get" | "mempool_getBySender" => vec![vec![Json::str(addr.clone())]],
                "tx_get" => vec![vec![Json::str("00".repeat(32))]],
                "emission_audit" => vec![vec![]],
                "author_getNotes" => vec![vec![], vec![Json::Null, Json::Int(10)]],
                "tx_sendRaw" | "checkpoint_submit" => vec![],
                "chain_getHeaderByHash" | "chain_getBlockByHash" => vec![],
                _ => vec![vec![]],
            };
            for params in param_sets {
                if let Some(v) = call(node, m, params) {
                    answers += 1;
                    walk(&format!("{tag}/{m}"), None, &v, &mut seen);
                }
            }
        }
    }

    assert!(
        answers >= 40,
        "only {answers} answers were walked; coverage of the surface dropped"
    );
    seen.sort();
    seen.dedup();
    assert!(
        seen.len() >= 12,
        "only {} distinct amount fields were reached: {seen:#?}",
        seen.len()
    );

    for must in [
        "issuedMile",
        "expectedByFormulaMile",
        "differenceMile",
        "maxSupplyMile",
        "subsidyAtHeightMile",
        "relayFeeMile",
        "consensusFeeFloorMile",
        "p50Mile",
        "spendable",
        "immature",
        "balance",
    ] {
        assert!(
            seen.iter().any(|s| s.ends_with(&format!(".{must}"))),
            "`{must}` was never reached, so nothing here defends it. Reached: {seen:#?}"
        );
    }
}

#[test]
fn emission_difference_is_signed() {
    let node = MockNode::synced().into_node();
    let v = call(&node, "emission_audit", vec![]).expect("emission_audit answers");
    let issued: i128 = v
        .get("issuedMile")
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let expected: i128 = v
        .get("expectedByFormulaMile")
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let diff: i128 = v
        .get("differenceMile")
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    assert_eq!(
        diff,
        issued - expected,
        "differenceMile must be issued - expected"
    );
    assert_eq!(
        v.get("matchesFormula").unwrap().as_bool().unwrap(),
        diff == 0,
        "matchesFormula and differenceMile must agree, or one of them is decoration"
    );

    if diff == 0 {
        assert_eq!(v.get("differenceMile").unwrap().as_str().unwrap(), "0");
    }
}
