use crate::json::{Json, JsonError, JsonErrorKind};

// cap requests per batch so one body can't fan out into unbounded work
pub const MAX_BATCH: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub method: String,
    pub params: Json,
    pub id: Option<Json>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    NotReady,
    NotFound,
    TxRejected,
    FeatureDisabled,
    Unauthorized,
    LimitExceeded,
    Busy,
    CheckpointRejected,
}

impl ErrorCode {
    pub fn code(self) -> i64 {
        // -327xx standard, -320xx ours; both frozen, a test pins every number.
        match self {
            ErrorCode::ParseError => -32700,
            ErrorCode::InvalidRequest => -32600,
            ErrorCode::MethodNotFound => -32601,
            ErrorCode::InvalidParams => -32602,
            ErrorCode::InternalError => -32603,
            ErrorCode::NotReady => -32000,
            ErrorCode::NotFound => -32001,
            ErrorCode::TxRejected => -32002,
            ErrorCode::FeatureDisabled => -32003,
            ErrorCode::Unauthorized => -32004,
            ErrorCode::LimitExceeded => -32005,
            ErrorCode::Busy => -32006,
            ErrorCode::CheckpointRejected => -32007,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::ParseError => "Parse error",
            ErrorCode::InvalidRequest => "Invalid Request",
            ErrorCode::MethodNotFound => "Method not found",
            ErrorCode::InvalidParams => "Invalid params",
            ErrorCode::InternalError => "Internal error",
            ErrorCode::NotReady => "Node not ready",
            ErrorCode::NotFound => "Not found",
            ErrorCode::TxRejected => "Transaction rejected",
            ErrorCode::FeatureDisabled => "Feature disabled",
            ErrorCode::Unauthorized => "Unauthorized",
            ErrorCode::LimitExceeded => "Limit exceeded",
            ErrorCode::Busy => "Busy",
            ErrorCode::CheckpointRejected => "Checkpoint rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: ErrorCode,
    pub detail: Option<String>,
    pub data: Option<Json>,
}

impl RpcError {
    pub fn new(code: ErrorCode) -> Self {
        RpcError {
            code,
            detail: None,
            data: None,
        }
    }

    pub fn detail(code: ErrorCode, detail: impl Into<String>) -> Self {
        RpcError {
            code,
            detail: Some(detail.into()),
            data: None,
        }
    }

    pub fn with_data(code: ErrorCode, detail: impl Into<String>, data: Json) -> Self {
        RpcError {
            code,
            detail: Some(detail.into()),
            data: Some(data),
        }
    }

    fn to_json(&self) -> Json {
        let mut members = vec![
            ("code".to_string(), Json::Int(self.code.code())),
            ("message".to_string(), Json::str(self.code.message())),
        ];
        let mut data_members: Vec<(String, Json)> = Vec::new();
        if let Some(d) = &self.detail {
            data_members.push(("detail".to_string(), Json::str(d.clone())));
        }
        if let Some(extra) = &self.data {
            data_members.push(("reason".to_string(), extra.clone()));
        }
        if !data_members.is_empty() {
            members.push(("data".to_string(), Json::Obj(data_members)));
        }
        Json::Obj(members)
    }
}

pub fn error_from_json(e: &JsonError) -> RpcError {
    let code = match e.kind {
        JsonErrorKind::TooLarge { .. }
        | JsonErrorKind::TooDeep { .. }
        | JsonErrorKind::TooManyValues { .. }
        | JsonErrorKind::TooManyMembers { .. } => ErrorCode::LimitExceeded,
        _ => ErrorCode::ParseError,
    };
    RpcError::detail(code, e.to_string())
}

pub fn parse_request(v: &Json) -> Result<Request, RpcError> {
    let Json::Obj(_) = v else {
        return Err(RpcError::detail(
            ErrorCode::InvalidRequest,
            "a request must be a JSON object (or an array of them for a batch)",
        ));
    };
    match v.get("jsonrpc").and_then(|j| j.as_str()) {
        Some("2.0") => {}
        Some(other) => {
            return Err(RpcError::detail(
                ErrorCode::InvalidRequest,
                format!("\"jsonrpc\" must be \"2.0\", found {other:?}"),
            ))
        }
        None => {
            return Err(RpcError::detail(
                ErrorCode::InvalidRequest,
                "missing \"jsonrpc\": \"2.0\"",
            ))
        }
    }
    let method = match v.get("method").and_then(|m| m.as_str()) {
        Some(m) => m.to_string(),
        None => {
            return Err(RpcError::detail(
                ErrorCode::InvalidRequest,
                "missing \"method\" (a string)",
            ))
        }
    };
    let params = match v.get("params") {
        None | Some(Json::Null) => Json::Arr(Vec::new()),
        Some(p @ Json::Arr(_)) | Some(p @ Json::Obj(_)) => p.clone(),
        Some(_) => {
            return Err(RpcError::detail(
                ErrorCode::InvalidRequest,
                "\"params\" must be an array (by position) or an object (by name)",
            ))
        }
    };

    // no id, or a null id, is a notification: no reply wanted
    let id = match v.get("id") {
        None | Some(Json::Null) => None,
        Some(i @ Json::Int(_)) | Some(i @ Json::Str(_)) => Some(i.clone()),
        Some(_) => {
            return Err(RpcError::detail(
                ErrorCode::InvalidRequest,
                "\"id\" must be a string or an integer",
            ))
        }
    };
    Ok(Request { method, params, id })
}

pub fn success(id: &Json, result: Json) -> Json {
    Json::Obj(vec![
        ("jsonrpc".to_string(), Json::str("2.0")),
        ("result".to_string(), result),
        ("id".to_string(), id.clone()),
    ])
}

pub fn failure(id: Json, err: &RpcError) -> Json {
    Json::Obj(vec![
        ("jsonrpc".to_string(), Json::str("2.0")),
        ("error".to_string(), err.to_json()),
        ("id".to_string(), id),
    ])
}

pub fn param<'a>(params: &'a Json, index: usize, name: &str) -> Option<&'a Json> {
    match params {
        Json::Arr(items) => items.get(index),
        Json::Obj(_) => params.get(name),
        _ => None,
    }
}

pub fn param_count(params: &Json) -> usize {
    match params {
        Json::Arr(items) => items.len(),
        Json::Obj(members) => members.len(),
        _ => 0,
    }
}

pub fn u64_param(params: &Json, index: usize, name: &str) -> Result<u64, RpcError> {
    match param(params, index, name) {
        Some(Json::Int(i)) if *i >= 0 => Ok(*i as u64),
        Some(Json::Int(i)) => Err(RpcError::detail(
            ErrorCode::InvalidParams,
            format!("`{name}` must not be negative, got {i}"),
        )),
        Some(_) => Err(RpcError::detail(
            ErrorCode::InvalidParams,
            format!("`{name}` must be a non-negative integer"),
        )),
        None => Err(RpcError::detail(
            ErrorCode::InvalidParams,
            format!("missing parameter `{name}` (position {index})"),
        )),
    }
}

pub fn opt_u64_param(params: &Json, index: usize, name: &str) -> Result<Option<u64>, RpcError> {
    match param(params, index, name) {
        None | Some(Json::Null) => Ok(None),
        _ => u64_param(params, index, name).map(Some),
    }
}

pub fn str_param<'a>(params: &'a Json, index: usize, name: &str) -> Result<&'a str, RpcError> {
    match param(params, index, name) {
        Some(Json::Str(s)) => Ok(s.as_str()),
        Some(_) => Err(RpcError::detail(
            ErrorCode::InvalidParams,
            format!("`{name}` must be a string"),
        )),
        None => Err(RpcError::detail(
            ErrorCode::InvalidParams,
            format!("missing parameter `{name}` (position {index})"),
        )),
    }
}

pub fn hash_param(params: &Json, index: usize, name: &str) -> Result<[u8; 32], RpcError> {
    let s = str_param(params, index, name)?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    // length first, so a wrong-length hash names that instead of a generic hex failure
    if s.len() != 64 {
        return Err(RpcError::detail(
            ErrorCode::InvalidParams,
            format!(
                "`{name}` must be 64 hex characters (32 bytes), got {}",
                s.len()
            ),
        ));
    }
    let bytes = plaine_consensus::hex::decode(s).map_err(|_| {
        RpcError::detail(
            ErrorCode::InvalidParams,
            format!("`{name}` is not valid hex"),
        )
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{parse, JsonLimits};

    fn v(s: &str) -> Json {
        parse(s.as_bytes(), JsonLimits::default()).unwrap()
    }

    #[test]
    fn well_formed_request_parses() {
        let r = parse_request(&v(r#"{"jsonrpc":"2.0","method":"chain_getInfo","id":7}"#)).unwrap();
        assert_eq!(r.method, "chain_getInfo");
        assert_eq!(r.id, Some(Json::Int(7)));
        assert_eq!(r.params, Json::Arr(vec![]));
    }

    #[test]
    fn version_one_clients_refused() {
        let e = parse_request(&v(r#"{"method":"chain_getInfo","id":1}"#)).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidRequest);
        assert!(e.detail.unwrap().contains("jsonrpc"));
    }

    #[test]
    fn missing_id_is_a_notification() {
        let r = parse_request(&v(r#"{"jsonrpc":"2.0","method":"chain_getInfo"}"#)).unwrap();
        assert!(r.id.is_none());
    }

    #[test]
    fn bad_params_and_id_shapes_refused() {
        for bad in ["7", r#""a""#, "true", "1.0e2"] {
            let body =
                format!(r#"{{"jsonrpc":"2.0","method":"chain_getInfo","params":{bad},"id":1}}"#);

            let Ok(value) = parse(body.as_bytes(), JsonLimits::default()) else {
                continue;
            };
            match parse_request(&value) {
                Err(e) => assert_eq!(e.code, ErrorCode::InvalidRequest, r#""params": {bad}"#),
                Ok(r) => panic!(r#""params": {bad} was accepted as {:?}"#, r.params),
            }
        }

        for good in ["[1]", r#"{"height":1}"#, "null"] {
            let body =
                format!(r#"{{"jsonrpc":"2.0","method":"chain_getInfo","params":{good},"id":1}}"#);
            assert!(
                parse_request(&v(&body)).is_ok(),
                r#""params": {good} was refused"#
            );
        }

        for bad in ["{}", "[]", "true", r#"{"a":1}"#] {
            let body = format!(r#"{{"jsonrpc":"2.0","method":"chain_getInfo","id":{bad}}}"#);
            match parse_request(&v(&body)) {
                Err(e) => assert_eq!(e.code, ErrorCode::InvalidRequest, r#""id": {bad}"#),
                Ok(_) => panic!(r#""id": {bad} was accepted as a correlation id"#),
            }
        }

        for good in ["1", r#""abc""#] {
            let body = format!(r#"{{"jsonrpc":"2.0","method":"chain_getInfo","id":{good}}}"#);
            assert!(
                parse_request(&v(&body)).expect("ok").id.is_some(),
                r#""id": {good}"#
            );
        }
    }

    #[test]
    fn named_and_positional_params_agree() {
        let by_pos = v(r#"[12345]"#);
        let by_name = v(r#"{"height":12345}"#);
        assert_eq!(u64_param(&by_pos, 0, "height").unwrap(), 12345);
        assert_eq!(u64_param(&by_name, 0, "height").unwrap(), 12345);
    }

    #[test]
    fn hash_param_error_is_specific() {
        let short = v(r#"["abc"]"#);
        let msg = hash_param(&short, 0, "hash").unwrap_err().detail.unwrap();
        assert!(msg.contains("got 3"), "{msg}");
        let good = v(r#"["0000000000000000000000000000000000000000000000000000000000000001"]"#);
        assert_eq!(hash_param(&good, 0, "hash").unwrap()[31], 1);
    }

    #[test]
    fn error_codes_are_frozen_numbers() {
        assert_eq!(ErrorCode::ParseError.code(), -32700);
        assert_eq!(ErrorCode::InvalidRequest.code(), -32600);
        assert_eq!(ErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(ErrorCode::InvalidParams.code(), -32602);
        assert_eq!(ErrorCode::InternalError.code(), -32603);
        assert_eq!(ErrorCode::NotReady.code(), -32000);
        assert_eq!(ErrorCode::NotFound.code(), -32001);
        assert_eq!(ErrorCode::TxRejected.code(), -32002);
        assert_eq!(ErrorCode::FeatureDisabled.code(), -32003);
        assert_eq!(ErrorCode::Unauthorized.code(), -32004);
        assert_eq!(ErrorCode::LimitExceeded.code(), -32005);
        assert_eq!(ErrorCode::Busy.code(), -32006);
    }

    #[test]
    fn responses_have_required_members() {
        let ok = success(&Json::Int(1), Json::Bool(true)).to_string();
        assert_eq!(ok, r#"{"jsonrpc":"2.0","result":true,"id":1}"#);
        let bad = failure(
            Json::Null,
            &RpcError::detail(ErrorCode::NotFound, "no such block"),
        );
        assert_eq!(
            bad.to_string(),
            r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Not found","data":{"detail":"no such block"}},"id":null}"#
        );
    }
}
