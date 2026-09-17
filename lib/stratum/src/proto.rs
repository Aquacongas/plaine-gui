use crate::json::{self, Doc, JsonError};
use crate::limits::{E1_BITS, MINER_ROLLABLE_BYTES};
use crate::nonce::E1;
use crate::target::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UnknownJob,
    StaleShare,
    DuplicateShare,
    LowDifficulty,
    Unauthorized,
    NonceOutOfSlice,
    Throttled,
    Banned,
    ServerBusy,
    UnknownMethod,
    BadMessage,
    SliceRevoked,
}

impl ErrorCode {
    pub fn code(self) -> u64 {
        match self {
            ErrorCode::UnknownJob => 20,
            ErrorCode::StaleShare => 21,
            ErrorCode::DuplicateShare => 22,
            ErrorCode::LowDifficulty => 23,
            ErrorCode::Unauthorized => 24,
            ErrorCode::NonceOutOfSlice => 25,
            ErrorCode::Throttled => 26,
            ErrorCode::Banned => 27,
            ErrorCode::ServerBusy => 28,
            ErrorCode::UnknownMethod => 29,
            ErrorCode::BadMessage => 30,
            ErrorCode::SliceRevoked => 31,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::UnknownJob => "unknown job",
            ErrorCode::StaleShare => "stale share",
            ErrorCode::DuplicateShare => "duplicate share",
            ErrorCode::LowDifficulty => "low difficulty",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::NonceOutOfSlice => "nonce out of slice",
            ErrorCode::Throttled => "throttled",
            ErrorCode::Banned => "banned",
            ErrorCode::ServerBusy => "server busy",
            ErrorCode::UnknownMethod => "unknown method",
            ErrorCode::BadMessage => "bad message",
            ErrorCode::SliceRevoked => "slice revoked",
        }
    }

    // Banscore per error. Soft codes are honest-miner mistakes that decay before
    // the hard ones. The zero-point codes (throttled, banned, busy, revoked) are
    // our backpressure or upstream's doing, not the client's, so they never score.
    pub fn penalty(self) -> (u32, crate::abuse::Severity) {
        use crate::abuse::Severity::{Hard, Soft};
        match self {
            ErrorCode::UnknownJob => (2, Soft),
            ErrorCode::StaleShare => (1, Soft),
            ErrorCode::DuplicateShare => (25, Hard),
            ErrorCode::LowDifficulty => (10, Hard),
            ErrorCode::Unauthorized => (25, Hard),
            ErrorCode::NonceOutOfSlice => (50, Hard),
            ErrorCode::Throttled => (0, Hard),
            ErrorCode::Banned => (0, Hard),
            ErrorCode::ServerBusy => (0, Hard),
            ErrorCode::UnknownMethod => (5, Soft),
            ErrorCode::BadMessage => (50, Hard),
            ErrorCode::SliceRevoked => (0, Hard),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Subscribe {
        id: Option<u64>,
        user_agent: String,
    },

    Authorize {
        id: Option<u64>,
        login: String,
    },

    Submit {
        id: Option<u64>,
        job_id: u32,
        nonce: u64,
    },

    Unknown {
        id: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Json(JsonError),
    Shape,
    BadShareFields,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    Request(Request),

    KeepAlive { id: Option<u64> },
}

pub fn parse_verb(doc: &mut Doc, line: &[u8], max_len: usize) -> Result<Verb, ParseError> {
    let root = json::parse(doc, line, max_len).map_err(ParseError::Json)?;
    let id = doc.obj_get(root, "id").and_then(|v| doc.as_u64(v));
    let method = doc
        .obj_get(root, "method")
        .and_then(|v| doc.as_str(v))
        .ok_or(ParseError::Shape)?;

    let params = doc.obj_get(root, "params");
    let param_str = |i: usize| -> Option<&str> {
        params
            .and_then(|p| doc.arr_get(p, i))
            .and_then(|v| doc.as_str(v))
    };

    match method {
        "mining.subscribe" => Ok(Verb::Request(Request::Subscribe {
            id,
            user_agent: param_str(0).unwrap_or("").to_string(),
        })),
        "mining.keepalive" => Ok(Verb::KeepAlive { id }),
        "mining.authorize" => {
            let login = param_str(0).ok_or(ParseError::Shape)?.to_string();
            Ok(Verb::Request(Request::Authorize { id, login }))
        }
        "mining.submit" => {
            if param_str(0).is_none() {
                return Err(ParseError::Shape);
            }
            let job_hex = param_str(1).ok_or(ParseError::Shape)?;
            let nonce_hex = param_str(2).ok_or(ParseError::Shape)?;
            let job_id = parse_job_id(job_hex).ok_or(ParseError::BadShareFields)?;
            let nonce =
                crate::nonce::parse_nonce_hex(nonce_hex).ok_or(ParseError::BadShareFields)?;
            Ok(Verb::Request(Request::Submit { id, job_id, nonce }))
        }
        _ => Ok(Verb::Request(Request::Unknown { id })),
    }
}

fn parse_job_id(s: &str) -> Option<u32> {
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

pub fn write_ok_true(out: &mut Vec<u8>, id: Option<u64>) {
    out.extend_from_slice(b"{\"id\":");
    write_id(out, id);
    out.extend_from_slice(b",\"result\":true,\"error\":null}\n");
}

pub fn write_error(out: &mut Vec<u8>, id: Option<u64>, e: ErrorCode) {
    out.extend_from_slice(b"{\"id\":");
    write_id(out, id);
    out.extend_from_slice(b",\"result\":null,\"error\":[");
    json::write_u64(out, e.code());
    out.push(b',');
    json::write_str(out, e.message());
    out.extend_from_slice(b",null]}\n");
}

pub fn write_subscribe_result(out: &mut Vec<u8>, id: Option<u64>, e1: E1, sub: u32, sub_bits: u32) {
    out.extend_from_slice(b"{\"id\":");
    write_id(out, id);
    out.extend_from_slice(b",\"result\":[[\"mining.notify\",\"mining.set_target\"],\"");

    let fixed = crate::nonce::slice_fixed(e1, sub, sub_bits);
    let width = ((E1_BITS + sub_bits) / 4) as usize;
    out.extend_from_slice(format!("{fixed:0width$x}").as_bytes());
    out.extend_from_slice(b"\",");
    json::write_u64(out, MINER_ROLLABLE_BYTES - u64::from(sub_bits / 8));
    out.extend_from_slice(b"],\"error\":null}\n");
}

pub fn write_set_target(out: &mut Vec<u8>, target: &Target) {
    out.extend_from_slice(b"{\"id\":null,\"method\":\"mining.set_target\",\"params\":[\"");
    json::write_hex(out, &target.0);
    out.extend_from_slice(b"\"]}\n");
}

pub fn write_notify(
    out: &mut Vec<u8>,
    job_id: u32,
    height: u64,
    prefix: &[u8; crate::limits::JOB_PREFIX_BYTES],
    clean: bool,
) {
    out.extend_from_slice(b"{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"");
    json::write_hex_u64(out, job_id as u64, 8);
    out.extend_from_slice(b"\",");
    json::write_u64(out, height);
    out.extend_from_slice(b",\"");
    json::write_hex(out, prefix);
    out.extend_from_slice(if clean {
        b"\",true]}\n"
    } else {
        b"\",false]}\n"
    });
}

pub fn write_reconnect(out: &mut Vec<u8>, host: &str, port: u16, wait_secs: u64) {
    out.extend_from_slice(b"{\"id\":null,\"method\":\"client.reconnect\",\"params\":[");
    json::write_str(out, host);
    out.push(b',');
    json::write_u64(out, port as u64);
    out.push(b',');
    json::write_u64(out, wait_secs.min(60));
    out.extend_from_slice(b"]}\n");
}

fn write_id(out: &mut Vec<u8>, id: Option<u64>) {
    match id {
        Some(n) => json::write_u64(out, n),
        None => out.extend_from_slice(b"null"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &str) -> Result<Request, ParseError> {
        let mut d = Doc::new();
        match parse_verb(&mut d, s.as_bytes(), crate::limits::MAX_LINE_POST_AUTH)? {
            Verb::Request(r) => Ok(r),
            Verb::KeepAlive { .. } => panic!("this line is a keepalive, not a Request: {s}"),
        }
    }

    fn s(v: Vec<u8>) -> String {
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn subscribe_exact_wire() {
        assert_eq!(
            req(r#"{"id":1,"method":"mining.subscribe","params":["plaine-miner/1.0"]}"#).unwrap(),
            Request::Subscribe {
                id: Some(1),
                user_agent: "plaine-miner/1.0".into()
            }
        );
        let mut out = Vec::new();
        write_subscribe_result(&mut out, Some(1), E1(0x00A3F2), 0, 0);
        assert_eq!(
            s(out),
            "{\"id\":1,\"result\":[[\"mining.notify\",\"mining.set_target\"],\"00a3f2\",5],\"error\":null}\n"
        );
    }

    #[test]
    fn subscribe_tolerates_zero_or_extra_params() {
        assert!(req(r#"{"id":1,"method":"mining.subscribe"}"#).is_ok());
        assert!(req(r#"{"id":1,"method":"mining.subscribe","params":[]}"#).is_ok());
        assert!(req(r#"{"id":1,"method":"mining.subscribe","params":["a","b"]}"#).is_ok());
    }

    #[test]
    fn authorize_exact_wire() {
        assert_eq!(
            req(r#"{"id":2,"method":"mining.authorize","params":["plne1qq.rig1","x"]}"#).unwrap(),
            Request::Authorize {
                id: Some(2),
                login: "plne1qq.rig1".into()
            }
        );
        let mut out = Vec::new();
        write_ok_true(&mut out, Some(2));
        assert_eq!(s(out), "{\"id\":2,\"result\":true,\"error\":null}\n");
    }

    #[test]
    fn submit_exact_wire_login_echo_inert() {
        let r =
            req(r#"{"id":7,"method":"mining.submit","params":["who.ever","0000002b","2a00000003f2a300"]}"#)
                .unwrap();
        match r {
            Request::Submit {
                id, job_id, nonce, ..
            } => {
                assert_eq!(id, Some(7));
                assert_eq!(job_id, 0x2b);
                assert_eq!(nonce, 0x00A3_F203_0000_002A);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn signed_job_id_refused() {
        assert_eq!(parse_job_id("0000002b"), Some(0x2b));
        assert_eq!(
            u32::from_str_radix("+000002b", 16),
            Ok(0x2b),
            "the differential is real"
        );
        assert_eq!(
            parse_job_id("+000002b"),
            None,
            "a signed job id is a second name for job 0x2b"
        );
        assert_eq!(parse_job_id("+0000000"), None);

        assert_eq!(
            req(
                r#"{"id":7,"method":"mining.submit","params":["w","+000002b","2a00000003f2a300"]}"#
            ),
            Err(ParseError::BadShareFields)
        );
    }

    #[test]
    fn submit_field_shapes_are_strict() {
        for bad in [
            r#"{"id":7,"method":"mining.submit","params":["w","2b","2a00000003f2a300"]}"#,
            r#"{"id":7,"method":"mining.submit","params":["w","000000zz","2a00000003f2a300"]}"#,
            r#"{"id":7,"method":"mining.submit","params":["w","0000002b","2a00000003f2a3"]}"#,
            r#"{"id":7,"method":"mining.submit","params":["w","0000002b","zzzzzzzzzzzzzzzz"]}"#,
        ] {
            assert_eq!(req(bad), Err(ParseError::BadShareFields), "{bad}");
        }
        for bad in [
            r#"{"id":7,"method":"mining.submit","params":["w","0000002b"]}"#,
            r#"{"id":7,"method":"mining.submit","params":[]}"#,
            r#"{"id":7,"method":"mining.submit"}"#,
            r#"{"id":7,"method":"mining.submit","params":["w",44,"2a00000003f2a300"]}"#,
        ] {
            assert_eq!(req(bad), Err(ParseError::Shape), "{bad}");
        }
    }

    #[test]
    fn unknown_methods_are_a_request_not_a_disconnect() {
        assert_eq!(
            req(r#"{"id":9,"method":"mining.extranonce.subscribe","params":[]}"#).unwrap(),
            Request::Unknown { id: Some(9) }
        );
        assert_eq!(
            req(r#"{"id":9,"method":"getblocktemplate","params":[]}"#).unwrap(),
            Request::Unknown { id: Some(9) },
            "there is no getblocktemplate; it is an unknown method"
        );
    }

    #[test]
    fn a_missing_method_is_a_shape_error() {
        assert_eq!(req(r#"{"id":1,"params":[]}"#), Err(ParseError::Shape));
        assert_eq!(req(r#"{"id":1,"method":5}"#), Err(ParseError::Shape));
    }

    #[test]
    fn notification_ids_are_null() {
        let mut out = Vec::new();
        write_notify(&mut out, 0x2b, 184_602, &[0xABu8; 124], true);
        let txt = s(out);
        assert!(txt.starts_with(
            r#"{"id":null,"method":"mining.notify","params":["0000002b",184602,"abab"#
        ));
        assert!(txt.ends_with("\",true]}\n"));

        let hex_start = txt.find(",\"ab").unwrap() + 2;
        let hex_end = txt.rfind("\",true").unwrap();
        assert_eq!(hex_end - hex_start, 248);
    }

    #[test]
    fn set_target_is_64_hex() {
        let mut out = Vec::new();
        write_set_target(&mut out, &Target::from_difficulty(8_192));
        assert_eq!(
            s(out),
            "{\"id\":null,\"method\":\"mining.set_target\",\"params\":[\"0008000000000000000000000000000000000000000000000000000000000000\"]}\n"
        );
    }

    #[test]
    fn error_wire_form() {
        let mut out = Vec::new();
        write_error(&mut out, Some(7), ErrorCode::NonceOutOfSlice);
        assert_eq!(
            s(out),
            "{\"id\":7,\"result\":null,\"error\":[25,\"nonce out of slice\",null]}\n"
        );
    }

    #[test]
    fn reconnect_clamps_wait() {
        let mut out = Vec::new();
        write_reconnect(&mut out, "eu.pool.example", 9259, 3_600);
        assert_eq!(
            s(out),
            "{\"id\":null,\"method\":\"client.reconnect\",\"params\":[\"eu.pool.example\",9259,60]}\n"
        );
    }

    #[test]
    fn unknown_method_probing_does_not_ban() {
        use crate::abuse::{BanTable, Severity};
        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(ErrorCode::UnknownMethod.penalty(), (5, Severity::Soft));

        let mut t = BanTable::new();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        for minute in 0..60u64 {
            for _ in 0..(20 * 3) {
                let (pts, sev) = ErrorCode::UnknownMethod.penalty();
                t.penalise(ip, pts, sev, minute * 60_000);
            }
            assert!(
                !t.is_banned(ip, minute * 60_000),
                "a farm of unported miners was banned for saying hello"
            );
        }
    }

    #[test]
    fn keepalive_is_a_verb_and_not_an_unknown_method() {
        let mut d = Doc::new();
        let line = br#"{"id":9,"method":"mining.keepalive"}"#;
        assert_eq!(
            parse_verb(&mut d, line, crate::limits::MAX_LINE_POST_AUTH),
            Ok(Verb::KeepAlive { id: Some(9) })
        );

        let mut out = Vec::new();
        write_ok_true(&mut out, Some(9));
        assert_eq!(
            s(out),
            "{\"id\":9,\"result\":true,\"error\":null}
"
        );
    }

    #[test]
    fn keepalive_ignores_whatever_params_it_is_sent() {
        for line in [
            r#"{"id":9,"method":"mining.keepalive"}"#,
            r#"{"id":9,"method":"mining.keepalive","params":[]}"#,
            r#"{"id":9,"method":"mining.keepalive","params":["1be0b7b6"]}"#,
        ] {
            let mut d = Doc::new();
            assert_eq!(
                parse_verb(&mut d, line.as_bytes(), crate::limits::MAX_LINE_POST_AUTH),
                Ok(Verb::KeepAlive { id: Some(9) }),
                "{line}"
            );
        }
    }

    #[test]
    fn keepalive_verb_vs_unknown_method() {
        let mut d = Doc::new();
        assert_eq!(
            parse_verb(
                &mut d,
                br#"{"id":9,"method":"mining.keepalive"}"#,
                crate::limits::MAX_LINE_POST_AUTH
            ),
            Ok(Verb::KeepAlive { id: Some(9) })
        );
        assert_eq!(
            parse_verb(
                &mut d,
                br#"{"id":9,"method":"mining.keepalived"}"#,
                crate::limits::MAX_LINE_POST_AUTH
            ),
            Ok(Verb::Request(Request::Unknown { id: Some(9) })),
            "one letter away from the verb is an unknown method, not a heartbeat"
        );
    }

    #[test]
    fn slice_revoked_is_code_31_and_never_scores() {
        assert_eq!(ErrorCode::SliceRevoked.code(), 31);
        assert_eq!(ErrorCode::SliceRevoked.message(), "slice revoked");
        assert_eq!(
            ErrorCode::SliceRevoked.penalty().0,
            0,
            "the client cannot cause a revocation, so it is never scored"
        );

        let mut out = Vec::new();
        write_error(&mut out, None, ErrorCode::SliceRevoked);
        assert_eq!(
            s(out),
            "{\"id\":null,\"result\":null,\"error\":[31,\"slice revoked\",null]}
"
        );
    }

    #[test]
    fn error_codes_are_distinct() {
        let all = [
            ErrorCode::UnknownJob,
            ErrorCode::StaleShare,
            ErrorCode::DuplicateShare,
            ErrorCode::LowDifficulty,
            ErrorCode::Unauthorized,
            ErrorCode::NonceOutOfSlice,
            ErrorCode::Throttled,
            ErrorCode::Banned,
            ErrorCode::ServerBusy,
            ErrorCode::UnknownMethod,
            ErrorCode::BadMessage,
            ErrorCode::SliceRevoked,
        ];
        let mut codes: Vec<u64> = all.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "two error codes collided");
        assert_eq!(codes.last(), Some(&31));
    }

    #[test]
    fn server_busy_never_scores() {
        assert_eq!(ErrorCode::ServerBusy.penalty().0, 0);
        assert_eq!(ErrorCode::ServerBusy.code(), 28);
    }

    #[test]
    fn documented_codes_match_the_register() {
        let table = [
            (ErrorCode::UnknownJob, 20u64, 2u32),
            (ErrorCode::StaleShare, 21, 1),
            (ErrorCode::DuplicateShare, 22, 25),
            (ErrorCode::LowDifficulty, 23, 10),
            (ErrorCode::Unauthorized, 24, 25),
            (ErrorCode::NonceOutOfSlice, 25, 50),
            (ErrorCode::Throttled, 26, 0),
            (ErrorCode::Banned, 27, 0),
            (ErrorCode::ServerBusy, 28, 0),
        ];
        for (e, code, pts) in table {
            assert_eq!(e.code(), code);
            assert_eq!(e.penalty().0, pts, "{e:?}");
        }
    }

    #[test]
    fn ids_pass_through_including_null_and_absent() {
        assert!(matches!(
            req(r#"{"id":null,"method":"mining.subscribe","params":[]}"#).unwrap(),
            Request::Subscribe { id: None, .. }
        ));
        assert!(matches!(
            req(r#"{"method":"mining.subscribe","params":[]}"#).unwrap(),
            Request::Subscribe { id: None, .. }
        ));
        let mut out = Vec::new();
        write_ok_true(&mut out, None);
        assert_eq!(s(out), "{\"id\":null,\"result\":true,\"error\":null}\n");
    }
}
