use core::fmt;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn obj(members: Vec<(String, Json)>) -> Json {
        Json::Obj(members)
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn u64(v: u64) -> Json {
        Json::Int(v.min(i64::MAX as u64) as i64)
    }

    // amounts go out as decimal strings: a mile can exceed 2^53 and a JS client would round a number.
    pub fn mile(v: u128) -> Json {
        Json::Str(v.to_string())
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(i) => out.push_str(&i.to_string()),
            Json::Str(s) => write_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(members) => {
                out.push('{');
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[derive(Clone, Copy, Debug)]
pub struct JsonLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_values: usize,
    pub max_members: usize,
}

impl Default for JsonLimits {
    fn default() -> Self {
        JsonLimits {
            max_bytes: 1024 * 1024,
            // bounded so a nesting bomb is refused before it becomes stack frames
            max_depth: 16,
            max_values: 65_536,
            max_members: 4_096,
        }
    }
}

impl JsonLimits {
    pub fn request() -> Self {
        JsonLimits { max_bytes: 1024 * 1024, max_depth: 16, max_values: 65_536, max_members: 4_096 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError {
    pub kind: JsonErrorKind,
    pub offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonErrorKind {
    TooLarge {
        len: usize,
        max: usize,
    },
    TooDeep {
        max: usize,
    },
    TooManyValues {
        max: usize,
    },
    TooManyMembers {
        max: usize,
    },
    UnexpectedEnd,
    Unexpected {
        found: char,
    },
    FloatRejected,
    IntegerOutOfRange,
    BadEscape,
    BadString,
    DuplicateKey {
        key: String,
    },
    TrailingBytes,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            JsonErrorKind::TooLarge { len, max } => {
                write!(f, "request body is {len} bytes, limit is {max}")
            }
            JsonErrorKind::TooDeep { max } => {
                write!(f, "JSON nested deeper than {max} levels at byte {}", self.offset)
            }
            JsonErrorKind::TooManyValues { max } => {
                write!(f, "JSON holds more than {max} values")
            }
            JsonErrorKind::TooManyMembers { max } => {
                write!(f, "a JSON array or object holds more than {max} entries at byte {}", self.offset)
            }
            JsonErrorKind::UnexpectedEnd => write!(f, "JSON ended unexpectedly at byte {}", self.offset),
            JsonErrorKind::Unexpected { found } => {
                write!(f, "unexpected character {found:?} at byte {}", self.offset)
            }
            JsonErrorKind::FloatRejected => write!(
                f,
                "fractional numbers are not accepted at byte {} - Plaine uses no floating point \
                 anywhere, and amounts are decimal strings of mile (a u128 does not survive a \
                 double)",
                self.offset
            ),
            JsonErrorKind::IntegerOutOfRange => {
                write!(f, "integer out of range at byte {} (i64 only)", self.offset)
            }
            JsonErrorKind::BadEscape => write!(f, "bad string escape at byte {}", self.offset),
            JsonErrorKind::BadString => write!(f, "invalid string at byte {}", self.offset),
            JsonErrorKind::DuplicateKey { key } => write!(
                f,
                "duplicate object key {key:?} at byte {} - rejected rather than last-wins, so \
                 that no two readers can disagree about which one counts",
                self.offset
            ),
            JsonErrorKind::TrailingBytes => {
                write!(f, "trailing bytes after the JSON value at byte {}", self.offset)
            }
        }
    }
}

impl std::error::Error for JsonError {}

pub fn parse(input: &[u8], limits: JsonLimits) -> Result<Json, JsonError> {
    if input.len() > limits.max_bytes {
        return Err(JsonError {
            kind: JsonErrorKind::TooLarge { len: input.len(), max: limits.max_bytes },
            offset: 0,
        });
    }
    let mut p = Parser { input, pos: 0, limits, values: 0, keys: RandomState::new() };
    p.skip_ws();
    let v = p.value(0)?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(p.err(JsonErrorKind::TrailingBytes));
    }
    Ok(v)
}

// below this many members a linear dup-key scan beats hashing; above it we build an index so the
// check stays linear rather than O(members^2).
const DUP_KEY_LINEAR_SCAN_MAX: usize = 16;

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    limits: JsonLimits,
    values: usize,
    keys: RandomState,
}

fn hash_key(state: &RandomState, key: &str) -> u64 {
    state.hash_one(key)
}

impl<'a> Parser<'a> {
    fn err(&self, kind: JsonErrorKind) -> JsonError {
        JsonError { kind, offset: self.pos }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn count_value(&mut self) -> Result<(), JsonError> {
        self.values += 1;
        if self.values > self.limits.max_values {
            return Err(self.err(JsonErrorKind::TooManyValues { max: self.limits.max_values }));
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        if depth > self.limits.max_depth {
            return Err(self.err(JsonErrorKind::TooDeep { max: self.limits.max_depth }));
        }
        self.count_value()?;
        let b = self.peek().ok_or_else(|| self.err(JsonErrorKind::UnexpectedEnd))?;
        match b {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.literal(b"true", Json::Bool(true)),
            b'f' => self.literal(b"false", Json::Bool(false)),
            b'n' => self.literal(b"null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            other => Err(self.err(JsonErrorKind::Unexpected { found: other as char })),
        }
    }

    fn literal(&mut self, want: &[u8], v: Json) -> Result<Json, JsonError> {
        if self.input.len() < self.pos + want.len()
            || &self.input[self.pos..self.pos + want.len()] != want
        {
            return Err(self.err(JsonErrorKind::Unexpected { found: self.peek().unwrap_or(b'?') as char }));
        }
        self.pos += want.len();
        Ok(v)
    }

    fn object(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.pos += 1;
        let mut members: Vec<(String, Json)> = Vec::new();

        let mut seen: Option<std::collections::HashSet<u64>> = None;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err(JsonErrorKind::Unexpected {
                    found: self.peek().unwrap_or(b'?') as char,
                }));
            }
            let key = self.string()?;

            let key_hash = hash_key(&self.keys, &key);
            let duplicate = match &seen {
                Some(set) => set.contains(&key_hash) && members.iter().any(|(k, _)| *k == key),
                None => members.iter().any(|(k, _)| *k == key),
            };
            if duplicate {
                return Err(self.err(JsonErrorKind::DuplicateKey { key }));
            }
            if members.len() + 1 > self.limits.max_members {
                return Err(self.err(JsonErrorKind::TooManyMembers { max: self.limits.max_members }));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err(JsonErrorKind::Unexpected {
                    found: self.peek().unwrap_or(b'?') as char,
                }));
            }
            self.pos += 1;
            self.skip_ws();
            let v = self.value(depth + 1)?;
            members.push((key, v));
            if let Some(set) = &mut seen {
                set.insert(key_hash);
            } else if members.len() >= DUP_KEY_LINEAR_SCAN_MAX {
                seen = Some(members.iter().map(|(k, _)| hash_key(&self.keys, k)).collect());
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(members));
                }
                Some(other) => return Err(self.err(JsonErrorKind::Unexpected { found: other as char })),
                None => return Err(self.err(JsonErrorKind::UnexpectedEnd)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.pos += 1;
        let mut items: Vec<Json> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            if items.len() + 1 > self.limits.max_members {
                return Err(self.err(JsonErrorKind::TooManyMembers { max: self.limits.max_members }));
            }
            let v = self.value(depth + 1)?;
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                Some(other) => return Err(self.err(JsonErrorKind::Unexpected { found: other as char })),
                None => return Err(self.err(JsonErrorKind::UnexpectedEnd)),
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err(self.err(JsonErrorKind::Unexpected { found: self.peek().unwrap_or(b'?') as char }));
        }

        // no leading zeroes; reject "012" rather than read it as 12
        if self.input[digits_start] == b'0' && self.pos - digits_start > 1 {
            self.pos = digits_start;
            return Err(self.err(JsonErrorKind::Unexpected { found: '0' }));
        }
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            return Err(self.err(JsonErrorKind::FloatRejected));
        }
        let text = core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| self.err(JsonErrorKind::BadString))?;
        let n: i64 = text.parse().map_err(|_| JsonError {
            kind: JsonErrorKind::IntegerOutOfRange,
            offset: start,
        })?;
        Ok(Json::Int(n))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = self.peek().ok_or_else(|| self.err(JsonErrorKind::UnexpectedEnd))?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let e = self.peek().ok_or_else(|| self.err(JsonErrorKind::UnexpectedEnd))?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let c = self.unicode_escape()?;
                            out.push(c);
                        }
                        _ => return Err(self.err(JsonErrorKind::BadEscape)),
                    }
                }

                0x00..=0x1f => return Err(self.err(JsonErrorKind::BadString)),
                _ => {
                    let rest = &self.input[self.pos..];
                    let len = utf8_len(b);
                    if len == 0 || rest.len() < len {
                        return Err(self.err(JsonErrorKind::BadString));
                    }
                    let s = core::str::from_utf8(&rest[..len])
                        .map_err(|_| self.err(JsonErrorKind::BadString))?;
                    out.push_str(s);
                    self.pos += len;
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let hi = self.hex4()?;
        // a high surrogate must be followed by its low half; a lone surrogate is not a char.
        if (0xD800..0xDC00).contains(&hi) {
            if self.peek() != Some(b'\\') {
                return Err(self.err(JsonErrorKind::BadEscape));
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return Err(self.err(JsonErrorKind::BadEscape));
            }
            self.pos += 1;
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Err(self.err(JsonErrorKind::BadEscape));
            }
            let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
            return char::from_u32(cp).ok_or_else(|| self.err(JsonErrorKind::BadEscape));
        }
        if (0xDC00..0xE000).contains(&hi) {
            return Err(self.err(JsonErrorKind::BadEscape));
        }
        char::from_u32(hi).ok_or_else(|| self.err(JsonErrorKind::BadEscape))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.pos + 4 > self.input.len() {
            return Err(self.err(JsonErrorKind::UnexpectedEnd));
        }
        let mut v = 0u32;
        for i in 0..4 {
            let d = match self.input[self.pos + i] {
                c @ b'0'..=b'9' => (c - b'0') as u32,
                c @ b'a'..=b'f' => (c - b'a' + 10) as u32,
                c @ b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return Err(self.err(JsonErrorKind::BadEscape)),
            };
            v = (v << 4) | d;
        }
        self.pos += 4;
        Ok(v)
    }
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Json, JsonError> {
        parse(s.as_bytes(), JsonLimits::default())
    }

    #[test]
    fn parses_rpc_shapes() {
        let v = p(r#"{"jsonrpc":"2.0","method":"chain_getInfo","params":[],"id":1}"#).unwrap();
        assert_eq!(v.get("jsonrpc").unwrap().as_str(), Some("2.0"));
        assert_eq!(v.get("method").unwrap().as_str(), Some("chain_getInfo"));
        assert_eq!(v.get("params").unwrap().as_arr().unwrap().len(), 0);
        assert_eq!(v.get("id").unwrap().as_int(), Some(1));
    }

    #[test]
    fn floats_rejected_with_reason() {
        let e = p("1.5").unwrap_err();
        assert_eq!(e.kind, JsonErrorKind::FloatRejected);
        assert!(e.to_string().contains("decimal strings of mile"));
        assert_eq!(p("1e18").unwrap_err().kind, JsonErrorKind::FloatRejected);

        assert_eq!(p("1000000").unwrap(), Json::Int(1_000_000));
    }

    #[test]
    fn depth_bomb_refused() {
        let deep = format!("{}{}", "[".repeat(64), "]".repeat(64));
        let e = p(&deep).unwrap_err();
        assert!(matches!(e.kind, JsonErrorKind::TooDeep { max: 16 }));

        let ok = format!("{}{}", "[".repeat(16), "]".repeat(16));
        assert!(p(&ok).is_ok());
    }

    #[test]
    fn width_bomb_refused() {
        let wide = format!("[{}]", vec!["0"; 5000].join(","));
        let e = parse(wide.as_bytes(), JsonLimits { max_members: 4096, ..Default::default() })
            .unwrap_err();
        assert!(matches!(e.kind, JsonErrorKind::TooManyMembers { .. }));
    }

    #[test]
    fn oversize_body_refused_before_scan() {
        let limits = JsonLimits { max_bytes: 16, ..Default::default() };
        let e = parse(b"[0,0,0,0,0,0,0,0,0,0,0,0]", limits).unwrap_err();
        assert!(matches!(e.kind, JsonErrorKind::TooLarge { .. }));
        assert_eq!(e.offset, 0);
    }

    #[test]
    fn value_member_and_surrogate_caps_bite() {
        let limits = JsonLimits { max_values: 8, ..Default::default() };
        let e = parse(b"[0,0,0,0,0,0,0,0,0,0,0,0]", limits).unwrap_err();
        assert!(matches!(e.kind, JsonErrorKind::TooManyValues { .. }), "{e:?}");

        let limits = JsonLimits { max_members: 4, ..Default::default() };
        let obj = r#"{"a":1,"b":2,"c":3,"d":4,"e":5}"#;
        let e = parse(obj.as_bytes(), limits).unwrap_err();
        assert!(matches!(e.kind, JsonErrorKind::TooManyMembers { .. }), "{e:?}");

        assert!(parse(br#"{"a":1,"b":2,"c":3,"d":4}"#, limits).is_ok());

        for bad in [
            r#""\ud800""#,
            r#""\udc00""#,
            r#""\ud800x""#,
            r#""\ud800A""#,
        ] {
            let e = p(bad).unwrap_err();
            assert!(matches!(e.kind, JsonErrorKind::BadEscape), "{bad} was accepted: {e:?}");
        }

        assert_eq!(p("\"\\ud83d\\ude00\"").expect("pair"), Json::Str("\u{1f600}".into()));
        assert_eq!(p("\"a\\ud83d\\ude00b\"").expect("pair"), Json::Str("a\u{1f600}b".into()));

        assert_eq!(p("\"\u{1f600}\"").expect("raw"), Json::Str("\u{1f600}".into()));
        assert_eq!(p("\"\\u00e9\"").expect("bmp"), Json::Str("\u{e9}".into()));
    }

    #[test]
    fn duplicate_keys_are_an_error() {
        let e = p(r#"{"method":"a","method":"b"}"#).unwrap_err();
        assert!(matches!(e.kind, JsonErrorKind::DuplicateKey { .. }));
    }

    #[test]
    fn dup_key_rule_survives_hash_index() {
        let n = DUP_KEY_LINEAR_SCAN_MAX * 8;

        let distinct: Vec<String> = (0..n).map(|i| format!(r#""k{i}":{i}"#)).collect();
        let wide = format!("{{{}}}", distinct.join(","));
        match p(&wide) {
            Ok(Json::Obj(m)) => assert_eq!(m.len(), n),
            other => panic!("a wide object of distinct keys was refused: {other:?}"),
        }

        let mut late = distinct.clone();
        late.push(r#""k5":99"#.to_string());
        let e = p(&format!("{{{}}}", late.join(","))).unwrap_err();
        assert!(
            matches!(e.kind, JsonErrorKind::DuplicateKey { .. }),
            "duplicate of an early key missed once the index kicks in - it isn't seeded from the \
             members already there: {e:?}"
        );

        let mut adjacent = distinct.clone();
        adjacent.push(format!(r#""k{}":0"#, n - 1));
        let e = p(&format!("{{{}}}", adjacent.join(","))).unwrap_err();
        assert!(matches!(e.kind, JsonErrorKind::DuplicateKey { .. }), "{e:?}");

        for count in [DUP_KEY_LINEAR_SCAN_MAX - 1, DUP_KEY_LINEAR_SCAN_MAX, DUP_KEY_LINEAR_SCAN_MAX + 1] {
            let mut keys: Vec<String> = (0..count).map(|i| format!(r#""k{i}":{i}"#)).collect();
            keys.push(r#""k0":1"#.to_string());
            let e = p(&format!("{{{}}}", keys.join(","))).unwrap_err();
            assert!(
                matches!(e.kind, JsonErrorKind::DuplicateKey { .. }),
                "{count} members: a duplicate of the first key was not caught: {e:?}"
            );
        }
    }

    fn wide_object(n: usize) -> String {
        let mut s = String::from("{");
        for i in 0..n {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(&"a".repeat(244));
            s.push_str(&format!("{i:06}"));
            s.push_str("\":0");
        }
        s.push('}');
        s
    }

    fn time_two(a: &str, b: &str) -> (std::time::Duration, std::time::Duration) {
        let limits = JsonLimits::request();
        let mut best_a = std::time::Duration::MAX;
        let mut best_b = std::time::Duration::MAX;

        for _ in 0..3 {
            let start = std::time::Instant::now();
            let _ = parse(a.as_bytes(), limits);
            best_a = best_a.min(start.elapsed());

            let start = std::time::Instant::now();
            let _ = parse(b.as_bytes(), limits);
            best_b = best_b.min(start.elapsed());
        }
        (best_a, best_b)
    }

    #[test]
    fn dup_key_check_is_not_quadratic() {
        let small = wide_object(1_024);
        let large = wide_object(4_096);
        assert!(
            large.len() <= JsonLimits::request().max_bytes,
            "fixture exceeds the body cap: {}",
            large.len()
        );

        let (t_small, t_large) = time_two(&small, &large);
        let ratio = t_large.as_secs_f64() / t_small.as_secs_f64().max(1e-9);
        println!("1024 keys: {t_small:?}   4096 keys: {t_large:?}   {ratio:.1}x for 4x the input");

        assert!(
            ratio < 6.0,
            "4x the members cost {ratio:.1}x the time - the dup-key check looks quadratic again \
             ({t_small:?} -> {t_large:?}); see DUP_KEY_LINEAR_SCAN_MAX"
        );
    }

    #[test]
    fn control_bytes_and_bad_escapes_refused() {
        assert_eq!(p("\"a\u{1b}b\"").unwrap_err().kind, JsonErrorKind::BadString);
        assert_eq!(p(r#""\x""#).unwrap_err().kind, JsonErrorKind::BadEscape);
        assert_eq!(p(r#""\ud800""#).unwrap_err().kind, JsonErrorKind::BadEscape);
        assert_eq!(p("\"\u{1f600}\"").unwrap(), Json::Str("\u{1f600}".into()));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(p("{} {}").unwrap_err().kind, JsonErrorKind::TrailingBytes);
    }

    #[test]
    fn escaping_is_terminal_safe() {
        let s = Json::Str("line\nbreak \u{1b}[31m red \u{2028} sep \"q\" \\ b".into());
        let out = s.to_string();
        assert!(!out.contains('\u{1b}'), "raw ESC must never reach output: {out}");
        assert!(out.contains("\\u001b"));
        assert!(out.contains("\\u2028"));

        assert_eq!(p(&out).unwrap(), s);
    }

    #[test]
    fn amounts_survive_full_u128() {
        let max = Json::mile(u128::MAX);
        assert_eq!(max, Json::Str("340282366920938463463374607431768211455".into()));
        assert_eq!(p(&max.to_string()).unwrap(), max);
    }

    #[test]
    fn leading_zeroes_rejected() {
        assert!(p("012").is_err());
        assert_eq!(p("0").unwrap(), Json::Int(0));
        assert_eq!(p("-7").unwrap(), Json::Int(-7));
    }
}
