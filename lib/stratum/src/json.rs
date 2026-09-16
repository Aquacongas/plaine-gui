use crate::limits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    TooLong,
    Depth,
    TooManyValues,
    TooManyMembers,
    TooManyElements,
    StringTooLong,
    BadEscape,
    BadUtf8,
    ControlChar,
    BadNumber,
    NumberOverflow,
    DuplicateKey,
    Trailing,
    Unexpected,
    Eof,
    NotObject,
}

impl JsonError {
    pub fn as_str(self) -> &'static str {
        match self {
            JsonError::TooLong => "too_long",
            JsonError::Depth => "depth",
            JsonError::TooManyValues => "too_many_values",
            JsonError::TooManyMembers => "too_many_members",
            JsonError::TooManyElements => "too_many_elements",
            JsonError::StringTooLong => "string_too_long",
            JsonError::BadEscape => "bad_escape",
            JsonError::BadUtf8 => "bad_utf8",
            JsonError::ControlChar => "control_char",
            JsonError::BadNumber => "bad_number",
            JsonError::NumberOverflow => "number_overflow",
            JsonError::DuplicateKey => "duplicate_key",
            JsonError::Trailing => "trailing",
            JsonError::Unexpected => "unexpected",
            JsonError::Eof => "eof",
            JsonError::NotObject => "not_object",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    off: u32,
    len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Node {
    Null,
    Bool(bool),
    Num(u64),
    Str(Span),
    Arr { start: u32, len: u32 },
    Obj { start: u32, len: u32 },
}

#[derive(Debug, Clone, Copy)]
struct Member {
    key: Span,
    val: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueId(u32);

#[derive(Debug, Default)]
pub struct Doc {
    nodes: Vec<Node>,
    members: Vec<Member>,
    elements: Vec<u32>,
    strings: Vec<u8>,
}

impl Doc {
    pub fn new() -> Doc {
        Doc {
            nodes: Vec::with_capacity(limits::JSON_MAX_VALUES),
            members: Vec::with_capacity(limits::JSON_MAX_MEMBERS * 2),
            elements: Vec::with_capacity(limits::JSON_MAX_ELEMENTS * 2),
            strings: Vec::with_capacity(limits::READ_BUF_INITIAL),
        }
    }

    pub fn resident_bytes(&self) -> usize {
        self.nodes.capacity() * core::mem::size_of::<Node>()
            + self.members.capacity() * core::mem::size_of::<Member>()
            + self.elements.capacity() * core::mem::size_of::<u32>()
            + self.strings.capacity()
    }

    fn clear(&mut self) {
        self.nodes.clear();
        self.members.clear();
        self.elements.clear();
        self.strings.clear();
    }

    fn str_of(&self, s: Span) -> &str {
        core::str::from_utf8(&self.strings[s.off as usize..(s.off + s.len) as usize])
            .unwrap_or("")
    }

    pub fn root(&self) -> ValueId {
        ValueId(self.nodes.len().saturating_sub(1) as u32)
    }

    pub fn is_null(&self, v: ValueId) -> bool {
        matches!(self.nodes.get(v.0 as usize), Some(Node::Null))
    }

    pub fn as_str(&self, v: ValueId) -> Option<&str> {
        match self.nodes.get(v.0 as usize)? {
            Node::Str(s) => Some(self.str_of(*s)),
            _ => None,
        }
    }

    pub fn as_u64(&self, v: ValueId) -> Option<u64> {
        match self.nodes.get(v.0 as usize)? {
            Node::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self, v: ValueId) -> Option<bool> {
        match self.nodes.get(v.0 as usize)? {
            Node::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn arr_len(&self, v: ValueId) -> Option<usize> {
        match self.nodes.get(v.0 as usize)? {
            Node::Arr { len, .. } => Some(*len as usize),
            _ => None,
        }
    }

    pub fn arr_get(&self, v: ValueId, i: usize) -> Option<ValueId> {
        match self.nodes.get(v.0 as usize)? {
            Node::Arr { start, len } => {
                if i >= *len as usize {
                    return None;
                }
                self.elements.get(*start as usize + i).map(|x| ValueId(*x))
            }
            _ => None,
        }
    }

    pub fn obj_get(&self, v: ValueId, key: &str) -> Option<ValueId> {
        match self.nodes.get(v.0 as usize)? {
            Node::Obj { start, len } => {
                let s = *start as usize;
                for m in &self.members[s..s + *len as usize] {
                    if self.str_of(m.key) == key {
                        return Some(ValueId(m.val));
                    }
                }
                None
            }
            _ => None,
        }
    }
}

pub fn parse(doc: &mut Doc, line: &[u8], max_len: usize) -> Result<ValueId, JsonError> {
    if line.len() > max_len {
        return Err(JsonError::TooLong);
    }
    doc.clear();
    let mut p = Parser {
        b: line,
        i: 0,
        doc,
        budget: limits::JSON_MAX_VALUES,
    };
    p.skip_ws();
    let root = p.value(1)?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(JsonError::Trailing);
    }
    // every stratum request is a json object; a bare array or scalar at the root
    // is rejected here rather than handled downstream.
    if !matches!(p.doc.nodes[root.0 as usize], Node::Obj { .. }) {
        return Err(JsonError::NotObject);
    }

    debug_assert_eq!(root.0 as usize, p.doc.nodes.len() - 1);
    Ok(root)
}

struct Parser<'a, 'd> {
    b: &'a [u8],
    i: usize,
    doc: &'d mut Doc,
    budget: usize,
}

impl<'a, 'd> Parser<'a, 'd> {
    #[inline]
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => self.i += 1,
                _ => break,
            }
        }
    }

    fn push(&mut self, n: Node) -> Result<ValueId, JsonError> {
        if self.budget == 0 {
            return Err(JsonError::TooManyValues);
        }
        self.budget -= 1;
        self.doc.nodes.push(n);
        Ok(ValueId((self.doc.nodes.len() - 1) as u32))
    }

    fn lit(&mut self, word: &[u8]) -> Result<(), JsonError> {
        if self.b.len() - self.i < word.len() {
            return Err(JsonError::Eof);
        }
        if &self.b[self.i..self.i + word.len()] != word {
            return Err(JsonError::Unexpected);
        }
        self.i += word.len();
        Ok(())
    }

    fn value(&mut self, depth: u32) -> Result<ValueId, JsonError> {
        match self.peek().ok_or(JsonError::Eof)? {
            b'n' => {
                self.lit(b"null")?;
                self.push(Node::Null)
            }
            b't' => {
                self.lit(b"true")?;
                self.push(Node::Bool(true))
            }
            b'f' => {
                self.lit(b"false")?;
                self.push(Node::Bool(false))
            }
            b'"' => {
                let s = self.string()?;
                self.push(Node::Str(s))
            }
            b'0'..=b'9' => {
                let n = self.number()?;
                self.push(Node::Num(n))
            }
            b'[' => {
                if depth > limits::JSON_MAX_DEPTH {
                    return Err(JsonError::Depth);
                }
                self.array(depth)
            }
            b'{' => {
                if depth > limits::JSON_MAX_DEPTH {
                    return Err(JsonError::Depth);
                }
                self.object(depth)
            }
            _ => Err(JsonError::Unexpected),
        }
    }

    fn array(&mut self, depth: u32) -> Result<ValueId, JsonError> {
        self.i += 1;
        let mut kids = [0u32; limits::JSON_MAX_ELEMENTS];
        let mut n = 0usize;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
        } else {
            loop {
                if n == limits::JSON_MAX_ELEMENTS {
                    return Err(JsonError::TooManyElements);
                }
                self.skip_ws();
                kids[n] = self.value(depth + 1)?.0;
                n += 1;
                self.skip_ws();
                match self.peek().ok_or(JsonError::Eof)? {
                    b',' => self.i += 1,
                    b']' => {
                        self.i += 1;
                        break;
                    }
                    _ => return Err(JsonError::Unexpected),
                }
            }
        }
        let start = self.doc.elements.len() as u32;
        self.doc.elements.extend_from_slice(&kids[..n]);
        self.push(Node::Arr {
            start,
            len: n as u32,
        })
    }

    fn object(&mut self, depth: u32) -> Result<ValueId, JsonError> {
        self.i += 1;
        let mut kids = [Member {
            key: Span { off: 0, len: 0 },
            val: 0,
        }; limits::JSON_MAX_MEMBERS];
        let mut n = 0usize;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
        } else {
            loop {
                if n == limits::JSON_MAX_MEMBERS {
                    return Err(JsonError::TooManyMembers);
                }
                self.skip_ws();
                if self.peek() != Some(b'"') {
                    return Err(JsonError::Unexpected);
                }
                let key = self.string()?;

                // duplicate keys are refused, not resolved: last-wins vs
                // first-wins is a parser differential, and either choice invites
                // a mismatch with whoever else parses the line.
                for prev in &kids[..n] {
                    if self.doc.str_of(prev.key) == self.doc.str_of(key) {
                        return Err(JsonError::DuplicateKey);
                    }
                }
                self.skip_ws();
                if self.peek() != Some(b':') {
                    return Err(JsonError::Unexpected);
                }
                self.i += 1;
                self.skip_ws();
                let val = self.value(depth + 1)?.0;
                kids[n] = Member { key, val };
                n += 1;
                self.skip_ws();
                match self.peek().ok_or(JsonError::Eof)? {
                    b',' => self.i += 1,
                    b'}' => {
                        self.i += 1;
                        break;
                    }
                    _ => return Err(JsonError::Unexpected),
                }
            }
        }
        let start = self.doc.members.len() as u32;
        self.doc.members.extend_from_slice(&kids[..n]);
        self.push(Node::Obj {
            start,
            len: n as u32,
        })
    }

    // integers only: no leading zeros, no sign, no fraction or exponent, and
    // overflow is a named error rather than a wrap. stratum carries no floats.
    fn number(&mut self) -> Result<u64, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'0') {
            self.i += 1;

            if matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::BadNumber);
            }
        } else {
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
                if self.i - start > limits::JSON_MAX_NUMBER_DIGITS {
                    return Err(JsonError::BadNumber);
                }
            }
        }

        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            return Err(JsonError::BadNumber);
        }
        let digits = &self.b[start..self.i];
        if digits.is_empty() {
            return Err(JsonError::BadNumber);
        }
        let mut acc: u64 = 0;
        for d in digits {
            acc = acc
                .checked_mul(10)
                .and_then(|a| a.checked_add((d - b'0') as u64))
                .ok_or(JsonError::NumberOverflow)?;
        }
        Ok(acc)
    }

    fn string(&mut self) -> Result<Span, JsonError> {
        self.i += 1;
        let off = self.doc.strings.len() as u32;
        let mut decoded = 0usize;
        loop {
            let c = self.peek().ok_or(JsonError::Eof)?;
            match c {
                b'"' => {
                    self.i += 1;
                    let span = Span {
                        off,
                        len: decoded as u32,
                    };
                    let bytes = &self.doc.strings[off as usize..];
                    if core::str::from_utf8(bytes).is_err() {
                        return Err(JsonError::BadUtf8);
                    }
                    return Ok(span);
                }
                0x00..=0x1F => return Err(JsonError::ControlChar),
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or(JsonError::Eof)?;
                    self.i += 1;
                    let mut buf = [0u8; 4];
                    let out: &[u8] = match e {
                        b'"' => b"\"",
                        b'\\' => b"\\",
                        b'/' => b"/",
                        b'b' => b"\x08",
                        b'f' => b"\x0C",
                        b'n' => b"\n",
                        b'r' => b"\r",
                        b't' => b"\t",
                        b'u' => {
                            let cp = self.unicode_escape()?;
                            let s = cp.encode_utf8(&mut buf);
                            s.as_bytes()
                        }
                        _ => return Err(JsonError::BadEscape),
                    };
                    decoded += out.len();
                    if decoded > limits::JSON_MAX_STRING_BYTES {
                        return Err(JsonError::StringTooLong);
                    }
                    self.doc.strings.extend_from_slice(out);
                }
                _ => {
                    self.i += 1;
                    decoded += 1;
                    if decoded > limits::JSON_MAX_STRING_BYTES {
                        return Err(JsonError::StringTooLong);
                    }
                    self.doc.strings.push(c);
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let hi = self.hex4()?;
        if (0xD800..0xDC00).contains(&hi) {
            if self.peek() != Some(b'\\') {
                return Err(JsonError::BadEscape);
            }
            self.i += 1;
            if self.peek() != Some(b'u') {
                return Err(JsonError::BadEscape);
            }
            self.i += 1;
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Err(JsonError::BadEscape);
            }
            let cp = 0x1_0000u32 + (((hi as u32) - 0xD800) << 10) + ((lo as u32) - 0xDC00);
            char::from_u32(cp).ok_or(JsonError::BadEscape)
        } else if (0xDC00..0xE000).contains(&hi) {
            Err(JsonError::BadEscape)
        } else {
            char::from_u32(hi as u32).ok_or(JsonError::BadEscape)
        }
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        if self.b.len() - self.i < 4 {
            return Err(JsonError::Eof);
        }
        let mut v: u16 = 0;
        for _ in 0..4 {
            let c = self.b[self.i];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(JsonError::BadEscape),
            };
            v = (v << 4) | d as u16;
            self.i += 1;
        }
        Ok(v)
    }
}

pub fn write_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                let n = c as u32;
                out.extend_from_slice(b"\\u00");
                out.push(hex_digit((n >> 4) as u8));
                out.push(hex_digit((n & 0xF) as u8));
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

pub fn write_u64(out: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&buf[i..]);
}

pub fn write_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    for b in bytes {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0xF));
    }
}

pub fn write_hex_u64(out: &mut Vec<u8>, n: u64, width: usize) {
    for i in (0..width).rev() {
        out.push(hex_digit(((n >> (4 * i)) & 0xF) as u8));
    }
}

#[inline]
fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Doc, JsonError> {
        let mut d = Doc::new();
        parse(&mut d, s.as_bytes(), limits::MAX_LINE_POST_AUTH)?;
        Ok(d)
    }

    #[test]
    fn parses_a_submit() {
        let d = p(r#"{"id":7,"method":"mining.submit","params":["a.rig","0000002b","2a00000003f2a300"]}"#)
            .unwrap();
        let r = d.root();
        assert_eq!(d.as_u64(d.obj_get(r, "id").unwrap()), Some(7));
        assert_eq!(
            d.as_str(d.obj_get(r, "method").unwrap()),
            Some("mining.submit")
        );
        let params = d.obj_get(r, "params").unwrap();
        assert_eq!(d.arr_len(params), Some(3));
        assert_eq!(
            d.as_str(d.arr_get(params, 2).unwrap()),
            Some("2a00000003f2a300")
        );
    }

    #[test]
    fn null_id_and_bools() {
        let d = p(r#"{"id":null,"ok":true,"no":false}"#).unwrap();
        let r = d.root();
        assert!(d.is_null(d.obj_get(r, "id").unwrap()));
        assert_eq!(d.as_bool(d.obj_get(r, "ok").unwrap()), Some(true));
        assert_eq!(d.as_bool(d.obj_get(r, "no").unwrap()), Some(false));
    }

    #[test]
    fn empty_containers() {
        let d = p(r#"{"a":[],"b":{}}"#).unwrap();
        let r = d.root();
        assert_eq!(d.arr_len(d.obj_get(r, "a").unwrap()), Some(0));
        assert_eq!(d.obj_get(d.obj_get(r, "b").unwrap(), "x"), None);
    }

    #[test]
    fn rejects_depth_4() {
        assert_eq!(p(r#"{"a":[[[1]]]}"#).err(), Some(JsonError::Depth));

        assert!(p(r#"{"a":[[1]]}"#).is_ok());
    }

    #[test]
    fn rejects_floats_signs_and_leading_zeros() {
        assert_eq!(p(r#"{"a":1.5}"#).err(), Some(JsonError::BadNumber));
        assert_eq!(p(r#"{"a":1e3}"#).err(), Some(JsonError::BadNumber));
        assert_eq!(p(r#"{"a":-1}"#).err(), Some(JsonError::Unexpected));
        assert_eq!(p(r#"{"a":007}"#).err(), Some(JsonError::BadNumber));
        assert!(p(r#"{"a":0}"#).is_ok());
    }

    #[test]
    fn number_overflow_is_named_not_wrapped() {
        assert_eq!(p(r#"{"a":18446744073709551616}"#).err(), Some(JsonError::NumberOverflow)
        );
        assert!(p(r#"{"a":18446744073709551615}"#).is_ok());

        assert_eq!(p(r#"{"a":111111111111111111111}"#).err(), Some(JsonError::BadNumber));
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert_eq!(p(r#"{"id":1,"id":2}"#).err(), Some(JsonError::DuplicateKey),
            "last-wins vs first-wins is a parser differential; refuse instead"
        );
    }

    #[test]
    fn rejects_trailing_and_non_object_roots() {
        assert_eq!(p(r#"{"a":1} {"b":2}"#).err(), Some(JsonError::Trailing));
        assert_eq!(p(r#"[1,2]"#).err(), Some(JsonError::NotObject));
        assert_eq!(p(r#""hi""#).err(), Some(JsonError::NotObject));
    }

    #[test]
    fn rejects_control_chars_and_bad_utf8() {
        assert_eq!(p("{\"a\":\"x\ty\"}").err(), Some(JsonError::ControlChar));
        let mut d = Doc::new();
        let bad = b"{\"a\":\"\xFF\"}";
        assert_eq!(
            parse(&mut d, bad, limits::MAX_LINE_POST_AUTH),
            Err(JsonError::BadUtf8)
        );
    }

    #[test]
    fn unicode_escapes() {
        let d = p("{\"a\":\"A\u{e9}\u{1f600}\"}").unwrap();
        assert_eq!(
            d.as_str(d.obj_get(d.root(), "a").unwrap()),
            Some("A\u{e9}\u{1F600}")
        );
        assert_eq!(p(r#"{"a":"\ud83d"}"#).err(), Some(JsonError::BadEscape));
        assert_eq!(p(r#"{"a":"\udc00"}"#).err(), Some(JsonError::BadEscape));
        assert_eq!(p(r#"{"a":"\uZZZZ"}"#).err(), Some(JsonError::BadEscape));
        assert_eq!(p(r#"{"a":"\q"}"#).err(), Some(JsonError::BadEscape));
    }

    #[test]
    fn simple_escapes() {
        let d = p(r#"{"a":"x\"y\\z\/w\b\f\n\r\t"}"#).unwrap();
        assert_eq!(
            d.as_str(d.obj_get(d.root(), "a").unwrap()),
            Some("x\"y\\z/w\u{08}\u{0C}\n\r\t")
        );
    }

    #[test]
    fn enforces_every_size_limit() {
        let long = format!(r#"{{"a":"{}"}}"#, "x".repeat(4096));
        let mut d = Doc::new();
        assert_eq!(
            parse(&mut d, long.as_bytes(), limits::MAX_LINE_PRE_AUTH),
            Err(JsonError::TooLong)
        );

        let s = format!(r#"{{"a":"{}"}}"#, "x".repeat(limits::JSON_MAX_STRING_BYTES + 1));
        assert_eq!(
            parse(&mut d, s.as_bytes(), limits::MAX_LINE_POST_AUTH),
            Err(JsonError::StringTooLong)
        );

        let mut o = String::from("{");
        for i in 0..(limits::JSON_MAX_MEMBERS + 1) {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!(r#""k{}":1"#, i));
        }
        o.push('}');
        assert_eq!(
            parse(&mut d, o.as_bytes(), limits::MAX_LINE_POST_AUTH),
            Err(JsonError::TooManyMembers)
        );

        let a = format!(
            r#"{{"a":[{}]}}"#,
            (0..(limits::JSON_MAX_ELEMENTS + 1))
                .map(|_| "1")
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            parse(&mut d, a.as_bytes(), limits::MAX_LINE_POST_AUTH),
            Err(JsonError::TooManyElements)
        );
    }

    #[test]
    fn value_budget_is_enforced() {
        let mut o = String::from("{");
        for i in 0..8 {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!(r#""k{}":[1,1,1,1,1,1,1,1]"#, i));
        }
        o.push('}');
        let mut d = Doc::new();
        assert_eq!(
            parse(&mut d, o.as_bytes(), limits::MAX_LINE_POST_AUTH),
            Err(JsonError::TooManyValues)
        );
    }

    #[test]
    fn truncations_never_panic() {
        let full =
            r#"{"id":7,"method":"mining.submit","params":["a.rig","0000002b","2a00000003f2a300"]}"#;
        let mut d = Doc::new();
        for i in 0..full.len() {
            let _ = parse(&mut d, &full.as_bytes()[..i], limits::MAX_LINE_POST_AUTH);
        }
    }

    #[test]
    fn every_single_byte_line_is_total() {
        let mut d = Doc::new();
        for b in 0u16..=255 {
            let line = [b as u8];
            let _ = parse(&mut d, &line, limits::MAX_LINE_POST_AUTH);
        }
    }

    #[test]
    fn arena_is_reusable_and_bounded() {
        let mut d = Doc::new();
        let line = br#"{"id":1,"method":"mining.subscribe","params":["m/1.0"]}"#;
        for _ in 0..1000 {
            parse(&mut d, line, limits::MAX_LINE_POST_AUTH).unwrap();
        }
        assert!(d.nodes.len() <= limits::JSON_MAX_VALUES);
        assert!(d.strings.len() <= limits::MAX_LINE_POST_AUTH);
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const ALPHABET: &[u8] =
        b"{}[]\",:0123456789.eE+-truefalsnl \t\r\n\\/u\x00\x01\x7f\xff\xc3\xa9\xed\xa0\x80abcxyz";

    fn seeds() -> Vec<Vec<u8>> {
        vec![
            br#"{"id":1,"method":"mining.subscribe","params":["plaine-miner/1.0"]}"#.to_vec(),
            br#"{"id":2,"method":"mining.authorize","params":["plne1qqqq.rig1+120000","x"]}"#
                .to_vec(),
            br#"{"id":7,"method":"mining.submit","params":["w","0000002b","2a00000003f2a300"]}"#
                .to_vec(),
            br#"{"id":null,"method":"mining.notify","params":["0000002b",184602,"ab",true]}"#
                .to_vec(),
            br#"{"a":[[1,2],[3,4]],"b":{"c":"\ud83d\ude00"},"d":null}"#.to_vec(),
            br#"{}"#.to_vec(),
        ]
    }

    fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        let ops = 1 + rng.below(4);
        for _ in 0..ops {
            if v.is_empty() {
                v.push(ALPHABET[rng.below(ALPHABET.len())]);
                continue;
            }
            match rng.below(6) {
                0 => {
                    let i = rng.below(v.len());
                    v[i] = ALPHABET[rng.below(ALPHABET.len())];
                }
                1 => {
                    let i = rng.below(v.len());
                    v.insert(i, ALPHABET[rng.below(ALPHABET.len())]);
                }
                2 => {
                    let i = rng.below(v.len());
                    v.remove(i);
                }
                3 => v.truncate(rng.below(v.len())),
                4 => {
                    let i = rng.below(v.len());
                    let j = i + rng.below(v.len() - i + 1);
                    let piece: Vec<u8> = v[i..j].to_vec();
                    let at = rng.below(v.len());
                    for (k, b) in piece.iter().enumerate() {
                        if v.len() >= 8 * 1024 {
                            break;
                        }
                        v.insert(at + k, *b);
                    }
                }
                _ => {
                    let i = rng.below(v.len());
                    v[i] ^= 1 << rng.below(8);
                }
            }
        }
        v
    }

    #[test]
    fn parser_total_arena_bounded() {
        const CASES: usize = 60_000;
        const MAX_LEN: usize = limits::MAX_LINE_PRE_AUTH;

        let bound = limits::JSON_MAX_VALUES * core::mem::size_of::<Node>()
            + 2 * limits::JSON_MAX_VALUES * core::mem::size_of::<Member>()
            + 2 * limits::JSON_MAX_VALUES * core::mem::size_of::<u32>()
            + MAX_LEN
            + limits::READ_BUF_INITIAL;

        let mut rng = Rng(0x5EED_1234_ABCD_0001);
        let corpus = seeds();

        let mut doc = Doc::new();
        let mut ok = 0usize;
        let mut by_error = std::collections::BTreeMap::<&'static str, usize>::new();

        for case in 0..CASES {
            let line: Vec<u8> = if case % 4 == 0 {
                let len = rng.below(64);
                (0..len)
                    .map(|_| ALPHABET[rng.below(ALPHABET.len())])
                    .collect()
            } else {
                let base = &corpus[rng.below(corpus.len())];
                mutate(&mut rng, base)
            };

            match parse(&mut doc, &line, MAX_LEN) {
                Ok(root) => {
                    ok += 1;

                    assert!(doc.arr_len(root).is_none());
                    let _ = doc.obj_get(root, "");
                    if let Some(par) = doc.obj_get(root, "params") {
                        for i in 0..16 {
                            if let Some(v) = doc.arr_get(par, i) {
                                let _ = doc.as_str(v);
                                let _ = doc.as_u64(v);
                                let _ = doc.as_bool(v);
                                let _ = doc.is_null(v);
                            }
                        }
                    }
                }
                Err(e) => {
                    assert!(!e.as_str().is_empty());
                    *by_error.entry(e.as_str()).or_default() += 1;
                }
            }

            let resident = doc.resident_bytes();
            assert!(
                resident <= bound,
                "arena grew to {resident} B (bound {bound} B) on case {case}, seed 0x5EED1234ABCD0001, input {:?}",
                String::from_utf8_lossy(&line)
            );
        }

        assert!(ok > 100, "only {ok} of {CASES} inputs parsed");
        assert!(
            by_error.len() >= 8,
            "the corpus reached only {} distinct error paths: {by_error:?}",
            by_error.len()
        );
    }

    #[test]
    fn nesting_does_not_grow_arena() {
        let mut doc = Doc::new();
        let deep = r#"{"a":[[1,2,3,4,5,6,7,8],[1,2,3,4,5,6,7,8]]}"#;
        let wide = format!(
            r#"{{{}}}"#,
            (0..limits::JSON_MAX_MEMBERS)
                .map(|i| format!(r#""k{i}":[1,2,3,4]"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let long = format!(r#"{{"a":"{}"}}"#, "x".repeat(limits::JSON_MAX_STRING_BYTES));
        let mut peak = 0usize;
        for i in 0..1_000 {
            for line in [deep, wide.as_str(), long.as_str()] {
                let _ = parse(&mut doc, line.as_bytes(), limits::MAX_LINE_POST_AUTH);
                peak = peak.max(doc.resident_bytes());
            }
            if i == 10 {
                let settled = doc.resident_bytes();
                for _ in 0..500 {
                    let _ = parse(&mut doc, wide.as_bytes(), limits::MAX_LINE_POST_AUTH);
                    assert_eq!(
                        doc.resident_bytes(),
                        settled,
                        "steady-state parsing allocated again"
                    );
                }
            }
        }
        assert!(peak <= 8 * 1024, "arena peaked at {peak} B");
    }

    #[test]
    fn writer_escapes_structural_bytes() {
        let mut out = Vec::new();
        write_str(&mut out, "a\"},{\"b");
        assert_eq!(String::from_utf8(out).unwrap(), r#""a\"},{\"b""#);
        let mut out = Vec::new();
        write_str(&mut out, "\u{1}");
        assert_eq!(String::from_utf8(out).unwrap(), r#""\u0001""#);
    }

    #[test]
    fn writers_round_trip() {
        let mut out = Vec::new();
        write_u64(&mut out, 0);
        write_u64(&mut out, u64::MAX);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "018446744073709551615"
        );
        let mut out = Vec::new();
        write_hex_u64(&mut out, 0x2b, 8);
        assert_eq!(String::from_utf8(out).unwrap(), "0000002b");
        let mut out = Vec::new();
        write_hex(&mut out, &[0x00, 0xa3, 0xf2]);
        assert_eq!(String::from_utf8(out).unwrap(), "00a3f2");
    }

    #[test]
    fn object_recursion_bound_enforced() {
        assert_eq!(limits::JSON_MAX_DEPTH, 3, "the tests below are written for depth 3");
        assert!(p(r#"{"a":{"b":{"c":1}}}"#).is_ok(), "depth 3 of objects must pass");
        assert_eq!(p(r#"{"a":{"b":{"c":{"d":1}}}}"#).err(), Some(JsonError::Depth));

        assert_eq!(p(r#"{"a":[{"b":{"c":1}}]}"#).err(), Some(JsonError::Depth));
        assert_eq!(p(r#"{"a":{"b":[[1]]}}"#).err(), Some(JsonError::Depth));

        let deep = format!("{}1{}", "{\"a\":".repeat(200), "}".repeat(200));
        assert!(deep.len() < limits::MAX_LINE_POST_AUTH);
        assert_eq!(p(&deep).err(), Some(JsonError::Depth));
    }

    #[test]
    fn string_limit_on_escape_path() {
        let n = limits::JSON_MAX_STRING_BYTES;
        assert!(p(&format!(r#"{{"a":"{}"}}"#, r"\n".repeat(n))).is_ok(), "exactly the limit");
        assert_eq!(
            p(&format!(r#"{{"a":"{}"}}"#, r"\n".repeat(n + 1))).err(),
            Some(JsonError::StringTooLong)
        );
        assert_eq!(
            p(&format!(r#"{{"a":"{}"}}"#, r"\uFFFF".repeat(n / 3 + 1))).err(),
            Some(JsonError::StringTooLong)
        );

        assert_eq!(
            p(&format!(r#"{{"a":"{}"}}"#, r"\uD83D\uDE00".repeat(n / 4 + 1))).err(),
            Some(JsonError::StringTooLong)
        );
    }

    #[test]
    fn surrogate_pair_must_be_a_pair() {
        assert_eq!(p(r#"{"a":"\ud83dXude00"}"#).err(), Some(JsonError::BadEscape));
        assert_eq!(p(r#"{"a":"\ud83d\Xde00"}"#).err(), Some(JsonError::BadEscape));
        assert_eq!(p(r#"{"a":"\ud83d\ud83d"}"#).err(), Some(JsonError::BadEscape));

        let d = p(r#"{"a":"\ud83d\ude00"}"#).unwrap();
        assert_eq!(d.as_str(d.obj_get(d.root(), "a").unwrap()), Some("\u{1F600}"));
    }

    #[test]
    fn member_is_quoted_key_colon_value() {
        assert_eq!(p(r#"{x"a":1}"#).err(), Some(JsonError::Unexpected));
        assert_eq!(p(r#"{"a"=1}"#).err(), Some(JsonError::Unexpected));
        assert_eq!(p(r#"{1:2}"#).err(), Some(JsonError::Unexpected));
        assert!(p(r#"{"a":1}"#).is_ok());
    }

    #[test]
    fn writer_escapes_backslash() {
        let mut out = Vec::new();
        write_str(&mut out, r"c:\rigs\one");
        assert_eq!(String::from_utf8(out).unwrap(), r#""c:\\rigs\\one""#);

        let mut line = Vec::from(&b"{\"a\":"[..]);
        write_str(&mut line, r"back\slash\");
        line.push(b'}');
        let mut d = Doc::new();
        let r = parse(&mut d, &line, limits::MAX_LINE_POST_AUTH).expect("must re-parse");
        assert_eq!(d.as_str(d.obj_get(r, "a").unwrap()), Some(r"back\slash\"));
    }
}
