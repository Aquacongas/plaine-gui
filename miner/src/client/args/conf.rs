use crate::client::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Num(u64),
    Bool(bool),
    List(Vec<u64>),
}

impl Value {
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Str(_) => "a string",
            Value::Num(_) => "a number",
            Value::Bool(_) => "a boolean",
            Value::List(_) => "an array",
        }
    }
}

pub fn parse(text: &str) -> Result<Vec<(String, Value)>, String> {
    let b = text.as_bytes();
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return Err(at(text, i, "a config file is one JSON object: it starts with `{`"));
    }
    i = skip_ws(b, i + 1);
    let mut out: Vec<(String, Value)> = Vec::new();
    if b.get(i) == Some(&b'}') {
        return Ok(out);
    }
    loop {
        i = skip_ws(b, i);
        if b.get(i) == Some(&b'}') {
            return Err(at(text, i, "a trailing comma before `}`, and JSON has none"));
        }
        if b.get(i) != Some(&b'"') {
            return Err(at(text, i, "expected a quoted key"));
        }
        let key_end = span_end(b, i).ok_or_else(|| at(text, i, "unterminated key"))?;
        let key = match decode(&text[i..key_end]) {
            Some(json::Owned::Str(s)) => s,
            _ => return Err(at(text, i, "expected a quoted key")),
        };
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return Err(at(text, i, "expected `:` after the key"));
        }
        i = skip_ws(b, i + 1);
        let val_end = span_end(b, i).ok_or_else(|| at(text, i, "unterminated value"))?;
        let raw = &text[i..val_end];
        let value = decode_value(raw)
            .ok_or_else(|| at(text, i, &format!("{raw} is not a value this reader understands")))?;
        out.push((key, value));
        i = skip_ws(b, val_end);
        match b.get(i) {
            Some(b',') => i += 1,
            Some(b'}') => {
                let rest = skip_ws(b, i + 1);
                if rest != b.len() {
                    return Err(at(text, rest, "trailing text after the closing `}`"));
                }
                return Ok(out);
            }
            None => return Err(at(text, i, "the object was never closed with `}`")),
            _ => {
                return Err(at(
                    text,
                    i,
                    "expected `,` or `}`; JSON has no trailing comma and no comments",
                ))
            }
        }
    }
}

fn decode_value(raw: &str) -> Option<Value> {
    let raw = raw.trim();
    if raw.starts_with('[') {
        let msg = json::parse(&format!("{{\"params\":{raw}}}"))?;
        let mut v = Vec::with_capacity(msg.args.len());
        for i in 0..msg.args.len() {
            v.push(msg.num_at(i)?);
        }
        return Some(Value::List(v));
    }
    match decode(raw)? {
        json::Owned::Str(s) => Some(Value::Str(s)),
        json::Owned::Num(n) => Some(Value::Num(n)),
        json::Owned::Bool(b) => Some(Value::Bool(b)),
        json::Owned::Other => None,
    }
}

fn decode(raw: &str) -> Option<json::Owned> {
    let msg = json::parse(&format!("{{\"params\":[{raw}]}}"))?;
    msg.args.into_iter().next()
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        i += 1;
    }
    i
}

fn span_end(b: &[u8], i: usize) -> Option<usize> {
    match *b.get(i)? {
        b'"' => string_end(b, i),
        open @ (b'[' | b'{') => {
            let close = if open == b'[' { b']' } else { b'}' };
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = string_end(b, j)?;
                        continue;
                    }
                    c if c == open => depth += 1,
                    c if c == close => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => {
            let mut j = i;
            while j < b.len()
                && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

fn string_end(b: &[u8], i: usize) -> Option<usize> {
    if *b.get(i)? != b'"' {
        return None;
    }
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

fn at(text: &str, byte: usize, msg: &str) -> String {
    let upto = &text[..byte.min(text.len())];
    let line = upto.matches('\n').count() + 1;
    let col = upto.rsplit('\n').next().map(|l| l.chars().count()).unwrap_or(0) + 1;
    format!("line {line}, column {col}: {msg}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_config_reads_as_written() {
        let text = r#"{
            "url": "plne1abc.rig1@pool.example:19258",
            "threads": 8,
            "cpu-affinity": [0, 2, 4, 6],
            "cpu-priority": 2,
            "huge-pages": true,
            "no-reconnect": false,
            "status": 30
        }"#;
        let v = parse(text).expect("parses");
        assert_eq!(v[0].0, "url");
        assert_eq!(v[0].1, Value::Str("plne1abc.rig1@pool.example:19258".into()));
        assert_eq!(v[1].1, Value::Num(8));
        assert_eq!(v[2].1, Value::List(vec![0, 2, 4, 6]));
        assert_eq!(v[4].1, Value::Bool(true));
        assert_eq!(v[5].1, Value::Bool(false));
        assert_eq!(v[6].1, Value::Num(30));
    }

    #[test]
    fn escapes_decoded_by_json() {
        let v = parse(r#"{"address":"plne1\"milerd}\\ .rig"}"#).expect("parses");
        assert_eq!(v[0].1, Value::Str("plne1\"milerd}\\ .rig".into()));
    }

    #[test]
    fn errors_name_the_line() {
        for (text, want) in [
            ("[1,2]", "JSON object"),
            ("{\"threads\": 4, 5}", "quoted key"),
            ("{\"threads\" 4}", "`:` after the key"),
            ("{\"threads\": 4 \"x\": 1}", "expected `,` or `}`"),
            ("{\"threads\": 4}garbage", "trailing text"),
            ("{\"threads\": 4", "never closed"),
        ] {
            let e = parse(text).unwrap_err();
            assert!(e.contains(want), "{text:?} -> {e:?}, wanted {want:?}");
            assert!(e.starts_with("line "), "{e:?} must locate itself");
        }
    }

    #[test]
    fn trailing_comma_is_an_error() {
        let e = parse("{\"threads\": 4,\n \"status\": 5,\n}").unwrap_err();
        assert!(e.contains("line 3"), "{e}");
        assert!(e.contains("trailing comma"), "{e}");
    }

    #[test]
    fn empty_object_is_valid() {
        assert_eq!(parse("{}").unwrap(), Vec::new());
        assert_eq!(parse("  {  }  ").unwrap(), Vec::new());
    }

    #[test]
    fn nested_objects_are_refused() {
        let e = parse(r#"{"cpu": {"threads": 4}}"#).unwrap_err();
        assert!(e.contains("not a value this reader understands"), "{e}");
    }
}
