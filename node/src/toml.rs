use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub path: String,
    pub line: usize,
    pub col: usize,
    pub span: usize,
    pub message: String,
    pub line_text: String,
    pub help: Option<String>,
    pub note: Option<String>,
}

impl Diagnostic {
    pub fn general(path: impl Into<String>, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            path: path.into(),
            line: 0,
            col: 0,
            span: 0,
            message: message.into(),
            line_text: String::new(),
            help: None,
            note: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Diagnostic {
        self.help = Some(help.into());
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Diagnostic {
        self.note = Some(note.into());
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "error: {}", self.message)?;
        if self.line == 0 {
            write!(f, "  --> {}", self.path)?;
        } else {
            writeln!(f, "  --> {}:{}:{}", self.path, self.line, self.col)?;
            let num = self.line.to_string();
            let pad = " ".repeat(num.len());
            writeln!(f, "{pad} |")?;
            writeln!(f, "{num} | {}", self.line_text)?;

            let lead = " ".repeat(self.col.saturating_sub(1));
            let carets = "^".repeat(self.span.max(1));
            write!(f, "{pad} | {lead}{carets}")?;
        }
        if let Some(h) = &self.help {
            write!(f, "\n\nhelp: {h}")?;
        }
        if let Some(n) = &self.note {
            write!(f, "\nnote: {n}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostic {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Arr(Vec<Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Str(_) => "a string",
            Value::Int(_) => "an integer",
            Value::Bool(_) => "a boolean",
            Value::Arr(_) => "an array",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub section: String,
    pub key: String,
    pub value: Value,
    pub line: usize,
    pub col: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Document {
    pub entries: Vec<Entry>,
    pub sections: Vec<(String, usize)>,
}

impl Document {
    pub fn get(&self, section: &str, key: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.section == section && e.key == key)
    }

    #[allow(dead_code)]
    pub fn has(&self, section: &str, key: &str) -> bool {
        self.get(section, key).is_some()
    }
}

pub fn parse(path: &str, src: &str) -> Result<Document, Diagnostic> {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    Parser {
        path,
        lines: src.lines().collect(),
        doc: Document::default(),
    }
    .run()
}

struct Parser<'a> {
    path: &'a str,
    lines: Vec<&'a str>,
    doc: Document,
}

impl<'a> Parser<'a> {
    fn diag(&self, line: usize, col: usize, span: usize, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            path: self.path.to_string(),
            line: line + 1,
            col,
            span,
            message: message.into(),
            line_text: self.lines.get(line).copied().unwrap_or("").to_string(),
            help: None,
            note: None,
        }
    }

    fn run(mut self) -> Result<Document, Diagnostic> {
        let mut section: Option<String> = None;
        let mut i = 0usize;
        while i < self.lines.len() {
            let raw = self.lines[i];
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                i += 1;
                continue;
            }
            if trimmed.starts_with('[') {
                section = Some(self.table_header(i, raw)?);
                i += 1;
                continue;
            }
            let (entry, consumed) = self.key_value(i, section.as_deref())?;

            if let Some(prev) = self.doc.get(&entry.section, &entry.key) {
                return Err(self
                    .diag(
                        i,
                        entry.col,
                        entry.key.chars().count(),
                        format!("`{}` is set twice in [{}]", entry.key, entry.section),
                    )
                    .with_help(format!(
                        "the first one is on line {}. Delete one of them - the node will not \
                         guess which you meant.",
                        prev.line
                    )));
            }
            self.doc.entries.push(entry);
            i += consumed;
        }
        Ok(self.doc)
    }

    fn table_header(&mut self, i: usize, raw: &str) -> Result<String, Diagnostic> {
        let trimmed = raw.trim();
        let col = raw.chars().count() - raw.trim_start().chars().count() + 1;

        if trimmed.starts_with("[[") {
            return Err(self
                .diag(
                    i,
                    col,
                    trimmed.chars().count(),
                    "arrays of tables are not supported",
                )
                .with_help(
                    "`[[name]]` declares a repeated table. noded.toml has a fixed, flat schema \
                     with no repeated sections, so there is nothing this could mean.",
                ));
        }
        let Some(close) = trimmed.find(']') else {
            return Err(self
                .diag(
                    i,
                    col,
                    trimmed.chars().count(),
                    "table header is missing its `]`",
                )
                .with_help("write it as `[section]` on a line of its own"));
        };
        let after = trimmed[close + 1..].trim();
        if !after.is_empty() && !after.starts_with('#') {
            return Err(self.diag(
                i,
                col + close + 1,
                after.chars().count(),
                "unexpected text after a table header",
            ));
        }
        let name = trimmed[1..close].trim().to_string();
        if name.contains('.') {
            return Err(self
                .diag(
                    i,
                    col,
                    close + 1,
                    format!("sub-tables are not supported (`[{name}]`)"),
                )
                .with_help(
                    "noded.toml is exactly one level deep. Every section is a plain name like \
                     [node], [rpc] or [checkpoints].",
                ));
        }
        if name.is_empty() || !name.chars().all(is_bare_key_char) {
            return Err(self.diag(
                i,
                col,
                close + 1,
                format!("`{name}` is not a valid section name"),
            ));
        }
        if let Some((_, prev)) = self.doc.sections.iter().find(|(s, _)| *s == name) {
            return Err(self
                .diag(i, col, close + 1, format!("section [{name}] appears twice"))
                .with_help(format!(
                    "the first [{name}] is on line {prev}. Merge the two into one section."
                )));
        }
        self.doc.sections.push((name.clone(), i + 1));
        Ok(name)
    }

    fn key_value(&self, i: usize, section: Option<&str>) -> Result<(Entry, usize), Diagnostic> {
        let raw = self.lines[i];
        let indent = raw.chars().count() - raw.trim_start().chars().count();
        let col = indent + 1;
        let trimmed = raw.trim();

        let Some(eq) = trimmed.find('=') else {
            return Err(self
                .diag(i, col, trimmed.chars().count(), "expected `key = value`")
                .with_help("every setting is `key = value`; comments start with `#`"));
        };
        let key = trimmed[..eq].trim().to_string();
        if key.is_empty() {
            return Err(self.diag(i, col, 1, "missing key before `=`"));
        }
        if key.contains('.') {
            let head = key.split('.').next().unwrap_or("");
            let tail = key.splitn(2, '.').nth(1).unwrap_or("");
            return Err(self
                .diag(
                    i,
                    col,
                    key.chars().count(),
                    format!("dotted keys are not supported (`{key}`)"),
                )
                .with_help(format!(
                    "write it as a section instead:\n\n    [{head}]\n    {tail} = ..."
                )));
        }
        if key.starts_with('"') || key.starts_with('\'') {
            return Err(self
                .diag(i, col, key.chars().count(), "quoted keys are not supported")
                .with_help("keys are bare words: letters, digits, `_` and `-`"));
        }
        if !key.chars().all(is_bare_key_char) {
            let bad = key.chars().find(|c| !is_bare_key_char(*c)).unwrap_or('?');
            return Err(self.diag(
                i,
                col,
                key.chars().count(),
                format!("`{bad}` is not allowed in a key name"),
            ));
        }
        let Some(section) = section else {
            return Err(self
                .diag(
                    i,
                    col,
                    key.chars().count(),
                    format!("`{key}` is not inside any section"),
                )
                .with_help(
                    "every setting belongs to a section. The first line of the file should be a \
                     header like [node].",
                )
                .with_note(
                    "delete the file and restart the node to have a fully commented default \
                     written for you.",
                ));
        };

        let value_col = col + trimmed[..eq].chars().count() + 1;
        let rest = &trimmed[eq + 1..];
        let (value, consumed) = self.value(i, value_col, rest)?;
        Ok((
            Entry {
                section: section.to_string(),
                key,
                value,
                line: i + 1,
                col,
            },
            consumed,
        ))
    }

    fn value(&self, i: usize, col: usize, rest: &str) -> Result<(Value, usize), Diagnostic> {
        let lead = rest.chars().count() - rest.trim_start().chars().count();
        let col = col + lead;
        let text = rest.trim_start();
        if text.is_empty() {
            return Err(self.diag(i, col, 1, "missing value after `=`").with_help(
                "if you meant to disable a setting, give it its empty value explicitly, \
                            or delete the line to take the default",
            ));
        }
        match text.as_bytes()[0] {
            b'"' if text.starts_with("\"\"\"") => Err(self
                .diag(i, col, 3, "multi-line strings are not supported")
                .with_help("every value in noded.toml fits on one line")),
            b'"' => self.basic_string(i, col, text).map(|v| (v, 1)),
            b'\'' if text.starts_with("'''") => Err(self
                .diag(i, col, 3, "multi-line strings are not supported")
                .with_help("every value in noded.toml fits on one line")),
            b'\'' => self.literal_string(i, col, text).map(|v| (v, 1)),
            b'[' => self.array(i, col, text),
            b'{' => Err(self
                .diag(i, col, 1, "inline tables are not supported")
                .with_help("use a section header instead:\n\n    [name]\n    key = value")),
            _ => self.scalar(i, col, text).map(|v| (v, 1)),
        }
    }

    fn basic_string(&self, i: usize, col: usize, text: &str) -> Result<Value, Diagnostic> {
        let mut out = String::new();
        let mut chars = text.char_indices().skip(1);
        while let Some((idx, c)) = chars.next() {
            match c {
                '"' => {
                    let after = text[idx + 1..].trim();
                    if !after.is_empty() && !after.starts_with('#') {
                        return Err(self.diag(
                            i,
                            col + text[..idx + 1].chars().count(),
                            after.chars().count(),
                            "unexpected text after the value",
                        ));
                    }
                    return Ok(Value::Str(out));
                }
                '\\' => {
                    let Some((eidx, e)) = chars.next() else {
                        return Err(self.diag(i, col, 1, "string ends with a lone backslash"));
                    };
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        other => {
                            return Err(self
                                .diag(
                                    i,
                                    col + text[..eidx].chars().count(),
                                    2,
                                    format!("unknown escape `\\{other}`"),
                                )
                                .with_help(
                                    "supported escapes are \\\" \\\\ \\n \\r \\t. For a Windows \
                                     path, use a literal string with single quotes instead:\n\n    \
                                     data_dir = 'C:\\plaine'",
                                ))
                        }
                    }
                }
                c => out.push(c),
            }
        }
        Err(self
            .diag(
                i,
                col,
                text.chars().count(),
                "string is missing its closing quote",
            )
            .with_help("strings are written \"like this\""))
    }

    fn literal_string(&self, i: usize, col: usize, text: &str) -> Result<Value, Diagnostic> {
        let Some(end) = text[1..].find('\'').map(|p| p + 1) else {
            return Err(self
                .diag(
                    i,
                    col,
                    text.chars().count(),
                    "literal string is missing its closing quote",
                )
                .with_help("literal strings are written 'like this' and contain no escapes"));
        };
        let after = text[end + 1..].trim();
        if !after.is_empty() && !after.starts_with('#') {
            return Err(self.diag(
                i,
                col + text[..end + 1].chars().count(),
                after.chars().count(),
                "unexpected text after the value",
            ));
        }
        Ok(Value::Str(text[1..end].to_string()))
    }

    fn scalar(&self, i: usize, col: usize, text: &str) -> Result<Value, Diagnostic> {
        let token: String = text
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '#')
            .collect();
        let span = token.chars().count().max(1);
        match token.as_str() {
            "true" => return Ok(Value::Bool(true)),
            "false" => return Ok(Value::Bool(false)),
            _ => {}
        }

        if token.contains('.')
            || ((token.contains('e') || token.contains('E'))
                && token.starts_with(|c: char| c.is_ascii_digit()))
        {
            return Err(self
                .diag(i, col, span, format!("`{token}` is a fractional number"))
                .with_help(
                    "every number in noded.toml is a whole number. Amounts are in mile \
                     (1 PLNE = 10^6 mile), so a fee of 0.5 PLNE is written \
                     relay_fee_mile = 500_000.",
                )
                .with_note(
                    "Plaine has no floating-point arithmetic anywhere (SPEC 5.1); the config file \
                     does not add any.",
                ));
        }

        if token.len() >= 8
            && token.starts_with(|c: char| c.is_ascii_digit())
            && (token.contains(':') || token.matches('-').count() >= 2)
        {
            return Err(self
                .diag(i, col, span, format!("`{token}` looks like a date or time"))
                .with_help("noded.toml has no date or time settings; nothing here takes one"));
        }
        let cleaned: String = token.chars().filter(|c| *c != '_').collect();
        if let Ok(n) = cleaned.parse::<i64>() {
            return Ok(Value::Int(n));
        }
        if token.starts_with(|c: char| c.is_ascii_digit()) || token.starts_with('-') {
            return Err(self
                .diag(
                    i,
                    col,
                    span,
                    format!("`{token}` is not a whole number this node can hold"),
                )
                .with_help("integers range from -9223372036854775808 to 9223372036854775807"));
        }
        Err(self
            .diag(i, col, span, format!("`{token}` is not a value"))
            .with_help(
                "values are: a string in \"double\" or 'single' quotes, a whole number, true, \
                 false, or an array like [\"a\", \"b\"]",
            ))
    }

    // arrays may span lines. pull lines in until the unquoted brackets balance,
    // then parse the joined text - that is what makes a multi-line seed list work.
    fn array(&self, start: usize, col: usize, first: &str) -> Result<(Value, usize), Diagnostic> {
        let mut joined = strip_comment(first).trim_end().to_string();

        let mut brackets = unquoted_brackets(&joined);
        let mut consumed = 1usize;
        loop {
            let opens = brackets.iter().filter(|(_, c)| *c == '[').count();
            let closes = brackets.len() - opens;
            if closes >= opens {
                break;
            }
            let next = start + consumed;
            let Some(line) = self.lines.get(next) else {
                return Err(self
                    .diag(start, col, 1, "array is missing its closing `]`")
                    .with_help("arrays look like [\"a\", \"b\"] and may span lines"));
            };
            let piece = strip_comment(line);
            let piece = piece.trim();
            let offset = joined.len() + 1;
            joined.push(' ');
            joined.push_str(piece);
            for (i, c) in unquoted_brackets(piece) {
                brackets.push((i + offset, c));
            }
            consumed += 1;
        }
        let close = brackets
            .iter()
            .rev()
            .find(|(_, c)| *c == ']')
            .map(|(i, _)| *i)
            .expect("the loop only exits once a closing `]` has been seen");
        let after = joined[close + 1..].trim();
        if !after.is_empty() {
            return Err(self.diag(start, col, 1, "unexpected text after the array"));
        }
        let inner = &joined[1..close];

        if brackets
            .iter()
            .any(|(i, c)| *c == '[' && *i > 0 && *i < close)
        {
            return Err(self
                .diag(start, col, 1, "nested arrays are not supported")
                .with_help("no setting in noded.toml takes a list of lists"));
        }
        let mut items: Vec<Value> = Vec::new();
        for piece in split_top_level(inner) {
            let piece = strip_comment(&piece);
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let v = if piece.starts_with('"') {
                self.basic_string(start, col, piece)?
            } else if piece.starts_with('\'') {
                self.literal_string(start, col, piece)?
            } else {
                self.scalar(start, col, piece)?
            };
            if let Some(prev) = items.first() {
                if core::mem::discriminant(prev) != core::mem::discriminant(&v) {
                    return Err(self
                        .diag(
                            start,
                            col,
                            1,
                            format!(
                                "this array mixes {} with {}",
                                prev.type_name(),
                                v.type_name()
                            ),
                        )
                        .with_help("every element of an array must be the same kind of value"));
                }
            }
            items.push(v);
        }
        Ok((Value::Arr(items), consumed))
    }
}

fn is_bare_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

// drop a trailing `# comment`, but only when the `#` sits outside a string. a hash
// inside a quoted value - a token, a path - has to survive.
fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut in_basic = false;
    let mut in_literal = false;
    let mut escaped = false;
    for c in line.chars() {
        match c {
            '#' if !in_basic && !in_literal => break,
            '"' if !in_literal && !escaped => {
                in_basic = !in_basic;
                out.push(c);
            }
            '\'' if !in_basic => {
                in_literal = !in_literal;
                out.push(c);
            }
            '\\' if in_basic => {
                escaped = !escaped;
                out.push(c);
                continue;
            }
            c => out.push(c),
        }
        escaped = false;
    }
    out
}

// only `[`/`]` outside strings count. an ipv6 seed like "[2001:db8::1]:9256"
// must not read as opening or closing an array.
fn unquoted_brackets(s: &str) -> Vec<(usize, char)> {
    let mut out = Vec::new();
    let mut in_basic = false;
    let mut in_literal = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' if !in_literal && !escaped => in_basic = !in_basic,
            '\'' if !in_basic => in_literal = !in_literal,
            '\\' if in_basic => {
                escaped = !escaped;
                continue;
            }
            '[' | ']' if !in_basic && !in_literal => out.push((i, c)),
            _ => {}
        }
        escaped = false;
    }
    out
}

fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_basic = false;
    let mut in_literal = false;
    let mut escaped = false;
    for c in s.chars() {
        match c {
            ',' if !in_basic && !in_literal => {
                out.push(core::mem::take(&mut cur));
                continue;
            }
            '"' if !in_literal && !escaped => in_basic = !in_basic,
            '\'' if !in_basic => in_literal = !in_literal,
            '\\' if in_basic => {
                escaped = !escaped;
                cur.push(c);
                continue;
            }
            _ => {}
        }
        escaped = false;
        cur.push(c);
    }
    out.push(cur);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(src: &str) -> Document {
        parse("noded.toml", src).unwrap_or_else(|e| panic!("should parse:\n{e}"))
    }

    fn err(src: &str) -> Diagnostic {
        parse("noded.toml", src).expect_err("should not parse")
    }

    #[test]
    fn bom_is_stripped() {
        let d = ok("\u{feff}[node]\nnetwork = \"main\"\n");
        assert_eq!(
            d.get("node", "network").unwrap().value,
            Value::Str("main".into())
        );

        let d = ok("[node]\ndata_dir = \"\u{feff}x\"\n");
        assert_eq!(
            d.get("node", "data_dir").unwrap().value,
            Value::Str("\u{feff}x".into())
        );
    }

    #[test]
    fn ipv6_seed_not_nested_array() {
        let d = ok(r#"
[p2p]
seeds = ["[2001:db8::1]:9256", "seed.example:9256"]
"#);
        let Value::Arr(arr) = &d.get("p2p", "seeds").unwrap().value else {
            panic!("not an array")
        };
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], Value::Str("[2001:db8::1]:9256".into()));

        let d = ok(r#"
[p2p]
seeds = [
  "[2001:db8::1]:9256",
  "[::1]:9256",
]
"#);
        let Value::Arr(arr) = &d.get("p2p", "seeds").unwrap().value else {
            panic!("not an array")
        };
        assert_eq!(arr.len(), 2);

        let d = ok("[p2p]\nseeds = [\"a:1\"]   # see [docs] for the format\n");
        let Value::Arr(arr) = &d.get("p2p", "seeds").unwrap().value else {
            panic!("not an array")
        };
        assert_eq!(arr.len(), 1);

        let e = err("[p2p]\nseeds = [[\"a\"], [\"b\"]]\n");
        assert!(e.message.contains("nested arrays"), "{}", e.message);
    }

    #[test]
    fn unclosed_array_stops_at_eof() {
        let e = err("[p2p]\nseeds = [\"a\"\n\n[rpc]\nlisten = \"127.0.0.1:9257\"\n");
        assert!(e.message.contains("closing `]`"), "{}", e.message);
        assert_eq!(e.line, 2, "the caret must sit on the array, not at EOF");
    }

    #[test]
    fn supported_subset_parses() {
        let d = ok(r#"
# a comment
[node]
network  = "main"          # trailing comment
data_dir = 'C:\Users\me\.plaine'
prune    = true
txindex  = false

[mempool]
relay_fee_mile = 1
max_txs       = 20000

[p2p]
seeds = [
  "seed1.plaine.example:9256",   # one per line reads better
  "seed2.plaine.example:9256",
]
"#);
        assert_eq!(
            d.get("node", "network").unwrap().value,
            Value::Str("main".into())
        );
        assert_eq!(
            d.get("node", "data_dir").unwrap().value,
            Value::Str(r"C:\Users\me\.plaine".into())
        );
        assert_eq!(d.get("node", "prune").unwrap().value, Value::Bool(true));
        assert_eq!(
            d.get("mempool", "relay_fee_mile").unwrap().value,
            Value::Int(1)
        );
        let Value::Arr(seeds) = &d.get("p2p", "seeds").unwrap().value else {
            panic!("seeds should be an array");
        };
        assert_eq!(seeds.len(), 2);
    }

    #[test]
    fn empty_or_comment_only_is_valid() {
        assert!(ok("").entries.is_empty());
        assert!(ok("# nothing but a comment\n\n").entries.is_empty());
    }

    #[test]
    fn presence_differs_from_absence() {
        let d = ok("[checkpoints]\nkeys = []\n");
        assert!(d.has("checkpoints", "keys"));
        assert_eq!(
            d.get("checkpoints", "keys").unwrap().value,
            Value::Arr(vec![])
        );
        let d2 = ok("[checkpoints]\nenabled = true\n");
        assert!(!d2.has("checkpoints", "keys"));
    }

    #[test]
    fn float_refused_with_mile_help() {
        let e = err("[mempool]\nrelay_fee_mile = 0.5\n");
        assert!(e.message.contains("fractional"), "{e}");
        assert!(e.help.unwrap().contains("mile"));
        assert!(e.note.unwrap().contains("SPEC 5.1"));
        assert_eq!(e.line, 2);
    }

    #[test]
    fn caret_under_offending_text() {
        let e = err("[mempool]\nrelay_fee_mile = 0.5\n");
        let rendered = e.to_string();
        let caret_line = rendered
            .lines()
            .find(|l| l.contains('^'))
            .expect("a caret line");
        let value_line = rendered
            .lines()
            .find(|l| l.starts_with("2 | "))
            .expect("the source line");
        let caret_at = caret_line.find('^').expect("caret");
        let value_at = value_line.find("0.5").expect("value");
        assert_eq!(
            caret_at, value_at,
            "caret must sit under the value:\n{rendered}"
        );
    }

    #[test]
    fn dotted_keys_redirected() {
        let e = err("[node]\nrpc.listen = \"x\"\n");
        assert!(e.message.contains("dotted keys"));
        assert!(
            e.help.unwrap().contains("[rpc]"),
            "the help must show the fix"
        );
    }

    #[test]
    fn unsupported_tables_each_named() {
        assert!(err("[a.b]\nx = 1\n").message.contains("sub-tables"));
        assert!(err("[[a]]\nx = 1\n").message.contains("arrays of tables"));
        assert!(err("[a]\nx = { y = 1 }\n")
            .message
            .contains("inline tables"));
        assert!(err("[a]\nx = \"\"\"y\"\"\"\n")
            .message
            .contains("multi-line"));
    }

    #[test]
    fn key_outside_section_named() {
        let e = err("network = \"main\"\n");
        assert!(e.message.contains("not inside any section"));
        assert!(e.help.unwrap().contains("[node]"));
    }

    #[test]
    fn duplicates_are_errors() {
        let e = err("[node]\nprune = true\nprune = false\n");
        assert!(e.message.contains("set twice"), "{e}");
        assert!(e.help.unwrap().contains("line 2"));
        let e2 = err("[node]\nprune = true\n[node]\ntxindex = true\n");
        assert!(e2.message.contains("appears twice"));
    }

    #[test]
    fn windows_path_backslash_help() {
        let e = err(r#"[node]
data_dir = "C:\Users\me\.plaine"
"#);
        assert!(e.message.contains("unknown escape"), "{e}");
        assert!(e.help.unwrap().contains("data_dir = 'C:\\plaine'"));

        let d = ok("[node]\ndata_dir = 'C:\\Users\\me\\.plaine'\n");
        assert_eq!(
            d.get("node", "data_dir").unwrap().value,
            Value::Str(r"C:\Users\me\.plaine".into())
        );
    }

    #[test]
    fn mixed_array_refused() {
        let e = err("[p2p]\nseeds = [\"a\", 3]\n");
        assert!(e.message.contains("mixes"), "{e}");
    }

    #[test]
    fn unterminated_array_or_string_named() {
        assert!(err("[p2p]\nseeds = [\"a\",\n")
            .message
            .contains("closing `]`"));
        assert!(err("[node]\nnetwork = \"main\n")
            .message
            .contains("closing quote"));
    }

    #[test]
    fn hash_in_string_not_comment() {
        let d = ok("[rpc]\ntoken = \"abc#def\"\n");
        assert_eq!(
            d.get("rpc", "token").unwrap().value,
            Value::Str("abc#def".into())
        );
    }

    #[test]
    fn missing_value_named() {
        let e = err("[node]\nnetwork =\n");
        assert!(e.message.contains("missing value"));
    }

    #[test]
    fn rendered_form_matches() {
        let e = err("[mempool]\nrelay_fee_mile = 0.5\n");
        let s = e.to_string();
        assert!(s.starts_with("error: "));
        assert!(s.contains("  --> noded.toml:2:18"));
        assert!(s.contains("2 | relay_fee_mile = 0.5"));
        assert!(s.contains("help: "));
    }
}
