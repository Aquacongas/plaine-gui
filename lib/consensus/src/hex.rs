#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    OddLength { len: usize },
    InvalidChar { index: usize, byte: u8 },
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HexError::OddLength { len } => write!(f, "hex string has odd length {len}"),
            HexError::InvalidChar { index, byte } => {
                write!(f, "invalid hex digit {byte:#04x} at index {index}")
            }
        }
    }
}

impl std::error::Error for HexError {}

const LUT: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0f) as usize] as char);
    }
    s
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(HexError::OddLength { len: b.len() });
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = nibble(b[i]).ok_or(HexError::InvalidChar { index: i, byte: b[i] })?;
        let lo = nibble(b[i + 1]).ok_or(HexError::InvalidChar { index: i + 1, byte: b[i + 1] })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_is_lowercase_and_pinned() {
        assert_eq!(encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(encode(&[]), "");

        let s = encode(&(0u8..=255).collect::<Vec<u8>>());
        assert!(s.chars().all(|c| !c.is_ascii_uppercase()), "encode must be lowercase");
        assert_eq!(s.len(), 512);
    }

    #[test]
    fn rfc4648_base16_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "66"),
            ("fo", "666f"),
            ("foo", "666f6f"),
            ("foob", "666f6f62"),
            ("fooba", "666f6f6261"),
            ("foobar", "666f6f626172"),
        ] {
            assert_eq!(encode(input.as_bytes()), expected);
            assert_eq!(decode(expected).unwrap(), input.as_bytes());
        }
    }

    #[test]
    fn decode_accepts_both_cases() {
        assert_eq!(decode("AbCd").unwrap(), vec![0xAB, 0xCD]);
        assert_eq!(decode("abcd").unwrap(), vec![0xAB, 0xCD]);
        assert_eq!(decode("ABCD").unwrap(), vec![0xAB, 0xCD]);
    }

    #[test]
    fn decode_rejects_odd_length_and_bad_chars() {
        assert_eq!(decode("abc"), Err(HexError::OddLength { len: 3 }));
        assert_eq!(decode("zz"), Err(HexError::InvalidChar { index: 0, byte: b'z' }));
        assert_eq!(decode("az"), Err(HexError::InvalidChar { index: 1, byte: b'z' }));
        assert_eq!(decode("00ff0g"), Err(HexError::InvalidChar { index: 5, byte: b'g' }));

        assert!(matches!(decode("00\u{e9}"), Err(HexError::InvalidChar { index: 2, .. })));
    }

    #[test]
    fn roundtrip() {
        for len in 0..64usize {
            let v: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode(&encode(&v)).unwrap(), v);
        }
    }
}
