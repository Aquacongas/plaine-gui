use crate::limits::MAX_RIG_LABEL;
use plaine_consensus::bech32m;
use plaine_consensus::constants::ADDRESS_PAYLOAD_BYTES;

pub type AddressBytes = [u8; ADDRESS_PAYLOAD_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub address: String,
    pub address_bytes: AddressBytes,
    pub rig: String,
    pub pinned_difficulty: Option<u64>,
}

impl Login {
    pub fn worker_id(&self) -> String {
        if self.rig.is_empty() {
            self.address.clone()
        } else {
            format!("{}.{}", self.address, self.rig)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    Empty,
    BadChecksum,
    WrongNetwork,
    BadPayloadLength,
    BadPinnedDifficulty,
}

impl LoginError {
    pub fn as_str(self) -> &'static str {
        match self {
            LoginError::Empty => "empty",
            LoginError::BadChecksum => "bad_checksum",
            LoginError::WrongNetwork => "wrong_network",
            LoginError::BadPayloadLength => "bad_payload_length",
            LoginError::BadPinnedDifficulty => "bad_pinned_difficulty",
        }
    }
}

pub fn parse_login(s: &str, expected_hrp: &str) -> Result<Login, LoginError> {
    if s.is_empty() {
        return Err(LoginError::Empty);
    }

    // split on the FIRST '+' so `<addr>+1+2` is one malformed pin, not addr
    // `<addr>+1`; the suffix must be a bare decimal (the charset check is not
    // redundant with parse, which would accept a leading '+').
    let (head, pin) = match s.find('+') {
        Some(i) => {
            let suffix = &s[i + 1..];
            if suffix.is_empty() || !suffix.bytes().all(|c| c.is_ascii_digit()) {
                return Err(LoginError::BadPinnedDifficulty);
            }
            let v: u64 = suffix
                .parse()
                .map_err(|_| LoginError::BadPinnedDifficulty)?;
            (&s[..i], Some(v))
        }
        None => (s, None),
    };

    let (addr, rig_raw) = match head.find('.') {
        Some(i) => (&head[..i], &head[i + 1..]),
        None => (head, ""),
    };
    if addr.is_empty() {
        return Err(LoginError::Empty);
    }

    let (hrp, payload) = bech32m::decode_bytes(addr).map_err(|_| LoginError::BadChecksum)?;
    if hrp != expected_hrp {
        return Err(LoginError::WrongNetwork);
    }
    if payload.len() != ADDRESS_PAYLOAD_BYTES {
        return Err(LoginError::BadPayloadLength);
    }
    let mut address_bytes = [0u8; ADDRESS_PAYLOAD_BYTES];
    address_bytes.copy_from_slice(&payload);

    // canonical lowercase: bech32m accepts either case, but the address is the
    // payout and dashboard key, so one spelling must not become two accounts.
    Ok(Login {
        address: addr.to_ascii_lowercase(),
        address_bytes,
        rig: sanitise_rig(rig_raw),
        pinned_difficulty: pin,
    })
}

pub fn sanitise_rig(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_RIG_LABEL));
    for c in raw.chars() {
        if out.len() >= MAX_RIG_LABEL {
            break;
        }
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use plaine_consensus::constants::ADDRESS_HRP;

    fn addr(seed: u8) -> String {
        bech32m::encode_bytes(ADDRESS_HRP, &[seed; ADDRESS_PAYLOAD_BYTES]).unwrap()
    }

    #[test]
    fn bare_address() {
        let a = addr(1);
        let l = parse_login(&a, ADDRESS_HRP).unwrap();
        assert_eq!(l.address, a);
        assert_eq!(l.rig, "");
        assert_eq!(l.pinned_difficulty, None);
        assert_eq!(l.address_bytes, [1u8; 20]);
        assert_eq!(l.worker_id(), a);
    }

    #[test]
    fn address_dot_rig() {
        let a = addr(2);
        let l = parse_login(&format!("{a}.rig1"), ADDRESS_HRP).unwrap();
        assert_eq!(l.rig, "rig1");
        assert_eq!(l.worker_id(), format!("{a}.rig1"));
    }

    #[test]
    fn pinned_difficulty() {
        let a = addr(3);
        let l = parse_login(&format!("{a}.rig1+120000"), ADDRESS_HRP).unwrap();
        assert_eq!(l.rig, "rig1");
        assert_eq!(l.pinned_difficulty, Some(120_000));

        let l = parse_login(&format!("{a}+8192"), ADDRESS_HRP).unwrap();
        assert_eq!(l.rig, "");
        assert_eq!(l.pinned_difficulty, Some(8_192));
    }

    #[test]
    fn dots_in_rig_label_ok() {
        let a = addr(4);
        let l = parse_login(&format!("{a}.rig.name.3+900"), ADDRESS_HRP).unwrap();
        assert_eq!(l.rig, "rig.name.3");
        assert_eq!(l.pinned_difficulty, Some(900));
    }

    #[test]
    fn rig_labels_sanitised() {
        let a = addr(5);
        let l = parse_login(&format!("{a}.b\u{fc}ro 2/../etc"), ADDRESS_HRP).unwrap();
        assert_eq!(l.rig, "bro2..etc");
        let long = "x".repeat(100);
        let l = parse_login(&format!("{a}.{long}"), ADDRESS_HRP).unwrap();
        assert_eq!(l.rig.len(), MAX_RIG_LABEL);
    }

    #[test]
    fn rig_label_cannot_break_out_of_json() {
        let mut out = Vec::new();
        crate::json::write_str(&mut out, &sanitise_rig(r#"a","x":["#));
        assert_eq!(String::from_utf8(out).unwrap(), r#""ax""#);
    }

    #[test]
    fn typo_caught_by_checksum() {
        let a = addr(6);
        let mut broken: Vec<char> = a.chars().collect();

        let i = broken.len() - 8;
        broken[i] = if broken[i] == 'q' { 'p' } else { 'q' };
        let broken: String = broken.into_iter().collect();
        assert_eq!(
            parse_login(&broken, ADDRESS_HRP),
            Err(LoginError::BadChecksum),
            "bech32m must catch a single-character typo; a plain-hex address could not"
        );
    }

    #[test]
    fn wrong_network_is_its_own_error() {
        let foreign = bech32m::encode_bytes("abcd", &[7u8; 20]).unwrap();
        assert_eq!(
            parse_login(&foreign, ADDRESS_HRP),
            Err(LoginError::WrongNetwork)
        );
    }

    #[test]
    fn wrong_payload_length_is_refused() {
        let short = bech32m::encode_bytes(ADDRESS_HRP, &[7u8; 19]).unwrap();
        assert_eq!(
            parse_login(&short, ADDRESS_HRP),
            Err(LoginError::BadPayloadLength)
        );
    }

    #[test]
    fn malformed_pins_refused() {
        let a = addr(8);
        for bad in ["+", "+abc", "+-1", "+1.5", "+ 100"] {
            assert_eq!(
                parse_login(&format!("{a}{bad}"), ADDRESS_HRP),
                Err(LoginError::BadPinnedDifficulty),
                "input {bad}"
            );
        }

        assert_eq!(
            parse_login(&format!("{a}+99999999999999999999999"), ADDRESS_HRP),
            Err(LoginError::BadPinnedDifficulty)
        );
    }

    #[test]
    fn empty_and_degenerate_inputs() {
        assert_eq!(parse_login("", ADDRESS_HRP), Err(LoginError::Empty));
        assert_eq!(parse_login(".rig", ADDRESS_HRP), Err(LoginError::Empty));
        assert_eq!(parse_login("+100", ADDRESS_HRP), Err(LoginError::Empty));
        assert_eq!(parse_login("x", ADDRESS_HRP), Err(LoginError::BadChecksum));
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let samples = [
            "\u{1F600}",
            "..",
            "++",
            ".+",
            "+.",
            "plne1",
            "PLNE1QQQ",
            "plne1qqqqq.rig+1+2",
        ];
        for s in samples {
            let _ = parse_login(s, ADDRESS_HRP);
        }
    }

    #[test]
    fn pin_split_at_first_plus() {
        let a = addr(9);

        assert_eq!(
            parse_login(&format!("{a}+1+2"), ADDRESS_HRP),
            Err(LoginError::BadPinnedDifficulty),
            "must split at the first plus, not the last"
        );
        assert_eq!(
            parse_login(&format!("{a}.rig+1+2"), ADDRESS_HRP),
            Err(LoginError::BadPinnedDifficulty)
        );

        assert_eq!(
            "+5".parse::<u64>(),
            Ok(5),
            "this is why the charset check is not redundant with the parse"
        );
        assert_eq!(
            parse_login(&format!("{a}++5"), ADDRESS_HRP),
            Err(LoginError::BadPinnedDifficulty),
            "`++5` must not pin 5: the suffix is not a bare decimal integer"
        );

        let l = parse_login(&format!("{a}.rig.name+120000"), ADDRESS_HRP).expect("valid");
        assert_eq!(l.rig, "rig.name");
        assert_eq!(l.pinned_difficulty, Some(120_000));
    }

    #[test]
    fn uppercase_is_same_payout_key() {
        let a = addr(12);
        let upper = a.to_ascii_uppercase();
        assert_ne!(upper, a, "the fixture must actually differ in case");

        let l = parse_login(&upper, ADDRESS_HRP).expect("uppercase bech32m is valid input");
        assert_eq!(l.address, a, "the payout key must be canonical lowercase");
        assert_eq!(
            l.address_bytes,
            parse_login(&a, ADDRESS_HRP)
                .expect("lowercase")
                .address_bytes,
            "and both spellings must decode to the same twenty bytes"
        );
        assert_eq!(l.worker_id(), a, "worker_id carries the same key into logs");

        let l = parse_login(&format!("{upper}.RIG1+8192"), ADDRESS_HRP).expect("valid");
        assert_eq!(l.address, a);
        assert_eq!(l.pinned_difficulty, Some(8_192));
    }

    #[test]
    fn rig_charset_survives_only() {
        assert_eq!(
            sanitise_rig("Rig-01_a.b9"),
            "Rig-01_a.b9",
            "the charset is [A-Za-z0-9._-] and every one of those must survive"
        );

        assert_eq!(sanitise_rig("a-b"), "a-b", "the hyphen");
        assert_eq!(sanitise_rig("a_b"), "a_b", "the underscore");
        assert_eq!(sanitise_rig("a.b"), "a.b", "the dot");
        assert_eq!(sanitise_rig("aZ9"), "aZ9", "letters and digits, both cases");

        assert_eq!(sanitise_rig("a b"), "ab");
        assert_eq!(sanitise_rig("a/b"), "ab");
        assert_eq!(sanitise_rig("a+b"), "ab");
    }

    #[test]
    fn login_errors_have_distinct_names() {
        let all = [
            LoginError::Empty,
            LoginError::BadChecksum,
            LoginError::WrongNetwork,
            LoginError::BadPayloadLength,
            LoginError::BadPinnedDifficulty,
        ];
        let mut names: Vec<&str> = all.iter().map(|e| e.as_str()).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            n,
            "two login errors share a short name: {names:?}"
        );
        assert!(names.iter().all(|s| !s.is_empty()));
    }
}
