const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

// bech32m checksum constant (bip-350). differs from bech32's 1, so a bech32
// string never verifies here and vice versa: addresses can't be cross-decoded.
pub const BECH32M_CONST: u32 = 0x2bc8_30a3;

#[cfg(test)]
pub(crate) const BECH32_CONST: u32 = 1;

const MAX_STRING_LEN: usize = 90;
const MAX_HRP_LEN: usize = 83;
const CHECKSUM_CHARS: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bech32Error {
    TooLong { len: usize },
    TooShort,
    MixedCase,
    NoSeparator,
    EmptyHrp,
    HrpTooLong { len: usize },
    HrpChar { index: usize, byte: u8 },
    DataChar { index: usize, byte: u8 },
    BadChecksum,
    Padding,
}

impl core::fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Bech32Error::TooLong { len } => {
                write!(f, "bech32m string is {len} chars, max {MAX_STRING_LEN}")
            }
            Bech32Error::TooShort => write!(f, "data part shorter than the 6-char checksum"),
            Bech32Error::MixedCase => write!(f, "mixed case is not allowed"),
            Bech32Error::NoSeparator => write!(f, "no \"1\" separator"),
            Bech32Error::EmptyHrp => write!(f, "empty human-readable part"),
            Bech32Error::HrpTooLong { len } => {
                write!(f, "human-readable part is {len} chars, max {MAX_HRP_LEN}")
            }
            Bech32Error::HrpChar { index, byte } => {
                write!(
                    f,
                    "byte {byte:#04x} at index {index} is outside ASCII 33..=126"
                )
            }
            Bech32Error::DataChar { index, byte } => {
                write!(
                    f,
                    "byte {byte:#04x} at index {index} is not in the bech32 charset"
                )
            }
            Bech32Error::BadChecksum => write!(f, "bech32m checksum does not verify"),
            Bech32Error::Padding => write!(f, "non-canonical padding bits"),
        }
    }
}

impl std::error::Error for Bech32Error {}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (*v as u32);
        for (i, gen) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    let mut v = Vec::with_capacity(b.len() * 2 + 1);
    for c in b {
        v.push(c >> 5);
    }
    v.push(0);
    for c in b {
        v.push(c & 31);
    }
    v
}

pub fn convert_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in data {
        acc = (acc << 8) | (*b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

pub fn convert_5_to_8(data: &[u8]) -> Result<Vec<u8>, Bech32Error> {
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for (index, v) in data.iter().enumerate() {
        if *v >> 5 != 0 {
            return Err(Bech32Error::DataChar { index, byte: *v });
        }
        acc = (acc << 5) | (*v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // reject non-canonical padding: leftover bits must be fewer than 5 and all
    // zero, so each byte string has exactly one encoding and no padded alias
    // decodes to the same address.
    if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
        return Err(Bech32Error::Padding);
    }
    Ok(out)
}

fn encode_fes_with_const(hrp: &str, data5: &[u8], konst: u32) -> Result<String, Bech32Error> {
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    if hrp.len() > MAX_HRP_LEN {
        return Err(Bech32Error::HrpTooLong { len: hrp.len() });
    }
    for (index, byte) in hrp.bytes().enumerate() {
        if !(33..=126).contains(&byte) || byte.is_ascii_uppercase() {
            return Err(Bech32Error::HrpChar { index, byte });
        }
    }
    for (index, v) in data5.iter().enumerate() {
        if *v >> 5 != 0 {
            return Err(Bech32Error::DataChar { index, byte: *v });
        }
    }
    let total = hrp.len() + 1 + data5.len() + CHECKSUM_CHARS;
    if total > MAX_STRING_LEN {
        return Err(Bech32Error::TooLong { len: total });
    }

    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data5);
    values.extend_from_slice(&[0u8; CHECKSUM_CHARS]);
    let pm = polymod(&values) ^ konst;

    let mut s = String::with_capacity(total);
    s.push_str(hrp);
    s.push('1');
    for v in data5 {
        s.push(CHARSET[*v as usize] as char);
    }
    for i in 0..CHECKSUM_CHARS {
        let idx = ((pm >> (5 * (5 - i))) & 31) as usize;
        s.push(CHARSET[idx] as char);
    }
    Ok(s)
}

pub fn encode_fes(hrp: &str, data5: &[u8]) -> Result<String, Bech32Error> {
    encode_fes_with_const(hrp, data5, BECH32M_CONST)
}

#[cfg(test)]
pub(crate) fn encode_fes_bech32(hrp: &str, data5: &[u8]) -> Result<String, Bech32Error> {
    encode_fes_with_const(hrp, data5, BECH32_CONST)
}

pub fn decode_fes(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    if s.len() > MAX_STRING_LEN {
        return Err(Bech32Error::TooLong { len: s.len() });
    }

    let mut has_lower = false;
    let mut has_upper = false;
    for (index, byte) in s.bytes().enumerate() {
        if !(33..=126).contains(&byte) {
            return Err(Bech32Error::HrpChar { index, byte });
        }
        has_lower |= byte.is_ascii_lowercase();
        has_upper |= byte.is_ascii_uppercase();
    }

    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let lowered = s.to_ascii_lowercase();

    let pos = lowered.rfind('1').ok_or(Bech32Error::NoSeparator)?;
    if pos == 0 {
        return Err(Bech32Error::EmptyHrp);
    }
    if pos > MAX_HRP_LEN {
        return Err(Bech32Error::HrpTooLong { len: pos });
    }

    if lowered.len() - pos - 1 < CHECKSUM_CHARS {
        return Err(Bech32Error::TooShort);
    }

    let hrp = &lowered[..pos];
    let mut data5 = Vec::with_capacity(lowered.len() - pos - 1);
    for (offset, byte) in lowered[pos + 1..].bytes().enumerate() {
        let idx = CHARSET
            .iter()
            .position(|x| *x == byte)
            .ok_or(Bech32Error::DataChar {
                index: pos + 1 + offset,
                byte,
            })?;
        data5.push(idx as u8);
    }

    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data5);
    if polymod(&values) != BECH32M_CONST {
        return Err(Bech32Error::BadChecksum);
    }

    data5.truncate(data5.len() - CHECKSUM_CHARS);
    Ok((hrp.to_string(), data5))
}

pub fn encode_bytes(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    encode_fes(hrp, &convert_8_to_5(data))
}

pub fn decode_bytes(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    let (hrp, data5) = decode_fes(s)?;
    let bytes = convert_5_to_8(&data5)?;
    Ok((hrp, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    const BIP350_VALID: [&str; 7] = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];

    #[test]
    fn bip350_valid_vectors_decode() {
        for s in BIP350_VALID {
            let (hrp, data5) = decode_fes(s).unwrap_or_else(|e| panic!("{s:?}: {e}"));
            assert!(!hrp.is_empty());
            assert_eq!(hrp, hrp.to_ascii_lowercase());

            assert_eq!(encode_fes(&hrp, &data5).unwrap(), s.to_ascii_lowercase());
        }

        let max = BIP350_VALID[4];
        assert_eq!(max.len(), MAX_STRING_LEN);
        assert_eq!(decode_fes(max).unwrap().1.len(), 82);

        assert_eq!(82 * 5 % 8, 2);
    }

    #[test]
    fn bip350_invalid_vectors_rejected() {
        let cases: [(&str, Bech32Error); 14] = [
            ("\u{20}1xj0phk", Bech32Error::HrpChar { index: 0, byte: 0x20 }),
            ("\u{7F}1g6xzxy", Bech32Error::HrpChar { index: 0, byte: 0x7F }),
            ("\u{80}1vctc34", Bech32Error::HrpChar { index: 0, byte: 0xC2 }),
            (
                "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
                Bech32Error::TooLong { len: 91 },
            ),
            ("qyrz8wqd2c9m", Bech32Error::NoSeparator),
            ("1qyrz8wqd2c9m", Bech32Error::EmptyHrp),
            ("y1b0jsk6g", Bech32Error::DataChar { index: 2, byte: b'b' }),
            ("lt1igcx5c0", Bech32Error::DataChar { index: 3, byte: b'i' }),
            ("in1muywd", Bech32Error::TooShort),
            ("mm1crxm3i", Bech32Error::DataChar { index: 8, byte: b'i' }),
            ("au1s5cgom", Bech32Error::DataChar { index: 7, byte: b'o' }),
            ("M1VUXWEZ", Bech32Error::BadChecksum),
            ("16plkw9", Bech32Error::EmptyHrp),
            ("1p2gdwpf", Bech32Error::EmptyHrp),
        ];
        for (s, expected) in cases {
            assert_eq!(decode_fes(s), Err(expected), "{s:?}");
        }
    }

    #[test]
    fn bech32_and_bech32m_cross_reject() {
        for s in [
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        ] {
            assert_eq!(decode_fes(s), Err(Bech32Error::BadChecksum), "{s:?}");
        }

        let data5 = convert_8_to_5(&[0x11u8; 20]);
        let m = encode_fes("plne", &data5).unwrap();
        let non_m = encode_fes_bech32("plne", &data5).unwrap();
        assert_ne!(m, non_m);
        assert_eq!(decode_fes(&non_m), Err(Bech32Error::BadChecksum));

        let payload = hex::decode("bcff11daf7dbb8c789b7bcc4e45298041666f92f").unwrap();
        assert_eq!(
            encode_fes_bech32("plne", &convert_8_to_5(&payload)).unwrap(),
            "plne1hnl3rkhhmwuv0zdhhnzwg55cqstxd7f08d9fp2"
        );
    }

    #[test]
    fn pinned_plaine_addresses() {
        let cases = [
            (
                0x00u8,
                "2ada83c1819a5372dae1238fc1ded123c8104fda",
                "plne19tdg8svpnffh9khpyw8urhk3y0ypqn760a7hjh",
            ),
            (
                0x42,
                "bcff11daf7dbb8c789b7bcc4e45298041666f92f",
                "plne1hnl3rkhhmwuv0zdhhnzwg55cqstxd7f0j349yg",
            ),
            (
                0xFF,
                "9b34f060fbc0f0aa11f150e26519deff613277b6",
                "plne1nv60qc8mcrc25y032r3x2xw7lasnyaaktxs6z6",
            ),
        ];
        for (seed, payload_hex, addr) in cases {
            let digest = crate::blake3::hash(&[seed; 32]);
            assert_eq!(hex::encode(&digest[..20]), payload_hex);
            let s = encode_bytes("plne", &digest[..20]).unwrap();
            assert_eq!(s, addr);
            assert_eq!(s.len(), 43);
            let (hrp, bytes) = decode_bytes(&s).unwrap();
            assert_eq!(hrp, "plne");
            assert_eq!(bytes, digest[..20]);
        }
    }

    #[test]
    fn strict_padding() {
        assert_eq!(convert_5_to_8(&[0, 0, 0, 1]), Err(Bech32Error::Padding));

        assert_eq!(convert_5_to_8(&[0, 0, 0, 0]).unwrap(), vec![0, 0]);

        assert_eq!(convert_5_to_8(&[0, 0, 0, 0, 0]).unwrap(), vec![0, 0, 0]);

        assert_eq!(
            convert_5_to_8(&[0, 1, 2, 3, 4, 5, 6, 31]).unwrap(),
            vec![0, 68, 50, 20, 223]
        );
    }

    #[test]
    fn rejects_unpadded_alias() {
        let canonical = "plne1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3k5wr97";
        let alias = "plne1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3lea37uh";
        assert_eq!(canonical.len(), 43);
        assert_eq!(alias.len(), 44);

        let (hrp, bytes) = decode_bytes(canonical).unwrap();
        assert_eq!(hrp, "plne");
        assert_eq!(bytes.len(), 20);

        let (_, data5) = decode_fes(alias).expect("alias checksum is valid");
        assert_eq!(data5.len(), 33);
        assert_eq!(convert_5_to_8(&data5), Err(Bech32Error::Padding));
        assert_eq!(decode_bytes(alias), Err(Bech32Error::Padding));
    }

    #[test]
    fn payload_lengths_decodable() {
        for len in [19usize, 21, 32] {
            let s = encode_bytes("plne", &vec![0x55u8; len]).unwrap();
            assert_eq!(decode_bytes(&s).unwrap().1.len(), len);
        }
    }

    #[test]
    fn case_handling() {
        let s = encode_bytes("plne", &[0x42u8; 20]).unwrap();
        assert_eq!(s, s.to_ascii_lowercase(), "encoder always emits lowercase");
        assert_eq!(decode_bytes(&s.to_uppercase()).unwrap().1, vec![0x42u8; 20]);
        let mixed = format!("plne1{}", s[5..].to_uppercase());
        assert_eq!(decode_bytes(&mixed), Err(Bech32Error::MixedCase));
    }

    #[test]
    fn single_char_substitution_detected() {
        let s = encode_bytes("plne", &[0x42u8; 20]).unwrap();
        let bytes = s.as_bytes();
        for i in 5..bytes.len() {
            for c in CHARSET {
                if *c == bytes[i] {
                    continue;
                }
                let mut v = bytes.to_vec();
                v[i] = *c;
                let corrupt = String::from_utf8(v).unwrap();
                assert!(
                    decode_bytes(&corrupt).is_err(),
                    "undetected substitution at {i}"
                );
            }
        }
    }

    #[test]
    fn encoder_rejects_invalid_input() {
        assert_eq!(encode_fes("", &[]), Err(Bech32Error::EmptyHrp));
        assert_eq!(
            encode_fes("PLNE", &[]),
            Err(Bech32Error::HrpChar {
                index: 0,
                byte: b'P'
            })
        );
        assert_eq!(
            encode_fes("plne", &[32]),
            Err(Bech32Error::DataChar { index: 0, byte: 32 })
        );
        let hrp = "a".repeat(MAX_HRP_LEN + 1);
        assert_eq!(
            encode_fes(&hrp, &[]),
            Err(Bech32Error::HrpTooLong { len: 84 })
        );

        assert_eq!(
            encode_bytes("plne", &[0u8; 60]),
            Err(Bech32Error::TooLong { len: 107 })
        );
    }

    #[test]
    fn roundtrip_bytes() {
        for len in 0..40usize {
            let v: Vec<u8> = (0..len).map(|i| (i * 91 + 7) as u8).collect();
            let s = encode_bytes("plne", &v).unwrap();
            assert_eq!(decode_bytes(&s).unwrap(), ("plne".to_string(), v));
        }
    }
}
