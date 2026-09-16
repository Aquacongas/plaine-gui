use crate::error::{Result, WalletError};
use crate::secret::Secret32;

// The hex codec below is branchless on the byte value. No data-dependent
// branch means seed material does not leak through decode/encode timing.
fn in_range(c: u8, lo: u8, hi: u8) -> u8 {
    let x = c as i16;

    let ge_lo = ((lo as i16 - x - 1) >> 15) & 1;

    let le_hi = ((x - hi as i16 - 1) >> 15) & 1;
    (ge_lo & le_hi) as u8
}

fn nibble_to_ascii(n: u8) -> u8 {
    let gt9 = (9u8.wrapping_sub(n) >> 7) & 1;
    n.wrapping_add(b'0').wrapping_add(gt9.wrapping_mul(39))
}

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(nibble_to_ascii(b >> 4) as char);
        s.push(nibble_to_ascii(b & 0x0f) as char);
    }
    s
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(WalletError::format(format!(
            "hex value has odd length {} (a 32-byte seed is exactly 64 hex digits)",
            b.len()
        )));
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut all_valid: u8 = 1;
    for pair in b.chunks_exact(2) {
        let (hi, hv) = ascii_to_nibble(pair[0]);
        let (lo, lv) = ascii_to_nibble(pair[1]);
        all_valid &= hv & lv;
        out.push((hi << 4) | lo);
    }
    if all_valid != 1 {
        for x in out.iter_mut() {
            *x = 0;
        }
        return Err(WalletError::format(
            "hex value contains a non-hexadecimal character".to_string(),
        ));
    }
    Ok(out)
}

pub fn decode_seed(s: &str) -> Result<Secret32> {
    let mut v = decode(s)?;
    if v.len() != 32 {
        for x in v.iter_mut() {
            *x = 0;
        }
        return Err(WalletError::format(format!(
            "expected 64 hex digits (32 bytes), got {} bytes",
            v.len()
        )));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);

    for x in v.iter_mut() {
        *x = 0;
    }
    Ok(Secret32::from_bytes(a))
}

pub const TAG_BACKUP_CHECK: &[u8] = b"PLNE-wallet-backup-check-v1";

pub const BACKUP_CHECK_DIGITS: usize = 4;

// two-byte checksum tail on the backup string; catches a one-char slip before
// it silently restores a different, empty wallet
pub fn backup_check(seed: &[u8; 32]) -> [u8; 2] {
    let mut h = plaine_consensus::blake3::Hasher::new();
    h.update(TAG_BACKUP_CHECK);
    h.update(seed);
    let full = h.finalize();
    [full[0], full[1]]
}

pub fn encode_backup(seed: &Secret32) -> String {
    let mut s = encode(seed.expose());
    s.push_str(&encode(&backup_check(seed.expose())));
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedSource {
    Checked,
    Unchecked,
}

pub fn decode_backup(s: &str) -> Result<(Secret32, SeedSource)> {
    let n = s.len();
    if n == 64 + BACKUP_CHECK_DIGITS && s.is_ascii() {
        let seed = decode_seed(&s[..64])?;
        let given = decode(&s[64..]).map_err(|_| {
            WalletError::format(
                "the last 4 characters of a backup string are its checksum and must be hex",
            )
        })?;
        if !crate::secret::ct_eq(&given, &backup_check(seed.expose())) {
            return Err(WalletError::refused(
                "backup checksum mismatch: at least one character differs from the string \
                 `backup` printed. Restoring it would produce a different, empty wallet, \
                 so it is refused rather than warned about. Check the transcription and \
                 try again.",
            ));
        }
        return Ok((seed, SeedSource::Checked));
    }
    Ok((decode_seed(s)?, SeedSource::Unchecked))
}

fn ascii_to_nibble(c: u8) -> (u8, u8) {
    let is_digit = in_range(c, b'0', b'9');
    let is_lower = in_range(c, b'a', b'f');
    let is_upper = in_range(c, b'A', b'F');
    let v = is_digit.wrapping_mul(c.wrapping_sub(b'0'))
        | is_lower.wrapping_mul(c.wrapping_sub(b'a').wrapping_add(10))
        | is_upper.wrapping_mul(c.wrapping_sub(b'A').wrapping_add(10));
    (v & 0x0f, is_digit | is_lower | is_upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agrees_with_consensus_encoder() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(encode(&all), plaine_consensus::hex::encode(&all));
    }

    #[test]
    fn roundtrip_all_bytes() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn accepts_uppercase_and_rejects_garbage() {
        assert_eq!(decode("DEADbeef").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(decode("abc").is_err(), "odd length");
        assert!(decode("zz").is_err(), "not hex");
        assert!(decode("00 11").is_err(), "space is not hex");
    }

    #[test]
    fn error_message_never_quotes_the_input() {
        let err = decode("00112233445566778899aabbccddeeffzz").unwrap_err();
        let text = err.to_string();
        assert!(!text.contains("0011"), "error text leaked the input: {text}");
        assert!(!text.contains('z'), "error text named the character: {text}");
    }

    #[test]
    fn one_char_slip_in_backup_is_caught() {
        let seed = Secret32::from_bytes(plaine_consensus::blake3::hash(b"sechex backup"));
        let printed = encode_backup(&seed);
        assert_eq!(printed.len(), 68);
        let (back, src) = decode_backup(&printed).unwrap();
        assert_eq!(back.expose(), seed.expose());
        assert_eq!(src, SeedSource::Checked);

        let digits = b"0123456789abcdef";
        let mut checked = 0usize;
        for pos in 0..printed.len() {
            for &d in digits {
                let mut v: Vec<u8> = printed.as_bytes().to_vec();
                if v[pos] == d {
                    continue;
                }
                v[pos] = d;
                let typo = String::from_utf8(v).unwrap();
                assert!(
                    decode_backup(&typo).is_err(),
                    "a one-character slip at {pos} was accepted: {typo}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 68 * 15);

        let (bare, src) = decode_backup(&encode(seed.expose())).unwrap();
        assert_eq!(bare.expose(), seed.expose());
        assert_eq!(src, SeedSource::Unchecked);

        for bad in [
            "".to_string(),
            printed[..67].to_string(),
            format!("{printed}0"),
            format!("{printed}zz"),
            printed.replacen('a', "\u{00e9}", 1),
            "\u{00e9}".repeat(34),
        ] {
            let e = decode_backup(&bad).unwrap_err();
            assert!(!e.to_string().contains(&bad) || bad.is_empty(), "echoed: {e}");
        }
    }

    #[test]
    fn backup_checksum_is_seed_specific() {
        let a = Secret32::from_bytes(plaine_consensus::blake3::hash(b"backup check a"));
        let b = Secret32::from_bytes(plaine_consensus::blake3::hash(b"backup check b"));
        assert_ne!(backup_check(a.expose()), backup_check(b.expose()));
        assert_eq!(backup_check(a.expose()), backup_check(a.expose()));

        assert_ne!(&backup_check(a.expose())[..], &a.expose()[..2]);
        assert_ne!(
            &backup_check(a.expose())[..],
            &plaine_consensus::blake3::hash(a.expose())[..2]
        );
    }

    #[test]
    fn decode_seed_enforces_the_length() {
        let seed = plaine_consensus::blake3::hash(b"sechex seed");
        let hex = encode(&seed);
        assert_eq!(hex.len(), 64);
        assert_eq!(decode_seed(&hex).unwrap().expose(), &seed);
        assert!(decode_seed(&encode(&seed[..31])).is_err());
    }
}
