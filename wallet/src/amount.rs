use crate::error::{Result, WalletError};
use plaine_consensus::constants::{DECIMALS, MILE_PER_PLNE};

// corruption guard, not a supply cap (emission is uncapped): stops a mistyped
// amount from parsing into an absurd u128
pub const MAX_PARSE_MILE: u128 = 1_000_000_000_000_000;

pub fn parse_mile_for(flag: &str, s: &str) -> Result<u128> {
    parse_inner(&format!("--{flag}"), s)
}

pub fn parse_mile(s: &str) -> Result<u128> {
    parse_inner("amount", s)
}

fn parse_inner(what: &str, s: &str) -> Result<u128> {
    let lower = s.to_ascii_lowercase();
    let (num, unit_is_mile) = if let Some(rest) = lower.strip_suffix("mile") {
        (rest, true)
    } else if let Some(rest) = lower.strip_suffix("plne") {
        (rest, false)
    } else {
        return Err(WalletError::usage(format!(
            "{what} {s:?} has no unit; write it as `<n>mile` or `<n>plne` \
             (they differ by a factor of 10^{DECIMALS}, so the unit is not optional)"
        )));
    };

    if num.is_empty() {
        return Err(WalletError::usage(format!("{what} {s:?} has no digits")));
    }
    if num.starts_with('+') || num.starts_with('-') {
        return Err(WalletError::usage(format!(
            "{what} {s:?} carries a sign; amounts are unsigned"
        )));
    }
    if num.contains('e') {
        return Err(WalletError::usage(format!(
            "{what} {s:?} looks like exponent notation; write the digits out"
        )));
    }
    if num.contains('_') || num.contains(',') || num.contains(' ') {
        return Err(WalletError::usage(format!(
            "{what} {s:?} contains a separator; digits and at most one `.` only"
        )));
    }

    let (int_part, frac_part) = match num.split_once('.') {
        None => (num, ""),
        Some((_, rest)) if rest.contains('.') => {
            return Err(WalletError::usage(format!(
                "{what} {s:?} has more than one decimal point"
            )))
        }
        Some((i, f)) => (i, f),
    };

    if unit_is_mile && !frac_part.is_empty() {
        return Err(WalletError::usage(format!(
            "{what} {s:?} has a fractional part but mile is the indivisible unit"
        )));
    }
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(WalletError::usage(format!("{what} {s:?} has no digits")));
    }
    for (name, part) in [("integer", int_part), ("fractional", frac_part)] {
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WalletError::usage(format!(
                "{what} {s:?} has a non-digit character in its {name} part"
            )));
        }
    }
    if frac_part.len() > DECIMALS as usize {
        return Err(WalletError::usage(format!(
            "{what} {s:?} has {} fractional digits; PLNE has {DECIMALS}",
            frac_part.len()
        )));
    }

    let int_val: u128 = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse::<u128>()
            .map_err(|_| WalletError::usage(format!("{what} {s:?} overflows u128")))?
    };

    let total = if unit_is_mile {
        int_val
    } else {
        let scaled = int_val
            .checked_mul(MILE_PER_PLNE)
            .ok_or_else(|| WalletError::usage(format!("{what} {s:?} overflows u128")))?;
        let mut frac_val: u128 = 0;

        let padded: String = {
            let mut p = frac_part.to_string();
            while p.len() < DECIMALS as usize {
                p.push('0');
            }
            p
        };
        if !padded.is_empty() {
            frac_val = padded
                .parse::<u128>()
                .map_err(|_| WalletError::usage(format!("{what} {s:?} overflows u128")))?;
        }
        scaled
            .checked_add(frac_val)
            .ok_or_else(|| WalletError::usage(format!("{what} {s:?} overflows u128")))?
    };

    if total > MAX_PARSE_MILE {
        return Err(WalletError::usage(format!(
            "{what} {s:?} exceeds the parse ceiling ({} mile); this is a corruption \
             guard, not a supply cap (emission is uncapped)",
            MAX_PARSE_MILE
        )));
    }
    Ok(total)
}

pub fn format_plne(mile: u128) -> String {
    let int = mile / MILE_PER_PLNE;
    let frac = mile % MILE_PER_PLNE;
    let mut f = format!("{frac:0width$}", width = DECIMALS as usize);
    while f.len() > 1 && f.ends_with('0') {
        f.pop();
    }
    format!("{int}.{f}")
}

pub fn describe(mile: u128) -> String {
    format!("{mile} mile ({} PLNE)", format_plne(mile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_are_mandatory() {
        assert!(parse_mile("5").is_err());
        assert!(parse_mile("").is_err());
        assert!(parse_mile("plne").is_err());
        assert!(parse_mile("mile").is_err());
    }

    #[test]
    fn one_plne_is_ten_to_the_six_mile() {
        assert_eq!(parse_mile("1plne").unwrap(), 1_000_000);
        assert_eq!(parse_mile("1PLNE").unwrap(), 1_000_000);
        assert_eq!(parse_mile("1000000mile").unwrap(), 1_000_000);
        assert_eq!(
            parse_mile("1plne").unwrap(),
            parse_mile("1000000mile").unwrap()
        );
    }

    #[test]
    fn fractions_are_exact() {
        assert_eq!(parse_mile("1.5plne").unwrap(), 1_500_000);
        assert_eq!(parse_mile("0.1plne").unwrap(), 100_000);
        assert_eq!(parse_mile("0.000001plne").unwrap(), 1);
        assert_eq!(parse_mile(".5plne").unwrap(), 500_000);
    }

    #[test]
    fn floats_and_separators_and_signs_are_refused() {
        for bad in [
            "1e6plne",
            "1E6plne",
            "-1plne",
            "+1plne",
            "1_000plne",
            "1,000plne",
            "1 000plne",
            "1.2.3plne",
            "0.1mile",
            "1.0000001plne",
            "abcplne",
            "1.2xplne",
        ] {
            assert!(parse_mile(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn the_parse_ceiling_is_the_ceiling() {
        let max = format!("{MAX_PARSE_MILE}mile");
        assert_eq!(parse_mile(&max).unwrap(), MAX_PARSE_MILE);
        assert!(parse_mile(&format!("{}mile", MAX_PARSE_MILE + 1)).is_err());
        assert!(parse_mile("340282366920938463463374607431768211455mile").is_err());
    }

    #[test]
    fn overflow_does_not_panic() {
        assert!(parse_mile("340282366920938463463374607431768211455plne").is_err());
        assert!(parse_mile(&format!("{}0plne", u128::MAX)).is_err());
    }

    #[test]
    fn formatting_roundtrips() {
        for mile in [0u128, 1, 999, 1_000_000, 1_500_000] {
            let s = format!("{}plne", format_plne(mile));
            assert_eq!(parse_mile(&s).unwrap(), mile, "roundtrip failed for {mile}");
        }
        assert_eq!(format_plne(0), "0.0");
        assert_eq!(format_plne(1_000_000), "1.0");
        assert_eq!(format_plne(1_500_000), "1.5");
        assert_eq!(format_plne(1), "0.000001");
    }
}
