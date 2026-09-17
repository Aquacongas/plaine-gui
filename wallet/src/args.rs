use crate::error::{Result, WalletError};

const BANNED: &[(&str, &str)] = &[
    ("--allow-placeholder-chain-id", "this flag was removed. CHAIN_ID is frozen to the ASCII bytes of PLNE and the all-zero placeholder no longer compiles, so there is nothing left to override. Re-run without it; anything signed under the old placeholder is void and must be re-signed"),
    ("--passphrase", "a passphrase on argv is visible in process listings and shell history; use --passphrase-file or --passphrase-stdin"),
    ("--pass", "a passphrase on argv is visible in process listings and shell history; use --passphrase-file or --passphrase-stdin"),
    ("--password", "a passphrase on argv is visible in process listings and shell history; use --passphrase-file or --passphrase-stdin"),
    ("--seed", "seed material on argv is visible in process listings and shell history; use --seed-stdin or --seed-file"),
    ("--seed-hex", "seed material on argv is visible in process listings and shell history; use --seed-stdin or --seed-file"),
    ("--private-key", "private key material never goes on argv; use --seed-stdin or --seed-file"),
    ("--secret", "secret material never goes on argv"),
];

pub struct Spec {
    pub values: &'static [&'static str],
    pub switches: &'static [&'static str],
}

#[derive(Debug, Default)]
pub struct Parsed {
    values: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Parsed {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn require(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| WalletError::usage(format!("--{name} is required and has no default")))
    }

    pub fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    pub fn count_of(&self, names: &[&str]) -> usize {
        names
            .iter()
            .filter(|n| self.get(n).is_some() || self.has(n))
            .count()
    }
}

pub fn parse(args: &[String], spec: &Spec) -> Result<Parsed> {
    let mut out = Parsed::default();
    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with("--") {
            return Err(WalletError::usage(format!(
                "unexpected argument {arg:?}; every option is written --flag value or --flag=value"
            )));
        }
        let (name_with_dashes, inline) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        if let Some((_, why)) = BANNED.iter().find(|(b, _)| *b == name_with_dashes) {
            return Err(WalletError::usage(format!(
                "{name_with_dashes} is refused: {why}"
            )));
        }

        let Some(stripped) = name_with_dashes.strip_prefix("--") else {
            return Err(WalletError::usage(format!(
                "unexpected argument {arg:?}; every option is written --flag value or --flag=value"
            )));
        };
        let name = stripped.to_string();
        if name.is_empty() {
            return Err(WalletError::usage("bare `--` is not an option"));
        }

        if spec.switches.contains(&name.as_str()) {
            if inline.is_some() {
                return Err(WalletError::usage(format!("--{name} takes no value")));
            }
            if out.switches.contains(&name) {
                return Err(WalletError::usage(format!("--{name} given more than once")));
            }
            out.switches.push(name);
            i += 1;
            continue;
        }
        if spec.values.contains(&name.as_str()) {
            if out.values.iter().any(|(k, _)| *k == name) {
                return Err(WalletError::usage(format!("--{name} given more than once")));
            }
            let value = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    args.get(i)
                        .cloned()
                        .ok_or_else(|| WalletError::usage(format!("--{name} needs a value")))?
                }
            };
            out.values.push((name, value));
            i += 1;
            continue;
        }
        return Err(WalletError::usage(format!(
            "unknown option --{name}; accepted here: {}",
            known_list(spec)
        )));
    }
    Ok(out)
}

fn known_list(spec: &Spec) -> String {
    let mut all: Vec<String> = spec
        .values
        .iter()
        .map(|v| format!("--{v} <value>"))
        .chain(spec.switches.iter().map(|s| format!("--{s}")))
        .collect();
    all.sort();
    all.join(", ")
}

pub fn parse_u64(flag: &str, value: &str) -> Result<u64> {
    value.parse::<u64>().map_err(|_| {
        WalletError::usage(format!("--{flag} must be a decimal integer, got {value:?}"))
    })
}

pub fn parse_u32_flexible(flag: &str, value: &str) -> Result<u32> {
    let r = if let Some(h) = value.strip_prefix("0x") {
        u32::from_str_radix(h, 16)
    } else {
        value.parse::<u32>()
    };
    r.map_err(|_| {
        WalletError::usage(format!(
            "--{flag} must be a decimal or 0x-hex 32-bit integer, got {value:?}"
        ))
    })
}

pub fn parse_pubkey(flag: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = plaine_consensus::hex::decode(value)
        .map_err(|e| WalletError::usage(format!("--{flag}: {e}")))?;
    bytes.as_slice().try_into().map_err(|_| {
        WalletError::usage(format!(
            "--{flag} must be 32 bytes (64 hex digits), got {} bytes",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: Spec = Spec {
        values: &["in", "fee", "nonce"],
        switches: &["reuse-nonce"],
    };

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn both_forms_parse_identically() {
        let p1 = parse(&a(&["--fee", "1"]), &SPEC).unwrap();
        let p2 = parse(&a(&["--fee=1"]), &SPEC).unwrap();
        assert_eq!(p1.get("fee"), Some("1"));
        assert_eq!(p1.get("fee"), p2.get("fee"));
    }

    #[test]
    fn repeated_flag_is_an_error() {
        let err = parse(&a(&["--fee", "1", "--fee", "999"]), &SPEC).unwrap_err();
        assert_eq!(err.kind(), "usage");
        assert!(err.to_string().contains("--fee given more than once"));
        assert!(parse(&a(&["--reuse-nonce", "--reuse-nonce"]), &SPEC).is_err());
    }

    #[test]
    fn unknown_flags_are_errors() {
        let err = parse(&a(&["--feee", "1"]), &SPEC).unwrap_err();
        assert!(err.to_string().contains("unknown option --feee"));
        assert!(
            err.to_string().contains("--fee <value>"),
            "must list the real flags"
        );
    }

    #[test]
    fn missing_value_is_an_error() {
        assert!(parse(&a(&["--fee"]), &SPEC).is_err());
    }

    #[test]
    fn switches_and_values_do_not_mix() {
        assert!(parse(&a(&["--reuse-nonce=yes"]), &SPEC).is_err());

        let p = parse(&a(&["--fee", "--reuse-nonce"]), &SPEC).unwrap();
        assert_eq!(p.get("fee"), Some("--reuse-nonce"));
        assert!(parse_u64("fee", p.get("fee").unwrap()).is_err());
    }

    #[test]
    fn extra_leading_dashes_not_trimmed() {
        for bad in ["----fee", "------fee", "----fee=1", "--------nonce"] {
            let err = parse(&a(&[bad, "1"]), &SPEC).unwrap_err();
            assert_eq!(err.kind(), "usage", "{bad}");
            assert!(
                err.to_string().contains("unknown option"),
                "{bad} must be unknown, got: {err}"
            );
            assert!(
                err.to_string().contains("--fee <value>"),
                "the refusal must still list the real flags: {err}"
            );
        }

        assert_eq!(
            parse(&a(&["--fee", "1"]), &SPEC).unwrap().get("fee"),
            Some("1")
        );
    }

    #[test]
    fn positional_arguments_are_refused() {
        assert!(parse(&a(&["oops"]), &SPEC).is_err());
        assert!(parse(&a(&["--fee", "1", "oops"]), &SPEC).is_err());
    }

    #[test]
    fn passphrase_on_argv_is_refused_by_name() {
        for bad in [
            "--passphrase",
            "--pass",
            "--password",
            "--seed",
            "--seed-hex",
        ] {
            let err = parse(&a(&[bad, "hunter2"]), &SPEC).unwrap_err();
            assert!(
                err.to_string().contains("is refused"),
                "{bad} must be refused by name, got: {err}"
            );
        }

        assert!(parse(&a(&["--passphrase=hunter2"]), &SPEC).is_err());
    }

    #[test]
    fn removed_chain_id_flag_is_refused() {
        let err = parse(&a(&["--allow-placeholder-chain-id"]), &SPEC).unwrap_err();
        assert_eq!(err.kind(), "usage", "usage errors exit 2");
        assert!(err.to_string().contains("was removed"), "{err}");
        assert!(
            err.to_string().contains("PLNE"),
            "must name the frozen value: {err}"
        );

        assert!(parse(&a(&["--allow-placeholder-chain-id=1"]), &SPEC).is_err());
    }

    #[test]
    fn require_has_no_default() {
        let p = parse(&a(&[]), &SPEC).unwrap();
        let err = p.require("fee").unwrap_err();
        assert!(err.to_string().contains("has no default"));
    }

    #[test]
    fn number_parsers_name_the_flag() {
        assert!(parse_u64("nonce", "x")
            .unwrap_err()
            .to_string()
            .contains("--nonce"));
        assert_eq!(
            parse_u32_flexible("bits", "0x2000ffff").unwrap(),
            0x2000_ffff
        );
        assert_eq!(parse_u32_flexible("bits", "17").unwrap(), 17);
        assert!(parse_u32_flexible("bits", "zz").is_err());
        assert!(parse_pubkey("author-pubkey", "00").is_err());
        assert!(parse_pubkey("author-pubkey", &"11".repeat(32)).is_ok());
    }
}
