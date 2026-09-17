use std::path::PathBuf;

use crate::config::LogLevel;
use plaine_rpc::methods::edit_distance;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Run(Args),
    PrintConfig(Args),
    CheckConfig(Args),
    Help,
    Version,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Args {
    pub config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub log_level: Option<LogLevel>,
    pub write_config: bool,
}

impl Args {
    fn new() -> Args {
        Args {
            write_config: true,
            ..Default::default()
        }
    }
}

const FLAGS: &[&str] = &[
    "--config",
    "--data-dir",
    "--log-level",
    "--print-config",
    "--check-config",
    "--no-write-config",
    "--version",
    "--help",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgError {
    pub message: String,
    pub help: Option<String>,
}

impl core::fmt::Display for ArgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "error: {}", self.message)?;
        if let Some(h) = &self.help {
            write!(f, "\n\nhelp: {h}")?;
        }
        Ok(())
    }
}

fn err(message: impl Into<String>) -> ArgError {
    ArgError {
        message: message.into(),
        help: None,
    }
}

fn err_help(message: impl Into<String>, help: impl Into<String>) -> ArgError {
    ArgError {
        message: message.into(),
        help: Some(help.into()),
    }
}

pub fn parse<I, S>(argv: I) -> Result<Action, ArgError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let items: Vec<String> = argv.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut args = Args::new();
    let mut action: Option<Action> = None;
    let mut i = 0usize;

    // normalize `--flag=value` into two tokens up front so the loop below only
    // has to handle the space-separated form.
    let mut tokens: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        match item.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => {
                tokens.push(flag.to_string());
                tokens.push(value.to_string());
            }
            _ => tokens.push(item),
        }
    }

    while i < tokens.len() {
        let arg = tokens[i].as_str();
        let mut take_value = |name: &str| -> Result<String, ArgError> {
            i += 1;
            match tokens.get(i) {
                // reject a following `--flag` as the value, so a forgotten value
                // fails loudly instead of eating the next option.
                Some(v) if !v.starts_with("--") => Ok(v.clone()),

                _ => Err(err_help(
                    format!("{name} needs a value"),
                    format!("write it as `{name} <value>` or `{name}=<value>`"),
                )),
            }
        };
        match arg {
            "--help" | "-h" => return Ok(Action::Help),
            "--version" | "-V" => return Ok(Action::Version),
            "--config" => {
                let v = take_value("--config")?;
                if args.config.is_some() {
                    return Err(err("--config given twice"));
                }
                args.config = Some(PathBuf::from(v));
            }
            "--data-dir" => {
                let v = take_value("--data-dir")?;
                if args.data_dir.is_some() {
                    return Err(err("--data-dir given twice"));
                }
                args.data_dir = Some(crate::paths::expand_tilde(&v));
            }
            "--log-level" => {
                let v = take_value("--log-level")?;
                args.log_level = Some(LogLevel::parse(&v).ok_or_else(|| {
                    err_help(
                        format!("`{v}` is not a log level"),
                        "levels are: error, warn, info, debug, trace",
                    )
                })?);
            }
            "--no-write-config" => args.write_config = false,
            "--print-config" | "--check-config" => {
                if action.is_some() {
                    return Err(err(
                        "--print-config and --check-config are mutually exclusive",
                    ));
                }
                action = Some(if arg == "--print-config" {
                    Action::PrintConfig(Args::new())
                } else {
                    Action::CheckConfig(Args::new())
                });
            }

            "--role" => {
                return Err(err_help(
                    "`--role` does not exist, and it is not planned",
                    "everything a role selects is already in noded.toml - the p2p, rpc and \
                     stratum bind addresses, the token, the seeds - and what is left is enforced \
                     by the kernel against this process (SocketBindAllow, IPAddressAllow, \
                     nftables), where it is worth something precisely because the node cannot \
                     choose it. Delete ROLE_ARG from /etc/plaine/role.env and the EnvironmentFile \
                     line that reads it; there is nothing for them to become.",
                ));
            }
            other => {
                if !other.starts_with('-') {
                    return Err(err_help(
                        format!("unexpected argument `{other}`"),
                        "plaine-noded takes no positional arguments. Did you mean \
                         `--config <path>` or `--data-dir <path>`?",
                    ));
                }
                let best = FLAGS
                    .iter()
                    .min_by_key(|f| edit_distance(other, f))
                    .copied();
                return Err(match best {
                    Some(b) if edit_distance(other, b) <= 3 => err_help(
                        format!("unknown option `{other}`"),
                        format!("did you mean `{b}`?"),
                    ),
                    _ => err_help(
                        format!("unknown option `{other}`"),
                        "run `plaine-noded --help` for the list",
                    ),
                });
            }
        }
        i += 1;
    }

    Ok(match action {
        Some(Action::PrintConfig(_)) => Action::PrintConfig(args),
        Some(Action::CheckConfig(_)) => Action::CheckConfig(args),
        _ => Action::Run(args),
    })
}

pub fn usage() -> String {
    format!(
        "plaine-noded {} - Plaine node ({})

USAGE:
    plaine-noded [options]

    With no options at all it does the right thing: it finds or creates
    {}, uses the checkpoint and author keys built into this
    binary, and serves JSON-RPC on 127.0.0.1:{}. You do not have to configure
    anything.

OPTIONS:
    --config <path>        config file (default: <data-dir>/noded.toml)
    --data-dir <path>      override node.data_dir
    --log-level <level>    error | warn | info | debug | trace  (default: info)
    --print-config         print the effective configuration, with the source
                           of every value, and exit
    --check-config         validate the configuration and exit
                           (0 = good, 2 = something is wrong)
    --no-write-config      do not create noded.toml on first run
    -V, --version          print version and exit
    -h, --help             print this and exit

EXIT CODES:
    0  clean exit
    1  a runtime failure
    2  bad usage or bad configuration
    3  another node is already using this data directory or these ports

WHAT IS NOT HERE:
    No mining flags: mining is Stratum only, and the node has no second path.
    No key material of any kind: the node never holds a private key. Sending
    a transaction, or an author announcement, is the wallet's job.
    No --role. A deployment role selects bind addresses, which noded.toml
    already carries, and kernel-level confinement (SocketBindAllow,
    IPAddressAllow, nftables), which this process must not be able to choose
    for itself. Passing --role is refused with that explanation.
",
        env!("CARGO_PKG_VERSION"),
        plaine_consensus::constants::TICKER,
        crate::paths::default_data_dir().display(),
        plaine_consensus::constants::PORT_RPC,
    )
}

pub fn version() -> String {
    format!(
        "plaine-noded {}\nchain {}  ports p2p {} / rpc {} / stratum {}+{}\n\
         checkpoint sunset height {} (compiled in)",
        env!("CARGO_PKG_VERSION"),
        plaine_consensus::constants::TICKER,
        plaine_consensus::constants::PORT_P2P,
        plaine_consensus::constants::PORT_RPC,
        plaine_consensus::constants::PORT_STRATUM,
        plaine_consensus::constants::PORT_STRATUM_TLS,
        plaine_consensus::constants::CHECKPOINT_SUNSET_HEIGHT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_args_runs_with_defaults() {
        let a = parse(Vec::<String>::new()).expect("parse");
        assert_eq!(
            a,
            Action::Run(Args {
                write_config: true,
                ..Default::default()
            })
        );
    }

    #[test]
    fn both_flag_spellings_work() {
        for argv in [vec!["--log-level", "debug"], vec!["--log-level=debug"]] {
            let Action::Run(a) = parse(argv).expect("parse") else {
                panic!("expected Run")
            };
            assert_eq!(a.log_level, Some(LogLevel::Debug));
        }
    }

    #[test]
    fn missing_value_not_swallowed() {
        let e = parse(["--config", "--version"]).expect_err("should fail");
        assert!(e.message.contains("--config needs a value"), "{e}");
    }

    #[test]
    fn typo_suggests_real_flag() {
        let e = parse(["--data_dir", "/tmp"]).expect_err("should fail");
        assert!(e.help.unwrap().contains("--data-dir"), "{}", e.message);
    }

    #[test]
    fn positional_arg_refused() {
        let e = parse(["/etc/plaine/noded.toml"]).expect_err("should fail");
        assert!(e.message.contains("unexpected argument"));
        assert!(e.help.unwrap().contains("--config"));
    }

    #[test]
    fn repeats_and_conflicts_are_refused() {
        assert!(parse(["--config", "a", "--config", "b"]).is_err());
        assert!(parse(["--print-config", "--check-config"]).is_err());
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(
            parse(["--help", "--nonsense"]).expect("parse"),
            Action::Help
        );
        assert_eq!(parse(["-V", "--nonsense"]).expect("parse"), Action::Version);
    }

    #[test]
    fn action_flags_keep_options() {
        let Action::PrintConfig(a) =
            parse(["--print-config", "--log-level", "debug"]).expect("parse")
        else {
            panic!("expected PrintConfig")
        };
        assert_eq!(a.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn invalid_level_names_valid() {
        let e2 = parse(["--log-level", "verbose"]).expect_err("should fail");
        assert!(e2.help.unwrap().contains("trace"));
    }

    #[test]
    fn role_flag_refused_by_name() {
        for argv in [vec!["--role", "edge"], vec!["--role=core"], vec!["--role"]] {
            let e = parse(argv.clone()).expect_err("--role must be refused");
            assert!(
                e.message.contains("`--role` does not exist"),
                "{argv:?}: {e}"
            );
            let help = e.help.as_deref().unwrap_or("");
            assert!(
                help.contains("noded.toml"),
                "{argv:?}: the refusal must name the alternative"
            );
            assert!(
                help.contains("role.env"),
                "{argv:?}: the refusal must name the stub to delete"
            );
            assert!(
                !help.contains("did you mean"),
                "{argv:?}: --role must not be reported as a typo for a flag that exists"
            );
        }

        assert!(!FLAGS.contains(&"--role"));
    }

    #[test]
    fn help_says_zero_config() {
        let u = usage();
        assert!(u.contains("You do not have to configure"));

        assert!(u.contains("mining is Stratum only"));
        assert!(u.contains("never holds a private key"));
        assert!(
            u.contains("No --role"),
            "the role decision must be discoverable from --help"
        );
        assert!(u.contains("EXIT CODES"));
    }
}
