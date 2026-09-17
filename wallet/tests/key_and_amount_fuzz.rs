#![forbid(unsafe_code)]

#[cfg(feature = "author-tools")]
use plaine_consensus::codec::AnnouncementTx;
#[cfg(feature = "author-tools")]
use plaine_consensus::tx;
use plaine_consensus::{crypto, hex};

const NET: plaine_consensus::constants::Network = plaine_consensus::constants::Network::Main;

use plaine_wallet::ui::Streams;
use std::io::Cursor;
use std::path::PathBuf;

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("plaine-wallet-fuzz-{tag}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
    fn path(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
    fn s(&self, n: &str) -> String {
        self.path(n).display().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn all(&self) -> String {
        format!("{}\n{}", self.out, self.err)
    }
    fn ok(&self) -> &Run {
        assert_eq!(self.code, 0, "command failed:\n{}", self.all());
        self
    }
    fn field(&self, label: &str) -> String {
        let line = self
            .out
            .lines()
            .find(|l| l.trim_start().starts_with(label))
            .unwrap_or_else(|| panic!("no `{label}` line in:\n{}", self.out));
        line.trim_start()
            .strip_prefix(label)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    }
}

fn wallet(argv: &[&str], stdin: &[u8]) -> Run {
    let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let mut input = Cursor::new(stdin.to_vec());
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = {
        let mut s = Streams::new(&mut input, &mut out, &mut err);
        plaine_wallet::wallet_cli::run(&args, &mut s)
    };
    Run {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

fn wallet_bounded(argv: &[&str], stdin: &[u8], secs: u64) -> Option<Run> {
    let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let input = stdin.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let _ = tx.send(wallet(&refs, &input));
    });
    rx.recv_timeout(std::time::Duration::from_secs(secs)).ok()
}

fn seed_hex(tag: &[u8]) -> String {
    hex::encode(&plaine_consensus::blake3::hash(tag))
}

fn make_key(d: &Dir, name: &str, role: &str, tag: &[u8]) -> (String, String, String) {
    let pass = d.s("pass.txt");
    if !d.path("pass.txt").exists() {
        std::fs::write(&pass, "a generated passphrase, not a chosen one").unwrap();
    }
    let out = d.s(name);
    let r = wallet(
        &[
            "new",
            "--out",
            &out,
            "--role",
            role,
            "--seed-stdin",
            "--passphrase-file",
            &pass,
            "--kdf-iters",
            "1024",
        ],
        seed_hex(tag).as_bytes(),
    );
    r.ok();
    let a = wallet(&["address", "--in", &out], b"");
    a.ok();
    (out, a.out.trim().to_string(), r.field("pubkey"))
}

#[cfg(feature = "author-tools")]
#[test]
fn journal_refuses_fee_or_encoding_change_at_nonce() {
    let d = Dir::new("journal-fee");
    let (key, _, pubkey) = make_key(&d, "author.plnekey", "author", b"journal fee change");
    std::fs::write(
        d.path("msg.txt"),
        "EMERGENCY: switch to Isochron v2 at 100000",
    )
    .unwrap();

    let sign_with = |fee: &str, encoding: &str, extra: &[&str]| -> Run {
        let mut v = vec![
            "announce",
            "--in",
            &key,
            "--author-pubkey",
            &pubkey,
            "--payload-file",
            &d.s("msg.txt"),
            "--encoding",
            encoding,
            "--fee",
            fee,
            "--nonce",
            "42",
            "--passphrase-file",
            &d.s("pass.txt"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
        v.extend(extra.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
        wallet(&refs, b"")
    };

    let a = sign_with("50000mile", "1", &[]);
    a.ok();

    let bumped = sign_with("900000mile", "1", &[]);
    assert_ne!(
        bumped.code,
        0,
        "a fee bump at a used nonce must be refused:\n{}",
        bumped.all()
    );
    assert!(bumped.err.contains("nonce 42"), "{}", bumped.err);
    assert!(
        bumped.err.contains("different announcement"),
        "{}",
        bumped.err
    );

    let recoded = sign_with("50000mile", "2", &[]);
    assert_ne!(
        recoded.code,
        0,
        "an encoding change must be refused:\n{}",
        recoded.all()
    );
    assert!(recoded.err.contains("nonce 42"), "{}", recoded.err);

    let retry = sign_with("50000mile", "1", &[]);
    retry.ok();
    assert_eq!(
        retry.field("hex"),
        a.field("hex"),
        "a retry is byte-identical"
    );

    let forced = sign_with("900000mile", "1", &["--reuse-nonce"]);
    forced.ok();
    assert!(forced.err.contains("--reuse-nonce given"), "{}", forced.err);

    let ta = AnnouncementTx::decode(&hex::decode(&a.field("hex")).unwrap()).unwrap();
    let tb = AnnouncementTx::decode(&hex::decode(&forced.field("hex")).unwrap()).unwrap();
    let author = <[u8; 32]>::try_from(hex::decode(&pubkey).unwrap().as_slice()).unwrap();
    tx::check_announcement_stateless(NET, &ta, &author).unwrap();
    tx::check_announcement_stateless(NET, &tb, &author).unwrap();
    assert_eq!((ta.nonce, tb.nonce), (42, 42));
    assert_ne!(ta.txid().unwrap(), tb.txid().unwrap());

    let jnl = std::fs::read_to_string(format!("{key}.journal")).unwrap();
    assert!(
        jnl.contains("msg_b3="),
        "the journal must record the signed message: {jnl}"
    );
    let msg_hashes: Vec<&str> = jnl
        .split_whitespace()
        .filter_map(|f| f.strip_prefix("msg_b3="))
        .collect();
    assert_eq!(msg_hashes.len(), 3, "one per signed announcement: {jnl}");
    assert_ne!(
        msg_hashes[0], msg_hashes[2],
        "the fee bump is a different message"
    );
}

#[cfg(feature = "author-tools")]
#[test]
fn rotation_carries_the_journal() {
    let d = Dir::new("rotate-jnl");
    let (old_key, _, pubkey) = make_key(&d, "author.plnekey", "author", b"rotate key");
    std::fs::write(d.path("a.txt"), "first statement").unwrap();
    std::fs::write(d.path("b.txt"), "a contradictory second statement").unwrap();

    let announce = |key: &str, payload: &str| -> Run {
        wallet(
            &[
                "announce",
                "--in",
                key,
                "--author-pubkey",
                &pubkey,
                "--payload-file",
                payload,
                "--encoding",
                "1",
                "--fee",
                "50000mile",
                "--nonce",
                "9",
                "--passphrase-file",
                &d.s("pass.txt"),
            ],
            b"",
        )
    };

    let first = announce(&old_key, &d.s("a.txt"));
    first.ok();

    let blocked = announce(&old_key, &d.s("b.txt"));
    assert_ne!(blocked.code, 0, "control: the journal must refuse here");
    assert!(blocked.err.contains("nonce 9"), "{}", blocked.err);

    let new_key = d.s("author-rotated.plnekey");
    let rot = wallet(
        &[
            "passphrase",
            "--in",
            &old_key,
            "--out",
            &new_key,
            "--old-passphrase-file",
            &d.s("pass.txt"),
            "--new-passphrase-file",
            &d.s("pass.txt"),
            "--kdf-iters",
            "1024",
        ],
        b"",
    );
    rot.ok();
    assert!(
        rot.all().contains("journal"),
        "the rotation must say what happened to the journal:\n{}",
        rot.all()
    );
    assert!(
        d.path("author-rotated.plnekey.journal").exists(),
        "the rotated key must carry the journal:\n{}",
        rot.all()
    );
    assert_eq!(
        std::fs::read_to_string(d.path("author.plnekey.journal")).unwrap(),
        std::fs::read_to_string(d.path("author-rotated.plnekey.journal")).unwrap(),
        "the carried journal must be the same history, not a fresh one"
    );

    let second = announce(&new_key, &d.s("b.txt"));
    assert_ne!(
        second.code,
        0,
        "the journal defence must survive rotation:\n{}",
        second.all()
    );
    assert!(second.err.contains("nonce 9"), "{}", second.err);

    let retry = announce(&new_key, &d.s("a.txt"));
    retry.ok();
    assert_eq!(
        retry.field("hex"),
        first.field("hex"),
        "same key, same message"
    );

    let ta = AnnouncementTx::decode(&hex::decode(&first.field("hex")).unwrap()).unwrap();
    let tb = AnnouncementTx::decode(&hex::decode(&retry.field("hex")).unwrap()).unwrap();
    let author = <[u8; 32]>::try_from(hex::decode(&pubkey).unwrap().as_slice()).unwrap();
    tx::check_announcement_stateless(NET, &ta, &author).unwrap();
    tx::check_announcement_stateless(NET, &tb, &author).unwrap();
    assert_eq!(
        ta.from_pub, tb.from_pub,
        "the rotated key is the same account"
    );

    let third = d.s("author-third.plnekey");
    std::fs::write(format!("{third}.journal"), "").unwrap();
    let clash = wallet(
        &[
            "passphrase",
            "--in",
            &old_key,
            "--out",
            &third,
            "--old-passphrase-file",
            &d.s("pass.txt"),
            "--new-passphrase-file",
            &d.s("pass.txt"),
            "--kdf-iters",
            "1024",
        ],
        b"",
    );
    assert_ne!(clash.code, 0, "{}", clash.all());
    assert!(clash.err.contains("journal"), "{}", clash.err);
    assert!(
        !std::path::Path::new(&third).exists(),
        "nothing may be created"
    );
}

#[test]
fn non_canonical_keyfile_is_refused() {
    use plaine_wallet::keyfile::KeyFile;
    use plaine_wallet::secret::{Secret32, SecretBytes};

    let seed = Secret32::from_bytes(plaine_consensus::blake3::hash(b"noncanonical version"));
    let pass = SecretBytes::from_vec(b"a generated passphrase".to_vec());
    let kf = KeyFile::seal(
        plaine_wallet::keyfile::Role::Spend,
        1_765_432_100,
        &seed,
        Some(&pass),
        64,
    )
    .unwrap();
    let good = kf.render();

    for bogus in ["4294967297", "8589934593", "18446744069414584321", "2"] {
        let text = good.replacen("version: 1\n", &format!("version: {bogus}\n"), 1);
        let err = KeyFile::parse(&text)
            .err()
            .unwrap_or_else(|| panic!("version {bogus} must be refused"));
        assert!(
            err.to_string().contains(bogus),
            "the refusal must name it: {err}"
        );
    }

    for (name, text) in [
        ("appended line", format!("{good}pwned: yes\n")),
        (
            "leading zeros",
            good.replacen("version: 1\n", "version: 001\n", 1),
        ),
        (
            "uppercase hex",
            good.replacen(
                &hex::encode(&kf.kdf_salt),
                &hex::encode(&kf.kdf_salt).to_uppercase(),
                1,
            ),
        ),
    ] {
        assert!(KeyFile::parse(&text).is_err(), "{name} must be refused");
    }

    let d = Dir::new("version");
    let path = d.s("k.plnekey");
    std::fs::write(&path, &good).unwrap();
    wallet(&["inspect", "--in", &path], b"").ok();
    let bogus_path = d.s("bogus.plnekey");
    std::fs::write(
        &bogus_path,
        good.replacen("version: 1\n", "version: 4294967297\n", 1),
    )
    .unwrap();
    let r = wallet(&["inspect", "--in", &bogus_path], b"");
    assert_ne!(r.code, 0, "{}", r.all());
    assert!(r.err.contains("4294967297"), "{}", r.err);
}

#[test]
fn absurd_iter_count_in_file_is_refused() {
    let d = Dir::new("iters");
    let (key, _, _) = make_key(&d, "spend.plnekey", "spend", b"iters in file");
    let text = std::fs::read_to_string(&key).unwrap();

    let bogus = d.s("bogus.plnekey");
    std::fs::write(
        &bogus,
        text.replacen("kdf_iters: 1024", &format!("kdf_iters: {}", u64::MAX), 1),
    )
    .unwrap();

    for argv in [
        vec!["inspect", "--in", &bogus],
        vec!["address", "--in", &bogus],
        vec![
            "verify",
            "--in",
            &bogus,
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
    ] {
        let r = wallet_bounded(&argv, b"", 20).unwrap_or_else(|| {
            panic!(
                "`{}` on a key file claiming {} iterations is still running: the ceiling \
                 is gone and this is the outage it prevents",
                argv[0],
                u64::MAX
            )
        });
        assert_ne!(r.code, 0, "{} must be refused:\n{}", argv[0], r.all());
        assert!(r.err.contains("kdf_iters"), "{}: {}", argv[0], r.err);
        assert!(
            r.err.contains(&u64::MAX.to_string()),
            "{}: {}",
            argv[0],
            r.err
        );
    }

    let r = wallet_bounded(
        &[
            "new",
            "--out",
            &d.s("huge.plnekey"),
            "--role",
            "spend",
            "--seed-stdin",
            "--passphrase-file",
            &d.s("pass.txt"),
            "--kdf-iters",
            &u64::MAX.to_string(),
        ],
        seed_hex(b"iters on cli").as_bytes(),
        20,
    )
    .unwrap_or_else(|| {
        panic!(
            "`new --kdf-iters {}` was accepted and is deriving a key that will never \
             finish; the flag ceiling is gone",
            u64::MAX
        )
    });
    assert_eq!(r.code, 2, "a usage error exits 2:\n{}", r.all());
    assert!(!d.path("huge.plnekey").exists(), "nothing may be created");
}

#[test]
fn one_char_typo_in_backup_is_refused() {
    let d = Dir::new("backup-typo");
    let (key, addr, _) = make_key(&d, "spend.plnekey", "spend", b"backup typo");

    let b = wallet(
        &[
            "backup",
            "--in",
            &key,
            "--passphrase-file",
            &d.s("pass.txt"),
            "--i-understand-this-prints-a-secret",
        ],
        b"",
    );
    b.ok();
    let printed: String = b
        .out
        .lines()
        .find(|l| l.len() == 68 && l.bytes().all(|c| c.is_ascii_hexdigit()))
        .expect("backup prints 68 hex digits: 64 of seed and 4 of checksum")
        .to_string();
    assert!(
        b.err.contains("checksum"),
        "the operator must be told the tail is a checksum:\n{}",
        b.err
    );

    let good = wallet(
        &[
            "import",
            "--out",
            &d.s("good.plnekey"),
            "--role",
            "spend",
            "--seed-stdin",
            "--passphrase-file",
            &d.s("pass.txt"),
            "--kdf-iters",
            "1024",
        ],
        printed.as_bytes(),
    );
    good.ok();
    assert_eq!(
        good.field("address"),
        addr,
        "an exact restore must be identical"
    );

    let digits = b"0123456789abcdef";
    let mut refused = 0usize;
    for pos in 0..printed.len() {
        for &dig in digits {
            let mut v = printed.as_bytes().to_vec();
            if v[pos] == dig {
                continue;
            }
            v[pos] = dig;
            let typo = String::from_utf8(v).unwrap();
            let out = d.s(&format!("typo-{pos}-{dig}.plnekey"));
            let bad = wallet(
                &[
                    "import",
                    "--out",
                    &out,
                    "--role",
                    "spend",
                    "--seed-stdin",
                    "--no-passphrase",
                ],
                typo.as_bytes(),
            );
            assert_ne!(
                bad.code,
                0,
                "a one-character slip at {pos} was accepted and restored a different \
                 wallet:\n{}",
                bad.all()
            );
            assert!(
                !std::path::Path::new(&out).exists(),
                "nothing may be created"
            );
            assert!(
                !bad.all().contains(&typo),
                "the refusal must not echo the material"
            );
            refused += 1;
        }
    }
    assert_eq!(refused, 68 * 15);

    let bare = &printed[..64];
    let r = wallet(
        &[
            "import",
            "--out",
            &d.s("bare.plnekey"),
            "--role",
            "spend",
            "--seed-stdin",
            "--no-passphrase",
        ],
        bare.as_bytes(),
    );
    assert_ne!(r.code, 0, "{}", r.all());
    assert!(r.err.contains("checksum"), "{}", r.err);
    assert!(
        r.err.contains("new"),
        "the refusal must name the way out: {}",
        r.err
    );

    let n = wallet(
        &[
            "new",
            "--out",
            &d.s("bare-new.plnekey"),
            "--role",
            "spend",
            "--seed-stdin",
            "--no-passphrase",
        ],
        bare.as_bytes(),
    );
    n.ok();
    assert_eq!(n.field("address"), addr);
    assert!(n.err.contains("no checksum"), "{}", n.err);
}

#[test]
fn extra_leading_dashes_refused_nothing_signed() {
    let d = Dir::new("dashes");
    let (key, _, _) = make_key(&d, "spend.plnekey", "spend", b"leading dashes");
    let to = crypto::address_from_pubkey(&plaine_consensus::blake3::hash(b"dashes payee"));

    let r = wallet(
        &[
            "transfer",
            "--in",
            &key,
            "--to",
            &to,
            "--amount",
            "1plne",
            "----fee",
            "1000mile",
            "--------nonce",
            "3",
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
        b"",
    );
    assert_eq!(r.code, 2, "a usage error exits 2:\n{}", r.all());
    assert!(r.err.contains("unknown option ----fee"), "{}", r.err);
    assert!(
        !r.out.contains("signed"),
        "nothing may be signed:\n{}",
        r.out
    );

    #[cfg_attr(not(feature = "author-tools"), allow(unused_mut))]
    let mut cases: Vec<Vec<&str>> = vec![vec!["transfer", "--in", &key, "----fee=1000mile"]];

    #[cfg(feature = "author-tools")]
    cases.push(vec!["announce", "--in", &key, "----reuse-nonce"]);
    for argv in cases {
        let r = wallet(&argv, b"");
        assert_eq!(r.code, 2, "{}", r.all());
        assert!(r.err.contains("unknown option"), "{}", r.err);
    }

    wallet(
        &[
            "transfer",
            "--in",
            &key,
            "--to",
            &to,
            "--amount",
            "1plne",
            "--fee",
            "1000mile",
            "--nonce",
            "3",
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
        b"",
    )
    .ok();
}

#[test]
fn slow_file_warns_before_it_goes_quiet() {
    use plaine_wallet::kdf;

    const _: () = assert!(
        kdf::MAX_ITERS > 100 * kdf::DEFAULT_ITERS,
        "room for a paranoid operator"
    );
    const _: () = assert!(
        kdf::MAX_ITERS < u64::MAX / 1_000_000,
        "and far below a mistyped digit"
    );
    const _: () = assert!(
        kdf::NOTICE_ABOVE_ITERS > kdf::DEFAULT_ITERS,
        "the default must not warn"
    );

    let d = Dir::new("iters-notice");
    let (key, _, _) = make_key(&d, "spend.plnekey", "spend", b"slow file notice");
    let slow = d.s("slow.plnekey");
    let big = 5 * kdf::DEFAULT_ITERS;
    assert!(big > kdf::NOTICE_ABOVE_ITERS && big < kdf::MAX_ITERS);
    std::fs::write(
        &slow,
        std::fs::read_to_string(&key).unwrap().replacen(
            "kdf_iters: 1024",
            &format!("kdf_iters: {big}"),
            1,
        ),
    )
    .unwrap();

    let r = wallet(&["verify", "--in", &slow], b"");
    assert_ne!(r.code, 0);
    assert!(
        r.err.contains(&big.to_string()) && r.err.contains("not a hang"),
        "a slow key file must announce itself:\n{}",
        r.err
    );

    let quiet = wallet(&["verify", "--in", &key], b"");
    assert!(!quiet.err.contains("not a hang"), "{}", quiet.err);
}

#[test]
fn kdf_iters_from_file_is_uncapped_work() {
    use plaine_wallet::kdf;
    use plaine_wallet::secret::SecretBytes;
    use std::time::Instant;

    let pass = SecretBytes::from_vec(b"a generated passphrase".to_vec());
    let salt = [0x5Au8; 32];
    const N: u64 = 200_000;
    let t = Instant::now();
    let _ = kdf::derive_key(&pass, &salt, N);
    let per = t.elapsed().as_secs_f64() / N as f64;

    let years_for_u64_max = (u64::MAX as f64) * per / (365.25 * 24.0 * 3600.0);
    println!(
        "measured {:.3} us / iteration; kdf_iters = u64::MAX (a legal value in the \
         file, and one mistyped digit away) would take ~{:.3e} years with no \
         progress output and no cap",
        per * 1e6,
        years_for_u64_max
    );
    assert!(
        years_for_u64_max > 1_000.0,
        "sanity: a u64::MAX iteration count must be unreachable"
    );
}

#[test]
fn amount_parser_battery() {
    use plaine_wallet::amount::parse_mile;
    use plaine_wallet::amount::MAX_PARSE_MILE;

    let must_refuse = [
        "1e18",
        "1e18plne",
        "1E18plne",
        "1e18mile",
        "0.1000000000000000001plne",
        "+1plne",
        "+1mile",
        "-1plne",
        "-1mile",
        "-0plne",
        "\u{FF11}plne",
        "\u{0661}plne",
        "\u{06F1}plne",
        "\u{0967}plne",
        "\u{1D7CF}plne",
        "1\u{200B}plne",
        "1plne\u{0000}",
        "5",
        "5 plne",
        "5_plne",
        "5\u{9}plne",
        " 5plne",
        "5plne ",
        "5plne\n",
        "1_000plne",
        "1,000plne",
        "1 000plne",
        "1.2.3plne",
        "0.1mile",
        "0.5mile",
        "1.0000000000000000001plne",
        "abcplne",
        "1.2xplne",
        "plne",
        "mile",
        "",
        "..plne",
        "0x10mile",
        "1nplne",
        "1PLNEplne",
        "340282366920938463463374607431768211455mile",
        "340282366920938463463374607431768211455plne",
        "170141183460469231731687303715884105728plne",
    ];
    for bad in must_refuse {
        assert!(
            parse_mile(bad).is_err(),
            "parse_mile({bad:?}) must be refused, got {:?}",
            parse_mile(bad)
        );
    }

    assert_eq!(
        parse_mile(&format!("{MAX_PARSE_MILE}mile")).unwrap(),
        MAX_PARSE_MILE
    );
    assert!(parse_mile(&format!("{}mile", MAX_PARSE_MILE + 1)).is_err());

    let max_plne = plaine_wallet::amount::format_plne(MAX_PARSE_MILE);
    assert_eq!(
        parse_mile(&format!("{max_plne}plne")).unwrap(),
        MAX_PARSE_MILE
    );

    assert_eq!(parse_mile("1plne").unwrap(), 1_000_000);
    assert_eq!(parse_mile("0.1plne").unwrap(), 100_000);
    assert_eq!(parse_mile(".5plne").unwrap(), 500_000);
    assert_eq!(parse_mile("0.000001plne").unwrap(), 1);
    assert_eq!(parse_mile("0.000000plne").unwrap(), 0);
    assert_eq!(parse_mile("0000000001plne").unwrap(), 1_000_000);

    let a = parse_mile("0.1plne").unwrap();
    let b = parse_mile("0.2plne").unwrap();
    assert_eq!(a + b, parse_mile("0.3plne").unwrap());

    for w in [
        0u128,
        1,
        2,
        999,
        10u128.pow(6),
        10u128.pow(9) - 1,
        10u128.pow(9),
        10u128.pow(12) + 1,
        MAX_PARSE_MILE - 1,
        MAX_PARSE_MILE,
    ] {
        let s = format!("{}plne", plaine_wallet::amount::format_plne(w));
        assert_eq!(parse_mile(&s).unwrap(), w, "roundtrip {w}");
    }

    for junk in [
        "\u{0}",
        "\u{10FFFF}plne",
        &"9".repeat(4096),
        &format!("{}plne", "9".repeat(4096)),
        &format!("0.{}plne", "9".repeat(4096)),
        &format!(".{}mile", "0".repeat(64)),
        "..",
        "...plne",
        "-.plne",
        "+.mile",
        &"plne".repeat(64),
        &"mile".repeat(64),
    ] {
        let _ = parse_mile(junk);
    }
}

#[test]
fn restore_is_byte_identical_bad_backups_refused() {
    let d = Dir::new("restore");
    let (key, addr, pubkey) = make_key(&d, "spend.plnekey", "spend", b"restore roundtrip");
    let b = wallet(
        &[
            "backup",
            "--in",
            &key,
            "--passphrase-file",
            &d.s("pass.txt"),
            "--i-understand-this-prints-a-secret",
        ],
        b"",
    );
    b.ok();
    let printed: String = b
        .out
        .lines()
        .find(|l| l.len() == 68 && l.bytes().all(|c| c.is_ascii_hexdigit()))
        .unwrap()
        .to_string();

    std::fs::write(d.path("other.txt"), "an entirely different passphrase").unwrap();
    let r = wallet(
        &[
            "import",
            "--out",
            &d.s("r1.plnekey"),
            "--role",
            "author",
            "--seed-stdin",
            "--passphrase-file",
            &d.s("other.txt"),
            "--kdf-iters",
            "2048",
        ],
        printed.as_bytes(),
    );
    r.ok();
    assert_eq!(r.field("address"), addr);
    assert_eq!(r.field("pubkey"), pubkey);

    let r2 = wallet(
        &[
            "import",
            "--out",
            &d.s("r2.plnekey"),
            "--role",
            "spend",
            "--seed-stdin",
            "--no-passphrase",
        ],
        printed.as_bytes(),
    );
    r2.ok();
    assert_eq!(r2.field("address"), addr);

    for bad in [
        printed[..67].to_string(),
        printed[..64].to_string(),
        format!("{printed}0"),
        format!("{printed}00"),
        printed.replacen(|c: char| c.is_ascii_hexdigit(), "z", 1),
        "0".repeat(68),
        "42".repeat(34),
        String::new(),
    ] {
        let out = d.s(&format!("bad-{}.plnekey", bad.len()));
        let r = wallet(
            &[
                "import",
                "--out",
                &out,
                "--role",
                "spend",
                "--seed-stdin",
                "--no-passphrase",
            ],
            bad.as_bytes(),
        );
        assert_ne!(r.code, 0, "bad backup {bad:?} must be refused");
        assert!(
            !std::path::Path::new(&out).exists(),
            "nothing may be created"
        );
        assert!(
            !r.all().contains(&bad) || bad.is_empty(),
            "the error must not echo the material"
        );
    }
}

#[test]
fn signing_preimage_is_unambiguous() {
    use plaine_wallet::secret::Secret32;
    use plaine_wallet::{sig, txbuild};
    use std::collections::HashMap;

    let sk = Secret32::from_bytes(plaine_consensus::blake3::hash(b"preimage battery"));
    let pk = sig::public_key_of(&sk);
    let to_a = crypto::address_from_pubkey(&[0x11u8; 32]);
    let to_b = crypto::address_from_pubkey(&[0x22u8; 32]);

    let mut seen: HashMap<[u8; 32], (String, u128, u128, u64)> = HashMap::new();
    for to in [&to_a, &to_b] {
        for amount in [
            0u128,
            1,
            255,
            256,
            u64::MAX as u128,
            (u64::MAX as u128) + 1,
            1u128 << 100,
        ] {
            for fee in [1u128, 255, 256, 1 << 64] {
                for nonce in [0u64, 1, 255, 256, u64::MAX] {
                    let payload = crypto::decode_address(to).unwrap();
                    let m = crypto::signing_message(NET, &pk, &payload, amount, fee, nonce);
                    let key = (to.clone(), amount, fee, nonce);
                    if let Some(prev) = seen.insert(m, key.clone()) {
                        panic!("signing-message collision: {prev:?} vs {key:?}");
                    }
                }
            }
        }
    }

    let mut ann: HashMap<[u8; 32], String> = HashMap::new();
    for enc in [0u8, 1, 2, 255] {
        for fee in [1u128, 2, 1 << 100] {
            for nonce in [0u64, 1, u64::MAX] {
                for p in [
                    b"a".to_vec(),
                    b"ab".to_vec(),
                    b"a\x00".to_vec(),
                    b"\x00a".to_vec(),
                    vec![0x41; 1024],
                    vec![0x41; 1023],
                ] {
                    let m = crypto::announcement_signing_message(NET, &pk, fee, nonce, enc, &p)
                        .unwrap();
                    let d = format!("{enc}/{fee}/{nonce}/{p:?}");
                    if let Some(prev) = ann.insert(m, d.clone()) {
                        panic!("announcement-message collision: {prev} vs {d}");
                    }
                }
            }
        }
    }

    let t = crypto::signing_message(NET, &pk, &crypto::decode_address(&to_a).unwrap(), 1, 1, 1);
    let a = crypto::announcement_signing_message(NET, &pk, 1, 1, 1, b"x").unwrap();
    assert_ne!(t, a);

    assert!(
        txbuild::build_transfer(NET, &sk, &to_a, 1, 0, 0).is_err(),
        "fee below floor"
    );
    assert!(txbuild::build_transfer(NET, &sk, "not-an-address", 1, 1, 0).is_err());
    assert!(
        txbuild::build_transfer(NET, &sk, &to_a.to_uppercase(), 1, 1, 0).is_ok(),
        "bech32 uppercase is legal"
    );

    let lo = txbuild::build_transfer(NET, &sk, &to_a, 5, 1, 0).unwrap();
    let up = txbuild::build_transfer(NET, &sk, &to_a.to_uppercase(), 5, 1, 0).unwrap();
    assert_eq!(
        lo, up,
        "the same address in two cases must sign identically"
    );
}

#[test]
fn no_secret_reaches_argv_env_or_temp_file() {
    let d = Dir::new("channels");
    let seed = seed_hex(b"secret channels");
    std::fs::write(d.path("pass.txt"), "a generated passphrase").unwrap();
    let key = d.s("spend.plnekey");

    let before: Vec<PathBuf> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();

    wallet(
        &[
            "new",
            "--out",
            &key,
            "--role",
            "spend",
            "--seed-stdin",
            "--passphrase-file",
            &d.s("pass.txt"),
            "--kdf-iters",
            "1024",
        ],
        seed.as_bytes(),
    )
    .ok();
    wallet(
        &[
            "verify",
            "--in",
            &key,
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
        b"",
    )
    .ok();

    for p in std::fs::read_dir(std::env::temp_dir()).unwrap().flatten() {
        let path = p.path();
        if before.contains(&path) || path.starts_with(&d.0) || path.is_dir() {
            continue;
        }
        if let Ok(t) = std::fs::read_to_string(&path) {
            assert!(
                !t.to_lowercase().contains(&seed),
                "{} holds the seed",
                path.display()
            );
        }
    }

    for (k, v) in std::env::vars() {
        assert!(
            !v.to_lowercase().contains(&seed),
            "env var {k} holds the seed"
        );
    }

    for bad in [
        "--passphrase",
        "--pass",
        "--password",
        "--seed",
        "--seed-hex",
        "--private-key",
        "--secret",
    ] {
        for form in [
            vec![bad.to_string(), seed.clone()],
            vec![format!("{bad}={seed}")],
        ] {
            let mut argv = vec!["new".to_string(), "--out".to_string(), d.s("nope")];
            argv.extend(form);
            let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            let r = wallet(&refs, b"");
            assert_eq!(r.code, 2, "{bad} must be a usage error: {}", r.all());
            assert!(r.err.contains("is refused"), "{}", r.err);
            assert!(!r.all().contains(&seed), "the refusal echoed the secret");
        }
    }

    let text = std::fs::read_to_string(&key).unwrap();
    assert!(!text.to_lowercase().contains(&seed));

    assert!(!d.path("spend.plnekey.journal").exists());
}

#[test]
fn junk_argv_never_panics() {
    let d = Dir::new("fuzz");

    #[cfg_attr(not(feature = "author-tools"), allow(unused_variables))]
    let (key, _, pubkey) = make_key(&d, "spend.plnekey", "spend", b"argv fuzz");
    std::fs::write(d.path("p.txt"), "x").unwrap();

    let zpath = d.s("z");
    #[cfg_attr(not(feature = "author-tools"), allow(unused_mut))]
    let mut junk: Vec<Vec<&str>> = vec![
        vec![],
        vec![""],
        vec!["--"],
        vec!["--="],
        vec!["-"],
        vec!["transfer"],
        vec!["transfer", "--in"],
        vec!["transfer", "--in", "/nonexistent"],
        vec![
            "transfer", "--in", &key, "--to", "", "--amount", "", "--fee", "", "--nonce", "",
        ],
        vec![
            "transfer",
            "--in",
            &key,
            "--to",
            "plne1",
            "--amount",
            "1plne",
            "--fee",
            "1mile",
            "--nonce",
            "18446744073709551616",
        ],
        vec!["decode", "--hex", ""],
        vec!["decode", "--hex", "00"],
        vec!["decode", "--hex", "01"],
        vec!["decode", "--hex", "02"],
        vec!["decode", "--hex", "ff"],
        vec!["decode", "--hex", "0"],
        vec!["decode", "--hex", "zz"],
        vec!["decode", "--hex", "01ff"],
        vec!["decode", "--in", "/nonexistent"],
        vec!["inspect", "--in", "/nonexistent"],
        vec!["address", "--in", &key, "--in", &key],
        vec!["backup"],
        vec!["passphrase", "--in", &key, "--out", &key],
        vec!["new", "--out", &key, "--role", "nope"],
        vec![
            "new",
            "--out",
            &zpath,
            "--role",
            "spend",
            "--seed-stdin",
            "--kdf-iters",
            "18446744073709551615",
            "--no-passphrase",
        ],
        vec!["\u{feff}transfer"],
        vec!["TRANSFER"],
    ];

    #[cfg(feature = "author-tools")]
    {
        junk.push(vec![
            "announce",
            "--in",
            &key,
            "--author-pubkey",
            &pubkey,
            "--payload-hex",
            "",
            "--encoding",
            "0",
            "--fee",
            "1mile",
            "--nonce",
            "0",
            "--no-passphrase",
        ]);
        junk.push(vec![
            "announce",
            "--in",
            &key,
            "--author-pubkey",
            "zz",
            "--payload-hex",
            "41",
            "--encoding",
            "999",
            "--fee",
            "1mile",
            "--nonce",
            "0",
        ]);
    }
    for argv in junk {
        let r = wallet(&argv, b"not hex\n\n\n");
        assert!(
            r.code == 0 || r.code == 1 || r.code == 2,
            "argv {argv:?} produced exit {}",
            r.code
        );
    }

    let to = crypto::address_from_pubkey(&plaine_consensus::blake3::hash(b"fuzz payee"));
    let t = wallet(
        &[
            "transfer",
            "--in",
            &key,
            "--to",
            &to,
            "--amount",
            "1plne",
            "--fee",
            "1000mile",
            "--nonce",
            "0",
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
        b"",
    );
    t.ok();
    let full = t.field("hex");
    for n in 0..full.len() {
        let _ = wallet(&["decode", "--hex", &full[..n]], b"");
    }

    for i in 0..full.len() {
        let mut v: Vec<char> = full.chars().collect();
        v[i] = if v[i] == 'f' { '0' } else { 'f' };
        let s: String = v.into_iter().collect();
        let r = wallet(&["decode", "--hex", &s], b"");
        assert!(
            r.code == 0 || r.code == 1,
            "corruption at {i} gave {}",
            r.code
        );
    }
}

#[test]
fn keyfile_parser_survives_hostile_files() {
    use plaine_wallet::keyfile::KeyFile;
    use plaine_wallet::secret::{Secret32, SecretBytes};

    let seed = Secret32::from_bytes(plaine_consensus::blake3::hash(b"hostile keyfile"));
    let pass = SecretBytes::from_vec(b"a generated passphrase".to_vec());
    let kf = KeyFile::seal(
        plaine_wallet::keyfile::Role::Checkpoint,
        1_765_432_100,
        &seed,
        Some(&pass),
        64,
    )
    .unwrap();
    let good = kf.render();

    let bytes = good.as_bytes();
    for i in 0..bytes.len() {
        let mut v = bytes.to_vec();
        v.remove(i);
        if let Ok(t) = String::from_utf8(v) {
            if let Ok(p) = KeyFile::parse(&t) {
                if let Ok(s) = p.open(Some(&pass)) {
                    assert_eq!(
                        s.expose(),
                        seed.expose(),
                        "deletion at {i} opened a different seed"
                    );
                }
            }
        }
    }
    for i in 0..bytes.len() {
        for repl in [b'0', b'9', b'a', b'f', b'z', b' ', b'\n', b':', 0x7f] {
            let mut v = bytes.to_vec();
            v[i] = repl;
            if let Ok(t) = String::from_utf8(v) {
                if let Ok(p) = KeyFile::parse(&t) {
                    if let Ok(s) = p.open(Some(&pass)) {
                        assert_eq!(
                            s.expose(),
                            seed.expose(),
                            "substitution {repl:#x} at {i} opened a different seed"
                        );
                    }
                }
            }
        }
    }

    for t in [
        String::new(),
        "\n".to_string(),
        "PLNEKEY1".to_string(),
        "PLNEKEY1\n".to_string(),
        format!("{good}{good}"),
        format!("{good}\n"),
        format!("\n{good}"),
        good.replace('\n', "\r\n"),
        good.to_uppercase(),
        "PLNEKEY1\n".to_string() + &"version: 1\n".repeat(12),
        "PLNEKEY1\n".to_string() + &"x".repeat(100_000),
    ] {
        let _ = KeyFile::parse(&t);
    }
}
