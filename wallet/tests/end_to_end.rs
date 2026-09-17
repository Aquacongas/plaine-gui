#![forbid(unsafe_code)]

use plaine_consensus::codec::TransferTx;

#[cfg(feature = "author-tools")]
use plaine_consensus::codec::AnnouncementTx;
use plaine_consensus::constants::Network;
#[cfg(feature = "author-tools")]
use plaine_consensus::tx;
use plaine_consensus::{crypto, hex};
use plaine_wallet::ui::Streams;
use std::io::Cursor;
use std::path::{Path, PathBuf};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("plaine-wallet-e2e-{tag}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn s(&self, name: &str) -> String {
        self.path(name).display().to_string()
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
            .unwrap_or_else(|| panic!("`{label}` line has no value: {line}"))
            .to_string()
    }
}

fn wallet(argv: &[&str], stdin: &[u8]) -> Run {
    drive(plaine_wallet::wallet_cli::run, argv, stdin)
}

fn drive(f: fn(&[String], &mut Streams) -> i32, argv: &[&str], stdin: &[u8]) -> Run {
    let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let mut input = Cursor::new(stdin.to_vec());
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = {
        let mut s = Streams::new(&mut input, &mut out, &mut err);
        f(&args, &mut s)
    };
    Run {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

fn seed_hex(tag: &[u8]) -> String {
    hex::encode(&plaine_consensus::blake3::hash(tag))
}

fn make_key(d: &Dir, name: &str, role: &str, tag: &[u8]) -> (String, String, String) {
    let pass = d.s("pass.txt");
    if !Path::new(&pass).exists() {
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
    let addr = wallet(&["address", "--in", &out], b"");
    addr.ok();
    (out, addr.out.trim().to_string(), r.field("pubkey"))
}

#[test]
fn transfer_accepted_by_consensus() {
    let d = Dir::new("transfer");
    let (key, from_addr, from_pub) = make_key(&d, "spend.plnekey", "spend", b"e2e transfer");
    let to = crypto::address_from_pubkey(&plaine_consensus::blake3::hash(b"e2e payee"));

    let r = wallet(
        &[
            "transfer",
            "--in",
            &key,
            "--to",
            &to,
            "--amount",
            "1.5plne",
            "--fee",
            "1000mile",
            "--nonce",
            "7",
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
        b"",
    );
    r.ok();

    assert_eq!(r.field("from"), from_addr);

    let bytes = hex::decode(&r.field("hex")).expect("the wallet must emit hex");
    assert_eq!(
        bytes.len(),
        157,
        "a signed transfer is 157 bytes on the wire"
    );

    let decoded = TransferTx::decode(&bytes).expect("consensus must decode it");
    crypto::verify_transfer_signature(Network::Main, &decoded)
        .expect("consensus must accept a signature the wallet made");

    assert_eq!(hex::encode(&decoded.from_pub), from_pub);
    assert_eq!(decoded.to, crypto::decode_address(&to).unwrap());
    assert_eq!(decoded.amount, 1_500_000u128);
    assert_eq!(decoded.fee, 1000);
    assert_eq!(decoded.nonce, 7);
    assert_eq!(hex::encode(&decoded.txid()), r.field("txid"));

    let back = wallet(&["decode", "--hex", &hex::encode(&bytes)], b"");
    back.ok();
    assert!(back.out.contains("signature  VALID"));
    assert_eq!(back.field("txid"), r.field("txid"));
}

#[test]
fn wallet_signs_under_one_chain_id() {
    let d = Dir::new("chainid");
    let (key, _, _) = make_key(&d, "spend.plnekey", "spend", b"e2e chainid");
    let to = crypto::address_from_pubkey(&plaine_consensus::blake3::hash(b"e2e payee"));

    let m = wallet(
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
    m.ok();

    assert!(m.out.contains("504c4e45"), "{}", m.out);
    assert!(m.out.contains("PLNE"), "{}", m.out);

    let mb = hex::decode(&m.field("hex")).unwrap();
    let mtx = plaine_consensus::codec::TransferTx::decode(&mb).unwrap();
    crypto::verify_transfer_signature(Network::Main, &mtx).expect("main tx on main");

    let ok = wallet(&["decode", "--hex", &m.field("hex")], b"");
    ok.ok();
    assert!(ok.all().contains("VALID"), "{}", ok.all());
}

#[test]
fn removed_placeholder_flag_is_rejected() {
    let d = Dir::new("chainid-removed-flag");
    let (key, _, _) = make_key(&d, "spend.plnekey", "spend", b"e2e removed flag");
    let to = crypto::address_from_pubkey(&plaine_consensus::blake3::hash(b"e2e payee"));

    let r = wallet(
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
            "--allow-placeholder-chain-id",
        ],
        b"",
    );
    assert_eq!(r.code, 2, "a removed flag is a usage error: {}", r.all());
    assert!(r.err.contains("was removed"), "{}", r.err);
    assert!(
        r.err.contains("PLNE"),
        "must name the frozen value: {}",
        r.err
    );
    assert!(
        !r.out.contains("hex        "),
        "nothing may be emitted when the invocation is refused:
{}",
        r.out
    );

    #[cfg(feature = "author-tools")]
    {
        let (author_key, _, author_pub) =
            make_key(&d, "author.plnekey", "author", b"e2e removed ann");
        std::fs::write(d.path("msg.txt"), "a message").unwrap();
        let r2 = wallet(
            &[
                "announce",
                "--in",
                &author_key,
                "--author-pubkey",
                &author_pub,
                "--payload-file",
                &d.s("msg.txt"),
                "--encoding",
                "1",
                "--fee",
                "50000mile",
                "--nonce",
                "0",
                "--passphrase-file",
                &d.s("pass.txt"),
                "--allow-placeholder-chain-id",
            ],
            b"",
        );
        assert_eq!(r2.code, 2, "{}", r2.all());
        assert!(r2.err.contains("was removed"), "{}", r2.err);
    }
}

#[cfg(feature = "author-tools")]
#[test]
fn author_announcement_accepted_impostor_refused() {
    let d = Dir::new("announce");
    let (author_key, _, author_pub) = make_key(&d, "author.plnekey", "author", b"e2e author");
    let (other_key, _, other_pub) = make_key(&d, "other.plnekey", "spend", b"e2e impostor");
    assert_ne!(author_pub, other_pub);

    std::fs::write(
        d.path("msg.txt"),
        "PLNE emergency: algorithm change at height 100000",
    )
    .unwrap();

    let r = wallet(
        &[
            "announce",
            "--in",
            &author_key,
            "--author-pubkey",
            &author_pub,
            "--payload-file",
            &d.s("msg.txt"),
            "--encoding",
            "1",
            "--fee",
            "50000mile",
            "--nonce",
            "3",
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
        b"",
    );
    r.ok();

    let bytes = hex::decode(&r.field("hex")).unwrap();
    let decoded = AnnouncementTx::decode(&bytes).expect("consensus must decode it");
    crypto::verify_announcement_signature(Network::Main, &decoded).expect("signature must verify");

    let author = <[u8; 32]>::try_from(hex::decode(&author_pub).unwrap().as_slice()).unwrap();

    tx::check_announcement_stateless(Network::Main, &decoded, &author)
        .expect("consensus must accept an announcement from the author key");

    let refused = wallet(
        &[
            "announce",
            "--in",
            &other_key,
            "--author-pubkey",
            &author_pub,
            "--payload-file",
            &d.s("msg.txt"),
            "--encoding",
            "1",
            "--fee",
            "50000mile",
            "--nonce",
            "3",
            "--passphrase-file",
            &d.s("pass.txt"),
        ],
        b"",
    );
    assert_ne!(
        refused.code, 0,
        "a non-author key must not produce an announcement"
    );
    assert!(
        refused.err.contains("author"),
        "the refusal must say why: {}",
        refused.err
    );
    assert!(
        !refused.out.contains("hex        "),
        "nothing may be emitted for a doomed announcement:\n{}",
        refused.out
    );

    let impostor = <[u8; 32]>::try_from(hex::decode(&other_pub).unwrap().as_slice()).unwrap();
    let mut forged = decoded.clone();
    forged.from_pub = impostor;
    let err = tx::check_announcement_stateless(Network::Main, &forged, &author).unwrap_err();
    assert!(
        format!("{err:?}").contains("NotAuthorKey"),
        "expected NotAuthorKey, got {err:?}"
    );

    let checked = wallet(
        &[
            "decode",
            "--hex",
            &hex::encode(&bytes),
            "--author-pubkey",
            &other_pub,
        ],
        b"",
    );
    assert_ne!(checked.code, 0);
    assert!(
        checked.out.contains("rule 1     REJECTED"),
        "{}",
        checked.out
    );
}

#[cfg(feature = "author-tools")]
#[test]
fn journal_refuses_second_message_at_nonce() {
    let d = Dir::new("journal");
    let (key, _, pubkey) = make_key(&d, "author.plnekey", "author", b"e2e journal");
    std::fs::write(d.path("a.txt"), "first message").unwrap();
    std::fs::write(d.path("b.txt"), "a DIFFERENT message").unwrap();

    let base: Vec<String> = vec![
        "announce".into(),
        "--in".into(),
        key.clone(),
        "--author-pubkey".into(),
        pubkey.clone(),
        "--encoding".into(),
        "1".into(),
        "--fee".into(),
        "50000mile".into(),
        "--nonce".into(),
        "11".into(),
        "--passphrase-file".into(),
        d.s("pass.txt"),
    ];
    let with = |file: &str, extra: &[&str]| -> Run {
        let mut v: Vec<String> = base.clone();
        v.push("--payload-file".into());
        v.push(file.to_string());
        v.extend(extra.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
        wallet(&refs, b"")
    };

    with(&d.s("a.txt"), &[]).ok();

    with(&d.s("a.txt"), &[]).ok();

    let clash = with(&d.s("b.txt"), &[]);
    assert_ne!(clash.code, 0);
    assert!(clash.err.contains("nonce 11"), "{}", clash.err);

    let bumped = {
        let mut v: Vec<String> = base.clone();
        v.push("--payload-file".into());
        v.push(d.s("a.txt"));

        let i = v.iter().position(|x| x == "50000mile").unwrap();
        v[i] = "900000mile".into();
        let refs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
        wallet(&refs, b"")
    };
    assert_ne!(
        bumped.code,
        0,
        "a fee bump at a used nonce is a conflict:\n{}",
        bumped.all()
    );
    assert!(bumped.err.contains("nonce 11"), "{}", bumped.err);

    with(&d.s("b.txt"), &["--reuse-nonce"]).ok();

    assert_ne!(with(&d.s("a.txt"), &[]).code, 0);
}

#[test]
fn only_backup_prints_the_seed() {
    let d = Dir::new("disclosure");
    let seed = seed_hex(b"e2e disclosure");
    let pass = d.s("pass.txt");
    std::fs::write(&pass, "a generated passphrase").unwrap();
    let key = d.s("spend.plnekey");
    let to = crypto::address_from_pubkey(&plaine_consensus::blake3::hash(b"e2e payee"));
    std::fs::write(d.path("msg.txt"), "a message").unwrap();

    let mut runs: Vec<(&str, Run)> = Vec::new();
    runs.push((
        "new",
        wallet(
            &[
                "new",
                "--out",
                &key,
                "--role",
                "spend",
                "--seed-stdin",
                "--passphrase-file",
                &pass,
                "--kdf-iters",
                "1024",
            ],
            seed.as_bytes(),
        ),
    ));
    let _pubkey = runs[0].1.field("pubkey");
    runs.push(("inspect", wallet(&["inspect", "--in", &key], b"")));
    runs.push(("address", wallet(&["address", "--in", &key], b"")));
    runs.push((
        "verify",
        wallet(&["verify", "--in", &key, "--passphrase-file", &pass], b""),
    ));
    runs.push((
        "passphrase",
        wallet(
            &[
                "passphrase",
                "--in",
                &key,
                "--out",
                &d.s("rotated.plnekey"),
                "--old-passphrase-file",
                &pass,
                "--new-passphrase-file",
                &pass,
                "--kdf-iters",
                "1024",
            ],
            b"",
        ),
    ));

    let backup_string =
        plaine_wallet::sechex::encode_backup(&plaine_wallet::secret::Secret32::from_bytes(
            plaine_consensus::blake3::hash(b"e2e disclosure"),
        ));
    let imported = wallet(
        &[
            "import",
            "--out",
            &d.s("restored.plnekey"),
            "--role",
            "spend",
            "--seed-stdin",
            "--passphrase-file",
            &pass,
            "--kdf-iters",
            "1024",
        ],
        backup_string.as_bytes(),
    );
    imported.ok();
    runs.push(("import", imported));
    let transfer = wallet(
        &[
            "transfer",
            "--in",
            &key,
            "--to",
            &to,
            "--amount",
            "2plne",
            "--fee",
            "1000mile",
            "--nonce",
            "1",
            "--passphrase-file",
            &pass,
        ],
        b"",
    );
    let tx_hex = transfer.field("hex");
    runs.push(("transfer", transfer));

    #[cfg(feature = "author-tools")]
    runs.push((
        "announce",
        wallet(
            &[
                "announce",
                "--in",
                &key,
                "--author-pubkey",
                &_pubkey,
                "--payload-file",
                &d.s("msg.txt"),
                "--encoding",
                "1",
                "--fee",
                "50000mile",
                "--nonce",
                "1",
                "--passphrase-file",
                &pass,
            ],
            b"",
        ),
    ));
    runs.push(("decode", wallet(&["decode", "--hex", &tx_hex], b"")));
    runs.push(("help", wallet(&["help"], b"")));
    runs.push(("version", wallet(&["version"], b"")));

    runs.push(("bad-flag", wallet(&["transfer", "--nope", "1"], b"")));
    runs.push((
        "wrong-passphrase",
        wallet(
            &["verify", "--in", &key, "--passphrase-file", &d.s("msg.txt")],
            b"",
        ),
    ));
    runs.push((
        "seed-on-argv",
        wallet(&["new", "--seed-hex", &seed, "--out", &d.s("nope")], b""),
    ));

    let upper = seed.to_uppercase();
    for (name, r) in &runs {
        let all = r.all();
        assert!(
            !all.contains(&seed) && !all.contains(&upper),
            "`{name}` printed the private seed:\n{all}"
        );

        for token in all.split(|c: char| !c.is_ascii_hexdigit()) {
            if token.len() == 64 {
                assert!(
                    !token.eq_ignore_ascii_case(&seed),
                    "`{name}` printed the seed as a hex token"
                );
            }
        }
    }

    let b = wallet(
        &[
            "backup",
            "--in",
            &key,
            "--passphrase-file",
            &pass,
            "--i-understand-this-prints-a-secret",
        ],
        b"",
    );
    b.ok();
    assert!(
        b.out.contains(&seed),
        "backup is the one command that discloses"
    );

    let refused = wallet(&["backup", "--in", &key, "--passphrase-file", &pass], b"");
    assert_ne!(refused.code, 0);
    assert!(!refused.all().contains(&seed));
}

#[test]
fn new_without_a_seed_generates_a_key() {
    let d = Dir::new("generate");
    let key = d.s("spend.plnekey");
    let r = wallet(
        &["new", "--out", &key, "--role", "spend", "--no-passphrase"],
        b"",
    );
    r.ok();

    let addr = r.field("address");
    assert!(
        addr.starts_with("plne1"),
        "expected a plne1 address, got {addr}"
    );
    crypto::decode_address(&addr).expect("the printed address must decode");

    let back = wallet(&["address", "--in", &key], b"");
    back.ok();
    assert_eq!(
        back.out.trim(),
        addr,
        "the file reads back to the printed address"
    );

    let text = std::fs::read_to_string(&key).unwrap();
    assert!(text.starts_with("PLNEKEY1"), "a real key file was written");
}

#[test]
fn generated_keys_differ_between_runs() {
    let d = Dir::new("generate-fresh");
    let mut seen = Vec::new();
    for name in ["one.plnekey", "two.plnekey", "three.plnekey"] {
        let r = wallet(
            &[
                "new",
                "--out",
                &d.s(name),
                "--role",
                "spend",
                "--no-passphrase",
            ],
            b"",
        );
        r.ok();
        let addr = r.field("address");
        assert!(addr.starts_with("plne1"));
        assert!(
            !seen.contains(&addr),
            "a generated key must not repeat an earlier address: {addr}"
        );
        seen.push(addr);
    }
}

#[test]
fn a_supplied_seed_still_pins_the_address() {
    let d = Dir::new("supplied");
    let seed = seed_hex(b"a fixed seed produces a fixed address");
    let make = |name: &str| -> String {
        wallet(
            &[
                "new",
                "--out",
                &d.s(name),
                "--role",
                "spend",
                "--no-passphrase",
                "--seed-stdin",
            ],
            seed.as_bytes(),
        )
        .ok();
        wallet(&["address", "--in", &d.s(name)], b"")
            .out
            .trim()
            .to_string()
    };
    let first = make("a.plnekey");
    let second = make("b.plnekey");
    assert!(first.starts_with("plne1"));
    assert_eq!(
        first, second,
        "the same supplied seed yields the same address"
    );
}

#[test]
fn keyfile_and_journal_hold_no_seed() {
    let d = Dir::new("ondisk");
    let seed = seed_hex(b"e2e ondisk");
    std::fs::write(d.path("pass.txt"), "a generated passphrase").unwrap();
    let key = d.s("author.plnekey");
    wallet(
        &[
            "new",
            "--out",
            &key,
            "--role",
            "author",
            "--seed-stdin",
            "--passphrase-file",
            &d.s("pass.txt"),
            "--kdf-iters",
            "1024",
        ],
        seed.as_bytes(),
    )
    .ok();

    let text = std::fs::read_to_string(&key).unwrap();
    assert!(!text.contains(&seed) && !text.to_uppercase().contains(&seed.to_uppercase()));

    assert!(text.starts_with("PLNEKEY1"));

    #[cfg(feature = "author-tools")]
    {
        let pubkey = {
            let r = wallet(&["inspect", "--in", &key], b"");
            r.ok();
            r.field("pubkey")
        };
        std::fs::write(d.path("m.txt"), "note").unwrap();
        wallet(
            &[
                "announce",
                "--in",
                &key,
                "--author-pubkey",
                &pubkey,
                "--payload-file",
                &d.s("m.txt"),
                "--encoding",
                "1",
                "--fee",
                "9000mile",
                "--nonce",
                "0",
                "--passphrase-file",
                &d.s("pass.txt"),
            ],
            b"",
        )
        .ok();

        let journal = std::fs::read_to_string(format!("{key}.journal")).unwrap();
        assert!(!journal.contains(&seed));
        assert!(!journal.contains("PLNEKEY1"));
        assert!(
            journal.contains("nonce"),
            "the journal must record the nonce: {journal}"
        );
    }
}

#[test]
fn no_networking_and_no_unsafe() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src, &mut files);
    assert!(
        files.len() > 10,
        "expected the whole crate, found {}",
        files.len()
    );

    let mut lib_forbids = false;
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let name = f.display().to_string();
        for needle in ["std::net", "TcpStream", "UdpSocket", "TcpListener"] {
            assert!(
                !text.contains(needle),
                "{name} mentions {needle}; this crate has no networking"
            );
        }

        for (i, line) in text.lines().enumerate() {
            let l = line.trim();
            if l.starts_with("//") || l.starts_with("*") || l.starts_with("///") {
                continue;
            }
            for construct in ["unsafe {", "unsafe fn", "unsafe impl", "unsafe trait"] {
                assert!(
                    !l.contains(construct),
                    "{name}:{} contains `{construct}`: {l}",
                    i + 1
                );
            }
        }
        if f.file_name().unwrap() == "lib.rs" && text.contains("#![forbid(unsafe_code)]") {
            lib_forbids = true;
        }
    }
    assert!(
        lib_forbids,
        "the crate root must carry #![forbid(unsafe_code)]"
    );

    let bin = "plaine-wallet.rs";
    let text = std::fs::read_to_string(src.join("bin").join(bin)).unwrap();
    assert!(
        text.contains("#![forbid(unsafe_code)]"),
        "src/bin/{bin} must forbid unsafe in its own right"
    );
}

#[test]
fn no_height_zero_pow_exemption() {
    let wallet_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let consensus_src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("lib")
        .join("consensus")
        .join("src");
    let mut files = Vec::new();
    collect_rs(&wallet_src, &mut files);
    collect_rs(&consensus_src, &mut files);
    assert!(
        files.len() > 15,
        "expected both crates, found {}",
        files.len()
    );

    const FORBIDDEN_NAMES: [&str; 6] = [
        "skip_pow",
        "pow_exempt",
        "genesis_pow_exempt",
        "bypass_pow",
        "no_pow_check",
        "skip_proof_of_work",
    ];
    const POW_WORDS: [&str; 6] = [
        "pow",
        "proof_of_work",
        "isochron",
        "meets_target",
        "work",
        "nonce",
    ];

    let mut checked_a_height_zero_line = false;
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let name = f.display().to_string();

        let code: Vec<String> = strip_comments_and_strings(&text);

        for (i, l) in code.iter().enumerate() {
            let lower = l.to_lowercase();

            for bad in FORBIDDEN_NAMES {
                assert!(
                    !lower.contains(bad),
                    "{name}:{}: `{bad}` is a PoW exemption by name. The genesis header must \
                     satisfy PoW and no validator may carry a height-0 exemption; genesis \
                     is pinned by its hash, never by skipping the check.\n  {l}",
                    i + 1
                );
            }

            let guards_height_zero = ["height == 0", "height==0", "height() == 0"]
                .iter()
                .any(|pat| word_bounded_match(l, pat));
            if !guards_height_zero {
                continue;
            }
            checked_a_height_zero_line = true;

            let branch = code[i..(i + 3).min(code.len())].join(" ").to_lowercase();
            let permissive = ["return ok", "return true", "continue", "=> ok", "skip"]
                .iter()
                .any(|good| branch.contains(good));
            if !permissive {
                continue;
            }

            let (start, end) = enclosing_fn(&code, i);
            let window = code[start..end].join(" ").to_lowercase();
            for w in POW_WORDS {
                assert!(
                    !window.contains(w),
                    "{name}:{}: a permissive `height == 0` branch sits inside a function \
                     that also mentions `{w}`. If this is a PoW exemption it must not exist. \
                     It is safe only while `is this genesis` means `hash == GENESIS_HASH`; \
                     the day someone writes the cheaper `height == 0`, any fabricated \
                     height-0 header skips PoW.\n  {l}",
                    i + 1
                );
            }
        }
    }
    assert!(
        checked_a_height_zero_line,
        "no `height == 0` line was examined at all; the scan is looking in the wrong place \
         and would pass vacuously"
    );
}

fn strip_comments_and_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_string = false;
    for line in text.lines() {
        let mut kept = String::new();
        let mut chars = line.chars().peekable();
        let mut escaped = false;
        while let Some(c) = chars.next() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                kept.push(' ');
                continue;
            }
            if c == '/' && chars.peek() == Some(&'/') {
                break;
            }
            if c == '"' {
                in_string = true;
                kept.push(' ');
                continue;
            }
            kept.push(c);
        }

        out.push(kept.trim().to_string());
    }
    out
}

fn enclosing_fn(code: &[String], i: usize) -> (usize, usize) {
    let is_fn_decl = |l: &String| {
        let t = l.trim_start();
        t.starts_with("fn ") || t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ")
    };
    let start = (0..=i).rev().find(|&j| is_fn_decl(&code[j])).unwrap_or(0);
    let end = ((i + 1)..code.len())
        .find(|&j| is_fn_decl(&code[j]))
        .unwrap_or(code.len());
    (start, end)
}

fn word_bounded_match(line: &str, pat: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = line[from..].find(pat) {
        let at = from + rel;
        let before_ok = at == 0 || {
            let c = bytes[at - 1] as char;
            !c.is_ascii_alphanumeric() && c != '_'
        };
        if before_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn only_one_file_names_the_signature_library() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src, &mut files);
    for f in &files {
        if f.file_name().unwrap() == "sig.rs" {
            continue;
        }
        let text = std::fs::read_to_string(f).unwrap();
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with("//") || l.starts_with("*") || l.starts_with("#") {
                continue;
            }
            assert!(
                !l.contains("ed25519_dalek"),
                "{} names ed25519_dalek outside src/sig.rs: {l}",
                f.display()
            );
        }
    }

    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("a [dependencies] section");
    let named: Vec<&str> = deps
        .lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .filter(|l| l.contains('=') && !l.trim_start().starts_with('#'))
        .map(|l| l.split('=').next().unwrap().trim())
        .collect();
    assert!(
        named.contains(&"plaine-consensus"),
        "plaine-consensus must be a dependency, found {named:?}"
    );
    assert!(
        named.len() <= 3
            && named.iter().all(|d| {
                *d == "plaine-consensus" || *d == "ed25519-dalek" || *d == "getrandom"
            }),
        "the only permitted dependencies are plaine-consensus, the documented \
         ed25519-dalek deviation, and getrandom for the OS CSPRNG, found {named:?}"
    );
}
