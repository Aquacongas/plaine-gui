#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddedKey {
    pub bytes: [u8; 32],
    pub placeholder: bool,
}

impl EmbeddedKey {
    #[allow(dead_code)]
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.bytes)
    }
}

pub fn fingerprint(bytes: &[u8; 32]) -> String {
    plaine_consensus::hex::encode(&bytes[..4])
}

pub const CHECKPOINT_AUTHORITY_KEY: EmbeddedKey = EmbeddedKey {
    bytes: hexkey(b"0741b159b8a39d6460738f94f587cb07672c07d0285d33c7952efe6571d94e19"),
    placeholder: false,
};

pub const AUTHOR_KEY: EmbeddedKey = EmbeddedKey {
    bytes: hexkey(b"da8c68b1de3ba9c9ae94ea27cbc158c496643c50779edf6a302cef728813f76b"),
    placeholder: false,
};

pub const FINGERPRINT_CHECKPOINT: &str = "0741b159";

pub const FINGERPRINT_AUTHOR: &str = "da8c68b1";

const fn const_fingerprint(bytes: &[u8; 32]) -> [u8; 8] {
    const fn hexdigit(n: u8) -> u8 {
        if n < 10 {
            b'0' + n
        } else {
            b'a' + (n - 10)
        }
    }
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < 4 {
        out[2 * i] = hexdigit(bytes[i] >> 4);
        out[2 * i + 1] = hexdigit(bytes[i] & 0x0f);
        i += 1;
    }
    out
}

const fn fp_eq(a: [u8; 8], b: &str) -> bool {
    let b = b.as_bytes();
    if b.len() != 8 {
        return false;
    }
    let mut i = 0;
    while i < 8 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    fp_eq(
        const_fingerprint(&CHECKPOINT_AUTHORITY_KEY.bytes),
        FINGERPRINT_CHECKPOINT
    ),
    "the embedded checkpoint authority key does not have the published fingerprint 0741b159. \
     Either the key bytes are wrong or the fingerprint is; do not change one to match the other \
     without knowing which is which."
);
const _: () = assert!(
    fp_eq(const_fingerprint(&AUTHOR_KEY.bytes), FINGERPRINT_AUTHOR),
    "the embedded author announcement key does not have the published fingerprint da8c68b1."
);

#[cfg(all(not(debug_assertions), not(feature = "placeholder-keys")))]
const _: () = assert!(
    !CHECKPOINT_AUTHORITY_KEY.placeholder,
    "Refusing to build an optimised binary with a placeholder checkpoint authority key. \
     A shipped binary carrying a placeholder has a checkpoint layer its own log reports as on \
     and that nobody holds the private half of, which is strictly worse than no layer at all. \
     Paste the real public key into CHECKPOINT_AUTHORITY_KEY and set `placeholder: false`. \
     If you genuinely need an optimised build mid-rotation, pass --features placeholder-keys \
     and do not let the result reach deploy/build.sh."
);
#[cfg(all(not(debug_assertions), not(feature = "placeholder-keys")))]
const _: () = assert!(
    !AUTHOR_KEY.placeholder,
    "Refusing to build an optimised binary with a placeholder author announcement key. \
     SPEC 4.1's emergency channel is the thing an algorithm change is announced through, and a \
     binary that trusts a placeholder cannot receive one. Paste the real public key into \
     AUTHOR_KEY and set `placeholder: false`."
);

pub const RETIRED_CHECKPOINT_PLACEHOLDER: [u8; 32] = ascii32(b"CHECKPOINT-PLACEHOLDER-NOT-REAL0");

pub const RETIRED_AUTHOR_PLACEHOLDER: [u8; 32] = ascii32(b"AUTHOR-KEY-PLACEHOLDER-NOT-REAL2");

pub fn placeholder_role(bytes: &[u8; 32]) -> Option<&'static str> {
    if *bytes == RETIRED_CHECKPOINT_PLACEHOLDER {
        return Some("checkpoint authority");
    }
    if *bytes == RETIRED_AUTHOR_PLACEHOLDER {
        return Some("author announcement");
    }
    if CHECKPOINT_AUTHORITY_KEY.placeholder && *bytes == CHECKPOINT_AUTHORITY_KEY.bytes {
        return Some("checkpoint authority");
    }
    if AUTHOR_KEY.placeholder && *bytes == AUTHOR_KEY.bytes {
        return Some("author announcement");
    }
    None
}

const fn ascii32(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        if s[i] < 0x20 || s[i] > 0x7e {
            panic!("placeholder keys are printable ASCII so they are obvious in a hex dump");
        }
        out[i] = s[i];
        i += 1;
    }
    out
}

pub struct EmbeddedSeeds {
    pub hosts: &'static [&'static str],
    pub placeholder: bool,
}

pub const PLACEHOLDER_TLD: &str = ".invalid";

pub const SEEDS_MAIN: EmbeddedSeeds = EmbeddedSeeds {
    hosts: &["45.9.2.226", "45.148.31.153"],
    placeholder: false,
};

// placeholder seeds live under .invalid (RFC 6761: guaranteed never to resolve).
// a build that still carries them trips the release gate below.
pub fn is_placeholder_host(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    h.len() > PLACEHOLDER_TLD.len() && h.to_ascii_lowercase().ends_with(PLACEHOLDER_TLD)
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn const_is_placeholder(h: &str) -> bool {
    let (h, t) = (h.as_bytes(), PLACEHOLDER_TLD.as_bytes());
    if h.len() <= t.len() {
        return false;
    }
    let off = h.len() - t.len();
    let mut i = 0;
    while i < t.len() {
        if h[off + i] != t[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn is_valid_ipv4_literal(h: &str) -> bool {
    let b = h.as_bytes();
    let mut i = 0usize;
    let mut octets = 0usize;
    let mut cur: u32 = 0;
    let mut digits = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'.' {
            if digits == 0 || digits > 3 || cur > 255 {
                return false;
            }
            octets += 1;
            cur = 0;
            digits = 0;
        } else if c >= b'0' && c <= b'9' {
            cur = cur * 10 + (c - b'0') as u32;
            digits += 1;
            if digits > 3 {
                return false;
            }
        } else {
            return false;
        }
        i += 1;
    }
    if digits == 0 || digits > 3 || cur > 255 {
        return false;
    }
    octets += 1;
    octets == 4
}

const fn is_valid_seed_host(h: &str) -> bool {
    let b = h.as_bytes();
    if b.is_empty() || b.len() > 253 {
        return false;
    }

    if is_valid_ipv4_literal(h) {
        return true;
    }
    let mut i = 0;
    let mut label_len = 0usize;
    let mut labels = 0usize;

    let mut alpha_in_label = false;
    while i < b.len() {
        let c = b[i];
        if c == b'.' {
            if label_len == 0 || b[i - 1] == b'-' {
                return false;
            }
            labels += 1;
            label_len = 0;
            alpha_in_label = false;
            i += 1;
            continue;
        }
        let ok = (c >= b'a' && c <= b'z') || c.is_ascii_digit() || c == b'-';
        if !ok {
            return false;
        }

        if label_len == 0 && c == b'-' {
            return false;
        }
        if c >= b'a' && c <= b'z' {
            alpha_in_label = true;
        }
        label_len += 1;
        if label_len > 63 {
            return false;
        }
        i += 1;
    }

    if label_len == 0 || b[b.len() - 1] == b'-' {
        return false;
    }
    if !alpha_in_label {
        return false;
    }
    labels += 1;
    labels >= 2
}

const fn table_is_well_formed(t: &EmbeddedSeeds) -> bool {
    if t.hosts.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < t.hosts.len() {
        if !is_valid_seed_host(t.hosts[i]) {
            return false;
        }

        if const_is_placeholder(t.hosts[i]) != t.placeholder {
            return false;
        }

        let mut j = i + 1;
        while j < t.hosts.len() {
            if str_eq(t.hosts[i], t.hosts[j]) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

pub const SEEDS_ARE_NOT_EMPTY: () = {
    assert!(
        !SEEDS_MAIN.hosts.is_empty(),
        "SEEDS_MAIN is empty. An empty seed table does not mean 'no seeds' - config.rs falls \
         back to this table when p2p.seeds is absent or empty, so an empty table means a stock \
         node dials nobody and stalls at height 0 forever. That is the B5 failure and \
         it is not re-committable. Put the operator's registered seed hostnames here."
    );
};

const _: () = SEEDS_ARE_NOT_EMPTY;

const _: () = assert!(
    table_is_well_formed(&SEEDS_MAIN),
    "SEEDS_MAIN is malformed. Every entry must be a bare lower-case DNS hostname with at least \
     two labels and no port (the port comes from the network, not the table), every entry must \
     be unique, and every entry must end in .invalid if and only if `placeholder` is true."
);

#[cfg(all(not(debug_assertions), not(feature = "placeholder-seeds")))]
const _: () = assert!(
    !SEEDS_MAIN.placeholder,
    "Refusing to build an optimised binary with placeholder mainnet seeds. The names in \
     SEEDS_MAIN end in .invalid, which RFC 6761 guarantees will never resolve, so this artifact \
     would ship to strangers who cannot reach the network at all. Register the DNS records \
     listed in docs/false`. If you genuinely need an optimised build before the records exist, \
     pass --features placeholder-seeds and do not let the result reach deploy/build.sh."
);

// The low-order ed25519 points. A signature verifies against any of these for any
// message, so a pubkey encoding one is refused before it is ever trusted as a key.
const SMALL_ORDER_KEYS: [[u8; 32]; 12] = [
    hexkey(b"0100000000000000000000000000000000000000000000000000000000000000"),
    hexkey(b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hexkey(b"0000000000000000000000000000000000000000000000000000000000000000"),
    hexkey(b"0000000000000000000000000000000000000000000000000000000000000080"),
    hexkey(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    hexkey(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hexkey(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    hexkey(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    hexkey(b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hexkey(b"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hexkey(b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    hexkey(b"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
];

const fn hexkey(s: &[u8; 64]) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("a hex key literal contains a non-hex character (lower case only)"),
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(s[2 * i]) << 4) | nib(s[2 * i + 1]);
        i += 1;
    }
    out
}

pub fn is_valid_pubkey(bytes: &[u8; 32]) -> bool {
    if SMALL_ORDER_KEYS.contains(bytes) {
        return false;
    }
    !matches!(
        plaine_consensus::crypto::verify_signature(bytes, b"", &[0u8; 64]),
        Err(plaine_consensus::crypto::SigError::InvalidPubkey)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_keys_are_curve_points() {
        assert!(is_valid_pubkey(&CHECKPOINT_AUTHORITY_KEY.bytes));
        assert!(is_valid_pubkey(&AUTHOR_KEY.bytes));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn fresh_install_verifies_checkpoints() {
        assert!(
            !CHECKPOINT_AUTHORITY_KEY.placeholder,
            "the checkpoint key is still a placeholder"
        );
        assert!(
            !AUTHOR_KEY.placeholder,
            "the author key is still a placeholder"
        );
        assert_eq!(placeholder_role(&CHECKPOINT_AUTHORITY_KEY.bytes), None);
        assert_eq!(placeholder_role(&AUTHOR_KEY.bytes), None);
        assert_eq!(
            CHECKPOINT_AUTHORITY_KEY.fingerprint(),
            FINGERPRINT_CHECKPOINT
        );
        assert_eq!(AUTHOR_KEY.fingerprint(), FINGERPRINT_AUTHOR);
    }

    #[test]
    fn compile_and_runtime_fingerprint_agree() {
        for k in [CHECKPOINT_AUTHORITY_KEY, AUTHOR_KEY] {
            let compiled = core::str::from_utf8(&const_fingerprint(&k.bytes))
                .unwrap()
                .to_string();
            assert_eq!(compiled, k.fingerprint());
        }

        assert_eq!(
            core::str::from_utf8(&const_fingerprint(&[
                0xda, 0x8c, 0x68, 0xb1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ]))
            .unwrap(),
            "da8c68b1"
        );
        assert!(fp_eq(const_fingerprint(&AUTHOR_KEY.bytes), "da8c68b1"));
        assert!(!fp_eq(const_fingerprint(&AUTHOR_KEY.bytes), "da8c68b2"));
        assert!(!fp_eq(const_fingerprint(&AUTHOR_KEY.bytes), "da8c68b"));
    }

    #[test]
    fn keys_are_distinct() {
        assert_ne!(CHECKPOINT_AUTHORITY_KEY.bytes, AUTHOR_KEY.bytes);
    }

    #[test]
    fn small_order_encodings_refused() {
        for k in SMALL_ORDER_KEYS {
            assert!(
                !is_valid_pubkey(&k),
                "accepted small-order key {}",
                plaine_consensus::hex::encode(&k)
            );
        }

        assert!(is_valid_pubkey(&CHECKPOINT_AUTHORITY_KEY.bytes));
        assert!(is_valid_pubkey(&AUTHOR_KEY.bytes));
    }

    #[test]
    fn corrupted_key_rejected() {
        assert!(!is_valid_pubkey(&[0u8; 32]));

        let mut bad = CHECKPOINT_AUTHORITY_KEY.bytes;
        bad[31] ^= 0x40;

        assert_ne!(bad, CHECKPOINT_AUTHORITY_KEY.bytes);
    }

    #[test]
    fn fingerprints_are_eight_hex() {
        assert_eq!(CHECKPOINT_AUTHORITY_KEY.fingerprint(), "0741b159");
        assert_eq!(AUTHOR_KEY.fingerprint(), "da8c68b1");
        assert_eq!(CHECKPOINT_AUTHORITY_KEY.fingerprint().len(), 8);
        assert_ne!(
            CHECKPOINT_AUTHORITY_KEY.fingerprint(),
            AUTHOR_KEY.fingerprint()
        );
    }

    #[test]
    fn retired_placeholders_are_plain_text() {
        let cp = core::str::from_utf8(&RETIRED_CHECKPOINT_PLACEHOLDER).unwrap();
        let au = core::str::from_utf8(&RETIRED_AUTHOR_PLACEHOLDER).unwrap();
        assert!(
            cp.contains("PLACEHOLDER") && cp.contains("NOT-REAL"),
            "{cp}"
        );
        assert!(
            au.contains("PLACEHOLDER") && au.contains("NOT-REAL"),
            "{au}"
        );
        assert!(cp.contains("CHECKPOINT") && au.contains("AUTHOR"));

        assert!(is_valid_pubkey(&RETIRED_CHECKPOINT_PLACEHOLDER));
        assert!(is_valid_pubkey(&RETIRED_AUTHOR_PLACEHOLDER));
    }

    #[test]
    fn keys_are_not_rfc8032_test_vectors() {
        const RFC8032_TEST1_PUBLIC: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        const RFC8032_TEST2_PUBLIC: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        for known in [RFC8032_TEST1_PUBLIC, RFC8032_TEST2_PUBLIC] {
            assert_ne!(CHECKPOINT_AUTHORITY_KEY.bytes, known);
            assert_ne!(AUTHOR_KEY.bytes, known);
        }
    }

    #[test]
    fn placeholder_recognised_by_bytes() {
        assert_eq!(
            placeholder_role(&RETIRED_CHECKPOINT_PLACEHOLDER),
            Some("checkpoint authority")
        );
        assert_eq!(
            placeholder_role(&RETIRED_AUTHOR_PLACEHOLDER),
            Some("author announcement")
        );

        let mut other = RETIRED_CHECKPOINT_PLACEHOLDER;
        other[31] = b'4';
        assert_eq!(placeholder_role(&other), None);

        assert_eq!(placeholder_role(&CHECKPOINT_AUTHORITY_KEY.bytes), None);
        assert_eq!(placeholder_role(&AUTHOR_KEY.bytes), None);
    }

    #[test]
    fn seed_table_not_empty() {
        assert!(
            !SEEDS_MAIN.hosts.is_empty(),
            "SEEDS_MAIN is empty - this is B5 again"
        );
        let () = SEEDS_ARE_NOT_EMPTY;
    }

    #[test]
    fn seeds_have_no_port_or_scheme() {
        for h in SEEDS_MAIN.hosts.iter() {
            assert!(!h.contains(':'), "{h} carries a port or a scheme");
            assert!(!h.contains('/'), "{h} looks like a URL");
            assert!(!h.contains('@'), "{h} carries userinfo");
            assert!(
                h.contains('.'),
                "{h} is a single label and would go through the search domain"
            );
            assert_eq!(*h, h.to_ascii_lowercase(), "{h} is not lower case");
            assert!(is_valid_seed_host(h), "{h} is not a valid seed hostname");
        }
    }

    #[test]
    fn placeholder_table_all_placeholder() {
        for t in [&SEEDS_MAIN] {
            for h in t.hosts {
                assert_eq!(
                    is_placeholder_host(h),
                    t.placeholder,
                    "{h} disagrees with the table's placeholder flag"
                );
                assert_eq!(const_is_placeholder(h), t.placeholder);
            }
            assert!(table_is_well_formed(t));
        }
    }

    #[test]
    fn placeholder_recognised_any_spelling() {
        assert!(is_placeholder_host(
            "seed1.main.placeholder-not-real.invalid"
        ));
        assert!(is_placeholder_host(
            "seed1.main.placeholder-not-real.invalid."
        ));
        assert!(is_placeholder_host(
            "SEED1.MAIN.PLACEHOLDER-NOT-REAL.INVALID"
        ));
        assert!(is_placeholder_host("anything.invalid"));

        assert!(!is_placeholder_host("seed1.example.net"));
        assert!(!is_placeholder_host("invalid.example.net"));
        assert!(!is_placeholder_host("notinvalid"));

        assert!(!is_placeholder_host(".invalid"));
    }

    #[test]
    fn hostname_rules_refuse_bad_hosts() {
        assert!(is_valid_seed_host("seed1.example.net"));
        assert!(is_valid_seed_host("a.b"));
        assert!(is_valid_seed_host("seed-1.test.example.net"));
        assert!(
            !is_valid_seed_host("seed1.example.net:9256"),
            "a port must not be accepted"
        );
        assert!(!is_valid_seed_host("http://seed1.example.net"));
        assert!(!is_valid_seed_host("user@seed1.example.net"));
        assert!(
            !is_valid_seed_host("seed1"),
            "a single label uses the search domain"
        );
        assert!(
            !is_valid_seed_host("seed1.example.net."),
            "a trailing dot is an empty last label"
        );
        assert!(
            !is_valid_seed_host("Seed1.Example.Net"),
            "upper case defeats byte comparison"
        );
        assert!(!is_valid_seed_host(""));
        assert!(!is_valid_seed_host("seed1..net"));
        assert!(!is_valid_seed_host("-seed.net"));
        assert!(!is_valid_seed_host("seed-.net"));
        assert!(!is_valid_seed_host("seed.net-"));

        assert!(
            is_valid_seed_host("1.2.3.4"),
            "a bare IPv4 literal is a sanctioned seed"
        );
        assert!(is_valid_seed_host("203.0.113.10"));
        assert!(
            !is_valid_seed_host("1.2.3.4:9256"),
            "a port is still not accepted"
        );
        assert!(
            !is_valid_seed_host("256.1.1.1"),
            "an octet over 255 is not an IPv4"
        );
        assert!(!is_valid_seed_host("1.2.3"), "three octets is not an IPv4");
        assert!(
            !is_valid_seed_host("1.2.3.4.5"),
            "five octets is not an IPv4"
        );

        let long = format!("{}.net", "a".repeat(64));
        assert!(!is_valid_seed_host(&long));
        let ok63 = format!("{}.net", "a".repeat(63));
        assert!(is_valid_seed_host(&ok63));

        assert!(is_valid_seed_host("seed1.plaine.net"));
        assert!(is_valid_seed_host("seed4.plaine.net"));
        assert!(is_valid_seed_host("seed1.node.plaine.net"));
        assert!(!is_placeholder_host("seed1.plaine.net"));
        assert!(!is_placeholder_host("seed1.node.plaine.net"));
    }

    #[test]
    fn well_formed_catches_bad_tables() {
        const DUP: EmbeddedSeeds = EmbeddedSeeds {
            hosts: &["a.invalid", "a.invalid"],
            placeholder: true,
        };
        assert!(!table_is_well_formed(&DUP));
        const MIXED: EmbeddedSeeds = EmbeddedSeeds {
            hosts: &["a.invalid", "b.example"],
            placeholder: true,
        };
        assert!(
            !table_is_well_formed(&MIXED),
            "a mixed table must not be well formed"
        );
        const LYING: EmbeddedSeeds = EmbeddedSeeds {
            hosts: &["a.invalid"],
            placeholder: false,
        };
        assert!(
            !table_is_well_formed(&LYING),
            "real-flagged .invalid names must be refused"
        );
        const EMPTY: EmbeddedSeeds = EmbeddedSeeds {
            hosts: &[],
            placeholder: false,
        };
        assert!(
            !table_is_well_formed(&EMPTY),
            "B5: an empty table is not well formed"
        );
    }

    #[test]
    fn seed_gate_matches_names() {
        let gate_would_refuse = SEEDS_MAIN.placeholder;
        let some_name_can_never_resolve = SEEDS_MAIN.hosts.iter().any(|h| is_placeholder_host(h));
        assert_eq!(
            gate_would_refuse, some_name_can_never_resolve,
            "the placeholder flag and the seed names disagree"
        );
    }

    #[test]
    #[ignore = "operator tool: red until the seed DNS records exist. \
                Run with --ignored before tagging a release."]
    #[allow(clippy::assertions_on_constants)]
    fn seed_tables_ready_for_release() {
        assert!(
            !SEEDS_MAIN.placeholder,
            "an optimised build of this source would be REFUSED by the seed release gate in \
             embedded.rs: SEEDS_MAIN still holds .invalid placeholder names, which \
             RFC 6761 guarantees will never resolve. Register the DNS records listed in \
             paste the real hostnames in."
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn no_placeholder_in_release() {
        assert!(
            !CHECKPOINT_AUTHORITY_KEY.placeholder && !AUTHOR_KEY.placeholder,
            "an optimised build of this source would be REFUSED by the release gate in \
             embedded.rs: a shipped binary must not carry a placeholder authority key"
        );
    }
}
