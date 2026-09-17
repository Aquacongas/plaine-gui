use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::config::LogLevel;
use crate::embedded;

// per-seed and total caps. One seed name should not own the whole dial book -
// that is how an eclipse starts.
pub const MAX_ADDRS_PER_SEED: usize = 8;

pub const MAX_ADDRS_TOTAL: usize = 32;

// retry ladder: climb on each failed attempt, then hold at the top. A node with
// no reachable seeds keeps trying, but stops hammering dns.
pub const BACKOFF_MS: [u64; 5] = [5_000, 15_000, 60_000, 300_000, 600_000];

pub const SETTLED_POLL_MS: u64 = 30_000;

pub trait Resolve {
    fn lookup(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn lookup(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seed {
    Literal(SocketAddr),

    Host { name: String, port: u16 },
    Placeholder(String),

    Malformed { text: String, why: &'static str },
}

pub fn parse(text: &str, default_port: u16) -> Seed {
    let t = text.trim();
    if t.is_empty() {
        return Seed::Malformed {
            text: text.to_string(),
            why: "empty entry",
        };
    }

    if let Ok(sa) = t.parse::<SocketAddr>() {
        return if sa.port() == 0 {
            Seed::Malformed {
                text: t.to_string(),
                why: "port 0 is not a listener",
            }
        } else {
            Seed::Literal(sa)
        };
    }

    let bare = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(t);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Seed::Literal(SocketAddr::new(ip, default_port));
    }

    if t.contains('/') {
        return Seed::Malformed {
            text: t.to_string(),
            why: "that is a URL, not a hostname - drop the scheme and the path",
        };
    }
    if t.contains('@') {
        return Seed::Malformed {
            text: t.to_string(),
            why: "a seed is a host, not a user@host",
        };
    }

    let (name, port) = match t.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(0) => {
                return Seed::Malformed {
                    text: t.to_string(),
                    why: "port 0 is not a listener",
                }
            }
            Ok(p) => (h, p),
            Err(_) => {
                return Seed::Malformed {
                    text: t.to_string(),
                    why: "the text after ':' is not a port number",
                }
            }
        },
        None => (t, default_port),
    };
    if let Some(why) = name_fault(name) {
        return Seed::Malformed {
            text: t.to_string(),
            why,
        };
    }
    if embedded::is_placeholder_host(name) {
        return Seed::Placeholder(name.to_ascii_lowercase());
    }
    Seed::Host {
        name: name.to_ascii_lowercase(),
        port,
    }
}

fn name_fault(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("empty hostname");
    }
    if name.len() > 253 {
        return Some("a hostname is at most 253 characters");
    }
    if name.contains('/') {
        return Some("that is a URL, not a hostname - drop the scheme and the path");
    }
    if name.contains('@') {
        return Some("a seed is a host, not a user@host");
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Some("empty hostname");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Some("empty label (two dots in a row, or a leading dot)");
        }
        if label.len() > 63 {
            return Some("a hostname label is at most 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some("a hostname label may not start or end with '-'");
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Some("a hostname is letters, digits and '-' only");
        }
    }
    None
}

// refuse loopback, private, link-local and reserved ranges. A seed has no
// business pointing this node at its own machine or lan.
pub fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_routable_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_routable_v4(v4);
            }
            is_routable_v6(a)
        }
    }
}

fn is_routable_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || o[0] >= 240)
}

fn is_routable_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0)
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010)
        || (s[0] == 0x0064 && s[1] == 0xff9b))
}

// coarse network bucket (v4 /16, v6 /32) for measuring address diversity. Every
// bootstrap address landing in one bucket is what an eclipse looks like.
pub fn group_of(a: &SocketAddr) -> [u8; 4] {
    match a.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [0, 0, o[0], o[1]]
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                let o = v4.octets();
                return [0, 0, o[0], o[1]];
            }
            let o = v6.octets();
            [o[0], o[1], o[2], o[3]]
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    Literal(SocketAddr),

    Resolved {
        host: String,
        kept: usize,
        unroutable: usize,
        capped: usize,
    },

    Empty {
        host: String,
        unroutable: usize,
    },

    Failed {
        host: String,
        why: String,
    },
    Placeholder(String),

    Malformed {
        text: String,
        why: &'static str,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub addrs: Vec<SocketAddr>,
    pub notes: Vec<Note>,
}

impl Attempt {
    pub fn groups(&self) -> usize {
        let mut g: Vec<[u8; 4]> = self.addrs.iter().map(group_of).collect();
        g.sort_unstable();
        g.dedup();
        g.len()
    }

    pub fn names_tried(&self) -> usize {
        self.notes
            .iter()
            .filter(|n| {
                matches!(
                    n,
                    Note::Resolved { .. } | Note::Empty { .. } | Note::Failed { .. }
                )
            })
            .count()
    }

    pub fn names_answered(&self) -> usize {
        self.notes
            .iter()
            .filter(|n| matches!(n, Note::Resolved { .. }))
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct Bootstrap {
    seeds: Vec<Seed>,
    failures: u32,
}

impl Bootstrap {
    pub fn new(seeds: &[String], port: u16) -> Bootstrap {
        Bootstrap {
            seeds: seeds.iter().map(|s| parse(s, port)).collect(),
            failures: 0,
        }
    }

    #[allow(dead_code)]
    pub fn seeds(&self) -> &[Seed] {
        &self.seeds
    }

    pub fn resolvable_names(&self) -> usize {
        self.seeds
            .iter()
            .filter(|s| matches!(s, Seed::Host { .. }))
            .count()
    }

    pub fn placeholders(&self) -> usize {
        self.seeds
            .iter()
            .filter(|s| matches!(s, Seed::Placeholder(_)))
            .count()
    }

    pub fn literals(&self) -> Vec<SocketAddr> {
        self.seeds
            .iter()
            .filter_map(|s| match s {
                Seed::Literal(a) => Some(*a),
                _ => None,
            })
            .collect()
    }

    pub fn is_hopeless(&self) -> bool {
        !self
            .seeds
            .iter()
            .any(|s| matches!(s, Seed::Literal(_) | Seed::Host { .. }))
    }

    pub fn run(&mut self, r: &dyn Resolve) -> Attempt {
        let mut notes = Vec::with_capacity(self.seeds.len());

        let mut buckets: Vec<Vec<SocketAddr>> = Vec::new();
        let mut seen: HashSet<SocketAddr> = HashSet::new();

        for s in &self.seeds {
            match s {
                Seed::Literal(a) => {
                    notes.push(Note::Literal(*a));
                    if seen.insert(*a) {
                        buckets.push(vec![*a]);
                    }
                }
                Seed::Placeholder(h) => notes.push(Note::Placeholder(h.clone())),
                Seed::Malformed { text, why } => notes.push(Note::Malformed {
                    text: text.clone(),
                    why,
                }),
                Seed::Host { name, port } => match r.lookup(name, *port) {
                    Err(e) => notes.push(Note::Failed {
                        host: name.clone(),
                        why: e.to_string(),
                    }),
                    Ok(answers) => {
                        let total = answers.len();
                        let mut kept = Vec::new();
                        let mut unroutable = 0usize;
                        for a in answers {
                            if !is_routable(a.ip()) {
                                unroutable += 1;
                                continue;
                            }
                            if kept.len() >= MAX_ADDRS_PER_SEED {
                                continue;
                            }
                            if seen.insert(a) {
                                kept.push(a);
                            }
                        }
                        let capped = total - unroutable - kept.len();
                        if kept.is_empty() {
                            notes.push(Note::Empty {
                                host: name.clone(),
                                unroutable,
                            });
                        } else {
                            notes.push(Note::Resolved {
                                host: name.clone(),
                                kept: kept.len(),
                                unroutable,
                                capped,
                            });
                            buckets.push(kept);
                        }
                    }
                },
            }
        }

        let addrs = interleave(buckets, MAX_ADDRS_TOTAL);
        Attempt { addrs, notes }
    }

    pub fn record(&mut self, progress: bool) {
        if progress {
            self.failures = 0;
        } else {
            self.failures = self.failures.saturating_add(1);
        }
    }

    #[allow(dead_code)]
    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn backoff_ms(&self) -> u64 {
        let i = self.failures.saturating_sub(1) as usize;
        BACKOFF_MS[i.min(BACKOFF_MS.len() - 1)]
    }

    pub fn settle(&mut self) {
        self.failures = 0;
    }
}

// round-robin across seed buckets: draw from every name before taking a second
// address from any one. keeps a single seed from dominating.
pub fn interleave(mut buckets: Vec<Vec<SocketAddr>>, cap: usize) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut round = 0usize;
    loop {
        let mut moved = false;
        for b in buckets.iter_mut() {
            if let Some(a) = b.get(round).copied() {
                moved = true;
                if out.len() < cap {
                    out.push(a);
                }
            }
        }
        if !moved || out.len() >= cap {
            break;
        }
        round += 1;
    }
    out
}

pub fn lines(a: &Attempt, backoff_ms: u64) -> Vec<(LogLevel, String)> {
    let mut out = Vec::new();
    for n in &a.notes {
        match n {
            Note::Literal(addr) => out.push((
                LogLevel::Debug,
                format!("seed {addr} (literal address, dialling)"),
            )),
            Note::Resolved {
                host,
                kept,
                unroutable,
                capped,
            } => {
                let mut m = format!("seed {host} resolved to {kept} address(es)");
                if *unroutable > 0 {
                    m.push_str(&format!(
                        ", {unroutable} refused as non-routable (loopback, private or reserved - \
                         a seed must not be able to point this node at its own network)"
                    ));
                }
                if *capped > 0 {
                    m.push_str(&format!(
                        ", {capped} dropped by the per-seed cap of {MAX_ADDRS_PER_SEED}"
                    ));
                }
                out.push((LogLevel::Info, m));
            }
            Note::Empty { host, unroutable } => out.push((
                LogLevel::Warn,
                format!(
                    "seed {host} resolved, but every one of its {unroutable} answer(s) was \
                     non-routable (loopback, private or reserved). Either this name is pointed \
                     at the wrong thing or the answer did not come from the real zone."
                ),
            )),
            Note::Failed { host, why } => out.push((
                LogLevel::Warn,
                format!("seed {host} did not resolve: {why}"),
            )),
            Note::Placeholder(host) => out.push((
                LogLevel::Error,
                format!(
                    "seed {host} is a build placeholder and was not looked up. `.invalid` is \
                     reserved by RFC 6761 and can never resolve, so the query would only ever \
                     return NXDOMAIN. It reached this node either from a binary built before \
                     the real seed names existed - the release gate refuses to compile an \
                     optimised one - or from a `p2p.seeds` line that names it. Set `p2p.seeds` \
                     to names that exist, or run a release binary."
                ),
            )),
            Note::Malformed { text, why } => out.push((
                LogLevel::Error,
                format!("seed {text:?} is not usable: {why}. It was ignored."),
            )),
        }
    }

    if a.is_empty() {
        out.push((
            LogLevel::Warn,
            format!(
                "No seed addresses. This node has nothing to dial and cannot find the network \
                 on its own; it will still accept peers that dial in. Retrying in {}s. If this \
                 repeats: check that the machine can resolve names at all, and that outbound \
                 TCP is not blocked.",
                backoff_ms / 1000
            ),
        ));
    } else {
        let g = a.groups();
        out.push((
            LogLevel::Info,
            format!(
                "bootstrap: {} address(es) from {}/{} seed name(s) plus literals, spanning {} \
                 /16 group(s)",
                a.addrs.len(),
                a.names_answered(),
                a.names_tried(),
                g
            ),
        ));
        if g == 1 && a.addrs.len() > 1 {
            out.push((
                LogLevel::Warn,
                "every bootstrap address is in one /16. That is correct on a private network \
                 and is what an eclipse looks like on a public one - if this is mainnet, the \
                 seed names are not as diverse as they should be."
                    .to_string(),
            ));
        }
    }
    out
}

pub fn drive_with(
    mut d: Driver,
    resolver: &dyn Resolve,
    dial: &dyn Fn(SocketAddr),
    outbound_peers: &dyn Fn() -> usize,
    stop: &std::sync::atomic::AtomicBool,
) {
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let wait = d.step(
            resolver,
            outbound_peers(),
            &mut |a| dial(a),
            &mut |level, msg| crate::log::log(level, "p2p", &msg),
        );
        nap(wait, stop);
    }
}

pub struct Driver {
    b: Bootstrap,
    already: HashSet<SocketAddr>,
    last: Option<Vec<Note>>,
}

impl Driver {
    pub fn new(b: Bootstrap) -> Driver {
        Driver {
            b,
            already: HashSet::new(),
            last: None,
        }
    }

    pub fn step(
        &mut self,
        resolver: &dyn Resolve,
        outbound_peers: usize,
        dial: &mut dyn FnMut(SocketAddr),
        say: &mut dyn FnMut(LogLevel, String),
    ) -> u64 {
        // outbound, not total. A sync peer is only ever designated from an outbound
        // connection, so inbound-only peers do not stop us dialling.
        if outbound_peers > 0 {
            self.b.settle();

            self.last = None;
            return SETTLED_POLL_MS;
        }
        let attempt = self.b.run(resolver);
        let mut fresh = 0usize;
        for a in &attempt.addrs {
            if self.already.insert(*a) {
                dial(*a);
                fresh += 1;
            }
        }

        self.b.record(fresh > 0);
        let wait = self.b.backoff_ms();

        let changed = self.last.as_deref() != Some(attempt.notes.as_slice());
        if fresh > 0 || changed {
            for (level, msg) in lines(&attempt, wait) {
                say(level, msg);
            }
        }
        self.last = Some(attempt.notes);
        wait
    }

    #[allow(dead_code)]
    pub fn offered(&self) -> usize {
        self.already.len()
    }

    pub fn pre_offered(&mut self, a: SocketAddr) {
        self.already.insert(a);
    }
}

fn nap(ms: u64, stop: &std::sync::atomic::AtomicBool) {
    let mut left = ms;
    while left > 0 && !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let slice = left.min(250);
        std::thread::sleep(std::time::Duration::from_millis(slice));
        left -= slice;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        table: HashMap<String, std::io::Result<Vec<SocketAddr>>>,
        asked: std::cell::RefCell<Vec<(String, u16)>>,
    }

    impl Fake {
        fn ok(mut self, host: &str, addrs: &[&str]) -> Fake {
            self.table.insert(
                host.to_string(),
                Ok(addrs
                    .iter()
                    .map(|a| a.parse().expect("test address"))
                    .collect()),
            );
            self
        }
        fn fail(mut self, host: &str, kind: std::io::ErrorKind, msg: &str) -> Fake {
            self.table.insert(
                host.to_string(),
                Err(std::io::Error::new(kind, msg.to_string())),
            );
            self
        }
    }

    impl Resolve for Fake {
        fn lookup(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.asked.borrow_mut().push((host.to_string(), port));
            match self.table.get(host) {
                Some(Ok(v)) => Ok(v.clone()),
                Some(Err(e)) => Err(std::io::Error::new(e.kind(), e.to_string())),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such host is known (test)",
                )),
            }
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    const P: u16 = 9256;

    #[test]
    fn parse_understands_every_shape() {
        assert_eq!(
            parse("1.2.3.4:9256", P),
            Seed::Literal("1.2.3.4:9256".parse().unwrap())
        );

        assert_eq!(
            parse("1.2.3.4", P),
            Seed::Literal("1.2.3.4:9256".parse().unwrap())
        );
        assert_eq!(
            parse("[2001:db8::1]:9256", P),
            Seed::Literal("[2001:db8::1]:9256".parse().unwrap())
        );
        assert_eq!(
            parse("2001:db8::1", P),
            Seed::Literal("[2001:db8::1]:9256".parse().unwrap())
        );
        assert_eq!(
            parse("[2001:db8::1]", P),
            Seed::Literal("[2001:db8::1]:9256".parse().unwrap())
        );
        assert_eq!(
            parse("seed1.example.net", P),
            Seed::Host {
                name: "seed1.example.net".into(),
                port: P
            }
        );
        assert_eq!(
            parse("seed1.example.net:19256", P),
            Seed::Host {
                name: "seed1.example.net".into(),
                port: 19256
            }
        );

        assert_eq!(
            parse("  Seed1.Example.NET  ", P),
            Seed::Host {
                name: "seed1.example.net".into(),
                port: P
            }
        );

        assert_eq!(
            parse("localhost:9256", P),
            Seed::Host {
                name: "localhost".into(),
                port: 9256
            }
        );
    }

    #[test]
    fn hostname_seed_is_kept() {
        for text in ["seed1.example.net", "seed1.example.net:19256", "localhost"] {
            assert!(
                matches!(parse(text, P), Seed::Host { .. }),
                "{text} must parse as a name, not vanish"
            );
        }
    }

    #[test]
    fn unusable_entry_says_why() {
        for (text, needle) in [
            ("", "empty"),
            ("   ", "empty"),
            ("http://seed1.example.net", "URL"),
            ("user@seed1.example.net", "user@host"),
            ("seed1.example.net:0", "port 0"),
            ("1.2.3.4:0", "port 0"),
            ("seed1.example.net:notaport", "not a port"),
            ("seed1..example.net", "empty label"),
            ("-seed.example.net", "'-'"),
        ] {
            match parse(text, P) {
                Seed::Malformed { why, .. } => {
                    assert!(
                        why.contains(needle),
                        "{text:?} -> {why:?} (wanted {needle:?})"
                    )
                }
                other => panic!("{text:?} should be malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn placeholder_recognised_before_query() {
        assert_eq!(
            parse("seed1.main.placeholder-not-real.invalid", P),
            Seed::Placeholder("seed1.main.placeholder-not-real.invalid".into())
        );

        assert_eq!(
            parse("SEED1.MAIN.PLACEHOLDER-NOT-REAL.INVALID:9256", P),
            Seed::Placeholder("seed1.main.placeholder-not-real.invalid".into())
        );
    }

    #[test]
    fn no_resolution_warns_and_retries() {
        let r = Fake::default()
            .fail(
                "a.example.net",
                std::io::ErrorKind::Other,
                "Temporary failure in name resolution",
            )
            .fail(
                "b.example.net",
                std::io::ErrorKind::Other,
                "Temporary failure in name resolution",
            );
        let mut b = Bootstrap::new(&s(&["a.example.net", "b.example.net"]), P);
        let a = b.run(&r);
        b.record(!a.is_empty());

        assert!(a.is_empty(), "nothing resolved, so nothing may be dialled");
        assert_eq!(a.names_tried(), 2);
        assert_eq!(a.names_answered(), 0);
        assert_eq!(b.failures(), 1);

        let text = lines(&a, b.backoff_ms());

        assert!(text.iter().any(|(l, m)| *l == LogLevel::Warn
            && m.contains("a.example.net")
            && m.contains("Temporary failure")));
        assert!(text
            .iter()
            .any(|(l, m)| *l == LogLevel::Warn && m.contains("No seed addresses")));
        assert!(text.iter().any(|(_, m)| m.contains("Retrying in 5s")));
    }

    #[test]
    fn backoff_ladder_climbs_and_caps() {
        let r = Fake::default();
        let mut b = Bootstrap::new(&s(&["a.example.net"]), P);
        let mut seen = Vec::new();
        for _ in 0..8 {
            let a = b.run(&r);
            b.record(!a.is_empty());
            seen.push(b.backoff_ms());
        }
        assert_eq!(&seen[..5], &BACKOFF_MS[..]);

        assert_eq!(&seen[5..], &[600_000, 600_000, 600_000]);
        assert!(seen.iter().all(|&x| x > 0), "a zero backoff is a spin loop");
    }

    #[test]
    fn success_resets_ladder() {
        let bad = Fake::default();
        let good = Fake::default().ok("a.example.net", &["5.6.7.7:9256"]);
        let mut b = Bootstrap::new(&s(&["a.example.net"]), P);
        for _ in 0..4 {
            let a = b.run(&bad);
            b.record(!a.is_empty());
        }
        assert_eq!(b.backoff_ms(), BACKOFF_MS[3]);
        let a = b.run(&good);
        b.record(!a.is_empty());
        assert_eq!(a.addrs.len(), 1);
        assert_eq!(b.failures(), 0);
        assert_eq!(b.backoff_ms(), BACKOFF_MS[0]);
    }

    #[test]
    fn peers_reset_ladder() {
        let mut b = Bootstrap::new(&s(&["a.example.net"]), P);
        for _ in 0..5 {
            let a = b.run(&Fake::default());
            b.record(!a.is_empty());
        }
        assert_eq!(b.backoff_ms(), BACKOFF_MS[4]);
        b.settle();
        assert_eq!(b.backoff_ms(), BACKOFF_MS[0]);
    }

    #[test]
    fn partial_resolution_uses_and_names() {
        let r = Fake::default().ok("a.example.net", &["5.6.7.7:9256"]).fail(
            "b.example.net",
            std::io::ErrorKind::NotFound,
            "NXDOMAIN",
        );
        let mut b = Bootstrap::new(&s(&["a.example.net", "b.example.net", "c.example.net"]), P);
        let a = b.run(&r);
        b.record(!a.is_empty());

        assert_eq!(a.addrs, vec!["5.6.7.7:9256".parse::<SocketAddr>().unwrap()]);
        assert_eq!(a.names_answered(), 1);
        assert_eq!(a.names_tried(), 3);

        assert_eq!(b.failures(), 0);

        let text = lines(&a, b.backoff_ms());
        assert!(text
            .iter()
            .any(|(_, m)| m.contains("b.example.net") && m.contains("NXDOMAIN")));
        assert!(text.iter().any(|(_, m)| m.contains("c.example.net")));
        assert!(!text.iter().any(|(_, m)| m.contains("No seed addresses")));
    }

    #[test]
    fn seeds_are_re_resolved() {
        let moved = Fake::default().ok("a.example.net", &["5.6.7.7:9256"]);
        let mut b = Bootstrap::new(&s(&["a.example.net"]), P);
        let first = b.run(&moved);
        assert_eq!(
            first.addrs,
            vec!["5.6.7.7:9256".parse::<SocketAddr>().unwrap()]
        );

        let after = Fake::default().ok("a.example.net", &["9.9.9.9:9256"]);
        let second = b.run(&after);
        assert_eq!(
            second.addrs,
            vec!["9.9.9.9:9256".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn seed_cannot_point_at_local() {
        let r = Fake::default().ok(
            "hostile.example.net",
            &[
                "127.0.0.1:9256",
                "10.44.0.1:9256",
                "192.168.1.10:9256",
                "172.16.5.5:9256",
                "169.254.1.1:9256",
                "100.64.0.1:9256",
                "0.0.0.0:9256",
                "224.0.0.1:9256",
                "255.255.255.255:9256",
                "240.0.0.1:9256",
                "198.18.0.1:9256",
                "192.0.2.1:9256",
                "[::1]:9256",
                "[fe80::1]:9256",
                "[fc00::1]:9256",
                "[ff02::1]:9256",
                "[2001:db8::1]:9256",
                "[::ffff:127.0.0.1]:9256",
            ],
        );
        let mut b = Bootstrap::new(&s(&["hostile.example.net"]), P);
        let a = b.run(&r);
        assert!(
            a.is_empty(),
            "every one of those must be refused, got {:?}",
            a.addrs
        );
        match &a.notes[0] {
            Note::Empty { unroutable, .. } => assert_eq!(*unroutable, 18),
            other => panic!("expected Empty, got {other:?}"),
        }
        assert!(lines(&a, b.backoff_ms())
            .iter()
            .any(|(l, m)| *l == LogLevel::Warn && m.contains("non-routable")));
    }

    #[test]
    fn routable_answers_accepted() {
        for a in [
            "5.6.7.7",
            "8.8.8.8",
            "1.1.1.1",
            "192.0.3.1",
            "9.9.9.9",
            "203.0.114.1",
        ] {
            assert!(is_routable(a.parse().unwrap()), "{a} should be dialable");
        }

        for a in [
            "198.17.255.255",
            "198.20.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "192.0.1.1",
        ] {
            assert!(
                is_routable(a.parse().unwrap()),
                "{a} is not reserved and must pass"
            );
        }
        for a in [
            "198.18.0.0",
            "198.19.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "192.0.0.1",
        ] {
            assert!(
                !is_routable(a.parse().unwrap()),
                "{a} is reserved and must not pass"
            );
        }
        assert!(is_routable("2606:4700::1111".parse().unwrap()));
        assert!(is_routable(
            "::ffff:5.6.7.7"
                .parse::<Ipv6Addr>()
                .map(IpAddr::V6)
                .unwrap()
        ));

        for a in ["203.0.113.1", "198.51.100.1", "192.0.2.1"] {
            assert!(
                !is_routable(a.parse().unwrap()),
                "{a} is documentation space"
            );
        }
    }

    #[test]
    fn config_literal_not_filtered() {
        let mut b = Bootstrap::new(&s(&["10.44.0.1:9256", "127.0.0.1:19256"]), P);
        let a = b.run(&Fake::default());
        assert_eq!(a.addrs.len(), 2);
        assert!(a.addrs.contains(&"10.44.0.1:9256".parse().unwrap()));
        assert!(a.addrs.contains(&"127.0.0.1:19256".parse().unwrap()));
    }

    #[test]
    fn one_seed_capped() {
        let many: Vec<String> = (1..=40).map(|i| format!("5.6.7.{i}:9256")).collect();
        let refs: Vec<&str> = many.iter().map(|x| x.as_str()).collect();
        let r = Fake::default().ok("greedy.example.net", &refs);
        let mut b = Bootstrap::new(&s(&["greedy.example.net"]), P);
        let a = b.run(&r);
        assert_eq!(a.addrs.len(), MAX_ADDRS_PER_SEED);
        match &a.notes[0] {
            Note::Resolved { kept, capped, .. } => {
                assert_eq!(*kept, MAX_ADDRS_PER_SEED);
                assert_eq!(*capped, 40 - MAX_ADDRS_PER_SEED);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_set_is_bounded() {
        let mut r = Fake::default();
        let mut names = Vec::new();
        for n in 0..10 {
            let host = format!("s{n}.example.net");
            let addrs: Vec<String> = (1..=8).map(|i| format!("203.0.{n}.{i}:9256")).collect();
            let refs: Vec<&str> = addrs.iter().map(|x| x.as_str()).collect();
            r = r.ok(&host, &refs);
            names.push(host);
        }
        let mut b = Bootstrap::new(&names, P);
        let a = b.run(&r);
        assert_eq!(a.addrs.len(), MAX_ADDRS_TOTAL);
    }

    #[test]
    fn dial_order_round_robin() {
        let r = Fake::default()
            .ok(
                "a.example.net",
                &["5.6.7.1:9256", "5.6.7.2:9256", "5.6.7.3:9256"],
            )
            .ok("b.example.net", &["9.9.9.1:9256", "9.9.9.2:9256"]);
        let mut b = Bootstrap::new(&s(&["a.example.net", "b.example.net"]), P);
        let a = b.run(&r);
        let ips: Vec<String> = a.addrs.iter().map(|x| x.ip().to_string()).collect();
        assert_eq!(
            ips,
            vec!["5.6.7.1", "9.9.9.1", "5.6.7.2", "9.9.9.2", "5.6.7.3"]
        );
        assert_eq!(a.groups(), 2);
    }

    #[test]
    fn duplicate_address_dialled_once() {
        let r = Fake::default()
            .ok("a.example.net", &["5.6.7.7:9256"])
            .ok("b.example.net", &["5.6.7.7:9256", "9.9.9.9:9256"]);
        let mut b = Bootstrap::new(&s(&["a.example.net", "b.example.net"]), P);
        let a = b.run(&r);
        assert_eq!(a.addrs.len(), 2);
    }

    #[test]
    fn single_group_is_warned() {
        let r = Fake::default()
            .ok("a.example.net", &["5.6.7.1:9256"])
            .ok("b.example.net", &["5.6.7.2:9256"]);
        let mut b = Bootstrap::new(&s(&["a.example.net", "b.example.net"]), P);
        let a = b.run(&r);
        assert_eq!(a.groups(), 1);
        assert!(lines(&a, b.backoff_ms())
            .iter()
            .any(|(l, m)| *l == LogLevel::Warn && m.contains("one /16")));
    }

    #[test]
    fn placeholder_seeds_not_dialled() {
        let r = Fake::default();
        let mut b = Bootstrap::new(
            &s(&[
                "seed1.main.placeholder-not-real.invalid",
                "seed2.main.placeholder-not-real.invalid",
            ]),
            P,
        );
        let a = b.run(&r);
        assert!(a.is_empty());
        assert_eq!(
            a.names_tried(),
            0,
            "a reserved TLD must not reach a resolver"
        );
        assert!(r.asked.borrow().is_empty(), "asked: {:?}", r.asked.borrow());
        assert!(b.is_hopeless());
        let text = lines(&a, b.backoff_ms());
        assert!(text.iter().any(|(l, m)| *l == LogLevel::Error
            && m.contains("build placeholder")
            && m.contains("RFC 6761")));
        assert!(text.iter().any(|(_, m)| m.contains("No seed addresses")));
    }

    #[test]
    fn shipped_tables_parse() {
        for host in embedded::SEEDS_MAIN.hosts.iter() {
            let seed = parse(host, P);
            assert!(
                matches!(
                    seed,
                    Seed::Host { .. } | Seed::Placeholder(_) | Seed::Literal(_)
                ),
                "{host} parsed as {seed:?}"
            );

            match seed {
                Seed::Host { port, .. } => assert_eq!(port, P),
                Seed::Literal(sa) => assert_eq!(sa.port(), P),
                _ => {}
            }
        }
    }

    #[test]
    fn bootstrap_uses_network_port() {
        let hosts: Vec<String> = embedded::SEEDS_MAIN
            .hosts
            .iter()
            .map(|h| h.to_string())
            .collect();
        let b = Bootstrap::new(&hosts, 19256);
        for seed in b.seeds() {
            match seed {
                Seed::Host { port, .. } => assert_eq!(*port, 19256),
                Seed::Literal(sa) => assert_eq!(sa.port(), 19256),
                Seed::Placeholder(_) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn empty_seed_list_is_hopeless() {
        let mut b = Bootstrap::new(&[], P);
        assert!(b.is_hopeless());
        assert_eq!(b.resolvable_names(), 0);
        let a = b.run(&Fake::default());
        assert!(a.is_empty());
        assert!(lines(&a, b.backoff_ms())
            .iter()
            .any(|(l, m)| *l == LogLevel::Warn && m.contains("No seed addresses")));
    }

    #[test]
    fn only_literals_need_no_resolver() {
        let r = Fake::default();
        let mut b = Bootstrap::new(&s(&["10.44.0.11:9256", "10.44.0.12:9256"]), P);
        assert_eq!(b.resolvable_names(), 0);
        assert!(!b.is_hopeless());
        let a = b.run(&r);
        b.record(!a.is_empty());
        assert_eq!(a.addrs.len(), 2);
        assert!(
            r.asked.borrow().is_empty(),
            "no name should have been looked up"
        );
        assert_eq!(b.failures(), 0);
    }

    #[test]
    fn literals_survive_dead_resolver() {
        let r = Fake::default();
        let mut b = Bootstrap::new(&s(&["10.44.0.11:9256", "seed1.example.net"]), P);
        let a = b.run(&r);
        b.record(!a.is_empty());
        assert_eq!(
            a.addrs,
            vec!["10.44.0.11:9256".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(b.failures(), 0, "a working literal is not a failed attempt");
    }

    #[test]
    fn every_failure_produces_a_line() {
        let cases: Vec<(&str, Vec<String>, Fake)> = vec![
            ("no resolution", s(&["a.example.net"]), Fake::default()),
            (
                "all answers non-routable",
                s(&["a.example.net"]),
                Fake::default().ok("a.example.net", &["127.0.0.1:9256"]),
            ),
            (
                "placeholder",
                s(&["x.main.placeholder-not-real.invalid"]),
                Fake::default(),
            ),
            ("malformed", s(&["http://x"]), Fake::default()),
            ("no seeds at all", Vec::new(), Fake::default()),
        ];
        for (name, seeds, r) in cases {
            let mut b = Bootstrap::new(&seeds, P);
            let a = b.run(&r);
            let text = lines(&a, b.backoff_ms());
            assert!(
                text.iter()
                    .any(|(l, _)| matches!(l, LogLevel::Warn | LogLevel::Error)),
                "{name}: produced no warning at all: {text:?}"
            );
        }
    }

    #[test]
    fn working_bootstrap_is_quiet() {
        let r = Fake::default()
            .ok("a.example.net", &["5.6.7.1:9256"])
            .ok("b.example.net", &["9.9.9.1:9256"]);
        let mut b = Bootstrap::new(&s(&["a.example.net", "b.example.net"]), P);
        let a = b.run(&r);
        let text = lines(&a, b.backoff_ms());
        assert!(
            !text
                .iter()
                .any(|(l, _)| matches!(l, LogLevel::Warn | LogLevel::Error)),
            "clean bootstrap warned: {text:?}"
        );
        assert!(text
            .iter()
            .any(|(_, m)| m.contains("2 address(es) from 2/2 seed name(s)")));
    }

    fn run_driver(
        d: &mut Driver,
        r: &dyn Resolve,
        peers: usize,
    ) -> (Vec<SocketAddr>, Vec<(LogLevel, String)>, u64) {
        let mut dialled = Vec::new();
        let mut said = Vec::new();
        let wait = d.step(r, peers, &mut |a| dialled.push(a), &mut |l, m| {
            said.push((l, m))
        });
        (dialled, said, wait)
    }

    #[test]
    fn address_dialled_at_most_once() {
        let r = Fake::default().ok("a.example.net", &["5.6.7.7:9256"]);
        let mut d = Driver::new(Bootstrap::new(&s(&["a.example.net"]), P));
        let (first, _, _) = run_driver(&mut d, &r, 0);
        assert_eq!(first.len(), 1);
        let (second, _, _) = run_driver(&mut d, &r, 0);
        assert!(second.is_empty(), "re-offered {second:?}");
        assert_eq!(d.offered(), 1);

        let moved = Fake::default().ok("a.example.net", &["5.6.7.7:9256", "9.9.9.9:9256"]);
        let (third, _, _) = run_driver(&mut d, &moved, 0);
        assert_eq!(third, vec!["9.9.9.9:9256".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn node_with_peers_skips_dns() {
        let r = Fake::default().ok("a.example.net", &["5.6.7.7:9256"]);
        let mut d = Driver::new(Bootstrap::new(&s(&["a.example.net"]), P));
        let (dialled, said, wait) = run_driver(&mut d, &r, 4);
        assert!(dialled.is_empty());
        assert!(said.is_empty(), "a healthy node must not narrate: {said:?}");
        assert_eq!(wait, SETTLED_POLL_MS);
        assert!(r.asked.borrow().is_empty(), "resolved while it had peers");
    }

    #[test]
    fn driver_uses_outbound_count() {
        let node_rs = include_str!("node.rs");
        assert!(
            node_rs.contains("&|| net.outbound_count(),"),
            "seeds::drive_with must be handed the OUTBOUND count: designation is \
             outbound-only, so a node with inbound peers only can sync from none of them"
        );

        let bad: Vec<&str> = node_rs
            .lines()
            .map(str::trim)
            .filter(|l| l.contains("&|| net.peer_count()") && !l.starts_with("//"))
            .collect();
        assert!(
            bad.is_empty(),
            "the total peer count is not the question: {bad:?}"
        );
    }

    #[test]
    fn inbound_only_keeps_resolving() {
        let r = Fake::default().ok("a.example.net", &["5.6.7.7:9256"]);
        let mut d = Driver::new(Bootstrap::new(&s(&["a.example.net"]), P));

        let (dialled, _said, wait) = run_driver(&mut d, &r, 0);
        assert!(
            !r.asked.borrow().is_empty(),
            "a node that can sync from nobody must ask DNS"
        );
        assert_eq!(dialled, vec!["5.6.7.7:9256".parse::<SocketAddr>().unwrap()]);
        assert_ne!(
            wait, SETTLED_POLL_MS,
            "it has not settled: it cannot reach anybody"
        );
    }

    #[test]
    fn losing_peers_restarts_ladder() {
        let mut d = Driver::new(Bootstrap::new(&s(&["a.example.net"]), P));
        for _ in 0..5 {
            run_driver(&mut d, &Fake::default(), 0);
        }
        let (_, _, long) = run_driver(&mut d, &Fake::default(), 0);
        assert_eq!(long, 600_000);
        run_driver(&mut d, &Fake::default(), 3);
        let (_, _, short) = run_driver(&mut d, &Fake::default(), 0);
        assert_eq!(short, BACKOFF_MS[0]);
    }

    #[test]
    fn loop_never_gives_up() {
        let mut d = Driver::new(Bootstrap::new(&s(&["a.example.net"]), P));
        let mut spoke = 0;
        for i in 0..20 {
            let (_, said, wait) = run_driver(&mut d, &Fake::default(), 0);
            assert!(wait > 0 && wait <= 600_000, "iteration {i}: wait {wait}");
            if said
                .iter()
                .any(|(l, _)| matches!(l, LogLevel::Warn | LogLevel::Error))
            {
                spoke += 1;
            }
        }

        assert_eq!(
            spoke, 1,
            "the answer never changed, so it should be said once"
        );
    }

    #[test]
    fn answer_said_once_unless_changed() {
        let r = Fake::default().ok("a.example.net", &["5.6.7.7:9256"]);
        let mut d = Driver::new(Bootstrap::new(&s(&["a.example.net"]), P));
        let (dialled, said, _) = run_driver(&mut d, &r, 0);
        assert_eq!(dialled.len(), 1);
        assert!(!said.is_empty(), "the first pass must always speak");
        for _ in 0..5 {
            let (dialled, said, _) = run_driver(&mut d, &r, 0);
            assert!(dialled.is_empty());
            assert!(said.is_empty(), "repeated the same answer: {said:?}");
        }

        let moved = Fake::default().ok("a.example.net", &["9.9.9.9:9256"]);
        let (dialled, said, _) = run_driver(&mut d, &moved, 0);
        assert_eq!(dialled, vec!["9.9.9.9:9256".parse::<SocketAddr>().unwrap()]);
        assert!(!said.is_empty(), "a changed answer must be reported");

        let (_, _, wait) = run_driver(&mut d, &moved, 0);
        assert_eq!(wait, BACKOFF_MS[0], "one stale pass is one rung");
        for _ in 0..6 {
            run_driver(&mut d, &moved, 0);
        }
        assert_eq!(
            wait_of(&mut d, &moved),
            600_000,
            "a stuck node must stop hammering DNS"
        );
    }

    fn wait_of(d: &mut Driver, r: &dyn Resolve) -> u64 {
        let (_, _, w) = run_driver(d, r, 0);
        w
    }

    #[test]
    fn interleave_bounded_keeps_order() {
        let a: Vec<SocketAddr> = (1..=3)
            .map(|i| format!("5.6.7.{i}:9256").parse().unwrap())
            .collect();
        let b: Vec<SocketAddr> = (1..=1)
            .map(|i| format!("9.9.9.{i}:9256").parse().unwrap())
            .collect();
        let out = interleave(vec![a.clone(), b.clone()], 100);
        assert_eq!(out, vec![a[0], b[0], a[1], a[2]]);
        assert_eq!(interleave(vec![a, b], 2).len(), 2);
        assert!(interleave(Vec::new(), 10).is_empty());
        assert!(interleave(vec![Vec::new(), Vec::new()], 10).is_empty());
    }
}
