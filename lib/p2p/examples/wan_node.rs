use plaine_p2p::config::P2pConfig;
use plaine_p2p::constants::HEADER_BYTES;
use plaine_p2p::mock::{MockBits, MockChain};
use plaine_p2p::net::{NetNode, NetOptions, SystemClock, TickMode};
use plaine_p2p::sync::SyncEngine;
use plaine_p2p::traits::{BlockSink, ChainView, Clock, Hash32, PowVerifier};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct BurnPow {
    cost_ms: u64,
    calls: AtomicU64,
}

impl BurnPow {
    fn new(cost_ms: u64) -> BurnPow {
        BurnPow {
            cost_ms,
            calls: AtomicU64::new(0),
        }
    }
}

impl PowVerifier for BurnPow {
    fn verify(&self, _hdr: &[u8; HEADER_BYTES]) -> bool {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.cost_ms > 0 {
            let until = Instant::now() + Duration::from_micros(self.cost_ms * 1000);

            let mut x = 0u64;
            while Instant::now() < until {
                for _ in 0..512 {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                }
            }
            std::hint::black_box(x);
        }
        true
    }
    fn cost_ms(&self) -> u64 {
        self.cost_ms
    }
}

type Engine = SyncEngine<MockChain, MockChain, BurnPow, MockBits>;

fn arg(name: &str, def: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned().unwrap_or_else(|| def.to_string());
        }
    }
    def.to_string()
}

fn hexs(h: &Hash32) -> String {
    h.iter().take(6).map(|b| format!("{:02x}", b)).collect()
}

fn seed_real_bodies(chain: &MockChain) {
    for h in chain.headers() {
        let mut b = h.raw.to_vec();
        b.extend_from_slice(&0u32.to_le_bytes());
        let _ = BlockSink::submit_block(chain, h.hash, b);
    }
}

fn main() {
    let name = arg("--name", "node");
    let listen: SocketAddr = arg("--listen", "127.0.0.1:9000").parse().expect("--listen");
    let blocks: u64 = arg("--blocks", "1").parse().expect("--blocks");
    let base_time: u64 = arg("--base-time", "0").parse().expect("--base-time");
    let cost_ms: u64 = arg("--pow-ms", "1").parse().expect("--pow-ms");
    let workers: usize = arg("--workers", "4").parse().expect("--workers");
    let run_secs: u64 = arg("--run-secs", "120").parse().expect("--run-secs");
    let status_ms: u64 = arg("--status-ms", "1000").parse().expect("--status-ms");
    let want: u64 = arg("--want", "0").parse().expect("--want");
    let dials = arg("--dial", "");

    let dial_file = arg("--dial-file", "");

    let base_time = if base_time == 0 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            - blocks.max(1) * 60
    } else {
        base_time
    };

    let chain = Arc::new(MockChain::linear(blocks, base_time, 1));
    seed_real_bodies(&chain);
    let pow = Arc::new(BurnPow::new(cost_ms));
    let bits = Arc::new(MockBits);
    let clock: Arc<SystemClock> = Arc::new(SystemClock::new());

    let gossip = arg("--gossip", "0") != "0";
    let chain_id_arg = arg("--chain-id", "");
    let cfg = P2pConfig {
        isolated: !gossip,
        accept_local_addrs: gossip,
        chain_id: if chain_id_arg.len() == 4 {
            let b = chain_id_arg.as_bytes();
            [b[0], b[1], b[2], b[3]]
        } else {
            P2pConfig::default().chain_id
        },
        ..P2pConfig::default()
    };

    let engine = SyncEngine::new(
        Arc::clone(&chain),
        Arc::clone(&chain),
        Arc::clone(&pow),
        bits,
        cfg.clone(),
        0xC0FFEE ^ blocks,
        clock.mono(),
    );

    let node: NetNode<Engine> = NetNode::start(
        engine,
        Arc::clone(&chain),
        cfg,
        Arc::clone(&clock) as Arc<dyn Clock>,
        NetOptions {
            listen,
            ticks: TickMode::Auto,
            workers,
        },
    )
    .expect("start node");

    println!(
        "START name={} listen={} blocks={} base_time={} pow_ms={} tip={} genesis={}",
        name,
        node.local_addr(),
        blocks,
        base_time,
        cost_ms,
        chain.tip().height,
        hexs(&chain.header_at(0).expect("genesis").hash)
    );

    for d in dials.split(',').filter(|s| !s.is_empty()) {
        match d.parse::<SocketAddr>() {
            Ok(a) => {
                node.dial(a);
                println!("DIAL {}", a);
            }
            Err(e) => println!("DIAL_BAD {} {}", d, e),
        }
    }

    let t0 = Instant::now();
    let mut converged_at: Option<f64> = None;
    let mut last_cond = 0usize;
    let mut seen_dials: Vec<String> = Vec::new();
    while t0.elapsed() < Duration::from_secs(run_secs) {
        std::thread::sleep(Duration::from_millis(status_ms));
        let tip = chain.tip();
        let el = t0.elapsed().as_secs_f64();
        if !dial_file.is_empty() {
            if let Ok(txt) = std::fs::read_to_string(&dial_file) {
                for l in txt.lines() {
                    let l = l.trim();
                    if l.is_empty() || seen_dials.iter().any(|s| s == l) {
                        continue;
                    }
                    seen_dials.push(l.to_string());
                    match l.parse::<SocketAddr>() {
                        Ok(a) => {
                            node.dial(a);
                            println!("DIAL t={:.1} {}", el, a);
                        }
                        Err(e) => println!("DIAL_BAD {} {}", l, e),
                    }
                }
            }
        }
        let conds = node.conditions();
        if conds.len() > last_cond {
            for c in conds.iter().skip(last_cond) {
                println!("COND t={:.1} {:?}", el, c);
            }
            last_cond = conds.len();
        }

        let net = node.net();
        let out: Vec<String> = node
            .peer_rows()
            .iter()
            .filter(|r| r.outbound)
            .map(|r| {
                format!(
                    "{}.{}.{}.{}:{}",
                    r.ip[12], r.ip[13], r.ip[14], r.ip[15], r.port
                )
            })
            .collect();
        println!(
            "STAT name={} t={:.1} height={} tip={} peers={} out={} in={} \
             addrs={} learned={} filtered={} overquota={} getaddr_ans={} \
             fd={} pow_calls={} hdrs={} bodies={} acts={} conds={} peers_out=[{}]",
            name,
            el,
            tip.height,
            hexs(&tip.hash),
            node.peer_count(),
            node.outbound_count(),
            node.inbound_count(),
            net.addr_count(),
            net.addrs_learned.load(Ordering::Relaxed),
            net.addrs_filtered.load(Ordering::Relaxed),
            net.addrs_over_quota.load(Ordering::Relaxed),
            net.getaddr_answered.load(Ordering::Relaxed),
            node.fd().total_open(),
            pow.calls.load(Ordering::Relaxed),
            chain.accepted_headers(),
            chain.accepted_blocks(),
            node.actions().len(),
            conds.len(),
            out.join(",")
        );
        if want > 0 && converged_at.is_none() && tip.height >= want {
            converged_at = Some(el);
            println!(
                "CONVERGED name={} t={:.1} height={} tip={}",
                name,
                el,
                tip.height,
                hexs(&tip.hash)
            );
        }
    }

    let tip = chain.tip();
    println!(
        "FINAL name={} height={} tip={} peers={} fd={} pow_calls={} hdrs={} \
         bodies={} converged_at={:?}",
        name,
        tip.height,
        hexs(&tip.hash),
        node.peer_count(),
        node.fd().total_open(),
        pow.calls.load(Ordering::Relaxed),
        chain.accepted_headers(),
        chain.accepted_blocks(),
        converged_at
    );

    {
        let am = node.net().addrs.lock().expect("addrs");
        let mut rows: Vec<String> = am
            .entries()
            .iter()
            .map(|e| {
                format!(
                    "{}.{}.{}.{}:{}/{}{}",
                    e.ip[12],
                    e.ip[13],
                    e.ip[14],
                    e.ip[15],
                    e.port,
                    if e.table == plaine_p2p::addr::Table::Tried {
                        "T"
                    } else {
                        "N"
                    },
                    if e.from_seed { "*" } else { "" }
                )
            })
            .collect();
        rows.sort();
        println!("BOOK name={} n={} [{}]", name, rows.len(), rows.join(" "));
    }
    let acts = node.actions();
    let mut kinds: Vec<(String, usize)> = Vec::new();
    for a in &acts {
        let k = format!("{:?}", a);
        let k = k.split(['(', ' ', '{']).next().unwrap_or("?").to_string();
        match kinds.iter_mut().find(|(n, _)| *n == k) {
            Some((_, c)) => *c += 1,
            None => kinds.push((k, 1)),
        }
    }
    println!("ACTIONS name={} total={} {:?}", name, acts.len(), kinds);
    let fd = Arc::clone(node.fd());
    node.shutdown();
    println!("SHUTDOWN name={} fd_after={}", name, fd.total_open());
}
