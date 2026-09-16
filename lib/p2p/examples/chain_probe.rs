use plaine_p2p::constants::*;
use plaine_p2p::wire::codec::{decode, encode};
use plaine_p2p::wire::frame::{encode_frame, FrameReader};
use plaine_p2p::wire::msg::{Hello, Msg};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn arg(name: &str, def: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned().unwrap_or_else(|| def.to_string());
        }
    }
    def.to_string()
}

fn four(s: &str) -> [u8; 4] {
    let b = s.as_bytes();
    assert!(b.len() == 4, "a chain id is exactly four bytes, got {:?}", s);
    [b[0], b[1], b[2], b[3]]
}

fn main() {
    let to: SocketAddr = arg("--to", "127.0.0.1:9256").parse().expect("--to");
    let magic = match arg("--magic", "main").as_str() {
        "main" => MAGIC_MAIN,
        "foreign" => FOREIGN_MAGIC,
        other => panic!("--magic is main or foreign, got {other}"),
    };

    let claim = four(&arg("--claim", "PLNE"));
    let wait_ms: u64 = arg("--wait-ms", "3000").parse().expect("--wait-ms");

    let mut sock = match TcpStream::connect_timeout(&to, Duration::from_millis(wait_ms)) {
        Ok(s) => s,
        Err(e) => {
            println!("PROBE to={to} result=NO_CONNECT err={e}");
            return;
        }
    };
    sock.set_read_timeout(Some(Duration::from_millis(wait_ms))).expect("timeout");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let hello = Msg::Hello(Hello {
        proto_ver: PROTO_VER,
        min_proto: MIN_PROTO,
        chain_id: claim,
        services: 0,
        nonce: 0xC0FF_EE00_0000_0000 ^ now,
        time: now,
        height: 0,
        tip_hash: [0u8; 32],
        cum_work: [0u8; 32],
        listen_port: 0,
        user_agent: b"plaine-chain-probe".to_vec(),
    });
    let frame = encode_frame(&magic, hello.cmd(), &encode(&hello));
    if let Err(e) = sock.write_all(&frame) {
        println!("PROBE to={to} result=NO_WRITE err={e}");
        return;
    }

    let mut reader = FrameReader::new(magic);
    let mut buf = [0u8; 4096];
    let mut theirs: Option<Hello> = None;
    let mut acked = false;
    let mut frames = 0usize;
    let mut closed = false;
    loop {
        match sock.read(&mut buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => {
                let got = match reader.push(&buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        println!("PROBE to={to} result=BAD_FRAME err={e:?}");
                        return;
                    }
                };
                for (cmd, payload) in got {
                    frames += 1;
                    match decode(cmd, &payload) {
                        Ok(Msg::Hello(h)) => {
                            let ack = encode_frame(&magic, plaine_p2p::wire::cmd::Cmd::HelloAck, &[]);
                            let _ = sock.write_all(&ack);
                            theirs = Some(h);
                        }
                        Ok(Msg::HelloAck) => acked = true,
                        _ => {}
                    }
                }
                if theirs.is_some() && acked {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let their_id = theirs
        .as_ref()
        .map(|h| String::from_utf8_lossy(&h.chain_id).into_owned())
        .unwrap_or_else(|| "-".to_string());
    let their_height = theirs.as_ref().map(|h| h.height).unwrap_or(0);
    let their_ua = theirs
        .as_ref()
        .map(|h| String::from_utf8_lossy(&h.user_agent).into_owned())
        .unwrap_or_default();
    let result = if acked {
        "ACK"
    } else if frames == 0 {
        "NO_FRAMES"
    } else if closed {
        "CLOSED"
    } else {
        "TIMEOUT"
    };
    println!(
        "PROBE to={to} magic={} claimed={} result={result} THEIRS chain_id={their_id} \
         height={their_height} ua={their_ua} frames={frames}",
        String::from_utf8_lossy(&magic).escape_debug(),
        String::from_utf8_lossy(&claim),
    );
}
