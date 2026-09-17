mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use plaine_chain::checkpoints::{CheckpointOutcome, CheckpointReport};
use plaine_chain::mock::Scenario;
use plaine_chain::Progress;
use plaine_consensus::rules::{CheckpointSig, SignedCheckpoint};
use support::*;

const CHECKPOINT_SIGS_MAX: usize = 15;

const CAP_CHECKPOINT: usize = 1_016;

const CAP: u64 = plaine_consensus::constants::MAX_REORG_DEPTH;
const HONEST_TIP: u64 = CAP * 2;

fn honest_chain() -> Scenario {
    Scenario::genesis(&params(), T0).extend(HONEST_TIP)
}

fn rig_on(chain: &Scenario) -> Rig {
    let p = params();
    let mut r = Rig::new(chain, p);
    r.sync(chain, 1);
    r
}

fn branch_at_depth(honest: &Scenario, depth: u64) -> Scenario {
    honest.fork_at(HONEST_TIP - depth).spacing(1).extend(depth)
}

fn refused() -> Option<CheckpointReport> {
    Some(CheckpointReport {
        outcome: CheckpointOutcome::Unverified,
        anchor_advanced: false,
    })
}

fn sign_with(sk: &ed25519_dalek::SigningKey, height: u64, hash: &[u8; 32]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let msg = plaine_consensus::rules::checkpoint_message(height, hash);
    sk.sign(&msg).to_bytes()
}

fn encode_frame(height: u64, hash: &[u8; 32], sigs: &[(u8, [u8; 64])]) -> Vec<u8> {
    let mut o = Vec::with_capacity(8 + 32 + 1 + sigs.len() * 65);
    o.extend_from_slice(&height.to_le_bytes());
    o.extend_from_slice(hash);
    o.push(sigs.len() as u8);
    for (id, sig) in sigs {
        o.push(*id);
        o.extend_from_slice(sig);
    }
    o
}

fn decode_frame(buf: &[u8], authority_keys: &[[u8; 32]]) -> Option<SignedCheckpoint> {
    if buf.len() < 41 {
        return None;
    }
    let height = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let hash: [u8; 32] = buf[8..40].try_into().ok()?;
    let n = buf[40] as usize;
    if n > CHECKPOINT_SIGS_MAX || buf.len() != 41 + n * 65 {
        return None;
    }
    let mut sigs = Vec::with_capacity(n);
    for i in 0..n {
        let at = 41 + i * 65;
        let key_id = buf[at] as usize;
        let sig: [u8; 64] = buf[at + 1..at + 65].try_into().ok()?;
        match authority_keys.get(key_id) {
            Some(pubkey) => sigs.push(CheckpointSig {
                pubkey: *pubkey,
                sig,
            }),
            None => continue,
        }
    }
    Some(SignedCheckpoint { height, hash, sigs })
}

fn deliver_over_a_socket(r: &mut Rig, frame: &[u8]) -> Option<CheckpointReport> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let addr = listener.local_addr().expect("bound addr");
    let owned = frame.to_vec();
    let sender = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.write_all(&owned).expect("write frame");
        s.flush().expect("flush");
    });

    let (mut sock, _peer) = listener.accept().expect("accept");
    let mut got = Vec::new();
    sock.read_to_end(&mut got).expect("read frame");
    sender.join().expect("sender thread");

    assert_eq!(
        got, frame,
        "the bytes that arrived are the bytes that were sent"
    );

    let keys = params().authority_keys;
    let cp = decode_frame(&got, &keys)?;
    Some(
        r.cm.submit_checkpoint(&cp)
            .expect("submit_checkpoint never errors"),
    )
}

#[test]
fn signed_checkpoint_admits_deep_reorg() {
    let honest = honest_chain();
    let depth = CAP + 1;
    let base = HONEST_TIP - depth;
    let attacker = branch_at_depth(&honest, depth);

    let anchored = attacker.blocks[(base + depth / 2) as usize].rec;
    assert!(
        anchored.height > base,
        "the anchor must sit inside the branch"
    );

    let mut control = rig_on(&honest);
    let a = control.offer(7, &blocks_above(&attacker, base));
    assert_eq!(
        a.connected, 0,
        "without an anchor the cheap gate refuses the branch"
    );
    assert!(matches!(
        control.cm.advance().expect("not halted"),
        Progress::NoChange
    ));
    assert_eq!(control.height(), HONEST_TIP);

    let mut r = rig_on(&honest);
    assert!(
        r.cm.anchor().is_none(),
        "premise: no anchor before the frame arrives"
    );

    let sig = sign_with(&authority_key(), anchored.height, &anchored.hash);
    let frame = encode_frame(anchored.height, &anchored.hash, &[(0u8, sig)]);
    assert_eq!(
        frame.len(),
        8 + 32 + 1 + 65,
        "one signature is a 106-byte frame"
    );

    let outcome = deliver_over_a_socket(&mut r, &frame).expect("the frame decodes");

    assert_eq!(outcome.outcome, CheckpointOutcome::StoredAsAnchor);
    assert!(outcome.anchor_advanced, "a first anchor is an advance");
    assert_eq!(
        r.cm.anchor().map(|a| (a.height, a.hash)),
        Some((anchored.height, anchored.hash))
    );
    assert!(
        r.cm.checkpoints().is_empty(),
        "a contradicted height never enters enforcement"
    );

    let a = r.offer(7, &blocks_above(&attacker, base));
    assert_eq!(a.connected, depth, "the anchor relaxes the ingest gate");
    match r.cm.advance().expect("the anchor admits the deep reorg") {
        Progress::Advanced {
            tip, rolled_back, ..
        } => {
            assert_eq!(rolled_back, depth);
            assert_eq!(tip.hash, attacker.tip().hash);
        }
        other => panic!("expected adoption, got {other:?}"),
    }
}

#[test]
fn unsigned_checkpoint_refused() {
    let honest = honest_chain();
    let depth = CAP + 1;
    let base = HONEST_TIP - depth;
    let attacker = branch_at_depth(&honest, depth);
    let anchored = attacker.blocks[(base + depth / 2) as usize].rec;

    let mut r = rig_on(&honest);

    let forged = sign_with(&impostor_key(), anchored.height, &anchored.hash);
    let frame = encode_frame(anchored.height, &anchored.hash, &[(0u8, forged)]);
    assert_eq!(
        deliver_over_a_socket(&mut r, &frame),
        refused(),
        "a signature from a key we do not trust must not become an anchor"
    );
    assert!(r.cm.anchor().is_none());

    let unsigned = encode_frame(anchored.height, &anchored.hash, &[(0u8, [0u8; 64])]);
    assert_eq!(deliver_over_a_socket(&mut r, &unsigned), refused());
    assert!(r.cm.anchor().is_none());

    let lifted = sign_with(&authority_key(), anchored.height + 1, &anchored.hash);
    let moved = encode_frame(anchored.height, &anchored.hash, &[(0u8, lifted)]);
    assert_eq!(deliver_over_a_socket(&mut r, &moved), refused());
    assert!(r.cm.anchor().is_none());

    let no_such_key = encode_frame(anchored.height, &anchored.hash, &[(7u8, [0u8; 64])]);
    assert_eq!(deliver_over_a_socket(&mut r, &no_such_key), refused());
    assert!(r.cm.anchor().is_none());

    let a = r.offer(7, &blocks_above(&attacker, base));
    assert_eq!(a.connected, 0);
    assert!(matches!(
        r.cm.advance().expect("not halted"),
        Progress::NoChange
    ));
    assert_eq!(
        r.height(),
        HONEST_TIP,
        "an unsigned deep reorg never moves the tip"
    );
}

#[test]
fn oversized_frame_refused() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);

    let hash = honest.blocks[10].rec.hash;
    let sigs: Vec<(u8, [u8; 64])> = (0..CHECKPOINT_SIGS_MAX as u8)
        .map(|i| (0u8, [i ^ 0xA5; 64]))
        .collect();
    let frame = encode_frame(10, &hash, &sigs);
    assert_eq!(
        frame.len(),
        CAP_CHECKPOINT,
        "this is the biggest checkpoint the wire admits, and it is what the cost is per"
    );

    assert_eq!(deliver_over_a_socket(&mut r, &frame), refused());
    assert!(r.cm.anchor().is_none());
    assert!(r.cm.checkpoints().is_empty());

    let good = sign_with(&authority_key(), 10, &hash);
    let honest_frame = encode_frame(10, &hash, &[(0u8, good)]);
    assert_eq!(
        deliver_over_a_socket(&mut r, &honest_frame),
        Some(CheckpointReport {
            outcome: CheckpointOutcome::Admitted,
            anchor_advanced: true
        }),
        "the honest one-signature frame at a height we hold enters the enforcement map"
    );
    assert_eq!(r.cm.checkpoints(), vec![(10, hash)]);
}

#[test]
fn replayed_checkpoint_not_an_advance() {
    let honest = honest_chain();
    let mut r = rig_on(&honest);

    let framed = |height: u64, hash: &[u8; 32]| {
        encode_frame(
            height,
            hash,
            &[(0u8, sign_with(&authority_key(), height, hash))],
        )
    };

    let h20 = honest.blocks[20].rec.hash;
    let h10 = honest.blocks[10].rec.hash;

    assert_eq!(
        deliver_over_a_socket(&mut r, &framed(20, &h20)),
        Some(CheckpointReport {
            outcome: CheckpointOutcome::Admitted,
            anchor_advanced: true
        })
    );
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(20));

    assert_eq!(
        deliver_over_a_socket(&mut r, &framed(20, &h20)),
        Some(CheckpointReport {
            outcome: CheckpointOutcome::Admitted,
            anchor_advanced: false
        }),
        "a replay enters the same map entry again, and the anchor does not move"
    );
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(20));

    assert_eq!(
        deliver_over_a_socket(&mut r, &framed(10, &h10)),
        Some(CheckpointReport {
            outcome: CheckpointOutcome::Admitted,
            anchor_advanced: false
        })
    );
    assert_eq!(
        r.cm.anchor().map(|a| a.height),
        Some(20),
        "the anchor is monotone in height"
    );

    let h25 = honest.blocks[25].rec.hash;
    assert_eq!(
        deliver_over_a_socket(&mut r, &framed(25, &h25)),
        Some(CheckpointReport {
            outcome: CheckpointOutcome::Admitted,
            anchor_advanced: true
        })
    );
    assert_eq!(r.cm.anchor().map(|a| a.height), Some(25));
}
