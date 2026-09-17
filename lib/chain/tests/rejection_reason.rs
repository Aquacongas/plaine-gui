mod support;

use plaine_chain::error::Reject;
use plaine_chain::mock::Scenario;
use plaine_consensus::codec::Header;
use plaine_consensus::constants::VERSION_BASE;
use support::*;

fn synced_rig() -> (Rig, Scenario) {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    assert_eq!(r.height(), 20);
    r.pow.reset();
    (r, chain)
}

fn submit_one(
    tweak: impl Fn(Header) -> Header,
) -> (plaine_chain::Accepted, plaine_chain::types::Hash32) {
    let (mut r, chain) = synced_rig();
    let parent = chain.tip();
    let bits = chain.expected_bits(parent.height);
    let hdr = tweak(Header {
        version: VERSION_BASE,
        height: parent.height + 1,
        prev_hash: parent.hash,
        tx_root: [7u8; 32],
        ext_root: [0u8; 32],
        time: parent.time + 60,
        bits,
        author_note_len: 0,
        nonce: 0,
    });
    let raw = hdr.encode();
    let hash = plaine_consensus::crypto::header_hash(&raw);
    let a = r.cm.submit_headers(9, &[raw]).expect("not halted");
    (a, hash)
}

fn case(name: &str, want: Reject, height: u64, tweak: impl Fn(Header) -> Header) {
    let (a, hash) = submit_one(tweak);
    assert_eq!(
        a.rejected, 1,
        "{name}: fixture - exactly one rejection expected"
    );
    let rej = a.first_rejection.unwrap_or_else(|| {
        panic!("{name}: rejected: 1 but first_rejection: None; the verdict is lost")
    });
    assert_eq!(
        rej.why,
        want.why(),
        "{name}: tagged {:?}, but this case fires {want:?}",
        rej.why
    );
    assert_eq!(
        rej.height, height,
        "{name}: attributed to height {}, expected {height}",
        rej.height
    );
    assert_eq!(
        rej.hash, hash,
        "{name}: the refusal named a different header than the one submitted"
    );

    let want_repair = match want {
        Reject::UnknownParent { .. } => height - 1,
        _ => height,
    };
    assert_eq!(
        rej.repair_from, want_repair,
        "{name}: the transport was told to repair from {}, expected {want_repair}",
        rej.repair_from
    );
}

#[test]
fn orphan_header_reports_missing_parent() {
    case(
        "unknown parent",
        Reject::UnknownParent { prev: [0u8; 32] },
        21,
        |mut h| {
            h.prev_hash = [0xab; 32];
            h
        },
    );
}

#[test]
fn wrong_difficulty_reported() {
    case(
        "bits",
        Reject::BitsNotAsert {
            got: 0,
            expected: 0,
        },
        21,
        |mut h| {
            h.bits = h.bits.wrapping_sub(1);
            h
        },
    );
}

#[test]
fn a_stale_timestamp_says_so() {
    case(
        "mtp",
        Reject::TimestampTooOld { mtp: 0, time: 0 },
        21,
        |mut h| {
            h.time = 1;
            h
        },
    );
}

#[test]
fn unparseable_header_named() {
    let (a, hash) = submit_one(|mut h| {
        h.ext_root = [1u8; 32];
        h
    });
    assert_eq!(a.rejected, 1);
    let rej = a.first_rejection.expect("a reason");
    assert_eq!(rej.why, Reject::ExtRootNotZero.why());
    assert_eq!(rej.hash, hash);
}

#[test]
fn connecting_batch_no_reason() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    let raws = chain.raw_headers_from(19);
    let a = r.cm.submit_headers(9, &raws[..1]).expect("not halted");
    assert_eq!(a.rejected, 0, "fixture: the control batch was refused");
    assert!(
        a.first_rejection.is_none(),
        "a batch that refused nothing still reported {:?}",
        a.first_rejection
    );
}

#[test]
fn only_first_refusal_reported() {
    let (mut r, chain) = synced_rig();
    let parent = chain.tip();
    let bits = chain.expected_bits(parent.height);
    let mk = |ext: u8, nonce: u32| {
        Header {
            version: VERSION_BASE,
            height: parent.height + 1,
            prev_hash: parent.hash,
            tx_root: [7u8; 32],
            ext_root: [ext; 32],
            time: parent.time + 60,
            bits,
            author_note_len: 0,
            nonce: nonce as u64,
        }
        .encode()
    };
    let first = mk(1, 0);
    let hash = plaine_consensus::crypto::header_hash(&first);
    let a =
        r.cm.submit_headers(9, &[first, mk(2, 1), mk(3, 2)])
            .expect("not halted");
    assert_eq!(
        a.rejected, 3,
        "fixture: all three were expected to be refused"
    );
    let rej = a.first_rejection.expect("a reason");
    assert_eq!(
        rej.hash, hash,
        "the first refusal is the break in a contiguous stream, not a later one"
    );
}

#[test]
fn every_reject_has_unique_tag() {
    let all = [
        Reject::BadHeaderLength { got: 0 },
        Reject::ExtRootNotZero,
        Reject::AuthorNoteLen { got: 0 },
        Reject::BadVersion { got: 0 },
        Reject::BadBits { got: 0 },
        Reject::CheckpointMismatch { height: 0 },
        Reject::UnknownParent { prev: [0u8; 32] },
        Reject::HeightNotParentPlusOne {
            got: 0,
            expected: 0,
        },
        Reject::BitsNotAsert {
            got: 0,
            expected: 0,
        },
        Reject::AsertAnchorUnavailable { height: 0 },
        Reject::TimestampTooOld { mtp: 0, time: 0 },
        Reject::TimestampTooFarInFuture { time: 0, limit: 0 },
        Reject::ForkTooDeep { depth: 0, cap: 0 },
        Reject::InsufficientClaimedWork,
        Reject::PowInvalid { hash: [0u8; 32] },
        Reject::BudgetExhausted { source: 0 },
        Reject::DuplicateFlood {
            source: 0,
            count: 0,
        },
        Reject::StagingFull { source: 0 },
        Reject::BatchTooLong { got: 0, cap: 0 },
        Reject::TooManySources { source: 0, cap: 0 },
        Reject::BodyNotAdmissible { hash: [0u8; 32] },
        Reject::BodyAlreadyHeld { hash: [0u8; 32] },
        Reject::BodyStructure { detail: "x" },
        Reject::TxRootMismatch,
        Reject::Tx {
            index: 0,
            err: plaine_consensus::tx::TxError::BadSignature,
        },
        Reject::BadTransferSignature { index: 0 },
        Reject::FeeBelowFloor { index: 0 },
        Reject::BadNonce {
            index: 0,
            expected: 0,
            got: 0,
        },
        Reject::InsufficientBalance {
            index: 0,
            need: 0,
            have: 0,
        },
        Reject::ArithmeticOverflow,
        Reject::Rule(plaine_consensus::rules::RuleError::EmptyCandidate),
        Reject::BranchInvalid {
            height: 0,
            hash: [0u8; 32],
            cause: Box::new(Reject::Busy),
        },
        Reject::ResyncRequired {
            fork_height: 0,
            replay_floor: 0,
        },
        Reject::Busy,
        Reject::SinkRefused { detail: "x" },
        Reject::Halted { detail: "x" },
        Reject::BootInvariant { detail: "x" },
        Reject::TxKnown,
        Reject::TxStale { next: 0, got: 0 },
        Reject::NonceGapTooLarge { next: 0, got: 0 },
        Reject::TxTypeNotRelayable { type_byte: 0 },
        Reject::BelowRelayFloor { fee: 0, floor: 0 },
        Reject::ReplacementUnderpriced { need: 0, got: 0 },
        Reject::PoolFull,
        Reject::SenderCap { cap: 0 },
        Reject::TxDecode,
        Reject::TxTooLarge { got: 0 },
    ];
    let mut seen: Vec<(&'static str, String)> = Vec::new();
    for r in &all {
        let w = r.why();
        assert!(!w.is_empty(), "{r:?} has an empty tag");
        if let Some((other, _)) = seen.iter().find(|(t, _)| *t == w) {
            panic!("{r:?} and {other:?} share the tag {w:?}; every gate needs a distinct one");
        }
        seen.push((w, format!("{r:?}")));
    }
    assert!(
        seen.len() >= 40,
        "only {} variants were listed; the enum has more, and a variant nobody \
         listed is one whose tag can be anything",
        seen.len()
    );
}

#[test]
fn late_dropped_header_named() {
    let p = params();
    let chain = Scenario::genesis(&p, T0).extend(20);
    let mut r = Rig::new(&chain, p);
    r.sync(&chain, 1);
    assert_eq!(r.height(), 20);

    let mut fork = chain.fork_at(20);
    fork.push_block(&[]);
    fork.push_block(&[]);
    let raws = fork.raw_headers_from(21);
    assert_eq!(raws.len(), 2, "fixture: two headers expected");
    let first = plaine_consensus::crypto::header_hash(&raws[0]);
    r.pow.reset();
    r.pow.set_mode(plaine_chain::mock::PowMode::AllButListed);
    r.pow.reject_hash(first);

    let a = r.cm.submit_headers(9, &raws).expect("not halted");
    assert_eq!(a.connected, 0, "fixture: nothing may have connected");

    assert_eq!(a.rejected, 0);
    assert_eq!(a.duplicates, 0);
    assert_eq!(a.staged, 0);
    let rej = a.first_rejection.expect(
        "two staged headers drained with every counter at zero must still report the break",
    );
    assert_eq!(
        rej.hash, first,
        "the break is the header that failed, not its child"
    );
    assert_eq!(rej.height, 21);
    assert_eq!(
        rej.repair_from, 21,
        "a header whose own proof of work failed is the break; nothing below it is implicated"
    );
    assert_eq!(
        rej.why,
        plaine_chain::error::Reject::PowInvalid { hash: first }.why()
    );
}
