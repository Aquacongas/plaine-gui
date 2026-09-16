use plaine_chain::gates;
use plaine_p2p::gate::{check_context, BitsRule, ContextParams, Rejection};
use plaine_p2p::traits::{HeaderRec, Hash32};

const TIMES_51_TO_61: [u64; 11] = [
    1_786_573_454,
    1_786_573_463,
    1_786_573_467,
    1_786_573_484,
    1_786_573_486,
    1_786_573_489,
    1_786_573_496,
    1_786_573_542,
    1_786_573_571,
    1_786_573_573,
    1_786_573_587,
];

const CHILD_TIME: u64 = 1_786_573_587;

struct AnyBits;
impl BitsRule for AnyBits {
    fn expected_bits(&self, _parent: &HeaderRec) -> Option<u32> {
        None
    }
    fn expand(&self, _bits: u32) -> Option<Hash32> {
        Some([0xff; 32])
    }
}

fn rec(height: u64, hash: Hash32, prev: Hash32, time: u64) -> HeaderRec {
    HeaderRec {
        height,
        hash,
        prev_hash: prev,
        time,
        bits: plaine_consensus::constants::GENESIS_BITS,
        target: [0xff; 32],
        raw: [0u8; plaine_consensus::constants::HEADER_BYTES],
    }
}

#[test]
fn same_second_block_accepted() {
    let now = CHILD_TIME + 5;
    assert_eq!(
        gates::s4_time(&TIMES_51_TO_61, CHILD_TIME, now),
        Ok(()),
        "a block whose timestamp equals its parent's is legal: MTP is the \
         median of ELEVEN ancestors, not the parent's own timestamp"
    );
}

#[test]
fn p2p_admits_the_same_second_block_when_it_cannot_establish_an_mtp() {
    let parent = rec(61, [1u8; 32], [0u8; 32], TIMES_51_TO_61[10]);
    let mut child = rec(62, [2u8; 32], parent.hash, CHILD_TIME);
    let params = ContextParams {
        now_unix: CHILD_TIME + 5,
        mtp: None,
        fork_depth: 0,
        branch_contains_anchor: false,
    };
    assert_eq!(
        check_context(&AnyBits, &parent, &mut child, &params),
        Ok(()),
        "with no establishable MTP the gate must DECLINE to judge, not guess: \
         guessing bans the only honest peer on the first batch"
    );

    let mut child2 = rec(62, [2u8; 32], parent.hash, CHILD_TIME);
    let fallback = ContextParams { mtp: Some(parent.time), ..params };
    assert_eq!(
        check_context(&AnyBits, &parent, &mut child2, &fallback),
        Err(Rejection::TimePast),
        "`Some(parent.time)` is the old fallback spelled differently; it must \
         never be what a caller reaches for when the window is short"
    );

    assert_eq!(
        Rejection::TimePast.offence(),
        Some(plaine_p2p::peer::score::Offence::BadTimePast),
        "TimePast bans; that is why the gate may not guess"
    );
}

#[test]
fn same_header_passes_with_window() {
    let parent = rec(61, [1u8; 32], [0u8; 32], TIMES_51_TO_61[10]);
    let mut child = rec(62, [2u8; 32], parent.hash, CHILD_TIME);
    let real_mtp = plaine_consensus::rules::median_time_past(&TIMES_51_TO_61);
    assert!(
        real_mtp < parent.time,
        "the real MTP sits several blocks back, which is the whole point"
    );
    let params = ContextParams {
        now_unix: CHILD_TIME + 5,
        mtp: Some(real_mtp),
        fork_depth: 0,
        branch_contains_anchor: false,
    };
    assert_eq!(check_context(&AnyBits, &parent, &mut child, &params), Ok(()));
}

#[test]
fn later_block_unaffected() {
    let parent = rec(61, [1u8; 32], [0u8; 32], TIMES_51_TO_61[10]);
    let mut child = rec(62, [2u8; 32], parent.hash, CHILD_TIME + 1);
    let params = ContextParams {
        now_unix: CHILD_TIME + 10,
        mtp: Some(parent.time),
        fork_depth: 0,
        branch_contains_anchor: false,
    };
    assert_eq!(check_context(&AnyBits, &parent, &mut child, &params), Ok(()));
    assert_eq!(gates::s4_time(&TIMES_51_TO_61, CHILD_TIME + 1, CHILD_TIME + 10), Ok(()));
}
