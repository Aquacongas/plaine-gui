use std::panic::{catch_unwind, AssertUnwindSafe};

fn opaque<T>(v: T) -> T {
    std::hint::black_box(v)
}

#[test]
fn arithmetic_overflow_panics() {
    let u64_overflow = catch_unwind(AssertUnwindSafe(|| opaque(u64::MAX) + opaque(1u64)));
    assert!(
        u64_overflow.is_err(),
        "u64::MAX + 1 wrapped: overflow-checks is off for this build"
    );

    let u128_overflow = catch_unwind(AssertUnwindSafe(|| opaque(u128::MAX) + opaque(1u128)));
    assert!(
        u128_overflow.is_err(),
        "u128::MAX + 1 wrapped; u128 is the balance type, so a wrap is a mint"
    );

    let u128_underflow = catch_unwind(AssertUnwindSafe(|| opaque(0u128) - opaque(1u128)));
    assert!(
        u128_underflow.is_err(),
        "0u128 - 1 wrapped: a balance underflow becomes 3.4e38 PLNE"
    );
}

#[test]
fn flat_subsidy_constant_no_panic() {
    use plaine_consensus::constants::BLOCK_SUBSIDY;
    use plaine_consensus::emission::{block_reward, subsidy};

    for h in [0u64, 1, 43_200, 5_000_000, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
        if h == 0 {
            assert_eq!(subsidy(h), 0, "genesis pays nothing");
            assert_eq!(block_reward(h), 0);
        } else {
            assert_eq!(subsidy(h), BLOCK_SUBSIDY, "subsidy({h}) is flat");
            assert_eq!(block_reward(h), BLOCK_SUBSIDY, "block_reward({h}) is flat");
        }
    }
}
