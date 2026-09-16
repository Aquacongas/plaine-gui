use crate::constants::BLOCK_SUBSIDY;

pub fn subsidy(height: u64) -> u128 {
    if height == 0 {
        0
    } else {
        BLOCK_SUBSIDY
    }
}

pub fn block_reward(height: u64) -> u128 {
    subsidy(height)
}

pub fn cumulative_issued(height: u64) -> u128 {
    height.saturating_sub(1) as u128 * BLOCK_SUBSIDY
}

pub fn issued_through(height: u64) -> u128 {
    height as u128 * BLOCK_SUBSIDY
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BLOCKS_PER_YEAR, MILE_PER_PLNE};

    #[test]
    fn genesis_pays_nothing_every_other_block_pays_the_flat_subsidy() {
        assert_eq!(block_reward(0), 0);
        assert_eq!(subsidy(0), 0);
        for h in [1u64, 2, 100, 43_200, 5_000_000, 100_000_000, u64::MAX] {
            assert_eq!(block_reward(h), BLOCK_SUBSIDY, "at {h}");
            assert_eq!(subsidy(h), BLOCK_SUBSIDY, "at {h}");
        }
    }

    #[test]
    fn the_subsidy_is_two_tenths_of_a_plne() {
        assert_eq!(BLOCK_SUBSIDY, 200_000);
        assert_eq!(BLOCK_SUBSIDY * 5, MILE_PER_PLNE);
    }

    #[test]
    fn one_million_plne_by_block_five_million_and_no_cap_after() {
        assert_eq!(issued_through(5_000_000), 1_000_000 * MILE_PER_PLNE);

        assert_eq!(issued_through(10_000_000), 2_000_000 * MILE_PER_PLNE);
        assert_eq!(issued_through(15_000_000), 3_000_000 * MILE_PER_PLNE);
    }

    #[test]
    fn year_one_emission_is_105_192_plne() {
        assert_eq!(issued_through(BLOCKS_PER_YEAR), 105_192 * MILE_PER_PLNE);
    }

    #[test]
    fn cumulative_and_subsidy_agree_at_every_boundary() {
        for h in [0u64, 1, 2, 100, 43_200, 5_000_000, 100_000_000] {
            assert_eq!(
                cumulative_issued(h + 1) - cumulative_issued(h),
                subsidy(h),
                "at height {h}"
            );
        }

        for h in [0u64, 1, 5_000_000, u64::MAX - 1] {
            assert_eq!(issued_through(h), cumulative_issued(h + 1), "at {h}");
        }
    }

    #[test]
    fn no_overflow_or_panic_at_the_extremes() {
        let _ = issued_through(u64::MAX);
        let _ = cumulative_issued(u64::MAX);
        assert_eq!(block_reward(u64::MAX), BLOCK_SUBSIDY);
        assert_eq!(cumulative_issued(0), 0);
        assert_eq!(issued_through(0), 0);
    }
}
