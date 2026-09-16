use plaine_consensus::asert::{asert_next_bits, Target, POW_LIMIT};
use plaine_consensus::constants::{
    ASERT_HALF_LIFE_SECS, ASERT_TARGET_SPACING_SECS, GENESIS_BITS,
};
use plaine_wallet::genesis::{launch_window, LaunchWindow};

fn blocks_pinned_at_the_floor(late: i64, blocks: u64) -> u64 {
    let genesis_time: u64 = 1_800_000_000;
    let mut pinned = 0;
    for h in 1..=blocks {
        let parent_height = h - 1;
        let parent_time = if parent_height == 0 {
            genesis_time
        } else {
            (genesis_time as i64
                + late
                + ASERT_TARGET_SPACING_SECS * (parent_height as i64 - 1))
                as u64
        };
        let bits = asert_next_bits(
            GENESIS_BITS,
            0,
            genesis_time,
            parent_height,
            parent_time,
            &POW_LIMIT,
        )
        .expect("asert answers for a child of the genesis anchor");
        if bits == POW_LIMIT.to_compact() {
            pinned += 1;
        }
    }
    pinned
}

#[test]
fn late_genesis_pins_at_floor() {
    let on_time = blocks_pinned_at_the_floor(ASERT_TARGET_SPACING_SECS, 500);
    assert!(
        on_time < 100,
        "a punctual genesis must not pin the chain at the floor; {on_time}/500 blocks pinned"
    );

    for (late, label) in [
        (ASERT_HALF_LIFE_SECS, "one ASERT half-life"),
        (86_400, "one day"),
        (231 * 86_400, "231 days, the actual observed gap"),
    ] {
        let pinned = blocks_pinned_at_the_floor(late, 500);
        println!("{label} late ({late} s): {pinned}/500 blocks pinned at POW_LIMIT");

        assert_eq!(
            pinned, 499,
            "{label} late: expected 499 of 500 blocks pinned at POW_LIMIT, got {pinned}. \
             The offset does not decay, so the count does not vary with the size of the gap: if it does, the model is wrong."
        );
    }

    assert_eq!(
        GENESIS_BITS,
        POW_LIMIT.to_compact(),
        "GENESIS_BITS must equal POW_LIMIT"
    );

    assert!(
        Target::from_compact(GENESIS_BITS).unwrap() <= POW_LIMIT,
        "the expressible floor must not be easier than POW_LIMIT"
    );
}

#[test]
fn launch_window_is_one_half_life() {
    let now: u64 = 1_800_000_000;
    let hl = ASERT_HALF_LIFE_SECS as u64;

    for t in [now, now - hl, now + hl, now - hl + 1, now + hl - 1] {
        assert_eq!(
            launch_window(t, now),
            LaunchWindow::InWindow,
            "time {t} at now {now} must be inside the window"
        );
    }

    assert_eq!(
        launch_window(now - hl - 1, now),
        LaunchWindow::TooEarly { by_secs: hl + 1 }
    );
    assert_eq!(
        launch_window(now + hl + 1, now),
        LaunchWindow::TooLate { by_secs: hl + 1 }
    );

    let launch_gap = 231 * 86_400;
    assert_eq!(
        launch_window(now - launch_gap, now),
        LaunchWindow::TooEarly { by_secs: launch_gap }
    );

    assert!(matches!(launch_window(0, now), LaunchWindow::TooEarly { .. }));
}

#[test]
fn verdict_explains_itself_in_hash_rate() {
    let now: u64 = 1_800_000_000;
    let one_day_early = launch_window(now - 86_400, now);
    let text = one_day_early.explain();
    assert!(text.contains("86400"), "must name the gap in seconds: {text}");

    assert!(
        text.contains("24"),
        "must name the doublings of hash rate the gap costs: {text}"
    );
    assert!(
        text.contains("POW_LIMIT") || text.contains("floor"),
        "must name where the chain sits: {text}"
    );

    assert_eq!(launch_window(now, now).explain(), "");
}
