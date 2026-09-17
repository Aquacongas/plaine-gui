use plaine_consensus::constants::{
    BLOCK_TIME_SECS, MAX_FUTURE_DRIFT_SECS, MAX_REORG_DEPTH, MEDIAN_TIME_SPAN, SYNC_WINDOW_SECS,
};
use plaine_consensus::rules::{
    check_block_time, evaluate_reorg, median_time_past, work_from_target, ChainView, HeaderInfo,
    ReorgParams, Work,
};

fn flat_target() -> [u8; 32] {
    let mut t = [0xffu8; 32];
    t[0] = 0;
    t[1] = 0;
    t
}

fn hash_of(height: u64, tag: u8) -> [u8; 32] {
    let mut h = [tag; 32];
    h[0..8].copy_from_slice(&height.to_be_bytes());
    h
}

struct Chain {
    headers: Vec<HeaderInfo>,
}

impl Chain {
    fn work(&self) -> Work {
        let unit = work_from_target(&flat_target());
        let mut w = Work::ZERO;
        for _ in 0..self.headers.len() {
            w = w.checked_add(&unit).expect("fixture work fits");
        }
        w
    }
}

impl ChainView for Chain {
    fn len(&self) -> u64 {
        self.headers.len() as u64
    }
    fn header_at(&self, height: u64) -> Option<HeaderInfo> {
        self.headers.get(height as usize).copied()
    }
    fn header_by_hash(&self, hash: &[u8; 32]) -> Option<HeaderInfo> {
        self.headers.iter().find(|h| h.hash == *hash).copied()
    }
    fn cumulative_work(&self) -> Work {
        self.work()
    }
}

fn minimum_legal_time(times: &[u64]) -> u64 {
    let window_start = times.len().saturating_sub(MEDIAN_TIME_SPAN);
    median_time_past(&times[window_start..]) + 1
}

// Build a chain whose tail is stamped at the legal minimum (one past the MTP),
// so the tip timestamp lags the wall clock as far as the rules permit.
fn floor_stamped_chain(honest_prefix: usize, floor_blocks: usize, tag: u8) -> (Chain, u64) {
    let epoch: u64 = 1_700_000_000;
    let mut times: Vec<u64> = Vec::new();

    for i in 0..honest_prefix {
        times.push(epoch + BLOCK_TIME_SECS * i as u64);
    }
    let mut wall = *times.last().expect("prefix is non-empty");
    for _ in 0..floor_blocks {
        let t = minimum_legal_time(&times);

        wall += BLOCK_TIME_SECS;

        let ancestors_start = times.len().saturating_sub(MEDIAN_TIME_SPAN);
        assert_eq!(
            check_block_time(median_time_past(&times[ancestors_start..]), t, wall),
            Ok(()),
            "the floor timestamp must itself be legal, or this is not an attack"
        );
        assert!(
            t < wall,
            "a floor-stamped block sits in the past; that is why it is legal"
        );
        times.push(t);
    }
    let headers = times
        .iter()
        .enumerate()
        .map(|(h, &time)| HeaderInfo {
            height: h as u64,
            hash: hash_of(h as u64, tag),
            time,
            target: flat_target(),
        })
        .collect();
    (Chain { headers }, wall)
}

#[test]
fn lag_crosses_sync_window_in_eight_blocks() {
    let prefix = MEDIAN_TIME_SPAN * 2;
    let mut first_crossing = None;
    for n in 1..=32 {
        let (chain, wall) = floor_stamped_chain(prefix, n, 0xAA);
        let tip = chain.tip();
        let lag = wall - tip.time;
        if lag > SYNC_WINDOW_SECS && first_crossing.is_none() {
            first_crossing = Some((n, lag));
        }
    }
    let (blocks, lag) =
        first_crossing.expect("floor-stamped blocks must eventually push the tip past the window");
    assert_eq!(
        blocks, 8,
        "expected 8 blocks to cross the sync window, got {blocks} (lag {lag} s)"
    );

    let (long, wall) = floor_stamped_chain(prefix, 200, 0xAA);
    let lag = wall - long.tip().time;
    assert!(
        lag > 10 * SYNC_WINDOW_SECS,
        "the lag must grow without bound, got {lag} s"
    );
}

#[test]
fn unsigned_reorg_past_cap_refused_floor_stamped() {
    let prefix = MEDIAN_TIME_SPAN * 2;

    let (chain, wall) = floor_stamped_chain(prefix, 64, 0xAA);
    let tip = chain.tip();
    assert!(
        wall - tip.time > SYNC_WINDOW_SECS,
        "premise: the tip must look stale"
    );

    let depth = MAX_REORG_DEPTH + 1;
    let fork_height = chain.len() - depth;
    let start_height = fork_height;

    let candidate: Vec<HeaderInfo> = (0..depth + 1)
        .map(|i| HeaderInfo {
            height: start_height + i,
            hash: hash_of(start_height + i, 0xBB),
            time: tip.time + 1 + i,
            target: flat_target(),
        })
        .collect();

    let verdict = evaluate_reorg(
        &chain,
        start_height,
        &candidate,
        &ReorgParams {
            anchor: None,
            checkpoints: &[],
            local_time: wall,
        },
    );

    assert!(
        verdict.is_err(),
        "SPEC 7.1: a reorg past MAX_REORG_DEPTH must be refused however stale the tip \
         timestamp makes the chain look; depth {depth} was admitted as {verdict:?}"
    );
}

#[test]
fn honest_stamp_reorg_refused() {
    let prefix = MEDIAN_TIME_SPAN * 2 + 64;
    let (chain, wall) = floor_stamped_chain(prefix, 0, 0xAA);
    let tip = chain.tip();
    assert!(
        wall - tip.time <= SYNC_WINDOW_SECS,
        "premise: an honest tip is fresh"
    );

    let depth = MAX_REORG_DEPTH + 1;
    let start_height = chain.len() - depth;
    let candidate: Vec<HeaderInfo> = (0..depth + 1)
        .map(|i| HeaderInfo {
            height: start_height + i,
            hash: hash_of(start_height + i, 0xBB),
            time: tip.time + 1 + i,
            target: flat_target(),
        })
        .collect();

    let verdict = evaluate_reorg(
        &chain,
        start_height,
        &candidate,
        &ReorgParams {
            anchor: None,
            checkpoints: &[],
            local_time: wall,
        },
    );
    assert!(
        verdict.is_err(),
        "the honest-stamp control must refuse the same depth"
    );
}

#[ignore = "refuted: the depth cap is unconditional, so a timestamp floor is the wrong remedy and breaks initial sync - see the doc comment"]
#[test]
fn block_timestamp_floor_vs_wall_clock() {
    let now: u64 = 1_700_000_000;

    let ancient_mtp = now - 100 * SYNC_WINDOW_SECS;

    assert_eq!(
        check_block_time(ancient_mtp, now + MAX_FUTURE_DRIFT_SECS, now),
        Ok(())
    );
    assert!(check_block_time(ancient_mtp, now + MAX_FUTURE_DRIFT_SECS + 1, now).is_err());

    let far_past = ancient_mtp + 1;
    assert!(
        check_block_time(ancient_mtp, far_past, now).is_err(),
        "a stamp {} s behind the wall clock was accepted; the reorg cap keys on this quantity",
        now - far_past
    );
}
