use plaine_rpc::SyncStatus;

use crate::log;

pub const HEARTBEAT_SYNCED_SECS: u64 = 60;

pub const HEARTBEAT_SYNCING_SECS: u64 = 10;

// Two stall thresholds. STALL_AFTER_SECS is short: it only fires with a second
// symptom to corroborate (behind and not moving, bodies missing, peers gone).
// The quiet arm has nothing to corroborate it, so it waits much longer.
pub const STALL_AFTER_SECS: u64 = 180;

// The evidence-free arm. Kept in block times, so it tracks the chain it guards,
// and sized so a quiet-but-healthy chain almost never trips it.
pub const QUIET_STALL_AFTER_SECS: u64 =
    plaine_consensus::constants::BLOCK_TIME_SECS * QUIET_STALL_BLOCK_TIMES;

// budget the quiet arm is sized against: false stalls per node per day
pub const QUIET_STALL_FALSE_FIRINGS_PER_BOX_PER_DAY: f64 = 0.5;

// smallest whole block time that stays under that budget
pub const QUIET_STALL_BLOCK_TIMES: u64 = 8;

#[derive(Clone, Copy, Debug, Default)]
pub struct Observation {
    pub height: u64,
    pub best_known_height: Option<u64>,
    pub tip_age_secs: u64,
    pub idle_secs: u64,
    pub gap_idle_secs: u64,
    pub peer_height_idle_secs: u64,
    pub peers: usize,
    pub started: bool,
    pub blocks_per_sec: f64,
    pub mempool_txs: usize,
    pub branch: Option<plaine_chain::BranchReport>,
    pub transport_stranded: Option<TransportStranded>,
    pub transport_repair_stuck: Option<TransportRepairStuck>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportRepairStuck {
    pub height: u64,
    pub why: &'static str,
    pub repeats: u32,
    pub our_tip: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportStranded {
    pub our_tip: u64,
    pub their_tip: u64,
    pub depth: u64,
    pub cap: u64,
}

pub const REPAIR_STUCK_HOLD_SECS: u64 = 300;

#[derive(Default, Debug)]
pub struct RepairStuckFlag {
    at: std::sync::atomic::AtomicU64,
    now: std::sync::atomic::AtomicU64,
    height: std::sync::atomic::AtomicU64,
    our_tip: std::sync::atomic::AtomicU64,
    repeats: std::sync::atomic::AtomicU32,
    why: std::sync::Mutex<Option<&'static str>>,
}

impl RepairStuckFlag {
    pub fn note(&self, unix_now: u64, r: TransportRepairStuck) {
        use std::sync::atomic::Ordering::Relaxed;
        self.height.store(r.height, Relaxed);
        self.our_tip.store(r.our_tip, Relaxed);
        self.repeats.store(r.repeats, Relaxed);
        *self.why.lock().expect("repair why") = Some(r.why);
        self.at.store(unix_now, Relaxed);
    }

    pub fn tick(&self, unix_now: u64) {
        self.now
            .store(unix_now, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn report(&self) -> Option<TransportRepairStuck> {
        use std::sync::atomic::Ordering::Relaxed;
        let at = self.at.load(Relaxed);
        // expires after the hold; a node that got past the break should not
        // report STALLED for the rest of the process.
        if at == 0 || self.now.load(Relaxed).saturating_sub(at) >= REPAIR_STUCK_HOLD_SECS {
            return None;
        }
        Some(TransportRepairStuck {
            height: self.height.load(Relaxed),
            our_tip: self.our_tip.load(Relaxed),
            repeats: self.repeats.load(Relaxed),
            why: self
                .why
                .lock()
                .expect("repair why")
                .unwrap_or("reason not carried"),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub status: SyncStatus,
    pub reason: Option<String>,
}

pub fn thresholds_line() -> String {
    let per_day = (86_400.0 / HEARTBEAT_SYNCED_SECS as f64)
        * (-(QUIET_STALL_AFTER_SECS as f64) / plaine_consensus::constants::BLOCK_TIME_SECS as f64)
            .exp();
    format!(
        "stall thresholds  {}s when a second symptom corroborates the clock, {}s ({} block \
         times) on a quiet chain with no other symptom. The quiet arm is the only one that can \
         fire on luck: at nominal hash rate it is expected to be wrong about {:.2} times a day \
         per node (budget {:.2}), i.e. roughly once every {:.0} days. Every other stall arm \
         needs evidence that does not happen by chance.",
        STALL_AFTER_SECS,
        QUIET_STALL_AFTER_SECS,
        QUIET_STALL_BLOCK_TIMES,
        per_day,
        QUIET_STALL_FALSE_FIRINGS_PER_BOX_PER_DAY,
        1.0 / per_day
    )
}

#[derive(Clone, Copy, Debug)]
pub struct Live {
    pub height: u64,
    pub tip_age_secs: u64,
    pub peers: usize,
    pub best_known_height: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Latched {
    pub obs: Observation,
    pub at: std::time::Instant,
}

impl Latched {
    pub fn refreshed(&self, live: Live) -> Verdict {
        // idle clock keeps running between heartbeats; height and peers are read
        // live. The rpc verdict is never staler than the last beat.
        let elapsed = self.at.elapsed().as_secs();
        let mut o = self.obs;
        o.idle_secs = if live.height == o.height {
            o.idle_secs.saturating_add(elapsed)
        } else {
            0
        };
        o.height = live.height;
        o.tip_age_secs = live.tip_age_secs;
        o.peers = live.peers;
        o.best_known_height = live.best_known_height;
        assess(&o)
    }
}

// second-highest claim, not the max: one lying peer shouting a huge height
// cannot move our idea of where the network is. a single peer is taken at its word.
pub fn backed_height(claims: &[u64]) -> u64 {
    let mut v: Vec<u64> = claims.to_vec();
    v.sort_unstable_by(|a, b| b.cmp(a));
    match v.len() {
        0 => 0,
        1 => v[0],
        _ => v[1],
    }
}

pub fn best_known(peers: usize, backed: u64, ours: u64) -> Option<u64> {
    (peers > 0).then(|| backed.max(ours))
}

// Arms are ordered by how much evidence they carry. No-peers, stranded, and
// stuck-repair verdicts come first and survive a height that moved: a node
// extending its own dead branch keeps moving while it is wedged. The quiet arm,
// which fires on absence alone, is last.
pub fn assess(o: &Observation) -> Verdict {
    if !o.started {
        return Verdict {
            status: SyncStatus::Starting,
            reason: None,
        };
    }

    if o.peers == 0 {
        return Verdict {
            status: SyncStatus::Stalled,
            reason: Some(
                "no peers connected - nothing can arrive. Check that outbound connections are \
                 allowed and that at least one seed resolves."
                    .to_string(),
            ),
        };
    }

    if let Some(b) = o.branch {
        if let plaine_chain::BranchVerdict::Stranded { cap } = b.verdict {
            return Verdict {
                status: SyncStatus::Stalled,
                reason: Some(format!(
                    "Stranded. This node forked from the better chain at height {} and would \
                     have to discard {} of its own blocks to rejoin, more than the {}-block \
                     reorg limit. It will not recover on its own. The better chain's tip is {} \
                     at height {}. Recovery: SPEC.md.",
                    log::thousands(b.fork_height),
                    log::thousands(b.depth),
                    log::thousands(cap),
                    plaine_consensus::hex::encode(&b.best_hash),
                    log::thousands(b.best)
                )),
            };
        }
    }

    if let Some(r) = o.transport_repair_stuck {
        return Verdict {
            status: SyncStatus::Stalled,
            reason: Some(format!(
                "Stuck repairing the same header. The p2p engine has repaired the break at height {} and re-reached it {} times without this node's tip moving off {}. The chain's reason each time: \"{}\". Sockets and peers are not the problem - this is engine state, and a process restart clears it.",
                log::thousands(r.height),
                r.repeats,
                log::thousands(r.our_tip),
                r.why
            )),
        };
    }

    if let Some(t) = o.transport_stranded {
        return Verdict {
            status: SyncStatus::Stalled,
            reason: Some(format!(
                "Stranded. This node's chain refused a better branch at height {} because rejoining it would discard {} of its own blocks, more than the {}-block reorg limit. The branch was never admitted, so this node's own arena cannot see it and reports no fork. It will not recover on its own and has stopped building templates. Our tip is {}. Recovery: SPEC.md.",
                log::thousands(t.their_tip),
                log::thousands(t.depth),
                log::thousands(t.cap),
                log::thousands(t.our_tip)
            )),
        };
    }

    let Some(best) = o.best_known_height else {
        return Verdict {
            status: SyncStatus::Stalled,
            reason: Some(format!(
                "{} peers are connected but none has told us its height, so \"synced\" cannot be established. This is a reporting fault in the node, not a network fault.",
                o.peers
            )),
        };
    };
    let behind = best.saturating_sub(o.height);

    if behind > 1 {
        if o.idle_secs >= STALL_AFTER_SECS {
            return Verdict {
                status: SyncStatus::Stalled,
                reason: Some(format!(
                    "{} blocks behind the network and no progress for {} - the peers we have may \
                     not be serving blocks",
                    log::thousands(behind),
                    log::human_duration(o.idle_secs)
                )),
            };
        }

        if o.gap_idle_secs >= STALL_AFTER_SECS {
            return Verdict {
                status: SyncStatus::Stalled,
                reason: Some(format!(
                    "{} blocks behind the network and the gap has not closed for {}, even though \
                     this node's own height is moving. That is what a node extending its own \
                     branch looks like: it is mining, not following. Check the log for `header \
                     REFUSED` and for `HeaderRefusedByChain` - a header this node's chain refused \
                     is the way it leaves the network.",
                    log::thousands(behind),
                    log::human_duration(o.gap_idle_secs)
                )),
            };
        }
        return Verdict {
            status: SyncStatus::Syncing,
            reason: None,
        };
    }

    if let Some(b) = o.branch {
        if let plaine_chain::BranchVerdict::NeedBodies { missing } = b.verdict {
            if b.best > b.tip && o.idle_secs >= STALL_AFTER_SECS {
                return Verdict {
                    status: SyncStatus::Stalled,
                    reason: Some(format!(
                        "{} blocks behind: this node holds the headers up to height {} and is \
                         missing {} block bodies. This is a body-fetch fault, not a fork - it \
                         has not forked from anything (fork height {} is its own tip).",
                        log::thousands(b.best - b.tip),
                        log::thousands(b.best),
                        log::thousands(missing as u64),
                        log::thousands(b.fork_height)
                    )),
                };
            }
        }
    }

    if o.idle_secs >= QUIET_STALL_AFTER_SECS {
        return Verdict {
            status: SyncStatus::Stalled,
            reason: Some(format!(
                "no new block for {} (one is expected about every {}s). The network may be \
                 quiet, or this node may be on a fork nobody else is extending.",
                log::human_duration(o.idle_secs),
                plaine_consensus::constants::BLOCK_TIME_SECS
            )),
        };
    }

    if o.idle_secs < STALL_AFTER_SECS && o.peer_height_idle_secs >= STALL_AFTER_SECS {
        return Verdict {
            status: SyncStatus::Stalled,
            reason: Some(format!(
                "this node's own height is moving (last change {} ago) while no peer's claimed \
                 height has moved for {}. \"Synced\" here means level with a number that stopped \
                 being refreshed. Check the log for `header REFUSED` and for \
                 `HeaderRefusedByChain`.",
                log::human_duration(o.idle_secs),
                log::human_duration(o.peer_height_idle_secs)
            )),
        };
    }
    Verdict {
        status: SyncStatus::Synced,
        reason: None,
    }
}

fn word(status: SyncStatus) -> &'static str {
    match status {
        SyncStatus::Starting => "STARTING",
        SyncStatus::Syncing => "SYNCING ",
        SyncStatus::Synced => "SYNCED  ",
        SyncStatus::Stalled => "STALLED ",
    }
}

pub fn heartbeat_line(o: &Observation, v: &Verdict) -> String {
    match v.status {
        SyncStatus::Starting => format!("{} opening storage", word(v.status)),
        SyncStatus::Syncing => {
            let target = o.best_known_height.unwrap_or(o.height).max(1);
            let pct = (o.height as f64 / target as f64) * 100.0;
            let remaining = target.saturating_sub(o.height);
            let eta = if o.blocks_per_sec > 0.01 {
                log::human_duration((remaining as f64 / o.blocks_per_sec) as u64)
            } else {
                "unknown".to_string()
            };
            format!(
                "{} {:>5.1}%  {} / {} blocks   {:.0} blk/s   eta {}   peers {}",
                word(v.status),
                pct,
                log::thousands(o.height),
                log::thousands(target),
                o.blocks_per_sec,
                eta,
                o.peers
            )
        }
        SyncStatus::Synced => format!(
            "{} height {}   tip {} ago   peers {}   mempool {}",
            word(v.status),
            log::thousands(o.height),
            log::human_duration(o.tip_age_secs),
            o.peers,
            o.mempool_txs
        ),
        SyncStatus::Stalled => format!(
            "{} height {}   {}   peers {}",
            word(v.status),
            log::thousands(o.height),
            v.reason.as_deref().unwrap_or("stalled"),
            o.peers
        ),
    }
}

// How long after start a no-peers stall reads as ordinary startup rather than a
// fault. Only the no-peers arm is graced, and only this early: every other stall
// arm needs its own idle threshold to have elapsed, which cannot happen this soon.
pub const STARTUP_GRACE_SECS: u64 = 45;

pub fn emit(o: &Observation, v: &Verdict, uptime: u64) {
    // Fresh start with no peers yet: seeds are still resolving. Say so calmly
    // instead of raising a stall warning that self-corrects a moment later.
    if v.status == SyncStatus::Stalled && o.peers == 0 && uptime < STARTUP_GRACE_SECS {
        log::info("chain", "connecting to seeds...");
        return;
    }
    let line = heartbeat_line(o, v);
    if v.status == SyncStatus::Stalled {
        log::warn("chain", line);
    } else {
        log::info("chain", line);
    }
}

pub fn heartbeat_interval(status: SyncStatus) -> u64 {
    match status {
        SyncStatus::Syncing | SyncStatus::Starting => HEARTBEAT_SYNCING_SECS,
        _ => HEARTBEAT_SYNCED_SECS,
    }
}

#[derive(Clone, Debug, Default)]
pub struct Tracker {
    last_height: u64,
    last_change_at: u64,
    window_start_at: u64,
    window_start_height: u64,
    best_gap: u64,
    best_gap_at: u64,
    best_backed: u64,
    best_backed_at: u64,
}

impl Tracker {
    pub fn new(height: u64, now: u64) -> Tracker {
        Tracker {
            last_height: height,
            last_change_at: now,
            window_start_at: now,
            window_start_height: height,
            best_gap: u64::MAX,
            best_gap_at: now,
            best_backed: 0,
            best_backed_at: now,
        }
    }

    pub fn note_height(&mut self, height: u64, now: u64) {
        if height != self.last_height {
            self.last_height = height;
            self.last_change_at = now;
        }
    }

    pub fn observe(&mut self, height: u64, now: u64) {
        self.note_height(height, now);

        if now.saturating_sub(self.window_start_at) >= 30 {
            self.window_start_at = now;
            self.window_start_height = height;
        }
    }

    // Rearm only when the gap actually shrank (or we are level). A gap no smaller
    // than the best already seen leaves the clock alone; otherwise a node stuck on
    // its own branch keeps looking like it is catching up.
    pub fn observe_gap(&mut self, behind: u64, now: u64) {
        if behind <= 1 || behind < self.best_gap {
            self.best_gap = behind;
            self.best_gap_at = now;
        }
    }

    pub fn gap_idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.best_gap_at)
    }

    // a peer leaving lowers the top claim, which must not read as the network
    // moving. Only a strictly higher claim rearms the clock.
    pub fn observe_top_claim(&mut self, top: u64, now: u64) {
        if top > self.best_backed {
            self.best_backed = top;
            self.best_backed_at = now;
        }
    }

    pub fn peer_height_idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.best_backed_at)
    }

    pub fn idle_secs_at(&mut self, height: u64, now: u64) -> u64 {
        self.note_height(height, now);
        self.idle_secs(now)
    }

    fn idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_change_at)
    }

    pub fn blocks_per_sec(&self, now: u64) -> f64 {
        let elapsed = now.saturating_sub(self.window_start_at);
        if elapsed == 0 {
            return 0.0;
        }
        self.last_height.saturating_sub(self.window_start_height) as f64 / elapsed as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Observation {
        Observation {
            started: true,
            peers: 8,
            ..Default::default()
        }
    }

    fn latched(o: Observation, ago: u64) -> Latched {
        Latched {
            obs: o,
            at: std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(ago))
                .expect("monotonic clock older than the test"),
        }
    }

    fn live(height: u64, tip_age_secs: u64, peers: usize) -> Live {
        Live {
            height,
            tip_age_secs,
            peers,
            best_known_height: Some(height),
        }
    }

    #[test]
    fn quiet_threshold_is_smallest_within_budget() {
        let tau = plaine_consensus::constants::BLOCK_TIME_SECS as f64;
        let trials_per_day = 86_400.0 / HEARTBEAT_SYNCED_SECS as f64;

        let per_box_per_day = |t: u64| trials_per_day * (-(t as f64) / tau).exp();

        let budget = QUIET_STALL_FALSE_FIRINGS_PER_BOX_PER_DAY;
        let chosen = per_box_per_day(QUIET_STALL_AFTER_SECS);
        assert!(
            chosen <= budget,
            "the bare stall arm waits {}s, which buys {:.3} false firings per box per \
             day against a budget of {}. Solve it: T >= tau*ln(trials/budget) = {:.1}s.",
            QUIET_STALL_AFTER_SECS,
            chosen,
            budget,
            tau * (trials_per_day / budget).ln()
        );

        let shorter = QUIET_STALL_AFTER_SECS - plaine_consensus::constants::BLOCK_TIME_SECS;
        let cheaper = per_box_per_day(shorter);
        assert!(
            cheaper > budget,
            "{}s already meets the budget ({:.3} <= {}), so waiting {}s costs a genuinely \
             dead chain an extra block time of silence and buys nothing. The threshold \
             must be the SMALLEST whole block time that meets the budget.",
            shorter,
            cheaper,
            budget,
            QUIET_STALL_AFTER_SECS
        );

        assert!(
            STALL_AFTER_SECS < QUIET_STALL_AFTER_SECS,
            "the evidence-free arm must wait strictly longer than the arms with evidence"
        );
        assert_eq!(
            QUIET_STALL_AFTER_SECS,
            plaine_consensus::constants::BLOCK_TIME_SECS * QUIET_STALL_BLOCK_TIMES,
            "the threshold must be expressed in block times, or it stops tracking the \
             chain it is a threshold for"
        );
    }

    #[test]
    fn banner_states_thresholds_and_quiet_cost() {
        let s = thresholds_line();
        assert!(s.contains(&format!("{STALL_AFTER_SECS}s")), "{s}");
        assert!(s.contains(&format!("{QUIET_STALL_AFTER_SECS}s")), "{s}");

        let tau = plaine_consensus::constants::BLOCK_TIME_SECS as f64;
        let per_day = (86_400.0 / HEARTBEAT_SYNCED_SECS as f64)
            * (-(QUIET_STALL_AFTER_SECS as f64) / tau).exp();
        assert!(
            s.contains(&format!("{per_day:.2} times a day")),
            "the banner must state the quiet arm's modeled false-firing rate \
             ({per_day:.2}/day). Got: {s}"
        );
    }

    #[test]
    fn stall_not_served_beside_refuting_height() {
        let quiet = Observation {
            height: 3_285,
            best_known_height: Some(3_285),
            idle_secs: QUIET_STALL_AFTER_SECS,
            tip_age_secs: QUIET_STALL_AFTER_SECS,
            peers: 5,
            ..base()
        };
        assert_eq!(
            assess(&quiet).status,
            SyncStatus::Stalled,
            "the control: this observation IS a stall while it is the live one"
        );

        let v = latched(quiet, 30).refreshed(live(3_287, 36, 5));
        assert_ne!(
            v.status,
            SyncStatus::Stalled,
            "live facts say a block arrived (height 3,287, tip 36s) but the verdict was {:?}: {:?}",
            v.status,
            v.reason
        );
    }

    #[test]
    fn idle_clock_runs_between_heartbeats() {
        let almost = Observation {
            height: 3_285,
            best_known_height: Some(3_285),
            idle_secs: QUIET_STALL_AFTER_SECS - 45,
            tip_age_secs: QUIET_STALL_AFTER_SECS - 45,
            peers: 5,
            ..base()
        };
        assert_eq!(
            assess(&almost).status,
            SyncStatus::Synced,
            "the control: 45 s short of the threshold is not yet a stall"
        );

        let v = latched(almost, 50).refreshed(live(3_285, QUIET_STALL_AFTER_SECS + 5, 5));
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "the height has not moved and the clock has run past the threshold, so the \
             RPC must say so without waiting for the next beat"
        );
        assert!(
            v.reason.unwrap_or_default().contains("no new block for"),
            "and it must be the bare quiet arm that fired, not some other one"
        );
    }

    #[test]
    fn stuck_and_stranded_survive_moving_height() {
        let stuck = Observation {
            transport_repair_stuck: Some(super::TransportRepairStuck {
                height: 414,
                why: "the chain does not hold the parent",
                repeats: 3,
                our_tip: 424,
            }),
            ..wedge_obs()
        };
        let v = latched(stuck, 30).refreshed(live(430, 2, 2));
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "a stuck repair loop keeps mining, so a moving height must not read as recovery"
        );
        assert!(
            v.reason.unwrap_or_default().contains("414"),
            "and it must still name the height it is stuck on"
        );

        let stranded = Observation {
            transport_stranded: Some(super::TransportStranded {
                our_tip: 424,
                their_tip: 495,
                depth: 11,
                cap: 30,
            }),
            ..wedge_obs()
        };
        let v = latched(stranded, 30).refreshed(live(430, 2, 2));
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "a stranded node extends its OWN branch, so its height moves the whole time \
             it is stranded. That must not clear the verdict."
        );
        assert!(
            v.reason.unwrap_or_default().contains("Stranded"),
            "and it must still say stranded rather than blaming its peers"
        );
    }

    #[test]
    fn refreshed_height_and_position_same_instant() {
        let latched_at_3285 = Observation {
            height: 3_285,
            best_known_height: Some(3_285),
            idle_secs: 10,
            tip_age_secs: 10,
            peers: 5,
            ..base()
        };
        assert_eq!(
            assess(&latched_at_3285).status,
            SyncStatus::Synced,
            "the control"
        );

        let v = latched(latched_at_3285, 20).refreshed(live(3_290, 4, 5));
        assert_eq!(
            v.status,
            SyncStatus::Synced,
            "level with peers at 3,290 but the verdict was {:?}: {:?}",
            v.status,
            v.reason
        );
    }

    #[test]
    fn network_ahead_since_heartbeat_not_synced() {
        let level = Observation {
            height: 3_285,
            best_known_height: Some(3_285),
            idle_secs: 10,
            tip_age_secs: 10,
            peers: 5,
            ..base()
        };
        assert_eq!(
            assess(&level).status,
            SyncStatus::Synced,
            "the control: we were level"
        );

        let v = latched(level, 20).refreshed(Live {
            height: 3_285,
            tip_age_secs: 30,
            peers: 5,
            best_known_height: Some(3_400),
        });
        assert_eq!(
            v.status,
            SyncStatus::Syncing,
            "the peer set is 115 blocks ahead of us and the reply said {:?}. `behind` is a \
             subtraction: taking our height live and the network's from a minute ago is how \
             it inverts.",
            v.status
        );
    }

    #[test]
    fn refresh_reads_live_peer_count() {
        let healthy = Observation {
            height: 3_285,
            best_known_height: Some(3_285),
            idle_secs: 10,
            tip_age_secs: 10,
            peers: 5,
            ..base()
        };
        assert_eq!(assess(&healthy).status, SyncStatus::Synced, "the control");

        let v = latched(healthy, 5).refreshed(Live {
            height: 3_285,
            tip_age_secs: 15,
            peers: 0,
            best_known_height: None,
        });
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "every peer is gone and the reply still said {:?}",
            v.status
        );
        assert!(v.reason.unwrap_or_default().contains("no peers connected"));
    }

    fn wedge_obs() -> Observation {
        Observation {
            height: 424,
            best_known_height: Some(424),
            tip_age_secs: 3,
            idle_secs: 3,
            gap_idle_secs: 3,
            peer_height_idle_secs: 3,
            peers: 2,
            ..base()
        }
    }

    #[test]
    fn wedge_without_report_looks_healthy() {
        assert_eq!(
            assess(&wedge_obs()).status,
            SyncStatus::Synced,
            "the fixture no longer reproduces the run: something else in `assess` now catches this, and the new arm below would be scored by a test that proves nothing"
        );
    }

    #[test]
    fn stuck_repair_loop_says_where() {
        let o = Observation {
            transport_repair_stuck: Some(super::TransportRepairStuck {
                height: 414,
                why: "the chain does not hold the parent",
                repeats: 3,
                our_tip: 424,
            }),
            ..wedge_obs()
        };
        let v = assess(&o);
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "repair ran three times without moving and the node still called itself {:?}",
            v.status
        );
        let reason = v.reason.expect("a stall must carry a reason");
        assert!(
            reason.contains("414"),
            "the stall reason does not name the break, so an operator cannot grep for it: {reason}"
        );
        assert!(
            reason.contains("424"),
            "the stall reason does not name our own tip, so there is nothing to compare a peer's height against: {reason}"
        );
        assert!(
            reason.contains("the chain does not hold the parent"),
            "the stall reason drops the chain's own reason, which is the part that says which gate refused: {reason}"
        );
    }

    #[test]
    fn repair_report_named_ahead_of_cap() {
        let o = Observation {
            transport_repair_stuck: Some(super::TransportRepairStuck {
                height: 414,
                why: "the chain does not hold the parent",
                repeats: 3,
                our_tip: 424,
            }),
            transport_stranded: Some(super::TransportStranded {
                our_tip: 424,
                their_tip: 495,
                depth: 11,
                cap: 30,
            }),
            ..wedge_obs()
        };
        let reason = assess(&o).reason.expect("a stall must carry a reason");
        assert!(
            reason.contains("Stuck repairing"),
            "the cap arm answered for a fork inside the cap: {reason}"
        );
    }

    #[test]
    fn repair_report_expires_after_recovery() {
        let f = super::RepairStuckFlag::default();
        let r = super::TransportRepairStuck {
            height: 414,
            why: "the chain does not hold the parent",
            repeats: 3,
            our_tip: 424,
        };
        f.tick(1_000);
        assert_eq!(f.report(), None, "an untouched flag reported a wedge");
        f.note(1_000, r);
        assert_eq!(
            f.report(),
            Some(r),
            "the flag dropped the report it was just given"
        );
        f.tick(1_000 + super::REPAIR_STUCK_HOLD_SECS - 1);
        assert_eq!(f.report(), Some(r), "the flag expired inside its own hold");
        f.tick(1_000 + super::REPAIR_STUCK_HOLD_SECS);
        assert_eq!(
            f.report(),
            None,
            "the flag never expires, so a node that got past the break reports STALLED for the rest of the process"
        );
    }

    fn report(
        tip: u64,
        best: u64,
        fork: u64,
        verdict: plaine_chain::BranchVerdict,
    ) -> plaine_chain::BranchReport {
        plaine_chain::BranchReport {
            tip,
            best,
            best_hash: [0xab; 32],
            fork_height: fork,
            depth: tip.saturating_sub(fork),
            verdict,
        }
    }

    #[test]
    fn missing_bodies_not_reported_as_quiet() {
        let o = Observation {
            height: 1_686,
            best_known_height: Some(1_686),
            idle_secs: STALL_AFTER_SECS + 60,
            peers: 7,
            branch: Some(report(
                1_686,
                2_965,
                1_686,
                plaine_chain::BranchVerdict::NeedBodies { missing: 1_279 },
            )),
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        let r = v.reason.expect("a reason");
        assert!(
            !r.contains("may be quiet"),
            "the quiet sentence was printed to a node holding 1,279 headers: {r}"
        );
        assert!(
            r.contains("1,279"),
            "the missing-body count is the actionable number: {r}"
        );
        assert!(
            r.contains("2,965"),
            "the height it is holding headers to: {r}"
        );
    }

    #[test]
    fn stranded_not_blamed_on_peers() {
        let o = Observation {
            height: 247,
            best_known_height: Some(4_239),
            idle_secs: STALL_AFTER_SECS * 10,
            peers: 4,
            branch: Some(report(
                247,
                4_239,
                33,
                plaine_chain::BranchVerdict::Stranded { cap: 30 },
            )),
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        let r = v.reason.expect("a reason");
        assert!(r.contains("Stranded"), "{r}");
        assert!(r.contains("not recover on its own"), "{r}");
        assert!(
            !r.contains("may not be serving blocks"),
            "four peers that were serving perfectly were blamed: {r}"
        );
    }

    #[test]
    fn branch_arms_fall_back_without_validator() {
        let quiet = Observation {
            height: 100,
            best_known_height: Some(100),
            idle_secs: QUIET_STALL_AFTER_SECS + 1,
            branch: None,
            ..base()
        };
        let r = assess(&quiet).reason.expect("a reason");
        assert!(r.contains("may be quiet"), "{r}");

        let stranded_and_alone = Observation {
            peers: 0,
            height: 247,
            branch: Some(report(
                247,
                4_239,
                33,
                plaine_chain::BranchVerdict::Stranded { cap: 30 },
            )),
            ..base()
        };
        let r = assess(&stranded_and_alone).reason.expect("a reason");
        assert!(r.contains("no peers connected"), "{r}");
    }

    #[test]
    fn healthy_ibd_not_stranded() {
        let syncing = Observation {
            height: 512,
            best_known_height: Some(946),
            idle_secs: 2,
            blocks_per_sec: 8.0,
            branch: Some(report(
                512,
                946,
                512,
                plaine_chain::BranchVerdict::NeedBodies { missing: 434 },
            )),
            ..base()
        };
        assert_eq!(assess(&syncing).status, SyncStatus::Syncing);

        let level = Observation {
            height: 946,
            best_known_height: Some(946),
            idle_secs: 5,
            branch: Some(report(946, 946, 946, plaine_chain::BranchVerdict::OnBest)),
            ..base()
        };
        assert_eq!(assess(&level).status, SyncStatus::Synced);
    }

    #[test]
    fn peers_give_a_comparison() {
        assert_eq!(best_known(3, 946, 512), Some(946));
        assert_eq!(best_known(0, 946, 512), None);

        assert_eq!(best_known(3, 100, 512), Some(512));
    }

    #[test]
    fn synced_needs_peer_comparison() {
        let o = Observation {
            height: 512,
            best_known_height: None,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "a node with {} peers and no idea where they are reported {:?}",
            o.peers,
            v.status
        );
        assert!(v.reason.expect("a reason").contains("height"));
    }

    #[test]
    fn fleet_shape_reads_as_syncing() {
        let o = Observation {
            height: 512,
            best_known_height: Some(946),
            tip_age_secs: 200,
            idle_secs: 30,
            peers: 3,
            blocks_per_sec: 8.0,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(
            v.status,
            SyncStatus::Syncing,
            "434 blocks behind three peers and the verdict was {:?}",
            v.status
        );
        let line = heartbeat_line(&o, &v);
        assert!(
            line.contains("512 / 946 blocks"),
            "the line must name where it is AND where the network is: {line}"
        );
    }

    #[test]
    fn mining_own_branch_not_busy() {
        let o = Observation {
            height: 487,
            best_known_height: Some(652),
            tip_age_secs: 24,
            idle_secs: 4,
            gap_idle_secs: 1_800,
            peers: 4,
            blocks_per_sec: 0.2,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "165 behind for 30 min while mining its own branch, verdict was {:?}",
            v.status
        );
        let reason = v.reason.clone().expect("a stall must carry a reason");
        assert!(
            reason.contains("165"),
            "the reason must name how far off it is: {reason}"
        );
        let line = heartbeat_line(&o, &v);
        assert!(
            !line.starts_with("SYNCED") && !line.starts_with("SYNCING"),
            "the line an operator reads was {line:?}"
        );
    }

    #[test]
    fn closing_gap_is_syncing() {
        let o = Observation {
            height: 12_000,
            best_known_height: Some(525_960),
            tip_age_secs: 400_000,
            idle_secs: 1,
            gap_idle_secs: 0,
            peers: 6,
            blocks_per_sec: 120.0,
            ..base()
        };
        assert_eq!(
            assess(&o).status,
            SyncStatus::Syncing,
            "a download closing 120 blocks a second was called something other \
             than syncing"
        );
    }

    #[test]
    fn gap_clock_restarts_only_on_progress() {
        let mut t = Tracker::new(100, 0);
        t.observe_gap(40, 0);
        assert_eq!(t.gap_idle_secs(0), 0);

        t.observe_gap(20, 10);
        assert_eq!(
            t.gap_idle_secs(30),
            20,
            "closing the gap must restart the clock"
        );

        t.observe_gap(35, 40);
        t.observe_gap(20, 50);
        assert_eq!(
            t.gap_idle_secs(60),
            50,
            "the clock was rearmed by a gap no smaller than the best already \
             seen; a node stuck on its own branch keeps looking like it is \
             catching up"
        );

        t.observe_gap(19, 70);
        assert_eq!(t.gap_idle_secs(70), 0);
    }

    #[test]
    fn level_then_two_behind_is_syncing() {
        let mut t = Tracker::new(1_000, 0);
        for s in 0..=3_600 {
            t.observe_gap(0, s);
        }
        assert_eq!(t.gap_idle_secs(3_600), 0, "being level IS progress");
        t.observe_gap(3, 3_601);
        let o = Observation {
            height: 1_000,
            best_known_height: Some(1_003),
            idle_secs: 5,
            gap_idle_secs: t.gap_idle_secs(3_610),
            peers: 5,
            ..base()
        };
        assert_eq!(
            assess(&o).status,
            SyncStatus::Syncing,
            "a node that fell three blocks behind nine seconds ago was called \
             stalled because it had been healthy for an hour first"
        );
    }

    #[test]
    fn frozen_peers_not_synced() {
        let o = Observation {
            height: 487,
            best_known_height: Some(487),
            tip_age_secs: 24,
            idle_secs: 24,
            peer_height_idle_secs: 1_800,
            peers: 4,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(
            v.status,
            SyncStatus::Stalled,
            "own height moves while every peer's has been frozen for 30 min, verdict was {:?}",
            v.status
        );
        assert!(
            v.reason.expect("a reason").contains("claimed height"),
            "the reason must name WHAT is stale, or the operator has nothing to act on"
        );
    }

    #[test]
    fn mined_ahead_still_synced() {
        let o = Observation {
            height: 900,
            best_known_height: Some(900),
            tip_age_secs: 4,
            idle_secs: 4,
            peer_height_idle_secs: 6,
            peers: 8,
            ..base()
        };
        assert_eq!(assess(&o).status, SyncStatus::Synced);
    }

    #[test]
    fn quiet_network_gets_quiet_sentence() {
        let quiet_for = QUIET_STALL_AFTER_SECS + 20;
        let o = Observation {
            height: 900,
            best_known_height: Some(900),
            tip_age_secs: quiet_for,
            idle_secs: quiet_for,
            peer_height_idle_secs: quiet_for,
            peers: 8,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        assert!(
            v.reason.expect("a reason").contains("network may be quiet"),
            "a quiet network was reported as a peer-staleness fault"
        );
    }

    #[test]
    fn quiet_network_not_stalled_on_luck() {
        for idle in [STALL_AFTER_SECS, QUIET_STALL_AFTER_SECS - 1] {
            let o = Observation {
                height: 900,
                best_known_height: Some(900),
                tip_age_secs: idle,
                idle_secs: idle,
                peer_height_idle_secs: idle,
                peers: 8,
                ..base()
            };
            let v = assess(&o);
            assert_eq!(
                v.status,
                SyncStatus::Synced,
                "a healthy chain idle for {idle}s was called stalled: {:?}",
                v.reason
            );
        }
    }

    #[test]
    fn only_quiet_arm_waits_longer() {
        let idle = STALL_AFTER_SECS;
        assert!(
            idle < QUIET_STALL_AFTER_SECS,
            "the split must be a real gap"
        );

        let behind = Observation {
            height: 100,
            best_known_height: Some(4_000),
            idle_secs: idle,
            gap_idle_secs: 0,
            peers: 8,
            ..base()
        };
        let v = assess(&behind);
        assert_eq!(v.status, SyncStatus::Stalled);
        assert!(
            v.reason.expect("a reason").contains("no progress for"),
            "the behind-and-not-moving arm is no longer the one that fired"
        );

        let bodies = Observation {
            height: 100,
            best_known_height: Some(100),
            idle_secs: idle,
            branch: Some(report(
                100,
                1_379,
                0,
                plaine_chain::BranchVerdict::NeedBodies { missing: 1_279 },
            )),
            peers: 8,
            ..base()
        };
        let r = assess(&bodies);
        assert_eq!(r.status, SyncStatus::Stalled);
        assert!(r.reason.expect("a reason").contains("body-fetch fault"));

        let walking_away = Observation {
            height: 900,
            best_known_height: Some(900),
            idle_secs: 0,
            peer_height_idle_secs: idle,
            peers: 8,
            ..base()
        };
        assert_eq!(assess(&walking_away).status, SyncStatus::Stalled);
    }

    #[test]
    fn peer_leaving_is_not_progress() {
        let mut t = Tracker::new(100, 0);
        t.observe_top_claim(500, 0);
        t.observe_top_claim(400, 100);
        assert_eq!(
            t.peer_height_idle_secs(200),
            200,
            "a shrinking peer set must not rearm the clock"
        );
        t.observe_top_claim(501, 250);
        assert_eq!(t.peer_height_idle_secs(250), 0);
    }

    #[test]
    fn one_liar_cannot_move_best_known() {
        assert_eq!(backed_height(&[700, 700, 700, 5_000_000]), 700);
        assert_eq!(backed_height(&[5_000_000, 700, 700]), 700);
        let o = Observation {
            height: 700,
            best_known_height: Some(backed_height(&[700, 700, 5_000_000])),
            tip_age_secs: 12,
            idle_secs: 12,
            peers: 3,
            ..base()
        };
        assert_eq!(assess(&o).status, SyncStatus::Synced);
    }

    #[test]
    fn single_peer_taken_at_word() {
        assert_eq!(backed_height(&[941]), 941);
        assert_eq!(backed_height(&[]), 0);
    }

    #[test]
    fn healthy_says_synced() {
        let o = Observation {
            height: 525_960,
            best_known_height: Some(525_960),
            tip_age_secs: 12,
            idle_secs: 12,
            mempool_txs: 43,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Synced);
        let line = heartbeat_line(&o, &v);
        assert!(line.starts_with("SYNCED"));
        assert!(line.contains("525,960"));
        assert!(line.contains("tip 12s ago"));

        assert_eq!(heartbeat_interval(v.status), 60);
    }

    #[test]
    fn behind_and_moving_has_eta() {
        let o = Observation {
            height: 65_231,
            best_known_height: Some(525_960),
            idle_secs: 1,
            blocks_per_sec: 1_240.0,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Syncing);
        let line = heartbeat_line(&o, &v);
        assert!(line.starts_with("SYNCING"));
        assert!(line.contains("12.4%"), "{line}");
        assert!(line.contains("65,231 / 525,960"));
        assert!(
            line.contains("eta 6m11s") || line.contains("eta 6m12s"),
            "{line}"
        );
        assert_eq!(heartbeat_interval(v.status), 10);
    }

    #[test]
    fn behind_and_stuck_is_stall() {
        let o = Observation {
            height: 65_231,
            best_known_height: Some(525_960),
            idle_secs: 600,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        let reason = v.reason.clone().expect("a stall must explain itself");
        assert!(reason.contains("460,729 blocks behind"), "{reason}");
        assert!(reason.contains("10m00s"));
    }

    #[test]
    fn zero_peers_is_root_cause() {
        let o = Observation {
            peers: 0,
            height: 0,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        let reason = v.reason.unwrap();
        assert!(reason.contains("no peers connected"));

        assert!(reason.contains("outbound connections"));
    }

    #[test]
    fn quiet_tip_stalled_with_baseline() {
        let idle = 544;
        assert!(
            idle >= QUIET_STALL_AFTER_SECS,
            "544s no longer reaches the arm this test is about"
        );
        let o = Observation {
            height: 100,
            best_known_height: Some(100),
            idle_secs: idle,
            tip_age_secs: idle,
            ..base()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        let r = v.reason.unwrap();
        assert!(r.contains("no new block for 9m04s"), "{r}");
        assert!(
            r.contains("every 60s"),
            "the baseline must be in the message"
        );
        assert!(r.contains("fork nobody else is extending"));
    }

    #[test]
    fn quiet_arm_fires_at_threshold() {
        let almost = Observation {
            height: 100,
            best_known_height: Some(100),
            idle_secs: QUIET_STALL_AFTER_SECS - 1,
            ..base()
        };
        assert_eq!(assess(&almost).status, SyncStatus::Synced);
        let over = Observation {
            idle_secs: QUIET_STALL_AFTER_SECS,
            ..almost
        };
        assert_eq!(assess(&over).status, SyncStatus::Stalled);
    }

    #[test]
    fn idle_clock_resets_with_height() {
        let mut t = Tracker::new(3_285, 0);
        assert_eq!(
            t.idle_secs_at(3_285, 301),
            301,
            "genuine quiet must still read"
        );
        assert_eq!(
            t.idle_secs_at(3_287, 302),
            0,
            "the clock must reset on the same call that reports the new height"
        );

        assert_eq!(t.idle_secs_at(3_287, 362), 60);
    }

    #[test]
    fn old_chain_download_not_stall() {
        let o = Observation {
            height: 500_000,
            best_known_height: Some(525_960),
            tip_age_secs: 2_000_000,
            idle_secs: 0,
            blocks_per_sec: 900.0,
            ..base()
        };
        assert_eq!(assess(&o).status, SyncStatus::Syncing);
    }

    #[test]
    fn verdict_word_leads_line() {
        for (o, expect) in [
            (
                Observation {
                    started: false,
                    ..base()
                },
                "STARTING",
            ),
            (
                Observation {
                    height: 1,
                    best_known_height: Some(1),
                    ..base()
                },
                "SYNCED",
            ),
            (Observation { peers: 0, ..base() }, "STALLED"),
        ] {
            let v = assess(&o);
            assert!(heartbeat_line(&o, &v).starts_with(expect));
        }
    }

    #[test]
    fn tracker_measures_idle_and_rate() {
        let mut t = Tracker::new(0, 0);
        for s in 1..=20u64 {
            t.observe(s * 100, s);
        }
        assert_eq!(t.idle_secs(20), 0);
        assert!(
            (t.blocks_per_sec(20) - 100.0).abs() < 1.0,
            "{}",
            t.blocks_per_sec(20)
        );

        t.observe(2000, 320);
        assert_eq!(t.idle_secs(320), 300);
    }
}

#[cfg(test)]
mod n1_stranded_reproduction {
    use plaine_chain::mock::{CountingPow, MemStore, MockClock, PowMode, Scenario};
    use plaine_chain::types::ChainParams;
    use plaine_chain::{BranchVerdict, ChainManager};
    use plaine_consensus::constants::{HEADER_BYTES, MAX_HEADERS_PER_MSG};
    use std::sync::Arc;

    const T0: u64 = 1_700_000_000;

    const WINNER: u64 = 72;
    const LOSER: u64 = 53;

    type Cm = ChainManager<MemStore, MemStore, CountingPow, MockClock>;

    fn two_forked_nodes(cap: u64) -> (Cm, Vec<[u8; HEADER_BYTES]>) {
        let p = ChainParams {
            max_reorg_depth: cap,
            ..ChainParams::default()
        };
        let root = Scenario::genesis(&p, T0);

        let winner = root.clone().spacing(30).extend(WINNER);
        let loser = root.clone().spacing(60).extend(LOSER);
        assert_ne!(
            winner.blocks[1].rec.hash, loser.blocks[1].rec.hash,
            "the fixture must fork at genesis"
        );

        let g = loser.blocks[0].clone();
        let store = Arc::new(MemStore::with_genesis(g.rec, g.body, &p));
        let mut cm = ChainManager::new(
            store.clone(),
            store.clone(),
            Arc::new(CountingPow::new(PowMode::AlwaysOk)),
            Arc::new(MockClock::new(
                winner.tip().time.max(loser.tip().time).max(T0),
            )),
            p,
            None,
        )
        .expect("boot invariants hold");

        let own: Vec<_> = loser.blocks.iter().skip(1).map(|b| b.rec.raw).collect();
        for part in own.chunks(MAX_HEADERS_PER_MSG) {
            cm.submit_headers_solicited(1, part).expect("own headers");
        }
        for b in loser.blocks.iter().skip(1) {
            cm.submit_block(&b.rec.hash, b.body.clone())
                .expect("own body");
        }
        while let Ok(plaine_chain::Progress::Advanced { .. }) = cm.advance() {}
        assert_eq!(
            cm.tip().height,
            LOSER,
            "the loser must be on its own branch"
        );

        let rival: Vec<_> = winner.blocks.iter().skip(1).map(|b| b.rec.raw).collect();
        (cm, rival)
    }

    #[test]
    fn arena_onbest_after_ingest_refused() {
        let cap = plaine_consensus::constants::MAX_REORG_DEPTH;
        assert!(LOSER > cap, "the fixture must exceed the cap ({cap})");
        let (mut cm, rival) = two_forked_nodes(cap);

        let mut why: Option<&'static str> = None;
        for part in rival.chunks(MAX_HEADERS_PER_MSG) {
            match cm.submit_headers(2, part) {
                Ok(a) => {
                    if let Some(r) = a.first_rejection {
                        why.get_or_insert(r.why);
                    }
                }
                Err(e) => {
                    why.get_or_insert(e.why());
                }
            }
        }
        let _ = cm.advance();

        let fork_too_deep = plaine_chain::error::Reject::ForkTooDeep { depth: 0, cap: 0 }.why();
        assert_eq!(
            why,
            Some(fork_too_deep),
            "expected the depth gate to refuse at ingest; if this changed, N1's \
             cause moved and the fallback below may no longer be the only route"
        );

        let b = cm.branch_report();
        assert_eq!(b.tip, LOSER);
        assert_eq!(
            b.verdict,
            BranchVerdict::OnBest,
            "the arena reports OnBest after ingest refused the better branch"
        );
    }

    #[test]
    fn stranded_says_stranded_not_peers() {
        let cap = plaine_consensus::constants::MAX_REORG_DEPTH;
        let (mut cm, rival) = two_forked_nodes(cap);
        for part in rival.chunks(MAX_HEADERS_PER_MSG) {
            let _ = cm.submit_headers(2, part);
        }
        let _ = cm.advance();

        let before = super::Observation {
            height: LOSER,
            best_known_height: Some(WINNER),
            idle_secs: super::STALL_AFTER_SECS + 60,
            gap_idle_secs: super::STALL_AFTER_SECS + 60,
            peers: 2,
            started: true,
            branch: Some(cm.branch_report()),
            transport_stranded: None,
            ..Default::default()
        };
        let r = super::assess(&before).reason.expect("a reason");
        assert!(
            r.contains("may not be serving blocks"),
            "before: without the transport report the wrong sentence is produced: {r}"
        );
        assert!(!r.contains("Stranded"), "BEFORE: {r}");

        let after = super::Observation {
            transport_stranded: Some(super::TransportStranded {
                our_tip: LOSER,
                their_tip: WINNER,
                depth: LOSER,
                cap,
            }),
            ..before
        };
        let v = super::assess(&after);
        assert_eq!(v.status, super::SyncStatus::Stalled);
        let r = v.reason.expect("a reason");
        assert!(r.contains("Stranded"), "AFTER: {r}");
        assert!(
            !r.contains("may not be serving blocks"),
            "after: the stranded arm must not blame the peers: {r}"
        );

        for n in [format!("{WINNER}"), format!("{LOSER}"), format!("{cap}")] {
            assert!(r.contains(&n), "AFTER: missing {n} in: {r}");
        }
        assert!(r.contains("SPEC.md"), "AFTER: no recovery document: {r}");
    }

    #[test]
    fn rejoined_node_not_kept_stranded() {
        let o = super::Observation {
            height: 100,
            best_known_height: Some(100),
            peers: 4,
            started: true,
            transport_stranded: None,
            branch: Some(plaine_chain::BranchReport {
                tip: 100,
                best: 100,
                best_hash: [0u8; 32],
                fork_height: 100,
                depth: 0,
                verdict: BranchVerdict::OnBest,
            }),
            ..Default::default()
        };
        assert_eq!(super::assess(&o).status, super::SyncStatus::Synced);
    }
}

#[cfg(test)]
mod n2_frozen_peer_reproduction {
    use super::{assess, backed_height, Observation, SyncStatus, Tracker, STALL_AFTER_SECS};

    const FOLLOWING: [u64; 10] = [100, 120, 140, 160, 180, 200, 220, 240, 260, 280];
    const STUCK: u64 = 53;

    #[test]
    fn backed_freezes_on_stuck_peer() {
        let mut t = Tracker::new(100, 0);
        let mut now = 0;
        for h in FOLLOWING {
            now += 30;

            let backed = backed_height(&[h, STUCK]);
            assert_eq!(backed, STUCK, "the anti-DoS rule returns the stuck peer");
            t.observe_top_claim(backed, now);
            t.observe(h.saturating_sub(50), now);
        }
        assert!(
            t.peer_height_idle_secs(now) >= STALL_AFTER_SECS,
            "the clock must have run out: {}",
            t.peer_height_idle_secs(now)
        );

        let o = Observation {
            height: 150,
            best_known_height: Some(150),
            idle_secs: 0,
            peer_height_idle_secs: t.peer_height_idle_secs(now),
            peers: 2,
            started: true,
            ..Default::default()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        assert!(
            v.reason.expect("a reason").contains("no peer's"),
            "BEFORE: the block producer calls its whole peer set frozen"
        );
    }

    #[test]
    fn top_claim_rearms_on_follower() {
        let mut t = Tracker::new(100, 0);
        let mut now = 0;
        for h in FOLLOWING {
            now += 30;
            let top = [h, STUCK].into_iter().max().expect("two claims");
            t.observe_top_claim(top, now);
            t.observe(h.saturating_sub(50), now);
        }
        assert_eq!(
            t.peer_height_idle_secs(now),
            0,
            "AFTER: the following peer rearms the clock"
        );
        let o = Observation {
            height: 150,
            best_known_height: Some(150),
            idle_secs: 0,
            peer_height_idle_secs: t.peer_height_idle_secs(now),
            peers: 2,
            started: true,
            ..Default::default()
        };
        assert_eq!(assess(&o).status, SyncStatus::Synced, "AFTER");
    }

    #[test]
    fn frozen_peer_set_is_stall() {
        let mut t = Tracker::new(100, 0);
        let mut now = 0;
        for _ in 0..10 {
            now += 30;
            t.observe_top_claim([426u64, 426].into_iter().max().expect("claims"), now);
            t.observe(430 + now / 30, now);
        }
        assert!(t.peer_height_idle_secs(now) >= STALL_AFTER_SECS);
        let o = Observation {
            height: 476,
            best_known_height: Some(476),
            idle_secs: 0,
            peer_height_idle_secs: t.peer_height_idle_secs(now),
            peers: 2,
            started: true,
            ..Default::default()
        };
        let v = assess(&o);
        assert_eq!(v.status, SyncStatus::Stalled);
        assert!(v.reason.expect("a reason").contains("no peer's"));
    }

    #[test]
    fn liar_cannot_move_backed() {
        assert_eq!(backed_height(&[5_000_000, 100, 101]), 101);
    }
}
