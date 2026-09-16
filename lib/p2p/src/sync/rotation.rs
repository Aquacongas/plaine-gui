use crate::constants::*;
use crate::peer::session::Session;
use crate::traits::{Mono, PeerId};

#[derive(Clone, Debug, Default)]
pub struct Rotator {
    charged: Vec<Mono>,
    last_group: Option<[u8; 4]>,
    designated_at: Option<Mono>,
    grant_headers: u64,
    since_none_eligible: Option<Mono>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Designation {
    Peer(PeerId),
    NoneYet,
    // no eligible peer, but liveness forces us to waive the rules for this one.
    Waive(PeerId),
}

impl Rotator {
    pub fn new() -> Rotator {
        Rotator::default()
    }

    pub fn charged_in_window(&self, now: Mono) -> u32 {
        self.charged
            .iter()
            .filter(|t| now.since(**t) < ROTATION_WINDOW_MS)
            .count() as u32
    }

    pub fn budget_available(&self, now: Mono) -> bool {
        self.charged_in_window(now) < ROTATION_BUDGET
    }

    pub fn charge(&mut self, now: Mono) {
        self.charged.push(now);
        self.charged.retain(|t| now.since(*t) < ROTATION_WINDOW_MS);
    }

    pub fn designate(&mut self, s: &Session, now: Mono) {
        self.last_group = Some(s.group);
        self.designated_at = Some(now);
        self.grant_headers = 0;
        self.since_none_eligible = None;
    }

    pub fn note_grant_headers(&mut self, n: u64) {
        self.grant_headers = self.grant_headers.saturating_add(n);
    }

    // a freshly designated peer that never showed a delivery rate loses the slot
    // once the grant runs out, in time or in headers, whichever comes first.
    pub fn probation_expired(&self, s: &Session, now: Mono) -> bool {
        if s.delivery_rate(now).is_some() {
            return false;
        }
        match self.designated_at {
            Some(t) => {
                now.expired(t, PROBE_GRANT_MS) || self.grant_headers >= PROBE_GRANT_HEADERS
            }
            None => false,
        }
    }

    pub fn select(
        &mut self,
        peers: &[&Session],
        now: Mono,
        ahead: &dyn Fn(&Session) -> bool,
    ) -> Designation {
        let eligible: Vec<&&Session> = peers
            .iter()
            .filter(|s| s.outbound && s.sync_eligible(now) && ahead(s))
            .collect();

        if !eligible.is_empty() {
            self.since_none_eligible = None;

            let mut best: Option<(&Session, u64, bool)> = None;
            for s in &eligible {
                let rate = s.delivery_rate(now);
                let proven = rate.is_some();
                let key = rate.unwrap_or(0);
                // Proven beats unproven, higher delivery rate wins. Never re-pick
                // the last group while another is free, so no single network can
                // monopolise our sync.
                let same_group = self.last_group == Some(s.group);
                let better = match best {
                    None => true,
                    Some((_, bk, bp)) => {
                        if same_group && eligible.len() > 1 {
                            false
                        } else if proven != bp {
                            proven
                        } else {
                            key > bk
                        }
                    }
                };
                if better {
                    best = Some((s, key, proven));
                }
            }
            if let Some((s, _, _)) = best {
                return Designation::Peer(s.id);
            }
        }

        // nobody qualified: rather than stall forever, waive the rules for the
        // peer we penalised least recently
        let started = *self.since_none_eligible.get_or_insert(now);
        if now.expired(started, SYNC_ELIGIBILITY_FLOOR_MS) {
            let victim = peers
                .iter()
                .filter(|s| {
                    s.outbound && s.is_ready() && !s.score.sync_disqualified() && ahead(s)
                })
                .min_by_key(|s| s.last_penalised.unwrap_or(Mono::ZERO));
            if let Some(v) = victim {
                self.since_none_eligible = None;
                return Designation::Waive(v.id);
            }
        }
        Designation::NoneYet
    }

    pub fn lonely_waiver(peers: &[&Session], now: Mono) -> Option<PeerId> {
        let ready: Vec<&&Session> = peers.iter().filter(|s| s.is_ready()).collect();
        if ready.len() != 1 {
            return None;
        }
        let only = ready[0];
        match only.sync_ineligible_until {
            Some(t) if now.since(t) == 0 => {
                if now.expired(only.connected_at, LONELY_WAIVER_MS) {
                    Some(only.id)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
