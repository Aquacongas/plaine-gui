use crate::constants::*;
use crate::rng::Rng;
use crate::traits::{Anchor, Hash32, HeaderRec, PeerId, PowVerifier};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Staged {
    pub rec: HeaderRec,
    pub from: PeerId,
    pub verified: bool,
    pub fast_forwarded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Idle,
    Verified { rec: HeaderRec, from: PeerId },
    FastForwarded { rec: HeaderRec, from: PeerId },
    BadPow { rec: HeaderRec, from: PeerId },
    AnchorMismatch { height: u64, got: Hash32, from: PeerId },
}

#[derive(Debug)]
pub struct Staging {
    queue: VecDeque<Staged>,
    index: HashMap<Hash32, HeaderRec>,
    verified_height: u64,
    verified_tip: Hash32,
    rng: Rng,
    // headers left to skip before the next sampled pow check below the anchor.
    countdown: u64,
    pub pow_calls: u64,
    pub fast_forwarded: u64,
}

impl Staging {
    pub fn new(verified_height: u64, verified_tip: Hash32, seed: u64) -> Staging {
        let mut rng = Rng::new(seed);
        let countdown = rng.below(FF_SAMPLE_RATE);
        Staging {
            queue: VecDeque::new(),
            index: HashMap::new(),
            verified_height,
            verified_tip,
            rng,
            countdown,
            pow_calls: 0,
            fast_forwarded: 0,
        }
    }

    pub fn staged_len(&self) -> u64 {
        self.queue.len() as u64
    }

    pub fn staged_bytes(&self) -> u64 {
        self.staged_len() * HEADER_BYTES as u64
    }

    pub fn verified_height(&self) -> u64 {
        self.verified_height
    }

    pub fn verified_tip(&self) -> Hash32 {
        self.verified_tip
    }

    pub fn staged_height(&self) -> u64 {
        self.queue
            .back()
            .map(|s| s.rec.height)
            .unwrap_or(self.verified_height)
    }

    pub fn staged_tip(&self) -> Hash32 {
        self.queue
            .back()
            .map(|s| s.rec.hash)
            .unwrap_or(self.verified_tip)
    }

    pub fn contains(&self, h: &Hash32) -> bool {
        self.index.contains_key(h)
    }

    pub fn get(&self, h: &Hash32) -> Option<HeaderRec> {
        self.index.get(h).copied()
    }

    pub fn front_from(&self) -> Option<PeerId> {
        self.queue.front().map(|s| s.from)
    }

    pub fn can_stage(&self) -> bool {
        self.staged_len() < PRESYNC_LEAD_HEADERS
    }

    pub fn push(&mut self, h: HeaderRec, from: PeerId) -> bool {
        if !self.can_stage() {
            return false;
        }
        self.index.insert(h.hash, h);
        self.queue.push_back(Staged {
            rec: h,
            from,
            verified: false,
            fast_forwarded: false,
        });
        true
    }

    pub fn front_costs_interpreter(&self, anchor: Option<&Anchor>, verify_all: bool) -> bool {
        let Some(s) = self.queue.front() else {
            return false;
        };
        if s.verified {
            return false;
        }
        if let Some(a) = anchor {
            if s.rec.height == a.height {
                return false;
            }
            if s.rec.height < a.height && !verify_all {
                return self.countdown == 0;
            }
        }
        true
    }

    pub fn verify_step<V: PowVerifier + ?Sized>(
        &mut self,
        pow: &V,
        anchor: Option<&Anchor>,
        verify_all: bool,
    ) -> VerifyOutcome {
        let Some(s) = self.queue.front().copied() else {
            return VerifyOutcome::Idle;
        };
        let h = s.rec;

        if s.verified {
            return VerifyOutcome::Verified { rec: h, from: s.from };
        }

        if let Some(a) = anchor {
            if h.height == a.height {
                // At the anchor height the hash must equal the signed checkpoint.
                // A mismatch means the whole staged branch contradicts it: drop it.
                if h.hash != a.hash {
                    let got = h.hash;
                    self.clear();
                    return VerifyOutcome::AnchorMismatch {
                        height: h.height,
                        got,
                        from: s.from,
                    };
                }

                self.mark_front_verified();
                return VerifyOutcome::Verified { rec: h, from: s.from };
            }
            // below the anchor the checkpoint vouches for the work; skip pow on
            // most headers, spot-check a random 1-in-N so a liar stays cheap to catch
            if h.height < a.height && !verify_all {
                if self.countdown == 0 {
                    self.countdown = self.rng.below(FF_SAMPLE_RATE);
                    self.pow_calls += 1;
                    if !pow.verify(&h.raw) {
                        self.pop_front();
                        return VerifyOutcome::BadPow { rec: h, from: s.from };
                    }
                } else {
                    self.countdown -= 1;
                }
                self.mark_front_verified();
                if let Some(f) = self.queue.front_mut() {
                    f.fast_forwarded = true;
                }
                return VerifyOutcome::FastForwarded { rec: h, from: s.from };
            }
        }

        self.pow_calls += 1;
        if !pow.verify(&h.raw) {
            self.pop_front();
            return VerifyOutcome::BadPow { rec: h, from: s.from };
        }
        self.mark_front_verified();
        VerifyOutcome::Verified { rec: h, from: s.from }
    }

    pub fn commit_front(&mut self) -> Option<HeaderRec> {
        let s = self.pop_front()?;
        if s.fast_forwarded {
            self.fast_forwarded += 1;
        }
        self.verified_height = s.rec.height;
        self.verified_tip = s.rec.hash;
        Some(s.rec)
    }

    fn mark_front_verified(&mut self) {
        if let Some(s) = self.queue.front_mut() {
            s.verified = true;
        }
    }

    fn pop_front(&mut self) -> Option<Staged> {
        let s = self.queue.pop_front()?;
        self.index.remove(&s.rec.hash);
        Some(s)
    }

    pub fn truncate_from(&mut self, height: u64) {
        let index = &mut self.index;
        self.queue.retain(|s| {
            if s.rec.height >= height {
                index.remove(&s.rec.hash);
                false
            } else {
                true
            }
        });
    }

    pub fn clear(&mut self) {
        self.queue.clear();
        self.index.clear();
    }

    pub fn survives_rotation(&self) -> u64 {
        self.staged_len()
    }
}
