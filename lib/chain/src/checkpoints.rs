use plaine_consensus::rules::{
    anchor_supersedes, checkpoint_admission, verify_checkpoint, Anchor, ChainView,
    CheckpointAdmission, SignedCheckpoint,
};

use crate::error::Condition;
use crate::types::{ChainParams, Hash32};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointOutcome {
    Unverified,
    GenesisImmutable,
    NotHeldYet,
    Admitted,
    StoredAsAnchor,
    AnchorNotSuperseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointReport {
    pub outcome: CheckpointOutcome,
    pub anchor_advanced: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Checkpoints {
    enforced: Vec<(u64, Hash32)>,
    anchor: Option<Anchor>,
    anchor_record: Option<SignedCheckpoint>,
}

impl Checkpoints {
    pub fn new() -> Checkpoints {
        Checkpoints::default()
    }

    pub fn enforced(&self) -> &[(u64, Hash32)] {
        &self.enforced
    }

    pub fn anchor(&self) -> Option<&Anchor> {
        self.anchor.as_ref()
    }

    pub fn anchor_record(&self) -> Option<&SignedCheckpoint> {
        self.anchor_record.as_ref()
    }

    pub fn load_anchor(&mut self, cp: &SignedCheckpoint, params: &ChainParams) -> bool {
        if !verify_checkpoint(cp, &params.authority_keys, params.checkpoint_threshold) {
            return false;
        }

        self.install_anchor(cp)
    }

    pub fn submit<V: ChainView>(
        &mut self,
        cp: &SignedCheckpoint,
        view: &V,
        params: &ChainParams,
        observe: &mut dyn FnMut(Condition),
    ) -> CheckpointReport {
        let report = |outcome, anchor_advanced| CheckpointReport {
            outcome,
            anchor_advanced,
        };
        if !verify_checkpoint(cp, &params.authority_keys, params.checkpoint_threshold) {
            return report(CheckpointOutcome::Unverified, false);
        }
        match checkpoint_admission(view, cp.height, &cp.hash) {
            CheckpointAdmission::GenesisImmutable => {
                report(CheckpointOutcome::GenesisImmutable, false)
            }
            // height we don't hold yet: recovery anchor only, no enforcement entry
            // until we reach it.
            CheckpointAdmission::NotHeldYet => {
                if self.install_anchor(cp) {
                    report(CheckpointOutcome::NotHeldYet, true)
                } else {
                    report(CheckpointOutcome::AnchorNotSuperseded, false)
                }
            }
            CheckpointAdmission::Admit => {
                if !self.enforced.iter().any(|(h, _)| *h == cp.height) {
                    self.enforced.push((cp.height, cp.hash));
                    self.enforced.sort_unstable();
                }

                let advanced = self.install_anchor(cp);
                report(CheckpointOutcome::Admitted, advanced)
            }
            CheckpointAdmission::HashConflict => {
                observe(Condition::AnchorContradiction {
                    height: cp.height,
                    hash: cp.hash,
                });
                if self.install_anchor(cp) {
                    report(CheckpointOutcome::StoredAsAnchor, true)
                } else {
                    report(CheckpointOutcome::AnchorNotSuperseded, false)
                }
            }
        }
    }

    // Anchor only moves forward; the supersede check drops stale or replayed records.
    fn install_anchor(&mut self, cp: &SignedCheckpoint) -> bool {
        let cand = Anchor {
            height: cp.height,
            hash: cp.hash,
        };
        if anchor_supersedes(self.anchor.as_ref(), &cand) {
            self.anchor = Some(cand);

            self.anchor_record = Some(cp.clone());
            true
        } else {
            false
        }
    }
}
