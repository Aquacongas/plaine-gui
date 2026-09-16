use crate::constants::*;
use crate::gate::RejectCache;
use crate::traits::{Hash32, Mono, PeerId};

#[derive(Debug)]
pub struct AuditPass(());

impl AuditPass {
    pub(in crate::sync) fn new() -> AuditPass {
        AuditPass(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Quarantine {
    entries: Vec<(Hash32, Mono, Vec<PeerId>)>,
}

impl Quarantine {
    pub fn new() -> Quarantine {
        Quarantine::default()
    }

    pub fn insert(&mut self, branch: Hash32, peers: Vec<PeerId>, now: Mono) {
        self.entries.retain(|(h, _, _)| *h != branch);
        self.entries
            .push((branch, now.plus_ms(QUARANTINE_MS), peers));
        if self.entries.len() > QUARANTINE_MAX {
            self.entries.remove(0);
        }
    }

    pub fn contains(&self, branch: &Hash32, now: Mono) -> bool {
        self.entries
            .iter()
            .any(|(h, until, _)| h == branch && *until > now)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn peers(&self, branch: &Hash32) -> Vec<PeerId> {
        self.entries
            .iter()
            .find(|(h, _, _)| h == branch)
            .map(|(_, _, p)| p.clone())
            .unwrap_or_default()
    }

    pub fn audit_expire(&mut self, now: Mono, _pass: &AuditPass) {
        self.entries.retain(|(_, until, _)| *until > now);
    }

    pub fn audit_clear(&mut self, _pass: &AuditPass) {
        self.entries.clear();
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecoveryGuard {
    failures: Vec<Mono>,
}

impl RecoveryGuard {
    pub fn new() -> RecoveryGuard {
        RecoveryGuard::default()
    }

    pub fn note_failure(&mut self, now: Mono) {
        self.failures.push(now);
        self.failures
            .retain(|t| now.since(*t) < RECOVERY_FLAP_WINDOW_MS);
    }

    pub fn flapping(&self, now: Mono) -> bool {
        self.failures
            .iter()
            .filter(|t| now.since(**t) < RECOVERY_FLAP_WINDOW_MS)
            .count() as u32
            >= RECOVERY_FLAP_LIMIT
    }

    pub fn recent_failures(&self, now: Mono) -> u32 {
        self.failures
            .iter()
            .filter(|t| now.since(**t) < RECOVERY_FLAP_WINDOW_MS)
            .count() as u32
    }
}

pub struct Audit;

impl Audit {
    pub fn tick(q: &mut Quarantine, now: Mono) {
        let pass = AuditPass::new();
        q.audit_expire(now, &pass);
    }

    pub fn on_anchor_advanced(q: &mut Quarantine, rc: &mut RejectCache) {
        let pass = AuditPass::new();
        q.audit_clear(&pass);
        rc.audit_clear(&pass);
    }
}
