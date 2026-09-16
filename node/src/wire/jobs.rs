use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use plaine_stratum::job::{JobError, JobSource, SealOutcome, Template, TemplateBody};
use plaine_stratum::login::AddressBytes;
use plaine_stratum::target::Target;

use crate::validator::{Cmd, Query, SealVerdict, TemplatePlan};
use crate::wire::tip::TipCell;

pub const SEAL_DEADLINE: std::time::Duration = std::time::Duration::from_millis(250);

pub const TEMPLATE_DEADLINE: std::time::Duration = std::time::Duration::from_millis(2_000);

pub struct Templates {
    tx: tokio::sync::mpsc::Sender<Cmd>,
    tip: TipCell,
    cache: Mutex<Vec<(AddressBytes, u64, Arc<Template>)>>,
    next_id: AtomicU64,
}

impl Templates {
    pub fn new(tx: tokio::sync::mpsc::Sender<Cmd>, tip: TipCell) -> Arc<Templates> {
        Arc::new(Templates {
            tx,
            tip,
            cache: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        })
    }

    fn build(&self, recipient: &AddressBytes) -> Option<Arc<Template>> {
        let (reply, rx) = std::sync::mpsc::sync_channel(1);
        self.tx
            .try_send(Cmd::Ask(Query::Template(*recipient, reply)))
            .ok()?;
        let plan: TemplatePlan = rx.recv_timeout(TEMPLATE_DEADLINE).ok()??;
        let body: Arc<dyn TemplateBody> = Arc::new(NodeBody {
            tx: self.tx.clone(),
            plan: plan.clone(),
            tip: self.tip.clone(),
        });
        Some(Arc::new(Template {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            prefix: plan.prefix,
            height: plan.height,
            network_target: Target(plan.network_target),
            new_tip: true,
            body,
        }))
    }
}

impl JobSource for Templates {
    // cached per (recipient, tip epoch). a new epoch - the tip moved - drops the
    // stale ones, so a miner never works a template for an old parent.
    fn current(&self, recipient: &AddressBytes) -> Result<Arc<Template>, JobError> {
        let epoch = self.tip.get().epoch;
        {
            let c = self.cache.lock().expect("template cache");
            if let Some((_, _, t)) = c
                .iter()
                .find(|(a, e, _)| a == recipient && *e == epoch)
            {
                return Ok(Arc::clone(t));
            }
        }
        let t = self.build(recipient).ok_or(JobError::NotReady)?;
        let mut c = self.cache.lock().expect("template cache");
        c.retain(|(_, e, _)| *e == epoch);

        if c.len() >= plaine_stratum::limits::SOLO_TEMPLATE_LRU {
            c.remove(0);
        }
        c.push((*recipient, epoch, Arc::clone(&t)));
        Ok(t)
    }

    fn generation(&self) -> u64 {
        self.tip.get().epoch
    }
}

struct NodeBody {
    tx: tokio::sync::mpsc::Sender<Cmd>,
    plan: TemplatePlan,
    tip: TipCell,
}

impl TemplateBody for NodeBody {
    fn seal(&self, nonce: u64) -> SealOutcome {
        // cheap pre-check: tip already off this template's parent means the solve is
        // obsolete. skip the message to the validator.
        if self.tip.get().hash != self.plan.parent {
            return SealOutcome::Obsolete;
        }
        let mut header = [0u8; 132];
        header[..124].copy_from_slice(&self.plan.prefix);
        header[124..].copy_from_slice(&nonce.to_le_bytes());
        let (reply, rx) = std::sync::mpsc::sync_channel(1);
        if self
            .tx
            .try_send(Cmd::Seal { header, body: self.plan.body.clone(), reply })
            .is_err()
        {
            return SealOutcome::Obsolete;
        }
        match rx.recv_timeout(SEAL_DEADLINE) {
            Ok(SealVerdict::Accepted) => SealOutcome::Accepted,
            Ok(SealVerdict::Rejected) => SealOutcome::Rejected,
            Ok(SealVerdict::Obsolete) => SealOutcome::Obsolete,
            Err(_) => SealOutcome::Obsolete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moved_tip_seal_is_obsolete_no_msg() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Cmd>(4);
        let tip = TipCell::default();
        tip.publish(crate::wire::tip::TipView { hash: [9u8; 32], ..Default::default() });
        let b = NodeBody {
            tx,
            tip,
            plan: TemplatePlan {
                prefix: [0u8; 124],
                height: 1,
                network_target: [0xff; 32],
                body: vec![0],
                parent: [1u8; 32],
            },
        };
        assert_eq!(b.seal(7), SealOutcome::Obsolete);
        assert!(rx.is_empty(), "an obsolete template must not cost the validator a message");
    }

    #[test]
    fn unresponsive_validator_bounded_by_deadline() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Cmd>(4);
        let tip = TipCell::default();
        let b = NodeBody {
            tx,
            tip,
            plan: TemplatePlan {
                prefix: [0u8; 124],
                height: 1,
                network_target: [0xff; 32],
                body: vec![0],
                parent: [0u8; 32],
            },
        };
        let t0 = std::time::Instant::now();
        assert_eq!(b.seal(7), SealOutcome::Obsolete);
        assert!(t0.elapsed() < SEAL_DEADLINE * 3, "the seal must not wait indefinitely");
    }
}
