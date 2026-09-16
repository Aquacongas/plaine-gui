use crate::traits::TipSnapshot;
use tokio::sync::watch;

#[derive(Debug)]
pub struct TipPublisher {
    tx: watch::Sender<TipSnapshot>,
}

#[derive(Clone, Debug)]
pub struct TipReader {
    rx: watch::Receiver<TipSnapshot>,
}

pub fn channel(initial: TipSnapshot) -> (TipPublisher, TipReader) {
    let (tx, rx) = watch::channel(initial);
    (TipPublisher { tx }, TipReader { rx })
}

impl TipPublisher {
    pub fn publish(&self, snap: TipSnapshot) {
        let _ = self.tx.send(snap);
    }
}

impl TipReader {
    pub fn tip(&self) -> TipSnapshot {
        *self.rx.borrow()
    }
}
