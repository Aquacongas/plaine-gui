use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default)]
pub struct TipView {
    pub height: u64,
    pub hash: [u8; 32],
    pub time: u64,
    pub chainwork: [u8; 32],
    pub epoch: u64,
    pub mempool_txs: usize,
    pub halted: Option<&'static str>,
}

#[derive(Clone)]
pub struct TipCell(Arc<RwLock<Arc<TipView>>>);

impl Default for TipCell {
    fn default() -> Self {
        TipCell::new(TipView::default())
    }
}

impl TipCell {
    pub fn new(v: TipView) -> TipCell {
        TipCell(Arc::new(RwLock::new(Arc::new(v))))
    }

    pub fn get(&self) -> Arc<TipView> {
        self.0.read().expect("tip cell").clone()
    }

    // swap a whole new Arc in rather than mutate in place. a reader already holding
    // a snapshot keeps its consistent view of the old tip.
    pub fn publish(&self, v: TipView) {
        *self.0.write().expect("tip cell") = Arc::new(v);
    }

    pub fn height(&self) -> u64 {
        self.get().height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_does_not_mutate_old_snapshot() {
        let cell = TipCell::default();
        let old = cell.get();
        cell.publish(TipView {
            height: 7,
            ..TipView::default()
        });

        assert_eq!(old.height, 0);
        assert_eq!(cell.height(), 7);
    }
}
