use crate::constants::*;
use crate::traits::{ChainView, Hash32};
use crate::wire::msg::Msg;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::mpsc;

pub type Reply = Box<dyn FnOnce(Msg) + Send + 'static>;

pub enum ServeJob {
    Headers {
        locator: Vec<Hash32>,
        stop: Hash32,
        reply: Reply,
    },

    Body {
        hash: Hash32,
        reply: Reply,
    },

    Checkpoint {
        keys: Vec<[u8; 32]>,
        reply: Reply,
    },

    Tx {
        txid: Hash32,
        reply: Reply,
    },
}

#[derive(Debug)]
pub struct ServePool {
    inner: std::sync::Mutex<Option<Inner>>,
    next: AtomicUsize,
}

#[derive(Debug)]
struct Inner {
    txs: Vec<mpsc::Sender<ServeJob>>,
    handles: Vec<JoinHandle<()>>,
}

impl ServePool {
    pub fn spawn<C: ChainView>(chain: Arc<C>) -> ServePool {
        let mut txs = Vec::with_capacity(SERVE_THREADS);
        let mut handles = Vec::with_capacity(SERVE_THREADS);
        for i in 0..SERVE_THREADS {
            let (tx, mut rx) = mpsc::channel::<ServeJob>(SERVE_QUEUE_ITEMS);
            let chain = Arc::clone(&chain);
            let h = std::thread::Builder::new()
                .name(format!("p2p-serve-{i}"))
                .spawn(move || {
                    while let Some(job) = rx.blocking_recv() {
                        match job {
                            ServeJob::Headers {
                                locator,
                                stop,
                                reply,
                            } => {
                                let hs = chain.headers_from(&locator, &stop, MAX_HEADERS_PER_MSG);

                                if !hs.is_empty() {
                                    reply(Msg::Headers(hs));
                                }
                            }
                            ServeJob::Checkpoint { keys, reply } => {
                                if let Some(cp) = chain.anchor_record() {
                                    let sigs: Vec<(u8, [u8; 64])> = cp
                                        .sigs
                                        .iter()
                                        .filter_map(|s| {
                                            keys.iter()
                                                .position(|k| *k == s.pubkey)
                                                .map(|i| (i as u8, s.sig))
                                        })
                                        .collect();
                                    if !sigs.is_empty() {
                                        reply(Msg::Checkpoint(crate::wire::msg::CheckpointMsg {
                                            height: cp.height,
                                            hash: cp.hash,
                                            sigs,
                                        }));
                                    }
                                }
                            }
                            ServeJob::Tx { txid, reply } => match chain.tx_bytes(&txid) {
                                Some(b) => reply(Msg::Tx(b)),
                                None => reply(Msg::NotFound(vec![crate::wire::msg::InvItem {
                                    kind: crate::wire::msg::InvKind::Tx,
                                    hash: txid,
                                }])),
                            },
                            ServeJob::Body { hash, reply } => match chain.body_bytes(&hash) {
                                Some(b) => reply(Msg::Block(b)),
                                None => reply(Msg::NotFound(vec![crate::wire::msg::InvItem {
                                    kind: crate::wire::msg::InvKind::Block,
                                    hash,
                                }])),
                            },
                        }
                    }
                })
                .expect("spawn serve thread");
            txs.push(tx);
            handles.push(h);
        }
        ServePool {
            inner: std::sync::Mutex::new(Some(Inner { txs, handles })),
            next: AtomicUsize::new(0),
        }
    }

    pub fn submit(&self, job: ServeJob) -> bool {
        let g = self.inner.lock().expect("serve pool");
        let Some(inner) = g.as_ref() else {
            return false;
        };
        let n = inner.txs.len();
        if n == 0 {
            return false;
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut job = job;
        for k in 0..n {
            match inner.txs[(start + k) % n].try_send(job) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Full(j)) => job = j,
                Err(mpsc::error::TrySendError::Closed(j)) => job = j,
            }
        }
        false
    }

    pub fn shutdown(&self) {
        let inner = self.inner.lock().expect("serve pool").take();
        if let Some(inner) = inner {
            drop(inner.txs);
            for h in inner.handles {
                let _ = h.join();
            }
        }
    }
}
