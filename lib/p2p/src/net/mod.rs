pub mod conn;
pub mod limits;
pub mod node;
pub mod sock;

pub use limits::{ip_bytes, BanSet, ConnLimits, Refusal};
pub use crate::engine::host::{NetNode, NetOptions, TickMode};
pub use node::{Net, PeerRow, PeerStat, Tier};

use crate::traits::{Clock, Mono};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl Default for SystemClock {
    fn default() -> SystemClock {
        SystemClock::new()
    }
}

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    fn mono(&self) -> Mono {
        Mono(self.origin.elapsed().as_millis() as u64)
    }
}
