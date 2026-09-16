use crate::constants::*;
use crate::gate::g4_budget::TokenBucket;
use crate::peer::session::group_of;
use crate::traits::Mono;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Banned,
    PerIp,
    PerGroup,
    Reconnect,
    Rate,
    NoSlot,
    NoDescriptor,
}

#[derive(Debug, Default)]
pub struct BanSet {
    until: HashMap<[u8; 16], Mono>,
    order: std::collections::VecDeque<[u8; 16]>,
}

impl BanSet {
    pub fn new() -> BanSet {
        BanSet::default()
    }

    pub fn ban(&mut self, ip: [u8; 16], ms: u64, now: Mono) {
        if self.until.insert(ip, now.plus_ms(ms)).is_none() {
            self.order.push_back(ip);
            while self.order.len() > BANLIST_MAX {
                if let Some(old) = self.order.pop_front() {
                    self.until.remove(&old);
                }
            }
        }
    }

    pub fn banned(&self, ip: &[u8; 16], now: Mono) -> bool {
        match self.until.get(ip) {
            Some(t) => now < *t,
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.until.len()
    }

    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }
}

#[derive(Debug)]
pub struct ConnLimits {
    accept: TokenBucket,
    inbound_per_ip: HashMap<[u8; 16], u32>,
    inbound_per_group: HashMap<[u8; 4], u32>,
    outbound_per_group: HashMap<[u8; 4], u32>,
    reconnects: HashMap<[u8; 16], (u32, Mono)>,
}

impl ConnLimits {
    pub fn new(now: Mono) -> ConnLimits {
        ConnLimits {
            accept: TokenBucket::new(ACCEPT_BURST as u64, ACCEPT_RATE_PER_SEC as u64, now),
            inbound_per_ip: HashMap::new(),
            inbound_per_group: HashMap::new(),
            outbound_per_group: HashMap::new(),
            reconnects: HashMap::new(),
        }
    }

    pub fn admit_inbound(&mut self, ip: [u8; 16], now: Mono) -> Result<(), Refusal> {
        let g = group_of(&ip);
        if self.inbound_per_ip.get(&ip).copied().unwrap_or(0) >= INBOUND_PER_IP as u32 {
            return Err(Refusal::PerIp);
        }
        if self.inbound_per_group.get(&g).copied().unwrap_or(0) >= INBOUND_PER_GROUP as u32 {
            return Err(Refusal::PerGroup);
        }
        let e = self.reconnects.entry(ip).or_insert((0, now));
        if now.since(e.1) >= 60_000 {
            *e = (0, now);
        }
        if e.0 >= RECONNECT_PER_IP_PER_MIN {
            return Err(Refusal::Reconnect);
        }

        if !self.accept.take(1, now) {
            return Err(Refusal::Rate);
        }
        e.0 += 1;
        *self.inbound_per_ip.entry(ip).or_insert(0) += 1;
        *self.inbound_per_group.entry(g).or_insert(0) += 1;
        Ok(())
    }

    pub fn release_inbound(&mut self, ip: [u8; 16]) {
        let g = group_of(&ip);
        if let Some(n) = self.inbound_per_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.inbound_per_ip.remove(&ip);
            }
        }
        if let Some(n) = self.inbound_per_group.get_mut(&g) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.inbound_per_group.remove(&g);
            }
        }
    }

    pub fn admit_outbound(&mut self, ip: [u8; 16], widen: bool) -> Result<(), Refusal> {
        let cap = if widen {
            OUTBOUND_PER_GROUP_WIDENED
        } else {
            OUTBOUND_PER_GROUP
        } as u32;
        let g = group_of(&ip);
        let n = self.outbound_per_group.entry(g).or_insert(0);
        if *n >= cap {
            return Err(Refusal::PerGroup);
        }
        *n += 1;
        Ok(())
    }

    pub fn outbound_in_group(&self, g: &[u8; 4]) -> u32 {
        self.outbound_per_group.get(g).copied().unwrap_or(0)
    }

    pub fn release_outbound(&mut self, ip: [u8; 16]) {
        let g = group_of(&ip);
        if let Some(n) = self.outbound_per_group.get_mut(&g) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.outbound_per_group.remove(&g);
            }
        }
    }

    pub fn inbound_for(&self, ip: &[u8; 16]) -> u32 {
        self.inbound_per_ip.get(ip).copied().unwrap_or(0)
    }
}

pub fn ip_bytes(addr: &std::net::SocketAddr) -> [u8; 16] {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let mut o = [0u8; 16];
            o[10] = 0xff;
            o[11] = 0xff;
            o[12..16].copy_from_slice(&v4.octets());
            o
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}
