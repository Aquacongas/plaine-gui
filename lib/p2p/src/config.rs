use crate::constants::*;
use crate::traits::Hash32;

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub magic: [u8; 4],
    pub chain_id: [u8; 4],
    pub port: u16,
    pub seeds: Vec<String>,
    pub whitelist: Vec<[u8; 16]>,
    pub authority_keys: Vec<[u8; 32]>,
    pub checkpoint_threshold: usize,
    pub services: u32,
    pub user_agent: Vec<u8>,
    pub isolated: bool,
    pub accept_local_addrs: bool,
    pub verify_all_pow: bool,
    pub genesis: Hash32,
}

impl Default for P2pConfig {
    fn default() -> P2pConfig {
        P2pConfig {
            magic: MAGIC_MAIN,
            chain_id: CHAIN_ID,
            port: PORT_P2P,
            seeds: Vec::new(),
            whitelist: Vec::new(),
            authority_keys: Vec::new(),
            checkpoint_threshold: 1,
            services: SERVICE_FULL_RELAY,
            user_agent: b"plaine/0.1".to_vec(),
            isolated: cfg!(test),
            accept_local_addrs: cfg!(test),
            verify_all_pow: false,
            genesis: [0u8; 32],
        }
    }
}

impl P2pConfig {
    pub fn isolated() -> P2pConfig {
        P2pConfig {
            isolated: true,
            accept_local_addrs: true,
            ..P2pConfig::default()
        }
    }
}
