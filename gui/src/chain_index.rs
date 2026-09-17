use std::collections::HashSet;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::chain_history;
use crate::chain_history::ChainTx;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainState {
    pub last_scanned_height: u64,
    pub initialized: bool,
    pub txs: Vec<ChainTx>,
}

fn config_dir() -> Result<PathBuf, String> {
    ProjectDirs::from("net", "Plaine", "Plaine Wallet")
        .map(|p| p.config_dir().to_path_buf())
        .ok_or_else(|| "cannot determine Plaine Wallet config directory".to_string())
}

fn state_file(address: &str) -> Result<PathBuf, String> {
    Ok(config_dir()?.join(format!("chain-history-{address}.json")))
}

pub fn load(address: &str) -> ChainState {
    let Ok(file) = state_file(address) else {
        return ChainState::default();
    };

    let Ok(raw) = std::fs::read_to_string(file) else {
        return ChainState::default();
    };

    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save(address: &str, state: &ChainState) -> Result<(), String> {
    let dir = config_dir()?;

    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let file = state_file(address)?;

    let raw = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;

    let temp = file.with_extension("json.tmp");

    std::fs::write(&temp, raw).map_err(|e| e.to_string())?;

    std::fs::rename(&temp, &file).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn scan_to_height(
    reader: plaine_noded::HistoryReader,

    address: &str,

    target_height: u64,

    start_height: u64,
) -> Result<ChainState, String> {
    let mut state = load(address);

    let mut next = if state.initialized {
        state.last_scanned_height.saturating_add(1)
    } else {
        start_height
    };

    if next < start_height {
        next = start_height;
    }

    if next > target_height {
        return Ok(state);
    }

    let mut known: HashSet<String> = state.txs.iter().map(|tx| tx.txid.clone()).collect();

    for height in next..=target_height {
        let raw = reader
            .block_raw(height)
            .map_err(|e| format!("cannot read block {height} directly from node storage: {e}"))?;

        let found = chain_history::scan_block_bytes(&raw, address)
            .map_err(|e| format!("cannot scan block {height}: {e}"))?;

        for tx in found {
            if known.insert(tx.txid.clone()) {
                state.txs.push(tx);
            }
        }

        state.last_scanned_height = height;

        state.initialized = true;

        if height % 100 == 0 {
            save(address, &state)?;
        }
    }

    state.txs.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| b.block_time.cmp(&a.block_time))
    });

    save(address, &state)?;

    Ok(state)
}
