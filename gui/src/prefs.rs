use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentTx {
    pub txid: String,
    pub to: String,
    pub amount_mile: u128,
    pub fee_mile: u128,
    pub nonce: u64,
    pub created_at: u64,
}

fn config_dir() -> Option<PathBuf> {
    ProjectDirs::from("net", "Plaine", "Plaine Wallet").map(|p| p.config_dir().to_path_buf())
}

fn last_wallet_file() -> Option<PathBuf> {
    config_dir().map(|p| p.join("last_wallet"))
}

fn history_file(address: &str) -> Option<PathBuf> {
    config_dir().map(|p| p.join(format!("history-{}.json", address)))
}

pub fn save_last_wallet(path: &Path) -> Result<(), String> {
    let Some(dir) = config_dir() else {
        return Err("cannot determine application config directory".to_string());
    };

    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let Some(file) = last_wallet_file() else {
        return Err("cannot determine last-wallet path".to_string());
    };

    std::fs::write(file, path.to_string_lossy().as_bytes()).map_err(|e| e.to_string())
}

pub fn load_last_wallet() -> Option<PathBuf> {
    let file = last_wallet_file()?;

    let raw = std::fs::read_to_string(file).ok()?;

    let raw = raw.trim();

    if raw.is_empty() {
        return None;
    }

    let path = PathBuf::from(raw);

    path.is_file().then_some(path)
}

pub fn load_history(address: &str) -> Vec<SentTx> {
    let Some(file) = history_file(address) else {
        return Vec::new();
    };

    let Ok(raw) = std::fs::read_to_string(file) else {
        return Vec::new();
    };

    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_history(address: &str, history: &[SentTx]) -> Result<(), String> {
    let Some(dir) = config_dir() else {
        return Err("cannot determine application config directory".to_string());
    };

    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let Some(file) = history_file(address) else {
        return Err("cannot determine transaction history path".to_string());
    };

    let raw = serde_json::to_string_pretty(history).map_err(|e| e.to_string())?;

    std::fs::write(file, raw).map_err(|e| e.to_string())
}

pub fn push_sent_tx(address: &str, tx: SentTx) -> Result<Vec<SentTx>, String> {
    let mut history = load_history(address);

    if !history.iter().any(|x| x.txid == tx.txid) {
        history.insert(0, tx);
    }

    // Keep the local history bounded.
    if history.len() > 100 {
        history.truncate(100);
    }

    save_history(address, &history)?;

    Ok(history)
}
