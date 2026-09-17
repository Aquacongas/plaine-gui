use std::sync::OnceLock;

pub type ChainInfo = plaine_noded::DirectChainInfo;

pub type AccountInfo = plaine_noded::DirectAccountInfo;

pub type FeeSuggest = plaine_noded::DirectFeeSuggest;

#[derive(Debug, Clone)]
pub struct RpcTx {
    pub txid: String,
}

static DIRECT: OnceLock<plaine_noded::DirectApi> = OnceLock::new();

pub fn install_direct_api(api: plaine_noded::DirectApi) -> Result<(), String> {
    DIRECT
        .set(api)
        .map_err(|_| "direct node API is already installed".to_string())
}

fn direct() -> Result<&'static plaine_noded::DirectApi, String> {
    DIRECT
        .get()
        .ok_or_else(|| "embedded node direct API is not ready".to_string())
}

pub fn chain_get_info() -> Result<ChainInfo, String> {
    Ok(direct()?.chain_info())
}

pub fn account_get(address: &str) -> Result<AccountInfo, String> {
    direct()?.account(address)
}

pub fn fee_suggest() -> Result<FeeSuggest, String> {
    Ok(direct()?.fee_suggest())
}

pub fn mempool_get_by_sender(address: &str) -> Result<Vec<RpcTx>, String> {
    Ok(direct()?
        .mempool_by_sender(address)?
        .into_iter()
        .map(|tx| RpcTx { txid: tx.txid })
        .collect())
}

pub fn tx_send_raw(raw_hex: &str) -> Result<String, String> {
    direct()?.tx_send_raw(raw_hex)
}
