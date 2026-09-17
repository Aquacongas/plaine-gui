use serde::{Deserialize, Serialize};

use plaine_consensus::codec::{BlockBody, Header, Tx};

use plaine_consensus::constants::HEADER_BYTES;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
    Mining,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTx {
    pub txid: String,
    pub direction: Direction,

    pub from: Option<String>,
    pub to: String,

    pub amount_mile: u128,
    pub fee_mile: u128,

    pub nonce: Option<u64>,

    pub height: u64,
    pub block_time: u64,
}

pub fn scan_block_bytes(raw: &[u8], wallet_address: &str) -> Result<Vec<ChainTx>, String> {
    if raw.len() < HEADER_BYTES {
        return Err("raw block shorter than header".into());
    }

    let header =
        Header::decode(&raw[..HEADER_BYTES]).map_err(|e| format!("header decode failed: {e}"))?;

    let body = BlockBody::parse(&raw[HEADER_BYTES..])
        .map_err(|e| format!("block body decode failed: {e}"))?;

    let wallet_payload = plaine_consensus::crypto::decode_address(wallet_address)
        .map_err(|e| format!("wallet address decode failed: {e}"))?;

    let mut result = Vec::new();

    for i in 0..body.len() {
        let Some(decoded) = body.decode_tx(i) else {
            continue;
        };

        let tx = decoded.map_err(|e| {
            format!(
                "tx decode failed at block {} index {}: {e}",
                header.height, i
            )
        })?;

        match tx {
            Tx::Transfer(t) => {
                let sender_payload = plaine_consensus::crypto::address_payload(&t.from_pub);

                let sender = plaine_consensus::crypto::encode_address(&sender_payload);

                let recipient = plaine_consensus::crypto::encode_address(&t.to);

                let direction = if sender_payload == wallet_payload {
                    Direction::Outgoing
                } else if t.to == wallet_payload {
                    Direction::Incoming
                } else {
                    continue;
                };

                result.push(ChainTx {
                    txid: plaine_consensus::hex::encode(&t.txid()),

                    direction,

                    from: Some(sender),

                    to: recipient,

                    amount_mile: t.amount,

                    fee_mile: t.fee,

                    nonce: Some(t.nonce),

                    height: header.height,

                    block_time: header.time,
                });
            }

            Tx::Coinbase(c) => {
                if c.to != wallet_payload {
                    continue;
                }

                let txid = c.txid().map_err(|e| format!("coinbase txid failed: {e}"))?;

                result.push(ChainTx {
                    txid: plaine_consensus::hex::encode(&txid),

                    direction: Direction::Mining,

                    from: None,

                    to: plaine_consensus::crypto::encode_address(&c.to),

                    amount_mile: c.reward.saturating_add(c.fees),

                    fee_mile: 0,

                    nonce: None,

                    height: header.height,

                    block_time: header.time,
                });
            }

            Tx::Announcement(_) => {}
        }
    }

    Ok(result)
}
