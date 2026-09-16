use crate::error::{Result, WalletError};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub time: u64,
    pub nonce: u64,
    pub txid: [u8; 32],
    pub payload_hash: [u8; 32],
    // absent on entries written before this build journalled the signed
    // message; a legacy entry like that always counts as a conflict
    pub msg_hash: Option<[u8; 32]>,
}

impl Entry {
    fn render(&self) -> String {
        let mut s = format!(
            "time={} nonce={} txid={} payload_b3={}",
            self.time,
            self.nonce,
            plaine_consensus::hex::encode(&self.txid),
            plaine_consensus::hex::encode(&self.payload_hash)
        );
        if let Some(m) = self.msg_hash {
            s.push_str(&format!(" msg_b3={}", plaine_consensus::hex::encode(&m)));
        }
        s.push('\n');
        s
    }

    fn is_the_same_statement(&self, msg_hash: &[u8; 32]) -> bool {
        match &self.msg_hash {
            Some(m) => crate::secret::ct_eq(m, msg_hash),
            None => false,
        }
    }

    pub fn predates_message_recording(&self) -> bool {
        self.msg_hash.is_none()
    }

    fn parse(line: &str, lineno: usize) -> Result<Entry> {
        let mut time = None;
        let mut nonce = None;
        let mut txid = None;
        let mut payload_hash = None;
        let mut msg_hash = None;
        for field in line.split_whitespace() {
            let Some((k, v)) = field.split_once('=') else {
                return Err(WalletError::format(format!(
                    "journal line {lineno}: field {field:?} is not key=value"
                )));
            };
            match k {
                "time" => time = Some(v.parse::<u64>().map_err(|_| bad(lineno, "time"))?),
                "nonce" => nonce = Some(v.parse::<u64>().map_err(|_| bad(lineno, "nonce"))?),
                "txid" => txid = Some(hash32(v, lineno, "txid")?),
                "payload_b3" => payload_hash = Some(hash32(v, lineno, "payload_b3")?),
                "msg_b3" => msg_hash = Some(hash32(v, lineno, "msg_b3")?),
                other => {
                    return Err(WalletError::format(format!(
                        "journal line {lineno}: unknown field {other:?}"
                    )))
                }
            }
        }
        Ok(Entry {
            time: time.ok_or_else(|| missing(lineno, "time"))?,
            nonce: nonce.ok_or_else(|| missing(lineno, "nonce"))?,
            txid: txid.ok_or_else(|| missing(lineno, "txid"))?,
            payload_hash: payload_hash.ok_or_else(|| missing(lineno, "payload_b3"))?,
            msg_hash,
        })
    }
}

fn bad(lineno: usize, field: &str) -> WalletError {
    WalletError::format(format!("journal line {lineno}: {field} is not a number"))
}

fn missing(lineno: usize, field: &str) -> WalletError {
    WalletError::format(format!("journal line {lineno}: missing {field}"))
}

fn hash32(v: &str, lineno: usize, field: &str) -> Result<[u8; 32]> {
    let bytes = plaine_consensus::hex::decode(v)
        .map_err(|e| WalletError::format(format!("journal line {lineno}: {field}: {e}")))?;
    bytes.as_slice().try_into().map_err(|_| {
        WalletError::format(format!("journal line {lineno}: {field} is not 32 bytes"))
    })
}

pub fn path_for(keyfile: &Path) -> PathBuf {
    let mut p = keyfile.as_os_str().to_os_string();
    p.push(".journal");
    PathBuf::from(p)
}

pub fn read(path: &Path) -> Result<Vec<Entry>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(WalletError::io(format!(
                "cannot read {}: {e}",
                path.display()
            )))
        }
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(Entry::parse(line, i + 1)?);
    }
    Ok(out)
}

pub fn append(path: &Path, entry: &Entry) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| WalletError::io(format!("cannot open {}: {e}", path.display())))?;
    f.write_all(entry.render().as_bytes())
        .map_err(|e| WalletError::io(format!("cannot append to {}: {e}", path.display())))?;
    Ok(())
}

// a nonce clashes only if a different signed message reused it; an identical
// retry is not a conflict
pub fn conflict<'a>(entries: &'a [Entry], nonce: u64, msg_hash: &[u8; 32]) -> Option<&'a Entry> {
    entries
        .iter()
        .find(|e| e.nonce == nonce && !e.is_the_same_statement(msg_hash))
}

pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    plaine_consensus::blake3::hash(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("plnj-{}-{}", name, crate::now_secs()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("k.plnekey")
    }

    #[test]
    fn journal_path_sits_beside_the_key_file() {
        let p = path_for(Path::new("/keys/author.plnekey"));
        assert!(p.to_string_lossy().ends_with("author.plnekey.journal"));
    }

    fn msg(fee: u128, nonce: u64, encoding: u8, payload: &[u8]) -> [u8; 32] {
        plaine_consensus::crypto::announcement_signing_message(
            plaine_consensus::constants::Network::Main,
            &[0x24u8; 32],
            fee,
            nonce,
            encoding,
            payload,
        )
        .unwrap()
    }

    fn entry(nonce: u64, fee: u128, encoding: u8, payload: &[u8]) -> Entry {
        Entry {
            time: 1_765_432_100,
            nonce,
            txid: [0xAB; 32],
            payload_hash: payload_hash(payload),
            msg_hash: Some(msg(fee, nonce, encoding, payload)),
        }
    }

    #[test]
    fn append_and_read_roundtrip() {
        let key = tmp("rt");
        let jp = path_for(&key);
        assert_eq!(read(&jp).unwrap().len(), 0, "missing file is an empty journal");
        let e = entry(7, 50_000, 1, b"hello");
        append(&jp, &e).unwrap();
        append(&jp, &Entry { nonce: 8, ..e.clone() }).unwrap();
        let back = read(&jp).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], e);
        assert_eq!(back[1].nonce, 8);
        std::fs::remove_dir_all(jp.parent().unwrap()).ok();
    }

    #[test]
    fn conflict_fires_on_signed_message_not_payload() {
        let entries = vec![entry(4, 50_000, 1, b"first message")];

        assert!(
            conflict(&entries, 4, &msg(50_000, 4, 1, b"first message")).is_none(),
            "a genuine retry is not a conflict"
        );

        assert!(conflict(&entries, 4, &msg(50_000, 4, 1, b"second message")).is_some());

        assert!(
            conflict(&entries, 4, &msg(900_000, 4, 1, b"first message")).is_some(),
            "same payload at a different fee is a second signed statement"
        );

        assert!(
            conflict(&entries, 4, &msg(50_000, 4, 2, b"first message")).is_some(),
            "same payload at a different encoding is a second signed statement"
        );

        assert!(conflict(&entries, 5, &msg(50_000, 5, 1, b"second message")).is_none());
    }

    #[test]
    fn entry_without_message_is_a_conflict() {
        let legacy = Entry {
            msg_hash: None,
            ..entry(4, 50_000, 1, b"first message")
        };
        assert!(legacy.predates_message_recording());
        let entries = vec![legacy];
        assert!(conflict(&entries, 4, &msg(50_000, 4, 1, b"first message")).is_some());
        assert!(conflict(&entries, 4, &msg(900_000, 4, 1, b"other")).is_some());
        assert!(conflict(&entries, 9, &msg(50_000, 9, 1, b"first message")).is_none());
    }

    #[test]
    fn line_without_msg_b3_still_parses() {
        let key = tmp("legacy");
        let jp = path_for(&key);
        std::fs::write(
            &jp,
            format!(
                "time=1 nonce=3 txid={} payload_b3={}\n",
                plaine_consensus::hex::encode(&[0xABu8; 32]),
                plaine_consensus::hex::encode(&payload_hash(b"old"))
            ),
        )
        .unwrap();
        let back = read(&jp).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].msg_hash, None);
        assert_eq!(back[0].nonce, 3);
        std::fs::remove_dir_all(jp.parent().unwrap()).ok();
    }

    #[test]
    fn journal_holds_no_secret_material() {
        let key = tmp("nosecret");
        let jp = path_for(&key);
        let e = entry(0, 50_000, 1, b"x");
        append(&jp, &e).unwrap();
        let text = std::fs::read_to_string(&jp).unwrap();
        assert!(!text.contains(crate::keyfile::MAGIC));

        let hexes: Vec<&str> = text
            .split_whitespace()
            .filter_map(|f| f.split_once('='))
            .filter(|(_, v)| v.len() == 64)
            .map(|(k, _)| k)
            .collect();
        assert_eq!(hexes, vec!["txid", "payload_b3", "msg_b3"]);
        std::fs::remove_dir_all(jp.parent().unwrap()).ok();
    }

    #[test]
    fn a_corrupt_line_is_named() {
        let key = tmp("corrupt");
        let jp = path_for(&key);
        std::fs::write(&jp, "time=1 nonce=x txid=00 payload_b3=00\n").unwrap();
        let err = read(&jp).unwrap_err();
        assert!(err.to_string().contains("journal line 1"));
        std::fs::remove_dir_all(jp.parent().unwrap()).ok();
    }
}
