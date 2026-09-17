use crate::log;
use std::io::Write;
use std::path::Path;

pub fn load(path: &Path) -> Option<Vec<u8>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            log::warn(
                "p2p",
                format!("peers.dat cannot be read ({e}); using seeds only"),
            );
            return None;
        }
    };

    let cap = plaine_p2p::addr::persist::PEERS_FILE_MAX as u64;
    if meta.len() > cap {
        log::warn(
            "p2p",
            format!(
                "peers.dat is {} bytes, larger than the {cap} a full address book can be; ignored",
                meta.len()
            ),
        );
        return None;
    }
    match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) => {
            log::warn(
                "p2p",
                format!("peers.dat cannot be read ({e}); using seeds only"),
            );
            None
        }
    }
}

// temp file, fsync, then rename over the target. a crash mid-write leaves the old
// peers.dat intact instead of a truncated one.
pub fn store(path: &Path, bytes: &[u8]) -> bool {
    let tmp = path.with_extension("dat.new");
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;

        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        Ok(())
    };
    match write() {
        Ok(()) => true,
        Err(e) => {
            log::warn("p2p", format!("peers.dat could not be written ({e})"));
            let _ = std::fs::remove_file(&tmp);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "plaine-peersdat-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).expect("temp dir");
        d
    }

    #[test]
    fn missing_file_is_not_error() {
        let d = tmpdir("missing");
        assert!(load(&d.join("peers.dat")).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn roundtrip_and_temp_cleaned() {
        let d = tmpdir("roundtrip");
        let p = d.join("peers.dat");
        assert!(store(&p, b"hello"));
        assert_eq!(load(&p).as_deref(), Some(&b"hello"[..]));
        assert!(
            !d.join("peers.dat.new").exists(),
            "the temp file must be renamed away, not left beside the real one"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn second_write_replaces_first() {
        let d = tmpdir("replace");
        let p = d.join("peers.dat");
        assert!(store(&p, &[1u8; 4096]));
        assert!(store(&p, &[2u8; 8]));
        assert_eq!(load(&p).as_deref(), Some(&[2u8; 8][..]));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn oversized_file_refused() {
        let d = tmpdir("oversize");
        let p = d.join("peers.dat");
        let big = vec![0u8; plaine_p2p::addr::persist::PEERS_FILE_MAX + 1];
        std::fs::write(&p, &big).expect("write");
        assert!(load(&p).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
