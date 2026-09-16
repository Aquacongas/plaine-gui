use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

#[cfg(not(any(unix, windows)))]
compile_error!("plaine-storage needs positional file I/O; only unix and windows are supported");

#[inline]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        f.read_at(buf, off)
    }
    #[cfg(windows)]
    {
        f.seek_read(buf, off)
    }
}

#[inline]
fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        f.write_at(buf, off)
    }
    #[cfg(windows)]
    {
        f.seek_write(buf, off)
    }
}

pub fn pread_exact(f: &File, off: u64, buf: &mut [u8]) -> io::Result<()> {
    let n = pread(f, off, buf)?;
    if n != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short positional read",
        ));
    }
    Ok(())
}

pub fn pread(f: &File, mut off: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        match read_at(f, &mut buf[done..], off) {
            Ok(0) => break,
            Ok(n) => {
                done += n;
                off += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

pub fn pwrite_all(f: &File, mut off: u64, buf: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        match write_at(f, &buf[done..], off) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "positional write made no progress",
                ))
            }
            Ok(n) => {
                done += n;
                off += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

static BARRIERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn barriers_performed() -> u64 {
    BARRIERS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn sync_data(f: &File) -> io::Result<()> {
    f.sync_data()?;
    BARRIERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

// A freshly created file isn't durable until its directory entry is fsynced too.
// Unix needs this explicitly; on Windows the create handle already covers it.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

pub fn open_rw_create(path: &Path) -> io::Result<(File, bool)> {
    let existed = path.exists();
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    Ok((f, !existed))
}

pub fn open_ro(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_data_really_calls_the_os() {
        let p = std::env::temp_dir().join(format!("plaine-posio-{}.probe", std::process::id()));
        {
            let (f, _) = open_rw_create(&p).expect("create");
            pwrite_all(&f, 0, b"barrier").expect("write");
            sync_data(&f).expect("a writable handle must flush");
        }
        let before = barriers_performed();
        let ro = open_ro(&p).expect("reopen read-only");
        let got = sync_data(&ro);
        #[cfg(windows)]
        assert!(
            got.is_err(),
            "sync_data returned Ok on a read-only handle: it did not reach the OS"
        );
        #[cfg(not(windows))]
        assert!(
            got.is_ok() && barriers_performed() > before,
            "sync_data neither flushed nor counted"
        );
        let _ = got;
        let _ = before;

        #[cfg(target_os = "linux")]
        {
            let devnull = OpenOptions::new()
                .read(true)
                .open("/dev/null")
                .expect("open /dev/null");
            assert!(
                sync_data(&devnull).is_err(),
                "sync_data returned Ok on /dev/null; fdatasync there is EINVAL, so the body did not reach the OS"
            );
        }
        drop(ro);
        let _ = std::fs::remove_file(&p);
    }
}
