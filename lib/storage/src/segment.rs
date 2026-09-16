use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use plaine_consensus::constants::HEADER_BYTES;

use crate::error::StoreError;
use crate::layout;
use crate::posio;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegKind {
    Header,
    Body,
    Bidx,
}

impl SegKind {
    fn path(self, root: &Path, seg: u32) -> PathBuf {
        match self {
            Self::Header => layout::hdr_seg_path(root, seg),
            Self::Body => layout::body_seg_path(root, seg),
            Self::Bidx => layout::bidx_path(root, seg),
        }
    }
}

pub struct FdCache {
    root: PathBuf,
    cap: usize,
    open: Mutex<CacheInner>,
}

struct CacheInner {
    map: HashMap<(SegKind, u32), Arc<Mutex<File>>>,
    order: Vec<(SegKind, u32)>,
}

impl FdCache {
    pub fn new(root: PathBuf, cap: usize) -> Self {
        Self {
            root,
            cap: cap.max(4),
            open: Mutex::new(CacheInner {
                map: HashMap::new(),
                order: Vec::new(),
            }),
        }
    }

    pub fn open_count(&self) -> usize {
        self.open.lock().expect("fd cache poisoned").map.len()
    }

    pub fn get(&self, kind: SegKind, seg: u32) -> Result<Option<Arc<Mutex<File>>>, StoreError> {
        let key = (kind, seg);
        {
            let mut c = self.open.lock().expect("fd cache poisoned");
            if let Some(f) = c.map.get(&key).cloned() {
                if let Some(p) = c.order.iter().position(|k| *k == key) {
                    let k = c.order.remove(p);
                    c.order.push(k);
                }
                return Ok(Some(f));
            }
        }
        let path = kind.path(&self.root, seg);
        let file = match posio::open_ro(&path) {
            Ok(f) => f,
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let arc = Arc::new(Mutex::new(file));
        let mut c = self.open.lock().expect("fd cache poisoned");

        while c.map.len() >= self.cap && !c.order.is_empty() {
            let victim = c.order.remove(0);
            c.map.remove(&victim);
        }
        c.map.insert(key, arc.clone());
        c.order.push(key);
        Ok(Some(arc))
    }

    pub fn evict(&self, kind: SegKind, seg: u32) {
        let mut c = self.open.lock().expect("fd cache poisoned");
        c.map.remove(&(kind, seg));
        c.order.retain(|k| *k != (kind, seg));
    }

    pub fn evict_all(&self) {
        let mut c = self.open.lock().expect("fd cache poisoned");
        c.map.clear();
        c.order.clear();
    }
}

pub fn read_header(f: &File, height: u64) -> Result<Option<[u8; HEADER_BYTES]>, StoreError> {
    let mut buf = [0u8; HEADER_BYTES];
    let n = posio::pread(f, layout::hdr_offset(height), &mut buf)?;
    if n != HEADER_BYTES {
        return Ok(None);
    }
    Ok(Some(buf))
}

pub type Frames = Vec<(u32, u32, u32)>;

// Walk frames until one fails its length or CRC, then stop. The returned offset
// is the end of the last good frame - i.e. where a torn tail gets truncated back.
pub fn scan_body_segment(f: &File, limit_slots: u64) -> Result<(Frames, u64), StoreError> {
    let mut out: Frames = Vec::new();
    let mut off: u64 = 0;
    let mut payload = Vec::new();
    while (out.len() as u64) < limit_slots {
        let mut fh = [0u8; 8];
        if posio::pread(f, off, &mut fh)? != 8 {
            break;
        }
        let (len, crc) = crate::codec::decode_frame_header(&fh);

        if len as usize > crate::MAX_BODY_BYTES {
            break;
        }
        payload.clear();
        payload.resize(len as usize, 0);
        if posio::pread(f, off + 8, &mut payload)? != len as usize {
            break;
        }
        if crate::crc32c::crc32c(&payload) != crc {
            break;
        }
        if off + 8 + len as u64 > u32::MAX as u64 {
            break;
        }
        out.push((off as u32, len, crc));
        off += 8 + len as u64;
    }
    Ok((out, off))
}
