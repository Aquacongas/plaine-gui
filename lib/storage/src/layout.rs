use std::path::{Path, PathBuf};

use plaine_consensus::constants::HEADER_BYTES;

// Segments are sized by block count, not bytes. That keeps seg = height >> 12
// pure arithmetic, so there is no height->offset index to keep in redb.
pub const SEG_SHIFT: u32 = 12;

// 4096 blocks per segment. This is also the prune granularity, ~2.8 days.
pub const SEG_BLOCKS: u64 = 1 << SEG_SHIFT;

pub const SEG_MASK: u64 = SEG_BLOCKS - 1;

pub const HDR_SEG_BYTES: u64 = (HEADER_BYTES as u64) * SEG_BLOCKS;

pub const BIDX_ENTRY_BYTES: u64 = 8;

pub const BIDX_SEG_BYTES: u64 = BIDX_ENTRY_BYTES * SEG_BLOCKS;

// Granularity of the reorg header undo: whole sectors. A 132-byte header can
// straddle a 4 KiB boundary, so in-place overwrites are staged sector at a time.
pub const SECTOR: u64 = 4096;

#[inline]
pub fn seg_of(h: u64) -> u32 {
    (h >> SEG_SHIFT) as u32
}

#[inline]
pub fn slot_of(h: u64) -> u64 {
    h & SEG_MASK
}

#[inline]
pub fn hdr_offset(h: u64) -> u64 {
    slot_of(h) * HEADER_BYTES as u64
}

#[inline]
pub fn bidx_offset(h: u64) -> u64 {
    slot_of(h) * BIDX_ENTRY_BYTES
}

#[inline]
pub fn seg_first_height(s: u32) -> u64 {
    (s as u64) << SEG_SHIFT
}

pub fn hdr_dir(root: &Path) -> PathBuf {
    root.join("segments").join("hdr")
}

pub fn body_dir(root: &Path) -> PathBuf {
    root.join("segments").join("body")
}

pub fn hdr_seg_path(root: &Path, s: u32) -> PathBuf {
    hdr_dir(root).join(format!("{s:06x}.hseg"))
}

pub fn body_seg_path(root: &Path, s: u32) -> PathBuf {
    body_dir(root).join(format!("{s:06x}.bseg"))
}

pub fn bidx_path(root: &Path, s: u32) -> PathBuf {
    body_dir(root).join(format!("{s:06x}.bidx"))
}

pub fn db_path(root: &Path) -> PathBuf {
    root.join("chain.redb")
}

pub fn lock_path(root: &Path) -> PathBuf {
    root.join("LOCK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_is_arithmetic() {
        assert_eq!(seg_of(0), 0);
        assert_eq!(seg_of(4095), 0);
        assert_eq!(seg_of(4096), 1);
        assert_eq!(hdr_offset(4096), 0);
        assert_eq!(hdr_offset(4097), 132);
        assert_eq!(HDR_SEG_BYTES, 540_672);
        assert_eq!(BIDX_SEG_BYTES, 32_768);

        assert_eq!(seg_first_height(seg_of(1_234_567)) + slot_of(1_234_567), 1_234_567);
    }
}
