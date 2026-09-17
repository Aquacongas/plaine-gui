use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::time::Instant;

use plaine_consensus::constants::HEADER_BYTES;
use plaine_consensus::crypto::header_hash;

use crate::codec;
use crate::layout::{self, BIDX_ENTRY_BYTES, BIDX_SEG_BYTES, HDR_SEG_BYTES, SEG_BLOCKS};
use crate::posio;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    Header,
    Body,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DamageKind {
    Missing,
    Short,
    Overlong,
    SidecarMissing,
    SidecarShort,
    SidecarZeroed,
    FrameMismatch,
    LinkBroken,
    AnchorMismatch,
    AnchorMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DamagedRange {
    pub kind: SegmentKind,
    pub segment: u32,
    pub first_height: u64,
    pub last_height: u64,
    pub expected_len: u64,
    pub actual_len: Option<u64>,
    pub reason: DamageKind,
}

impl DamagedRange {
    #[inline]
    pub fn contains(&self, height: u64) -> bool {
        height >= self.first_height && height <= self.last_height
    }

    #[inline]
    pub fn blocks(&self) -> u64 {
        self.last_height - self.first_height + 1
    }

    pub(crate) fn into_error(self, height: u64) -> crate::error::StoreError {
        crate::error::StoreError::SegmentDamaged {
            kind: self.kind,
            segment: self.segment,
            height,
            first_height: self.first_height,
            last_height: self.last_height,
            reason: self.reason,
        }
    }
}

impl std::fmt::Display for DamagedRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let k = match self.kind {
            SegmentKind::Header => "header",
            SegmentKind::Body => "body",
        };
        write!(
            f,
            "{k} segment {:06x} heights {}..={} {:?} (expected {} B, found {})",
            self.segment,
            self.first_height,
            self.last_height,
            self.reason,
            self.expected_len,
            match self.actual_len {
                Some(n) => n.to_string(),
                None => "no file".to_string(),
            }
        )
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DamageSet {
    pub header: Vec<DamagedRange>,
    pub body: Vec<DamagedRange>,
}

impl DamageSet {
    pub fn is_empty(&self) -> bool {
        self.header.is_empty() && self.body.is_empty()
    }

    pub fn header_at(&self, h: u64) -> Option<DamagedRange> {
        self.header.iter().copied().find(|d| d.contains(h))
    }

    pub fn body_at(&self, h: u64) -> Option<DamagedRange> {
        self.body.iter().copied().find(|d| d.contains(h))
    }

    pub fn header_overlaps(&self, lo: u64, hi: u64) -> Option<DamagedRange> {
        self.header
            .iter()
            .copied()
            .find(|d| d.first_height <= hi && d.last_height >= lo)
    }

    pub fn body_overlaps(&self, lo: u64, hi: u64) -> Option<DamagedRange> {
        self.body
            .iter()
            .copied()
            .find(|d| d.first_height <= hi && d.last_height >= lo)
    }

    pub fn intact_header_floor(&self) -> u64 {
        self.header
            .iter()
            .map(|d| d.last_height + 1)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct VouchSet {
    pub unverifiable: Vec<(u32, UnverifiableCause)>,
}

impl VouchSet {
    pub fn cause_for(&self, height: u64) -> Option<UnverifiableCause> {
        let seg = layout::seg_of(height);
        self.unverifiable
            .iter()
            .find(|(s, _)| *s == seg)
            .map(|(_, c)| *c)
    }
}

#[derive(Debug, Clone, Default)]
pub struct BodyVouch {
    pub verified: Vec<(u64, u64)>,
    pub unverifiable: Vec<(u64, u64, UnverifiableCause)>,
    pub damaged: Vec<DamagedRange>,
}

impl BodyVouch {
    pub fn vouches_for_everything(&self) -> bool {
        self.unverifiable.is_empty() && self.damaged.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct IntegrityReport {
    pub header_damage: Vec<DamagedRange>,
    pub body_damage: Vec<DamagedRange>,
    pub overlong_truncated: Vec<DamagedRange>,
    pub overlong_untruncated: Vec<DamagedRange>,
    pub segments_checked: u32,
    pub check_micros: u64,
    pub anchor_segments_checked: u32,
    pub anchors_verified: u32,
    pub anchor_bytes_read: u64,
}

impl IntegrityReport {
    pub fn is_clean(&self) -> bool {
        self.header_damage.is_empty() && self.body_damage.is_empty()
    }

    pub fn damaged_blocks(&self) -> u64 {
        self.header_damage.iter().map(|d| d.blocks()).sum::<u64>()
            + self.body_damage.iter().map(|d| d.blocks()).sum::<u64>()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeAvailability {
    Verified,

    Unverifiable {
        cause: UnverifiableCause,
    },
    Pruned {
        prune_floor: u64,
    },
    Damaged {
        first: u64,
        last: u64,
        reason: DamageKind,
    },
    AboveWatermark {
        watermark: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiableCause {
    PreAnchor { anchor_floor: u64 },
    Unsealed { body_watermark: u64 },
    UnchangedSince { anchor_floor: u64 },
    WriterRegressed { since: u64 },
    IdentityUnavailable,
}

pub(crate) fn list_segments(dir: &Path, ext: &str) -> BTreeMap<u32, u64> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some((stem, x)) = name.rsplit_once('.') else {
            continue;
        };
        if x != ext || stem.len() != 6 {
            continue;
        }
        let Ok(seg) = u32::from_str_radix(stem, 16) else {
            continue;
        };
        let len = e.metadata().map(|m| m.len()).unwrap_or(0);
        out.insert(seg, len);
    }
    out
}

pub(crate) fn list_hdr(root: &Path) -> BTreeMap<u32, u64> {
    list_segments(&layout::hdr_dir(root), "hseg")
}

pub(crate) fn list_bseg(root: &Path) -> BTreeMap<u32, u64> {
    list_segments(&layout::body_dir(root), "bseg")
}

pub(crate) fn list_bidx(root: &Path) -> BTreeMap<u32, u64> {
    list_segments(&layout::body_dir(root), "bidx")
}

#[inline]
pub(crate) fn hdr_expected_len(seg: u32, hdr_watermark: u64) -> u64 {
    let last = layout::seg_of(hdr_watermark - 1);
    if seg < last {
        HDR_SEG_BYTES
    } else {
        (layout::slot_of(hdr_watermark - 1) + 1) * HEADER_BYTES as u64
    }
}

pub(crate) fn scan(
    root: &Path,
    hdr_watermark: u64,
    body_watermark: u64,
    prune_floor: u64,
) -> IntegrityReport {
    let t0 = Instant::now();
    let mut rep = IntegrityReport::default();
    let hdrs = list_hdr(root);
    let bsegs = list_bseg(root);
    let bidxs = list_bidx(root);

    scan_headers(root, hdr_watermark, &hdrs, &mut rep);
    scan_bodies(root, body_watermark, prune_floor, &bsegs, &bidxs, &mut rep);

    rep.check_micros = t0.elapsed().as_micros() as u64;
    rep
}

fn scan_headers(root: &Path, w: u64, hdrs: &BTreeMap<u32, u64>, rep: &mut IntegrityReport) {
    if w == 0 {
        return;
    }
    let last = layout::seg_of(w - 1);
    for s in 0..=last {
        rep.segments_checked += 1;
        let first = layout::seg_first_height(s);
        let seg_top = if s == last {
            w - 1
        } else {
            first + SEG_BLOCKS - 1
        };
        let want = hdr_expected_len(s, w);
        match hdrs.get(&s).copied() {
            None => rep.header_damage.push(DamagedRange {
                kind: SegmentKind::Header,
                segment: s,
                first_height: first,
                last_height: seg_top,
                expected_len: want,
                actual_len: None,
                reason: DamageKind::Missing,
            }),
            Some(len) if len < want => {
                let backed = len / HEADER_BYTES as u64;
                rep.header_damage.push(DamagedRange {
                    kind: SegmentKind::Header,
                    segment: s,
                    first_height: first + backed,
                    last_height: seg_top,
                    expected_len: want,
                    actual_len: Some(len),
                    reason: DamageKind::Short,
                });
            }
            Some(len) if len > want => rep.overlong_truncated.push(DamagedRange {
                kind: SegmentKind::Header,
                segment: s,
                first_height: first,
                last_height: seg_top,
                expected_len: want,
                actual_len: Some(len),
                reason: DamageKind::Overlong,
            }),
            Some(_) => {}
        }
    }

    // Only the seams here: does each segment's first header name the last header
    // of the one below it? Interior links belong to the sweeper. A boundary is
    // where an out-of-order segment write would show, so that's what we stitch.
    let mut prev_file: Option<(u32, File)> = None;
    for s in 0..last {
        let boundary = layout::seg_first_height(s + 1);
        if rep
            .header_damage
            .iter()
            .any(|d| d.segment == s || d.segment == s + 1)
        {
            continue;
        }
        let lower = match prev_file.take() {
            Some((n, f)) if n == s => Some(f),
            _ => posio::open_ro(&layout::hdr_seg_path(root, s)).ok(),
        };
        let (Some(lo_f), Ok(hi_f)) = (lower, posio::open_ro(&layout::hdr_seg_path(root, s + 1)))
        else {
            continue;
        };
        let a = crate::segment::read_header(&lo_f, boundary - 1)
            .ok()
            .flatten();
        let b = crate::segment::read_header(&hi_f, boundary).ok().flatten();
        if let (Some(a), Some(b)) = (a, b) {
            if b[12..44] != header_hash(&a)[..] {
                rep.header_damage.push(DamagedRange {
                    kind: SegmentKind::Header,
                    segment: s + 1,
                    first_height: boundary,
                    last_height: (boundary + SEG_BLOCKS - 1).min(w - 1),
                    expected_len: hdr_expected_len(s + 1, w),
                    actual_len: hdrs.get(&(s + 1)).copied(),
                    reason: DamageKind::LinkBroken,
                });
            }
        }
        prev_file = Some((s + 1, hi_f));
    }
}

fn scan_bodies(
    root: &Path,
    bw: u64,
    prune_floor: u64,
    bsegs: &BTreeMap<u32, u64>,
    bidxs: &BTreeMap<u32, u64>,
    rep: &mut IntegrityReport,
) {
    if bw == 0 {
        return;
    }
    let last = layout::seg_of(bw - 1);
    let floor_seg = layout::seg_of(prune_floor);

    for s in floor_seg..last {
        rep.segments_checked += 1;
        let first = layout::seg_first_height(s);
        let seg_top = first + SEG_BLOCKS - 1;
        let mut damaged = |reason, expected_len, actual_len, from: u64| {
            rep.body_damage.push(DamagedRange {
                kind: SegmentKind::Body,
                segment: s,
                first_height: from,
                last_height: seg_top,
                expected_len,
                actual_len,
                reason,
            })
        };

        let idx_len = bidxs.get(&s).copied();
        let Some(idx_len) = idx_len else {
            if bsegs.contains_key(&s) {
                damaged(DamageKind::SidecarMissing, BIDX_SEG_BYTES, None, first);
            } else {
                damaged(DamageKind::Missing, BIDX_SEG_BYTES, None, first);
            }
            continue;
        };
        if idx_len < BIDX_SEG_BYTES {
            let backed = idx_len / BIDX_ENTRY_BYTES;
            damaged(
                DamageKind::SidecarShort,
                BIDX_SEG_BYTES,
                Some(idx_len),
                first + backed,
            );
            continue;
        }
        let Ok(idx_f) = posio::open_ro(&layout::bidx_path(root, s)) else {
            damaged(DamageKind::SidecarMissing, BIDX_SEG_BYTES, None, first);
            continue;
        };
        let Some((last_off, last_len)) = bidx_entry(&idx_f, SEG_BLOCKS - 1) else {
            damaged(
                DamageKind::SidecarShort,
                BIDX_SEG_BYTES,
                Some(idx_len),
                first,
            );
            continue;
        };
        if last_len == 0 {
            damaged(
                DamageKind::SidecarZeroed,
                BIDX_SEG_BYTES,
                Some(idx_len),
                first,
            );
            continue;
        }

        let want = last_off as u64 + crate::BODY_FRAME_BYTES as u64 + last_len as u64;
        match bsegs.get(&s).copied() {
            None => {
                damaged(DamageKind::Missing, want, None, first);
                continue;
            }
            Some(len) if len < want => {
                let from = first + first_unbacked_slot(&idx_f, len);
                damaged(DamageKind::Short, want, Some(len), from);
                continue;
            }
            Some(len) if len > want => rep.overlong_truncated.push(DamagedRange {
                kind: SegmentKind::Body,
                segment: s,
                first_height: first,
                last_height: seg_top,
                expected_len: want,
                actual_len: Some(len),
                reason: DamageKind::Overlong,
            }),
            Some(_) => {}
        }

        let Ok(seg_f) = posio::open_ro(&layout::body_seg_path(root, s)) else {
            damaged(DamageKind::Missing, want, None, first);
            continue;
        };
        let mut bad = false;
        if let Some((off0, len0)) = bidx_entry(&idx_f, 0) {
            if len0 == 0 || frame_len(&seg_f, off0 as u64) != Some(len0) {
                bad = true;
            }
        }
        if frame_len(&seg_f, last_off as u64) != Some(last_len) {
            bad = true;
        }
        if bad {
            damaged(
                DamageKind::FrameMismatch,
                want,
                bsegs.get(&s).copied(),
                first,
            );
        }
    }
}

fn bidx_entry(f: &File, slot: u64) -> Option<(u32, u32)> {
    let mut e = [0u8; 8];
    if posio::pread(f, slot * BIDX_ENTRY_BYTES, &mut e).ok()? != 8 {
        return None;
    }
    Some(codec::decode_bidx(&e))
}

fn frame_len(f: &File, off: u64) -> Option<u32> {
    let mut fh = [0u8; 8];
    if posio::pread(f, off, &mut fh).ok()? != 8 {
        return None;
    }
    Some(codec::decode_frame_header(&fh).0)
}

// binary search for the first slot whose frame spills past the truncated file
// end. offsets increase monotonically, so the backed slots are always a prefix.
fn first_unbacked_slot(idx_f: &File, actual_len: u64) -> u64 {
    let (mut lo, mut hi) = (0u64, SEG_BLOCKS);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let backed = match bidx_entry(idx_f, mid) {
            Some((off, len)) if len > 0 => {
                off as u64 + crate::BODY_FRAME_BYTES as u64 + len as u64 <= actual_len
            }
            _ => false,
        };
        if backed {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_len_is_arithmetic() {
        assert_eq!(hdr_expected_len(0, 3 * SEG_BLOCKS), HDR_SEG_BYTES);
        assert_eq!(hdr_expected_len(1, 3 * SEG_BLOCKS), HDR_SEG_BYTES);

        assert_eq!(hdr_expected_len(2, 2 * SEG_BLOCKS + 10), 10 * 132);
        assert_eq!(BIDX_SEG_BYTES, 32_768);
    }

    #[test]
    fn damaged_range_owns_its_heights() {
        let d = DamagedRange {
            kind: SegmentKind::Body,
            segment: 1,
            first_height: 4_096,
            last_height: 8_191,
            expected_len: 0,
            actual_len: None,
            reason: DamageKind::Missing,
        };
        assert!(!d.contains(4_095));
        assert!(d.contains(4_096));
        assert!(d.contains(8_191));
        assert!(!d.contains(8_192));
        assert_eq!(d.blocks(), 4_096);
        let set = DamageSet {
            header: vec![DamagedRange {
                kind: SegmentKind::Header,
                ..d
            }],
            body: vec![d],
        };

        assert_eq!(set.intact_header_floor(), 8_192);
        assert!(set.header_overlaps(8_000, 9_000).is_some());
        assert!(set.header_overlaps(0, 4_095).is_none());
    }
}
