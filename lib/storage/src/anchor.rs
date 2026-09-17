use std::collections::BTreeMap;
use std::path::Path;

use redb::ReadableTable;

use plaine_consensus::blake3;
use plaine_consensus::constants::HEADER_BYTES;
use plaine_consensus::crypto::header_hash;

use crate::error::StoreError;
use crate::integrity::{DamageKind, DamagedRange, SegmentKind, UnverifiableCause};
use crate::layout::{self, BIDX_ENTRY_BYTES, BIDX_SEG_BYTES, SEG_BLOCKS};
use crate::posio;
use crate::tables::BODY_ANCHOR;

pub const ANCHOR_BYTES: usize = 65;

pub const GRADE_SEALED_HERE: u8 = 1;

pub const GRADE_UNCHANGED_SINCE: u8 = 2;

pub const CONT_UNAVAILABLE: [u8; 32] = [0u8; 32];

const GEOM_TAG: &[u8] = b"plaine.bodyseg.geom.v1";
const CONT_TAG: &[u8] = b"plaine.bodyseg.cont.v1";

pub const L1_BYTES_PER_SEGMENT: u64 = BIDX_SEG_BYTES + 2 * HEADER_BYTES as u64 + 2 * 8;

// Highest fully-sealed segment, or -1 when none is. A segment counts as sealed
// only after the watermark passes its last block, which is where the -1 comes in.
#[inline]
pub fn sealed_through(body_watermark: u64) -> i64 {
    (body_watermark >> layout::SEG_SHIFT) as i64 - 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub first: [u8; 32],
    pub last: [u8; 32],
}

pub fn identity(root: &Path, seg: u32) -> Option<Identity> {
    let first_h = layout::seg_first_height(seg);
    let last_h = first_h + SEG_BLOCKS - 1;
    let a = read_header(root, first_h)?;
    let b = read_header(root, last_h)?;
    Some(Identity {
        first: header_hash(&a),
        last: header_hash(&b),
    })
}

fn read_header(root: &Path, h: u64) -> Option<[u8; HEADER_BYTES]> {
    let f = posio::open_ro(&layout::hdr_seg_path(root, layout::seg_of(h))).ok()?;
    crate::segment::read_header(&f, h).ok().flatten()
}

fn preimage_head(tag: &[u8], network: [u8; 4], seg: u32, id: &Identity) -> Vec<u8> {
    let mut v = Vec::with_capacity(tag.len() + 4 + 4 + 8 + 64 + BIDX_SEG_BYTES as usize + 8);
    v.extend_from_slice(tag);
    v.extend_from_slice(&network);
    v.extend_from_slice(&seg.to_le_bytes());
    v.extend_from_slice(&layout::seg_first_height(seg).to_le_bytes());
    v.extend_from_slice(&id.first);
    v.extend_from_slice(&id.last);
    v
}

pub fn geom(
    network: [u8; 4],
    seg: u32,
    id: &Identity,
    sidecar: &[u8],
    crc_first: u32,
    crc_last: u32,
) -> [u8; 32] {
    let mut v = preimage_head(GEOM_TAG, network, seg, id);
    v.extend_from_slice(sidecar);
    v.extend_from_slice(&crc_first.to_le_bytes());
    v.extend_from_slice(&crc_last.to_le_bytes());
    blake3::hash(&v)
}

pub fn cont(network: [u8; 4], seg: u32, id: &Identity, frames: &[u8]) -> [u8; 32] {
    if frames.len() as u64 != SEG_BLOCKS * 8 {
        return CONT_UNAVAILABLE;
    }
    let mut v = preimage_head(CONT_TAG, network, seg, id);
    v.extend_from_slice(frames);
    let h = blake3::hash(&v);
    // all-zeros doubles as the "unavailable" sentinel. if a real digest ever lands
    // there (never going to happen, but still) nudge it off so it can't be mistaken.
    if h == CONT_UNAVAILABLE {
        return [1u8; 32];
    }
    h
}

pub fn encode(grade: u8, geom: &[u8; 32], cont: &[u8; 32]) -> [u8; ANCHOR_BYTES] {
    let mut v = [0u8; ANCHOR_BYTES];
    v[0] = grade;
    v[1..33].copy_from_slice(geom);
    v[33..65].copy_from_slice(cont);
    v
}

pub fn decode(v: &[u8; ANCHOR_BYTES]) -> (u8, [u8; 32], [u8; 32]) {
    let mut g = [0u8; 32];
    let mut c = [0u8; 32];
    g.copy_from_slice(&v[1..33]);
    c.copy_from_slice(&v[33..65]);
    (v[0], g, c)
}

pub struct Material {
    pub sidecar: Vec<u8>,
    pub crc_first: u32,
    pub crc_last: u32,
}

pub fn material(root: &Path, seg: u32) -> Option<Material> {
    let idx = posio::open_ro(&layout::bidx_path(root, seg)).ok()?;
    let mut sidecar = vec![0u8; BIDX_SEG_BYTES as usize];
    if posio::pread(&idx, 0, &mut sidecar).ok()? != BIDX_SEG_BYTES as usize {
        return None;
    }
    let (off0, len0) = entry(&sidecar, 0);
    let (offl, lenl) = entry(&sidecar, SEG_BLOCKS - 1);
    if len0 == 0 || lenl == 0 {
        return None;
    }
    let seg_f = posio::open_ro(&layout::body_seg_path(root, seg)).ok()?;
    let crc_first = frame_crc(&seg_f, off0 as u64, len0)?;
    let crc_last = frame_crc(&seg_f, offl as u64, lenl)?;
    Some(Material {
        sidecar,
        crc_first,
        crc_last,
    })
}

fn entry(sidecar: &[u8], slot: u64) -> (u32, u32) {
    let i = (slot * BIDX_ENTRY_BYTES) as usize;
    let mut e = [0u8; 8];
    e.copy_from_slice(&sidecar[i..i + 8]);
    crate::codec::decode_bidx(&e)
}

fn frame_crc(f: &std::fs::File, off: u64, want_len: u32) -> Option<u32> {
    let mut fh = [0u8; 8];
    if posio::pread(f, off, &mut fh).ok()? != 8 {
        return None;
    }
    let (len, crc) = crate::codec::decode_frame_header(&fh);
    if len != want_len {
        return None;
    }
    Some(crc)
}

pub fn compute(
    root: &Path,
    network: [u8; 4],
    seg: u32,
    grade: u8,
    frames: Option<&[u8]>,
) -> Option<[u8; ANCHOR_BYTES]> {
    let id = identity(root, seg)?;
    let m = material(root, seg)?;
    let g = geom(network, seg, &id, &m.sidecar, m.crc_first, m.crc_last);
    let c = match frames {
        Some(f) => cont(network, seg, &id, f),
        None => CONT_UNAVAILABLE,
    };
    Some(encode(grade, &g, &c))
}

pub fn load_range(
    db: &redb::Database,
    lo: u32,
    hi: u32,
) -> Result<BTreeMap<u32, [u8; ANCHOR_BYTES]>, StoreError> {
    let txn = db.begin_read()?;
    let t = match txn.open_table(BODY_ANCHOR) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(BTreeMap::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = BTreeMap::new();
    if lo > hi {
        return Ok(out);
    }
    for e in t.range(lo..=hi)? {
        let (k, v) = e?;
        out.insert(k.value(), *v.value());
    }
    Ok(out)
}

pub fn all_segments(db: &redb::Database) -> Result<Vec<u32>, StoreError> {
    let txn = db.begin_read()?;
    let t = match txn.open_table(BODY_ANCHOR) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut v = Vec::new();
    for e in t.iter()? {
        v.push(e?.0.value());
    }
    Ok(v)
}

pub fn get(db: &redb::Database, seg: u32) -> Result<Option<[u8; ANCHOR_BYTES]>, StoreError> {
    let txn = db.begin_read()?;
    let t = match txn.open_table(BODY_ANCHOR) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(t.get(seg)?.map(|v| *v.value()))
}

pub fn insert(
    txn: &redb::WriteTransaction,
    seg: u32,
    v: &[u8; ANCHOR_BYTES],
) -> Result<(), StoreError> {
    let mut t = txn.open_table(BODY_ANCHOR)?;
    // Mint once, then immutable. Re-minting the same segment with different bytes
    // means the sealed segment moved under us - a bug to surface, not a repair.
    if let Some(old) = t.get(seg)? {
        let same = *old.value() == *v;
        drop(old);
        debug_assert!(
            same,
            "anchor for segment {seg:06x} rewritten with different bytes"
        );
        if !same {
            return Err(StoreError::BadPlan(
                "an anchor row was rewritten: minting is once per segment, never a repair",
            ));
        }
        return Ok(());
    }
    t.insert(seg, v)?;
    Ok(())
}

pub fn delete_above_watermark(
    txn: &redb::WriteTransaction,
    body_watermark: u64,
) -> Result<u32, StoreError> {
    let keep = sealed_through(body_watermark);
    let mut t = txn.open_table(BODY_ANCHOR)?;
    let doomed: Vec<u32> = t
        .iter()?
        .map(|e| e.map(|(k, _)| k.value()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|s| (*s as i64) > keep)
        .collect();
    for s in &doomed {
        t.remove(*s)?;
    }
    Ok(doomed.len() as u32)
}

pub fn delete_below_segment(
    txn: &redb::WriteTransaction,
    floor_seg: u32,
) -> Result<u32, StoreError> {
    let mut t = txn.open_table(BODY_ANCHOR)?;
    let doomed: Vec<u32> = t
        .range(..floor_seg)?
        .map(|e| e.map(|(k, _)| k.value()))
        .collect::<Result<_, _>>()?;
    for s in &doomed {
        t.remove(*s)?;
    }
    Ok(doomed.len() as u32)
}

pub fn count(db: &redb::Database) -> Result<u64, StoreError> {
    Ok(all_segments(db)?.len() as u64)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AnchorPass {
    pub verified: u32,
    pub unverifiable: Vec<(u32, UnverifiableCause)>,
    pub damage: Vec<DamagedRange>,
    pub floor_raised: Option<(u64, u64)>,
    pub segments_checked: u32,
    pub bytes_read: u64,
}

fn damaged(seg: u32, reason: DamageKind) -> DamagedRange {
    let first = layout::seg_first_height(seg);
    DamagedRange {
        kind: SegmentKind::Body,
        segment: seg,
        first_height: first,
        last_height: first + SEG_BLOCKS - 1,
        expected_len: 0,
        actual_len: None,
        reason,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_sealed(
    db: &redb::Database,
    root: &Path,
    network: [u8; 4],
    body_watermark: u64,
    prune_floor: u64,
    anchor_floor: u64,
    header_damage: &[DamagedRange],
    body_damage: &[DamagedRange],
) -> Result<AnchorPass, StoreError> {
    let mut pass = AnchorPass::default();
    let top = sealed_through(body_watermark);
    if top < 0 {
        return Ok(pass);
    }
    let top = top as u32;
    let lo = layout::seg_of(prune_floor);
    if lo > top {
        return Ok(pass);
    }
    let rows = load_range(db, lo, top)?;
    let highest_anchored = rows.keys().next_back().copied();

    let mut regressed_from: Option<u64> = None;
    for seg in lo..=top {
        let first = layout::seg_first_height(seg);
        let last = first + SEG_BLOCKS - 1;
        if body_damage
            .iter()
            .any(|d| d.first_height <= last && d.last_height >= first)
        {
            continue;
        }
        pass.segments_checked += 1;
        let header_hurt = header_damage
            .iter()
            .any(|d| d.first_height <= last && d.last_height >= first);

        match rows.get(&seg) {
            Some(v) => {
                let (grade, want_geom, _) = decode(v);
                let Some(id) = identity(root, seg) else {
                    pass.unverifiable
                        .push((seg, UnverifiableCause::IdentityUnavailable));
                    continue;
                };
                if header_hurt {
                    pass.unverifiable
                        .push((seg, UnverifiableCause::IdentityUnavailable));
                    continue;
                }
                let Some(m) = material(root, seg) else {
                    pass.unverifiable
                        .push((seg, UnverifiableCause::IdentityUnavailable));
                    continue;
                };
                pass.bytes_read += L1_BYTES_PER_SEGMENT;
                let got = geom(network, seg, &id, &m.sidecar, m.crc_first, m.crc_last);
                if got != want_geom {
                    pass.damage.push(damaged(seg, DamageKind::AnchorMismatch));
                } else if grade == GRADE_SEALED_HERE {
                    pass.verified += 1;
                } else {
                    pass.unverifiable
                        .push((seg, UnverifiableCause::UnchangedSince { anchor_floor }));
                }
            }
            None => {
                if first < anchor_floor {
                    pass.unverifiable
                        .push((seg, UnverifiableCause::PreAnchor { anchor_floor }));
                } else if header_hurt || identity(root, seg).is_none() {
                    pass.unverifiable
                        .push((seg, UnverifiableCause::IdentityUnavailable));
                } else if highest_anchored.is_some_and(|h| h > seg) {
                    pass.damage.push(damaged(seg, DamageKind::AnchorMissing));
                } else {
                    regressed_from = Some(regressed_from.unwrap_or(first).min(first));
                    pass.unverifiable
                        .push((seg, UnverifiableCause::WriterRegressed { since: first }));
                }
            }
        }
    }

    if let Some(from) = regressed_from {
        for (_, c) in pass.unverifiable.iter_mut() {
            if matches!(c, UnverifiableCause::WriterRegressed { .. }) {
                *c = UnverifiableCause::WriterRegressed { since: from };
            }
        }
        if from > anchor_floor {
            pass.floor_raised = Some((anchor_floor, from));
        }
    }
    Ok(pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_through_tracks_watermark() {
        assert_eq!(sealed_through(0), -1);
        assert_eq!(sealed_through(4_095), -1);
        assert_eq!(sealed_through(4_096), 0);
        assert_eq!(sealed_through(4_097), 0);
        assert_eq!(sealed_through(8_192), 1);
    }

    #[test]
    fn l1_cost_is_arithmetic() {
        assert_eq!(L1_BYTES_PER_SEGMENT, 32_768 + 264 + 16);
        assert_eq!(L1_BYTES_PER_SEGMENT, 33_048);

        assert_eq!(643 * L1_BYTES_PER_SEGMENT, 21_249_864);
        assert_eq!(643 * (ANCHOR_BYTES as u64 + 4), 44_367);
    }

    #[test]
    fn geom_binds_content_not_just_shape() {
        let id = Identity {
            first: [7u8; 32],
            last: [9u8; 32],
        };
        let sidecar = vec![0xABu8; BIDX_SEG_BYTES as usize];
        let a = geom([1, 2, 3, 4], 1, &id, &sidecar, 111, 222);
        let b = geom([1, 2, 3, 4], 1, &id, &sidecar, 333, 444);
        assert_ne!(a, b, "content is not bound: M12 walks through");

        let other = Identity {
            first: [8u8; 32],
            last: [9u8; 32],
        };
        assert_ne!(a, geom([1, 2, 3, 4], 1, &other, &sidecar, 111, 222));
        assert_ne!(a, geom([1, 2, 3, 4], 2, &id, &sidecar, 111, 222));
        assert_ne!(a, geom([9, 9, 9, 9], 1, &id, &sidecar, 111, 222));
    }

    #[test]
    fn cont_short_frames_is_unavailable() {
        let id = Identity {
            first: [0u8; 32],
            last: [0u8; 32],
        };
        assert_eq!(cont([0; 4], 0, &id, &[0u8; 16]), CONT_UNAVAILABLE);
        assert_ne!(
            cont([0; 4], 0, &id, &vec![0u8; (SEG_BLOCKS * 8) as usize]),
            CONT_UNAVAILABLE
        );
    }
}
