mod common;

use std::path::{Path, PathBuf};
use std::time::Instant;

use common::{machine_note, serial, tag, Chain, Scratch};
use plaine_storage::{
    open, AcceptUnverified, DamageKind, DurabilityMode, OpenReport, RangeAvailability, StoreConfig,
    StoreError, StoreReader, UnverifiableCause,
};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

const SEG: u64 = plaine_storage::SEG_BLOCKS;
const BIDX_BYTES: u64 = plaine_storage::BIDX_SEG_BYTES;

const ANCHOR_T: TableDefinition<u32, &[u8; 65]> = TableDefinition::new("body_anchor");
const META_T: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c.ibd_batch_blocks = Some(4_096);
    c
}

fn seed(name: &str, blocks: u64, variant: u64) -> Scratch {
    let s = Scratch::new(name);
    let (mut c, r, rep) = open(cfg_of(&s)).expect("seed open");
    assert!(rep.integrity.is_clean(), "a fresh store reported damage");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(blocks, variant);
    c.extend(&common::commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    s
}

fn seed_legacy(name: &str, blocks: u64, variant: u64) -> Scratch {
    let s = Scratch::new(name);
    let mut cfg = cfg_of(&s);
    cfg.anchor_mint_off = true;
    let (mut c, r, _) = open(cfg).expect("seed open");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, 64, 2);
    let bs = chain.build(blocks, variant);
    c.extend(&common::commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    s
}

fn hdr(s: &Scratch, seg: u32) -> PathBuf {
    s.0.join("segments")
        .join("hdr")
        .join(format!("{seg:06x}.hseg"))
}
fn bseg(s: &Scratch, seg: u32) -> PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bseg"))
}
fn bidx(s: &Scratch, seg: u32) -> PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bidx"))
}

fn poke(p: &Path, off: u64, bytes: &[u8]) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

fn set_len(p: &Path, n: u64) {
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    f.set_len(n).unwrap();
    f.sync_all().unwrap();
}

fn read_all(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

fn len_of(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn db_of(s: &Scratch) -> Database {
    Database::open(s.0.join("chain.redb")).expect("open chain.redb directly")
}

fn anchor_get(s: &Scratch, seg: u32) -> Option<[u8; 65]> {
    let db = db_of(s);
    let txn = db.begin_read().unwrap();
    let t = txn.open_table(ANCHOR_T).unwrap();
    t.get(seg).unwrap().map(|g| *g.value())
}

fn anchor_rows(s: &Scratch) -> Vec<u32> {
    let db = db_of(s);
    let txn = db.begin_read().unwrap();
    let t = txn.open_table(ANCHOR_T).unwrap();
    t.iter().unwrap().map(|e| e.unwrap().0.value()).collect()
}

fn anchor_put(s: &Scratch, seg: u32, v: [u8; 65]) {
    let db = db_of(s);
    let mut txn = db.begin_write().unwrap();
    txn.set_durability(redb::Durability::Immediate);
    {
        let mut t = txn.open_table(ANCHOR_T).unwrap();
        t.insert(seg, &v).unwrap();
    }
    txn.commit().unwrap();
}

fn anchor_del(s: &Scratch, segs: &[u32]) {
    let db = db_of(s);
    let mut txn = db.begin_write().unwrap();
    txn.set_durability(redb::Durability::Immediate);
    {
        let mut t = txn.open_table(ANCHOR_T).unwrap();
        for seg in segs {
            t.remove(*seg).unwrap();
        }
    }
    txn.commit().unwrap();
}

fn meta_del(s: &Scratch, key: &str) {
    let db = db_of(s);
    let mut txn = db.begin_write().unwrap();
    txn.set_durability(redb::Durability::Immediate);
    {
        let mut t = txn.open_table(META_T).unwrap();
        t.remove(key).unwrap();
    }
    txn.commit().unwrap();
}

fn body_line(r: &StoreReader, h: u64) -> String {
    let mut buf = Vec::new();
    match r.body_at(h, &mut buf) {
        Ok(None) => "none(above watermark)".into(),
        Ok(Some(b)) => match b.verified() {
            Ok(n) => format!("VERIFIED {n} B"),
            Err((c, n)) => format!("unverifiable {n} B {c:?}"),
        },
        Err(e) => format!("ERR {e}"),
    }
}

fn verdict(name: &str, rep: &OpenReport, r: &StoreReader, probe: u64) {
    println!(
        "  {name:<44} clean={:<5} degraded={:<5} hdr_dmg={} body_dmg={} kinds={:?} \
         anchors_ok={} floor={} raised={:?} unverif={} vouch_all={} | h{probe}: {} | {:?}",
        rep.integrity.is_clean(),
        r.is_degraded(),
        rep.integrity.header_damage.len(),
        rep.integrity.body_damage.len(),
        rep.integrity
            .body_damage
            .iter()
            .map(|d| d.reason)
            .collect::<Vec<_>>(),
        rep.anchors_verified,
        rep.anchor_floor,
        rep.anchor_floor_raised,
        rep.unverifiable_body_ranges.len(),
        r.vouches_for_all_bodies(),
        body_line(r, probe),
        r.body_availability(probe),
    );
}

fn assert_not_silently_accepted(name: &str, rep: &OpenReport, r: &StoreReader, probe: u64) {
    let mut buf = Vec::new();
    let served_verified = matches!(
        r.body_at(probe, &mut buf),
        Ok(Some(b)) if b.is_verified()
    );
    assert!(
        !(rep.integrity.is_clean() && served_verified),
        "{name}: SILENT ACCEPTANCE - open() reported clean and body_at({probe}) came back VERIFIED"
    );
}

fn damaged_body(rep: &OpenReport, h: u64) -> Option<DamageKind> {
    rep.integrity
        .body_damage
        .iter()
        .find(|d| d.contains(h))
        .map(|d| d.reason)
}

#[test]
fn v01_sidecar_shifted_by_one_slot() {
    let _g = serial();
    let s = seed("fv-v01", 3 * SEG, 1);
    let mut idx = read_all(&bidx(&s, 1));
    let tail = idx[8..].to_vec();
    idx[..tail.len()].copy_from_slice(&tail);
    poke(&bidx(&s, 1), 0, &idx);

    let before = len_of(&bseg(&s, 1));
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V01 sidecar shifted one slot", &rep, &r, SEG);
    assert_eq!(len_of(&bseg(&s, 1)), before, "V01 lost payload bytes");
    assert_not_silently_accepted("V01", &rep, &r, SEG);
    assert!(!rep.integrity.is_clean(), "V01 accepted a shifted sidecar");
    assert_eq!(
        damaged_body(&rep, SEG),
        Some(DamageKind::AnchorMismatch),
        "V01 must be custody damage, not a length complaint"
    );
    drop(c);
    drop(r);
}

#[test]
fn v01b_rotated_sidecar_no_truncation() {
    let _g = serial();
    let s = seed("fv-v01b", 3 * SEG, 1);
    let mut idx = read_all(&bidx(&s, 1));
    idx.rotate_left(8);
    poke(&bidx(&s, 1), 0, &idx);

    let before = len_of(&bseg(&s, 1));
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    let after = len_of(&bseg(&s, 1));
    verdict("V01b sidecar rotated one slot", &rep, &r, SEG);
    println!(
        "      V01b .bseg bytes {before} -> {after} (lost {})",
        before - after
    );
    assert_not_silently_accepted("V01b", &rep, &r, SEG);
    assert_eq!(
        after,
        before,
        "V01b: open() dropped {} payload bytes on the strength of a corrupt sidecar",
        before - after
    );
    assert!(!rep.integrity.is_clean(), "V01b accepted a rotated sidecar");
    drop(c);
    drop(r);
}

#[test]
fn v24_last_offset_flip_keeps_payload() {
    let _g = serial();
    let s = seed("fv-v24", 3 * SEG, 1);
    let idx = read_all(&bidx(&s, 1));
    let last = (BIDX_BYTES - 8) as usize;
    let off = u32::from_le_bytes(idx[last..last + 4].try_into().unwrap());

    let bad = off & !(1 << 18);
    assert!(bad < off);
    poke(&bidx(&s, 1), BIDX_BYTES - 8, &bad.to_le_bytes());

    let before = len_of(&bseg(&s, 1));
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    let after = len_of(&bseg(&s, 1));
    verdict("V24 one bit flipped in off[4095]", &rep, &r, SEG);
    println!("      V24 .bseg bytes {before} -> {after}");
    assert_not_silently_accepted("V24", &rep, &r, SEG);
    assert!(
        !rep.integrity.is_clean(),
        "V24: a corrupt sidecar was accepted"
    );
    assert_eq!(
        after,
        before,
        "V24: a segment the sweep called damaged was truncated anyway, losing {} bytes",
        before - after
    );
    drop(c);
    drop(r);
}

#[test]
fn v02_matched_foreign_pair() {
    let _g = serial();
    let a = seed("fv-v02a", 3 * SEG, 1);
    let b = seed("fv-v02b", 3 * SEG, 2);
    assert_eq!(
        read_all(&bidx(&a, 1)),
        read_all(&bidx(&b, 1)),
        "the two stores must have identical sidecar GEOMETRY or this test is easy"
    );
    std::fs::copy(bseg(&b, 1), bseg(&a, 1)).unwrap();
    std::fs::copy(bidx(&b, 1), bidx(&a, 1)).unwrap();
    drop(b);

    let (c, r, rep) = open(cfg_of(&a)).expect("open");
    verdict("V02 foreign .bseg+.bidx pair", &rep, &r, SEG);
    assert_not_silently_accepted("V02", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::AnchorMismatch));
    drop(c);
    drop(r);
}

#[test]
fn v03_foreign_segment_no_sidecar() {
    let _g = serial();
    let a = seed("fv-v03a", 3 * SEG, 1);
    let b = seed("fv-v03b", 3 * SEG, 2);
    std::fs::copy(bseg(&b, 1), bseg(&a, 1)).unwrap();
    std::fs::remove_file(bidx(&a, 1)).unwrap();
    drop(b);

    let (c, r, rep) = open(cfg_of(&a)).expect("open");
    verdict("V03 foreign .bseg, sidecar deleted", &rep, &r, SEG);
    assert_not_silently_accepted("V03", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::AnchorMismatch));
    assert!(
        !rep.bidx_rebuilt_segments.contains(&1),
        "V03: a sidecar was rebuilt to FIT the foreign segment - the M11 hole is open"
    );
    drop(c);
    drop(r);
}

#[test]
fn v04_seg0_duplicated_over_seg1() {
    let _g = serial();
    let s = seed("fv-v04", 3 * SEG, 1);
    std::fs::copy(bseg(&s, 0), bseg(&s, 1)).unwrap();
    std::fs::copy(bidx(&s, 0), bidx(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V04 body seg 0 duplicated over 1", &rep, &r, SEG);
    assert_not_silently_accepted("V04", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::AnchorMismatch));

    let mut buf = Vec::new();
    assert!(matches!(
        r.body_at(SEG, &mut buf),
        Err(StoreError::SegmentDamaged { .. })
    ));
    drop(c);
    drop(r);
}

#[test]
fn v05_pair_with_anchor_transplanted() {
    let _g = serial();
    let a = seed("fv-v05a", 3 * SEG, 1);
    let b = seed("fv-v05b", 3 * SEG, 2);
    let row = anchor_get(&b, 1).expect("the donor must have an anchor to steal");
    assert_ne!(
        row,
        anchor_get(&a, 1).unwrap(),
        "two different chains must not mint the same anchor"
    );
    std::fs::copy(bseg(&b, 1), bseg(&a, 1)).unwrap();
    std::fs::copy(bidx(&b, 1), bidx(&a, 1)).unwrap();
    anchor_put(&a, 1, row);
    drop(b);

    let (c, r, rep) = open(cfg_of(&a)).expect("open");
    verdict("V05 pair + its own anchor row", &rep, &r, SEG);
    assert_not_silently_accepted("V05", &rep, &r, SEG);
    assert_eq!(
        damaged_body(&rep, SEG),
        Some(DamageKind::AnchorMismatch),
        "V05: a self-consistent transplant of data AND anchor was accepted"
    );
    drop(c);
    drop(r);
}

#[test]
fn v06_triple_transplant() {
    let _g = serial();
    let a = seed("fv-v06a", 3 * SEG, 1);
    let b = seed("fv-v06b", 3 * SEG, 2);
    let row = anchor_get(&b, 1).unwrap();
    std::fs::copy(hdr(&b, 1), hdr(&a, 1)).unwrap();
    std::fs::copy(bseg(&b, 1), bseg(&a, 1)).unwrap();
    std::fs::copy(bidx(&b, 1), bidx(&a, 1)).unwrap();
    anchor_put(&a, 1, row);
    drop(b);

    let res = open(cfg_of(&a));
    match res {
        Ok((c, r, rep)) => {
            verdict("V06 hdr+body+anchor all transplanted", &rep, &r, SEG);
            assert_not_silently_accepted("V06", &rep, &r, SEG);
            assert!(
                !rep.integrity.is_clean(),
                "V06: a whole foreign generation was adopted silently"
            );
            assert!(
                !rep.integrity.header_damage.is_empty(),
                "V06: the header link must break - that is what makes the anchor unforgeable"
            );
            drop(c);
            drop(r);
        }
        Err(e) => println!("  V06 hdr+body+anchor all transplanted     open REFUSED | {e}"),
    }
}

#[test]
fn v07_interior_anchor_row_deleted() {
    let _g = serial();
    let s = seed("fv-v07", 3 * SEG, 1);
    assert_eq!(anchor_rows(&s), vec![0, 1, 2]);
    anchor_del(&s, &[1]);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V07 interior anchor row deleted", &rep, &r, SEG);
    assert_not_silently_accepted("V07", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::AnchorMissing));
    assert_eq!(
        rep.anchor_floor_raised, None,
        "V07: an interior hole must not move the floor"
    );
    drop(c);
    drop(r);
}

#[test]
fn v08_deleted_anchor_suffix_raises_floor() {
    let _g = serial();
    let s = seed("fv-v08", 3 * SEG, 1);
    anchor_del(&s, &[1, 2]);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V08 anchor rows 1..2 deleted (suffix)", &rep, &r, SEG);
    assert!(rep.integrity.is_clean(), "V08: a suffix gap is not damage");
    assert!(!r.is_degraded());
    assert_eq!(rep.unverifiable_body_ranges.len(), 2);
    assert!(rep.unverifiable_body_ranges.iter().all(
        |(_, _, c)| matches!(c, UnverifiableCause::WriterRegressed { since } if *since == SEG)
    ));
    assert_eq!(
        rep.anchor_floor_raised,
        Some((0, SEG)),
        "V08: the downgrade scar must be loud and exact"
    );
    assert_eq!(rep.anchors_verified, 1, "V08: segment 0 still verifies");
    assert!(!r.vouches_for_all_bodies());

    let mut buf = Vec::new();
    for h in [0u64, SEG, 2 * SEG, 3 * SEG - 1] {
        let n = r
            .body_at(h, &mut buf)
            .unwrap()
            .unwrap()
            .any_provenance(AcceptUnverified::because(
                "V08 asserts the range is serveable",
            ));
        assert_eq!(n, 64, "V08: height {h} stopped being serveable");
    }
    drop(c);
    drop(r);
}

#[test]
fn v09_anchor_geom_digest_byte_flipped() {
    let _g = serial();
    let s = seed("fv-v09", 3 * SEG, 1);
    let mut row = anchor_get(&s, 1).unwrap();
    row[5] ^= 0x01;
    anchor_put(&s, 1, row);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V09 anchor GEOM byte flipped", &rep, &r, SEG);
    assert_not_silently_accepted("V09", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::AnchorMismatch));
    drop(c);
    drop(r);
}

#[test]
fn v10_forced_grade_not_verified() {
    let _g = serial();
    let s = seed("fv-v10", 3 * SEG, 1);
    let mut row = anchor_get(&s, 1).unwrap();
    assert_eq!(row[0], 1, "a freshly sealed segment must be grade 1");
    row[0] = 2;
    anchor_put(&s, 1, row);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V10 anchor grade 1 -> 2", &rep, &r, SEG);
    assert!(
        rep.integrity.is_clean(),
        "V10: a grade change is not damage"
    );
    assert!(matches!(
        r.body_availability(SEG),
        RangeAvailability::Unverifiable {
            cause: UnverifiableCause::UnchangedSince { .. }
        }
    ));
    assert!(!r.vouches_for_all_bodies());
    drop(c);
    drop(r);
}

#[test]
fn v11_two_anchor_rows_swapped() {
    let _g = serial();
    let s = seed("fv-v11", 3 * SEG, 1);
    let a1 = anchor_get(&s, 1).unwrap();
    let a2 = anchor_get(&s, 2).unwrap();
    anchor_put(&s, 1, a2);
    anchor_put(&s, 2, a1);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V11 anchor rows 1 and 2 swapped", &rep, &r, SEG);
    assert_not_silently_accepted("V11", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::AnchorMismatch));
    assert_eq!(
        damaged_body(&rep, 2 * SEG),
        Some(DamageKind::AnchorMismatch)
    );
    drop(c);
    drop(r);
}

#[test]
fn v12_stray_anchor_above_wm() {
    let _g = serial();
    let s = seed("fv-v12", 3 * SEG, 1);
    let row = anchor_get(&s, 0).unwrap();
    anchor_put(&s, 99, row);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V12 stray anchor row for seg 99", &rep, &r, SEG);
    assert!(rep.integrity.is_clean());
    assert_eq!(rep.anchors_dropped, 1, "V12: the stray row survived open()");
    drop(c);
    drop(r);
    assert_eq!(anchor_rows(&s), vec![0, 1, 2]);
}

#[test]
fn v13_pre_anchor_store_honest() {
    let _g = serial();
    let s = seed_legacy("fv-v13", 3 * SEG, 1);
    assert!(
        anchor_rows(&s).is_empty(),
        "the legacy writer minted anchors"
    );

    let (c, r, rep) = open(cfg_of(&s)).expect("a pre-anchor store must still open");
    verdict("V13 pre-anchor store, first upgrade", &rep, &r, SEG);
    assert!(
        rep.integrity.is_clean(),
        "V13: absence was treated as damage"
    );
    assert!(
        !r.is_degraded(),
        "V13: an upgraded store must not be degraded"
    );
    assert_eq!(rep.unverifiable_body_ranges.len(), 3);
    assert!(rep
        .unverifiable_body_ranges
        .iter()
        .all(|(_, _, c)| matches!(c, UnverifiableCause::PreAnchor { .. })));
    assert!(!r.vouches_for_all_bodies());
    let mut buf = Vec::new();
    for h in [0u64, SEG, 2 * SEG, 3 * SEG - 1] {
        assert_eq!(
            r.body_at(h, &mut buf)
                .unwrap()
                .unwrap()
                .any_provenance(AcceptUnverified::because("V13 asserts serveability")),
            64
        );
    }
    let v = r.body_vouch();
    println!(
        "      V13 vouch: verified={:?} unverifiable={} damaged={}",
        v.verified,
        v.unverifiable.len(),
        v.damaged.len()
    );
    assert!(v.verified.is_empty());
    drop(c);
    drop(r);
}

#[test]
fn v14_foreign_below_floor_unverifiable() {
    let _g = serial();
    let a = seed_legacy("fv-v14a", 3 * SEG, 1);
    let b = seed_legacy("fv-v14b", 3 * SEG, 2);
    std::fs::copy(bseg(&b, 1), bseg(&a, 1)).unwrap();
    std::fs::copy(bidx(&b, 1), bidx(&a, 1)).unwrap();
    drop(b);

    let (c, r, rep) = open(cfg_of(&a)).expect("open");
    verdict("V14 foreign pair below anchor_floor", &rep, &r, SEG);
    assert_not_silently_accepted("V14", &rep, &r, SEG);
    assert!(
        !matches!(r.body_availability(SEG), RangeAvailability::Verified),
        "V14: a legacy range must never be advertised as vouched"
    );
    assert!(!r.vouches_for_all_bodies());
    drop(c);
    drop(r);
}

#[test]
fn v15_post_upgrade_seals_verified() {
    let _g = serial();
    let s = seed_legacy("fv-v15", 3 * SEG, 1);
    {
        let (mut c, r, rep) = open(cfg_of(&s)).expect("upgrade open");
        assert_eq!(rep.anchor_floor, 3 * SEG);
        c.set_mode(DurabilityMode::Ibd).unwrap();
        let mut chain = Chain::new(64, 64, 2);
        let _warm = chain.build(3 * SEG, 1);
        let more = chain.build(2 * SEG, 1);
        c.extend(&common::commits(&more)).unwrap();
        c.flush().unwrap();
        drop(c);
        drop(r);
    }
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V15 upgraded store grown by 2 segments", &rep, &r, 3 * SEG);
    assert!(rep.integrity.is_clean());
    assert_eq!(rep.anchors_verified, 2, "V15: the new segments must verify");
    assert!(matches!(
        r.body_availability(3 * SEG),
        RangeAvailability::Verified
    ));
    assert!(matches!(
        r.body_availability(SEG),
        RangeAvailability::Unverifiable {
            cause: UnverifiableCause::PreAnchor { .. }
        }
    ));
    let v = r.body_vouch();
    println!(
        "      V15 vouch: verified={:?} unverifiable={:?}",
        v.verified,
        v.unverifiable
            .iter()
            .map(|(a, b, _)| (*a, *b))
            .collect::<Vec<_>>()
    );
    assert_eq!(v.verified, vec![(3 * SEG, 5 * SEG - 1)]);
    drop(c);
    drop(r);
}

#[test]
fn v16_frame_crc_field_rewritten() {
    let _g = serial();
    let s = seed("fv-v16", 3 * SEG, 1);

    poke(&bseg(&s, 1), 4, &[0xDE, 0xAD, 0xBE, 0xEF]);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V16 probe frame CRC field rewritten", &rep, &r, SEG);
    assert_not_silently_accepted("V16", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::AnchorMismatch));
    drop(c);
    drop(r);
}

#[test]
fn v17_interior_crc_gap_closed_by_l2() {
    let _g = serial();
    let s = seed("fv-v17", 3 * SEG, 1);
    let idx = read_all(&bidx(&s, 1));
    let slot = 2_000usize;
    let off = u32::from_le_bytes(idx[slot * 8..slot * 8 + 4].try_into().unwrap()) as u64;
    poke(&bseg(&s, 1), off + 4, &[0x00, 0x00, 0x00, 0x00]);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    let h = SEG + slot as u64;
    verdict("V17 interior frame CRC (slot 2000)", &rep, &r, h);
    assert!(
        rep.integrity.is_clean(),
        "L1's coverage is stated as first+last only"
    );
    let mut buf = Vec::new();
    assert!(
        matches!(r.body_at(h, &mut buf), Err(StoreError::CrcMismatch { .. })),
        "V17: a tampered interior frame was SERVED"
    );
    assert_eq!(
        r.verify_segment_frames(1).unwrap(),
        Some(false),
        "V17: the deep tier must close what L1 states it does not cover"
    );
    drop(c);
    drop(r);
}

#[test]
fn v18_sealed_body_truncated_midway() {
    let _g = serial();
    let s = seed("fv-v18", 3 * SEG, 1);
    let was = len_of(&bseg(&s, 1));
    set_len(&bseg(&s, 1), was / 2);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V18 sealed .bseg halved", &rep, &r, 3 * SEG - 1);
    assert_eq!(damaged_body(&rep, 2 * SEG - 1), Some(DamageKind::Short));
    let mut buf = Vec::new();
    assert!(matches!(
        r.body_at(2 * SEG - 1, &mut buf),
        Err(StoreError::SegmentDamaged { .. })
    ));

    assert!(matches!(
        r.body_availability(0),
        RangeAvailability::Verified
    ));
    drop(c);
    drop(r);
}

#[test]
fn v19_whole_sealed_body_pair_deleted() {
    let _g = serial();
    let s = seed("fv-v19", 3 * SEG, 1);
    std::fs::remove_file(bseg(&s, 1)).unwrap();
    std::fs::remove_file(bidx(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V19 sealed body pair deleted", &rep, &r, SEG);
    assert_eq!(damaged_body(&rep, SEG), Some(DamageKind::Missing));
    let mut buf = Vec::new();
    assert!(
        !matches!(r.body_at(SEG, &mut buf), Err(StoreError::BodyPruned { .. })),
        "V19: a hole was reported as pruning"
    );
    assert_eq!(r.prune_floor(), 0);
    drop(c);
    drop(r);
}

#[test]
fn v20_lost_sidecar_slot_rebuilt() {
    let _g = serial();
    let s = seed("fv-v20", 3 * SEG, 1);
    poke(&bidx(&s, 1), BIDX_BYTES - 8, &[0u8; 8]);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict(
        "V20 sidecar last slot zeroed (honest)",
        &rep,
        &r,
        2 * SEG - 1,
    );
    assert!(
        rep.bidx_rebuilt_segments.contains(&1),
        "V20: the sidecar was not rebuilt"
    );
    assert!(
        rep.integrity.is_clean(),
        "V20: an honest lost slot was quarantined - the fix has a false positive"
    );
    let mut buf = Vec::new();
    let n = r
        .body_at(2 * SEG - 1, &mut buf)
        .unwrap()
        .expect("a present body was reported absent")
        .verified()
        .expect("V20: the rebuilt segment must still be vouched for");
    assert_eq!(n, 64);
    drop(c);
    drop(r);
}

#[test]
fn v23_floor_reset_cannot_forge_verified() {
    let _g = serial();
    let a = seed("fv-v23a", 3 * SEG, 1);
    let b = seed("fv-v23b", 3 * SEG, 2);
    std::fs::copy(bseg(&b, 1), bseg(&a, 1)).unwrap();
    std::fs::copy(bidx(&b, 1), bidx(&a, 1)).unwrap();
    drop(b);
    anchor_del(&a, &[1, 2]);
    meta_del(&a, "anchor_floor");

    let (c, r, rep) = open(cfg_of(&a)).expect("open");
    verdict("V23 foreign pair + floor key reset", &rep, &r, SEG);
    assert_not_silently_accepted("V23", &rep, &r, SEG);
    assert!(
        !matches!(r.body_availability(SEG), RangeAvailability::Verified),
        "V23: laundering produced a VERIFIED range - the anchor claims more than it proves"
    );
    assert!(!r.vouches_for_all_bodies());

    assert!(
        !r.body_vouch()
            .verified
            .iter()
            .any(|(lo, hi)| *lo <= SEG && *hi >= SEG),
        "V23: the laundered range was advertised as vouched history"
    );
    drop(c);
    drop(r);
}

#[test]
fn v25_anchored_overlong_truncated_verifies() {
    let _g = serial();
    let s = seed("fv-v25", 3 * SEG, 1);
    let before = len_of(&bseg(&s, 1));
    poke(&bseg(&s, 1), before + 100_000, &[0xAB; 4_096]);
    assert!(len_of(&bseg(&s, 1)) > before);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V25 anchored .bseg grew by 104,096 B", &rep, &r, SEG);
    assert_eq!(rep.integrity.overlong_truncated.len(), 1);
    assert!(rep.integrity.overlong_untruncated.is_empty());
    assert_eq!(
        len_of(&bseg(&s, 1)),
        before,
        "V25: the lossless repair stopped working"
    );
    assert!(rep.integrity.is_clean());
    let mut buf = Vec::new();
    assert_eq!(
        r.body_at(SEG + 7, &mut buf)
            .unwrap()
            .unwrap()
            .verified()
            .unwrap(),
        64
    );
    drop(c);
    drop(r);
}

#[test]
fn v26_anchorless_overlong_reported() {
    let _g = serial();
    let s = seed_legacy("fv-v26", 3 * SEG, 1);
    let before = len_of(&bseg(&s, 1));
    poke(&bseg(&s, 1), before + 100_000, &[0xAB; 4_096]);
    let grown = len_of(&bseg(&s, 1));

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("V26 anchorless .bseg grew", &rep, &r, SEG);
    assert_eq!(
        len_of(&bseg(&s, 1)),
        grown,
        "V26: bytes were deleted on the strength of a sidecar nothing can prove"
    );
    assert!(rep.integrity.overlong_truncated.is_empty());
    assert_eq!(rep.integrity.overlong_untruncated.len(), 1);
    assert!(
        rep.integrity.is_clean(),
        "V26: declining to repair is not damage"
    );
    let mut buf = Vec::new();
    assert_eq!(
        r.body_at(SEG + 7, &mut buf)
            .unwrap()
            .unwrap()
            .any_provenance(AcceptUnverified::because("V26 asserts serveability")),
        64
    );
    drop(c);
    drop(r);
}

#[test]
fn v21_hostile_open_bounded_lossless() {
    let _g = serial();
    machine_note("V21 open() on hostile stores");

    let a = seed("fv-v21a", 2 * SEG, 1);
    let b = seed("fv-v21b", 2 * SEG, 2);
    let hdr_before = len_of(&hdr(&a, 0)) + len_of(&hdr(&a, 1));
    let body_before = len_of(&bseg(&a, 0)) + len_of(&bseg(&a, 1));
    std::fs::copy(b.0.join("chain.redb"), a.0.join("chain.redb")).unwrap();
    drop(b);
    let t = Instant::now();
    let res = open(cfg_of(&a));
    let ms = t.elapsed().as_millis();
    let hdr_after = len_of(&hdr(&a, 0)) + len_of(&hdr(&a, 1));
    let body_after = len_of(&bseg(&a, 0)) + len_of(&bseg(&a, 1));
    match res {
        Ok((c, r, rep)) => {
            println!(
                "{}V21a alien chain.redb: open OK in {ms} ms | clean={} tip={} anchors_ok={}",
                tag(),
                rep.integrity.is_clean(),
                r.tip().height,
                rep.anchors_verified
            );
            drop(c);
            drop(r);
        }
        Err(e) => println!(
            "{}V21a alien chain.redb: open REFUSED in {ms} ms | {e}",
            tag()
        ),
    }
    println!(
        "      header bytes {hdr_before} -> {hdr_after} | body bytes {body_before} -> {body_after}"
    );
    assert!(ms < 30_000, "V21a open took {ms} ms");
    assert_eq!(hdr_after, hdr_before, "V21a lost header bytes");
    assert_eq!(body_after, body_before, "V21a lost body bytes");
    drop(a);

    let s = seed("fv-v21b2", 4 * SEG, 1);
    for seg in anchor_rows(&s) {
        let mut row = anchor_get(&s, seg).unwrap();
        row[10] ^= 0xFF;
        anchor_put(&s, seg, row);
    }
    let t = Instant::now();
    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    let ms = t.elapsed().as_millis();
    println!(
        "{}V21b every anchor mismatched: open OK in {ms} ms | body_dmg={} bytes_read={} \
         segments_checked={}",
        tag(),
        rep.integrity.body_damage.len(),
        rep.integrity.anchor_bytes_read,
        rep.integrity.anchor_segments_checked
    );
    assert_eq!(rep.integrity.body_damage.len(), 4);
    assert!(ms < 30_000, "V21b open took {ms} ms");
    drop(c);
    drop(r);
}

#[test]
fn v27_anchor_table_cost() {
    let _g = serial();
    machine_note("V27 body_anchor footprint, from redb's allocator");
    let mut page_size = 0u64;
    for segs in [1u64, 2, 4, 8] {
        let s = seed(&format!("fv-v27-{segs}"), segs * SEG, 1);
        let (mut c, r, _) = open(cfg_of(&s)).expect("open");
        let t = r
            .table_footprints()
            .unwrap()
            .into_iter()
            .find(|t| t.name == "body_anchor")
            .expect("body_anchor must appear in the per-table accounting");
        let page = c.db_footprint().unwrap().page_size;
        page_size = page;
        assert_eq!(t.rows, segs, "one row per sealed segment");
        assert_eq!(t.stored_bytes, segs * 69, "65 B of value + 4 B of key");
        println!(
            "  V27 {segs} segments: rows {} stored {} B | pages {}+{} = {} B | \
             per-segment true cost {} B",
            t.rows,
            t.stored_bytes,
            t.leaf_pages,
            t.branch_pages,
            t.page_bytes(page),
            t.page_bytes(page) / segs
        );
        drop(c);
        drop(r);
    }

    let s = Scratch::new("fv-v27-rows");
    {
        let (c, r, _) = open(cfg_of(&s)).expect("open");
        drop(c);
        drop(r);
    }
    for n in [129u32, 643] {
        let db = db_of(&s);
        let mut txn = db.begin_write().unwrap();
        txn.set_durability(redb::Durability::Immediate);
        {
            let mut t = txn.open_table(ANCHOR_T).unwrap();
            for seg in 0..n {
                t.insert(seg, &[0xA5u8; 65]).unwrap();
            }
        }
        txn.commit().unwrap();
        let txn = db.begin_read().unwrap();
        let t = txn.open_table(ANCHOR_T).unwrap();
        let st = t.stats().unwrap();
        let pages = st.leaf_pages() + st.branch_pages();
        println!(
            "  V27 {n} rows: stored {} B | leaves {} branches {} = {} B | \
             {:.1} B/segment true footprint",
            st.stored_bytes(),
            st.leaf_pages(),
            st.branch_pages(),
            pages * page_size,
            (pages * page_size) as f64 / n as f64
        );
        assert_eq!(st.stored_bytes(), n as u64 * 69);
    }
}

#[test]
fn v22_startup_cost_counted() {
    let _g = serial();
    machine_note("V22 L1 anchor tier startup cost");
    for segs in [1u64, 2, 4] {
        let s = seed(&format!("fv-v22-{segs}"), segs * SEG, 1);
        let t = Instant::now();
        let (c, r, rep) = open(cfg_of(&s)).expect("open");
        let us = t.elapsed().as_micros();
        assert_eq!(rep.integrity.anchor_segments_checked as u64, segs);
        assert_eq!(rep.integrity.anchor_bytes_read, segs * 33_048);
        assert_eq!(rep.anchors_verified as u64, segs);
        println!(
            "{}V22 {segs} sealed segments: anchor bytes {} (exact) | open {us} us | sweep {} us",
            tag(),
            rep.integrity.anchor_bytes_read,
            rep.integrity.check_micros
        );
        drop(c);
        drop(r);
    }
}
