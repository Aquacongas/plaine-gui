mod common;

use std::time::Instant;

use common::{body, commits, serial, Chain, Scratch};
use plaine_storage::{open, DamageKind, DurabilityMode, OpenReport, StoreConfig, StoreError};

const SEG: u64 = plaine_storage::SEG_BLOCKS;
const HDR_SEG_BYTES: u64 = plaine_storage::HDR_SEG_BYTES;

fn seed_len(name: &str, n: u64, variant: u64, body_len: usize) -> Scratch {
    let s = Scratch::new(name);
    let mut cfg = s.cfg();
    cfg.state_ckpt_interval = 0;
    cfg.ibd_batch_blocks = Some(4_096);
    let (mut c, r, rep) = open(cfg).expect("open");
    assert!(rep.integrity.is_clean(), "a fresh store reported damage");
    c.set_mode(DurabilityMode::Ibd).unwrap();
    let mut chain = Chain::new(64, body_len, 2);
    let bs = chain.build(n, variant);
    c.extend(&commits(&bs)).unwrap();
    c.flush().unwrap();
    drop(c);
    drop(r);
    s
}

fn seed(name: &str, n: u64, variant: u64) -> Scratch {
    seed_len(name, n, variant, 64)
}

fn cfg_of(s: &Scratch) -> StoreConfig {
    let mut c = s.cfg();
    c.state_ckpt_interval = 0;
    c
}

fn hdr(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("hdr")
        .join(format!("{seg:06x}.hseg"))
}
fn bseg(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bseg"))
}
fn bidx(s: &Scratch, seg: u32) -> std::path::PathBuf {
    s.0.join("segments")
        .join("body")
        .join(format!("{seg:06x}.bidx"))
}

fn set_len(p: &std::path::Path, n: u64) {
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    f.set_len(n).unwrap();
    f.sync_all().unwrap();
}

fn poke(p: &std::path::Path, off: u64, bytes: &[u8]) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

fn len_of(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn verdict(name: &str, rep: &OpenReport) {
    println!(
        "  {name:<50} open OK | clean={} hdr_dmg={} body_dmg={} overlong={} unlinked={} \
         hdr_trunc={:?} body_trunc={:?} bidx_rebuilt={:?}",
        rep.integrity.is_clean(),
        rep.integrity.header_damage.len(),
        rep.integrity.body_damage.len(),
        rep.integrity.overlong_truncated.len(),
        rep.segments_unlinked,
        rep.headers_truncated_to,
        rep.bodies_truncated_to,
        rep.bidx_rebuilt_segments,
    );
}

#[test]
fn m01_zero_len_sealed_hdr() {
    let _g = serial();
    let s = seed("adv-m01", 3 * SEG, 1);
    set_len(&hdr(&s, 1), 0);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M1 zero-length sealed .hseg", &rep);
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.header_damage[0];
    assert_eq!(
        d.reason,
        DamageKind::Short,
        "a 0-byte file is not 'missing'"
    );
    assert_eq!((d.first_height, d.last_height), (SEG, 2 * SEG - 1));
    assert_eq!(d.actual_len, Some(0));
    assert_eq!(d.expected_len, HDR_SEG_BYTES);
    assert!(matches!(
        r.header_at(SEG + 10),
        Err(StoreError::SegmentDamaged { .. })
    ));
    assert_eq!(r.intact_header_floor(), 2 * SEG);
    drop(c);
}

#[test]
fn m02_sealed_hdr_one_short() {
    let _g = serial();
    let s = seed("adv-m02", 3 * SEG, 1);
    set_len(&hdr(&s, 1), HDR_SEG_BYTES - 132);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M2 sealed .hseg one header short", &rep);
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.header_damage[0];
    assert_eq!(d.reason, DamageKind::Short);
    assert_eq!(
        (d.first_height, d.last_height),
        (2 * SEG - 1, 2 * SEG - 1),
        "exactly one height is lost and exactly one must be named"
    );
    assert!(r.header_at(2 * SEG - 2).unwrap().is_some(), "over-reported");
    assert!(matches!(
        r.header_at(2 * SEG - 1),
        Err(StoreError::SegmentDamaged { .. })
    ));
    drop(c);
}

#[test]
fn m03_zero_filled_sealed_hdr() {
    let _g = serial();
    let s = seed("adv-m03", 3 * SEG, 1);
    poke(&hdr(&s, 1), 0, &vec![0u8; HDR_SEG_BYTES as usize]);
    assert_eq!(len_of(&hdr(&s, 1)), HDR_SEG_BYTES);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M3 zero-filled sealed .hseg", &rep);
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.header_damage[0];
    assert_eq!(d.reason, DamageKind::LinkBroken);
    assert_eq!(d.segment, 1);
    assert_eq!((d.first_height, d.last_height), (SEG, 2 * SEG - 1));

    assert!(
        r.header_at(2 * SEG).unwrap().is_some(),
        "over-reported segment 2"
    );
    assert_eq!(r.intact_header_floor(), 2 * SEG);
    drop(c);
}

#[test]
fn m04_duplicated_header_segment() {
    let _g = serial();
    let s = seed("adv-m04", 3 * SEG, 1);
    std::fs::copy(hdr(&s, 0), hdr(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M4 header segment 0 duplicated over 1", &rep);
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(
        rep.integrity.header_damage[0].reason,
        DamageKind::LinkBroken
    );
    assert!(matches!(
        r.header_at(SEG + 100),
        Err(StoreError::SegmentDamaged { .. })
    ));
    drop(c);
}

#[test]
fn m05_foreign_hdr_segment() {
    let _g = serial();
    let alien = seed("adv-m05-alien", 3 * SEG, 7);
    let victim = seed("adv-m05", 3 * SEG, 1);
    std::fs::copy(hdr(&alien, 1), hdr(&victim, 1)).unwrap();
    assert_eq!(len_of(&hdr(&victim, 1)), HDR_SEG_BYTES);

    let (c, r, rep) = open(cfg_of(&victim)).expect("open");
    verdict("M5 .hseg from another store", &rep);
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(
        rep.integrity.header_damage[0].reason,
        DamageKind::LinkBroken
    );
    assert!(matches!(
        r.header_at(SEG + 100),
        Err(StoreError::SegmentDamaged { .. })
    ));
    drop(c);
}

#[test]
fn m14_stray_segment_above_wm() {
    let _g = serial();
    let s = seed("adv-m14", 3 * SEG, 1);
    std::fs::copy(hdr(&s, 0), hdr(&s, 0xFF)).unwrap();
    std::fs::copy(bseg(&s, 0), bseg(&s, 0xFF)).unwrap();
    std::fs::copy(bidx(&s, 0), bidx(&s, 0xFF)).unwrap();

    let (c, _r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M14 stray segment 0x0000ff", &rep);
    assert!(
        rep.integrity.is_clean(),
        "scratch was called damage: {:?}",
        rep.integrity
    );
    assert!(!hdr(&s, 0xFF).exists(), "stray .hseg survived");
    assert!(!bseg(&s, 0xFF).exists(), "stray .bseg survived");
    assert!(!bidx(&s, 0xFF).exists(), "stray .bidx survived");
    drop(c);
}

#[test]
fn m08_zero_len_body_intact_sidecar() {
    let _g = serial();
    let s = seed("adv-m08", 3 * SEG, 1);
    set_len(&bseg(&s, 1), 0);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M8 zero-length .bseg, sidecar intact", &rep);
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.body_damage[0];
    assert_eq!(d.reason, DamageKind::Short);
    assert_eq!((d.first_height, d.last_height), (SEG, 2 * SEG - 1));
    assert_eq!(d.actual_len, Some(0));
    let mut buf = Vec::new();
    assert!(matches!(
        r.body_at(SEG + 5, &mut buf),
        Err(StoreError::SegmentDamaged { .. })
    ));
    assert_eq!(r.prune_floor(), 0, "a hole must never move the prune floor");
    drop(c);
}

#[test]
fn m09_sidecar_rotated_by_one_slot() {
    let _g = serial();
    let s = seed("adv-m09", 3 * SEG, 1);
    let (c0, r0, _) = open(cfg_of(&s)).expect("open");
    let mut want = Vec::new();
    let mut neighbour = Vec::new();
    body(&r0, SEG, &mut want);
    body(&r0, SEG + 1, &mut neighbour);
    drop(c0);
    drop(r0);
    assert_ne!(want, neighbour);

    let mut raw = std::fs::read(bidx(&s, 1)).unwrap();
    let tail = raw[8..].to_vec();
    raw[..tail.len()].copy_from_slice(&tail);
    poke(&bidx(&s, 1), 0, &raw);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M9 sidecar rotated one slot", &rep);
    assert!(!rep.integrity.is_clean(), "a rotated sidecar was accepted");
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.body_damage[0];
    assert_eq!(d.reason, DamageKind::AnchorMismatch);
    assert_eq!((d.first_height, d.last_height), (SEG, 2 * SEG - 1));
    let mut got = Vec::new();
    assert!(
        matches!(
            r.body_at(SEG, &mut got),
            Err(StoreError::SegmentDamaged { .. })
        ),
        "the next height's body was served as this one's"
    );
    assert!(r.is_degraded());

    assert!(body(&r, 10, &mut got) > 0);
    assert!(body(&r, 2 * SEG + 10, &mut got) > 0);
    assert_eq!(
        r.body_availability(SEG + 1),
        plaine_storage::RangeAvailability::Damaged {
            first: SEG,
            last: 2 * SEG - 1,
            reason: DamageKind::AnchorMismatch
        }
    );
    drop(c);
}

#[test]
fn m10_foreign_body_pair() {
    let _g = serial();
    let alien = seed_len("adv-m10-alien", 3 * SEG, 7, 96);
    let victim = seed_len("adv-m10", 3 * SEG, 1, 64);
    let (c0, r0, _) = open(cfg_of(&victim)).expect("open");
    let mut mine = Vec::new();
    body(&r0, SEG, &mut mine);
    drop(c0);
    drop(r0);

    std::fs::copy(bseg(&alien, 1), bseg(&victim, 1)).unwrap();
    std::fs::copy(bidx(&alien, 1), bidx(&victim, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&victim)).expect("open");
    verdict("M10 matched .bseg+.bidx pair from another store", &rep);
    assert!(
        !rep.integrity.is_clean(),
        "an alien body segment was accepted"
    );
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(
        rep.integrity.body_damage[0].reason,
        DamageKind::AnchorMismatch
    );
    let mut got = Vec::new();
    assert!(
        matches!(
            r.body_at(SEG, &mut got),
            Err(StoreError::SegmentDamaged { .. })
        ),
        "another chain's bytes were served with a valid CRC"
    );
    assert!(r.is_degraded());
    assert_eq!(r.damaged_ranges().len(), 1);

    assert!(
        r.body_anchor(1).unwrap().is_some(),
        "the anchor row is still there"
    );
    println!(
        "      body_at(4096) refused; anchor row intact and unreproducible; is_degraded={}",
        r.is_degraded()
    );
    drop(c);
}

#[test]
fn m11_alien_body_no_sidecar() {
    let _g = serial();
    let alien = seed_len("adv-m11-alien", 3 * SEG, 7, 96);
    let victim = seed_len("adv-m11", 3 * SEG, 1, 64);
    let (c0, r0, _) = open(cfg_of(&victim)).expect("open");
    let mut mine = Vec::new();
    body(&r0, SEG, &mut mine);
    drop(c0);
    drop(r0);

    std::fs::copy(bseg(&alien, 1), bseg(&victim, 1)).unwrap();
    std::fs::remove_file(bidx(&victim, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&victim)).expect("open");
    verdict("M11 alien .bseg, sidecar deleted (rebuild path)", &rep);
    assert!(
        !rep.integrity.is_clean(),
        "the rebuild adopted an alien segment"
    );
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(
        rep.integrity.body_damage[0].reason,
        DamageKind::AnchorMismatch,
        "the rebuild comparison, not the sweep, must be what refuses this"
    );
    assert!(
        !rep.bidx_rebuilt_segments.contains(&1),
        "a sidecar was written to fit a segment that is not ours"
    );
    assert!(
        !bidx(&victim, 1).exists(),
        "the alien was given a fresh index"
    );
    let mut got = Vec::new();
    assert!(matches!(
        r.body_at(SEG, &mut got),
        Err(StoreError::SegmentDamaged { .. })
    ));
    assert!(got != mine || got.is_empty());
    drop(c);
}

#[test]
fn m12_duplicated_body_segment_pair() {
    let _g = serial();
    let s = seed("adv-m12", 3 * SEG, 1);
    let (c0, r0, _) = open(cfg_of(&s)).expect("open");
    let mut at0 = Vec::new();
    let mut at4096 = Vec::new();
    body(&r0, 0, &mut at0);
    body(&r0, SEG, &mut at4096);
    drop(c0);
    drop(r0);
    assert_ne!(at0, at4096);

    std::fs::copy(bseg(&s, 0), bseg(&s, 1)).unwrap();
    std::fs::copy(bidx(&s, 0), bidx(&s, 1)).unwrap();

    assert_eq!(
        std::fs::read(bidx(&s, 0)).unwrap(),
        std::fs::read(bidx(&s, 1)).unwrap(),
        "the premise of this test is a byte-identical sidecar"
    );

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M12 body segment 0 duplicated over 1", &rep);
    assert!(
        !rep.integrity.is_clean(),
        "a duplicated body segment was accepted"
    );
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(
        rep.integrity.body_damage[0].reason,
        DamageKind::AnchorMismatch
    );
    let mut got = Vec::new();
    assert!(
        matches!(
            r.body_at(SEG, &mut got),
            Err(StoreError::SegmentDamaged { .. })
        ),
        "height 0's body was served as height 4096's"
    );
    assert!(got != at0 || got.is_empty());
    drop(c);
}

#[test]
fn m13_zero_length_sidecar() {
    let _g = serial();
    let s = seed("adv-m13", 3 * SEG, 1);
    set_len(&bidx(&s, 1), 0);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M13 zero-length .bidx, .bseg intact", &rep);
    assert!(
        rep.bidx_rebuilt_segments.contains(&1),
        "a derived sidecar was not rebuilt: {:?}",
        rep.bidx_rebuilt_segments
    );
    assert!(rep.integrity.is_clean(), "{:?}", rep.integrity);
    assert_eq!(len_of(&bidx(&s, 1)), plaine_storage::BIDX_SEG_BYTES);
    let mut buf = Vec::new();
    assert!(body(&r, SEG + 7, &mut buf) > 0);
    drop(c);
}

#[test]
fn m18_sidecar_gone_segment_short() {
    let _g = serial();
    let s = seed("adv-m18", 3 * SEG, 1);
    let half = len_of(&bseg(&s, 1)) / 2;
    set_len(&bseg(&s, 1), half);
    std::fs::remove_file(bidx(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M18 .bidx deleted + .bseg halved", &rep);
    assert!(
        !rep.integrity.is_clean(),
        "a half-segment was rebuilt as if whole"
    );
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert!(
        !rep.bidx_rebuilt_segments.contains(&1),
        "a sidecar was written for a segment that cannot back it"
    );
    let mut buf = Vec::new();
    assert!(matches!(
        r.body_at(SEG + 5, &mut buf),
        Err(StoreError::SegmentDamaged { .. })
    ));
    drop(c);
}

#[test]
fn m15_interior_sidecar_byte_flip() {
    let _g = serial();
    let s = seed("adv-m15", 3 * SEG, 1);
    poke(&bidx(&s, 1), 2_000 * 8, &[0xEE, 0xBE, 0x00, 0x00]);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M15 interior .bidx byte flip (slot 2000)", &rep);
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    let d = rep.integrity.body_damage[0];
    assert_eq!(
        d.reason,
        DamageKind::AnchorMismatch,
        "caught at boot, not at read"
    );
    assert_eq!((d.first_height, d.last_height), (SEG, 2 * SEG - 1));
    let mut buf = Vec::new();
    assert!(matches!(
        r.body_at(SEG + 2_000, &mut buf),
        Err(StoreError::SegmentDamaged { .. })
    ));

    assert!(body(&r, SEG - 1, &mut buf) > 0);
    assert!(body(&r, 2 * SEG + 1, &mut buf) > 0);
    drop(c);
}

#[test]
fn m16_overlong_sealed_body_segment() {
    let _g = serial();
    let s = seed("adv-m16", 3 * SEG, 1);
    let before = len_of(&bseg(&s, 1));
    poke(&bseg(&s, 1), before + 100_000, &[0xAB; 4_096]);
    assert!(len_of(&bseg(&s, 1)) > before);

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M16 sealed .bseg grew by 104,096 B", &rep);
    assert_eq!(
        rep.integrity.overlong_truncated.len(),
        1,
        "{:?}",
        rep.integrity
    );
    assert!(
        rep.integrity.is_clean(),
        "a lossless repair was reported as damage"
    );
    assert_eq!(
        len_of(&bseg(&s, 1)),
        before,
        "the file was not truncated back"
    );
    assert!(rep.body_scratch_discarded >= 100_000);
    let mut buf = Vec::new();
    assert!(body(&r, SEG + 7, &mut buf) > 0);
    drop(c);
}

#[test]
fn m17_both_streams_holed() {
    let _g = serial();
    let s = seed("adv-m17", 3 * SEG, 1);
    std::fs::remove_file(hdr(&s, 1)).unwrap();
    std::fs::remove_file(bseg(&s, 1)).unwrap();
    std::fs::remove_file(bidx(&s, 1)).unwrap();

    let (c, r, rep) = open(cfg_of(&s)).expect("open");
    verdict("M17 header AND body segment 1 deleted", &rep);
    assert_eq!(rep.integrity.header_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(rep.integrity.body_damage.len(), 1, "{:?}", rep.integrity);
    assert_eq!(rep.integrity.damaged_blocks(), 2 * SEG);
    assert_eq!(r.damaged_ranges().len(), 2);
    assert!(r.is_degraded());
    assert_eq!(r.prune_floor(), 0);
    drop(c);
}

#[test]
fn m07_byte_flip_inside_chain_redb() {
    let _g = serial();
    for off in [4_096u64, 65_536, 200_000] {
        let s = seed(&format!("adv-m07-{off}"), 2 * SEG, 1);
        let db = s.0.join("chain.redb");
        if len_of(&db) <= off + 64 {
            continue;
        }
        poke(&db, off, &[0xFF; 64]);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open(cfg_of(&s))));
        match res {
            Ok(Ok((c, r, rep))) => {
                println!(
                    "  M7 chain.redb flipped at {off:<8} open OK | clean={} tip={} wm={} \
                     fingerprint={:?}",
                    rep.integrity.is_clean(),
                    r.tip().height,
                    r.hdr_watermark(),
                    r.verify_state_fingerprint().map_err(|e| e.to_string())
                );
                drop(c);
            }
            Ok(Err(e)) => println!("  M7 chain.redb flipped at {off:<8} open REFUSED | {e}"),
            Err(_) => println!("  M7 chain.redb flipped at {off:<8} open PANICKED"),
        }
    }
}

#[test]
fn m06_foreign_chain_redb() {
    let _g = serial();
    let n = 2 * SEG;
    let alien = seed("adv-m06-alien", n, 7);
    let victim = seed("adv-m06", n, 1);
    let before: u64 = (0..2).map(|s| len_of(&hdr(&victim, s))).sum();
    std::fs::copy(alien.0.join("chain.redb"), victim.0.join("chain.redb")).unwrap();

    let t0 = Instant::now();
    let res = open(cfg_of(&victim));
    let ms = t0.elapsed().as_millis();
    let after: u64 = (0..2).map(|s| len_of(&hdr(&victim, s))).sum();
    match res {
        Ok((c, r, rep)) => {
            println!(
                "  M6 chain.redb from another store  open OK in {ms} ms | clean={} tip={} \
                 wm={} truncated_to={:?}",
                rep.integrity.is_clean(),
                r.tip().height,
                r.hdr_watermark(),
                rep.headers_truncated_to
            );
            drop(c);
        }
        Err(e) => println!("  M6 chain.redb from another store  open REFUSED in {ms} ms | {e}"),
    }
    println!(
        "      header bytes {before} -> {after} ({} of {n} headers destroyed by open() itself)",
        before.saturating_sub(after) / 132
    );
    assert_eq!(
        after, before,
        "open() truncated segments it could not reconcile"
    );
    assert!(ms < 30_000, "open() took {ms} ms");
}

#[test]
fn m19_last_header_lost() {
    let _g = serial();
    let n = 3_000u64;
    let s = seed("adv-m19", n, 1);
    let before = len_of(&hdr(&s, 0));
    set_len(&hdr(&s, 0), before - 132);

    let t0 = Instant::now();
    let res = open(cfg_of(&s));
    let ms = t0.elapsed().as_millis();
    let after = len_of(&hdr(&s, 0));
    match res {
        Ok((c, r, rep)) => {
            println!(
                "  M19 last committed header truncated away  open OK in {ms} ms | tip={} wm={} \
                 truncated_to={:?} clean={}",
                r.tip().height,
                r.hdr_watermark(),
                rep.headers_truncated_to,
                rep.integrity.is_clean()
            );
            assert_eq!(
                r.hdr_watermark(),
                n - 1,
                "the watermark did not stop at the loss"
            );
            assert_eq!(rep.headers_truncated_to, Some(n - 1));
            assert_eq!(r.tip().height, n - 2);
            assert_eq!(
                after,
                before - 132,
                "more than the lost header was discarded"
            );
            assert!(r.header_at(n - 2).unwrap().is_some());
            drop(c);
        }
        Err(e) => panic!("M19 open REFUSED in {ms} ms | {e} | hseg {before} -> {after}"),
    }
    assert!(ms < 30_000, "M19 open took {ms} ms");
}
