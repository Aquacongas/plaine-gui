use std::time::{Duration, Instant};

use crate::error::StoreError;
use crate::layout;
use crate::reader::StoreReader;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepTrigger {
    Startup,
    Periodic,
    Targeted,
    Operator,
}

impl SweepTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            SweepTrigger::Startup => "startup",
            SweepTrigger::Periodic => "periodic",
            SweepTrigger::Targeted => "targeted-post-reorg",
            SweepTrigger::Operator => "operator",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SweepVerdict {
    Clean { segments: usize, links: u64 },
    Broken(Vec<(u32, u64)>),
    NothingJudged,
}

#[derive(Clone, Debug, Default)]
pub struct HeaderSweepReport {
    pub trigger: Option<SweepTrigger>,
    pub attempted: Vec<u32>,
    pub judged: Vec<u32>,
    pub links: u64,
    pub broken: Vec<(u32, u64)>,
    pub unjudged: u64,
    pub errors: u64,
    pub elapsed: Duration,
    pub bytes_read: u64,
    pub wrapped: bool,
}

impl HeaderSweepReport {
    pub fn verdict(&self) -> SweepVerdict {
        if !self.broken.is_empty() {
            return SweepVerdict::Broken(self.broken.clone());
        }
        if self.judged.is_empty() {
            return SweepVerdict::NothingJudged;
        }
        SweepVerdict::Clean { segments: self.judged.len(), links: self.links }
    }

    pub fn is_clean(&self) -> bool {
        matches!(self.verdict(), SweepVerdict::Clean { .. })
    }

    pub fn line(&self) -> String {
        let trig = self.trigger.map(|t| t.as_str()).unwrap_or("unspecified");
        let ms = self.elapsed.as_secs_f64() * 1e3;
        match self.verdict() {
            SweepVerdict::Broken(ref b) => format!(
                "L3-H ({trig}): {} broken header link(s) {b:?} - the header at that height does \
                 not state the hash of the header below it, so at least one header in that \
                 segment is not the one this node sealed. {} segment(s) walked, {} link(s) \
                 verified, {} could not be judged, {} read in {ms:.1} ms.",
                b.len(),
                self.judged.len(),
                self.links,
                self.unjudged,
                self.bytes_read
            ),
            SweepVerdict::Clean { segments, links } => format!(
                "L3-H ({trig}): {segments} sealed header segment(s) walked, {links} link(s) \
                 verified, 0 broken, {} could not be judged (not sealed, absent, or already \
                 named damaged by L1). {} bytes read in {ms:.1} ms. Could-not-be-judged is not \
                 the same as clean, and this is not the L2 line: L2 reads no interior header.",
                self.unjudged, self.bytes_read
            ),
            SweepVerdict::NothingJudged => format!(
                "L3-H ({trig}): nothing was judged. {} segment(s) attempted, {} could not be \
                 judged ({} of them by error), 0 walked. This is not a clean verdict: it is \
                 the verdict of a store with no sealed header segment in range, or one whose \
                 segments L1 has already condemned. {ms:.1} ms.",
                self.attempted.len(),
                self.unjudged,
                self.errors
            ),
        }
    }

    fn absorb(&mut self, seg: u32, r: Result<Option<u64>, StoreError>) {
        self.attempted.push(seg);
        match r {
            Ok(Some(n)) => {
                self.judged.push(seg);
                self.links += n;

                self.bytes_read += layout::HDR_SEG_BYTES
                    + if n >= layout::SEG_BLOCKS { HEADER_BYTES_U64 } else { 0 };
            }
            Ok(None) => self.unjudged += 1,
            Err(StoreError::LinkageBroken { height, .. }) => {
                self.judged.push(seg);
                self.broken.push((seg, height));
                self.bytes_read += layout::HDR_SEG_BYTES;
            }
            Err(_) => {
                self.unjudged += 1;
                self.errors += 1;
            }
        }
    }
}

const HEADER_BYTES_U64: u64 = plaine_consensus::constants::HEADER_BYTES as u64;

pub fn sweep_segments(
    reader: &StoreReader,
    segs: &[u32],
    trigger: SweepTrigger,
) -> HeaderSweepReport {
    let t0 = Instant::now();
    let mut out = HeaderSweepReport { trigger: Some(trigger), ..Default::default() };
    for &seg in segs {
        out.absorb(seg, reader.verify_segment_headers(seg));
    }
    out.elapsed = t0.elapsed();
    out
}

pub fn sweepable_range(reader: &StoreReader) -> (u32, u32) {
    let first = layout::seg_of(reader.prune_floor());
    let last = layout::seg_of(reader.tip().height).max(first);
    (first, last)
}

pub fn sweep_all(reader: &StoreReader, trigger: SweepTrigger) -> HeaderSweepReport {
    let (first, last) = sweepable_range(reader);
    let segs: Vec<u32> = (first..=last).collect();
    sweep_segments(reader, &segs, trigger)
}

#[derive(Debug, Clone)]
pub struct HeaderSweeper {
    cursor: u32,
    cycles: u64,
    budget: u32,
}

impl Default for HeaderSweeper {
    fn default() -> Self {
        Self::new(1)
    }
}

impl HeaderSweeper {
    pub fn new(budget_segments: u32) -> Self {
        Self { cursor: 0, cycles: 0, budget: budget_segments.max(1) }
    }

    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    pub fn cursor(&self) -> u32 {
        self.cursor
    }

    pub fn step(&mut self, reader: &StoreReader) -> HeaderSweepReport {
        let t0 = Instant::now();
        let mut out = HeaderSweepReport { trigger: Some(SweepTrigger::Periodic), ..Default::default() };

        for seg in reader.take_header_sweep_targets() {
            out.absorb(seg, reader.verify_segment_headers(seg));
        }

        let (first, last) = sweepable_range(reader);
        if self.cursor < first || self.cursor > last {
            self.cursor = first;
        }
        for _ in 0..self.budget {
            let seg = self.cursor;

            if !out.attempted.contains(&seg) {
                out.absorb(seg, reader.verify_segment_headers(seg));
            }
            if seg >= last {
                self.cursor = first;
                self.cycles += 1;
                out.wrapped = true;
            } else {
                self.cursor = seg + 1;
            }
        }
        out.elapsed = t0.elapsed();
        out
    }
}
