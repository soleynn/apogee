//! A coalesced set of half-open `[start, end)` byte intervals.
//!
//! The resume journal records which byte ranges are durably on disk. A single-connection download
//! grows one prefix `[0, watermark)`; a segmented download completes ranges out of order, so the set
//! coalesces overlapping and adjacent runs into the minimal cover. [`complement`](IntervalSet::complement)
//! turns that cover into the gaps a resume must still fetch.

use std::ops::Range;

/// A sorted, non-overlapping, non-adjacent set of half-open `[start, end)` intervals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IntervalSet {
    /// Sorted by `start`; no two runs overlap or touch; every run has `start < end`.
    runs: Vec<Range<u64>>,
}

impl IntervalSet {
    /// An empty set.
    pub(crate) fn new() -> Self {
        Self { runs: Vec::new() }
    }

    /// Build from unsorted, possibly overlapping runs, coalescing once. Empty/reversed runs are
    /// dropped.
    pub(crate) fn from_runs(runs: Vec<Range<u64>>) -> Self {
        let mut set = Self { runs };
        set.coalesce();
        set
    }

    /// Insert `[start, end)`, coalescing with any overlapping or adjacent runs. An empty or reversed
    /// range (`start >= end`) is ignored. (The set is otherwise built in bulk via [`from_runs`]; this
    /// incremental form backs the tests and the set's contract.)
    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.runs.push(start..end);
        self.coalesce();
    }

    /// The gaps in `[0, total)` this set does not cover, in ascending order: the ranges a resume must
    /// still fetch. Runs past `total` are clamped.
    pub(crate) fn complement(&self, total: u64) -> Vec<Range<u64>> {
        let mut gaps = Vec::new();
        let mut cursor = 0u64;
        for run in &self.runs {
            let start = run.start.min(total);
            if start > cursor {
                gaps.push(cursor..start);
            }
            cursor = cursor.max(run.end.min(total));
            if cursor >= total {
                return gaps;
            }
        }
        if cursor < total {
            gaps.push(cursor..total);
        }
        gaps
    }

    /// Total covered length.
    pub(crate) fn covered_len(&self) -> u64 {
        self.runs.iter().map(|r| r.end - r.start).sum()
    }

    /// The end of the contiguous run covering byte 0 (the resumable prefix), or 0 when 0 is uncovered.
    /// For a single-connection download this is exactly the old watermark.
    pub(crate) fn leading_end(&self) -> u64 {
        match self.runs.first() {
            Some(r) if r.start == 0 => r.end,
            _ => 0,
        }
    }

    /// The number of disjoint runs (a bound the journal caps to keep decoding total).
    pub(crate) fn len(&self) -> usize {
        self.runs.len()
    }

    /// Sort by start and merge overlapping or adjacent runs in one linear pass. Runs are already few
    /// (≈ segment count), so the sort is cheap.
    fn coalesce(&mut self) {
        self.runs.retain(|r| r.start < r.end);
        self.runs.sort_unstable_by_key(|r| r.start);
        let mut merged: Vec<Range<u64>> = Vec::with_capacity(self.runs.len());
        for run in self.runs.drain(..) {
            match merged.last_mut() {
                // `run.start <= last.end` is overlap or adjacency (touching runs form one region).
                Some(last) if run.start <= last.end => {
                    if run.end > last.end {
                        last.end = run.end;
                    }
                }
                _ => merged.push(run),
            }
        }
        self.runs = merged;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_coalesces_adjacent_and_overlapping() {
        let mut s = IntervalSet::new();
        s.insert(0, 10);
        s.insert(10, 20); // adjacent -> merges
        s.insert(15, 25); // overlaps -> extends
        assert_eq!(s.len(), 1);
        assert_eq!(s.covered_len(), 25);
        assert_eq!(s.leading_end(), 25);
    }

    #[test]
    fn insert_keeps_disjoint_runs_separate() {
        let mut s = IntervalSet::new();
        s.insert(0, 10);
        s.insert(20, 30);
        assert_eq!(s.len(), 2);
        assert_eq!(s.covered_len(), 20);
        assert_eq!(s.leading_end(), 10);
    }

    #[test]
    fn out_of_order_inserts_merge_the_gap() {
        let mut s = IntervalSet::new();
        s.insert(20, 30);
        s.insert(0, 10);
        s.insert(10, 20); // bridges the two, all coalesce
        assert_eq!(s.len(), 1);
        assert_eq!(s.leading_end(), 30);
    }

    #[test]
    fn empty_or_reversed_inserts_are_ignored() {
        let mut s = IntervalSet::new();
        s.insert(5, 5);
        s.insert(9, 4);
        assert_eq!(s.len(), 0);
        assert_eq!(s.leading_end(), 0);
    }

    #[test]
    fn complement_reports_the_gaps() {
        let mut s = IntervalSet::new();
        s.insert(0, 10);
        s.insert(20, 30);
        assert_eq!(s.complement(40), vec![10..20, 30..40]);
    }

    #[test]
    fn complement_of_a_full_prefix_is_the_tail() {
        let mut s = IntervalSet::new();
        s.insert(0, 25);
        assert_eq!(s.complement(100), vec![25..100]);
    }

    #[test]
    fn complement_of_a_full_cover_is_empty() {
        let mut s = IntervalSet::new();
        s.insert(0, 100);
        assert!(s.complement(100).is_empty());
    }

    #[test]
    fn complement_clamps_runs_past_total() {
        let mut s = IntervalSet::new();
        s.insert(0, 200); // covers past total
        assert!(s.complement(100).is_empty());
    }

    #[test]
    fn leading_end_is_zero_when_zero_is_uncovered() {
        let mut s = IntervalSet::new();
        s.insert(10, 20);
        assert_eq!(s.leading_end(), 0);
        assert_eq!(s.complement(20), vec![0..10]);
    }

    #[test]
    fn from_runs_coalesces_unsorted_input() {
        let s = IntervalSet::from_runs(vec![20..30, 0..10, 5..25, 40..40]);
        assert_eq!(s.len(), 1);
        assert_eq!(s.covered_len(), 30);
    }
}
