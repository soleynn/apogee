//! The seam: what a pristine install's containers should hold, and where this one disagrees.
//!
//! A [`PristineMap`] is a plain value a caller builds and hands in. It names nothing this crate does
//! not already name: containers, byte offsets and lengths. There is no patch in it, no CRC and no
//! chain, which is what lets the crate stay the read side of the archive format and still answer
//! "which of these files did a mod tool put there".
//!
//! Whoever holds a patch-derived block index and a verification of the tree against it has exactly
//! the two facts a map is made of: how long each container should be, and which byte ranges no
//! longer match. Lowering those into a map is a walk over each, and it belongs to the crate that owns
//! them.
//!
//! Two properties are load-bearing and easy to get wrong:
//!
//! - **A map covers what it covers.** A base-game block index says nothing about `sqpack/ex3`, and a
//!   container a map does not describe must not be read as one a mod tool invented. That is what
//!   [`MapBuilder::accounts_for`] is: an explicit claim, per repository, that the map is exhaustive
//!   there. Without it every unmapped container is [`crate::mods::Standing::Unknown`].
//! - **A length is a measurement.** Bytes past `pristine_len` are bytes no patch ever wrote, which is
//!   the whole of how appended content is recognised, so the length has to come from the map rather
//!   than from the file on disk.

use std::collections::{BTreeMap, BTreeSet};

use crate::game::Repo;
use crate::integrity::ContainerRef;

/// A half-open byte range of one container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteRange {
    /// First byte covered.
    pub start: u64,
    /// One past the last byte covered.
    pub end: u64,
}

impl ByteRange {
    /// The range of `len` bytes at `start`, saturating rather than wrapping on a hostile length.
    #[must_use]
    pub fn at(start: u64, len: u64) -> Self {
        Self {
            start,
            end: start.saturating_add(len),
        }
    }

    /// Whether the range covers no bytes.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.end <= self.start
    }

    /// How many bytes the range covers.
    #[must_use]
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the two ranges share a byte. Half-open, so ranges that merely touch do not.
    #[must_use]
    pub fn intersects(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// What the map says one container should hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    pristine_len: u64,
    dirty: Vec<ByteRange>,
}

impl Coverage {
    /// The length the container should have.
    #[must_use]
    pub fn pristine_len(&self) -> u64 {
        self.pristine_len
    }

    /// Every run whose bytes were measured not to match, ascending, disjoint and merged.
    #[must_use]
    pub fn dirty(&self) -> &[ByteRange] {
        &self.dirty
    }

    /// Whether the map vouches for the container end to end: nothing dirty, and it is the length it
    /// should be. This is the whole of the fast path, since a container that answers yes needs no
    /// byte of it read to know every file in it is pristine.
    #[must_use]
    pub fn vouches_whole(&self, actual_len: u64) -> bool {
        self.dirty.is_empty() && actual_len == self.pristine_len
    }

    /// The dirty runs a byte range touches, as a slice. The runs are held ascending and disjoint, so
    /// this is two binary searches rather than a scan.
    #[must_use]
    pub fn dirty_in(&self, range: ByteRange) -> &[ByteRange] {
        let start = self.dirty.partition_point(|run| run.end <= range.start);
        let end = self.dirty.partition_point(|run| run.start < range.end);
        self.dirty.get(start..end.max(start)).unwrap_or_default()
    }
}

/// Where a pristine install's SqPack bytes should be, and where this one disagrees.
///
/// Built by a caller, never parsed: nothing here reads a file or decodes a format, so the usual
/// hostile-input bounds do not apply and none are imposed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PristineMap {
    containers: BTreeMap<ContainerRef, Coverage>,
    accounted: BTreeSet<Repo>,
}

impl PristineMap {
    /// Start building a map.
    #[must_use]
    pub fn builder() -> MapBuilder {
        MapBuilder::default()
    }

    /// What the map says about one container, or `None` when it describes none.
    #[must_use]
    pub fn coverage(&self, at: ContainerRef) -> Option<&Coverage> {
        self.containers.get(&at)
    }

    /// Whether the map claims to describe every container of a repository.
    ///
    /// This is the difference between "a data file the pristine install never had" and "a data file
    /// this map was never asked about", and nothing but the caller can tell them apart.
    #[must_use]
    pub fn accounts_for(&self, repo: Repo) -> bool {
        self.accounted.contains(&repo)
    }

    /// Every container described, ascending.
    pub fn containers(&self) -> impl ExactSizeIterator<Item = (ContainerRef, &Coverage)> {
        self.containers.iter().map(|(at, coverage)| (*at, coverage))
    }

    /// Whether the map describes nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }
}

/// Builds a [`PristineMap`] from what a caller measured.
#[derive(Debug, Clone, Default)]
pub struct MapBuilder {
    containers: BTreeMap<ContainerRef, Coverage>,
    accounted: BTreeSet<Repo>,
}

impl MapBuilder {
    /// Claim that the map describes every container of `repo`, so one it does not name is one the
    /// pristine install did not have.
    ///
    /// A claim, not a derivation: only the caller knows whether the block index it built this from
    /// covered the whole repository. Claiming it wrongly is the worst mistake available here, since
    /// it turns a pristine archive the map simply never saw into a wholly foreign one.
    pub fn accounts_for(&mut self, repo: Repo) -> &mut Self {
        self.accounted.insert(repo);
        self
    }

    /// Describe a container: the length it should be, before any dirty run is recorded against it.
    ///
    /// Called twice for one container, the later length wins and the dirty runs accumulate.
    pub fn container(&mut self, at: ContainerRef, pristine_len: u64) -> &mut Self {
        self.containers.entry(at).or_default().pristine_len = pristine_len;
        self
    }

    /// Describe a container the map has and the tree does not: every byte of it disagrees.
    pub fn absent(&mut self, at: ContainerRef, pristine_len: u64) -> &mut Self {
        self.container(at, pristine_len).dirty(at, 0, pristine_len)
    }

    /// Record `len` bytes at `start` whose contents do not match what the map says.
    ///
    /// Ignored for a container [`MapBuilder::container`] did not describe: a map cannot call bytes
    /// wrong in a container it does not explain, and a container it does not explain is already
    /// answered by [`PristineMap::accounts_for`].
    pub fn dirty(&mut self, at: ContainerRef, start: u64, len: u64) -> &mut Self {
        if let Some(coverage) = self.containers.get_mut(&at) {
            let range = ByteRange::at(start, len);
            if !range.is_empty() {
                coverage.dirty.push(range);
            }
        }
        self
    }

    /// The finished map, with every container's runs sorted, merged and disjoint.
    ///
    /// Merging matters for more than tidiness: the classification asks whether a run touches more
    /// than one file, and two abutting runs left unmerged would answer that question twice about the
    /// same bytes.
    #[must_use]
    pub fn build(mut self) -> PristineMap {
        for coverage in self.containers.values_mut() {
            merge(&mut coverage.dirty);
        }
        PristineMap {
            containers: self.containers,
            accounted: self.accounted,
        }
    }
}

/// Sort and coalesce a container's dirty runs in place. Ranges that abut are one run: they name one
/// contiguous stretch of bytes, however many writes reported it.
fn merge(runs: &mut Vec<ByteRange>) {
    if runs.len() < 2 {
        return;
    }
    runs.sort_unstable();
    let mut kept = 0;
    for i in 1..runs.len() {
        let next = runs[i];
        if next.start <= runs[kept].end {
            runs[kept].end = runs[kept].end.max(next.end);
        } else {
            kept += 1;
            runs[kept] = next;
        }
    }
    runs.truncate(kept + 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::integrity::ContainerId;

    fn dat(n: u8) -> ContainerRef {
        ContainerRef::new(Repo::Base, ArchiveId::new(0x0a, 0, 0), ContainerId::Dat(n))
    }

    #[test]
    fn overlapping_and_abutting_runs_become_one() {
        let mut b = PristineMap::builder();
        b.container(dat(0), 8192)
            // Deliberately out of order, overlapping, abutting, and one that touches nothing.
            .dirty(dat(0), 4096, 512)
            .dirty(dat(0), 128, 128)
            .dirty(dat(0), 4608, 512)
            .dirty(dat(0), 192, 128)
            .dirty(dat(0), 7000, 0);
        let map = b.build();
        let coverage = map.coverage(dat(0)).unwrap();
        assert_eq!(
            coverage.dirty(),
            [
                ByteRange {
                    start: 128,
                    end: 320
                },
                ByteRange {
                    start: 4096,
                    end: 5120
                },
            ]
        );
        assert_eq!(coverage.pristine_len(), 8192);
    }

    #[test]
    fn a_run_against_an_undescribed_container_is_dropped() {
        // A map cannot say bytes are wrong in a container it does not explain: that container is
        // already answered by whether the repository is accounted for.
        let mut b = PristineMap::builder();
        b.dirty(dat(1), 0, 128);
        let map = b.build();
        assert!(map.coverage(dat(1)).is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn a_container_the_map_has_and_the_tree_does_not_is_dirty_end_to_end() {
        let mut b = PristineMap::builder();
        b.absent(dat(0), 4096);
        let map = b.build();
        let coverage = map.coverage(dat(0)).unwrap();
        assert_eq!(
            coverage.dirty(),
            [ByteRange {
                start: 0,
                end: 4096
            }]
        );
        // It cannot vouch for anything, at any length.
        assert!(!coverage.vouches_whole(4096));
        assert!(!coverage.vouches_whole(0));
    }

    #[test]
    fn vouching_needs_both_a_clean_run_list_and_the_right_length() {
        let mut b = PristineMap::builder();
        b.container(dat(0), 4096);
        let map = b.build();
        let coverage = map.coverage(dat(0)).unwrap();
        assert!(coverage.vouches_whole(4096));
        // Appended bytes are not dirty bytes: nothing measured them, and the length is what says so.
        assert!(!coverage.vouches_whole(8192));
        assert!(!coverage.vouches_whole(2048));
    }

    #[test]
    fn the_runs_touching_a_range_are_found_by_bisection() {
        let mut b = PristineMap::builder();
        b.container(dat(0), 8192)
            .dirty(dat(0), 0, 128)
            .dirty(dat(0), 1024, 128)
            .dirty(dat(0), 4096, 128);
        let map = b.build();
        let coverage = map.coverage(dat(0)).unwrap();

        assert_eq!(coverage.dirty_in(ByteRange::at(0, 8192)).len(), 3);
        assert_eq!(coverage.dirty_in(ByteRange::at(1024, 128)).len(), 1);
        // Half-open: a range ending exactly where a run starts touches nothing.
        assert!(coverage.dirty_in(ByteRange::at(896, 128)).is_empty());
        assert!(coverage.dirty_in(ByteRange::at(1152, 128)).is_empty());
        assert_eq!(coverage.dirty_in(ByteRange::at(1000, 200)).len(), 1);
        // Ending exactly at the third run's first byte leaves it out; one byte further takes it in.
        assert_eq!(coverage.dirty_in(ByteRange::at(64, 4032)).len(), 2);
        assert_eq!(coverage.dirty_in(ByteRange::at(64, 4033)).len(), 3);
        // An empty range touches nothing wherever it sits.
        assert!(coverage.dirty_in(ByteRange::at(1024, 0)).is_empty());
    }

    #[test]
    fn a_repository_is_accounted_for_only_when_the_caller_says_so() {
        let mut b = PristineMap::builder();
        b.container(dat(0), 4096).accounts_for(Repo::Base);
        let map = b.build();
        assert!(map.accounts_for(Repo::Base));
        assert!(!map.accounts_for(Repo::Ex(3)));
        assert_eq!(map.containers().len(), 1);
    }
}
