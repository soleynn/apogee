//! Mod detection: which of an install's files are the ones Square Enix shipped.
//!
//! The launcher's honest answer to "repair will revert your mods". Repair rewrites whatever
//! disagrees with the patch chain, which is exactly what a mod tool leaves behind, so before it runs
//! a user is owed the list. This module produces it.
//!
//! It works by comparing an install against a [`PristineMap`]: a caller-built value saying how long
//! each container should be and which of its byte ranges no longer match. Building one from a
//! patch-derived block index belongs to whoever holds that index; nothing here knows what a patch is.
//!
//! Three verdicts carry the meaning, and each rests on a different measurement:
//!
//! - **[`Standing::Pristine`]** — every byte the file is made of matches the map.
//! - **[`Standing::Modified`]** — the file sits where the map explains it and some of its bytes
//!   differ. Something rewrote it in the space the archive already held.
//! - **[`Standing::Foreign`]** — the file's bytes are past the length a data file should have, or in
//!   a data file the pristine install did not have. Appending content and repointing the index at it
//!   is what every mod tool does, which is why this arm rather than the last one carries them.
//!
//! What this module deliberately does not claim: it cannot tell an existing file retargeted at
//! appended bytes from a wholly new one, because it has no pristine key set to compare against, only
//! pristine *bytes*. Both are "not what Square Enix shipped", both are what a repair would revert,
//! and inventing a distinction between them would be a guess. Nor does it name files: SqPack lookups
//! are hash-based and this crate bundles no path dictionary, so a verdict carries the key and the
//! archive, and a caller with a hashlist supplies the rest.
//!
//! Cost is bounded by how much actually changed rather than by the size of the install. A container
//! the map vouches for end to end is answered without reading a byte of it, and so is one the map
//! never described, so a pristine install is classified out of its indexes alone.

mod classify;
mod map;
mod sweep;
mod verdict;

pub use classify::{ContainerComparison, classify_entries, content_extent};
pub use map::{ByteRange, Coverage, MapBuilder, PristineMap};
pub use verdict::{Confidence, ContainerStanding, ContainerVerdict, FileStanding, Standing};

use crate::integrity::ContainerRef;

/// Verdicts kept for one container before the rest are counted instead of carried. A container a mod
/// tool rebuilt otherwise names one verdict per entry, which is megabytes nobody reads.
pub const DEFAULT_MAX_FILES_PER_CONTAINER: usize = 4096;

/// How a comparison runs.
#[derive(Debug, Clone)]
pub struct ModOptions {
    /// Verdicts kept per container before the rest are counted instead of carried.
    pub max_files_per_container: usize,
}

impl Default for ModOptions {
    fn default() -> Self {
        Self {
            max_files_per_container: DEFAULT_MAX_FILES_PER_CONTAINER,
        }
    }
}

/// What a comparison found.
///
/// Pristine files are counted and not carried: a full install holds 1.9 M of them, and the list a
/// caller wants is the other one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModReport {
    /// Every file that is not pristine, ascending by `(container, offset, key)`. Two comparisons of
    /// one tree, at any thread count, produce identical reports.
    pub files: Vec<FileStanding>,
    /// How each container stands, ascending.
    pub containers: Vec<ContainerVerdict>,
    /// What the comparison counted.
    pub totals: ModTotals,
    /// Containers whose verdict list stopped at the budget, ascending and deduplicated.
    pub truncated: Vec<ContainerRef>,
}

impl ModReport {
    /// Whether the install holds only what the patch chain put there.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.totals.modified == 0 && self.totals.foreign == 0
    }

    /// How many files a repair would replace with something else. The number the pre-repair prompt
    /// is about.
    #[must_use]
    pub fn would_be_replaced(&self) -> u64 {
        self.totals.modified + self.totals.foreign
    }

    /// Whether every file was actually judged. False when the map did not speak for part of the
    /// install or a container could not be read, in which case the counts are about what was seen.
    #[must_use]
    pub fn is_exhaustive(&self) -> bool {
        self.totals.unknown == 0 && self.totals.containers_unreadable == 0
    }

    /// The files a repair would replace, in report order.
    pub fn replaced(&self) -> impl Iterator<Item = &FileStanding> {
        self.files
            .iter()
            .filter(|file| file.standing.repair_would_replace())
    }

    /// The files of one standing, in report order.
    pub fn of_standing(&self, standing: Standing) -> impl Iterator<Item = &FileStanding> {
        self.files
            .iter()
            .filter(move |file| file.standing == standing)
    }
}

/// What a comparison counted, so a report is honest about what it did not judge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModTotals {
    /// Data containers compared.
    pub containers: u32,
    /// Data containers that would not open or read, so nothing in them was judged.
    pub containers_unreadable: u32,
    /// Entry headers read. Far below the file count on a mostly-pristine install, which is the
    /// point: a vouched-for container is answered without reading one.
    pub entry_headers_read: u64,
    /// Files whose every byte matches the map.
    pub pristine: u64,
    /// Files rewritten where the map explains them.
    pub modified: u64,
    /// Files whose bytes the map explains nothing about.
    pub foreign: u64,
    /// Entries that do not hold together as entries.
    pub broken: u64,
    /// Files nothing was known about.
    pub unknown: u64,
    /// Verdicts resting on a run that covers more than one file, so which of them changed is not
    /// decided. A subset of `modified`.
    pub shared: u64,
    /// Verdicts the per-container budget dropped.
    pub files_suppressed: u64,
}

impl ModTotals {
    /// Fold another container's counts in. Every field sums, so the fold does not depend on the
    /// order the containers finished in.
    pub fn merge(&mut self, other: &ModTotals) {
        self.containers += other.containers;
        self.containers_unreadable += other.containers_unreadable;
        self.entry_headers_read += other.entry_headers_read;
        self.pristine += other.pristine;
        self.modified += other.modified;
        self.foreign += other.foreign;
        self.broken += other.broken;
        self.unknown += other.unknown;
        self.shared += other.shared;
        self.files_suppressed += other.files_suppressed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::game::Repo;
    use crate::integrity::ContainerId;

    fn file(standing: Standing) -> FileStanding {
        FileStanding {
            container: ContainerRef::new(
                Repo::Base,
                ArchiveId::new(0x0a, 0, 0),
                ContainerId::Dat(0),
            ),
            key: 1,
            offset: 2048,
            len: 128,
            standing,
            confidence: Confidence::Exact,
        }
    }

    #[test]
    fn a_report_says_how_many_files_a_repair_would_replace() {
        let report = ModReport {
            files: vec![
                file(Standing::Modified),
                file(Standing::Foreign),
                file(Standing::Broken),
            ],
            totals: ModTotals {
                pristine: 900,
                modified: 1,
                foreign: 1,
                broken: 1,
                ..ModTotals::default()
            },
            ..ModReport::default()
        };
        assert!(!report.is_pristine());
        assert_eq!(report.would_be_replaced(), 2);
        assert_eq!(report.replaced().count(), 2);
        assert_eq!(report.of_standing(Standing::Broken).count(), 1);
        // A broken entry is not something a repair "reverts": it is already not a file.
        assert!(report.replaced().all(|f| f.standing != Standing::Broken));
        assert!(report.is_exhaustive());
        assert!(ModReport::default().is_pristine());
    }

    #[test]
    fn a_report_that_could_not_judge_everything_says_so() {
        // A map covering one repository leaves the rest unknown, and a report that called itself
        // exhaustive there would let a caller read "no mods found" out of "nothing was looked at".
        let report = ModReport {
            totals: ModTotals {
                unknown: 12,
                ..ModTotals::default()
            },
            ..ModReport::default()
        };
        assert!(report.is_pristine());
        assert!(!report.is_exhaustive());
    }

    #[test]
    fn merging_counts_does_not_depend_on_the_order_containers_finished_in() {
        let a = ModTotals {
            pristine: 3,
            foreign: 1,
            ..ModTotals::default()
        };
        let b = ModTotals {
            pristine: 4,
            shared: 2,
            ..ModTotals::default()
        };
        let mut forward = a;
        forward.merge(&b);
        let mut backward = b;
        backward.merge(&a);
        assert_eq!(forward, backward);
        assert_eq!(forward.pristine, 7);
    }
}
