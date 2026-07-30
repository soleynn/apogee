//! Structural integrity: does what a container says about itself agree with what it holds?
//!
//! The inspector reports; it never repairs, never decides, and never guesses at whether a file was
//! modded (that needs a patch-derived block index and is not attempted here). Every check exists
//! because the same rule was measured to hold over every container of a full retail install, so a
//! pristine install produces no findings at all and anything reported is a real difference.
//!
//! Two layers. The pure one takes a container's bytes and answers with a [`ContainerReport`]:
//! [`inspect_index`] for an index container, nothing to open and nothing to schedule. The whole-tree
//! sweep is assembled on top of it and returns one [`Report`].
//!
//! Accounting is not a finding. Unclaimed space, slack inside slots and the hash fields a container
//! declines to claim live in [`Totals`], because a pristine install carries plenty of all three.

mod finding;
mod index;

use sha1::{Digest, Sha1};

pub use finding::{
    ContainerId, ContainerRef, DEFECT_SLUGS, Defect, Finding, HeaderId, HeaderWord, ReadFault,
    Scope, Severity, Site,
};
pub use index::{IndexFacts, IndexInspection, Located, compare_index_forms, inspect_index};

use crate::dat::DatLimits;
use crate::index::IndexLimits;

/// Defects kept for one container before the rest are counted instead of carried. A wrecked container
/// otherwise names one defect per entry.
pub const DEFAULT_MAX_DEFECTS_PER_CONTAINER: usize = 256;

/// Where a header's SHA-1 over its own leading bytes sits, and so also how much of the header it
/// covers. The same position in the common header at `0x000` and in the second header at `0x400`.
pub(crate) const SELF_HASH_AT: usize = 0x3C0;

/// The byte length of every hash field the format carries: all four are SHA-1.
pub(crate) const SELF_HASH_LEN: usize = 20;

/// The version both of a container's headers declare, in every container of an install.
pub(crate) const FORMAT_VERSION: u32 = 1;

/// Where the common header declares its own length: the position `parse_common_header` reads it from.
pub(crate) const COMMON_HEADER_SIZE_AT: u64 = 0x0C;

/// Where the common header declares its format version.
pub(crate) const COMMON_VERSION_AT: u64 = 0x10;

/// How far unclaimed space is accounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GapPolicy {
    /// Count unclaimed bytes from the slot map and read none of them.
    Skip,
    /// Walk the empty-block chain across each run of unclaimed space and check it tiles the run
    /// exactly. Reads a region header per region, which is nothing by volume.
    #[default]
    Chain,
}

/// How a sweep runs. The two expensive passes are independent: neither implies the other, and the
/// default does neither.
#[derive(Debug, Clone)]
pub struct SweepOptions {
    /// Read every entry header the indexes name, account for the slots and classify what the slots do
    /// not cover. On by default: it is the pass that proves an index and its dat files agree.
    pub walk_entries: bool,
    /// How far unclaimed space is accounted for. Ignored when `walk_entries` is false, since a run of
    /// unclaimed space is measured between slots.
    pub gaps: GapPolicy,
    /// Hash every dat's declared data region and compare it with the header's claim. Disk-bound:
    /// roughly four minutes for a 118 GiB install on a SATA SSD.
    pub hash_data_regions: bool,
    /// Extract every entry the indexes name and throw it away. Far longer than hashing the same
    /// bytes, since every block is inflated. Implies `walk_entries`.
    pub decode_entries: bool,
    /// Cap the sweep at this many worker threads; `None` uses the default pool.
    pub parallelism: Option<usize>,
    /// Defects kept per container before the rest are counted instead of carried.
    pub max_defects_per_container: usize,
    /// Bounds on reading an index container.
    pub index_limits: IndexLimits,
    /// Bounds on reading a dat container.
    pub dat_limits: DatLimits,
}

impl Default for SweepOptions {
    fn default() -> Self {
        Self {
            walk_entries: true,
            gaps: GapPolicy::default(),
            hash_data_regions: false,
            decode_entries: false,
            parallelism: None,
            max_defects_per_container: DEFAULT_MAX_DEFECTS_PER_CONTAINER,
            index_limits: IndexLimits::default(),
            dat_limits: DatLimits::default(),
        }
    }
}

/// What inspecting one container produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerReport {
    /// Every finding, in report order.
    pub findings: Vec<Finding>,
    /// What the checks accounted for.
    pub totals: Totals,
    /// Whether the per-container budget filled, so the rest of this container was counted rather than
    /// carried.
    pub truncated: bool,
}

/// What a sweep found and what its bytes accounted for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Every finding, ascending by `(container, offset, key, defect)`. Two sweeps of one tree, at any
    /// thread count, produce identical reports.
    pub findings: Vec<Finding>,
    /// What the sweep accounted for.
    pub totals: Totals,
    /// Containers whose checks stopped at the budget, ascending and deduplicated.
    pub truncated: Vec<ContainerRef>,
}

impl Report {
    /// Whether the install is structurally sound with nothing to repair.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// The worst finding's severity, or `None` when there are none.
    #[must_use]
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(Finding::severity).max()
    }

    /// The findings of one severity, in report order.
    pub fn of_severity(&self, severity: Severity) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(move |f| f.severity() == severity)
    }

    /// The findings of one repair scope, in report order.
    pub fn of_scope(&self, scope: Scope) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.scope() == scope)
    }

    /// Containers carrying a finding above [`Severity::Altered`]: the set a targeted repair
    /// re-fetches. Deduplicated, in report order.
    #[must_use]
    pub fn damaged_containers(&self) -> Vec<ContainerRef> {
        // Report order groups a container's findings together, so comparing against the one last
        // pushed is all the deduplication a sorted report needs.
        let mut out: Vec<ContainerRef> = Vec::new();
        for finding in &self.findings {
            if finding.severity() > Severity::Altered && out.last() != Some(&finding.site.container)
            {
                out.push(finding.site.container);
            }
        }
        out
    }
}

/// What a sweep accounted for, so a report is honest about what it did not check.
///
/// Byte counters only: a report carries no clock, so two runs over one tree compare equal and the
/// caller times its own sweep. Over every dat a slot walk covered,
/// `claimed_bytes + unclaimed_bytes == data_region_bytes`, where `claimed_bytes` is the *union* of the
/// slot extents, so an archive whose slots overlap still balances.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// Archives visited.
    pub archives: u32,
    /// Index containers inspected.
    pub index_files: u32,
    /// Data containers inspected.
    pub data_files: u32,
    /// Containers that would not open or parse. A caller that sees this equal to the container count
    /// is looking at a disconnected disk, not a corrupt install.
    pub containers_unreadable: u32,
    /// Bytes of index container read.
    pub index_bytes: u64,
    /// Index entries walked.
    pub entries: u64,
    /// Collision records walked, terminators excluded.
    pub collision_records: u64,
    /// Locations the primary form named: what the entry walk was handed.
    pub locations: u64,
    /// Entry headers read out of a dat file.
    pub entry_headers_read: u64,
    /// Entries extracted and thrown away.
    pub entries_decoded: u64,
    /// Bytes fed through a hash.
    pub bytes_hashed: u64,
    /// Bytes of declared data region across the dat files walked.
    pub data_region_bytes: u64,
    /// Data-region bytes at least one slot covers.
    pub claimed_bytes: u64,
    /// Reserved but unused bytes inside slots: allocated minus occupied.
    pub slack_bytes: u64,
    /// Data-region bytes no slot covers.
    pub unclaimed_bytes: u64,
    /// Runs of unclaimed space between slots.
    pub gaps: u64,
    /// The longest such run.
    pub largest_gap: u64,
    /// Empty-block regions a [`GapPolicy::Chain`] walk stepped through.
    pub unclaimed_regions: u64,
    /// Hash fields that were all zero and so claimed nothing: skipped, not compared.
    pub unclaimed_hash_fields: u32,
    /// Defects the per-container budget dropped.
    pub defects_suppressed: u64,
}

impl Totals {
    /// Fold another container's totals in. Every field sums except `largest_gap`, which takes the
    /// larger, so the fold does not depend on the order the containers finished in.
    pub fn merge(&mut self, other: &Totals) {
        self.archives += other.archives;
        self.index_files += other.index_files;
        self.data_files += other.data_files;
        self.containers_unreadable += other.containers_unreadable;
        self.index_bytes += other.index_bytes;
        self.entries += other.entries;
        self.collision_records += other.collision_records;
        self.locations += other.locations;
        self.entry_headers_read += other.entry_headers_read;
        self.entries_decoded += other.entries_decoded;
        self.bytes_hashed += other.bytes_hashed;
        self.data_region_bytes += other.data_region_bytes;
        self.claimed_bytes += other.claimed_bytes;
        self.slack_bytes += other.slack_bytes;
        self.unclaimed_bytes += other.unclaimed_bytes;
        self.gaps += other.gaps;
        self.largest_gap = self.largest_gap.max(other.largest_gap);
        self.unclaimed_regions += other.unclaimed_regions;
        self.unclaimed_hash_fields += other.unclaimed_hash_fields;
        self.defects_suppressed += other.defects_suppressed;
    }
}

/// SHA-1 of `bytes`, the digest all four of the format's hash fields carry.
pub(crate) fn sha1(bytes: &[u8]) -> [u8; 20] {
    Sha1::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::game::Repo;
    use crate::index::IndexKind;

    fn container(file: ContainerId) -> ContainerRef {
        ContainerRef::new(Repo::Base, ArchiveId::new(0x0a, 0, 0), file)
    }

    fn finding(file: ContainerId, defect: Defect) -> Finding {
        Finding {
            site: Site {
                container: container(file),
                offset: None,
                key: None,
            },
            defect,
        }
    }

    #[test]
    fn a_report_names_its_worst_severity_and_the_containers_a_repair_would_replace() {
        // An altered container is deliberately not in the repair set: a coherently rewritten dat is
        // what a mod tool leaves behind, and re-fetching it is exactly what the user did not ask for.
        let report = Report {
            findings: vec![
                finding(
                    ContainerId::Index(IndexKind::Index1),
                    Defect::EntryPadNotZero { pad: 1 },
                ),
                finding(ContainerId::Dat(0), Defect::SlotBeforeDataRegion),
                finding(
                    ContainerId::Dat(0),
                    Defect::EntryContentTypeUnknown { declared: 9 },
                ),
                finding(ContainerId::Dat(1), Defect::DuplicateEntryKey),
            ],
            ..Report::default()
        };
        assert!(!report.is_clean());
        assert_eq!(report.worst_severity(), Some(Severity::Damaged));
        assert_eq!(report.of_severity(Severity::Altered).count(), 1);
        assert_eq!(report.of_scope(Scope::File).count(), 2);
        assert_eq!(
            report.damaged_containers(),
            [
                container(ContainerId::Dat(0)),
                container(ContainerId::Dat(1))
            ]
        );
        assert!(Report::default().is_clean());
        assert_eq!(Report::default().worst_severity(), None);
    }

    #[test]
    fn merging_totals_sums_every_counter_and_keeps_the_largest_gap() {
        // The fold has to be order-independent, or a sweep's report would depend on which worker
        // finished first.
        let a = Totals {
            gaps: 2,
            largest_gap: 900,
            entries: 3,
            ..Totals::default()
        };
        let b = Totals {
            gaps: 5,
            largest_gap: 100,
            entries: 4,
            ..Totals::default()
        };
        let mut forward = a;
        forward.merge(&b);
        let mut backward = b;
        backward.merge(&a);
        assert_eq!(forward, backward);
        assert_eq!(forward.gaps, 7);
        assert_eq!(forward.entries, 7);
        assert_eq!(forward.largest_gap, 900);
    }

    #[test]
    fn the_digest_is_sha1() {
        // Pins which digest the four hash fields carry: an empty segment's descriptor declares this
        // value in a real container.
        assert_eq!(
            sha1(b""),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }
}
