//! Structural integrity: does what a container says about itself agree with what it holds?
//!
//! The inspector reports; it never repairs, never decides, and never guesses at whether a file was
//! modded (that needs a patch-derived block index and is not attempted here). Every check exists
//! because the same rule was measured to hold over every container of a full retail install, so a
//! pristine install produces no findings at all and anything reported is a real difference.
//!
//! Two layers. The pure one answers with a [`ContainerReport`] over one container and schedules
//! nothing: [`inspect_index`] takes an index container's bytes, and [`inspect_dat_headers`],
//! [`inspect_data_region`] and [`inspect_dat_entries`] take a dat container's random-access bytes,
//! which are far too many to hold. The whole-tree sweep is assembled on top of them and returns one
//! [`Report`].
//!
//! Accounting is not a finding. Unclaimed space, slack inside slots and the hash fields a container
//! declines to claim live in [`Totals`], because a pristine install carries plenty of all three.

mod dat;
mod finding;
mod index;
mod sweep;

#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) mod fixture;

use sha1::{Digest, Sha1};

pub use dat::{DatInspection, inspect_dat_entries, inspect_dat_headers, inspect_data_region};
use finding::Sink;
pub use finding::{
    ContainerId, ContainerRef, DEFECT_SLUGS, Defect, Finding, HeaderId, HeaderWord, ReadFault,
    Scope, Severity, Site,
};
pub use index::{IndexFacts, IndexInspection, Located, compare_index_forms, inspect_index};
pub(crate) use sweep::in_pool;

use crate::bytes;
use crate::container::COMMON_HEADER_LEN;
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

/// A digest field of all zeros claims nothing, so it is skipped and counted rather than compared. Two
/// dat files of a full install declare this over their data region, where a third declares the digest
/// of nothing.
pub(crate) const UNCLAIMED_DIGEST: [u8; SELF_HASH_LEN] = [0; SELF_HASH_LEN];

/// The window a data-region hash reads through: 118 GiB in 1 MiB reads is 120k calls.
const HASH_CHUNK_BYTES: usize = 1 << 20;

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
    ///
    /// A sweep that could not see everything can still be clean about what it saw, so this is not on
    /// its own the answer to "is the install fine": pair it with [`Report::is_complete`].
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Whether every container was actually looked at.
    ///
    /// False when a container was in use by another process, which a caller sweeping a tree while
    /// the game runs should expect. Those containers are counted, not reported, because "in use" is
    /// not a fault of the install and nothing was learned about them either way.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.totals.containers_busy == 0
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
    /// Containers another process holds and would not share, so this sweep did not look at them.
    /// Counted rather than reported: there is no [`Severity`] that fits "not examined", and grading
    /// a healthy container [`Severity::Unusable`] would tell a caller to replace it.
    pub containers_busy: u32,
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
        self.containers_busy += other.containers_busy;
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

/// Record a container that would not open or read: one finding, or nothing at all when it was only
/// in use.
///
/// A busy container is not a fault of the install. Another process holds it and this sweep did not
/// look, so reporting it would grade a healthy container [`Severity::Unusable`] at
/// [`Scope::Container`] and tell the caller to replace it, which is the worst mistake this module
/// can make. There is no severity that fits "not examined", and the axis is closed on purpose, so it
/// is counted into [`Totals::containers_busy`] and [`Report::is_complete`] is what says so.
pub(crate) fn note_unreadable(sink: &mut Sink, totals: &mut Totals, error: &crate::Error) {
    let (fault, detail, offset) = finding::read_fault(error);
    if fault == ReadFault::Busy {
        totals.containers_busy += 1;
        return;
    }
    totals.containers_unreadable += 1;
    sink.push_on(offset, Defect::ContainerUnreadable { fault, detail });
}

/// The digest each of a container's two headers declares over its own leading bytes.
///
/// The same field in the same place in an index and in a dat, including one of the dat files that
/// carries no `SqPack` magic: its digest covers the blob written over the magic rather than the magic.
/// A field of all zeros claims nothing, so it is counted instead of compared.
pub(crate) fn check_self_hashes(bytes: &[u8], sink: &mut Sink, totals: &mut Totals) {
    for header in [HeaderId::Common, HeaderId::Second] {
        let at = header.starts_at();
        let field = at + SELF_HASH_AT;
        let Some(covered) = bytes.get(at..field) else {
            continue;
        };
        let Some(declared) = digest_at(bytes, field) else {
            continue;
        };
        if declared == UNCLAIMED_DIGEST {
            totals.unclaimed_hash_fields += 1;
            continue;
        }
        let computed = sha1(covered);
        totals.bytes_hashed += covered.len() as u64;
        if computed != declared {
            sink.push_at(
                field as u64,
                Defect::HeaderHashMismatch {
                    header,
                    declared,
                    computed,
                },
            );
        }
    }
}

/// The two 44-byte runs that follow each header's own digest field are the only bytes in a container
/// that no hash covers, which is why they are checked directly and narrowly. Everything before them
/// sits under a self hash, so a second rule over those bytes would buy nothing but a second way to be
/// wrong.
pub(crate) fn check_uncovered_runs(bytes: &[u8], sink: &mut Sink) {
    for header in [HeaderId::Common, HeaderId::Second] {
        let start = header.starts_at() + SELF_HASH_AT + SELF_HASH_LEN;
        let end = header.starts_at() + COMMON_HEADER_LEN;
        let Some(run) = bytes.get(start..end) else {
            continue;
        };
        if let Some(i) = run.iter().position(|&b| b != 0) {
            sink.push_at(
                start as u64,
                Defect::ZeroRegionDirty {
                    len: (end - start) as u32,
                    first_nonzero: (start + i) as u64,
                },
            );
        }
    }
}

/// The 20-byte digest at `at`, or `None` if the container is shorter than that.
pub(crate) fn digest_at(bytes: &[u8], at: usize) -> Option<[u8; SELF_HASH_LEN]> {
    bytes
        .get(at..at.checked_add(SELF_HASH_LEN)?)
        .and_then(|raw| <[u8; SELF_HASH_LEN]>::try_from(raw).ok())
}

/// A little-endian `u32` at `at`, or `None` if the bytes do not reach.
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at.checked_add(4)?)
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(bytes::u32_le)
}

/// SHA-1 of `bytes`, the digest all four of the format's hash fields carry.
pub(crate) fn sha1(bytes: &[u8]) -> [u8; 20] {
    Sha1::digest(bytes).into()
}

/// Which slot of a two-digest override array a header owns, for the container builders the tests
/// drive: both of them can be told to declare something other than what their bytes hash to.
#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) fn self_hash_slot(header: HeaderId) -> usize {
    match header {
        HeaderId::Common => 0,
        HeaderId::Second => 1,
    }
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
