//! The record an archive carries about itself.
//!
//! Written as the last entry, so it can only ever describe a complete archive, and read back by name
//! out of the central directory, which costs a few kilobytes rather than inflating the payload. It is
//! also what proves an archive is ours: retention deletes on the strength of this record, never on a
//! filename.

use serde::{Deserialize, Serialize};

use super::rule::EntryKind;
use super::{RootLabel, RuleRole};

/// Format tag written into every archive. Retention treats this, not the extension, as proof of
/// origin.
pub const BACKUP_FORMAT: &str = "apogee-config-backup";

/// Bumped when the entry-name or manifest layout changes.
///
/// A reader refuses anything higher, because deleting an archive it cannot read is the one
/// unrecoverable mistake retention could make.
pub const BACKUP_FORMAT_VERSION: u32 = 1;

/// Entry name the manifest is written under, at the archive root.
pub const MANIFEST_ENTRY: &str = "apogee-backup.json";

/// Filename extension. A prefilter for retention and nothing more.
pub const BACKUP_EXTENSION: &str = "apbk";

/// A self-describing record of what an archive holds and how it was selected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BackupManifest {
    /// Always [`BACKUP_FORMAT`]; a reader that sees anything else leaves the file alone.
    pub format: String,
    /// Always [`BACKUP_FORMAT_VERSION`] at write time.
    pub format_version: u32,
    /// Crate name and version of the writer. Informational, never a gate.
    pub producer: String,
    /// Unix seconds, from the instant the caller supplied. The ordering key for retention.
    pub created_at: u64,
    /// Free-text label, such as why a scheduled backup fired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// One record per source tree.
    pub roots: Vec<RootRecord>,
    /// Every payload entry in archive order, so contents can be listed and checked without inflating
    /// anything but this.
    pub entries: Vec<EntryRecord>,
}

/// What one source tree contributed, including every rule's match count.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RootRecord {
    pub label: RootLabel,
    /// The host path the tree came from, for a human choosing between archives. Restore never reads
    /// it: the destination is always supplied by the caller.
    pub source: String,
    pub rules: Vec<RuleRecord>,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub links_skipped: u64,
    pub specials_skipped: u64,
}

/// One rule and how many entries it matched.
///
/// A zero here is the point: it is how a rule that does nothing stays visible after the fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RuleRecord {
    pub rule: String,
    pub role: RuleRole,
    pub matched: u64,
}

/// One entry as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EntryRecord {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Lowercase hex sha256 of the file bytes, computed while streaming into the archive. Empty for
    /// a directory.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
}
