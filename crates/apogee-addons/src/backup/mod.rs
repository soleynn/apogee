//! Choosing what a config backup covers.
//!
//! Selection is one filesystem walk plus rules that are predicates over what it found. The shape is
//! a response to how this goes wrong in practice: a backup that quietly covers less than it claims
//! reports success, and the loss is only discovered when someone tries to restore it. So a rule
//! states the kind of entry it matches and is checked against the kind actually on disk, name tests
//! fold case rather than inheriting the filesystem's answer, and every rule reports how many entries
//! it matched, which makes a rule that matched nothing a zero on a report instead of silence.
//!
//! The tree the game writes is taken whole and thinned by naming what to drop, rather than being
//! assembled by naming what to keep. A name that is never spelled cannot be misspelled, and a
//! mistake in a rule that drops things costs archive size, while a mistake in a rule that keeps
//! things costs the user their settings.

mod archive;
mod error;
mod manifest;
mod root;
mod rule;
mod walk;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use archive::{BackupReport, BackupSpec, create, inspect};
pub use error::BackupError;
pub use manifest::{
    BACKUP_EXTENSION, BACKUP_FORMAT, BACKUP_FORMAT_VERSION, BackupManifest, EntryRecord,
    MANIFEST_ENTRY, RootRecord, RuleRecord,
};
pub use root::{CompanionConfigOpts, GameConfigOpts, Presence, RootLabel, SelectionRoot};
pub use rule::{EntryKind, Expect, NameMatch, Rule};

/// Where a rule sits in the order each entry is tested in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleRole {
    /// Drops an entry at any depth, and cannot be switched off by a caller.
    Deny,
    /// Drops an entry at any depth.
    Prune,
    /// Admits one of a root's immediate children.
    Include,
}

/// What one rule did during a walk.
#[derive(Debug, Clone)]
pub struct RuleReport {
    role: RuleRole,
    rule: String,
    matched: usize,
}

impl RuleReport {
    /// Which list this rule came from.
    #[must_use]
    pub fn role(&self) -> RuleRole {
        self.role
    }

    /// The rule as rendered, which is its key on the report.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// How many entries it matched. Zero is the value that makes a rule that does nothing visible.
    #[must_use]
    pub fn matched(&self) -> usize {
        self.matched
    }
}

/// One file or directory chosen for the archive.
#[derive(Debug, Clone)]
pub struct SelectedEntry {
    name: String,
    source: PathBuf,
    kind: EntryKind,
    size: u64,
}

impl SelectedEntry {
    /// The archive name: the root's label, then the path below the root, `/`-separated.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where it is read from.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Whether it is a file or a directory.
    #[must_use]
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// The file's size in bytes, or zero for a directory.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// What one root contributed, including what was skipped and what every rule matched.
#[derive(Debug, Clone)]
pub struct RootReport {
    label: RootLabel,
    path: PathBuf,
    present: bool,
    files: usize,
    dirs: usize,
    bytes: u64,
    links_skipped: usize,
    specials_skipped: usize,
    rules: Vec<RuleReport>,
}

impl RootReport {
    /// The namespace this root's entries sit under.
    #[must_use]
    pub fn label(&self) -> RootLabel {
        self.label
    }

    /// The directory that was read.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the directory existed. An absent optional root reports false with every count zero.
    #[must_use]
    pub fn present(&self) -> bool {
        self.present
    }

    /// How many files were selected.
    #[must_use]
    pub fn files(&self) -> usize {
        self.files
    }

    /// How many directories were selected.
    #[must_use]
    pub fn dirs(&self) -> usize {
        self.dirs
    }

    /// The total length of the selected files.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// How many symlinks were passed over.
    #[must_use]
    pub fn links_skipped(&self) -> usize {
        self.links_skipped
    }

    /// How many sockets, fifos, and device nodes were passed over.
    #[must_use]
    pub fn specials_skipped(&self) -> usize {
        self.specials_skipped
    }

    /// Every rule of every role with its match count.
    #[must_use]
    pub fn rules(&self) -> &[RuleReport] {
        &self.rules
    }
}

/// What a selection resolved to: the entries to archive, and what each root's rules did.
#[derive(Debug, Clone)]
pub struct Selected {
    entries: Vec<SelectedEntry>,
    roots: Vec<RootReport>,
}

impl Selected {
    /// The entries, ordered by archive name so an archive built from them is too.
    #[must_use]
    pub fn entries(&self) -> &[SelectedEntry] {
        &self.entries
    }

    /// One report per root, in the order the roots were added.
    #[must_use]
    pub fn roots(&self) -> &[RootReport] {
        &self.roots
    }

    /// The total length of every selected file.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.roots.iter().map(RootReport::bytes).sum()
    }
}

/// The set of source trees one backup covers.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    roots: Vec<SelectionRoot>,
    resolved: Vec<PathBuf>,
}

impl Selection {
    /// An empty selection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source tree, resolving its path first so two roots that reach the same directory
    /// through different links cannot both be walked. A prefix reaches its config tree by several
    /// names, so this is the difference between one copy of the settings and four.
    ///
    /// # Errors
    /// [`BackupError::DuplicateRoot`] if it resolves to a directory already added.
    pub fn with_root(mut self, root: SelectionRoot) -> Result<Self, BackupError> {
        // An absent optional root cannot be resolved, so it stands in for itself; two absent roots
        // at the same literal path are still caught.
        let resolved = std::fs::canonicalize(root.path()).unwrap_or_else(|_| root.path().into());
        if let Some(at) = self.resolved.iter().position(|seen| *seen == resolved) {
            return Err(BackupError::DuplicateRoot {
                path: root.path().to_path_buf(),
                first: self.roots[at].path().to_path_buf(),
            });
        }
        self.resolved.push(resolved);
        self.roots.push(root);
        Ok(self)
    }

    /// The roots, in the order they were added.
    #[must_use]
    pub fn roots(&self) -> &[SelectionRoot] {
        &self.roots
    }

    /// The rules applied to every root at every depth, which no caller can switch off.
    ///
    /// These are the launcher identity files: an account name, a last-used one-time password, host
    /// absolute paths, and an account id. No default rule set reaches them, so this list is what
    /// keeps a caller who points a root at a launcher home from sweeping them into an archive that
    /// gets shared.
    #[must_use]
    pub fn deny_rules() -> Vec<Rule> {
        [
            "accounts.json",
            "accountsList.json",
            "launcher.ini",
            "launcherConfigV3.json",
        ]
        .into_iter()
        .map(|name| Rule::file(NameMatch::Exact(name.into()), Expect::Optional))
        .collect()
    }

    /// Walk every root and decide what the archive holds.
    ///
    /// # Errors
    /// [`BackupError::MissingRoot`] if a required root is absent, [`BackupError::RuleMatchedNothing`]
    /// if a required rule matched no entry, [`BackupError::NothingSelected`] if no root held a file,
    /// and [`BackupError::Io`], [`BackupError::NonUtf8Name`], or [`BackupError::TooDeep`] from the
    /// walk.
    pub fn resolve(&self) -> Result<Selected, BackupError> {
        let deny = Self::deny_rules();
        let mut entries = Vec::new();
        let mut roots = Vec::with_capacity(self.roots.len());
        for root in &self.roots {
            let (found, report) = walk::walk(root, &deny)?;
            entries.extend(found);
            roots.push(report);
        }
        if roots.iter().all(|r| r.files == 0) {
            // An archive holding nothing would restore as a success that returns no settings.
            return Err(BackupError::NothingSelected);
        }
        // Sorted on the archive name itself, as raw bytes, so the order does not depend on the
        // filesystem's directory order or on a locale. A parent sorts before its children because
        // its name is their prefix.
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        Ok(Selected { entries, roots })
    }
}
