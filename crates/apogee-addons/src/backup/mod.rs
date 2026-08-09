//! Reproducible archives of the settings the game writes for itself.
//!
//! A [`Selection`] names the source trees and the rules that carve them up, [`create`] writes one
//! into a deterministic zip carrying its own [`BackupManifest`], [`inspect`] reads that record back,
//! `restore` (unix only) puts a root back, and [`prune`] removes all but the newest few.
//!
//! Selection is one filesystem walk plus rules that are predicates over what it found. The shape is a
//! response to how this goes wrong in practice: a backup that quietly covers less than it claims
//! reports success, and the loss is only discovered when someone tries to restore it. So a rule
//! states the kind of entry it matches and is checked against the kind actually on disk, name tests
//! fold case rather than inheriting the filesystem's answer, and every rule reports how many entries
//! it matched, which makes a rule that matched nothing a zero on a report instead of silence.
//!
//! The tree the game writes is taken whole and thinned by naming what to drop, rather than being
//! assembled by naming what to keep. A name that is never spelled cannot be misspelled, and a mistake
//! in a rule that drops things costs archive size, while a mistake in a rule that keeps things costs
//! the user their settings.
//!
//! # Examples
//!
//! Capture the config tree inside a prefix, then prune the directory it landed in:
//!
//! ```
//! # use std::path::Path;
//! # use std::time::SystemTime;
//! # use tokio_util::sync::CancellationToken;
//! # use apogee_addons::backup::{
//! #     BackupError, BackupSpec, GameConfigOpts, Retain, Selection, SelectionRoot, create,
//! #     game_config_dirs, prune,
//! # };
//! # fn demo(
//! #     prefix: &Path,
//! #     dest: &Path,
//! #     policy: Retain,
//! #     cancel: &CancellationToken,
//! # ) -> Result<(), BackupError> {
//! // A prefix run under more than one runner holds a tree per runner; the newest is the live one.
//! let mut selection = Selection::new();
//! if let Some(tree) = game_config_dirs(prefix).into_iter().next() {
//!     let root = SelectionRoot::game_config(tree, GameConfigOpts::default());
//!     selection = selection.with_root(root)?;
//! }
//!
//! let spec = BackupSpec::new(selection, dest, SystemTime::now()).note("before a patch");
//! let report = create(&spec, cancel)?;
//! let pruned = prune(dest, policy)?;
//! # let _ = (report.archive, pruned.deleted);
//! # Ok(())
//! # }
//! ```

mod archive;
mod confine;
mod error;
mod manifest;
// Opens every target against a directory descriptor, so it is unix-only by construction.
#[cfg(unix)]
mod restore;
mod retain;
mod root;
mod rule;
mod walk;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use archive::{BackupReport, BackupSpec, create, inspect};
pub use confine::RejectReason;
pub use error::BackupError;
pub use manifest::{
    BACKUP_EXTENSION, BACKUP_FORMAT, BACKUP_FORMAT_VERSION, BackupManifest, EntryRecord,
    MANIFEST_ENTRY, RootRecord, RuleRecord,
};
#[cfg(unix)]
pub use restore::{RestorePlan, RestoreReport, RestoredRoot, restore};
pub use retain::{ArchiveRecord, ForeignReason, PrunePlan, PruneReport, Retain, plan_prune, prune};
pub use root::{GameConfigOpts, Presence, RootLabel, SelectionRoot};
pub use rule::EntryKind;

// The vocabulary a rule is written in. Crate-private, because nothing outside authors rules: the
// selection this layer captures is the launcher's decision about what a config backup covers, not a
// list a caller composes, and publishing the words for it would make that an extension point every
// later release has to keep working.
pub(crate) use rule::{Expect, NameMatch, Rule};

/// Where a rule sits in the order each entry is tested in.
// Exhaustive for the same reason as `RootLabel`: it is part of the archive record.
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

/// The directory name the game writes its settings into, under the user's documents.
const GAME_CONFIG_DIR: &str = "FINAL FANTASY XIV - A Realm Reborn";

/// Users that never own a config tree.
const NOT_A_USER: &[&str] = &["Public"];

/// Every game config tree inside `prefix`, most recently written first.
///
/// A search rather than a path join, and a list rather than one answer. The user directory inside a
/// prefix is named after whoever the runner claims to be, which differs between a plain wine prefix
/// and a Proton one, and a prefix that has been run under both holds a tree for each. Proton also
/// relocates the whole prefix a level down, so the drive is either directly inside or one `pfx`
/// deeper.
///
/// On such a prefix both trees hold a full set of settings, so the caller chooses; the order here
/// gives it something better than alphabetical to choose with, since the tree the game wrote to last
/// is the one it is using.
///
/// Empty when the game has never written a config, which is the state of a prefix that has only been
/// prepared.
///
/// # Examples
///
/// ```
/// # fn main() -> std::io::Result<()> {
/// use apogee_addons::backup::game_config_dirs;
///
/// let prepared_but_never_played = tempfile::tempdir()?;
/// assert!(game_config_dirs(prepared_but_never_played.path()).is_empty());
/// # Ok(())
/// # }
/// ```
#[must_use]
pub fn game_config_dirs(prefix: &Path) -> Vec<PathBuf> {
    let mut found: Vec<(std::time::SystemTime, PathBuf, PathBuf)> = Vec::new();
    // The relocation Proton applies is checked as well as the direct path, so a plain prefix whose
    // own directory is named `pfx` still resolves.
    for root in [prefix.to_path_buf(), prefix.join("pfx")] {
        let Ok(listing) = std::fs::read_dir(root.join("drive_c").join("users")) else {
            continue;
        };
        for entry in listing.flatten() {
            let Some(user) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if NOT_A_USER
                .iter()
                .any(|skip| user.eq_ignore_ascii_case(skip))
            {
                continue;
            }
            let candidate = entry
                .path()
                .join("Documents")
                .join("My Games")
                .join(GAME_CONFIG_DIR);
            if !candidate.is_dir() {
                continue;
            }
            // The root config file is what the game rewrites on exit, so it dates the tree far better
            // than the directory's own timestamp.
            let written = std::fs::metadata(candidate.join("FFXIV.cfg"))
                .or_else(|_| std::fs::metadata(&candidate))
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            // Resolved before comparing: a Proton prefix links `pfx` back at itself, so the same
            // tree is reachable under two names and would otherwise be reported twice.
            let key = candidate
                .canonicalize()
                .unwrap_or_else(|_| candidate.clone());
            if !found.iter().any(|(_, seen, _)| *seen == key) {
                found.push((written, key, candidate));
            }
        }
    }
    // Newest first, then by path, so the order is total and does not shift between runs.
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    found.into_iter().map(|(_, _, path)| path).collect()
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
    /// through different links cannot both be walked.
    ///
    /// A prefix reaches its config tree under several names, so this is the difference between one
    /// copy of the settings and four.
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

    /// The rules applied to every root at every depth, which no caller can switch off.
    ///
    /// These are the launcher identity files: an account name, a last-used one-time password, host
    /// absolute paths, and an account id. No default rule set reaches them, so this list is what
    /// keeps a caller who points a root at a launcher home from sweeping them into an archive that
    /// gets shared.
    #[must_use]
    pub(crate) fn deny_rules() -> Vec<Rule> {
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

#[cfg(test)]
mod tests {
    //! What the rule vocabulary does, which is in here because the vocabulary is crate-private. The
    //! tests that drive the presets from outside are still in `tests/`.

    use super::*;

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, body).expect("write");
    }

    fn allowlist(root: &Path, include: Vec<Rule>) -> Result<Selection, BackupError> {
        Selection::new().with_root(SelectionRoot::new(
            RootLabel::User,
            root,
            include,
            vec![],
            Presence::Required,
        )?)
    }

    /// A rule that matches nothing is the failure this selection exists to make impossible to miss.
    /// On an allowlist root, where a misspelling would silently shrink the archive, it stops the
    /// backup.
    #[test]
    fn a_required_rule_that_matches_nothing_fails_the_backup() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("tree");
        write(&root.join("present.cfg"), "here");

        let err = allowlist(
            &root,
            vec![
                Rule::file(NameMatch::Exact("present.cfg".into()), Expect::Required),
                Rule::file(NameMatch::Exact("absent.cfg".into()), Expect::Required),
            ],
        )
        .and_then(|selection| selection.resolve());

        match err {
            Err(BackupError::RuleMatchedNothing { rule, .. }) => {
                assert_eq!(rule, "file absent.cfg");
            }
            other => panic!("expected the missing rule to be named, got {other:?}"),
        }
    }

    /// A root the game has been pointed at and has never written into is the ordinary state before a
    /// first launch, so it is recorded rather than treated as a fault, and the populated root beside
    /// it is still captured.
    #[test]
    fn an_absent_optional_root_is_recorded_beside_a_populated_one() -> Result<(), BackupError> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let populated = tmp.path().join("written");
        write(&populated.join("FFXIV.cfg"), "cfg");

        let selected = allowlist(
            &populated,
            vec![Rule::file(NameMatch::Any, Expect::Optional)],
        )?
        .with_root(SelectionRoot::new(
            RootLabel::User,
            tmp.path().join("never-written"),
            vec![Rule::file(NameMatch::Any, Expect::Optional)],
            vec![],
            Presence::Optional,
        )?)?
        .resolve()?;

        assert_eq!(selected.roots().len(), 2);
        assert!(selected.roots()[0].present());
        assert!(!selected.roots()[1].present());
        assert_eq!(selected.roots()[1].files(), 0);
        Ok(())
    }

    /// The deny list is crate policy rather than a caller's choice, so it is worth pinning that it
    /// names what it is meant to name.
    #[test]
    fn the_deny_list_covers_the_launcher_identity_files() {
        let rendered: Vec<String> = Selection::deny_rules()
            .iter()
            .map(Rule::to_string)
            .collect();
        for want in [
            "file accounts.json",
            "file accountsList.json",
            "file launcher.ini",
            "file launcherConfigV3.json",
        ] {
            assert!(rendered.iter().any(|r| r == want), "{want} not denied");
        }
    }
}
