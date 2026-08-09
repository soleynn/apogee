//! Keeping the newest N archives and removing the rest.
//!
//! This is the only code here that deletes, and what it deletes is the user's only copy of settings
//! they cannot otherwise recover. The cost of the two mistakes is nothing alike: leaving one stale
//! archive behind costs disk, while removing one file that was not ours is unrecoverable. So an
//! archive has to prove it is ours before it is a candidate, and everything that fails to prove it is
//! reported with the check that rejected it rather than passed over.
//!
//! A filename is not proof. Anyone can rename a file to the extension, nothing reserves it, a
//! truncated file keeps its name, and a name cannot carry the format version that says whether this
//! build understands what it would be deleting. The extension is a prefilter so a directory of large
//! unrelated files is not opened one by one; the record inside decides.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use super::archive::inspect;
use super::error::BackupError;
use super::manifest::BACKUP_EXTENSION;

/// How many of our archives survive a prune.
#[derive(Debug, Clone, Copy)]
pub struct Retain(NonZeroUsize);

impl Retain {
    /// Keep the newest `n`. Takes a [`NonZeroUsize`] because keeping zero is a request to delete
    /// every backup there is, which no retention policy should be able to express.
    #[must_use]
    pub fn keep(n: NonZeroUsize) -> Self {
        Self(n)
    }

    /// How many are kept.
    #[must_use]
    pub fn count(self) -> usize {
        self.0.get()
    }
}

/// One of our archives, as identified by reading it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ArchiveRecord {
    pub path: PathBuf,
    /// From the record, never from the filename: an instant rendered into a name is a fragile
    /// ordering key, and two backups in one second share a stamp.
    pub created_at: u64,
    pub format_version: u32,
    pub bytes: u64,
}

/// Why a file in the backup directory was not treated as ours. Every variant means it was left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForeignReason {
    /// A directory, a symlink, or something else that is not a plain file.
    NotARegularFile,
    /// Does not carry our extension.
    WrongExtension,
    /// Does not open as an archive, which also covers a truncated or empty file.
    NotAnArchive,
    /// Opens, but carries no record of ours.
    NoRecord,
    /// Carries a record that does not parse, or whose format tag is not ours.
    UnreadableRecord,
    /// Written by a newer build than this one. Deleting an archive we cannot read is the one
    /// unrecoverable mistake available here, so a version we do not understand is left alone.
    UnsupportedFormatVersion(u32),
    /// Could not be examined at all: an open or a read that failed. Its own reason rather than "not an
    /// archive", which would send whoever reads the plan to look at the file when the answer is its
    /// permissions or the disk under it.
    CouldNotRead,
}

impl std::fmt::Display for ForeignReason {
    /// Each reason as what the file turned out to be, so a line naming it reads as a sentence. This is
    /// the answer to "why is that one still there", asked about a file the user can see, so the reason
    /// is the whole of what is worth reading.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotARegularFile => f.write_str("it is not a plain file"),
            Self::WrongExtension => f.write_str("it does not carry this launcher's extension"),
            Self::NotAnArchive => f.write_str("it does not open as an archive"),
            Self::NoRecord => f.write_str("it is an archive, but nothing in it is ours"),
            Self::UnreadableRecord => f.write_str("its record is not one this build can read"),
            Self::UnsupportedFormatVersion(found) => {
                write!(
                    f,
                    "it was written in format version {found}, which is newer than this build"
                )
            }
            Self::CouldNotRead => f.write_str("it could not be read at all"),
        }
    }
}

/// What a prune would do, worked out without deleting anything.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PrunePlan {
    /// Ours, newest first by recorded instant, ties broken by filename bytes.
    pub ours: Vec<ArchiveRecord>,
    /// The ones that survive.
    pub keep: Vec<PathBuf>,
    /// The ones a prune would remove.
    pub delete: Vec<PathBuf>,
    /// Everything else in the directory, with the check that rejected it, so "nothing was pruned"
    /// can be explained rather than guessed at.
    pub foreign: Vec<(PathBuf, ForeignReason)>,
}

/// What a prune did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PruneReport {
    pub deleted: Vec<PathBuf>,
    pub kept: usize,
    /// What was left alone and the check that rejected each one, carried through from the plan the
    /// prune ran.
    ///
    /// Named rather than counted, because this is the answer to the question a prune provokes: the
    /// directory still has files in it and the user wants to know which, and why this build would not
    /// touch them. A count says "seven" to somebody who can already see seven.
    pub foreign: Vec<(PathBuf, ForeignReason)>,
}

/// Work out what a prune of `dir` under `policy` would do. Reads, never writes.
///
/// # Errors
/// [`BackupError::Io`] if the directory cannot be listed.
pub fn plan_prune(dir: &Path, policy: Retain) -> Result<PrunePlan, BackupError> {
    let listing = std::fs::read_dir(dir).map_err(|source| BackupError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    let mut ours = Vec::new();
    let mut foreign = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|source| BackupError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        match identify(&entry, &path) {
            Ok(record) => ours.push(record),
            Err(reason) => foreign.push((path, reason)),
        }
    }

    // Newest first. The tie-break on the name keeps the order total, so a plan is the same on every
    // run over an unchanged directory.
    ours.sort_by(|a, b| {
        b.created_at.cmp(&a.created_at).then_with(|| {
            a.path
                .as_os_str()
                .as_encoded_bytes()
                .cmp(b.path.as_os_str().as_encoded_bytes())
        })
    });
    let keep: Vec<PathBuf> = ours
        .iter()
        .take(policy.count())
        .map(|r| r.path.clone())
        .collect();
    let delete: Vec<PathBuf> = ours
        .iter()
        .skip(policy.count())
        .map(|r| r.path.clone())
        .collect();

    Ok(PrunePlan {
        ours,
        keep,
        delete,
        foreign,
    })
}

/// Prune `dir` under `policy`.
///
/// This is [`plan_prune`] followed by removing exactly what the plan named, so the destructive step
/// has a dry run and a test can compare the two rather than restating the policy.
///
/// # Errors
/// [`BackupError::Io`] if the directory cannot be listed or a file cannot be removed.
pub fn prune(dir: &Path, policy: Retain) -> Result<PruneReport, BackupError> {
    let plan = plan_prune(dir, policy)?;
    for path in &plan.delete {
        std::fs::remove_file(path).map_err(|source| BackupError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(PruneReport {
        deleted: plan.delete,
        kept: plan.keep.len(),
        foreign: plan.foreign,
    })
}

/// Decide whether one directory entry is one of ours, cheapest check first.
fn identify(entry: &std::fs::DirEntry, path: &Path) -> Result<ArchiveRecord, ForeignReason> {
    let meta = entry
        .metadata()
        .map_err(|_| ForeignReason::NotARegularFile)?;
    if !meta.is_file() {
        // `metadata` on a DirEntry does not traverse a link, so a symlink named like an archive
        // lands here rather than being followed to whatever it points at.
        return Err(ForeignReason::NotARegularFile);
    }
    if path.extension().and_then(|e| e.to_str()) != Some(BACKUP_EXTENSION) {
        return Err(ForeignReason::WrongExtension);
    }
    match inspect(path) {
        Ok(manifest) => Ok(ArchiveRecord {
            path: path.to_path_buf(),
            created_at: manifest.created_at,
            format_version: manifest.format_version,
            bytes: meta.len(),
        }),
        Err(BackupError::UnsupportedFormat { found, .. }) => {
            Err(ForeignReason::UnsupportedFormatVersion(found))
        }
        Err(BackupError::Manifest { .. }) => Err(ForeignReason::UnreadableRecord),
        Err(BackupError::NotAnArchive { .. }) => Err(classify_unreadable(path)),
        Err(BackupError::Io { .. }) => Err(ForeignReason::CouldNotRead),
        // `inspect` raises nothing else. Kept as the safe direction if it ever does: every reason here
        // means the file was left alone, so an imprecise one costs a line in the plan, never a file.
        Err(_) => Err(ForeignReason::NotAnArchive),
    }
}

/// Separate "not an archive at all" from "an archive with nothing of ours in it", which are different
/// facts for someone looking at why their directory was left alone.
fn classify_unreadable(path: &Path) -> ForeignReason {
    let Ok(file) = std::fs::File::open(path) else {
        return ForeignReason::NotAnArchive;
    };
    match zip::ZipArchive::new(file) {
        Ok(mut zip) => {
            if zip.by_name(super::manifest::MANIFEST_ENTRY).is_ok() {
                ForeignReason::UnreadableRecord
            } else {
                ForeignReason::NoRecord
            }
        }
        Err(_) => ForeignReason::NotAnArchive,
    }
}
