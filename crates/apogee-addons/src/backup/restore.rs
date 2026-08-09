//! Putting an archive's contents back, one root at a time.
//!
//! Restore is the only operation here that writes into a live tree, so it is arranged so that a
//! failure at any point leaves that tree exactly as it was. Each root is extracted and verified into
//! a staging directory beside its destination; only once a root is complete does anything move, and
//! the tree that was there is renamed aside rather than deleted, so a restore is undone with one
//! rename.
//!
//! A root is replaced whole rather than merged into. Merging leaves files from an older configuration
//! in a tree the game will read, which is a quieter and longer-lived corruption than replacing; the
//! displaced tree is what keeps replacing lossless.
//!
//! Every target is opened one component at a time, relative to a directory this module opened itself,
//! with symlinks refused. No path is ever re-resolved from a string, so neither a planted link nor a
//! change between checking and opening can redirect a write.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};

use super::archive::inspect;
use super::confine::{ConfinedName, RejectReason, entry_name};
use super::error::BackupError;
use super::manifest::{EntryRecord, MANIFEST_ENTRY};
use super::root::RootLabel;

/// Bytes an archive file may be before it is refused unopened.
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
/// Bytes one restore may write in total, counted as they leave the decompressor.
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Bytes one entry may write.
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
/// Entries one archive may hold.
const MAX_ENTRIES: usize = 4096;
/// Copy buffer, shared by the hash and the write.
const COPY_BUF: usize = 256 * 1024;

/// Which roots of an archive to restore and where each lands.
#[derive(Debug, Clone)]
pub struct RestorePlan {
    /// The archive to read.
    pub archive: PathBuf,
    /// A root absent from this map is left alone and its live tree is untouched.
    pub targets: BTreeMap<RootLabel, PathBuf>,
}

impl RestorePlan {
    /// Restore what `archive` records, into `dir`.
    ///
    /// Reads the archive's own list of roots rather than making the caller state one. A caller that
    /// writes the map itself is guessing which labels the archive holds, and a guess that is missing
    /// one is not an error: the entries under it match no target and are passed over, so a restore
    /// that put back less than the archive holds returns exactly like one that put back everything.
    ///
    /// Every recorded root lands in `dir`, which is the shape of every archive this launcher writes.
    /// A label whose tree belongs somewhere else needs a constructor that says where, rather than this
    /// one quietly overlaying two trees in one directory.
    ///
    /// # Errors
    /// Whatever [`inspect`] raises about the archive: it is opened and its record read here, so a
    /// plan cannot name roots an unreadable archive was never asked about.
    pub fn into_dir(
        archive: impl Into<PathBuf>,
        dir: impl Into<PathBuf>,
    ) -> Result<Self, BackupError> {
        let archive = archive.into();
        let dir = dir.into();
        let manifest = inspect(&archive)?;
        Ok(Self {
            targets: manifest
                .roots
                .iter()
                .map(|root| (root.label, dir.clone()))
                .collect(),
            archive,
        })
    }
}

/// What a restore did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RestoreReport {
    /// One per root that was restored.
    pub restored: Vec<RestoredRoot>,
    /// Roots the archive holds that the plan did not name.
    pub skipped: Vec<RootLabel>,
    /// Roots the plan named that the archive does not hold.
    ///
    /// The other side of [`Self::skipped`], and the one that costs something: a caller asking for a
    /// root an archive never had gets a restore that writes nothing, and without this it reads exactly
    /// like one that wrote everything. The person on the end of it is recovering settings they cannot
    /// otherwise get back, so "nothing happened" has to be sayable.
    pub absent: Vec<RootLabel>,
}

/// One root put back.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RestoredRoot {
    pub label: RootLabel,
    pub target: PathBuf,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Where the tree that previously occupied the target was moved. Never deleted, so the restore
    /// is reversible with one rename. `None` when there was nothing there.
    pub displaced_to: Option<PathBuf>,
}

/// Restore the roots `plan` names.
///
/// Blocking, and unbounded in the size of the archive, so `cancel` is checked between entries. A
/// stopped restore leaves the live tree exactly as it was: everything is assembled in a staging tree
/// and only moved into place once the whole archive has been read, and cancelling takes the same path
/// out as a refused entry.
///
/// # Errors
/// [`BackupError::NotAnArchive`] or [`BackupError::UnsupportedFormat`] if the archive is not one this
/// build can read, [`BackupError::RejectedEntry`] if any entry name or content fails its checks,
/// [`BackupError::TooLarge`] or [`BackupError::TooManyEntries`] if it exceeds what a restore may
/// write, [`BackupError::Cancelled`] if the token fired, and [`BackupError::Io`] from the filesystem.
/// The live tree is untouched in every case.
pub fn restore(
    plan: &RestorePlan,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<RestoreReport, BackupError> {
    let size = std::fs::metadata(&plan.archive)
        .map_err(|source| BackupError::Io {
            path: plan.archive.clone(),
            source,
        })?
        .len();
    if size > MAX_ARCHIVE_BYTES {
        return Err(BackupError::TooLarge {
            found: size,
            limit: MAX_ARCHIVE_BYTES,
        });
    }
    // Also gates the format version, so an archive from a newer build is refused before it is read.
    let manifest = inspect(&plan.archive)?;
    let expected: HashMap<&str, &EntryRecord> = manifest
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e))
        .collect();

    let file = std::fs::File::open(&plan.archive).map_err(|source| BackupError::Io {
        path: plan.archive.clone(),
        source,
    })?;
    let mut zip = zip::ZipArchive::new(file).map_err(|_| BackupError::NotAnArchive {
        path: plan.archive.clone(),
    })?;
    if zip.len() > MAX_ENTRIES {
        return Err(BackupError::TooManyEntries {
            found: zip.len(),
            limit: MAX_ENTRIES,
        });
    }

    let mut staged: BTreeMap<RootLabel, Staged> = BTreeMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut written = 0_u64;

    let outcome = (|| -> Result<(), BackupError> {
        for i in 0..zip.len() {
            // Between entries, which is also where the staging trees are still discardable: the exit
            // below is the one a refused entry takes, so a stopped restore and a refused one leave the
            // live tree in the same state.
            if cancel.is_cancelled() {
                return Err(BackupError::Cancelled);
            }
            let mut entry = zip.by_index(i).map_err(|_| BackupError::NotAnArchive {
                path: plan.archive.clone(),
            })?;
            let raw = entry.name().to_owned();
            if raw == MANIFEST_ENTRY {
                continue;
            }
            let is_regular = !entry.is_symlink();
            let name = match entry_name(&raw, is_regular) {
                Ok(name) => name,
                // The root's own directory entry carries nothing and needs no target.
                Err(RejectReason::Empty) if entry.is_dir() => continue,
                Err(reason) => {
                    return Err(BackupError::RejectedEntry { entry: raw, reason });
                }
            };
            if !seen.insert(name.collision_key()) {
                return Err(BackupError::RejectedEntry {
                    entry: raw,
                    reason: RejectReason::Collision,
                });
            }
            let Some(target) = plan.targets.get(&name.root()) else {
                continue;
            };
            let record = expected
                .get(raw.as_str())
                .ok_or_else(|| BackupError::RejectedEntry {
                    entry: raw.clone(),
                    reason: RejectReason::NotInRecord,
                })?;

            let root = match staged.get_mut(&name.root()) {
                Some(root) => root,
                None => staged
                    .entry(name.root())
                    .or_insert(Staged::new(name.root(), target)?),
            };
            if entry.is_dir() {
                root.make_dir(&name)?;
            } else {
                let bytes = root.write_file(&name, &mut entry, record, &raw, &mut written)?;
                written = bytes;
            }
        }
        Ok(())
    })();

    if let Err(err) = outcome {
        // Nothing has moved yet, so discarding the staging trees restores the starting state exactly.
        for root in staged.values() {
            let _ = std::fs::remove_dir_all(&root.staging);
        }
        return Err(err);
    }

    let mut restored = Vec::with_capacity(staged.len());
    for (label, root) in staged {
        restored.push(root.commit(label, manifest.created_at)?);
    }
    let skipped = manifest
        .roots
        .iter()
        .map(|r| r.label)
        .filter(|l| !plan.targets.contains_key(l))
        .collect();
    // Read off what was actually put back rather than off the archive's record: the record is what a
    // writer claimed, and what a caller needs to know is whether anything landed under the label it
    // asked for.
    let absent = plan
        .targets
        .keys()
        .copied()
        .filter(|label| !restored.iter().any(|root| root.label == *label))
        .collect();
    Ok(RestoreReport {
        restored,
        skipped,
        absent,
    })
}

/// One root being assembled next to where it will land.
struct Staged {
    target: PathBuf,
    staging: PathBuf,
    /// Directory descriptors by path below the root, so every open is one component against a
    /// directory this module opened.
    dirs: HashMap<PathBuf, OwnedFd>,
    files: u64,
    dir_count: u64,
    bytes: u64,
}

impl Staged {
    /// Create the staging directory as a sibling of the target, so the final move is a rename on one
    /// filesystem rather than a copy.
    fn new(label: RootLabel, target: &Path) -> Result<Self, BackupError> {
        let parent = target.parent().ok_or_else(|| BackupError::Io {
            path: target.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a restore target needs a parent directory",
            ),
        })?;
        std::fs::create_dir_all(parent).map_err(|source| BackupError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let staging = unique_sibling(target, &format!(".apogee-restore-{}", label.prefix()))?;
        std::fs::create_dir(&staging).map_err(|source| BackupError::Io {
            path: staging.clone(),
            source,
        })?;
        let root_fd = open_dir(&staging)?;
        let mut dirs = HashMap::new();
        dirs.insert(PathBuf::new(), root_fd);
        Ok(Self {
            target: target.to_path_buf(),
            staging,
            dirs,
            files: 0,
            dir_count: 0,
            bytes: 0,
        })
    }

    fn make_dir(&mut self, name: &ConfinedName) -> Result<(), BackupError> {
        self.ensure_dir(name.relative())?;
        self.dir_count += 1;
        Ok(())
    }

    /// Open, creating if needed, the directory at `rel`, and every ancestor. Recursive so an archive
    /// that omits a parent's own entry still works.
    fn ensure_dir(&mut self, rel: &Path) -> Result<(), BackupError> {
        if self.dirs.contains_key(rel) {
            return Ok(());
        }
        let (parent, leaf) = split(rel)?;
        self.ensure_dir(&parent)?;
        let parent_fd = self.dirs.get(&parent).ok_or_else(|| io_err(rel))?;
        match rustix::fs::mkdirat(parent_fd, leaf.as_str(), Mode::from_raw_mode(0o755)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(errno) => {
                return Err(BackupError::Io {
                    path: self.staging.join(rel),
                    source: errno.into(),
                });
            }
        }
        let fd = rustix::fs::openat(
            parent_fd,
            leaf.as_str(),
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::empty(),
        )
        .map_err(|errno| BackupError::Io {
            path: self.staging.join(rel),
            source: errno.into(),
        })?;
        self.dirs.insert(rel.to_path_buf(), fd);
        Ok(())
    }

    /// Write one file, hashing it against the archive's own record on the way in.
    fn write_file(
        &mut self,
        name: &ConfinedName,
        source: &mut impl Read,
        record: &EntryRecord,
        raw: &str,
        written: &mut u64,
    ) -> Result<u64, BackupError> {
        let rel = name.relative();
        let (parent, leaf) = split(rel)?;
        self.ensure_dir(&parent)?;
        let parent_fd = self.dirs.get(&parent).ok_or_else(|| io_err(rel))?;
        let fd = rustix::fs::openat(
            parent_fd,
            leaf.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(|errno| BackupError::Io {
            path: self.staging.join(rel),
            source: errno.into(),
        })?;
        let mut out = std::fs::File::from(fd);

        let mut hasher = Sha256::new();
        let mut buf = vec![0_u8; COPY_BUF];
        let mut size = 0_u64;
        let mut total = *written;
        loop {
            let read = source.read(&mut buf).map_err(|source| BackupError::Io {
                path: self.staging.join(rel),
                source,
            })?;
            if read == 0 {
                break;
            }
            size += read as u64;
            total += read as u64;
            // Bounded on bytes leaving the decompressor, never on the size the container claims,
            // which the archive controls.
            if size > MAX_ENTRY_BYTES || total > MAX_TOTAL_BYTES {
                return Err(BackupError::TooLarge {
                    found: total,
                    limit: MAX_TOTAL_BYTES,
                });
            }
            hasher.update(&buf[..read]);
            std::io::Write::write_all(&mut out, &buf[..read]).map_err(|source| {
                BackupError::Io {
                    path: self.staging.join(rel),
                    source,
                }
            })?;
        }
        if hex(&hasher.finalize()) != record.sha256 || size != record.size {
            return Err(BackupError::ContentMismatch {
                entry: raw.to_owned(),
            });
        }
        self.files += 1;
        self.bytes += size;
        Ok(total)
    }

    /// Move the finished tree into place, setting the previous one aside first.
    fn commit(self, label: RootLabel, created_at: u64) -> Result<RestoredRoot, BackupError> {
        let displaced_to = if self.target.exists() {
            let aside = unique_sibling(&self.target, &format!(".apogee-prerestore-{created_at}"))?;
            std::fs::rename(&self.target, &aside).map_err(|source| BackupError::Io {
                path: self.target.clone(),
                source,
            })?;
            Some(aside)
        } else {
            None
        };
        std::fs::rename(&self.staging, &self.target).map_err(|source| BackupError::Io {
            path: self.target.clone(),
            source,
        })?;
        Ok(RestoredRoot {
            label,
            target: self.target,
            files: self.files,
            dirs: self.dir_count,
            bytes: self.bytes,
            displaced_to,
        })
    }
}

/// Split a relative path into its parent and its final component.
fn split(rel: &Path) -> Result<(PathBuf, String), BackupError> {
    let leaf = rel
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io_err(rel))?
        .to_owned();
    Ok((rel.parent().unwrap_or(Path::new("")).to_path_buf(), leaf))
}

/// A sibling name that does not exist yet, so a second restore cannot land on the first's leftovers.
fn unique_sibling(target: &Path, suffix: &str) -> Result<PathBuf, BackupError> {
    let base = target.as_os_str().to_string_lossy().into_owned();
    for n in 0..1024 {
        let candidate = if n == 0 {
            PathBuf::from(format!("{base}{suffix}"))
        } else {
            PathBuf::from(format!("{base}{suffix}-{n}"))
        };
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io_err(target))
}

fn open_dir(path: &Path) -> Result<OwnedFd, BackupError> {
    rustix::fs::open(
        path,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )
    .map_err(|errno| BackupError::Io {
        path: path.to_path_buf(),
        source: errno.into(),
    })
}

fn io_err(path: &Path) -> BackupError {
    BackupError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "unusable entry path"),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
