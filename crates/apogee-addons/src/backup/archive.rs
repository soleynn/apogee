//! Writing a selection into a reproducible archive, and reading one back.
//!
//! Two backups of the same trees, at the same paths, stamped with the same instant, are
//! byte-identical. Everything that would otherwise vary is pinned rather than inherited: entry order
//! comes from the names instead of from directory order, timestamps and permissions are fixed
//! constants instead of copies of the source, and the compression level is stated rather than
//! defaulted. Two inputs do move the bytes and both are deliberate: the instant, which is a
//! caller-supplied parameter rather than a clock read, and the source paths, which the record keeps
//! so a human can tell two archives apart. Injecting the instant is what makes the property testable
//! in a hermetic run.
//!
//! The archive is written to a temporary in the destination directory and renamed into place, so an
//! interrupted run leaves an ignorable temporary rather than a truncated file whose central directory
//! still parses.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use super::error::BackupError;
use super::manifest::{
    BACKUP_EXTENSION, BACKUP_FORMAT, BACKUP_FORMAT_VERSION, BackupManifest, EntryRecord,
    MANIFEST_ENTRY, RootRecord, RuleRecord,
};
use super::rule::EntryKind;
use super::{RootReport, Selected, Selection};

/// Entries one archive may hold. A real config tree is a few hundred.
const MAX_ENTRIES: usize = 4096;

/// Total payload bytes one archive may hold. A real config tree is a few megabytes; the richest tree
/// observed, with chat logs opted in, is well under this.
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// Read buffer, shared by the hash and the compressor so each file is read once.
const COPY_BUF: usize = 256 * 1024;

/// What to capture, where to put it, and the instant to stamp it with.
#[derive(Debug, Clone)]
pub struct BackupSpec {
    /// The source trees and the rules that carve them up.
    pub selection: Selection,
    /// Directory the archive lands in, which is also the directory retention later scans.
    pub dest_dir: PathBuf,
    /// Supplied rather than read from the clock, so an archive is a function of its inputs and two
    /// runs can be compared byte for byte.
    pub created_at: SystemTime,
    /// Free-text label carried into the manifest.
    pub note: Option<String>,
}

/// What one backup captured.
#[derive(Debug, Clone)]
pub struct BackupReport {
    /// Where the archive was written.
    pub archive: PathBuf,
    /// Size of the archive on disk.
    pub archive_bytes: u64,
    /// Per-root outcome, including every rule's match count.
    pub roots: Vec<RootReport>,
}

/// Write `spec`'s selection into a new archive.
///
/// # Errors
/// Anything [`Selection::resolve`] raises, [`BackupError::TooManyEntries`] or
/// [`BackupError::TooLarge`] if the selection exceeds what an archive may hold, and
/// [`BackupError::Io`] or [`BackupError::Archive`] from the write.
pub fn create(spec: &BackupSpec) -> Result<BackupReport, BackupError> {
    let selected = spec.selection.resolve()?;
    check_limits(&selected)?;

    std::fs::create_dir_all(&spec.dest_dir).map_err(|source| BackupError::Io {
        path: spec.dest_dir.clone(),
        source,
    })?;
    let temp =
        tempfile::NamedTempFile::new_in(&spec.dest_dir).map_err(|source| BackupError::Io {
            path: spec.dest_dir.clone(),
            source,
        })?;

    let mut writer = ZipWriter::new(temp.reopen().map_err(|source| BackupError::Io {
        path: spec.dest_dir.clone(),
        source,
    })?);
    let mut records = Vec::with_capacity(selected.entries().len());

    for entry in selected.entries() {
        match entry.kind() {
            EntryKind::Dir => {
                writer
                    .add_directory(entry.name(), dir_options())
                    .map_err(|source| BackupError::Archive {
                        entry: entry.name().to_owned(),
                        source: Box::new(source),
                    })?;
                records.push(EntryRecord {
                    name: entry.name().to_owned(),
                    kind: EntryKind::Dir,
                    size: 0,
                    sha256: String::new(),
                });
            }
            EntryKind::File => {
                writer
                    .start_file(entry.name(), file_options())
                    .map_err(|source| BackupError::Archive {
                        entry: entry.name().to_owned(),
                        source: Box::new(source),
                    })?;
                let (size, sha256) = copy_hashed(entry.source(), &mut writer)?;
                records.push(EntryRecord {
                    name: entry.name().to_owned(),
                    kind: EntryKind::File,
                    size,
                    sha256,
                });
            }
        }
    }

    let manifest = BackupManifest {
        format: BACKUP_FORMAT.to_owned(),
        format_version: BACKUP_FORMAT_VERSION,
        producer: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        created_at: unix_seconds(spec.created_at),
        note: spec.note.clone(),
        roots: selected.roots().iter().map(root_record).collect(),
        entries: records,
    };
    let body = serde_json::to_vec_pretty(&manifest).map_err(|source| BackupError::Manifest {
        source: Box::new(source),
    })?;
    // Last, so a manifest can only ever describe a complete archive.
    writer
        .start_file(MANIFEST_ENTRY, file_options())
        .and_then(|()| writer.write_all(&body).map_err(Into::into))
        .map_err(|source| BackupError::Archive {
            entry: MANIFEST_ENTRY.to_owned(),
            source: Box::new(source),
        })?;
    writer.finish().map_err(|source| BackupError::Archive {
        entry: MANIFEST_ENTRY.to_owned(),
        source: Box::new(source),
    })?;

    let archive = persist(temp, &spec.dest_dir, manifest.created_at)?;
    let archive_bytes = std::fs::metadata(&archive)
        .map_err(|source| BackupError::Io {
            path: archive.clone(),
            source,
        })?
        .len();

    Ok(BackupReport {
        archive,
        archive_bytes,
        roots: selected.roots().to_vec(),
    })
}

/// Read an archive's manifest without inflating its payload.
///
/// # Errors
/// [`BackupError::Io`] if it cannot be opened, [`BackupError::NotAnArchive`] if it is not a zip or
/// carries no manifest, [`BackupError::Manifest`] if the manifest does not parse, and
/// [`BackupError::UnsupportedFormat`] if it was written by a newer format than this reader knows.
pub fn inspect(archive: &Path) -> Result<BackupManifest, BackupError> {
    let file = File::open(archive).map_err(|source| BackupError::Io {
        path: archive.to_path_buf(),
        source,
    })?;
    let mut zip = zip::ZipArchive::new(file).map_err(|_| BackupError::NotAnArchive {
        path: archive.to_path_buf(),
    })?;
    let mut entry = zip
        .by_name(MANIFEST_ENTRY)
        .map_err(|_| BackupError::NotAnArchive {
            path: archive.to_path_buf(),
        })?;
    let mut body = String::new();
    entry
        .read_to_string(&mut body)
        .map_err(|source| BackupError::Io {
            path: archive.to_path_buf(),
            source,
        })?;
    let manifest: BackupManifest =
        serde_json::from_str(&body).map_err(|source| BackupError::Manifest {
            source: Box::new(source),
        })?;
    if manifest.format != BACKUP_FORMAT {
        return Err(BackupError::NotAnArchive {
            path: archive.to_path_buf(),
        });
    }
    if manifest.format_version > BACKUP_FORMAT_VERSION {
        return Err(BackupError::UnsupportedFormat {
            path: archive.to_path_buf(),
            found: manifest.format_version,
            supported: BACKUP_FORMAT_VERSION,
        });
    }
    Ok(manifest)
}

/// Refuse a selection that would exceed what an archive may hold, before anything is written.
fn check_limits(selected: &Selected) -> Result<(), BackupError> {
    if selected.entries().len() > MAX_ENTRIES {
        return Err(BackupError::TooManyEntries {
            found: selected.entries().len(),
            limit: MAX_ENTRIES,
        });
    }
    if selected.bytes() > MAX_TOTAL_BYTES {
        return Err(BackupError::TooLarge {
            found: selected.bytes(),
            limit: MAX_TOTAL_BYTES,
        });
    }
    Ok(())
}

/// Options shared by every entry. Derived from the associated constant rather than `default()`,
/// which reads the clock when the crate's time support is compiled in.
fn base_options() -> SimpleFileOptions {
    SimpleFileOptions::DEFAULT
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6))
        .last_modified_time(zip::DateTime::default())
        .large_file(false)
}

/// A fixed mode, never the source file's: the real tree mixes modes depending on whether the game
/// rotated a file or wrote it in place, and permissions are applied to every entry or none so the
/// recorded originating system stays uniform.
fn file_options() -> SimpleFileOptions {
    base_options().unix_permissions(0o644)
}

fn dir_options() -> SimpleFileOptions {
    base_options().unix_permissions(0o755)
}

/// Copy one file into the writer, hashing the same buffer on the way through.
fn copy_hashed<W: Write + std::io::Seek>(
    source: &Path,
    writer: &mut ZipWriter<W>,
) -> Result<(u64, String), BackupError> {
    let mut file = File::open(source).map_err(|err| BackupError::Io {
        path: source.to_path_buf(),
        source: err,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; COPY_BUF];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buf).map_err(|err| BackupError::Io {
            path: source.to_path_buf(),
            source: err,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        writer
            .write_all(&buf[..read])
            .map_err(|err| BackupError::Io {
                path: source.to_path_buf(),
                source: err,
            })?;
        size += read as u64;
    }
    Ok((size, hex(&hasher.finalize())))
}

/// Move the finished temporary to its final name, which is the first free one. `create_new` in the
/// loop means two backups in the same second cannot land on each other.
fn persist(
    temp: tempfile::NamedTempFile,
    dest_dir: &Path,
    created_at: u64,
) -> Result<PathBuf, BackupError> {
    let stamp = stamp(created_at);
    for suffix in 0..64 {
        let name = if suffix == 0 {
            format!("apogee-config-{stamp}.{BACKUP_EXTENSION}")
        } else {
            format!("apogee-config-{stamp}-{suffix}.{BACKUP_EXTENSION}")
        };
        let candidate = dest_dir.join(&name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => {
                // Reserved, then replaced by the rename: same filesystem, so the final name appears
                // whole or not at all.
                return temp
                    .persist(&candidate)
                    .map(|_| candidate.clone())
                    .map_err(|err| BackupError::Io {
                        path: candidate,
                        source: err.error,
                    });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(BackupError::Io {
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(BackupError::Io {
        path: dest_dir.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "no free archive name for this instant",
        ),
    })
}

/// `YYYYMMDDTHHMMSSZ` from unix seconds, computed rather than formatted by a date library since the
/// only consumer is a filename that has to sort.
fn stamp(unix: u64) -> String {
    let (days, secs) = (unix / 86_400, unix % 86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // Civil-from-days, shifting the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = era * 400 + yoe + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}T{h:02}{m:02}{s:02}Z")
}

fn unix_seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn root_record(report: &RootReport) -> RootRecord {
    RootRecord {
        label: report.label(),
        source: report.path().to_string_lossy().into_owned(),
        rules: report
            .rules()
            .iter()
            .map(|r| RuleRecord {
                rule: r.rule().to_owned(),
                role: r.role(),
                matched: r.matched() as u64,
            })
            .collect(),
        files: report.files() as u64,
        dirs: report.dirs() as u64,
        bytes: report.bytes(),
        links_skipped: report.links_skipped() as u64,
        specials_skipped: report.specials_skipped() as u64,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stamp_is_a_sortable_utc_instant() {
        assert_eq!(stamp(0), "19700101T000000Z");
        assert_eq!(stamp(1_000_000_000), "20010909T014640Z");
        // A leap day, which the civil-from-days shift exists to get right.
        assert_eq!(stamp(1_709_164_800), "20240229T000000Z");
        assert_eq!(stamp(1_785_000_000), "20260725T172000Z");
    }
}
