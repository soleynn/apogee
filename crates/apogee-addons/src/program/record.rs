//! What a program step placed, file by file, and checking it is still what was placed.
//!
//! A program's bytes are pinned as archives, and an archive's digest says nothing about a file in
//! the prefix a week later: the program's own updater, a careless tool or the user can have replaced
//! any of them. So a step's archive is unpacked into staging first, every file it holds is hashed
//! there, and only then moved into place, and the list is kept outside the prefix under the addons
//! root. When a launch is planned, before the game is spawned, every listed file is hashed again,
//! walking from `C:` without following a link.
//!
//! The list lives in the launcher's own data directory, which a process running as the same user
//! can rewrite as easily as the files it describes. It catches self-updates and accidents, not a
//! determined local attacker.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::paths;
use crate::manifest::ComponentPath;
use crate::{AddonError, Result};

/// The largest record read back. A real one lists a few hundred files.
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
/// How much of a file is hashed per read.
const CHUNK: usize = 64 * 1024;

/// One placed file: where, how long, and what it hashed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlacedFile {
    /// Relative to the prefix's `C:`, `/`-separated.
    pub path: String,
    pub size: u64,
    pub blake3: String,
}

/// What one step of one program placed, at the row version it was placed for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StepRecord {
    pub program: String,
    pub version: String,
    pub step: String,
    pub files: Vec<PlacedFile>,
}

/// Where a prefix's records live: one directory per prefix under the addons root, keyed on a digest
/// of the prefix's path so two prefixes never share one and no prefix path becomes a file name.
pub(crate) fn records_dir(addons_root: &Path, prefix_path: &Path) -> PathBuf {
    let key = blake3::hash(prefix_path.as_os_str().as_encoded_bytes()).to_hex();
    addons_root.join("programs").join(&key.as_str()[..32])
}

/// Write `record` for its step, replacing any earlier one. Written beside and renamed over, so an
/// interrupted write leaves the previous record rather than a truncated one.
///
/// # Errors
/// [`AddonError::Io`] if the directory or the file cannot be written.
pub(crate) fn write(dir: &Path, record: &StepRecord) -> Result<()> {
    let io = |step: &'static str, path: &Path, source: std::io::Error| AddonError::Io {
        what: record.step.clone(),
        step,
        path: path.to_path_buf(),
        source: Box::new(source),
    };
    std::fs::create_dir_all(dir).map_err(|e| io("make its install record directory", dir, e))?;
    let path = dir.join(format!("{}.json", record.step));
    let staged = dir.join(format!("{}.json.new", record.step));
    let bytes = serde_json::to_vec(record).map_err(|e| {
        io(
            "write its install record",
            &staged,
            std::io::Error::other(e),
        )
    })?;
    std::fs::write(&staged, bytes).map_err(|e| io("write its install record", &staged, e))?;
    std::fs::rename(&staged, &path).map_err(|e| io("write its install record", &path, e))
}

/// Remove the record for `step`, if there is one.
///
/// # Errors
/// [`AddonError::Io`] if it exists and cannot be removed.
pub(crate) fn forget(dir: &Path, step: &str) -> Result<()> {
    let path = dir.join(format!("{step}.json"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AddonError::Io {
            what: step.to_owned(),
            step: "forget its install record",
            path,
            source: Box::new(source),
        }),
    }
}

/// The record for `step`, or why there is none to use.
pub(crate) fn read(dir: &Path, step: &str) -> std::result::Result<StepRecord, String> {
    let path = dir.join(format!("{step}.json"));
    let file = std::fs::File::open(&path).map_err(|_| "no record of what it placed".to_owned())?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "its install record cannot be read".to_owned())?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err("its install record is larger than any install".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|_| "its install record does not parse".to_owned())
}

/// Hash `reader` to completion.
pub(crate) fn hash(mut reader: impl Read) -> std::io::Result<(u64, String)> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, hasher.finalize().to_hex().to_string()))
}

/// Move every file of a staged tree into `dest`, hashing each first, and return what was placed with
/// paths relative to `C:` (`dest` being `drive_c/into`).
///
/// A staged entry that is neither a directory nor a regular file is refused before anything moves:
/// a program's archive has no business carrying a link, and a link moved into a prefix is a way out
/// of it.
///
/// # Errors
/// [`AddonError::Unpack`] for a link or special file in the archive, [`AddonError::UnsafePath`] if a
/// directory on the way into `dest` is a link or a file, [`AddonError::Io`] if a move fails.
pub(crate) fn place_staged(
    staged: &Path,
    dest: &Path,
    into: &Path,
    what: &str,
) -> Result<Vec<PlacedFile>> {
    let mut files = Vec::new();
    collect(staged, Path::new(""), &mut files, what)?;
    let mut placed = Vec::with_capacity(files.len());
    for rel in files {
        let from = staged.join(&rel);
        let file = std::fs::File::open(&from).map_err(|source| AddonError::Io {
            what: what.to_owned(),
            step: "read a staged file",
            path: from.clone(),
            source: Box::new(source),
        })?;
        let (size, digest) = hash(file).map_err(|source| AddonError::Io {
            what: what.to_owned(),
            step: "hash a staged file",
            path: from.clone(),
            source: Box::new(source),
        })?;
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        let dir = paths::walk_dirs(dest, parent, true, what)?;
        let Some(name) = rel.file_name() else {
            continue;
        };
        let to = dir.join(name);
        if std::fs::symlink_metadata(&to).is_ok_and(|m| m.is_dir()) {
            return Err(AddonError::UnsafePath {
                what: what.to_owned(),
                path: to,
                reason: "a directory stands where a file goes",
            });
        }
        // A rename replaces a link at `to` rather than writing through it. Staging sits beside the
        // target on the same volume, so a failed rename is refused rather than retried as a copy: a
        // copy opens `to` and would write through a link planted there.
        std::fs::rename(&from, &to).map_err(|source| AddonError::Io {
            what: what.to_owned(),
            step: "place a file",
            path: to.clone(),
            source: Box::new(source),
        })?;
        placed.push(PlacedFile {
            path: slashed(&into.join(&rel)),
            size,
            blake3: digest,
        });
    }
    Ok(placed)
}

fn collect(root: &Path, rel: &Path, out: &mut Vec<PathBuf>, what: &str) -> Result<()> {
    let dir = root.join(rel);
    let entries = std::fs::read_dir(&dir).map_err(|source| AddonError::Io {
        what: what.to_owned(),
        step: "read a staged directory",
        path: dir.clone(),
        source: Box::new(source),
    })?;
    let mut names: Vec<_> = entries.filter_map(std::result::Result::ok).collect();
    names.sort_by_key(std::fs::DirEntry::file_name);
    for entry in names {
        let child = rel.join(entry.file_name());
        let kind = entry.file_type().map_err(|source| AddonError::Io {
            what: what.to_owned(),
            step: "read a staged entry",
            path: root.join(&child),
            source: Box::new(source),
        })?;
        if kind.is_dir() {
            collect(root, &child, out, what)?;
        } else if kind.is_file() {
            out.push(child);
        } else {
            return Err(AddonError::Unpack {
                what: what.to_owned(),
                source: format!("{} is a link or special file", child.display()).into(),
            });
        }
    }
    Ok(())
}

/// A relative path as the record spells it.
fn slashed(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every file the program's non-seeded steps placed, later steps overriding earlier ones at the same
/// path, or why that cannot be told.
pub(crate) fn expected(
    dir: &Path,
    program: &str,
    version: &str,
    steps: &[&str],
) -> std::result::Result<BTreeMap<String, PlacedFile>, String> {
    let mut map = BTreeMap::new();
    for step in steps {
        let record = read(dir, step).map_err(|why| format!("{step}: {why}"))?;
        if record.program != program || record.step != *step || record.version != version {
            return Err(format!(
                "{step}: its install record is for another version of the program"
            ));
        }
        for file in record.files {
            map.insert(file.path.clone(), file);
        }
    }
    Ok(map)
}

/// Remove every file `previous` lists that `placed` does not: what an earlier install of a step put
/// in place and the install that just finished no longer carries.
///
/// Without this a file a newer version dropped would stay in the program's directory, loadable by
/// the program and listed by no record. Only a path this launcher recorded is ever touched, so what
/// the program or the user wrote beside its files is left alone.
///
/// `into` holds the step's destinations relative to `C:`. A recorded path is checked as a manifest
/// path is and must lie below one of them, so a rewritten record cannot aim a removal anywhere else.
/// The directories above a file are walked without following a link, and a path reached only through
/// one is left alone. A link standing at a recorded path is itself removed, never what it points to;
/// a directory or special file there is left alone, and a file already gone is fine.
///
/// # Errors
/// [`AddonError::Io`] if a file that should go cannot be removed.
pub(crate) fn remove_dropped(
    drive_c: &Path,
    into: &[PathBuf],
    previous: &[PlacedFile],
    placed: &[PlacedFile],
    what: &str,
) -> Result<()> {
    for file in previous {
        if placed.iter().any(|kept| kept.path == file.path) {
            continue;
        }
        let Ok(rel) = ComponentPath::parse(&file.path, what) else {
            continue;
        };
        let rel = rel.as_path();
        let (Some(parent), Some(name)) = (rel.parent(), rel.file_name()) else {
            continue;
        };
        if !into.iter().any(|dir| parent.starts_with(dir)) {
            continue;
        }
        let Ok(dir) = paths::walk_dirs(drive_c, parent, false, what) else {
            continue;
        };
        let path = dir.join(name);
        let removable = std::fs::symlink_metadata(&path)
            .is_ok_and(|meta| meta.file_type().is_file() || meta.file_type().is_symlink());
        if !removable {
            continue;
        }
        // Unlinking never follows: a link swapped in after the check loses the link, not its target.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(AddonError::Io {
                    what: what.to_owned(),
                    step: "remove a file an earlier version placed",
                    path,
                    source: Box::new(source),
                });
            }
        }
    }
    Ok(())
}

/// The first file in `expected` that is no longer what was placed, or `None` when all are.
///
/// A record path is checked as a manifest path is before it is opened, so a rewritten record cannot
/// send the hash outside the prefix.
pub(crate) fn first_changed(
    drive_c: &Path,
    expected: &BTreeMap<String, PlacedFile>,
) -> Option<String> {
    for file in expected.values() {
        let Ok(rel) = ComponentPath::parse(&file.path, "install record") else {
            return Some(file.path.clone());
        };
        let intact = paths::open_regular(drive_c, rel.as_path())
            .ok()
            .filter(|f| f.metadata().is_ok_and(|m| m.len() == file.size))
            .and_then(|f| hash(f).ok())
            .is_some_and(|(size, digest)| size == file.size && digest == file.blake3);
        if !intact {
            return Some(file.path.clone());
        }
    }
    None
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    fn staged_tree(root: &Path) -> PathBuf {
        let staged = root.join("staged");
        std::fs::create_dir_all(staged.join("Plugins")).expect("dirs");
        std::fs::write(staged.join("act.exe"), b"MZ act").expect("file");
        std::fs::write(staged.join("Plugins/parser.dll"), b"MZ plugin").expect("file");
        staged
    }

    /// What is placed is what was hashed, and a byte flipped afterwards, a file swapped for a link to
    /// an identical copy, or a file removed is each the first change found.
    #[test]
    fn a_placed_file_that_changed_is_found() {
        let root = tempfile::tempdir().expect("tempdir");
        let drive_c = root.path().join("drive_c");
        std::fs::create_dir_all(&drive_c).expect("drive_c");
        let staged = staged_tree(root.path());
        let dest = drive_c.join("Apogee/ACT");
        std::fs::create_dir_all(&dest).expect("dest");
        let placed =
            place_staged(&staged, &dest, Path::new("Apogee/ACT"), "act-files").expect("placed");
        let paths: Vec<&str> = placed.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            ["Apogee/ACT/Plugins/parser.dll", "Apogee/ACT/act.exe"]
        );

        let dir = root.path().join("records");
        write(
            &dir,
            &StepRecord {
                program: "act".to_owned(),
                version: "1".to_owned(),
                step: "act-files".to_owned(),
                files: placed,
            },
        )
        .expect("record");
        let expected = expected(&dir, "act", "1", &["act-files"]).expect("expected");
        assert_eq!(first_changed(&drive_c, &expected), None);
        // Another version's record does not stand in for this one.
        assert!(super::expected(&dir, "act", "2", &["act-files"]).is_err());

        let dll = dest.join("Plugins/parser.dll");
        std::fs::write(&dll, b"MZ plugix").expect("flip");
        assert_eq!(
            first_changed(&drive_c, &expected).as_deref(),
            Some("Apogee/ACT/Plugins/parser.dll")
        );

        std::fs::write(root.path().join("copy.dll"), b"MZ plugin").expect("copy");
        std::fs::remove_file(&dll).expect("rm");
        std::os::unix::fs::symlink(root.path().join("copy.dll"), &dll).expect("link");
        assert!(
            first_changed(&drive_c, &expected).is_some(),
            "a link is not the file"
        );

        std::fs::remove_file(&dll).expect("rm");
        assert!(
            first_changed(&drive_c, &expected).is_some(),
            "a missing file is a change"
        );
    }

    /// Only a recorded file below the step's own destination is removed. A record rewritten to name
    /// a path that climbs out, a file elsewhere in the prefix, or a file reached through a linked
    /// directory removes nothing, and neither does a directory standing at a recorded path.
    #[test]
    fn a_dropped_file_is_removed_only_from_below_its_steps_destination() {
        let root = tempfile::tempdir().expect("tempdir");
        let drive_c = root.path().join("drive_c");
        let outside = root.path().join("outside");
        for dir in [
            drive_c.join("Apogee/ACT/kept-dir.dll"),
            drive_c.join("Apogee/Other"),
            outside.clone(),
        ] {
            std::fs::create_dir_all(dir).expect("dirs");
        }
        let survivors = [
            root.path().join("secret"),
            drive_c.join("Apogee/Other/theirs.dll"),
            outside.join("linked.dll"),
        ];
        for file in &survivors {
            std::fs::write(file, b"keep").expect("file");
        }
        std::os::unix::fs::symlink(&outside, drive_c.join("Apogee/ACT/Plugins")).expect("link");
        std::fs::write(drive_c.join("Apogee/ACT/old.dll"), b"old").expect("file");

        let listed = |path: &str| PlacedFile {
            path: path.to_owned(),
            size: 0,
            blake3: String::new(),
        };
        let previous = [
            listed("Apogee/ACT/old.dll"),
            listed("Apogee/ACT/never-there.dll"),
            listed("Apogee/ACT/kept-dir.dll"),
            listed("Apogee/ACT/Plugins/linked.dll"),
            listed("Apogee/ACT/../../../secret"),
            listed("Apogee/Other/theirs.dll"),
            listed("/etc/hostname"),
        ];
        remove_dropped(
            &drive_c,
            &[PathBuf::from("Apogee/ACT")],
            &previous,
            &[],
            "act-files",
        )
        .expect("nothing here is an error");

        assert!(!drive_c.join("Apogee/ACT/old.dll").exists());
        assert!(drive_c.join("Apogee/ACT/kept-dir.dll").is_dir());
        for file in &survivors {
            assert!(file.exists(), "{} must survive", file.display());
        }
    }

    /// A record rewritten to point outside the prefix is a change, not a hash of whatever it names.
    #[test]
    fn a_record_naming_a_path_outside_the_prefix_is_a_change() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut expected = BTreeMap::new();
        expected.insert(
            "../../etc/passwd".to_owned(),
            PlacedFile {
                path: "../../etc/passwd".to_owned(),
                size: 0,
                blake3: String::new(),
            },
        );
        assert_eq!(
            first_changed(root.path(), &expected).as_deref(),
            Some("../../etc/passwd")
        );
    }

    /// A link in a program's archive is refused before anything moves into the prefix.
    #[test]
    fn a_staged_link_is_refused_before_anything_moves() {
        let root = tempfile::tempdir().expect("tempdir");
        let staged = staged_tree(root.path());
        std::os::unix::fs::symlink("/etc", staged.join("Plugins/escape")).expect("link");
        let dest = root.path().join("dest");
        let err = place_staged(&staged, &dest, Path::new("Apogee/ACT"), "act-files")
            .expect_err("a link is refused");
        assert!(matches!(err, AddonError::Unpack { .. }), "{err:?}");
        assert!(!dest.exists(), "nothing moved");
    }
}
