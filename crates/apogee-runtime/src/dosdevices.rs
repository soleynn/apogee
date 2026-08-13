//! Unix to windows path translation from a prefix's `dosdevices/` drive symlinks.
//!
//! A prefix maps its drives with one symlink per letter under `dosdevices/`: `c:` at `../drive_c`,
//! `z:` at `/`, plus whatever else has been mapped. They are static, so reading them once and
//! matching in process replaces a `winepath` subprocess per path (seven spawns per Dalamud launch).
//! Matching mirrors `winepath`: the drive whose target is the longest path prefix of the input wins.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::error::RuntimeError;

/// A prefix's drive letters, each resolved to an absolute unix path.
///
/// Drives are held longest-target-first, so the most specific one is the one that matches.
///
/// # Examples
///
/// ```
/// # use apogee_runtime::DriveMap;
/// # fn demo() -> Result<(), apogee_runtime::RuntimeError> {
/// # let dir = tempfile::tempdir().expect("tempdir");
/// # let root = dir.path().canonicalize().expect("canonicalize");
/// # std::fs::create_dir_all(root.join("drive_c/windows")).expect("drive_c");
/// # std::fs::create_dir_all(root.join("dosdevices")).expect("dosdevices");
/// # std::os::unix::fs::symlink("../drive_c", root.join("dosdevices/c:")).expect("c:");
/// # std::os::unix::fs::symlink("/", root.join("dosdevices/z:")).expect("z:");
/// // `root` is a prefix whose `dosdevices/c:` points at `drive_c` and whose `z:` points at `/`.
/// let map = DriveMap::from_prefix(&root)?;
///
/// assert_eq!(map.to_windows(&root.join("drive_c/windows"))?, r"C:\windows");
/// assert_eq!(map.to_unix(r"C:\windows")?, root.join("drive_c/windows"));
/// // A path no other drive covers falls to the one mapping `/`.
/// assert_eq!(map.to_windows(std::path::Path::new("/"))?, r"Z:\");
/// assert_eq!(map.to_unix(r"Z:\etc\hosts")?, std::path::PathBuf::from("/etc/hosts"));
/// # Ok(())
/// # }
/// # demo().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct DriveMap {
    drives: Vec<Drive>,
}

/// One drive letter and the unix path it points at.
#[derive(Debug, Clone)]
struct Drive {
    /// Lowercase ASCII drive letter.
    letter: char,
    /// Absolute unix target, canonicalized where it exists.
    target: PathBuf,
}

impl DriveMap {
    /// Read the drive map out of `<wine_root>/dosdevices`.
    ///
    /// Only symlinks named exactly `<letter>:` are drives. Device links (`c::`), ports (`com1`) and
    /// a plain file or directory carrying a drive's name are all skipped.
    ///
    /// # Errors
    /// [`RuntimeError::Io`] if the `dosdevices` directory cannot be listed or one of its entries
    /// cannot be read.
    pub fn from_prefix(wine_root: &Path) -> Result<Self, RuntimeError> {
        let dosdevices = wine_root.join("dosdevices");
        let entries = std::fs::read_dir(&dosdevices).map_err(|source| RuntimeError::Io {
            path: dosdevices.clone(),
            source,
        })?;
        let mut drives = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| RuntimeError::Io {
                path: dosdevices.clone(),
                source,
            })?;
            let Some(letter) = drive_letter(&entry.file_name()) else {
                continue;
            };
            // Only symlinks are drive maps; a plain file/dir named `c:` resolves to nothing.
            if let Some(target) = resolve_drive_target(&dosdevices, letter) {
                drives.push(Drive { letter, target });
            }
        }
        Ok(Self::from_drives(drives))
    }

    /// Sort drives longest-target-first, ties broken by letter, so the most specific mapping wins.
    fn from_drives(mut drives: Vec<Drive>) -> Self {
        drives.sort_by(|a, b| {
            b.target
                .components()
                .count()
                .cmp(&a.target.components().count())
                .then(a.letter.cmp(&b.letter))
        });
        Self { drives }
    }

    /// Map a unix path to its windows spelling, as `winepath -w` does.
    ///
    /// The longest matching drive wins and its letter comes back uppercase (`Z:\home\user`). The
    /// input is resolved first: an existing path is canonicalized, and one that does not exist yet
    /// is resolved through its longest existing ancestor, so a path under a symlinked prefix still
    /// maps to the drive it is under whether or not its leaf has been created.
    ///
    /// # Errors
    /// [`RuntimeError::PathMapping`] when no drive's target is a prefix of the path (with the usual
    /// `z:` mapping of `/`, only a relative path that does not exist), or when a component is not
    /// UTF-8 and so has no windows spelling.
    pub fn to_windows(&self, unix: &Path) -> Result<String, RuntimeError> {
        let key = resolve(unix);
        let (drive, rest) = self
            .drives
            .iter()
            .find_map(|d| key.strip_prefix(&d.target).ok().map(|rest| (d, rest)))
            .ok_or_else(|| RuntimeError::PathMapping {
                path: unix.to_path_buf(),
                reason: "no drive maps this path",
            })?;

        let mut out = String::new();
        out.push(drive.letter.to_ascii_uppercase());
        out.push(':');
        out.push('\\');
        let mut first = true;
        for comp in rest.components() {
            if let Component::Normal(segment) = comp {
                // A windows path is a String; a non-UTF8 unix component cannot be represented, so
                // error rather than lossily flattening it to replacement characters.
                let segment = segment.to_str().ok_or_else(|| RuntimeError::PathMapping {
                    path: unix.to_path_buf(),
                    reason: "path has a non-UTF8 component",
                })?;
                if !first {
                    out.push('\\');
                }
                out.push_str(segment);
                first = false;
            }
        }
        Ok(out)
    }

    /// Map a windows path to its unix form, reading nothing from the filesystem.
    ///
    /// The drive letter is matched case-insensitively and both slash styles are accepted, so
    /// `C:\windows` and `c:/windows` are one path. `.` and `..` resolve against the drive root and
    /// `..` is clamped there, as NT reads `C:\..` as `C:\`, so the result is always inside the
    /// drive's target.
    ///
    /// # Errors
    /// [`RuntimeError::PathMapping`] when the path does not begin with a drive letter and a colon
    /// (a UNC or relative path), or when this prefix has no such drive.
    pub fn to_unix(&self, windows: &str) -> Result<PathBuf, RuntimeError> {
        let bytes = windows.as_bytes();
        if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
            return Err(RuntimeError::PathMapping {
                path: PathBuf::from(windows),
                reason: "not a drive-letter path",
            });
        }
        let letter = (bytes[0] as char).to_ascii_lowercase();
        let drive = self
            .drives
            .iter()
            .find(|d| d.letter == letter)
            .ok_or_else(|| RuntimeError::PathMapping {
                path: PathBuf::from(windows),
                reason: "no such drive in this prefix",
            })?;

        // Resolve `.`/`..` against the drive root, clamping `..` there (NT treats `C:\..` as `C:\`),
        // so a hostile windows path can never escape the mapped drive subtree.
        let mut out = drive.target.clone();
        let mut depth = 0usize; // components pushed beyond the drive root
        for segment in windows[2..].split(['\\', '/']) {
            match segment {
                "" | "." => {}
                ".." => {
                    if depth > 0 {
                        out.pop();
                        depth -= 1;
                    }
                }
                normal => {
                    out.push(normal);
                    depth += 1;
                }
            }
        }
        Ok(out)
    }
}

/// The lowercase drive letter of a `dosdevices` entry named exactly `<letter>:`, or `None` for
/// anything else.
fn drive_letter(name: &OsStr) -> Option<char> {
    let s = name.to_str()?;
    let mut chars = s.chars();
    let letter = chars.next()?;
    if letter.is_ascii_alphabetic() && chars.next() == Some(':') && chars.next().is_none() {
        Some(letter.to_ascii_lowercase())
    } else {
        None
    }
}

/// The absolute unix target a `<letter>:` drive symlink resolves to, or `None` if it is missing or
/// is not a symlink.
///
/// Shared by [`DriveMap::from_prefix`] and the prefix health check, so drive-link resolution lives
/// in one place.
pub(crate) fn resolve_drive_target(dosdevices: &Path, letter: char) -> Option<PathBuf> {
    let target = std::fs::read_link(dosdevices.join(format!("{letter}:"))).ok()?;
    let absolute = if target.is_absolute() {
        target
    } else {
        dosdevices.join(target)
    };
    Some(resolve(&absolute))
}

/// Resolve `path` to the absolute, canonical form matching compares, the way `winepath` sees it.
///
/// An existing path is canonicalized outright; for one not created yet, the longest existing
/// ancestor is canonicalized and the missing tail re-appended, so ancestor symlinks resolve the same
/// whether or not the leaf exists. Both a drive target and a translation input pass through here, so
/// their symlink resolution stays symmetric. A path with no canonicalizable ancestor falls back to a
/// lexical [`normalize`].
fn resolve(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let mut tail = Vec::new();
    let mut current = path;
    loop {
        if let Ok(base) = current.canonicalize() {
            let mut out = base;
            out.extend(tail.iter().rev());
            return out;
        }
        match (current.file_name(), current.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                current = parent;
            }
            _ => return normalize(path),
        }
    }
}

/// Lexically normalize a path: drop `.`, resolve `..` against prior components, strip a trailing
/// separator. Touches no filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::Normal(segment) => out.push(segment),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(_) => {}
        }
    }
    if out.as_os_str().is_empty() {
        out.push(Component::RootDir.as_os_str());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a map straight from `(letter, absolute target)` pairs, bypassing the filesystem, so the
    /// translation logic is testable without a real prefix.
    fn map(drives: &[(char, &str)]) -> DriveMap {
        DriveMap::from_drives(
            drives
                .iter()
                .map(|&(letter, target)| Drive {
                    letter,
                    target: PathBuf::from(target),
                })
                .collect(),
        )
    }

    /// Only a name that is exactly a letter and a colon is a drive, so device links and ports in the
    /// same directory are not read as one.
    #[test]
    fn drive_letter_accepts_only_two_char_drive_names() {
        assert_eq!(drive_letter(OsStr::new("c:")), Some('c'));
        assert_eq!(drive_letter(OsStr::new("Z:")), Some('z'));
        assert_eq!(drive_letter(OsStr::new("c::")), None); // device link
        assert_eq!(drive_letter(OsStr::new("com1")), None);
        assert_eq!(drive_letter(OsStr::new("c")), None);
    }

    /// The most specific drive wins over the `z:` mapping of `/` that would also match, and a drive
    /// root itself maps to `X:\`.
    #[test]
    fn to_windows_picks_the_longest_matching_drive() {
        let m = map(&[('z', "/"), ('c', "/home/u/pfx/drive_c")]);
        assert_eq!(
            m.to_windows(Path::new("/home/u/pfx/drive_c/windows"))
                .unwrap(),
            "C:\\windows"
        );
        assert_eq!(
            m.to_windows(Path::new("/home/u/docs")).unwrap(),
            "Z:\\home\\u\\docs"
        );
        // The drive root itself maps to `X:\`.
        assert_eq!(m.to_windows(Path::new("/")).unwrap(), "Z:\\");
        assert_eq!(
            m.to_windows(Path::new("/home/u/pfx/drive_c")).unwrap(),
            "C:\\"
        );
    }

    /// Matching is by whole path component, so a drive target that is a string prefix of the input
    /// but not a path prefix of it does not match.
    #[test]
    fn to_windows_does_not_match_a_partial_component() {
        // `/home/user` must not match a drive at `/home/us`.
        let m = map(&[('z', "/"), ('d', "/home/us")]);
        assert_eq!(
            m.to_windows(Path::new("/home/user/file")).unwrap(),
            "Z:\\home\\user\\file"
        );
    }

    /// Both slash styles and either letter case name the same path, and a bare `X:\` is the drive
    /// target itself.
    #[test]
    fn to_unix_reverses_both_slash_styles() {
        let m = map(&[('z', "/"), ('c', "/home/u/pfx/drive_c")]);
        assert_eq!(
            m.to_unix("C:\\windows\\system32").unwrap(),
            PathBuf::from("/home/u/pfx/drive_c/windows/system32")
        );
        assert_eq!(
            m.to_unix("c:/windows").unwrap(),
            PathBuf::from("/home/u/pfx/drive_c/windows")
        );
        assert_eq!(m.to_unix("Z:\\").unwrap(), PathBuf::from("/"));
        assert_eq!(m.to_unix("Z:\\home\\u").unwrap(), PathBuf::from("/home/u"));
    }

    /// `..` resolves inside the drive and is clamped at its root, so a windows path from anywhere
    /// cannot name a unix path outside the drive's subtree.
    #[test]
    fn to_unix_clamps_parent_at_the_drive_root() {
        let m = map(&[('z', "/"), ('c', "/home/u/pfx/drive_c")]);
        // `..` inside the drive resolves normally.
        assert_eq!(
            m.to_unix("C:\\windows\\..\\system32").unwrap(),
            PathBuf::from("/home/u/pfx/drive_c/system32")
        );
        // `..` at or above the drive root is clamped (NT treats `C:\..` as `C:\`), never escaping.
        assert_eq!(
            m.to_unix("C:\\..\\..\\foo").unwrap(),
            PathBuf::from("/home/u/pfx/drive_c/foo")
        );
    }

    /// The two directions are inverses: a path translated to windows and back is the path it started
    /// as, whichever drive covered it.
    #[test]
    fn round_trip_holds_for_paths_under_each_drive() {
        let m = map(&[('z', "/"), ('c', "/home/u/pfx/drive_c")]);
        for unix in ["/home/u/pfx/drive_c/a/b", "/etc/hosts", "/"] {
            let win = m.to_windows(Path::new(unix)).unwrap();
            assert_eq!(
                m.to_unix(&win).unwrap(),
                PathBuf::from(unix),
                "round trip {unix}"
            );
        }
    }

    /// What is not a drive-letter path this prefix has is an error rather than a guessed-at unix
    /// path: a UNC path, a relative one, and a letter no drive carries.
    #[test]
    fn non_drive_windows_paths_are_rejected() {
        let m = map(&[('z', "/")]);
        assert!(m.to_unix("\\\\server\\share").is_err());
        assert!(m.to_unix("relative\\path").is_err());
        assert!(m.to_unix("q:\\nope").is_err()); // no such drive
    }

    /// The parse against a real prefix directory: relative and absolute drive links both resolve,
    /// and a device link sharing the directory is skipped.
    #[test]
    fn from_prefix_reads_real_symlinks() {
        let dir = apogee_test_support::sandbox::build_minimal_prefix().expect("prefix");
        let root = dir.path();
        // A device link that must be ignored (not a `<letter>:` drive).
        std::os::unix::fs::symlink("/dev/sda", root.join("dosdevices/c::")).expect("c::");

        let m = DriveMap::from_prefix(root).expect("parse");
        let real_c = root.join("drive_c").canonicalize().expect("canon");
        assert_eq!(m.to_unix("C:\\windows").unwrap(), real_c.join("windows"));
        assert_eq!(m.to_windows(&real_c).unwrap(), "C:\\");
        assert_eq!(m.to_windows(Path::new("/")).unwrap(), "Z:\\");
    }

    /// A path whose leaf does not exist yet still maps, because the drive target and the input
    /// resolve the same ancestor symlink identically.
    #[test]
    fn to_windows_resolves_symlinked_ancestors_of_a_missing_path() {
        // A prefix reached through a symlinked ancestor, translating a path whose leaf does not exist
        // yet (the injector-config case). Both the drive target and the input must resolve the
        // ancestor symlink identically, so the path still maps to C: (finding: oracle parity).
        let base = tempfile::tempdir().expect("tempdir");
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).expect("real");
        apogee_test_support::sandbox::write_prefix_skeleton(&real).expect("skeleton");
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("link");

        let m = DriveMap::from_prefix(&link).expect("parse");
        let missing = link.join("drive_c/newdir/newfile");
        assert_eq!(m.to_windows(&missing).unwrap(), "C:\\newdir\\newfile");
    }
}
