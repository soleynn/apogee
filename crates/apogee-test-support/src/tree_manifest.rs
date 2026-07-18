//! Record a directory tree as recorded-fact JSON and diff a tree against it.
//!
//! The byte-identity bar for the patch applier compares an applied tree against the reference
//! applier's output. The reference runs out-of-process on a developer machine; its resulting tree is
//! hashed once into a [`TreeManifest`] (per-file relative path, length, SHA256) and committed. The
//! manifest holds only our own facts, never game bytes, so it commits cleanly. CI then applies the
//! same corpus and [`compare`]s its tree against the manifest.
//!
//! The JSON is deterministic across machines: files are sorted by path, separators are always `/`,
//! and digests render as lowercase hex, so a committed manifest is reviewable and a re-author is
//! byte-identical.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read as _};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::golden::to_hex;

/// The recorded facts for one file: its `/`-joined path relative to the tree root, byte length, and
/// lowercase-hex SHA256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFact {
    pub path: String,
    pub len: u64,
    pub sha256: String,
}

/// A tree recorded as a sorted list of [`FileFact`]s. Empty directories are invisible (a file-only
/// record) and symlinks are neither followed nor recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeManifest {
    pub version: u32,
    pub files: Vec<FileFact>,
}

/// The current [`TreeManifest`] envelope version.
pub const MANIFEST_VERSION: u32 = 1;

impl TreeManifest {
    /// Serialize to pretty JSON. Deterministic: files are already sorted by path, fields are in a
    /// fixed order, so two authors of the same tree render byte-identically.
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        // Serializing a `Vec`/`String`/`u64` shape is infallible.
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Parse a manifest from JSON.
    ///
    /// # Errors
    /// Returns the `serde_json` error when the input is not a valid manifest.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

/// One way an applied tree can diverge from its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffEntry {
    /// In the manifest, absent on disk.
    Missing { path: String },
    /// On disk, absent from the manifest (a stray the ignore predicate did not excuse).
    Extra { path: String },
    /// Present on both, byte length differs.
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    /// Present on both, same length, content hash differs.
    HashMismatch { path: String },
}

impl fmt::Display for DiffEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffEntry::Missing { path } => write!(f, "missing: {path}"),
            DiffEntry::Extra { path } => write!(f, "stray:   {path}"),
            DiffEntry::SizeMismatch {
                path,
                expected,
                actual,
            } => write!(f, "size:    {path} (expected {expected}, got {actual})"),
            DiffEntry::HashMismatch { path } => write!(f, "hash:    {path}"),
        }
    }
}

/// The result of [`compare`]: the divergences that matter and the strays the ignore predicate
/// excused (reported for visibility, never failing).
#[derive(Debug, Clone, Default)]
pub struct TreeDiff {
    pub entries: Vec<DiffEntry>,
    pub ignored: Vec<String>,
}

impl TreeDiff {
    /// True when the tree matches the manifest (ignored strays do not count against a match).
    #[must_use]
    pub fn is_match(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Display for TreeDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} divergence(s):", self.entries.len())?;
        for entry in &self.entries {
            writeln!(f, "  {entry}")?;
        }
        if !self.ignored.is_empty() {
            writeln!(f, "{} ignored stray(s):", self.ignored.len())?;
            for path in &self.ignored {
                writeln!(f, "  ignored: {path}")?;
            }
        }
        Ok(())
    }
}

/// Walk `root` and record every regular file as a [`FileFact`], sorted by path.
///
/// # Errors
/// Returns an I/O error if the tree cannot be read or a file cannot be hashed.
pub fn author(root: &Path) -> io::Result<TreeManifest> {
    let mut files = walk(root)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(TreeManifest {
        version: MANIFEST_VERSION,
        files,
    })
}

/// Diff the tree at `root` against `manifest`. `ignore`, if given, classifies an on-disk stray
/// (a file absent from the manifest) as excused rather than a divergence; it is called with the
/// stray's on-disk path.
///
/// # Errors
/// Returns an I/O error if the tree cannot be read or a file cannot be hashed.
pub fn compare(
    root: &Path,
    manifest: &TreeManifest,
    ignore: Option<&dyn Fn(&Path) -> bool>,
) -> io::Result<TreeDiff> {
    let actual = walk(root)?;
    let actual_by_path: BTreeMap<&str, &FileFact> =
        actual.iter().map(|f| (f.path.as_str(), f)).collect();
    let expected_by_path: BTreeMap<&str, &FileFact> = manifest
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();

    let mut diff = TreeDiff::default();

    for expected in &manifest.files {
        match actual_by_path.get(expected.path.as_str()) {
            None => diff.entries.push(DiffEntry::Missing {
                path: expected.path.clone(),
            }),
            Some(actual) => {
                if actual.len != expected.len {
                    diff.entries.push(DiffEntry::SizeMismatch {
                        path: expected.path.clone(),
                        expected: expected.len,
                        actual: actual.len,
                    });
                } else if actual.sha256 != expected.sha256 {
                    diff.entries.push(DiffEntry::HashMismatch {
                        path: expected.path.clone(),
                    });
                }
            }
        }
    }

    for actual in &actual {
        if expected_by_path.contains_key(actual.path.as_str()) {
            continue;
        }
        let on_disk = root.join(&actual.path);
        if ignore.is_some_and(|f| f(&on_disk)) {
            diff.ignored.push(actual.path.clone());
        } else {
            diff.entries.push(DiffEntry::Extra {
                path: actual.path.clone(),
            });
        }
    }

    Ok(diff)
}

/// Assert the tree at `root` matches `manifest`, printing a readable diff on failure.
///
/// # Panics
/// Fails the test when the tree diverges from the manifest or cannot be walked.
#[track_caller]
pub fn assert_tree_matches(
    root: &Path,
    manifest: &TreeManifest,
    ignore: Option<&dyn Fn(&Path) -> bool>,
) {
    let report = match compare(root, manifest, ignore) {
        Ok(diff) if diff.is_match() => String::new(),
        Ok(diff) => diff.to_string(),
        Err(e) => format!("failed to walk {}: {e}", root.display()),
    };
    assert!(report.is_empty(), "{report}");
}

/// Iteratively walk `root` (explicit stack, so a pathologically deep tree cannot overflow the
/// call stack), collecting regular files. Symlinks are skipped, not followed.
fn walk(root: &Path) -> io::Result<Vec<FileFact>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                out.push(FileFact {
                    path: relative_slash_path(root, &path)?,
                    len: entry.metadata()?.len(),
                    sha256: to_hex(&hash_file(&path)?),
                });
            }
        }
    }
    Ok(out)
}

/// Render `path` (under `root`) as a `/`-joined string relative to `root`, regardless of OS
/// separator, so a manifest authored on any platform is byte-identical.
fn relative_slash_path(root: &Path, path: &Path) -> io::Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut out = String::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(&name.to_string_lossy());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected path component",
                ));
            }
        }
    }
    Ok(out)
}

/// Stream a file's SHA256 in a bounded buffer (game files are large; never buffer the whole file).
fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaos::sha256_of;

    fn write(root: &Path, rel: &str, bytes: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, bytes).expect("write file");
    }

    #[test]
    fn author_records_sorted_facts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(root, "b.dat", b"second");
        write(root, "a.dat", b"first");
        write(root, "sub/c.dat", b"third");

        let manifest = author(root).expect("author");
        assert_eq!(manifest.version, MANIFEST_VERSION);
        let paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["a.dat", "b.dat", "sub/c.dat"]);

        let a = &manifest.files[0];
        assert_eq!(a.len, 5);
        assert_eq!(a.sha256, to_hex(&sha256_of(b"first")));
    }

    #[test]
    fn json_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "x", b"bytes");
        let manifest = author(dir.path()).expect("author");
        let json = manifest.to_json_pretty();
        assert_eq!(TreeManifest::from_json(&json).expect("parse"), manifest);
    }

    #[test]
    fn compare_of_the_same_tree_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "a", b"aa");
        write(dir.path(), "d/b", b"bb");
        let manifest = author(dir.path()).expect("author");
        let diff = compare(dir.path(), &manifest, None).expect("compare");
        assert!(diff.is_match(), "{diff}");
    }

    #[test]
    fn compare_reports_each_divergence() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "keep", b"unchanged");
        write(dir.path(), "shrink", b"original");
        write(dir.path(), "flip", b"aaaa");
        write(dir.path(), "gone", b"present");
        let manifest = author(dir.path()).expect("author");

        // Mutate: truncate -> SizeMismatch, same-len flip -> HashMismatch, delete -> Missing,
        // add stray -> Extra.
        write(dir.path(), "shrink", b"cut");
        write(dir.path(), "flip", b"bbbb");
        fs::remove_file(dir.path().join("gone")).expect("remove");
        write(dir.path(), "stray", b"new");

        let diff = compare(dir.path(), &manifest, None).expect("compare");
        assert!(diff.entries.contains(&DiffEntry::SizeMismatch {
            path: "shrink".into(),
            expected: 8,
            actual: 3,
        }));
        assert!(diff.entries.contains(&DiffEntry::HashMismatch {
            path: "flip".into()
        }));
        assert!(diff.entries.contains(&DiffEntry::Missing {
            path: "gone".into()
        }));
        assert!(diff.entries.contains(&DiffEntry::Extra {
            path: "stray".into()
        }));
        assert_eq!(diff.entries.len(), 4);
    }

    #[test]
    fn ignore_predicate_excuses_strays() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "game.dat", b"data");
        let manifest = author(dir.path()).expect("author");
        write(dir.path(), "ffxivgame.ver", b"2024");

        let ignore = |p: &Path| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("ver"));
        let diff = compare(dir.path(), &manifest, Some(&ignore)).expect("compare");
        assert!(diff.is_match(), "{diff}");
        assert_eq!(diff.ignored, ["ffxivgame.ver"]);
    }
}
