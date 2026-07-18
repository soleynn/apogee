//! The seams this crate owns for the apply/repair phases: the [`PatchSink`] the one interpreter
//! drives (apply, index, or trace) and the [`RangeSource`] repair pulls bytes through. These are the
//! public shape the applier and the repair planner fill in; the parser above produces the [`Chunk`]
//! stream they consume.
//!
//! [`Chunk`]: crate::Chunk

use std::ops::Range;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Limit, Result};

/// The deepest a confined patch path may nest. Real trees are a handful of levels; a patch claiming
/// dozens is hostile, so it is a typed fault, not an unbounded traversal.
const MAX_PATH_DEPTH: usize = 64;

/// A game-root-relative directory path that has passed confinement; sinks accept nothing else.
/// Unconstructable outside this crate: minted only by [`SafePath::confine`].
pub struct SafePath(PathBuf);

impl SafePath {
    /// Confine a patch-supplied directory path against the game root.
    ///
    /// # Errors
    /// [`Error::PathEscape`] if the path is absolute, contains `..`, names a drive, or is empty;
    /// [`Error::LimitExceeded`] if it nests past [`MAX_PATH_DEPTH`].
    pub(crate) fn confine(raw: &str) -> Result<Self> {
        Ok(Self(confine(raw)?))
    }

    /// The confined relative path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// A concrete file a patch writes to: a game-root-relative path that has passed confinement.
/// Unconstructable outside this crate: minted only by [`TargetPath::confine`].
pub struct TargetPath(PathBuf);

impl TargetPath {
    /// Confine a patch-supplied file path against the game root.
    ///
    /// # Errors
    /// [`Error::PathEscape`] if the path is absolute, contains `..`, names a drive, or is empty;
    /// [`Error::LimitExceeded`] if it nests past [`MAX_PATH_DEPTH`].
    pub(crate) fn confine(raw: &str) -> Result<Self> {
        Ok(Self(confine(raw)?))
    }

    /// The confined relative path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Confine a patch-supplied path to a game-root-relative path that cannot escape the tree.
///
/// Backslashes are folded to `/` **first**: on Linux `Path::components` treats `\` as an ordinary
/// character, so `..\..\x` would otherwise pass the `ParentDir` check as one opaque component. After
/// folding, only `Normal` components survive; `RootDir`/`ParentDir`/`Prefix` and a bare drive letter
/// (`C:`, which parses as `Normal` off-Windows) are escapes, and an over-deep path is a limit fault.
fn confine(raw: &str) -> Result<PathBuf> {
    let normalized = raw.replace('\\', "/");
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for comp in Path::new(&normalized).components() {
        match comp {
            Component::Normal(c) if !is_drive_letter(c.to_str()) => {
                depth += 1;
                if depth > MAX_PATH_DEPTH {
                    return Err(Error::LimitExceeded {
                        what: Limit::PathDepth,
                        value: depth as u64,
                        max: MAX_PATH_DEPTH as u64,
                    });
                }
                out.push(c);
            }
            Component::CurDir => {}
            Component::Normal(_)
            | Component::RootDir
            | Component::ParentDir
            | Component::Prefix(_) => {
                return Err(Error::PathEscape {
                    raw: raw.to_owned(),
                });
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(Error::PathEscape {
            raw: raw.to_owned(),
        });
    }
    Ok(out)
}

/// Whether a path component is a bare Windows drive letter such as `C:`.
fn is_drive_letter(comp: Option<&str>) -> bool {
    comp.is_some_and(|s| {
        let b = s.as_bytes();
        b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    })
}

/// Which expansion files to keep during a [`PatchSink::remove_expansion`].
#[derive(Debug, Clone, Default)]
pub struct KeepFilter {/* keep-rules not yet modeled */}

/// Identifies one source patch file to a [`RangeSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchId(pub u32);

/// Where written bytes come from: carries provenance for free.
#[derive(Debug)]
pub enum DataSource<'a> {
    Raw {
        patch_off: u64,
        bytes: &'a [u8],
    },
    Deflate {
        patch_off: u64,
        compressed_len: u32,
        decompressed_len: u32,
        /// The raw DEFLATE payload (no 16-byte block header), `compressed_len` bytes. A sink that
        /// records rather than applies (index, trace) ignores it; [`DiskSink`] decodes it.
        ///
        /// [`DiskSink`]: crate::DiskSink
        bytes: &'a [u8],
    },
    Zeros {
        len: u64,
    },
}

/// The apply target: every mutation a ZiPatch can make, expressed as typed calls so a sink can
/// journal, verify, or marshal them (the elevated worker is one such sink).
pub trait PatchSink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<()>;
    fn write_empty_block(&mut self, target: &TargetPath, off: u64, blocks: u32) -> Result<()>;
    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<()>;
    fn remove_file(&mut self, target: &TargetPath) -> Result<()>;
    fn remove_expansion(&mut self, expansion: u16, keep: &KeepFilter) -> Result<()>;
    fn make_dir_tree(&mut self, rel: &SafePath) -> Result<()>;
    fn remove_dir(&mut self, rel: &SafePath) -> Result<()>;
}

/// Random-access byte-range reads over one source patch file. Ranges are pre-merged and sorted by
/// the caller. The local implementor is `LocalPatchSource`; the HTTP one (`HttpRangeSource`) lives
/// in `apogee-fetch`.
pub trait RangeSource {
    fn read_ranges(
        &mut self,
        patch: PatchId,
        ranges: &[Range<u64>],
        out: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalizes_relative_paths() {
        let c = |raw: &str| confine(raw).unwrap().to_string_lossy().into_owned();
        assert_eq!(c("ffxivboot.exe"), "ffxivboot.exe");
        assert_eq!(c("locales/fileinfo.fiin"), "locales/fileinfo.fiin");
        // Backslashes fold to the platform separator, and a leading `./` is transparent.
        assert_eq!(c("sub\\dir\\file"), "sub/dir/file");
        assert_eq!(c("./a/b"), "a/b");
    }

    #[test]
    fn rejects_traversal_absolute_and_drive() {
        for raw in [
            "..",
            "../etc/passwd",
            "a/../../b",
            "/etc/passwd",
            "C:\\Windows\\x",
        ] {
            assert!(
                matches!(confine(raw), Err(Error::PathEscape { .. })),
                "expected {raw:?} to be rejected as an escape"
            );
        }
        // A backslash form of `..` must be caught: it is folded to `/` before the component walk, or
        // it would pass as one opaque component.
        assert!(matches!(
            confine("..\\..\\x"),
            Err(Error::PathEscape { .. })
        ));
    }

    #[test]
    fn rejects_empty_and_dot_only() {
        for raw in ["", ".", "./."] {
            assert!(
                matches!(confine(raw), Err(Error::PathEscape { .. })),
                "expected {raw:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_paths_deeper_than_the_cap() {
        let ok = vec!["a"; MAX_PATH_DEPTH].join("/");
        assert!(confine(&ok).is_ok());
        let too_deep = vec!["a"; MAX_PATH_DEPTH + 1].join("/");
        assert!(matches!(
            confine(&too_deep),
            Err(Error::LimitExceeded {
                what: Limit::PathDepth,
                ..
            })
        ));
    }

    #[test]
    fn newtypes_mint_only_through_confinement() {
        assert!(SafePath::confine("data").is_ok());
        assert!(TargetPath::confine("data/file").is_ok());
        assert!(SafePath::confine("../escape").is_err());
        assert!(TargetPath::confine("/abs").is_err());
    }
}
