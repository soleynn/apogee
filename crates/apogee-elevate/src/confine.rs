//! Keeping every privileged write inside the tree the session was bound to.
//!
//! The parent chooses the paths, so without this the worker is a general-purpose "write these bytes
//! there, as administrator" service. Two rules do the narrowing: the bound root must be absolute
//! (an elevated process inherits the system directory as its working directory, so a relative one
//! would resolve somewhere no caller intended), and every path the parent names afterwards is
//! relative, made of ordinary components only, and re-checked against the root after the parent
//! directories exist.

use std::path::{Component, Path, PathBuf};

/// A path the parent named that the worker refuses to write.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfineError {
    /// A path that had to be absolute was not.
    #[error("{what} must be an absolute path, got {path:?}")]
    NotAbsolute {
        /// Which path the rule is about.
        what: &'static str,
        /// The offending value.
        path: PathBuf,
    },
    /// A relative path carried a root, a drive prefix, a parent hop, or nothing at all.
    #[error("relative path {path:?} is not confined to the bound tree")]
    NotConfined {
        /// The offending value.
        path: PathBuf,
    },
    /// The resolved location left the bound tree once the filesystem was consulted.
    #[error("{path:?} resolves outside the bound tree")]
    Escapes {
        /// The offending value.
        path: PathBuf,
    },
    /// The check could not be completed.
    #[error("cannot resolve {path:?}")]
    Io {
        /// The path being resolved.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// Require an absolute path.
///
/// # Errors
/// [`ConfineError::NotAbsolute`] if `path` is relative.
pub fn require_absolute(what: &'static str, path: &Path) -> Result<(), ConfineError> {
    if path.is_absolute() {
        return Ok(());
    }
    Err(ConfineError::NotAbsolute {
        what,
        path: path.to_path_buf(),
    })
}

/// Join a parent-supplied relative path onto `root`, rejecting anything that is not a plain
/// descent.
///
/// Only [`Component::Normal`] is accepted, which drops a leading `/`, a Windows drive or UNC
/// prefix, and every `..` in one rule rather than three; `.` is skipped. An empty result is refused,
/// since it names the root itself.
///
/// A backslash or a colon anywhere in `rel` is refused before that, because those two characters do
/// not mean the same thing on both platforms and the component rule alone would therefore accept
/// different things depending on where it ran: a Linux build reads `C:\Windows\x` as one ordinary
/// filename, and a Windows one reads `name:stream` as an alternate data stream rather than as a
/// file. Every path this protocol carries is generated with forward slashes, so the rule costs
/// nothing and makes the check answer identically everywhere.
///
/// This is the lexical half. It does not follow links, so it is paired with
/// [`assert_within`] once the directories exist.
///
/// # Errors
/// [`ConfineError::NotConfined`] if `rel` carries a backslash or a colon, anything but ordinary
/// components, or resolves to no components at all.
pub fn join_confined(root: &Path, rel: &str) -> Result<PathBuf, ConfineError> {
    let bad = || ConfineError::NotConfined {
        path: PathBuf::from(rel),
    };
    if rel.contains('\\') || rel.contains(':') {
        return Err(bad());
    }
    let mut out = root.to_path_buf();
    let mut any = false;
    for component in Path::new(rel).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                out.push(part);
                any = true;
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return Err(bad()),
        }
    }
    if !any {
        return Err(bad());
    }
    Ok(out)
}

/// Assert that `path`'s existing parent directory really sits inside `root`.
///
/// [`join_confined`] cannot see a symbolic link or a directory junction standing in for one of the
/// components it accepted, so the parent is canonicalized and compared once it exists. The file
/// itself need not exist; its directory must.
///
/// # Errors
/// [`ConfineError::Escapes`] if the canonical parent is not beneath the canonical root,
/// [`ConfineError::Io`] if either cannot be canonicalized, or [`ConfineError::NotConfined`] if
/// `path` has no parent.
pub fn assert_within(root: &Path, path: &Path) -> Result<(), ConfineError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| ConfineError::Io { path, source }
    };
    let real_root = root.canonicalize().map_err(io(root))?;
    let parent = path.parent().ok_or_else(|| ConfineError::NotConfined {
        path: path.to_path_buf(),
    })?;
    let real_parent = parent.canonicalize().map_err(io(parent))?;
    if real_parent.starts_with(&real_root) {
        return Ok(());
    }
    Err(ConfineError::Escapes {
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ordinary descent joins onto the root.
    #[test]
    fn a_plain_relative_path_joins_onto_the_root() {
        let root = Path::new("/install/game");
        assert_eq!(
            join_confined(root, "sqpack/ex3/ex3.ver").unwrap(),
            Path::new("/install/game/sqpack/ex3/ex3.ver")
        );
        assert_eq!(
            join_confined(root, "./ffxivgame.ver").unwrap(),
            Path::new("/install/game/ffxivgame.ver")
        );
    }

    /// Every shape that would leave the tree is refused, and the same set is refused on every
    /// platform. Two of these only mean something on Windows (a drive-qualified path, a UNC share)
    /// and one only there as well (an alternate data stream); the answer must not depend on which
    /// build is asking, or a rule proven on the runner would not be the rule that ships.
    #[test]
    fn a_path_that_would_leave_the_tree_is_refused_on_every_platform() {
        let root = Path::new("/install/game");
        for rel in [
            "../boot/ffxivboot.ver",
            "a/../../b",
            "/etc/passwd",
            "",
            ".",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"\\server\share\x",
            r"sqpack\..\..\boot",
            "ffxivgame.ver:stream",
        ] {
            assert!(
                join_confined(root, rel).is_err(),
                "{rel:?} was accepted as confined"
            );
        }
    }

    /// An absolute path is required where one is required, and a relative one is named as the
    /// offender rather than silently resolved against whatever directory the process happens to be
    /// in.
    #[test]
    fn require_absolute_names_the_relative_path() {
        assert!(require_absolute("apply root", Path::new("/install/game")).is_ok());
        let err = require_absolute("apply root", Path::new("game")).unwrap_err();
        assert!(
            matches!(err, ConfineError::NotAbsolute { .. }),
            "got {err:?}"
        );
    }

    /// The filesystem-level check accepts a real descent and rejects one whose directory is a link
    /// out of the tree. This is the case the lexical rule cannot see: every component is `Normal`.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_out_of_the_tree_is_caught_by_the_second_check() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("game");
        let outside = base.path().join("outside");
        std::fs::create_dir_all(root.join("sqpack")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();

        let inside = join_confined(&root, "sqpack/ffxivgame.ver").unwrap();
        assert_within(&root, &inside).unwrap();

        let escaped = join_confined(&root, "escape/ffxivgame.ver").unwrap();
        let err = assert_within(&root, &escaped).unwrap_err();
        assert!(matches!(err, ConfineError::Escapes { .. }), "got {err:?}");
    }
}
