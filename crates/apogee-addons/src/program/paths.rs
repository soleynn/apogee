//! Turning a row's path into a place inside a prefix, without following a link on the way.
//!
//! Two jobs. The `{appdata}` token resolves to the prefix user's roaming application data, whose user
//! differs by runner. And every directory on the way from `C:` to a destination is walked one
//! component at a time with no-follow semantics, so a symlink planted anywhere above it (or one of
//! wine's own user-folder links into `$HOME`) is refused rather than written through. The extractor
//! already refuses links below a destination; this is the same rule above it.
//!
//! A race between the walk and the write by a process running as the same user remains: the
//! standard library has no `openat` walk for creation, and closing that is a kernel boundary's job.

use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use apogee_runtime::{Prefix, RunnerKind};

use crate::manifest::{ComponentPath, PathRoot};
use crate::{AddonError, Result};

/// The user Proton builds every prefix for.
const PROTON_USER: &str = "steamuser";
/// The shared profile every wine prefix carries beside its user's own.
const PUBLIC_USER: &str = "Public";

/// The account whose profile a prefix's `{appdata}` belongs to, or `None` when it cannot be told.
///
/// Proton prefixes always belong to `steamuser`. A plain wine prefix belongs to the account that
/// created it, which is the one running the launcher: its name is taken from the environment when
/// the prefix carries a profile for it, and otherwise from the prefix's only non-shared profile.
pub(crate) fn wine_user(prefix: &Prefix) -> Option<String> {
    if prefix.runner().kind() == RunnerKind::ProtonUmu {
        return Some(PROTON_USER.to_owned());
    }
    let users = prefix.drive_c().join("users");
    let from_env = ["USER", "LOGNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .filter(|name| usable_user(name));
    if let Some(name) = &from_env
        && std::fs::symlink_metadata(users.join(name)).is_ok_and(|m| m.is_dir())
    {
        return from_env;
    }
    let profiles: Vec<String> = std::fs::read_dir(&users)
        .ok()?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name != PUBLIC_USER && usable_user(name))
        .collect();
    match profiles.as_slice() {
        [only] => Some(only.clone()),
        _ => from_env,
    }
}

/// Whether `name` can be one path component naming a profile.
fn usable_user(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name != PUBLIC_USER
        && !name.contains(['/', '\\', '\0'])
        && !name.chars().any(char::is_control)
}

/// `path` relative to the prefix's `C:`, with its root resolved.
///
/// # Errors
/// [`AddonError::UnsafePath`] when the path is rooted at `{appdata}` and the prefix's user cannot be
/// told.
pub(crate) fn under_drive_c(prefix: &Prefix, path: &ComponentPath, what: &str) -> Result<PathBuf> {
    match path.root() {
        PathRoot::DriveC => Ok(path.as_path().to_path_buf()),
        PathRoot::AppData => {
            let user = wine_user(prefix).ok_or_else(|| AddonError::UnsafePath {
                what: what.to_owned(),
                path: path.as_path().to_path_buf(),
                reason: "the prefix has no user profile to resolve {appdata} against",
            })?;
            Ok(Path::new("users")
                .join(user)
                .join("AppData")
                .join("Roaming")
                .join(path.as_path()))
        }
    }
}

/// Walk `rel` below `base` one directory at a time without following a link, creating what is
/// missing when `create` is set, and return the full path.
///
/// # Errors
/// [`AddonError::UnsafePath`] if a component is a symlink or not a directory, or (without `create`)
/// does not exist; [`AddonError::Io`] if one cannot be read or made.
pub(crate) fn walk_dirs(base: &Path, rel: &Path, create: bool, what: &str) -> Result<PathBuf> {
    let mut current = base.to_path_buf();
    for part in rel.components() {
        let Component::Normal(name) = part else {
            return Err(unsafe_path(what, rel, "it is not a plain relative path"));
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(unsafe_path(
                    what,
                    &current,
                    "a directory on the way is a link",
                ));
            }
            Ok(_) => {
                return Err(unsafe_path(
                    what,
                    &current,
                    "a directory on the way is a file",
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&current).map_err(|source| AddonError::Io {
                    what: what.to_owned(),
                    step: "make a directory",
                    path: current.clone(),
                    source: Box::new(source),
                })?;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(unsafe_path(what, &current, "it does not exist"));
            }
            Err(source) => {
                return Err(AddonError::Io {
                    what: what.to_owned(),
                    step: "read a directory on the way",
                    path: current,
                    source: Box::new(source),
                });
            }
        }
    }
    Ok(current)
}

/// Open the regular file at `rel` below `base` for reading, refusing a link anywhere on the way or at
/// the file itself, and anything that is not a regular file.
///
/// Opened non-blocking as well as no-follow, so a pipe swapped in after the type check cannot hold
/// the launch on an open that never returns.
pub(crate) fn open_regular(base: &Path, rel: &Path) -> io::Result<File> {
    let refuse = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_owned());
    let parent = rel.parent().unwrap_or_else(|| Path::new(""));
    let dir = walk_dirs(base, parent, false, "")
        .map_err(|_| refuse("a directory on the way is missing, a link or a file"))?;
    let name = rel.file_name().ok_or_else(|| refuse("it names no file"))?;
    let path = dir.join(name);
    let meta = std::fs::symlink_metadata(&path)?;
    if !meta.file_type().is_file() {
        return Err(refuse("it is not a regular file"));
    }
    open_no_follow(&path)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    #[allow(clippy::cast_possible_wrap)]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "it is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn unsafe_path(what: &str, path: &Path, reason: &'static str) -> AddonError {
    AddonError::UnsafePath {
        what: what.to_owned(),
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    /// A link anywhere above the destination is refused, and nothing is written through it: the
    /// directory the link points at stays empty. This is the case a planted link, or one of wine's
    /// own user folders that point into the home directory, would otherwise turn into a write
    /// outside the prefix.
    #[test]
    fn a_link_on_the_way_is_refused_and_nothing_is_written_through_it() {
        let root = tempfile::tempdir().expect("tempdir");
        let drive_c = root.path().join("drive_c");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(drive_c.join("users/me/AppData")).expect("tree");
        std::fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, drive_c.join("users/me/AppData/Roaming"))
            .expect("link");

        let err = walk_dirs(
            &drive_c,
            Path::new("users/me/AppData/Roaming/Advanced Combat Tracker/Config"),
            true,
            "act",
        )
        .expect_err("the link is refused");
        assert!(matches!(err, AddonError::UnsafePath { .. }), "{err:?}");
        assert_eq!(std::fs::read_dir(&outside).expect("read").count(), 0);

        // A file in the place of a directory is refused too, and a plain path is made.
        std::fs::write(drive_c.join("Apogee"), b"").expect("file");
        assert!(walk_dirs(&drive_c, Path::new("Apogee/ACT"), true, "act").is_err());
        let made = walk_dirs(&drive_c, Path::new("Other/ACT"), true, "act").expect("made");
        assert!(made.is_dir());
    }

    /// A link at the file itself or above it, and anything that is not a regular file, is refused on
    /// the read side as well, so a re-hash cannot be pointed at a file outside the prefix or at a pipe.
    #[test]
    fn a_read_refuses_a_link_and_anything_but_a_regular_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = root.path();
        std::fs::create_dir_all(base.join("a")).expect("dir");
        std::fs::write(base.join("a/real"), b"x").expect("file");
        std::fs::write(base.join("secret"), b"s").expect("file");
        std::os::unix::fs::symlink(base.join("secret"), base.join("a/link")).expect("link");
        std::os::unix::fs::symlink(base.join("a"), base.join("b")).expect("dir link");

        assert!(open_regular(base, Path::new("a/real")).is_ok());
        assert!(open_regular(base, Path::new("a/link")).is_err());
        assert!(open_regular(base, Path::new("b/real")).is_err());
        assert!(open_regular(base, Path::new("a")).is_err());
        assert!(open_regular(base, Path::new("a/missing")).is_err());
    }
}
