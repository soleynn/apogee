//! Deciding whether an archive entry name may be written at all.
//!
//! Pure and filesystem-free, run over every entry before any syscall. An archive can arrive from
//! anywhere, including from someone who built it by hand, so a name is treated as a claim rather than
//! a path until it has passed all of this.
//!
//! The Windows-shaped rules are here because the destination sits inside a prefix and the program
//! that reads these files is a Windows one. None of `..\..\x`, `C:`, `name:stream`, `CON`, or a
//! trailing space escapes anything at the Linux layer, and every one of them is reinterpreted by the
//! runner or by the game's own config reader.

#![cfg_attr(
    not(unix),
    allow(dead_code, reason = "only the restore path calls this")
)]

use std::path::{Component, Path, PathBuf};

use super::root::RootLabel;

/// Components a name may carry. The real tree is three deep.
const MAX_PATH_DEPTH: usize = 32;
/// Bytes in a whole name.
const MAX_PATH_BYTES: usize = 4096;
/// Bytes in one component, matching the usual filesystem limit.
const MAX_NAME_BYTES: usize = 255;

/// Names Windows reserves regardless of extension.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Why an entry name was refused. Every variant aborts the restore rather than skipping the entry,
/// because a restore that quietly drops entries reports success and returns an incomplete tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// Not a regular file or a directory. Symlinks and device nodes are refused outright: the real
    /// tree contains none, so allowing them buys nothing and admits aliasing into a live directory.
    NotAFileOrDir,
    /// Rooted, so it would land outside the destination.
    Absolute,
    /// Contains a parent reference.
    Traversal,
    /// Carries a drive letter, which is a `Normal` component off Windows and so would otherwise pass.
    DriveLetter,
    /// Resolves to nothing at all.
    Empty,
    /// The leading component is not a root this archive declares.
    UnknownRoot,
    /// Longer than a name may be.
    NameTooLong,
    /// One component is longer than a component may be.
    ComponentTooLong,
    /// Nested deeper than a config tree ever is.
    TooDeep,
    /// A trailing dot or space, an alternate-stream colon, or a reserved device name: all things the
    /// destination reinterprets rather than stores verbatim.
    WindowsHostile,
    /// Two entries that differ only in case, which land on one file on a case-insensitive
    /// destination. A real config archive never contains a pair like this.
    Collision,
    /// Present in the container but absent from the archive's own record.
    NotInRecord,
}

impl std::fmt::Display for RejectReason {
    /// Each reason as the thing that is wrong with the name, so the refusal reads as a sentence rather
    /// than as an identifier. What is refused is attacker-chosen, so the reason is the only part of the
    /// message worth reading.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotAFileOrDir => "it is neither a regular file nor a directory",
            Self::Absolute => "it is rooted, so it would land outside the destination",
            Self::Traversal => "it contains a parent reference",
            Self::DriveLetter => "it carries a drive letter",
            Self::Empty => "it resolves to nothing at all",
            Self::UnknownRoot => "it starts at a root this archive does not declare",
            Self::NameTooLong => "the whole name is too long",
            Self::ComponentTooLong => "one part of the name is too long",
            Self::TooDeep => "it nests deeper than a config tree ever does",
            Self::WindowsHostile => "the destination would reinterpret it rather than store it",
            Self::Collision => "another entry differs from it only in case",
            Self::NotInRecord => "the archive's own record does not list it",
        })
    }
}

/// A name that has passed every check.
#[derive(Debug, Clone)]
pub(crate) struct ConfinedName {
    root: RootLabel,
    relative: PathBuf,
}

impl ConfinedName {
    /// Which root the entry belongs to.
    pub(crate) fn root(&self) -> RootLabel {
        self.root
    }

    /// The path below that root, with the root component removed.
    pub(crate) fn relative(&self) -> &Path {
        &self.relative
    }

    /// The folded key used to detect two entries colliding on a case-insensitive destination.
    pub(crate) fn collision_key(&self) -> String {
        format!("{}/{}", self.root.prefix(), self.relative.to_string_lossy()).to_lowercase()
    }
}

/// Validate one entry name.
///
/// `is_dir` and `is_file` come from the container, so an entry that claims to be neither is refused
/// before its name is even looked at.
pub(crate) fn entry_name(raw: &str, is_regular: bool) -> Result<ConfinedName, RejectReason> {
    if !is_regular {
        return Err(RejectReason::NotAFileOrDir);
    }
    if raw.len() > MAX_PATH_BYTES {
        return Err(RejectReason::NameTooLong);
    }
    if raw.contains('\0') {
        return Err(RejectReason::WindowsHostile);
    }

    // Folded before the component walk, not after: on Linux a backslash is an ordinary character, so
    // `..\..\x` would otherwise survive as one opaque component and pass every check below.
    let folded = raw.replace('\\', "/");

    let mut parts: Vec<String> = Vec::new();
    for component in Path::new(&folded).components() {
        match component {
            Component::CurDir => continue,
            Component::RootDir => return Err(RejectReason::Absolute),
            Component::ParentDir => return Err(RejectReason::Traversal),
            Component::Prefix(_) => return Err(RejectReason::DriveLetter),
            Component::Normal(raw_part) => {
                let part = raw_part.to_string_lossy();
                check_component(&part)?;
                if parts.len() == MAX_PATH_DEPTH {
                    return Err(RejectReason::TooDeep);
                }
                parts.push(part.into_owned());
            }
        }
    }

    let mut parts = parts.into_iter();
    let Some(head) = parts.next() else {
        return Err(RejectReason::Empty);
    };
    let root = label(&head).ok_or(RejectReason::UnknownRoot)?;
    let relative: PathBuf = parts.collect();
    if relative.as_os_str().is_empty() {
        // The root's own directory entry, which carries no content and needs no target.
        return Err(RejectReason::Empty);
    }
    Ok(ConfinedName { root, relative })
}

/// Reject the component shapes the destination would reinterpret rather than store.
fn check_component(part: &str) -> Result<(), RejectReason> {
    if part.len() > MAX_NAME_BYTES {
        return Err(RejectReason::ComponentTooLong);
    }
    if part.len() == 2 && part.ends_with(':') && part.starts_with(|c: char| c.is_ascii_alphabetic())
    {
        return Err(RejectReason::DriveLetter);
    }
    if part.ends_with('.') || part.ends_with(' ') || part.contains(':') {
        return Err(RejectReason::WindowsHostile);
    }
    let stem = part.split_once('.').map_or(part, |(s, _)| s);
    if RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return Err(RejectReason::WindowsHostile);
    }
    Ok(())
}

/// The root a leading component names, folded because the rest of this layer folds.
fn label(head: &str) -> Option<RootLabel> {
    [RootLabel::User, RootLabel::Roaming]
        .into_iter()
        .find(|candidate| head.eq_ignore_ascii_case(candidate.prefix()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &str) -> ConfinedName {
        match entry_name(raw, true) {
            Ok(name) => name,
            Err(reason) => panic!("{raw} should be accepted, got {reason:?}"),
        }
    }

    fn err(raw: &str) -> RejectReason {
        match entry_name(raw, true) {
            Ok(_) => panic!("{raw} should be refused"),
            Err(reason) => reason,
        }
    }

    #[test]
    fn a_normal_entry_keeps_its_root_and_path() {
        let name = ok("user/FFXIV_CHR004000174C116E58/HOTBAR.DAT");
        assert_eq!(name.root(), RootLabel::User);
        assert_eq!(
            name.relative(),
            Path::new("FFXIV_CHR004000174C116E58/HOTBAR.DAT")
        );
    }

    /// The whole point: nothing may resolve outside its root.
    #[test]
    fn nothing_escapes_the_destination() {
        assert_eq!(err("/etc/passwd"), RejectReason::Absolute);
        assert_eq!(err("user/../../etc/passwd"), RejectReason::Traversal);
        assert_eq!(err("../user/FFXIV.cfg"), RejectReason::Traversal);
        assert_eq!(err(""), RejectReason::Empty);
        assert_eq!(err("."), RejectReason::Empty);
    }

    /// A backslash is an ordinary character on Linux, so a name using them would arrive as one
    /// component and sail past a walk that had not folded it first.
    #[test]
    fn a_backslash_path_is_folded_before_it_is_walked() {
        assert_eq!(err(r"user\..\..\etc\passwd"), RejectReason::Traversal);
        let name = ok(r"user\cfgcopy\FFXIV_CFGCPYB4E9C66C1760C0EE.dat");
        assert_eq!(
            name.relative(),
            Path::new("cfgcopy/FFXIV_CFGCPYB4E9C66C1760C0EE.dat")
        );
    }

    /// A drive letter parses as an ordinary component off Windows, so it needs naming explicitly.
    #[test]
    fn a_drive_letter_is_refused_even_though_linux_would_take_it() {
        assert_eq!(
            err(r"C:\windows\system32\evil.dll"),
            RejectReason::DriveLetter
        );
        assert_eq!(err("user/C:/x"), RejectReason::DriveLetter);
    }

    /// The destination is read by a Windows program, so shapes it reinterprets are refused here.
    #[test]
    fn names_the_destination_would_reinterpret_are_refused() {
        assert_eq!(err("user/CON"), RejectReason::WindowsHostile);
        assert_eq!(err("user/nul.dat"), RejectReason::WindowsHostile);
        assert_eq!(err("user/trailing "), RejectReason::WindowsHostile);
        assert_eq!(err("user/trailing."), RejectReason::WindowsHostile);
        assert_eq!(err("user/file.dat:stream"), RejectReason::WindowsHostile);
    }

    /// An entry has to belong to a root this format declares, so a hand-built archive cannot invent
    /// a destination.
    #[test]
    fn an_entry_outside_a_declared_root_is_refused() {
        assert_eq!(err("elsewhere/FFXIV.cfg"), RejectReason::UnknownRoot);
        assert_eq!(err("apogee-backup.json"), RejectReason::UnknownRoot);
        assert_eq!(ok("roaming/dalamudConfig.json").root(), RootLabel::Roaming);
    }

    #[test]
    fn a_symlink_or_device_entry_is_refused_before_its_name_matters() {
        assert_eq!(
            entry_name("user/FFXIV.cfg", false).unwrap_err(),
            RejectReason::NotAFileOrDir
        );
    }

    #[test]
    fn absurd_names_are_refused() {
        assert_eq!(
            err(&format!("user/{}", "a".repeat(256))),
            RejectReason::ComponentTooLong
        );
        assert_eq!(err(&"a/".repeat(3000)), RejectReason::NameTooLong);
        let deep = format!("user/{}x", "d/".repeat(MAX_PATH_DEPTH));
        assert_eq!(err(&deep), RejectReason::TooDeep);
    }

    /// Two entries differing only in case land on one file on a case-insensitive destination, which
    /// a prefix's Windows view and several filesystems both are.
    #[test]
    fn the_collision_key_folds_case() {
        assert_eq!(
            ok("user/FFXIV.cfg").collision_key(),
            ok("USER/ffxiv.CFG").collision_key()
        );
        assert_ne!(
            ok("user/FFXIV.cfg").collision_key(),
            ok("user/FFXIV.cfg.old").collision_key()
        );
    }
}
