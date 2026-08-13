//! Streaming, in-process extraction of runner, tool, and component archives.
//!
//! Pure-Rust decoders (`flate2`, `ruzstd`, `lzma-rs`) feed `tar` entry by entry, so peak memory is
//! bounded by the decoder window and never by the archive size. Every entry is confined to the
//! destination before it is written: an archive comes from the signed catalog, but its bytes are
//! still treated as hostile, and no directory component is ever traversed through a symlink, so a
//! crafted archive cannot plant a link that redirects a later write outside the tree.
//!
//! Zip is here for the Windows-side companions, which is all anyone publishes them as. It shares the
//! confinement and differs in the two ways the container forces: entries are addressed through a
//! central directory rather than streamed, and a symlink entry is refused outright rather than
//! recreated, because a zip encodes its target as file content and no companion archive contains one.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use tar::EntryType;

use crate::catalog::{ArchiveFormat, ArchiveLayout};
use crate::error::RuntimeError;

/// Read/write buffer for the per-entry copy.
///
/// Larger than the 8 KiB default, so a multi-gigabyte runner costs fewer syscalls without
/// materializing anything.
const COPY_BUF: usize = 256 * 1024;

/// Extract `archive` into `dest`, stripping `layout.strip_prefix` from every entry.
///
/// Streams to disk and returns the number of entries written; zero means nothing matched the strip
/// prefix. Entries are confined to `dest`: an absolute path, a `..` component, a symlink or hardlink
/// target that does not resolve inside `dest`, a parent component that is an existing symlink or
/// non-directory, and, for zip, a symlink entry at all are refusals rather than a write outside the
/// tree. Entry kinds a runner never contains, such as devices and fifos, are skipped and not counted.
///
/// # Errors
///
/// [`RuntimeError::Extract`] naming `archive`, for every failure. Its source is the raw `io::Error`
/// for a filesystem failure, and an `io::ErrorKind::InvalidData` carrying the reason for a container
/// that will not decode or an entry the confinement refused.
///
/// # Examples
///
/// ```
/// # use std::path::Path;
/// # use apogee_runtime::{ArchiveFormat, ArchiveLayout, RuntimeError, extract_archive};
/// # fn demo(archive: &Path, dest: &Path) -> Result<(), RuntimeError> {
/// let layout = ArchiveLayout {
///     format: ArchiveFormat::TarXz,
///     strip_prefix: Some("UMU-Proton-9-20".to_owned()),
/// };
/// let entries = extract_archive(archive, &layout, dest)?;
/// assert!(entries > 0);
/// # Ok(())
/// # }
/// ```
pub fn extract_archive(
    archive: &Path,
    layout: &ArchiveLayout,
    dest: &Path,
) -> Result<u64, RuntimeError> {
    fs::create_dir_all(dest).map_err(|e| io_err(archive, e))?;
    let file = File::open(archive).map_err(|e| io_err(archive, e))?;
    let reader = BufReader::with_capacity(COPY_BUF, file);
    match layout.format {
        ArchiveFormat::TarGz => {
            let dec = flate2::read::GzDecoder::new(reader);
            unpack(dec, layout.strip_prefix.as_deref(), dest, archive)
        }
        ArchiveFormat::TarZst => {
            let dec = ruzstd::decoding::StreamingDecoder::new(reader)
                .map_err(|e| decode_err(archive, &e))?;
            unpack(dec, layout.strip_prefix.as_deref(), dest, archive)
        }
        ArchiveFormat::TarXz => extract_xz(reader, layout.strip_prefix.as_deref(), dest, archive),
        ArchiveFormat::Zip => unpack_zip(reader, layout.strip_prefix.as_deref(), dest, archive),
    }
}

/// Extract a zip, entry by entry, with the confinement the tar path applies.
///
/// Permissions are the one deliberate divergence; see [`zip_mode`].
fn unpack_zip(
    reader: BufReader<File>,
    strip_prefix: Option<&str>,
    dest: &Path,
    archive: &Path,
) -> Result<u64, RuntimeError> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| decode_err(archive, &e))?;
    let mut count = 0u64;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|e| decode_err(archive, &e))?;
        // A zip name is specified to use `/`, so a `\` in one is either Windows tooling being loose
        // or someone hand-building an escape. Folded before the walk either way: on Linux a backslash
        // is an ordinary character, so `..\..\x` would otherwise survive as one opaque component.
        let raw = PathBuf::from(entry.name().replace('\\', "/"));
        let rel = match resolve(&raw, strip_prefix) {
            Resolved::Path(p) => p,
            Resolved::Skip => continue,
            Resolved::Reject => {
                return Err(confined(
                    archive,
                    "entry path escapes the component directory",
                ));
            }
        };
        // Checked before the directory test, because a symlink entry can carry a directory's name.
        if entry.is_symlink() {
            return Err(confined(archive, "zip symlink entries are not extracted"));
        }
        let out = dest.join(&rel);
        safe_make_dirs(dest, &rel, archive)?;

        if entry.is_dir() {
            unlink_if_symlink(&out, archive)?;
            fs::create_dir_all(&out).map_err(|e| io_err(archive, e))?;
        } else {
            unlink_if_symlink(&out, archive)?;
            let file = File::create(&out).map_err(|e| io_err(archive, e))?;
            let mut sink = BufWriter::with_capacity(COPY_BUF, file);
            io::copy(&mut entry, &mut sink).map_err(|e| io_err(archive, e))?;
            sink.flush().map_err(|e| io_err(archive, e))?;
            fs::set_permissions(
                &out,
                fs::Permissions::from_mode(zip_mode(entry.unix_mode())),
            )
            .map_err(|e| io_err(archive, e))?;
        }
        count += 1;
    }
    Ok(count)
}

/// The mode to write for a zip entry, given whatever the container claimed.
///
/// A tarball is built on Unix and its modes are meaningful, so the tar path takes them as they are.
/// A zip's are not dependable: an entry may carry no external attributes at all, and one written by
/// Windows tooling gets a mode synthesised from the MS-DOS attribute bits, which is a
/// plausible-looking number rather than an intended one. So the low nine bits are kept where there
/// are any, the owner's read and write are forced on so an install is never left unreadable, and an
/// entry with nothing usable gets the ordinary file default.
fn zip_mode(claimed: Option<u32>) -> u32 {
    match claimed.map(|mode| mode & 0o777).filter(|mode| *mode != 0) {
        Some(mode) => mode | 0o600,
        None => 0o644,
    }
}

/// Extract an xz tarball, decoding on a helper thread.
///
/// `lzma-rs` is push-model (it writes to a sink), so the decode runs on its own thread and pipes into
/// the `tar` reader on this one. That keeps the extraction streaming, with memory bounded by the LZMA
/// dictionary window.
fn extract_xz(
    mut reader: BufReader<File>,
    strip_prefix: Option<&str>,
    dest: &Path,
    archive: &Path,
) -> Result<u64, RuntimeError> {
    let (pipe_reader, mut pipe_writer) = io::pipe().map_err(|e| io_err(archive, e))?;
    let decoder = std::thread::spawn(move || -> io::Result<()> {
        let result = lzma_rs::xz_decompress(&mut reader, &mut pipe_writer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        // Drop the writer so the reader always reaches EOF, even on a decode error.
        drop(pipe_writer);
        result
    });

    // `unpack` drains its reader to EOF, so the decoder thread can finish writing and exit cleanly.
    let unpacked = unpack(pipe_reader, strip_prefix, dest, archive);

    let decoded = decoder
        .join()
        .map_err(|_| io_err(archive, io::Error::other("xz decoder thread panicked")))?;
    // Prefer the tar-side error: if unpacking failed it dropped the reader, which is what made the
    // decoder see a broken pipe.
    let count = unpacked?;
    decoded.map_err(|e| io_err(archive, e))?;
    Ok(count)
}

/// Unpack the tar stream in `reader` into `dest`, confining every entry, and count what was written.
///
/// Drains `reader` to EOF on the way out so an upstream streaming decoder finishes rather than dying
/// on a broken pipe.
fn unpack<R: Read>(
    reader: R,
    strip_prefix: Option<&str>,
    dest: &Path,
    archive: &Path,
) -> Result<u64, RuntimeError> {
    let mut ar = tar::Archive::new(reader);
    let mut count = 0u64;
    for entry in ar.entries().map_err(|e| io_err(archive, e))? {
        let mut entry = entry.map_err(|e| io_err(archive, e))?;
        let raw = entry.path().map_err(|e| io_err(archive, e))?.into_owned();
        let rel = match resolve(&raw, strip_prefix) {
            Resolved::Path(p) => p,
            Resolved::Skip => continue,
            Resolved::Reject => {
                return Err(confined(archive, "entry path escapes the runner directory"));
            }
        };
        let out = dest.join(&rel);
        // Create every parent as a real directory, refusing to traverse a symlinked component. This
        // guarantees `out`'s parents are real dirs, which is what makes `symlink_within_dest`'s
        // lexical depth accounting exact.
        safe_make_dirs(dest, &rel, archive)?;

        let kind = entry.header().entry_type();
        if kind.is_dir() {
            unlink_if_symlink(&out, archive)?;
            fs::create_dir_all(&out).map_err(|e| io_err(archive, e))?;
        } else if kind.is_symlink() {
            let link = link_target(&mut entry, archive)?;
            if !symlink_within_dest(&rel, &link) {
                return Err(confined(
                    archive,
                    "symlink target escapes the runner directory",
                ));
            }
            let _ = fs::remove_file(&out);
            std::os::unix::fs::symlink(&link, &out).map_err(|e| io_err(archive, e))?;
        } else if kind == EntryType::Link {
            // A hardlink references another already-extracted entry by its in-archive path.
            let link = link_target(&mut entry, archive)?;
            let target_rel = match resolve(&link, strip_prefix) {
                Resolved::Path(p) => p,
                Resolved::Skip | Resolved::Reject => {
                    return Err(confined(
                        archive,
                        "hardlink target escapes the runner directory",
                    ));
                }
            };
            let _ = fs::remove_file(&out);
            fs::hard_link(dest.join(target_rel), &out).map_err(|e| io_err(archive, e))?;
        } else if kind.is_file() {
            // Never write through a symlink planted at the final component.
            unlink_if_symlink(&out, archive)?;
            let file = File::create(&out).map_err(|e| io_err(archive, e))?;
            let mut sink = BufWriter::with_capacity(COPY_BUF, file);
            io::copy(&mut entry, &mut sink).map_err(|e| io_err(archive, e))?;
            sink.flush().map_err(|e| io_err(archive, e))?;
            let mode = entry.header().mode().unwrap_or(0o644) & 0o777; // drop suid/sgid/sticky
            fs::set_permissions(&out, fs::Permissions::from_mode(mode))
                .map_err(|e| io_err(archive, e))?;
        } else {
            // Other entry kinds (device/fifo/…) are not part of a runner; skip them.
            continue;
        }
        count += 1;
    }

    // Drain trailing bytes so an upstream streaming decoder finishes and exits without a broken pipe.
    let mut inner = ar.into_inner();
    io::copy(&mut inner, &mut io::sink()).map_err(|e| io_err(archive, e))?;
    Ok(count)
}

/// The result of stripping the prefix from one entry path and confining what is left.
enum Resolved {
    /// The confined path, relative to the destination.
    Path(PathBuf),
    /// The entry is outside the strip prefix, or is the prefix directory itself.
    Skip,
    /// The entry would have escaped the destination.
    Reject,
}

/// Strip `strip_prefix` from `path` and confine the remainder.
///
/// Rejects a root, `..`, or filesystem-prefix component; skips the prefix directory itself and any
/// entry outside it. A leading `./`, the GNU-tar convention, is transparent.
fn resolve(path: &Path, strip_prefix: Option<&str>) -> Resolved {
    let mut comps = path.components().peekable();
    while matches!(comps.peek(), Some(Component::CurDir)) {
        comps.next();
    }
    if let Some(prefix) = strip_prefix {
        match comps.next() {
            Some(Component::Normal(c)) if c == std::ffi::OsStr::new(prefix) => {}
            _ => return Resolved::Skip,
        }
    }
    let mut out = PathBuf::new();
    for comp in comps {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Resolved::Reject;
            }
        }
    }
    if out.as_os_str().is_empty() {
        Resolved::Skip
    } else {
        Resolved::Path(out)
    }
}

/// Create the ancestor directories of `rel` under `dest`, refusing to traverse an existing symlink.
///
/// A crafted archive could otherwise plant an in-tree symlink and relocate a later write outside
/// `dest`. Refusing traversal keeps every parent a real directory, which is also what makes
/// [`symlink_within_dest`]'s lexical depth accounting exact.
///
/// # Errors
///
/// [`RuntimeError::Extract`] if a component exists and is not a directory, or if creating one fails.
fn safe_make_dirs(dest: &Path, rel: &Path, archive: &Path) -> Result<(), RuntimeError> {
    let Some(parent) = rel.parent() else {
        return Ok(());
    };
    let mut cur = dest.to_path_buf();
    for comp in parent.components() {
        // `resolve` guarantees only Normal components survive.
        cur.push(comp.as_os_str());
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(confined(
                    archive,
                    "archive entry traverses a symlink or non-directory",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur).map_err(|e| io_err(archive, e))?;
            }
            Err(e) => return Err(io_err(archive, e)),
        }
    }
    Ok(())
}

/// Remove `out` if it is an existing symlink.
///
/// So a write never follows a link planted at the final path component.
///
/// # Errors
///
/// [`RuntimeError::Extract`] if the link is there and cannot be removed.
fn unlink_if_symlink(out: &Path, archive: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(out) {
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::remove_file(out).map_err(|e| io_err(archive, e))
        }
        _ => Ok(()),
    }
}

/// Decide lexically whether a symlink at `link_path` with `target` stays inside the destination.
///
/// No filesystem access is needed: [`safe_make_dirs`] guarantees every parent is a real directory, so
/// the component count is the true on-disk depth. That also means this alone does not settle
/// confinement, since it accepts an in-tree link such as `a/b` pointing at `..`; what stops a later
/// entry from traversing that link is [`safe_make_dirs`].
fn symlink_within_dest(link_path: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    // Depth of the symlink's own directory below dest.
    let mut depth = link_path.components().count().saturating_sub(1) as isize;
    for comp in target.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// The target a symlink or hardlink entry names.
///
/// # Errors
///
/// [`RuntimeError::Extract`] if the header is unreadable or the entry carries no target at all.
fn link_target(
    entry: &mut tar::Entry<'_, impl Read>,
    archive: &Path,
) -> Result<PathBuf, RuntimeError> {
    entry
        .link_name()
        .map_err(|e| io_err(archive, e))?
        .map(|c| c.into_owned())
        .ok_or_else(|| confined(archive, "link entry without a target"))
}

/// The single build site for this module's failures: every one names `archive`.
fn io_err(archive: &Path, source: io::Error) -> RuntimeError {
    RuntimeError::Extract {
        archive: archive.to_path_buf(),
        source,
    }
}

/// A container that would not decode, as an `InvalidData` error carrying the decoder's own message.
fn decode_err(archive: &Path, e: &dyn std::fmt::Display) -> RuntimeError {
    io_err(
        archive,
        io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
    )
}

/// A refused entry, as an `InvalidData` error carrying which confinement rule it broke.
fn confined(archive: &Path, msg: &'static str) -> RuntimeError {
    io_err(archive, io::Error::new(io::ErrorKind::InvalidData, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`resolve`] as a two-state answer, for the cases about stripping rather than confinement.
    ///
    /// A reject here is the test itself being wrong, so it panics.
    fn resolved(path: &str, strip: Option<&str>) -> Option<PathBuf> {
        match resolve(Path::new(path), strip) {
            Resolved::Path(p) => Some(p),
            Resolved::Skip => None,
            Resolved::Reject => panic!("unexpected reject for {path}"),
        }
    }

    /// The versioned top directory an upstream tarball wraps its content in is removed.
    #[test]
    fn resolve_strips_the_prefix() {
        assert_eq!(
            resolved("runner-1.0/bin/wine", Some("runner-1.0")),
            Some(PathBuf::from("bin/wine"))
        );
    }

    /// A leading `./` does not shift the strip prefix onto the second component.
    ///
    /// So a tarball built the GNU way strips the same as one built without it.
    #[test]
    fn resolve_is_transparent_to_a_leading_dot_slash() {
        // GNU `tar czf x ./runner-1.0` stores entries as `./runner-1.0/...`.
        assert_eq!(
            resolved("./runner-1.0/bin/wine", Some("runner-1.0")),
            Some(PathBuf::from("bin/wine"))
        );
    }

    /// The prefix directory itself yields nothing to write, and neither does an outsider.
    ///
    /// A second top-level directory is a tarball's business, not an escape, so it is skipped rather
    /// than refused.
    #[test]
    fn resolve_skips_the_prefix_dir_and_outsiders() {
        assert_eq!(resolved("runner-1.0", Some("runner-1.0")), None);
        assert_eq!(resolved("runner-1.0/", Some("runner-1.0")), None);
        assert_eq!(resolved("other/thing", Some("runner-1.0")), None);
    }

    /// The three escapes an entry path can spell are refusals, never skips.
    ///
    /// A leading `..`, one buried after the strip prefix, and an absolute path.
    #[test]
    fn resolve_rejects_traversal_and_absolute() {
        assert!(matches!(
            resolve(Path::new("../escape"), None),
            Resolved::Reject
        ));
        assert!(matches!(
            resolve(Path::new("runner/../../escape"), Some("runner")),
            Resolved::Reject
        ));
        assert!(matches!(
            resolve(Path::new("/etc/passwd"), None),
            Resolved::Reject
        ));
    }

    /// A symlink target is judged against the link's own depth below the destination.
    ///
    /// So `../c.so` from two levels down stays inside while the same walk from one level down does
    /// not. An absolute target is refused whatever its depth.
    #[test]
    fn symlink_confinement() {
        assert!(symlink_within_dest(
            Path::new("lib/libfoo.so"),
            Path::new("libfoo.so.1")
        ));
        assert!(symlink_within_dest(
            Path::new("lib/a/b.so"),
            Path::new("../c.so")
        ));
        assert!(!symlink_within_dest(
            Path::new("bin/x"),
            Path::new("../../etc/passwd")
        ));
        assert!(!symlink_within_dest(
            Path::new("bin/x"),
            Path::new("/etc/passwd")
        ));
    }

    /// A zip entry with no usable mode still lands readable.
    ///
    /// A zip built by Windows tooling routinely carries no mode, or a mode of zero, and taking either
    /// verbatim lands an install the launcher cannot read back.
    #[test]
    fn a_zip_entry_without_a_usable_mode_still_lands_readable() {
        assert_eq!(zip_mode(None), 0o644);
        assert_eq!(zip_mode(Some(0)), 0o644);
        // A real mode is kept, including the executable bit a native launcher script needs.
        assert_eq!(zip_mode(Some(0o755)), 0o755);
        // Owner read/write is forced, so a read-only entry is still replaceable by a reinstall.
        assert_eq!(zip_mode(Some(0o444)), 0o644);
        // The file-type and setuid/setgid/sticky bits above the low nine are dropped.
        assert_eq!(zip_mode(Some(0o104755)), 0o755);
    }

    /// An in-tree symlink is never walked through, even one [`symlink_within_dest`] accepts.
    ///
    /// A link `a/b` pointing at `..` passes the lexical check on its own, so this is the half of the
    /// confinement only the directory walk covers.
    #[test]
    fn safe_make_dirs_refuses_to_traverse_a_symlinked_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path();
        // Plant an in-tree symlink `a/b` -> `..` (which `symlink_within_dest` accepts on its own).
        fs::create_dir_all(dest.join("a")).expect("mkdir a");
        std::os::unix::fs::symlink("..", dest.join("a/b")).expect("symlink");
        // A later entry under `a/b/...` must be refused, not followed.
        let err = safe_make_dirs(dest, Path::new("a/b/c/file"), Path::new("archive.tar"))
            .expect_err("must reject");
        assert!(matches!(err, RuntimeError::Extract { .. }));
    }
}
