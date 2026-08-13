//! Streaming, in-process extraction of runner, tool, and component archives.
//!
//! Pure-Rust decoders (`flate2`, `ruzstd`, `lzma-rs`) feed `tar` entry by entry, so peak memory is
//! bounded by the decoder window and never by the archive size. Every entry is confined to the
//! destination before it is written: an archive comes from the signed catalog, but its bytes are
//! still treated as hostile. No symlink is ever traversed: an entry's own parent components are
//! created as real directories, a link target is resolved against the tree as it stands rather than
//! counted, and a hardlink target has to be a regular file already below the destination. A crafted
//! archive therefore cannot plant a link that redirects a later write out of the tree.
//!
//! Zip is here for the Windows-side companions, which is all anyone publishes them as. It shares the
//! confinement and differs in the three ways the container forces: entries are addressed through a
//! central directory rather than streamed, a symlink entry is refused outright rather than recreated
//! (a zip encodes its target as file content and no companion archive contains one), and a mode is
//! synthesized rather than read, because Windows tooling writes attribute bits instead.

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
/// prefix. Entries are confined to `dest`: an absolute path, a `..` component that leaves the tree, a
/// parent component that is an existing symlink or non-directory, a symlink target that resolves
/// outside the tree, a hardlink target that is not a regular file already inside it, and, for zip,
/// a symlink entry at all are refusals rather than a write outside the tree. Entry kinds a runner
/// never contains, such as devices and fifos, are skipped and not counted.
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
///     format: ArchiveFormat::TarGz,
///     strip_prefix: Some("wine-xiv-staging-fsync-git-8.5.r4.g4211bac7".to_owned()),
/// };
/// let entries = extract_archive(archive, &layout, dest)?;
/// // Zero is not an error: it means nothing in the archive matched the strip prefix.
/// # let _ = entries;
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
        // Create every parent as a real directory, refusing to traverse a symlinked component, so
        // `out` is where its path says it is however the entry before it left the tree.
        safe_make_dirs(dest, &rel, archive)?;

        let kind = entry.header().entry_type();
        if kind.is_dir() {
            unlink_if_symlink(&out, archive)?;
            fs::create_dir_all(&out).map_err(|e| io_err(archive, e))?;
        } else if kind.is_symlink() {
            let link = link_target(&mut entry, archive)?;
            if !symlink_within_dest(dest, &rel, &link) {
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
            let source = hardlink_source(dest, &target_rel, archive)?;
            let _ = fs::remove_file(&out);
            fs::hard_link(source, &out).map_err(|e| io_err(archive, e))?;
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
/// `dest`. Refusing traversal keeps every parent a real directory, which is also the invariant
/// [`symlink_within_dest`] walks the link's own path against.
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

/// How many symlinks one target may resolve through, matching the kernel's own `SYMLOOP_MAX`. What
/// this actually stops is a cycle, which a crafted archive can write in two entries.
const MAX_LINK_HOPS: u32 = 40;

/// Decide whether a symlink at `link_path` with `target` resolves inside `dest`.
///
/// Counting components is not enough. Component counting is exact for the link's own path, which
/// [`safe_make_dirs`] has already made all real directories, but not for the target's, where a
/// component may be a symlink an earlier entry planted, and the kernel would follow it. So the target
/// is resolved against the tree as it stands, expanding each component that is already a link.
fn symlink_within_dest(dest: &Path, link_path: &Path, target: &Path) -> bool {
    let mut cur = dest.to_path_buf();
    let mut depth = 0usize;
    let mut hops = MAX_LINK_HOPS;
    // From the link's own directory, which is where a relative target starts.
    let parent = link_path.parent().unwrap_or(Path::new(""));
    resolve_within(parent, &mut cur, &mut depth, &mut hops)
        && resolve_within(target, &mut cur, &mut depth, &mut hops)
}

/// Walk `path`'s components from `cur`, following any that is already a symlink, and leave `cur` and
/// `depth` at what the kernel would arrive at. False as soon as the walk would leave `dest`.
///
/// `depth` is the number of components below `dest`, so a `..` at zero is an escape and is the only
/// thing that can pop `cur` past the destination.
fn resolve_within(path: &Path, cur: &mut PathBuf, depth: &mut usize, hops: &mut u32) -> bool {
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if *depth == 0 {
                    return false;
                }
                cur.pop();
                *depth -= 1;
            }
            Component::Normal(c) => {
                cur.push(c);
                *depth += 1;
                // A component that is not a link, or is not there at all, is walked as itself: only an
                // existing link redirects, and only an existing one can be followed later.
                let is_link =
                    fs::symlink_metadata(&*cur).is_ok_and(|meta| meta.file_type().is_symlink());
                if is_link {
                    let Ok(next) = fs::read_link(&*cur) else {
                        return false;
                    };
                    if *hops == 0 {
                        return false;
                    }
                    *hops -= 1;
                    // Step back to the link's own directory, which its target is relative to.
                    cur.pop();
                    *depth -= 1;
                    if !resolve_within(&next, cur, depth, hops) {
                        return false;
                    }
                }
            }
            // An absolute target is outside by definition: `dest` is where a relative walk starts.
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// Resolve a hardlink entry's target to the file it names under `dest`, refusing to traverse a
/// symlink.
///
/// [`fs::hard_link`] does not follow a link at the final component, but the kernel follows one at any
/// component before it, and `dest.join(target)` alone cannot see that. So every component is checked:
/// the parents must already be real directories and the target itself a regular file. That is all a
/// hardlink in a tarball ever names, because it is a second name for a member the archive already
/// wrote. Anything else is crafted.
///
/// # Errors
///
/// [`RuntimeError::Extract`] if a component is a symlink, is missing, or is not the kind of file it
/// has to be.
fn hardlink_source(
    dest: &Path,
    target_rel: &Path,
    archive: &Path,
) -> Result<PathBuf, RuntimeError> {
    let mut cur = dest.to_path_buf();
    let last = target_rel.components().count().saturating_sub(1);
    for (index, comp) in target_rel.components().enumerate() {
        // `resolve` guarantees only Normal components survive.
        cur.push(comp.as_os_str());
        // `symlink_metadata` reports a symlink as neither a file nor a directory, so a planted link is
        // refused at whichever position it sits in.
        let last_component = index == last;
        let wrong_kind = if last_component {
            "hardlink target is not a regular file in the runner directory"
        } else {
            "hardlink target is reached through a symlink or a non-directory"
        };
        match fs::symlink_metadata(&cur) {
            Ok(meta) if last_component && meta.is_file() => {}
            Ok(meta) if !last_component && meta.is_dir() => {}
            Ok(_) => return Err(confined(archive, wrong_kind)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(confined(
                    archive,
                    "hardlink target is not present in the runner directory",
                ));
            }
            Err(e) => return Err(io_err(archive, e)),
        }
    }
    Ok(cur)
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
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path();
        assert!(symlink_within_dest(
            dest,
            Path::new("lib/libfoo.so"),
            Path::new("libfoo.so.1")
        ));
        assert!(symlink_within_dest(
            dest,
            Path::new("lib/a/b.so"),
            Path::new("../c.so")
        ));
        assert!(!symlink_within_dest(
            dest,
            Path::new("bin/x"),
            Path::new("../../etc/passwd")
        ));
        assert!(!symlink_within_dest(
            dest,
            Path::new("bin/x"),
            Path::new("/etc/passwd")
        ));
    }

    /// A target's own components are followed the way the kernel would follow them, so the depth a
    /// count arrives at is not what settles this.
    #[test]
    fn symlink_confinement_follows_a_planted_link_in_the_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path();
        // `a/b` -> `..` lands back on the destination, which is inside it, so it is allowed.
        fs::create_dir_all(dest.join("a")).expect("mkdir a");
        std::os::unix::fs::symlink("..", dest.join("a/b")).expect("symlink");
        assert!(symlink_within_dest(dest, Path::new("a/b"), Path::new("..")));
        // Routed through it, `a/b/..` is the destination's own parent, which a count reads as depth 1.
        assert!(!symlink_within_dest(
            dest,
            Path::new("x"),
            Path::new("a/b/..")
        ));
        // A link that resolves back inside is still fine, however many hops it takes.
        std::os::unix::fs::symlink("a", dest.join("also_a")).expect("symlink");
        assert!(symlink_within_dest(
            dest,
            Path::new("x"),
            Path::new("also_a/../a/thing")
        ));
    }

    /// Two links pointing at each other resolve forever, so the walk gives up rather than hangs.
    #[test]
    fn symlink_confinement_gives_up_on_a_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path();
        std::os::unix::fs::symlink("loop_b", dest.join("loop_a")).expect("symlink");
        std::os::unix::fs::symlink("loop_a", dest.join("loop_b")).expect("symlink");
        assert!(!symlink_within_dest(
            dest,
            Path::new("x"),
            Path::new("loop_a/thing")
        ));
    }

    #[test]
    fn hardlink_source_refuses_anything_but_an_extracted_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path();
        let archive = Path::new("archive.tar");
        fs::create_dir_all(dest.join("bin")).expect("mkdir bin");
        fs::write(dest.join("bin/wine"), b"#!/bin/sh\n").expect("write");
        // The ordinary case: an earlier member, reached through real directories.
        assert_eq!(
            hardlink_source(dest, Path::new("bin/wine"), archive).expect("real member"),
            dest.join("bin/wine")
        );
        // A symlinked component is refused rather than followed, which is the escape itself: `x`
        // resolves above the destination, so the kernel would link an inode outside it.
        std::os::unix::fs::symlink("..", dest.join("x")).expect("symlink");
        assert!(hardlink_source(dest, Path::new("x/outside.txt"), archive).is_err());
        // A symlink at the target itself, a directory, and a member no entry wrote are all refused.
        std::os::unix::fs::symlink("bin/wine", dest.join("wine64")).expect("symlink");
        assert!(hardlink_source(dest, Path::new("wine64"), archive).is_err());
        assert!(hardlink_source(dest, Path::new("bin"), archive).is_err());
        assert!(hardlink_source(dest, Path::new("bin/absent"), archive).is_err());
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
    /// A link `a/b` pointing at `..` lands back on the destination, so it is allowed to exist. What
    /// stops it being used is this walk, and only this walk.
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
