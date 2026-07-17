//! Streaming, in-process extraction of runner/tool tarballs.
//!
//! Pure-Rust decoders (`flate2`/`ruzstd`/`lzma-rs`) feed `tar` entry by entry, so peak memory stays
//! bounded by the decoder window, never the tarball size. Every entry is confined to the
//! destination before it is written: an archive comes from the signed catalog, but its bytes are
//! still treated as hostile. Directory components are never traversed through a symlink, so a
//! crafted archive cannot plant a link that redirects a later write outside the tree.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use tar::EntryType;

use crate::catalog::{ArchiveFormat, ArchiveLayout};
use crate::error::RuntimeError;

/// Read/write buffer for the per-entry copy: bigger than the 8 KiB default to cut syscalls on a
/// multi-gigabyte runner without materializing anything.
const COPY_BUF: usize = 256 * 1024;

/// Extract `archive` (a `layout.format` tarball) into `dest`, stripping `layout.strip_prefix` from
/// each entry. Streams to disk without holding the whole tarball in memory. Returns the number of
/// entries written (zero means nothing matched the strip prefix).
///
/// Entries are confined to `dest`: an absolute path, a `..` component, a symlink/hardlink whose
/// target would escape `dest`, or a directory component that is a symlink are all hard errors, never
/// a write outside the tree.
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
    }
}

/// `lzma-rs` is push-model (it writes to a sink), so decode on a helper thread whose output pipes
/// into `tar` on this thread — streaming, with memory bounded by the LZMA dictionary window.
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

/// The result of stripping the prefix from and confining one entry path.
enum Resolved {
    Path(PathBuf),
    Skip,
    Reject,
}

/// Strip `strip_prefix` from `path` and confine the remainder: reject absolute paths, `..`, and
/// filesystem-root/prefix components; skip the prefix directory itself and entries outside it. A
/// leading `./` (the GNU-tar convention) is transparent.
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

/// Create the ancestor directories of `rel` under `dest`, refusing to traverse an existing symlink
/// (or a non-directory). A crafted archive could otherwise plant an in-tree symlink to relocate a
/// later write outside `dest`; refusing traversal keeps every parent a real directory.
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

/// Remove `out` if it is an existing symlink, so a write never follows a symlink planted at the
/// final path component.
fn unlink_if_symlink(out: &Path, archive: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(out) {
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::remove_file(out).map_err(|e| io_err(archive, e))
        }
        _ => Ok(()),
    }
}

/// Lexically decide whether a symlink at `link_path` (relative to `dest`) with `target` stays inside
/// `dest`. No filesystem access is needed: [`safe_make_dirs`] guarantees every parent is a real
/// directory, so the component count is the true on-disk depth.
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

fn io_err(archive: &Path, source: io::Error) -> RuntimeError {
    RuntimeError::Extract {
        archive: archive.to_path_buf(),
        source,
    }
}

fn decode_err(archive: &Path, e: &dyn std::fmt::Display) -> RuntimeError {
    io_err(
        archive,
        io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
    )
}

fn confined(archive: &Path, msg: &'static str) -> RuntimeError {
    io_err(archive, io::Error::new(io::ErrorKind::InvalidData, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(path: &str, strip: Option<&str>) -> Option<PathBuf> {
        match resolve(Path::new(path), strip) {
            Resolved::Path(p) => Some(p),
            Resolved::Skip => None,
            Resolved::Reject => panic!("unexpected reject for {path}"),
        }
    }

    #[test]
    fn resolve_strips_the_prefix() {
        assert_eq!(
            resolved("runner-1.0/bin/wine", Some("runner-1.0")),
            Some(PathBuf::from("bin/wine"))
        );
    }

    #[test]
    fn resolve_is_transparent_to_a_leading_dot_slash() {
        // GNU `tar czf x ./runner-1.0` stores entries as `./runner-1.0/...`.
        assert_eq!(
            resolved("./runner-1.0/bin/wine", Some("runner-1.0")),
            Some(PathBuf::from("bin/wine"))
        );
    }

    #[test]
    fn resolve_skips_the_prefix_dir_and_outsiders() {
        assert_eq!(resolved("runner-1.0", Some("runner-1.0")), None);
        assert_eq!(resolved("runner-1.0/", Some("runner-1.0")), None);
        assert_eq!(resolved("other/thing", Some("runner-1.0")), None);
    }

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
