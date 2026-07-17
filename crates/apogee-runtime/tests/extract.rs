#![cfg(target_os = "linux")]
//! Runner-tarball extraction: every archive format, prefix stripping, the exec bit, in-tree
//! symlinks, and rejection of a symlink that escapes the destination.

use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apogee_runtime::{ArchiveFormat, ArchiveLayout, RuntimeError, extract_archive};

/// A small runner tree under `top/`: an executable, a nested data file, and an in-tree symlink.
fn build_archive(top: &str, format: ArchiveFormat) -> io::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    add_file(
        &mut builder,
        &format!("{top}/bin/wine"),
        b"#!/bin/sh\n",
        0o755,
    )?;
    add_file(
        &mut builder,
        &format!("{top}/share/note.txt"),
        b"hello",
        0o644,
    )?;
    add_symlink(&mut builder, &format!("{top}/bin/wine64"), "wine")?;
    let tar = builder.into_inner()?;
    compress(&tar, format)
}

/// A single symlink whose target climbs out of the destination directory.
fn build_escaping_symlink_archive() -> io::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    add_symlink(&mut builder, "escape", "../../../../etc/passwd")?;
    let tar = builder.into_inner()?;
    compress(&tar, ArchiveFormat::TarGz)
}

/// The core of the symlink depth-inflation escape: an in-tree symlink `a/b` -> `..` (which the
/// lexical check accepts on its own) followed by a write under it. The extractor must refuse to
/// traverse the planted symlink rather than follow it out of the tree.
fn build_symlink_traversal_archive() -> io::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    add_symlink(&mut builder, "a/b", "..")?;
    add_file(&mut builder, "a/b/escape", b"pwned", 0o644)?;
    let tar = builder.into_inner()?;
    compress(&tar, ArchiveFormat::TarGz)
}

fn add_file(
    builder: &mut tar::Builder<Vec<u8>>,
    path: &str,
    data: &[u8],
    mode: u32,
) -> io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_entry_type(tar::EntryType::Regular);
    builder.append_data(&mut header, path, data)
}

fn add_symlink(builder: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) -> io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    builder.append_link(&mut header, path, target)
}

fn compress(tar: &[u8], format: ArchiveFormat) -> io::Result<Vec<u8>> {
    match format {
        ArchiveFormat::TarGz => {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(tar)?;
            enc.finish()
        }
        ArchiveFormat::TarXz => {
            let mut out = Vec::new();
            let mut src = tar;
            lzma_rs::xz_compress(&mut src, &mut out)?;
            Ok(out)
        }
        ArchiveFormat::TarZst => Ok(ruzstd::encoding::compress_to_vec(
            tar,
            ruzstd::encoding::CompressionLevel::Fastest,
        )),
        _ => Err(io::Error::other("unhandled archive format")),
    }
}

fn mode_bits(path: &Path) -> io::Result<u32> {
    Ok(std::fs::metadata(path)?.permissions().mode())
}

#[test]
fn extracts_each_format_stripping_the_prefix() {
    for format in [
        ArchiveFormat::TarGz,
        ArchiveFormat::TarXz,
        ArchiveFormat::TarZst,
    ] {
        let bytes = build_archive("runner-1.0", format).expect("build archive");
        let tmp = tempfile::tempdir().expect("tempdir");
        let archive = tmp.path().join("runner.tar");
        std::fs::write(&archive, &bytes).expect("write archive");
        let dest = tmp.path().join("out");
        let layout = ArchiveLayout {
            format,
            strip_prefix: Some("runner-1.0".to_owned()),
        };

        let entries = extract_archive(&archive, &layout, &dest).expect("extract");
        assert_eq!(entries, 3, "{format:?}: two files and a symlink extracted");

        assert!(dest.join("bin/wine").is_file(), "{format:?}: wine present");
        assert_eq!(
            std::fs::read(dest.join("share/note.txt")).expect("read note"),
            b"hello",
            "{format:?}: content"
        );
        assert!(
            !dest.join("runner-1.0").exists(),
            "{format:?}: prefix stripped"
        );
        assert_ne!(
            mode_bits(&dest.join("bin/wine")).expect("wine mode") & 0o111,
            0,
            "{format:?}: wine executable"
        );
        assert_eq!(
            mode_bits(&dest.join("share/note.txt")).expect("note mode") & 0o111,
            0,
            "{format:?}: note not executable"
        );
        let link = dest.join("bin/wine64");
        assert!(
            link.symlink_metadata()
                .expect("symlink meta")
                .file_type()
                .is_symlink(),
            "{format:?}: symlink created"
        );
        assert_eq!(
            std::fs::read_link(&link).expect("readlink"),
            Path::new("wine"),
            "{format:?}: symlink target"
        );
    }
}

#[test]
fn rejects_a_symlink_escaping_the_destination() {
    let bytes = build_escaping_symlink_archive().expect("build archive");
    let tmp = tempfile::tempdir().expect("tempdir");
    let archive = tmp.path().join("evil.tar.gz");
    std::fs::write(&archive, &bytes).expect("write archive");
    let dest = tmp.path().join("out");
    let layout = ArchiveLayout {
        format: ArchiveFormat::TarGz,
        strip_prefix: None,
    };

    let err = extract_archive(&archive, &layout, &dest).expect_err("escaping symlink must reject");
    assert!(matches!(err, RuntimeError::Extract { .. }));
    assert!(!dest.join("escape").exists(), "nothing escaped");
}

#[test]
fn refuses_to_write_through_a_symlinked_parent() {
    let bytes = build_symlink_traversal_archive().expect("build archive");
    let tmp = tempfile::tempdir().expect("tempdir");
    let archive = tmp.path().join("evil.tar.gz");
    std::fs::write(&archive, &bytes).expect("write archive");
    let dest = tmp.path().join("out");
    let layout = ArchiveLayout {
        format: ArchiveFormat::TarGz,
        strip_prefix: None,
    };

    let err = extract_archive(&archive, &layout, &dest).expect_err("traversal must reject");
    assert!(matches!(err, RuntimeError::Extract { .. }));
    // The write never happened: nothing landed at dest/ or through the planted link.
    assert!(
        !dest.join("escape").exists(),
        "no write through the symlink"
    );
}
