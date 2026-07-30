#![cfg(target_os = "linux")]
//! Archive extraction: every format, prefix stripping, the exec bit, in-tree symlinks, and rejection
//! of a symlink that escapes the destination. Zip is a component container rather than a runner one,
//! so it is checked against what the tools that build those archives actually emit: `\`-separated
//! names, missing modes, and a symlink smuggled in as a mode bit.

use std::io::{self, Cursor, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apogee_runtime::{ArchiveFormat, ArchiveLayout, RuntimeError, extract_archive};
use zip::write::SimpleFileOptions;

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

/// The loop above compresses with this workspace's own encoder, which is not what a runner is
/// published with. The catalog's wine rows ship an archive written by the standard `xz` tool, whose
/// streams carry a CRC64 integrity check where the in-process encoder writes CRC32, so the container
/// the launcher actually downloads goes through a code path the round-trip never reaches. The fixture
/// is a real one of those, holding the same three entries under the same prefix.
#[test]
fn a_stream_from_the_standard_xz_tool_extracts_like_any_other() {
    let bytes = include_bytes!("fixtures/xz_utils_runner.tar.xz");
    // Byte 7 of the header is the stream's check id; 4 is CRC64.
    assert_eq!(bytes[7] & 0x0f, 4, "the fixture is a CRC64 stream");

    let tmp = tempfile::tempdir().expect("tempdir");
    let archive = tmp.path().join("runner.tar.xz");
    std::fs::write(&archive, bytes).expect("write archive");
    let dest = tmp.path().join("out");
    let layout = ArchiveLayout {
        format: ArchiveFormat::TarXz,
        strip_prefix: Some("runner-1.0".to_owned()),
    };

    let entries = extract_archive(&archive, &layout, &dest).expect("extract");
    // One more than the built-in-process archives above yield for the same tree: a real `tar` writes
    // an entry for `bin/` too, where the builder used here only appends the leaves.
    assert_eq!(entries, 4, "a directory, two files and a symlink extracted");
    assert!(dest.join("bin/wine").is_file());
    assert_eq!(
        std::fs::read(dest.join("share.txt")).expect("read note"),
        b"note\n"
    );
    assert_ne!(
        mode_bits(&dest.join("bin/wine")).expect("wine mode") & 0o111,
        0,
        "wine executable"
    );
    assert_eq!(
        std::fs::read_link(dest.join("bin/wine64")).expect("readlink"),
        Path::new("wine")
    );
    assert!(!dest.join("runner-1.0").exists(), "prefix stripped");
}

/// A zip laid out the way a Windows-built companion archive is: a wrapping top directory, one entry
/// with no mode at all, one marked executable, and a nested path written with backslashes.
fn build_component_zip(top: &str) -> io::Result<Vec<u8>> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let no_mode = SimpleFileOptions::DEFAULT.last_modified_time(zip::DateTime::default());
    writer
        .start_file(format!("{top}/tool.exe"), no_mode)
        .and_then(|()| writer.write_all(b"MZ").map_err(Into::into))
        .map_err(io::Error::other)?;
    writer
        .start_file(
            format!("{top}/bin/launch.sh"),
            no_mode.unix_permissions(0o755),
        )
        .and_then(|()| writer.write_all(b"#!/bin/sh\n").map_err(Into::into))
        .map_err(io::Error::other)?;
    // A `\` in a zip name is out of spec, and Windows tooling emits it anyway. On Linux it is an
    // ordinary character, so it has to be folded or the whole path lands as one filename.
    writer
        .start_file(format!("{top}\\plugins\\overlay.dll"), no_mode)
        .and_then(|()| writer.write_all(b"dll").map_err(Into::into))
        .map_err(io::Error::other)?;
    Ok(writer.finish().map_err(io::Error::other)?.into_inner())
}

/// A zip whose only entry is a symlink out of the tree. A zip marks a link with `S_IFLNK` in the mode
/// bits above the permissions and stores the target as the entry's content, so this is the shape a
/// crafted archive would use to plant one.
fn build_zip_symlink() -> io::Result<Vec<u8>> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_symlink(
            "escape",
            "/etc/passwd",
            SimpleFileOptions::DEFAULT.last_modified_time(zip::DateTime::default()),
        )
        .map_err(io::Error::other)?;
    Ok(writer.finish().map_err(io::Error::other)?.into_inner())
}

fn extract_zip(
    bytes: &[u8],
    strip_prefix: Option<&str>,
) -> io::Result<(tempfile::TempDir, Result<u64, RuntimeError>)> {
    let tmp = tempfile::tempdir()?;
    let archive = tmp.path().join("component.zip");
    std::fs::write(&archive, bytes)?;
    let layout = ArchiveLayout {
        format: ArchiveFormat::Zip,
        strip_prefix: strip_prefix.map(str::to_owned),
    };
    let result = extract_archive(&archive, &layout, &tmp.path().join("out"));
    Ok((tmp, result))
}

#[test]
fn extracts_a_component_zip_stripping_the_prefix() {
    let bytes = build_component_zip("ACT-3.9.0").expect("build zip");
    let (tmp, result) = extract_zip(&bytes, Some("ACT-3.9.0")).expect("stage");
    let dest = tmp.path().join("out");
    assert_eq!(result.expect("extract"), 3);

    assert!(!dest.join("ACT-3.9.0").exists(), "prefix stripped");
    assert_eq!(
        std::fs::read(dest.join("tool.exe")).expect("read exe"),
        b"MZ"
    );
    // The backslash path became a real nested path rather than one long filename.
    assert_eq!(
        std::fs::read(dest.join("plugins/overlay.dll")).expect("read dll"),
        b"dll"
    );

    // A mode the archive did state is kept, which is what a native launcher script needs.
    assert_ne!(
        mode_bits(&dest.join("bin/launch.sh")).expect("mode") & 0o111,
        0,
        "the executable bit survived"
    );
    // A mode the archive did not state still lands readable, rather than as a file nobody can open.
    assert_ne!(
        mode_bits(&dest.join("tool.exe")).expect("mode") & 0o400,
        0,
        "an entry with no mode is still readable"
    );
}

#[test]
fn rejects_a_zip_symlink_entry() {
    let bytes = build_zip_symlink().expect("build zip");
    let (tmp, result) = extract_zip(&bytes, None).expect("stage");
    let err = result.expect_err("a zip symlink must be refused");
    assert!(matches!(err, RuntimeError::Extract { .. }));
    assert!(!tmp.path().join("out/escape").exists(), "nothing landed");
}

#[test]
fn rejects_a_zip_entry_escaping_the_destination() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            r"..\..\etc\passwd",
            SimpleFileOptions::DEFAULT.last_modified_time(zip::DateTime::default()),
        )
        .expect("start");
    writer.write_all(b"pwned").expect("write");
    let bytes = writer.finish().expect("finish").into_inner();

    let (_tmp, result) = extract_zip(&bytes, None).expect("stage");
    assert!(matches!(
        result.expect_err("traversal must reject"),
        RuntimeError::Extract { .. }
    ));
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
