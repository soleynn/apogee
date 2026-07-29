//! Where a dat container's bytes come from.
//!
//! A `.dat` is far too large to read whole (a full install's largest is seven gigabytes), so the
//! readers above take random-access byte ranges rather than a buffer. [`FileSource`] is the real
//! one; a `&[u8]` is the same source over an in-memory container, which is what lets the entry
//! readers be exercised by tests and the fuzzer without a file on disk.

use std::fs::File;
use std::path::Path;

use crate::error::{Error, Result};

/// A random-access source of a dat container's bytes.
pub trait DatSource {
    /// The container's total length.
    #[must_use]
    fn len(&self) -> u64;

    /// Read into `buf` starting at `offset`, returning how many bytes were available. A return
    /// shorter than `buf` means the container ended, which callers turn into [`Error::Truncated`].
    ///
    /// # Errors
    /// [`Error::Io`] if the underlying source fails.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize>;

    /// Whether the container is empty.
    #[must_use]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` from `offset`, reporting a short read as a truncation at the byte it stopped on.
    ///
    /// # Errors
    /// - [`Error::Truncated`] if the container ends before `buf` is full.
    /// - [`Error::Io`] if the underlying source fails.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        let want = buf.len();
        let got = self.read_at(buf, offset)?;
        if got != want {
            return Err(Error::Truncated {
                offset: offset.saturating_add(got as u64),
                needed: (want - got) as u64,
            });
        }
        Ok(())
    }
}

impl DatSource for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        let total = <[u8]>::len(self);
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(total);
        let available = &self[start..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

/// A dat container backed by a file, read by absolute offset.
///
/// Positioned reads keep the handle shareable: reads carry their own offset instead of moving a
/// cursor, so one open container answers several threads at once (which is what a whole-install
/// sweep does) without a lock between them. Both platform calls behind it are safe, so the crate
/// keeps `#![forbid(unsafe_code)]`.
#[derive(Debug)]
pub struct FileSource {
    file: File,
    len: u64,
}

impl FileSource {
    /// Open a container read-only and record its length.
    ///
    /// # Errors
    /// [`Error::Io`] if the file cannot be opened or its length cannot be read.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl DatSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        let mut done = 0usize;
        while done < buf.len() {
            // A positioned read is free to come back short of what was asked for even mid-file (a
            // signal, a network filesystem), so a fill loops until the source stops producing.
            let n = read_at(&self.file, &mut buf[done..], offset + done as u64)?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> Result<usize> {
    use std::os::unix::fs::FileExt;
    Ok(file.read_at(buf, offset)?)
}

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> Result<usize> {
    use std::os::windows::fs::FileExt;
    // `seek_read` reads at an explicit offset; the handle's own cursor lands wherever, and nothing
    // here reads it.
    Ok(file.seek_read(buf, offset)?)
}

#[cfg(not(any(unix, windows)))]
compile_error!(
    "apogee-sqpack reads dat containers by absolute offset, which needs unix or windows"
);

/// A `Read` view over one span of a source, so a block can be handed to the codec without first
/// copying it. Reading past `end` is a clean end of stream, which is what turns a block that runs
/// off the end of its region into a truncation rather than a read into the next entry.
pub(crate) struct Window<'a, S: DatSource + ?Sized> {
    source: &'a S,
    pos: u64,
    end: u64,
}

impl<'a, S: DatSource + ?Sized> Window<'a, S> {
    pub(crate) fn new(source: &'a S, start: u64, end: u64) -> Self {
        Self {
            source,
            pos: start,
            end: end.max(start),
        }
    }
}

impl<S: DatSource + ?Sized> std::io::Read for Window<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let room = usize::try_from(self.end - self.pos).unwrap_or(usize::MAX);
        let want = buf.len().min(room);
        if want == 0 {
            return Ok(0);
        }
        let n = self
            .source
            .read_at(&mut buf[..want], self.pos)
            .map_err(|err| match err {
                Error::Io(io) => io,
                other => std::io::Error::other(other.to_string()),
            })?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn a_slice_source_reads_at_an_offset_and_stops_at_the_end() {
        let bytes: &[u8] = b"0123456789";
        let mut buf = [0u8; 4];
        assert_eq!(bytes.read_at(&mut buf, 3).unwrap(), 4);
        assert_eq!(&buf, b"3456");
        // Past the end is zero bytes, not an error: the caller decides whether that is a truncation.
        assert_eq!(bytes.read_at(&mut buf, 99).unwrap(), 0);
        assert_eq!(bytes.read_at(&mut buf, 8).unwrap(), 2);
    }

    #[test]
    fn an_exact_read_off_the_end_reports_where_it_ran_out() {
        let bytes: &[u8] = b"0123456789";
        let mut buf = [0u8; 4];
        match bytes.read_exact_at(&mut buf, 8) {
            Err(Error::Truncated { offset, needed }) => {
                assert_eq!(offset, 10);
                assert_eq!(needed, 2);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn a_file_source_reads_the_same_bytes_a_slice_does() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000000.win32.dat0");
        std::fs::write(&path, b"the quick brown fox").unwrap();
        let source = FileSource::open(&path).unwrap();
        assert_eq!(source.len(), 19);
        assert!(!source.is_empty());
        let mut buf = [0u8; 5];
        source.read_exact_at(&mut buf, 4).unwrap();
        assert_eq!(&buf, b"quick");
        assert!(matches!(
            source.read_exact_at(&mut buf, 17),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn a_window_ends_at_its_own_boundary_rather_than_the_sources() {
        let bytes: &[u8] = b"0123456789";
        let mut window = Window::new(&bytes, 2, 6);
        let mut out = Vec::new();
        window.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"2345");
        // An inverted span is empty rather than a wrapping read.
        let mut window = Window::new(&bytes, 6, 2);
        let mut out = Vec::new();
        window.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }
}
