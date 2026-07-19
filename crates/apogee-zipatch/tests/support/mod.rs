//! Shared helpers for the apply integration tests: a patch byte builder, SqPack block builders, and
//! two sinks (an in-memory applier and a call recorder). Lives in a `tests/` subdirectory so it is a
//! plain module, not its own test binary.
//!
//! Each test binary pulls in the whole module but uses only part of it, so unused-item warnings are
//! expected and silenced here. The fixture encoders and mock sinks operate on in-memory buffers that
//! cannot fail in practice, so they assert rather than thread a `Result` through every call site.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use apogee_zipatch::{DataSource, Error, KeepFilter, MAGIC, PatchSink, SafePath, TargetPath};

/// Builds ZiPatch bytes chunk by chunk, framing each `[u32be size][4-char type][payload][u32be crc]`
/// exactly as the container does; SQPK chunks get the `innerSize`/command prefix.
#[derive(Default)]
pub struct PatchBuilder {
    body: Vec<u8>,
}

impl PatchBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn chunk(&mut self, fourcc: &[u8; 4], payload: &[u8]) -> &mut Self {
        self.body
            .extend_from_slice(&(payload.len() as u32).to_be_bytes());
        self.body.extend_from_slice(fourcc);
        self.body.extend_from_slice(payload);
        let mut crc_input = fourcc.to_vec();
        crc_input.extend_from_slice(payload);
        let crc = crc32fast::hash(&crc_input);
        self.body.extend_from_slice(&crc.to_be_bytes());
        self
    }

    /// Frame a SQPK chunk: `innerSize` (== payload len) + 1-char command + command payload.
    pub fn sqpk(&mut self, command: u8, cmd_payload: &[u8]) -> &mut Self {
        let inner_len = (4 + 1 + cmd_payload.len()) as u32;
        let mut payload = Vec::new();
        payload.extend_from_slice(&inner_len.to_be_bytes());
        payload.push(command);
        payload.extend_from_slice(cmd_payload);
        self.chunk(b"SQPK", &payload)
    }

    pub fn fhdr(&mut self, patch_type: &[u8; 4], entry_files: u32) -> &mut Self {
        let mut v = Vec::new();
        v.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // version dword (LE): v2
        v.extend_from_slice(patch_type);
        v.extend_from_slice(&entry_files.to_be_bytes());
        v.extend_from_slice(&[0u8; 8]); // v2 trailing zeros
        self.chunk(b"FHDR", &v)
    }

    pub fn target_info(&mut self, platform: u16) -> &mut Self {
        let mut v = Vec::new();
        v.extend_from_slice(&[0, 0, 0]); // reserved / alignment
        v.extend_from_slice(&platform.to_be_bytes());
        v.extend_from_slice(&(-1i16).to_be_bytes()); // region: global
        v.extend_from_slice(&0u16.to_be_bytes()); // isDebug
        v.extend_from_slice(&0u16.to_be_bytes()); // version
        v.extend_from_slice(&0u64.to_le_bytes()); // deletedDataSize (LE)
        v.extend_from_slice(&0u64.to_le_bytes()); // seekCount (LE)
        self.sqpk(b'T', &v)
    }

    /// A `SQPK F` file op. `blocks` is the raw block stream (only meaningful for `A`).
    pub fn file_op(
        &mut self,
        op: u8,
        file_offset: i64,
        file_size: i64,
        path: &str,
        blocks: &[u8],
    ) -> &mut Self {
        let mut v = Vec::new();
        v.push(op);
        v.extend_from_slice(&[0, 0]); // alignment
        v.extend_from_slice(&file_offset.to_be_bytes());
        v.extend_from_slice(&file_size.to_be_bytes());
        v.extend_from_slice(&(path.len() as u32).to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // expansionId
        v.extend_from_slice(&[0, 0]); // padding
        v.extend_from_slice(path.as_bytes());
        v.extend_from_slice(blocks);
        self.sqpk(b'F', &v)
    }

    pub fn add_directory(&mut self, path: &str) -> &mut Self {
        self.directory_chunk(b"ADIR", path)
    }

    pub fn delete_directory(&mut self, path: &str) -> &mut Self {
        self.directory_chunk(b"DELD", path)
    }

    /// An `ADIR`/`DELD` chunk: `u32be pathLen` + path bytes.
    fn directory_chunk(&mut self, fourcc: &[u8; 4], path: &str) -> &mut Self {
        let mut v = Vec::new();
        v.extend_from_slice(&(path.len() as u32).to_be_bytes());
        v.extend_from_slice(path.as_bytes());
        self.chunk(fourcc, &v)
    }

    pub fn eof(&mut self) -> &mut Self {
        self.chunk(b"EOF_", &[])
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.body);
        out
    }
}

/// One SqPack block: a 16-byte LE header (`header_size`, pad, `compressed_size`, `decompressed_size`)
/// then `payload`, padded to a 128-byte boundary.
fn block(compressed_size: u32, decompressed_size: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&16u32.to_le_bytes()); // header_size
    b.extend_from_slice(&0u32.to_le_bytes()); // pad
    b.extend_from_slice(&compressed_size.to_le_bytes());
    b.extend_from_slice(&decompressed_size.to_le_bytes());
    b.extend_from_slice(payload);
    pad_to_128(b)
}

/// A stored (uncompressed) SqPack block carrying `payload` verbatim.
pub fn block_stored(payload: &[u8]) -> Vec<u8> {
    block(0x7D00, payload.len() as u32, payload)
}

/// A DEFLATE-compressed SqPack block that decodes to `plain` (raw deflate, no zlib wrapper).
pub fn block_deflate(plain: &[u8]) -> Vec<u8> {
    let compressed = deflate_raw(plain);
    block(compressed.len() as u32, plain.len() as u32, &compressed)
}

/// A DEFLATE block whose header claims `claimed_decompressed` output bytes (which may differ from the
/// true size), for driving the decode-size cap and size-mismatch paths.
pub fn block_deflate_claiming(plain: &[u8], claimed_decompressed: u32) -> Vec<u8> {
    let compressed = deflate_raw(plain);
    block(compressed.len() as u32, claimed_decompressed, &compressed)
}

/// A well-framed block whose payload is not valid DEFLATE, so decoding it fails.
pub fn block_bad_deflate(payload_len: u32, decompressed: u32) -> Vec<u8> {
    block(
        payload_len,
        decompressed,
        &vec![0xFFu8; payload_len as usize],
    )
}

/// A block with an arbitrary (possibly hostile) header, for framing/guard tests.
pub fn block_raw(compressed_size: u32, decompressed_size: u32, payload: &[u8]) -> Vec<u8> {
    block(compressed_size, decompressed_size, payload)
}

fn pad_to_128(mut v: Vec<u8>) -> Vec<u8> {
    let target = (v.len() + 127) & !127;
    v.resize(target, 0);
    v
}

fn deflate_raw(plain: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(plain).expect("deflate write");
    e.finish().expect("deflate finish")
}

/// A [`PatchSink`] that reconstructs each file in memory, so a test can assert final contents.
#[derive(Default)]
pub struct InMemorySink {
    pub files: BTreeMap<PathBuf, Vec<u8>>,
}

impl InMemorySink {
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(&PathBuf::from(path)).map(Vec::as_slice)
    }

    fn splice(&mut self, path: PathBuf, off: u64, bytes: &[u8]) {
        let buf = self.files.entry(path).or_default();
        let end = off as usize + bytes.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[off as usize..end].copy_from_slice(bytes);
    }
}

impl PatchSink for InMemorySink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<(), Error> {
        let path = target.as_path().to_path_buf();
        let bytes = match src {
            DataSource::Raw { bytes, .. } => bytes.to_vec(),
            DataSource::Deflate {
                bytes,
                decompressed_len,
                ..
            } => {
                let mut out = Vec::new();
                let mut dec = flate2::read::DeflateDecoder::new(bytes);
                std::io::copy(&mut dec, &mut out).expect("inflate");
                assert_eq!(
                    out.len(),
                    decompressed_len as usize,
                    "declared decompressed size"
                );
                out
            }
            DataSource::Zeros { len } => vec![0u8; len as usize],
        };
        self.splice(path, off, &bytes);
        Ok(())
    }

    fn write_empty_block(&mut self, _t: &TargetPath, _off: u64, _blocks: u32) -> Result<(), Error> {
        Ok(())
    }

    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<(), Error> {
        self.files
            .entry(target.as_path().to_path_buf())
            .or_default()
            .resize(len as usize, 0);
        Ok(())
    }

    fn remove_file(&mut self, target: &TargetPath) -> Result<(), Error> {
        self.files.remove(target.as_path());
        Ok(())
    }

    fn remove_expansion(&mut self, _exp: u16, _keep: &KeepFilter) -> Result<(), Error> {
        Ok(())
    }

    fn make_dir_tree(&mut self, _rel: &SafePath) -> Result<(), Error> {
        Ok(())
    }

    fn remove_dir(&mut self, _rel: &SafePath) -> Result<(), Error> {
        Ok(())
    }
}

/// A [`PatchSink`] that records each call as a byte-free line, for deterministic effect-trace asserts.
#[derive(Default)]
pub struct TraceSink {
    pub calls: Vec<String>,
}

impl PatchSink for TraceSink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<(), Error> {
        let path = target.as_path().display();
        let line = match src {
            DataSource::Raw { bytes, .. } => {
                format!("write raw {path} off={off} len={}", bytes.len())
            }
            DataSource::Deflate {
                compressed_len,
                decompressed_len,
                ..
            } => format!(
                "write deflate {path} off={off} clen={compressed_len} dlen={decompressed_len}"
            ),
            DataSource::Zeros { len } => format!("write zeros {path} off={off} len={len}"),
        };
        self.calls.push(line);
        Ok(())
    }

    fn write_empty_block(
        &mut self,
        target: &TargetPath,
        off: u64,
        blocks: u32,
    ) -> Result<(), Error> {
        self.calls.push(format!(
            "empty {} off={off} blocks={blocks}",
            target.as_path().display()
        ));
        Ok(())
    }

    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<(), Error> {
        self.calls
            .push(format!("truncate {} len={len}", target.as_path().display()));
        Ok(())
    }

    fn remove_file(&mut self, target: &TargetPath) -> Result<(), Error> {
        self.calls
            .push(format!("remove {}", target.as_path().display()));
        Ok(())
    }

    fn remove_expansion(&mut self, exp: u16, _keep: &KeepFilter) -> Result<(), Error> {
        self.calls.push(format!("remove_expansion {exp}"));
        Ok(())
    }

    fn make_dir_tree(&mut self, rel: &SafePath) -> Result<(), Error> {
        self.calls
            .push(format!("mkdir {}", rel.as_path().display()));
        Ok(())
    }

    fn remove_dir(&mut self, rel: &SafePath) -> Result<(), Error> {
        self.calls
            .push(format!("rmdir {}", rel.as_path().display()));
        Ok(())
    }
}
