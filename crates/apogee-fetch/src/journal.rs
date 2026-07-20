//! The resumable-download sidecar journal (`.apdl`).
//!
//! A small append-only binary log written next to the `.part` file: a write-once header recording
//! the request's identity, then fixed-size, CRC-framed records naming completed byte intervals.
//! It is an optimization, never a source of truth: any decode defect (bad magic, wrong version,
//! failed CRC, a torn tail, or an identity that does not match the current request) resolves to
//! "start the download over", so a corrupt journal can never fail a download or be trusted into a
//! lie. Only a genuine filesystem error surfaces.
//!
//! The header CRC covers everything before it; each record CRC covers its `[start, end)` pair.
//! Because records are appended only after their bytes are flushed, every intact interval names bytes
//! the disk has confirmed. A single-connection download writes one growing prefix `[0, watermark)`;
//! a segmented download writes several intervals out of order, folded into a coalesced set on load.

use std::io;
use std::path::Path;

use tokio::io::AsyncWriteExt;

use crate::intervals::IntervalSet;

const MAGIC: [u8; 4] = *b"APDL";
/// Version 2 records completed `[start, end)` intervals; version 1 (a single watermark) is read as a
/// version mismatch and restarts cleanly.
const FORMAT_VERSION: u16 = 2;
/// magic (4) + version (2) + flags (2) + identity length (4).
const HEADER_FIXED: usize = 12;
const URL_CAP: usize = 8 * 1024;
const TAG_CAP: usize = 1024;
const RECORD_LEN: usize = 20; // start (8) + end (8) + crc32 (4)
/// A journal larger than this is pathological; treat it as corrupt rather than read it.
const MAX_JOURNAL_LEN: u64 = 1024 * 1024;
/// A coalesced interval set larger than this means a crafted or degenerate journal; treat it as
/// corrupt. Realistic downloads hold a run per segment (tens), far under this.
const MAX_INTERVALS: usize = 8192;

/// The request fingerprint a resume must match: same source, same expected length, same validator.
/// `etag`/`last_modified` are not matched (they are the `If-Range` value the resume sends); the first
/// three fields are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) url: String,
    pub(crate) expected_len: Option<u64>,
    pub(crate) validator_digest: [u8; 32],
    pub(crate) etag: Option<Vec<u8>>,
    pub(crate) last_modified: Option<Vec<u8>>,
}

impl Identity {
    /// Whether a resume against `self` may reuse a journal recorded with `other`: the source, the
    /// declared length, and the validator must be identical. Server validators are deliberately
    /// excluded.
    pub(crate) fn matches(&self, other: &Identity) -> bool {
        self.url == other.url
            && self.expected_len == other.expected_len
            && self.validator_digest == other.validator_digest
    }
}

/// A decoded journal: the recorded identity and the coalesced set of durable byte intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Loaded {
    pub(crate) identity: Identity,
    pub(crate) intervals: IntervalSet,
}

impl Loaded {
    /// The furthest byte of the contiguous prefix from 0, i.e. where a single-connection resume
    /// continues. Zero when byte 0 is not yet durable.
    pub(crate) fn watermark(&self) -> u64 {
        self.intervals.leading_end()
    }
}

/// An open journal accepting appended watermark records.
#[derive(Debug)]
pub(crate) struct Journal {
    file: tokio::fs::File,
}

impl Journal {
    /// Create (truncating any existing file) the journal at `path` and write its header. `Ok(None)`
    /// means the identity is too large to encode, so the download proceeds without resume support.
    pub(crate) async fn create(path: &Path, identity: &Identity) -> io::Result<Option<Journal>> {
        let Some(header) = encode_header(identity) else {
            return Ok(None);
        };
        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(&header).await?;
        file.sync_data().await?;
        Ok(Some(Journal { file }))
    }

    /// Open an existing journal for appending further records (its header is left intact).
    pub(crate) async fn open_append(path: &Path) -> io::Result<Journal> {
        let file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .await?;
        Ok(Journal { file })
    }

    /// Append a completed-interval record and flush it durably. The caller must have already flushed
    /// the data covering `[start, end)`, so the record never names bytes that are not on disk. An
    /// empty or reversed range is a no-op.
    pub(crate) async fn commit_interval(&mut self, start: u64, end: u64) -> io::Result<()> {
        if start >= end {
            return Ok(());
        }
        self.file.write_all(&encode_record(start, end)).await?;
        self.file.sync_data().await?;
        Ok(())
    }
}

/// Fuzz entry point: decode arbitrary bytes, proving the parser is total and bounded on hostile
/// input. Gated to the `fuzzing` feature; never part of the shipping API.
#[cfg(feature = "fuzzing")]
pub fn fuzz_decode(bytes: &[u8]) {
    let _ = decode(bytes);
}

/// Read and decode the journal at `path`. `Ok(None)` is "no usable journal, start fresh": the file
/// is absent, or it decoded as corrupt/oversized/torn/mismatched. Only a genuine I/O failure errors.
pub(crate) async fn load(path: &Path) -> io::Result<Option<Loaded>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(decode(&bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn encode_header(identity: &Identity) -> Option<Vec<u8>> {
    let id = encode_identity(identity)?;
    let mut out = Vec::with_capacity(HEADER_FIXED + id.len() + 4);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // flags, reserved
    out.extend_from_slice(&u32::try_from(id.len()).ok()?.to_le_bytes());
    out.extend_from_slice(&id);
    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Some(out)
}

fn encode_identity(identity: &Identity) -> Option<Vec<u8>> {
    if identity.url.len() > URL_CAP
        || identity.etag.as_ref().map_or(0, Vec::len) > TAG_CAP
        || identity.last_modified.as_ref().map_or(0, Vec::len) > TAG_CAP
    {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(identity.url.len()).ok()?.to_le_bytes());
    out.extend_from_slice(identity.url.as_bytes());
    match identity.expected_len {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => {
            out.push(0);
            out.extend_from_slice(&0u64.to_le_bytes());
        }
    }
    out.extend_from_slice(&identity.validator_digest);
    write_blob(&mut out, identity.etag.as_deref())?;
    write_blob(&mut out, identity.last_modified.as_deref())?;
    Some(out)
}

fn write_blob(out: &mut Vec<u8>, blob: Option<&[u8]>) -> Option<()> {
    let bytes = blob.unwrap_or(&[]);
    out.extend_from_slice(&u16::try_from(bytes.len()).ok()?.to_le_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

fn encode_record(start: u64, end: u64) -> [u8; RECORD_LEN] {
    let mut rec = [0u8; RECORD_LEN];
    rec[0..8].copy_from_slice(&start.to_le_bytes());
    rec[8..16].copy_from_slice(&end.to_le_bytes());
    let crc = crc32(&rec[0..16]).to_le_bytes();
    rec[16..20].copy_from_slice(&crc);
    rec
}

/// Decode a journal image. Returns `None` for any defect, which the caller reads as "start over".
fn decode(bytes: &[u8]) -> Option<Loaded> {
    if bytes.len() as u64 > MAX_JOURNAL_LEN || bytes.len() < HEADER_FIXED || bytes[0..4] != MAGIC {
        return None;
    }
    if u16::from_le_bytes([bytes[4], bytes[5]]) != FORMAT_VERSION {
        return None;
    }
    let identity_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let id_end = HEADER_FIXED.checked_add(identity_len)?;
    let crc_end = id_end.checked_add(4)?;
    if bytes.len() < crc_end {
        return None;
    }
    let stored_crc = u32::from_le_bytes([
        bytes[id_end],
        bytes[id_end + 1],
        bytes[id_end + 2],
        bytes[id_end + 3],
    ]);
    if crc32(&bytes[0..id_end]) != stored_crc {
        return None;
    }
    let identity = decode_identity(&bytes[HEADER_FIXED..id_end])?;

    // Records: fold intact `[start, end)` intervals, stopping at the first torn/short/CRC-bad tail
    // (writes are sequential, so a bad record can only be the last). A record whose end exceeds the
    // declared length, or which is empty/reversed, is treated as the torn boundary and stops the fold.
    let mut runs: Vec<std::ops::Range<u64>> = Vec::new();
    let mut rest = &bytes[crc_end..];
    while rest.len() >= RECORD_LEN {
        let (rec, tail) = rest.split_at(RECORD_LEN);
        let start = u64::from_le_bytes(rec[0..8].try_into().ok()?);
        let end = u64::from_le_bytes(rec[8..16].try_into().ok()?);
        let crc = u32::from_le_bytes(rec[16..20].try_into().ok()?);
        if crc32(&rec[0..16]) != crc {
            break;
        }
        if start >= end || identity.expected_len.is_some_and(|len| end > len) {
            break;
        }
        runs.push(start..end);
        rest = tail;
    }
    // Bound the COALESCED set, not the raw record stream. Both engines append one record per batch and
    // never compact, so a healthy large download holds many records that fold to a handful of intervals
    // (the single-connection path's growing `[0, watermark)` records fold to one). The raw count is
    // already bounded by MAX_JOURNAL_LEN; only a genuinely fragmented set is rejected here.
    let intervals = IntervalSet::from_runs(runs);
    if intervals.len() > MAX_INTERVALS {
        return None;
    }
    Some(Loaded {
        identity,
        intervals,
    })
}

fn decode_identity(bytes: &[u8]) -> Option<Identity> {
    let mut r = Reader::new(bytes);
    let url_len = r.u32()? as usize;
    if url_len > URL_CAP {
        return None;
    }
    let url = String::from_utf8(r.take(url_len)?.to_vec()).ok()?;
    let present = r.u8()?;
    let raw_len = r.u64()?;
    let expected_len = match present {
        0 => None,
        1 => Some(raw_len),
        _ => return None,
    };
    let validator_digest: [u8; 32] = r.take(32)?.try_into().ok()?;
    let etag = read_blob(&mut r)?;
    let last_modified = read_blob(&mut r)?;
    // v1 identity is exact: trailing bytes mean corruption.
    if !r.is_empty() {
        return None;
    }
    Some(Identity {
        url,
        expected_len,
        validator_digest,
        etag,
        last_modified,
    })
}

fn read_blob(r: &mut Reader<'_>) -> Option<Option<Vec<u8>>> {
    let len = r.u16()? as usize;
    if len > TAG_CAP {
        return None;
    }
    if len == 0 {
        return Some(None);
    }
    Some(Some(r.take(len)?.to_vec()))
}

/// A bounds-checked forward reader over a byte slice; every read returns `None` on underflow.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            url: "https://host.invalid/f.bin".to_owned(),
            expected_len: Some(4096),
            validator_digest: [7; 32],
            etag: Some(b"\"v1\"".to_vec()),
            last_modified: None,
        }
    }

    fn image(identity: &Identity, intervals: &[(u64, u64)]) -> Vec<u8> {
        let mut buf = encode_header(identity).unwrap();
        for &(start, end) in intervals {
            buf.extend_from_slice(&encode_record(start, end));
        }
        buf
    }

    #[test]
    fn a_growing_prefix_folds_to_its_watermark() {
        // The single-connection path commits [0, w) as w grows; the runs coalesce to one prefix.
        let id = identity();
        let decoded = decode(&image(&id, &[(0, 1000), (0, 2000), (0, 3000)])).unwrap();
        assert_eq!(decoded.identity, id);
        assert_eq!(decoded.watermark(), 3000);
        assert_eq!(decoded.intervals.len(), 1);
    }

    #[test]
    fn out_of_order_intervals_coalesce() {
        // The segmented path commits disjoint segment ranges; a gap keeps them separate, and the
        // watermark is only the prefix from 0.
        let decoded = decode(&image(&identity(), &[(2048, 3072), (0, 1024)])).unwrap();
        assert_eq!(decoded.watermark(), 1024);
        assert_eq!(decoded.intervals.covered_len(), 2048);
        assert_eq!(decoded.intervals.complement(3072), vec![1024..2048]);
    }

    #[test]
    fn a_header_with_no_records_resumes_from_zero() {
        let decoded = decode(&image(&identity(), &[])).unwrap();
        assert_eq!(decoded.watermark(), 0);
    }

    #[test]
    fn many_growing_prefix_records_survive_coalescing() {
        // The append-only journal never compacts, so a large single-connection download accrues one
        // `[0, watermark)` record per batch - far more than MAX_INTERVALS, all coalescing to one run.
        // Decode must bound the coalesced set, not the raw record count, or resume breaks past ~8 GiB.
        let mut id = identity();
        id.expected_len = None; // no per-record length ceiling for this synthetic image
        let records: Vec<(u64, u64)> = (1..=10_000u64).map(|k| (0, k * 4096)).collect();
        let decoded = decode(&image(&id, &records)).unwrap();
        assert_eq!(decoded.intervals.len(), 1);
        assert_eq!(decoded.watermark(), 10_000 * 4096);
    }

    #[test]
    fn a_torn_trailing_record_is_ignored() {
        let mut buf = image(&identity(), &[(0, 1000), (0, 2000)]);
        buf.extend_from_slice(&[0xAB, 0xCD, 0xEF]); // a partial third record
        assert_eq!(decode(&buf).unwrap().watermark(), 2000);
    }

    #[test]
    fn a_corrupted_record_crc_stops_the_fold() {
        let mut buf = image(&identity(), &[(0, 1000), (0, 2000)]);
        let last = buf.len() - RECORD_LEN;
        buf[last] ^= 0xFF; // flip a start byte; its CRC no longer matches
        assert_eq!(decode(&buf).unwrap().watermark(), 1000);
    }

    #[test]
    fn a_record_past_the_declared_length_stops_the_fold() {
        // expected_len is 4096; a record naming bytes beyond it is a torn boundary, not a truth.
        let mut id = identity();
        id.expected_len = Some(4096);
        let decoded = decode(&image(&id, &[(0, 4096), (0, 5000)])).unwrap();
        assert_eq!(decoded.watermark(), 4096);
    }

    #[test]
    fn a_corrupt_middle_record_discards_every_later_record() {
        // Corrupt the first of three records: the fold must stop there, not skip ahead to a later
        // still-valid record naming bytes past the torn gap.
        let id = identity();
        let header = encode_header(&id).unwrap().len();
        let mut buf = image(&id, &[(0, 1000), (1000, 2000), (2000, 3000)]);
        buf[header] ^= 0xFF; // flip a byte of the first record's start
        assert_eq!(decode(&buf).unwrap().watermark(), 0);
    }

    #[test]
    fn bad_magic_is_start_over() {
        let mut buf = image(&identity(), &[(0, 1000)]);
        buf[0] = b'X';
        assert!(decode(&buf).is_none());
    }

    #[test]
    fn a_version_one_journal_is_start_over() {
        // A v1 journal on disk (version byte 1) is read as a mismatch and restarts cleanly.
        let mut buf = image(&identity(), &[(0, 1000)]);
        buf[4] = 1;
        assert!(decode(&buf).is_none());
    }

    #[test]
    fn a_flipped_header_crc_is_start_over() {
        let id = identity();
        let mut buf = image(&id, &[(0, 1000)]);
        let header_crc_at = HEADER_FIXED + encode_identity(&id).unwrap().len();
        buf[header_crc_at] ^= 0xFF;
        assert!(decode(&buf).is_none());
    }

    #[test]
    fn an_oversized_journal_is_start_over() {
        let mut buf = image(&identity(), &[(0, 1000)]);
        buf.resize(usize::try_from(MAX_JOURNAL_LEN).unwrap() + 1, 0);
        assert!(decode(&buf).is_none());
    }

    #[test]
    fn a_truncated_header_is_start_over() {
        let buf = image(&identity(), &[]);
        assert!(decode(&buf[..HEADER_FIXED - 1]).is_none());
    }

    #[test]
    fn identity_matches_ignore_server_validators() {
        let a = identity();
        let mut b = identity();
        b.etag = Some(b"\"v2\"".to_vec());
        b.last_modified = Some(b"today".to_vec());
        assert!(a.matches(&b), "etag/last-modified must not affect identity");

        let mut different_len = identity();
        different_len.expected_len = Some(9999);
        assert!(!a.matches(&different_len));
    }
}
