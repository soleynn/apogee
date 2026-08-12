//! The privileged side: serve requests over one stream until the parent goes away.
//!
//! Everything here is deliberately dumb. There is no network client, no patchlist, no ordering and
//! no retry policy: the parent has already fetched and sequenced, and this side only re-proves local
//! bytes and writes them. What it does own is the two rules the parent cannot be trusted to keep for
//! it, since the parent runs unprivileged and the store is writable by the same user: every patch is
//! re-verified from the handle it is applied from, and every path stays inside the bound tree.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use apogee_zipatch::{ApplyOptions, ApplyProgress, DiskSink, PatchReader, apply, scan_crc};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::confine::{assert_within, join_confined, require_absolute};
use crate::error::{Error, Result};
use crate::proto::{
    Admission, MAX_VERSION_LEN, PROTOCOL_VERSION, VersionWrite, WorkerErrorKind, WorkerProgress,
    WorkerRequest, WorkerResponse, read_frame, write_frame,
};

/// How much of a patch is hashed between re-verification progress frames.
const VERIFY_PROGRESS_STRIDE: u64 = 8 << 20;

/// The read size for the re-verification pass, when a block is larger than this.
const VERIFY_READ_CHUNK: usize = 1 << 20;

/// A request failure, on its way to a [`WorkerResponse::Failed`].
struct Fault {
    kind: WorkerErrorKind,
    failed_file: Option<PathBuf>,
    detail: String,
}

impl Fault {
    fn new(kind: WorkerErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            failed_file: None,
            detail: detail.into(),
        }
    }

    fn at(kind: WorkerErrorKind, file: &Path, detail: impl Into<String>) -> Self {
        Self {
            kind,
            failed_file: Some(file.to_path_buf()),
            detail: detail.into(),
        }
    }
}

impl From<Fault> for WorkerResponse {
    fn from(fault: Fault) -> Self {
        Self::Failed {
            kind: fault.kind,
            failed_file: fault.failed_file,
            detail: fault.detail,
        }
    }
}

/// Serve requests until the parent closes the stream.
///
/// Announces [`WorkerResponse::Ready`] first, then handles one request at a time. A request that
/// fails is answered with [`WorkerResponse::Failed`] and the session continues; only a broken
/// transport ends it. Nothing in here exits the process.
///
/// # Errors
/// [`Error::Frame`] if the transport fails. A clean close by the parent is `Ok(())`.
pub async fn serve<R, W>(reader: R, writer: W) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (responses, mut outbox) = mpsc::unbounded_channel::<WorkerResponse>();
    // One task owns the write half, because progress frames come off a blocking apply thread while
    // the request loop is waiting to answer: two writers would interleave inside a frame.
    let pump = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(response) = outbox.recv().await {
            if let Err(e) = write_frame(&mut writer, &response).await {
                tracing::debug!(error = %e, "the parent stopped reading");
                return Err(Error::from(e));
            }
        }
        Ok(())
    });

    let cancel = Arc::new(AtomicBool::new(false));
    let (requests, mut inbox) = mpsc::unbounded_channel::<WorkerRequest>();
    // And one task owns the read half, so a cancel is seen while an apply is running rather than
    // after it. It is the only request handled out of band.
    let reading = {
        let cancel = Arc::clone(&cancel);
        tokio::spawn(async move {
            let mut reader = reader;
            loop {
                match read_frame::<_, WorkerRequest>(&mut reader).await {
                    Ok(Some(WorkerRequest::Cancel)) => cancel.store(true, Ordering::Relaxed),
                    Ok(Some(request)) => {
                        if requests.send(request).is_err() {
                            return Ok(());
                        }
                    }
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(Error::from(e)),
                }
            }
        })
    };

    let _ = responses.send(WorkerResponse::Ready {
        protocol: PROTOCOL_VERSION,
    });

    let mut root: Option<PathBuf> = None;
    while let Some(request) = inbox.recv().await {
        // A cancel only ever applies to the request in flight when it arrived.
        cancel.store(false, Ordering::Relaxed);
        let response = match handle(request, &mut root, &cancel, &responses).await {
            Ok(()) => WorkerResponse::Done,
            Err(fault) => WorkerResponse::from(fault),
        };
        if responses.send(response).is_err() {
            break;
        }
    }

    drop(responses);
    let read_result = reading.await.unwrap_or(Ok(()));
    let write_result = pump.await.unwrap_or(Ok(()));
    read_result.and(write_result)
}

/// Dispatch one request.
async fn handle(
    request: WorkerRequest,
    root: &mut Option<PathBuf>,
    cancel: &Arc<AtomicBool>,
    responses: &mpsc::UnboundedSender<WorkerResponse>,
) -> std::result::Result<(), Fault> {
    match request {
        WorkerRequest::Bind { apply_root } => {
            require_absolute("the apply root", &apply_root)
                .map_err(|e| Fault::at(WorkerErrorKind::Protocol, &apply_root, e.to_string()))?;
            // Created here rather than left to the sink: the confinement check canonicalizes the
            // root, which needs it to exist, and a fresh install points at a directory that does not.
            std::fs::create_dir_all(&apply_root)
                .map_err(|e| Fault::at(WorkerErrorKind::Apply, &apply_root, e.to_string()))?;
            tracing::info!(root = %apply_root.display(), "bound the elevated session to a tree");
            *root = Some(apply_root);
            Ok(())
        }
        WorkerRequest::Apply {
            patch,
            admission,
            advance,
        } => {
            let root = bound(root)?;
            apply_one(root, patch, admission, advance, cancel, responses).await
        }
        WorkerRequest::CopyWithin { from, to } => {
            let root = bound(root)?;
            copy_within(root, &from, &to)
        }
        // Handled out of band by the reader; reachable only if that changes, and a no-op either way.
        WorkerRequest::Cancel => Ok(()),
    }
}

/// The bound tree, or a protocol refusal.
fn bound(root: &Option<PathBuf>) -> std::result::Result<PathBuf, Fault> {
    root.clone().ok_or_else(|| {
        Fault::new(
            WorkerErrorKind::Protocol,
            "the session was not bound to a tree",
        )
    })
}

/// Re-prove one patch and apply it, then advance the version file if it landed cleanly.
async fn apply_one(
    root: PathBuf,
    patch: PathBuf,
    admission: Admission,
    advance: Option<VersionWrite>,
    cancel: &Arc<AtomicBool>,
    responses: &mpsc::UnboundedSender<WorkerResponse>,
) -> std::result::Result<(), Fault> {
    require_absolute("the patch", &patch)
        .map_err(|e| Fault::at(WorkerErrorKind::Protocol, &patch, e.to_string()))?;

    // Resolved before a byte is written, so a version path that leaves the tree fails the request
    // rather than leaving a patch applied and the version refused.
    let advance = match advance {
        None => None,
        Some(VersionWrite { path, contents }) => {
            if contents.len() > MAX_VERSION_LEN {
                return Err(Fault::new(
                    WorkerErrorKind::Protocol,
                    format!("version body of {} bytes is too long", contents.len()),
                ));
            }
            let target = join_confined(&root, &path).map_err(|e| {
                Fault::at(WorkerErrorKind::Protocol, Path::new(&path), e.to_string())
            })?;
            Some((target, contents))
        }
    };

    // zipatch reports progress on a synchronous channel; drain it onto the response stream from its
    // own blocking task, exactly as the in-process path does.
    let (ztx, zrx) = std::sync::mpsc::channel::<ApplyProgress>();
    let drain = {
        let responses = responses.clone();
        tokio::task::spawn_blocking(move || {
            while let Ok(p) = zrx.recv() {
                let _ = responses.send(WorkerResponse::Progress(WorkerProgress::Applying {
                    bytes_done: p.bytes_done,
                }));
            }
        })
    };

    let outcome = {
        let cancel = Arc::clone(cancel);
        let responses = responses.clone();
        tokio::task::spawn_blocking(move || {
            verify_then_apply(
                &root, &patch, &admission, advance, &cancel, &responses, &ztx,
            )
        })
        .await
    };
    let _ = drain.await;

    match outcome {
        Ok(inner) => inner,
        Err(join) => Err(Fault::new(
            WorkerErrorKind::Apply,
            format!("the apply task ended abnormally: {join}"),
        )),
    }
}

/// The synchronous half: verify from one handle, apply from that same handle, then write the
/// version file.
///
/// The handle is opened once and rewound rather than reopened between the two passes. Reopening
/// would re-resolve the path, so a rename between them would hand the privileged write a file
/// nothing had checked. A residual window remains, because a same-user process can still modify the
/// bytes in place after they are hashed; closing that would mean copying every patch into a
/// directory the user cannot write, which is not affordable at patch sizes.
#[allow(
    clippy::too_many_arguments,
    reason = "one call site, all of it required"
)]
fn verify_then_apply(
    root: &Path,
    patch: &Path,
    admission: &Admission,
    advance: Option<(PathBuf, String)>,
    cancel: &AtomicBool,
    responses: &mpsc::UnboundedSender<WorkerResponse>,
    zipatch_progress: &std::sync::mpsc::Sender<ApplyProgress>,
) -> std::result::Result<(), Fault> {
    let file = File::open(patch)
        .map_err(|e| Fault::at(WorkerErrorKind::Verify, patch, format!("cannot open: {e}")))?;

    reverify(&file, patch, admission, cancel, responses)?;

    (&file)
        .seek(SeekFrom::Start(0))
        .map_err(|e| Fault::at(WorkerErrorKind::Apply, patch, format!("cannot rewind: {e}")))?;

    let mut reader = PatchReader::open(BufReader::new(&file))
        .map_err(|e| Fault::at(WorkerErrorKind::Apply, patch, e.to_string()))?
        .verify_crc(false);
    let mut sink =
        DiskSink::new(root).map_err(|e| Fault::at(WorkerErrorKind::Apply, root, e.to_string()))?;
    let opts = ApplyOptions {
        progress: Some(zipatch_progress),
        cancel: Some(cancel),
    };
    match apply(&mut reader, &mut sink, &opts) {
        Ok(()) => {}
        Err(apogee_zipatch::Error::Cancelled) => {
            return Err(Fault::new(
                WorkerErrorKind::Cancelled,
                "apply was cancelled",
            ));
        }
        Err(e) => return Err(Fault::at(WorkerErrorKind::Apply, patch, e.to_string())),
    }

    let Some((target, contents)) = advance else {
        return Ok(());
    };
    write_version(root, &target, &contents)
}

/// Write the version file, re-checking its resolved location now that the directories exist.
fn write_version(root: &Path, target: &Path, contents: &str) -> std::result::Result<(), Fault> {
    let io = |e: std::io::Error| Fault::at(WorkerErrorKind::Apply, target, e.to_string());
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    assert_within(root, target)
        .map_err(|e| Fault::at(WorkerErrorKind::Protocol, target, e.to_string()))?;
    std::fs::write(target, contents).map_err(io)
}

/// Copy one file to another inside the bound tree.
fn copy_within(root: PathBuf, from: &str, to: &str) -> std::result::Result<(), Fault> {
    let resolve = |rel: &str| {
        join_confined(&root, rel)
            .map_err(|e| Fault::at(WorkerErrorKind::Protocol, Path::new(rel), e.to_string()))
    };
    let (from, to) = (resolve(from)?, resolve(to)?);
    for path in [&from, &to] {
        assert_within(&root, path)
            .map_err(|e| Fault::at(WorkerErrorKind::Protocol, path, e.to_string()))?;
    }
    std::fs::copy(&from, &to)
        .map(|_| ())
        .map_err(|e| Fault::at(WorkerErrorKind::Apply, &to, e.to_string()))
}

/// Re-derive the patch's proof from the bytes about to be applied.
fn reverify(
    file: &File,
    patch: &Path,
    admission: &Admission,
    cancel: &AtomicBool,
    responses: &mpsc::UnboundedSender<WorkerResponse>,
) -> std::result::Result<(), Fault> {
    match admission {
        Admission::BlockSha1 { block_size, hashes } => {
            verify_block_sha1(file, patch, *block_size, hashes, cancel, responses)
        }
        Admission::ChunkCrc => {
            // The same scan the unprivileged path runs to admit a boot patch, repeated here because
            // its result did not cross with it. It reads the whole file, so it doubles as the
            // "nothing is written until the bytes are proven" step.
            let mut reader = PatchReader::open(BufReader::new(file))
                .map_err(|e| Fault::at(WorkerErrorKind::Verify, patch, e.to_string()))?
                .verify_crc(true);
            scan_crc(&mut reader)
                .map_err(|e| Fault::at(WorkerErrorKind::Verify, patch, e.to_string()))
        }
    }
}

/// Hash the file block by block and compare against the patchlist digests.
fn verify_block_sha1(
    file: &File,
    patch: &Path,
    block_size: u32,
    hashes: &[String],
    cancel: &AtomicBool,
    responses: &mpsc::UnboundedSender<WorkerResponse>,
) -> std::result::Result<(), Fault> {
    let bad = |detail: String| Fault::at(WorkerErrorKind::Verify, patch, detail);
    if block_size == 0 {
        return Err(Fault::new(WorkerErrorKind::Protocol, "block size is zero"));
    }
    let block_size = block_size as usize;
    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; block_size.min(VERIFY_READ_CHUNK)];
    let mut done: u64 = 0;
    let mut announced: u64 = 0;

    for (index, expected) in hashes.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(Fault::new(
                WorkerErrorKind::Cancelled,
                "verification was cancelled",
            ));
        }
        let mut hasher = Sha1::new();
        let mut in_block = 0usize;
        while in_block < block_size {
            let want = buf.len().min(block_size - in_block);
            let read = read_up_to(&mut reader, &mut buf[..want])
                .map_err(|e| bad(format!("cannot read block {index}: {e}")))?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
            in_block += read;
            done += read as u64;
            if done - announced >= VERIFY_PROGRESS_STRIDE {
                announced = done;
                let _ = responses.send(WorkerResponse::Progress(WorkerProgress::Verifying {
                    bytes_done: done,
                }));
            }
        }
        // Only the last block may be short, and no block may be empty: either means the file is not
        // the length the digests were taken over.
        if in_block == 0 || (in_block < block_size && index + 1 != hashes.len()) {
            return Err(bad(format!(
                "patch is shorter than its {} block digests (ran out at block {index})",
                hashes.len()
            )));
        }
        let got = hasher.finalize();
        if !digest_matches(expected, &got) {
            return Err(bad(format!("block {index} does not match its digest")));
        }
    }

    // Anything past the last digest is unverified, so it is not applied.
    if read_up_to(&mut reader, &mut buf[..1])
        .map_err(|e| bad(format!("cannot read past the last block: {e}")))?
        != 0
    {
        return Err(bad(format!(
            "patch is longer than its {} block digests",
            hashes.len()
        )));
    }
    Ok(())
}

/// Fill as much of `buf` as the reader has, returning the byte count (zero only at end of file).
fn read_up_to(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Compare a hex patchlist digest against a computed one, decoding rather than re-encoding so the
/// per-block comparison allocates nothing.
fn digest_matches(expected: &str, got: &[u8]) -> bool {
    if expected.len() != got.len() * 2 {
        return false;
    }
    let mut pairs = expected.as_bytes().chunks_exact(2);
    got.iter().all(|byte| {
        pairs.next().is_some_and(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                == Some(*byte)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Digest comparison accepts the matching hex and rejects a truncated or altered one.
    #[test]
    fn digest_comparison_is_exact() {
        let got = Sha1::digest(b"apogee");
        assert!(digest_matches(&hex(&got), &got));
        assert!(!digest_matches(&hex(&got)[..38], &got));
        let mut wrong = hex(&got);
        wrong.replace_range(0..1, if wrong.starts_with('a') { "b" } else { "a" });
        assert!(!digest_matches(&wrong, &got));
        assert!(!digest_matches("", &got));
    }

    /// A partial read short of the buffer is filled to end of file rather than returned early, so a
    /// block spanning several reads still hashes as one block.
    #[test]
    fn reads_are_filled_to_end_of_file() {
        let mut src = std::io::Cursor::new(vec![7u8; 5]);
        let mut buf = [0u8; 8];
        assert_eq!(read_up_to(&mut src, &mut buf).unwrap(), 5);
        assert_eq!(read_up_to(&mut src, &mut buf).unwrap(), 0);
    }
}
