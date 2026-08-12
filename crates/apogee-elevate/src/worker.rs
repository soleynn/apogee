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
    //
    // The flag is cleared here rather than in the request loop below, because this task is the only
    // place the two are ordered against each other. Clearing it as a request is dequeued instead
    // loses a cancel that arrived while the request was still queued: this task can read both frames
    // before the loop is polled once, and the reset would then erase a stop the parent had already
    // asked for, applying the patch and advancing the version while the parent is told it stopped.
    let reading = {
        let cancel = Arc::clone(&cancel);
        tokio::spawn(async move {
            let mut reader = reader;
            let outcome = loop {
                match read_frame::<_, WorkerRequest>(&mut reader).await {
                    Ok(Some(WorkerRequest::Cancel)) => cancel.store(true, Ordering::Relaxed),
                    Ok(Some(request)) => {
                        cancel.store(false, Ordering::Relaxed);
                        if requests.send(request).is_err() {
                            break Ok(());
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(Error::from(e)),
                }
            };
            // The parent is gone, whether it closed cleanly or died. Anything still applying must
            // stop: without this, a privileged process keeps writing into the install tree, and then
            // advances the version file, long after the launcher that asked for it has exited.
            cancel.store(true, Ordering::Relaxed);
            outcome
        })
    };

    let _ = responses.send(WorkerResponse::Ready {
        protocol: PROTOCOL_VERSION,
    });

    let mut root: Option<PathBuf> = None;
    while let Some(request) = inbox.recv().await {
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
/// nothing had checked. On Windows the handle also denies other writers for as long as it is held
/// (see [`open_patch`]), which is what closes the other half of that window: without it, hashing the
/// bytes proves nothing about the bytes the applier goes on to read, because a same-user process can
/// overwrite them in place during the minutes an apply takes.
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
    let file = open_patch(patch)
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

/// Write the version file, checking its resolved location at every point the filesystem can answer.
///
/// The check runs before the directories are made, not only after. Creating them first would mean a
/// junction standing in for one of the accepted components had already been followed, and the
/// privileged process would have made directories outside the bound tree on its way to refusing the
/// request.
fn write_version(root: &Path, target: &Path, contents: &str) -> std::result::Result<(), Fault> {
    let io = |e: std::io::Error| Fault::at(WorkerErrorKind::Apply, target, e.to_string());
    let refused = |e: crate::confine::ConfineError| {
        Fault::at(WorkerErrorKind::Protocol, target, e.to_string())
    };
    if let Some(parent) = target.parent() {
        assert_deepest_existing_within(root, parent).map_err(refused)?;
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    assert_within(root, target).map_err(refused)?;
    replace_file(target, contents.as_bytes()).map_err(io)
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
    let bytes = std::fs::read(&from)
        .map_err(|e| Fault::at(WorkerErrorKind::Apply, &from, e.to_string()))?;
    replace_file(&to, &bytes).map_err(|e| Fault::at(WorkerErrorKind::Apply, &to, e.to_string()))
}

/// Open a patch for the verify-then-apply pass, refusing to share it with another writer.
///
/// Windows lets an opener say who else may hold the file. Denying writers for the life of the handle
/// is what makes the re-verification mean anything: the bytes hashed on the first pass are then the
/// bytes applied on the second, and a same-user process cannot rewrite the tail of a multi-gigabyte
/// patch while the applier is still reading the head. It costs nothing, because nothing else is
/// meant to be writing a patch that is already being applied.
#[cfg(windows)]
fn open_patch(patch: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    /// `FILE_SHARE_READ`: other readers are fine, other writers and deleters are not.
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(patch)
}

/// Open a patch for the verify-then-apply pass.
///
/// No share mode here: Unix has no equivalent that is not advisory, and this is the platform with no
/// elevation model, so the worker runs with the same privileges as the process that asked for it.
#[cfg(not(windows))]
fn open_patch(patch: &Path) -> std::io::Result<File> {
    File::open(patch)
}

/// Write `bytes` to `path`, replacing whatever entry is there rather than writing through it.
///
/// The existing entry is unlinked first and the new file is created fresh. Writing to the path as it
/// stands would follow a symbolic link or a reparse point at the final component, and would write
/// through a hard link into a file elsewhere entirely; neither is visible to the confinement check,
/// which can only canonicalize the directory above. Unlinking makes both harmless: the link is what
/// is removed, and the bytes land in a new file at the checked location.
///
/// `create_new` is what makes that airtight rather than merely likely: if anything re-creates the
/// name between the unlink and this call, the write fails instead of following it.
fn replace_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::File::create_new(path)?.write_all(bytes)
}

/// Assert that the deepest part of `dir` that exists today is inside `root`.
///
/// The confinement check needs a path it can canonicalize, so a directory chain that has not been
/// made yet is checked at the deepest point that has.
fn assert_deepest_existing_within(
    root: &Path,
    dir: &Path,
) -> std::result::Result<(), crate::confine::ConfineError> {
    let existing = dir.ancestors().find(|candidate| candidate.exists());
    match existing {
        // `assert_within` checks a path's parent, so it is handed a child of the directory to check.
        Some(existing) => assert_within(root, &existing.join("x")),
        None => Ok(()),
    }
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
        Admission::ChunkCrc { content } => {
            // The digest first, because it is the half that an attacker cannot recompute for a file
            // of their own choosing. The CRC scan behind it is the same one the unprivileged path
            // runs to admit a boot patch, repeated here because its result did not cross with it.
            verify_content_digest(file, patch, content, cancel, responses)?;
            (&*file)
                .seek(SeekFrom::Start(0))
                .map_err(|e| Fault::at(WorkerErrorKind::Verify, patch, e.to_string()))?;
            let mut reader = PatchReader::open(BufReader::new(file))
                .map_err(|e| Fault::at(WorkerErrorKind::Verify, patch, e.to_string()))?
                .verify_crc(true);
            scan_crc(&mut reader)
                .map_err(|e| Fault::at(WorkerErrorKind::Verify, patch, e.to_string()))
        }
    }
}

/// Hash the whole file and compare it against the digest the parent took when it admitted the file.
fn verify_content_digest(
    file: &File,
    patch: &Path,
    expected: &[u8; 32],
    cancel: &AtomicBool,
    responses: &mpsc::UnboundedSender<WorkerResponse>,
) -> std::result::Result<(), Fault> {
    let mut hasher = blake3::Hasher::new();
    hash_stream(file, &mut hasher, cancel, responses)
        .map_err(|e| Fault::at(WorkerErrorKind::Verify, patch, e.to_string()))?;
    if hasher.finalize().as_bytes() == expected {
        return Ok(());
    }
    Err(Fault::at(
        WorkerErrorKind::Verify,
        patch,
        "the patch is not the file the launcher admitted".to_owned(),
    ))
}

/// Read a whole file into `hasher`, reporting progress and honouring a cancel.
fn hash_stream(
    file: &File,
    hasher: &mut blake3::Hasher,
    cancel: &AtomicBool,
    responses: &mpsc::UnboundedSender<WorkerResponse>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; VERIFY_READ_CHUNK];
    let (mut done, mut announced) = (0u64, 0u64);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("verification was cancelled"));
        }
        let read = read_up_to(&mut reader, &mut buf)?;
        if read == 0 {
            return Ok(());
        }
        hasher.update(&buf[..read]);
        done += read as u64;
        if done - announced >= VERIFY_PROGRESS_STRIDE {
            announced = done;
            let _ = responses.send(WorkerResponse::Progress(WorkerProgress::Verifying {
                bytes_done: done,
            }));
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
