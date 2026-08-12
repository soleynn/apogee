//! The message set and its framing.
//!
//! Frames are a little-endian `u32` byte count followed by that many bytes of JSON. Both sides cap
//! the count at [`MAX_FRAME`] before allocating, so a garbled or hostile peer cannot make the other
//! reserve memory by claiming a length.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol revision both sides must agree on, exchanged in [`WorkerResponse::Ready`].
///
/// A worker binary left behind by an older install answers with a number the parent does not know,
/// which is a typed refusal rather than a misread frame.
pub const PROTOCOL_VERSION: u32 = 1;

/// The largest frame either side will read.
///
/// Sized by the one message that grows with the work: an [`Admission::BlockSha1`] carries one hash
/// per patch block, and a patch large enough to matter under an unusually small block size runs to a
/// few megabytes of digests.
pub const MAX_FRAME: u32 = 8 << 20;

/// A request from the unprivileged parent to the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkerRequest {
    /// Bind the session to one tree. Every path the worker writes for the rest of the session is
    /// confined beneath `apply_root`, which must be absolute.
    Bind {
        /// The tree the sink writes into (a repo subtree of the install root).
        apply_root: PathBuf,
    },
    /// Apply one local patch file, re-proving its bytes first.
    Apply {
        /// The patch on disk, absolute. The worker opens it once and both verifies and applies from
        /// that handle.
        patch: PathBuf,
        /// How the worker must re-prove `patch` before writing.
        admission: Admission,
        /// The version file to write after the patch applies cleanly, if any.
        advance: Option<VersionWrite>,
    },
    /// Copy one file to another within the bound tree, both paths relative to it (the version-file
    /// backup taken after a whole set applies).
    CopyWithin {
        /// Source, relative to the bound root.
        from: String,
        /// Destination, relative to the bound root.
        to: String,
    },
    /// Abandon the in-flight request. Apply stops between commands and answers
    /// [`WorkerErrorKind::Cancelled`]; the partial tree is safe to re-apply.
    Cancel,
}

/// How the worker re-proves a local patch file before writing a byte of it.
///
/// The parent has already verified the same file, but a proof is a parent-process value and the
/// store is writable by the unprivileged user, so the privileged side re-derives it from the bytes
/// it is about to read. This is what closes the window between the parent's check and the
/// privileged write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Admission {
    /// Per-block SHA1, the form a game patchlist publishes. `hashes` are lowercase hex, in block
    /// order, and the last block may be short.
    BlockSha1 {
        /// The block width the digests were taken over.
        block_size: u32,
        /// One 40-character lowercase-hex digest per block.
        hashes: Vec<String>,
    },
    /// The ZiPatch chunk CRC, which is a boot patch's only integrity check: the whole file is
    /// scanned before the first write.
    ChunkCrc,
}

/// A version file to write after a clean apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionWrite {
    /// Where to write it, relative to the bound root.
    pub path: String,
    /// The exact bytes (a bare version, no trailing newline).
    pub contents: String,
}

/// The longest version-file body the worker will write.
///
/// A version is twenty characters. The cap is here because this is the one request field whose
/// contents the parent chooses freely, and an unbounded one would make the privileged side a
/// general-purpose writer of arbitrary bytes.
pub const MAX_VERSION_LEN: usize = 64;

/// A reply from the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkerResponse {
    /// Sent once on connect, before any request is read.
    Ready {
        /// The worker's [`PROTOCOL_VERSION`].
        protocol: u32,
    },
    /// An in-flight request is making progress.
    Progress(WorkerProgress),
    /// The request completed.
    Done,
    /// The request failed. The three fields are the ones a caller needs to act: what kind of failure
    /// it was, which file it struck, and the underlying detail.
    Failed {
        /// The failure class.
        kind: WorkerErrorKind,
        /// The file the failure named, when it named one.
        failed_file: Option<PathBuf>,
        /// The rendered underlying error.
        detail: String,
    },
}

/// A progress frame streamed mid-request.
///
/// Exhaustive on purpose, unlike the request and response envelopes: version skew between the two
/// sides is caught by the [`PROTOCOL_VERSION`] handshake and would surface here as a decode failure
/// rather than as an unmatched arm, so marking it open would only cost every relay its exhaustive
/// match and let a new phase go silently unrelayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerProgress {
    /// Re-proving the local patch, before any byte is written. Its own phase because it is a second
    /// full pass over a file that can run to gigabytes: without it a caller sees no movement at all
    /// for as long as the digest takes.
    Verifying {
        /// Patch bytes hashed so far.
        bytes_done: u64,
    },
    /// Payload bytes written to disk so far, rising monotonically over one apply.
    Applying {
        /// Bytes written so far. No total: nothing in the patch format declares one.
        bytes_done: u64,
    },
}

/// How a worker request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkerErrorKind {
    /// The worker could not be started or could not be reached (parent-side only).
    Spawn,
    /// A frame was malformed, out of order, or asked for something the session forbids.
    Protocol,
    /// The patch failed the worker's own re-verification, so nothing was written.
    Verify,
    /// The apply itself failed.
    Apply,
    /// The request was abandoned on a [`WorkerRequest::Cancel`].
    Cancelled,
}

/// A framing failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The stream failed.
    #[error("frame i/o failed")]
    Io(#[from] std::io::Error),
    /// The peer announced a frame past [`MAX_FRAME`].
    #[error("frame of {len} bytes exceeds the {MAX_FRAME}-byte cap")]
    TooLarge {
        /// The announced length.
        len: u32,
    },
    /// The frame body was not the message it should have been.
    #[error("frame body could not be decoded")]
    Decode(#[source] serde_json::Error),
    /// The value could not be encoded (a bug on the sending side).
    #[error("frame body could not be encoded")]
    Encode(#[source] serde_json::Error),
}

/// Write one framed message.
///
/// # Errors
/// [`FrameError::Encode`] if `value` will not serialize, [`FrameError::TooLarge`] if it exceeds
/// [`MAX_FRAME`], or [`FrameError::Io`] if the stream fails.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value).map_err(FrameError::Encode)?;
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge { len: u32::MAX })?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge { len });
    }
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one framed message, or `None` if the peer closed the stream cleanly between frames.
///
/// A close *part way through* a frame is [`FrameError::Io`], not `None`: the two are the difference
/// between a peer that finished and a peer that died, and the caller acts differently on each.
///
/// # Errors
/// [`FrameError::TooLarge`] if the announced length exceeds [`MAX_FRAME`],
/// [`FrameError::Decode`] if the body is not the expected message, or [`FrameError::Io`] if the
/// stream fails or ends mid-frame.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        // Nothing at all arrived, which is the peer closing between frames.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_le_bytes(len);
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge { len });
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(FrameError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request survives a round trip through the framing unchanged.
    #[tokio::test]
    async fn a_request_round_trips_through_a_frame() {
        let mut buf = Vec::new();
        let sent = WorkerRequest::Apply {
            patch: PathBuf::from("/store/p0.patch"),
            admission: Admission::BlockSha1 {
                block_size: 64,
                hashes: vec!["ab".repeat(20)],
            },
            advance: Some(VersionWrite {
                path: "ffxivgame.ver".to_owned(),
                contents: "2024.01.02.0000.0000".to_owned(),
            }),
        };
        write_frame(&mut buf, &sent).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let got: Option<WorkerRequest> = read_frame(&mut cursor).await.unwrap();
        assert_eq!(got, Some(sent));
    }

    /// Several frames on one stream are read back in order, and a clean end is `None` rather than an
    /// error: the two ways a stream can stop have to stay distinguishable.
    #[tokio::test]
    async fn frames_are_read_back_in_order_and_a_clean_close_is_not_an_error() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &WorkerResponse::Ready { protocol: 1 })
            .await
            .unwrap();
        write_frame(
            &mut buf,
            &WorkerResponse::Progress(WorkerProgress::Applying { bytes_done: 7 }),
        )
        .await
        .unwrap();
        write_frame(&mut buf, &WorkerResponse::Done).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let mut seen = Vec::new();
        while let Some(msg) = read_frame::<_, WorkerResponse>(&mut cursor).await.unwrap() {
            seen.push(msg);
        }
        assert_eq!(
            seen,
            vec![
                WorkerResponse::Ready { protocol: 1 },
                WorkerResponse::Progress(WorkerProgress::Applying { bytes_done: 7 }),
                WorkerResponse::Done,
            ]
        );
    }

    /// An announced length past the cap is refused before the body is allocated.
    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused_without_allocating() {
        let mut bytes = (MAX_FRAME + 1).to_le_bytes().to_vec();
        // Deliberately no body: the reader must fail on the header alone. Were the cap checked after
        // the read instead, this would hang or fail as a truncated frame rather than as too large.
        bytes.extend_from_slice(b"{}");
        let mut cursor = std::io::Cursor::new(bytes);
        let err = read_frame::<_, WorkerResponse>(&mut cursor)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { .. }), "got {err:?}");
    }

    /// A stream that stops part way through a frame is an i/o failure, not a clean end.
    #[tokio::test]
    async fn a_truncated_frame_is_an_error_and_not_a_clean_close() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &WorkerResponse::Done).await.unwrap();
        buf.truncate(buf.len() - 1);
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_frame::<_, WorkerResponse>(&mut cursor)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Io(_)), "got {err:?}");
    }

    /// A well-framed body that is not the expected message decodes to a typed refusal.
    #[tokio::test]
    async fn a_body_that_is_not_the_expected_message_is_a_decode_error() {
        let body = br#"{"NotAVariant":{}}"#;
        let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(body);
        let mut cursor = std::io::Cursor::new(bytes);
        let err = read_frame::<_, WorkerRequest>(&mut cursor)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)), "got {err:?}");
    }
}
