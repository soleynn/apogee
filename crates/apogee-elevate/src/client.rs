//! The unprivileged side: open a session, then drive it one request at a time.

use std::path::Path;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::proto::{
    Admission, PROTOCOL_VERSION, VersionWrite, WorkerErrorKind, WorkerProgress, WorkerRequest,
    WorkerResponse, read_frame, write_frame,
};

/// A live conversation with one worker.
///
/// Requests are strictly serial: each one is written and then read to its [`WorkerResponse::Done`]
/// or [`WorkerResponse::Failed`] before the next is sent, so there is no request id and no
/// interleaving to get wrong. Generic over the two halves rather than over a duplex, because the
/// three transports it runs on present differently: a pipe splits, a child's standard streams are
/// already two objects, and an in-memory pair is two ends.
pub struct Session<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> Session<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Open a session over an already-connected pair, exchanging the protocol handshake.
    ///
    /// # Errors
    /// [`Error::Gone`] if the worker closed before saying anything, [`Error::Protocol`] if it
    /// answered with a version this build does not speak or with anything but
    /// [`WorkerResponse::Ready`], or [`Error::Frame`] on a transport failure.
    pub async fn open(reader: R, writer: W) -> Result<Self> {
        let mut session = Self { reader, writer };
        match read_frame::<_, WorkerResponse>(&mut session.reader).await? {
            Some(WorkerResponse::Ready { protocol }) if protocol == PROTOCOL_VERSION => Ok(session),
            Some(WorkerResponse::Ready { protocol }) => Err(Error::Protocol {
                detail: format!(
                    "worker speaks protocol {protocol}, this build speaks {PROTOCOL_VERSION}"
                ),
            }),
            Some(other) => Err(Error::Protocol {
                detail: format!("expected a ready frame, got {other:?}"),
            }),
            None => Err(Error::Gone),
        }
    }

    /// Bind the session to one tree; every later path is confined beneath it.
    ///
    /// # Errors
    /// [`Error::Worker`] with [`WorkerErrorKind::Protocol`] if the worker refuses the root (it must
    /// be absolute), or the transport arms of [`Error`].
    pub async fn bind(&mut self, apply_root: &Path) -> Result<()> {
        self.request(
            &WorkerRequest::Bind {
                apply_root: apply_root.to_path_buf(),
            },
            &CancellationToken::new(),
            |_| {},
        )
        .await
    }

    /// Apply one patch, optionally advancing a version file after it lands cleanly.
    ///
    /// The worker re-proves `patch` against `admission` before writing anything, so a file swapped
    /// between the parent's verification and this call is rejected rather than applied. `advance` is
    /// written by the worker itself, in the same request: the version file lives in the tree that
    /// needed elevation in the first place, and coupling it to the apply is what makes a torn run
    /// leave the old version behind.
    ///
    /// # Errors
    /// [`Error::Worker`] carrying the worker's own [`WorkerErrorKind`] (a re-verification failure is
    /// [`WorkerErrorKind::Verify`], with nothing written), [`Error::Gone`] if the worker died
    /// mid-apply, [`Error::Cancelled`] if `cancel` fired, or the transport arms of [`Error`].
    pub async fn apply(
        &mut self,
        patch: &Path,
        admission: Admission,
        advance: Option<VersionWrite>,
        cancel: &CancellationToken,
        on_progress: impl FnMut(WorkerProgress),
    ) -> Result<()> {
        self.request(
            &WorkerRequest::Apply {
                patch: patch.to_path_buf(),
                admission,
                advance,
            },
            cancel,
            on_progress,
        )
        .await
    }

    /// Copy one file to another inside the bound tree (the version-file backup).
    ///
    /// # Errors
    /// [`Error::Worker`] if either path leaves the tree or the copy fails, or the transport arms of
    /// [`Error`].
    pub async fn copy_within(&mut self, from: &str, to: &str) -> Result<()> {
        self.request(
            &WorkerRequest::CopyWithin {
                from: from.to_owned(),
                to: to.to_owned(),
            },
            &CancellationToken::new(),
            |_| {},
        )
        .await
    }

    /// Write one request and read it to its terminal response.
    async fn request(
        &mut self,
        request: &WorkerRequest,
        cancel: &CancellationToken,
        mut on_progress: impl FnMut(WorkerProgress),
    ) -> Result<()> {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        write_frame(&mut self.writer, request).await?;

        // Scoped so the completion future's borrow of the reader ends before the cancel arm needs
        // the writer; `select!` keeps every branch alive while a handler runs.
        let settled = {
            let reader = &mut self.reader;
            tokio::select! {
                biased;
                outcome = settle(reader, &mut on_progress) => Some(outcome),
                () = cancel.cancelled() => None,
            }
        };
        match settled {
            Some(outcome) => outcome,
            None => {
                // The worker is mid-apply. Ask it to stop and then read its answer: dropping the
                // stream instead would leave a privileged process still writing into the tree.
                write_frame(&mut self.writer, &WorkerRequest::Cancel).await?;
                match settle(&mut self.reader, &mut on_progress).await {
                    Ok(()) => Err(Error::Cancelled),
                    Err(Error::Worker {
                        kind: WorkerErrorKind::Cancelled,
                        ..
                    }) => Err(Error::Cancelled),
                    Err(other) => Err(other),
                }
            }
        }
    }
}

/// Read responses until the request settles, handing every progress frame to `on_progress`.
async fn settle<R: AsyncRead + Unpin>(
    reader: &mut R,
    on_progress: &mut impl FnMut(WorkerProgress),
) -> Result<()> {
    loop {
        match read_frame::<_, WorkerResponse>(reader).await? {
            Some(WorkerResponse::Progress(p)) => on_progress(p),
            Some(WorkerResponse::Done) => return Ok(()),
            Some(WorkerResponse::Failed {
                kind,
                failed_file,
                detail,
            }) => {
                return Err(Error::Worker {
                    kind,
                    failed_file,
                    detail,
                });
            }
            Some(WorkerResponse::Ready { .. }) => {
                return Err(Error::Protocol {
                    detail: "a second ready frame arrived mid-session".to_owned(),
                });
            }
            // A worker that closed or died between frames is indistinguishable from here and is the
            // same fact to the caller: no answer is coming.
            None => return Err(Error::Gone),
        }
    }
}
