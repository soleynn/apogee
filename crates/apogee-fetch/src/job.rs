//! The handle to a submitted download.

use std::future::{Future, IntoFuture};
use std::pin::Pin;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::FetchError;
use crate::progress::Progress;
use crate::validator::VerifiedFile;

/// A download running on the scheduler, returned by [`Fetcher::submit`](crate::Fetcher::submit).
/// Take its [`progress`](Self::progress) channel, [`cancel`](Self::cancel) it, and await its verified
/// result with `job.await` or [`wait`](Self::wait).
///
/// **Dropping a `Job` detaches it**: the transfer keeps running on its own task and still publishes to
/// the destination on success; nothing outside the fetcher can stop it once the last externally held
/// [`cancel_token`](Self::cancel_token) clone is gone. A caller that wants drop-to-abort semantics
/// should hold a [`cancel_token`](Self::cancel_token) clone and cancel it before letting the job go.
///
/// # Examples
///
/// ```
/// # async fn demo(mut job: apogee_fetch::Job) -> Result<(), apogee_fetch::FetchError> {
/// let _progress = job.progress();
/// let _token = job.cancel_token();
///
/// let verified = job.wait().await?;
/// let _path = verified.path();
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Job {
    handle: JoinHandle<Result<VerifiedFile, FetchError>>,
    progress: Option<mpsc::UnboundedReceiver<Progress>>,
    cancel: CancellationToken,
}

impl Job {
    pub(crate) fn new(
        handle: JoinHandle<Result<VerifiedFile, FetchError>>,
        progress: mpsc::UnboundedReceiver<Progress>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            handle,
            progress: Some(progress),
            cancel,
        }
    }

    /// The channel of progress snapshots. Consumable once: a second call returns an already-closed
    /// channel, since a job has one progress channel.
    pub fn progress(&mut self) -> mpsc::UnboundedReceiver<Progress> {
        // A bare receiver rather than a `Stream` wrapper: wrapping here would pin a `0.x` crate's
        // type into this frozen signature. A caller that wants a `Stream` can wrap the receiver
        // itself, the same way the workspace's other `Stream`-returning handles do.
        self.progress.take().unwrap_or_else(|| {
            let (_closed, rx) = mpsc::unbounded_channel();
            rx
        })
    }

    /// Request cancellation. The partial file and its journal survive for a later resume.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// A clone of this job's cancellation token, so a driver can bridge an external cancel signal to
    /// the job while still holding the job by value for [`wait`](Self::wait), which consumes it. Also
    /// the only way to stop a job whose handle is about to be dropped, since dropping detaches rather
    /// than cancels.
    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Await the verified result.
    ///
    /// # Errors
    ///
    /// A [`FetchError`] for any transfer failure, [`FetchError::Cancelled`] specifically if the job
    /// was cancelled, or [`FetchError::Internal`] if the transfer task itself panicked.
    pub async fn wait(self) -> Result<VerifiedFile, FetchError> {
        match self.handle.await {
            Ok(result) => result,
            Err(join) if join.is_cancelled() => Err(FetchError::Cancelled),
            // The engine never panics by design; surface a task panic as the engine defect it is
            // rather than unwinding the caller.
            Err(join) => Err(FetchError::Internal {
                detail: "the transfer task panicked",
                source: std::io::Error::other(join),
            }),
        }
    }
}

impl IntoFuture for Job {
    type Output = Result<VerifiedFile, FetchError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.wait())
    }
}
