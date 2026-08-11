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
/// Take its [`progress`](Self::progress) channel, [`cancel`](Self::cancel) it, and await its
/// verified result (`job.await` or [`wait`](Self::wait)).
///
/// **Dropping a `Job` detaches it.** The transfer keeps running on its spawned task, finishes or
/// fails on its own, and publishes to the destination on success; nothing outside the fetcher can
/// stop it once the last externally held [`cancel_token`](Self::cancel_token) clone is gone. A
/// caller that wants drop-to-abort semantics holds the token and cancels before letting go.
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

    /// The channel of progress snapshots. Consumable once; a second call yields an already-closed
    /// channel, since a job has a single progress channel.
    ///
    /// A bare receiver rather than a `Stream` wrapper, deliberately: the wrapper's only effect on
    /// this surface was to put a `0.x` crate's type into a frozen signature, and the sibling
    /// `Stream`-returning handles elsewhere in the workspace can wrap a receiver themselves.
    pub fn progress(&mut self) -> mpsc::UnboundedReceiver<Progress> {
        self.progress.take().unwrap_or_else(|| {
            let (_closed, rx) = mpsc::unbounded_channel();
            rx
        })
    }

    /// Request cancellation. The partial file and its journal survive for a later resume.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// A clone of this job's cancellation token, so a driver can bridge an external cancel signal
    /// to the job (cancelling the token stops the run) while still holding the job by value for
    /// [`wait`](Self::wait), which consumes it. Also the only way to stop a job whose handle is
    /// about to be dropped, since dropping detaches rather than cancels.
    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Await the verified result.
    ///
    /// # Errors
    /// A [`FetchError`] for any transfer failure, or [`FetchError::Cancelled`] if the job was
    /// cancelled.
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
