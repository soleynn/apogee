//! The handle to a submitted download.

use std::future::{Future, IntoFuture};
use std::path::PathBuf;
use std::pin::Pin;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::error::FetchError;
use crate::progress::Progress;
use crate::validator::VerifiedFile;

/// A download running on the scheduler, returned by [`Fetcher::submit`](crate::Fetcher::submit).
/// Take its [`progress`](Self::progress) stream, [`cancel`](Self::cancel) it, and await its verified
/// result (`job.await` or [`wait`](Self::wait)).
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

    /// The stream of progress snapshots. Consumable once; a second call yields an already-closed
    /// stream, since a job has a single progress channel.
    pub fn progress(&mut self) -> UnboundedReceiverStream<Progress> {
        let rx = self.progress.take().unwrap_or_else(|| {
            let (_closed, rx) = mpsc::unbounded_channel();
            rx
        });
        UnboundedReceiverStream::new(rx)
    }

    /// Request cancellation. The partial file and its journal survive for a later resume.
    pub fn cancel(&self) {
        self.cancel.cancel();
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
            // The engine never panics by design; surface a task panic as an i/o failure rather than
            // unwinding the caller.
            Err(join) => Err(FetchError::io(PathBuf::new(), std::io::Error::other(join))),
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
