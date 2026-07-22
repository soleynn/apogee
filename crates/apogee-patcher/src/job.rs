//! The handle to a running install or repair.

use std::future::{Future, IntoFuture};
use std::pin::Pin;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::PatchError;
use crate::progress::PatchProgress;

/// A running patch operation, returned by [`Patcher::install`](crate::Patcher::install) (`T =
/// Installed`) or [`Patcher::repair`](crate::Patcher::repair) (`T = RepairOutcome`). Take its
/// [`progress`](Self::progress) stream, [`cancel`](Self::cancel) it, and await its result
/// (`job.await` or [`wait`](Self::wait)).
pub struct Job<T> {
    handle: JoinHandle<Result<T, PatchError>>,
    progress: Option<mpsc::UnboundedReceiver<PatchProgress>>,
    cancel: CancellationToken,
}

impl<T> Job<T> {
    /// The stream of progress frames. Consumable once; a second call yields an already-closed
    /// stream, since an operation has a single progress channel.
    pub fn progress(&mut self) -> UnboundedReceiverStream<PatchProgress> {
        let rx = self.progress.take().unwrap_or_else(|| {
            let (_closed, rx) = mpsc::unbounded_channel();
            rx
        });
        UnboundedReceiverStream::new(rx)
    }

    /// Request cancellation. In-flight downloads leave their partial file and journal for a later
    /// resume; a torn apply leaves the old `.ver`, so the operation re-runs cleanly.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Await the operation result.
    ///
    /// # Errors
    /// A [`PatchError`] for any failure, or [`PatchError::Cancelled`] if it was cancelled.
    pub async fn wait(self) -> Result<T, PatchError> {
        match self.handle.await {
            Ok(result) => result,
            Err(join) if join.is_cancelled() => Err(PatchError::Cancelled),
            // The orchestrator never panics by design; surface a task panic as an i/o failure rather
            // than unwinding the caller.
            Err(join) => Err(PatchError::Io {
                path: std::path::PathBuf::new(),
                source: std::io::Error::other(join),
            }),
        }
    }
}

impl<T: Send + 'static> IntoFuture for Job<T> {
    type Output = Result<T, PatchError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.wait())
    }
}

/// Spawn an operation onto the current runtime and hand back its [`Job`]. `make` is handed the
/// progress sender and the run's cancellation token and returns the operation future.
pub(crate) fn spawn<T, Fut>(
    make: impl FnOnce(mpsc::UnboundedSender<PatchProgress>, CancellationToken) -> Fut,
) -> Job<T>
where
    Fut: Future<Output = Result<T, PatchError>> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let fut = make(tx, cancel.clone());
    let handle = tokio::spawn(fut);
    Job {
        handle,
        progress: Some(rx),
        cancel,
    }
}
