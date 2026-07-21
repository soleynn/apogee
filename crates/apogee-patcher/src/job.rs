//! The handle to a running install.

use std::future::{Future, IntoFuture};
use std::pin::Pin;

use apogee_fetch::Fetcher;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::install;
use crate::progress::PatchProgress;
use crate::request::{InstallRequest, Installed};
use crate::{PatchError, PatcherConfig};

/// A running install, returned by [`Patcher::install`](crate::Patcher::install). Take its
/// [`progress`](Self::progress) stream, [`cancel`](Self::cancel) it, and await its result
/// (`job.await` or [`wait`](Self::wait)).
pub struct Job {
    handle: JoinHandle<Result<Installed, PatchError>>,
    progress: Option<mpsc::UnboundedReceiver<PatchProgress>>,
    cancel: CancellationToken,
}

impl Job {
    /// The stream of progress frames. Consumable once; a second call yields an already-closed
    /// stream, since an install has a single progress channel.
    pub fn progress(&mut self) -> UnboundedReceiverStream<PatchProgress> {
        let rx = self.progress.take().unwrap_or_else(|| {
            let (_closed, rx) = mpsc::unbounded_channel();
            rx
        });
        UnboundedReceiverStream::new(rx)
    }

    /// Request cancellation. In-flight downloads leave their partial file and journal for a later
    /// resume; a torn apply leaves the old `.ver`, so the install re-runs cleanly.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Await the install result.
    ///
    /// # Errors
    /// A [`PatchError`] for any failure, or [`PatchError::Cancelled`] if the install was cancelled.
    pub async fn wait(self) -> Result<Installed, PatchError> {
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

impl IntoFuture for Job {
    type Output = Result<Installed, PatchError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.wait())
    }
}

/// Spawn an install onto the current runtime and hand back its [`Job`].
pub(crate) fn spawn(fetcher: Fetcher, config: PatcherConfig, request: InstallRequest) -> Job {
    let (tx, rx) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let handle =
        tokio::spawn(async move { install::run(fetcher, config, request, tx, token).await });
    Job {
        handle,
        progress: Some(rx),
        cancel,
    }
}
