//! Confirming that what a launch was redirected through actually came up inside the game.
//!
//! A loader reports its own verdict by exiting with a status, and on a container-style runner that
//! status never reaches the launcher: what was spawned is the runner, which outlives the session, and
//! the loader finishes inside it. So the launcher's own reading has to come from somewhere else.
//!
//! It comes from a file. The launcher tells the injector where to write its boot log, that log is
//! written from *inside* the game process, and it lands on the host filesystem whatever runner the
//! prefix uses. A write to it after this launch began is therefore proof the payload is in the game,
//! and it is a stronger claim than the loader's own status, which is only what the loader believed on
//! its way out.
//!
//! Reading it back is not a dependency on somebody else's format: the path is one this crate chose and
//! passed in, and nothing here parses a byte of what it contains. The question asked is only whether it
//! was written.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio_util::sync::CancellationToken;

use crate::external::{AddonEvent, AddonEvents};

/// How often the file is checked. Small enough that the report lands while a user is still looking at
/// the launcher, large enough that a bounded wait is a handful of stats rather than thousands.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// What a launch is watching for, owned so it can outlive the call that made it.
///
/// Owned rather than borrowing the addon layer, because the wait outlasts the launch step that starts
/// it: the game is up, the setup pass is over, and the thing being waited on happens seconds later
/// inside a process this launcher did not start.
#[derive(Debug, Clone)]
pub struct LoadEvidence {
    /// What to call it in the report.
    what: String,
    /// The file whose being written is the proof.
    path: PathBuf,
    /// The launch's own starting point. A write older than this belongs to a previous session: the
    /// boot log is appended to across runs rather than truncated, so its mere existence proves nothing.
    since: SystemTime,
    /// How long absence stays "not yet" before it is reported as such.
    window: Duration,
}

impl LoadEvidence {
    /// Watch `path`, reporting under `what`, counting only writes after `since`.
    #[must_use]
    pub fn new(what: impl Into<String>, path: impl Into<PathBuf>, since: SystemTime) -> Self {
        Self {
            what: what.into(),
            path: path.into(),
            since,
            window: Duration::from_secs(90),
        }
    }

    /// Wait a different length of time. The default is 90 seconds, which is the game's own start-up
    /// time on a cold prefix plus room to spare, measured against a real client rather than guessed.
    #[must_use]
    pub fn within(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// The file being watched.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Poll until the proof appears, the window closes, or `cancel` fires.
    ///
    /// Consuming, because a watch is one launch's question and asking it twice would report twice. It
    /// reports on both outcomes for the same reason the loader's exit status is reported on success:
    /// a companion that loaded and one that never ran are indistinguishable from outside the game, so
    /// silence would mean both. A cancelled watch reports neither, which is the honest answer: both
    /// readings are only worth having while the session they are about is still running.
    ///
    /// The token is owned rather than borrowed because this is spawned, and a borrow cannot outlive
    /// the call that starts the wait. Without one the only way to stop it is to abort the task, which
    /// makes a task something every caller has to keep rather than something it may choose.
    pub async fn watch(self, cancel: CancellationToken, events: AddonEvents) {
        let started = SystemTime::now();
        loop {
            if self.written_since() {
                events.emit(AddonEvent::Loaded { what: self.what });
                return;
            }
            let waited = started.elapsed().unwrap_or_default();
            if waited >= self.window {
                events.emit(AddonEvent::NotConfirmed {
                    what: self.what,
                    waited,
                    evidence: self.path,
                });
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(POLL_INTERVAL) => {}
                () = cancel.cancelled() => return,
            }
        }
    }

    /// Whether the file has been written since this launch began.
    ///
    /// A file that cannot be read counts as not written. Every reason it might not be (absent, a
    /// directory that was never created, a filesystem with no modification time) is the same answer to
    /// the only question being asked, and none of them is worth failing a launch over.
    fn written_since(&self) -> bool {
        std::fs::metadata(&self.path)
            .and_then(|meta| meta.modified())
            .is_ok_and(|written| written > self.since)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A file written after the launch began is the proof, and it is reported under the name the
    /// caller gave rather than the file's.
    #[tokio::test]
    async fn a_write_after_the_launch_began_is_proof_it_loaded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("boot.log");
        let since = SystemTime::now() - Duration::from_secs(60);
        std::fs::write(&log, b"loaded").expect("write");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        LoadEvidence::new("Dalamud", &log, since)
            .watch(CancellationToken::new(), AddonEvents::new(tx))
            .await;

        match rx.try_recv().expect("a report") {
            AddonEvent::Loaded { what } => assert_eq!(what, "Dalamud"),
            other => panic!("{other:?}"),
        }
    }

    /// The boot log is appended to across runs rather than truncated, so a file left by an earlier
    /// session is present and proves nothing. Reading its existence as proof is how a launch that
    /// loaded nothing would report success forever after the first one that did.
    #[tokio::test]
    async fn a_file_left_by_an_earlier_session_is_not_proof() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("boot.log");
        std::fs::write(&log, b"from the run before").expect("write");
        // The launch begins after that write.
        let since = SystemTime::now() + Duration::from_secs(1);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        LoadEvidence::new("Dalamud", &log, since)
            .within(Duration::from_millis(1))
            .watch(CancellationToken::new(), AddonEvents::new(tx))
            .await;

        match rx.try_recv().expect("a report") {
            AddonEvent::NotConfirmed { what, evidence, .. } => {
                assert_eq!(what, "Dalamud");
                assert_eq!(evidence, log, "the report names the file it watched");
            }
            other => panic!("{other:?}"),
        }
    }

    /// Nothing there at all is the ordinary shape of a companion that never ran, and it is reported as
    /// unconfirmed rather than as a failure: the game is running either way and may still be starting.
    #[tokio::test]
    async fn a_file_that_never_appears_is_unconfirmed_rather_than_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        LoadEvidence::new("Dalamud", dir.path().join("never"), SystemTime::now())
            .within(Duration::from_millis(1))
            .watch(CancellationToken::new(), AddonEvents::new(tx))
            .await;

        assert!(matches!(
            rx.try_recv().expect("a report"),
            AddonEvent::NotConfirmed { .. }
        ));
    }

    /// The wait ends the moment the proof lands rather than running the window out, so the report
    /// reaches a user while they are still watching the launcher.
    #[tokio::test]
    async fn the_wait_ends_as_soon_as_the_proof_lands() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("boot.log");
        let since = SystemTime::now() - Duration::from_secs(60);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let writing = tokio::spawn({
            let log = log.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                std::fs::write(&log, b"loaded").expect("write");
            }
        });
        // Far longer than the write takes: finishing early is the property under test.
        LoadEvidence::new("Dalamud", &log, since)
            .within(Duration::from_secs(30))
            .watch(CancellationToken::new(), AddonEvents::new(tx))
            .await;
        writing.await.expect("writer");

        assert!(matches!(
            rx.try_recv().expect("a report"),
            AddonEvent::Loaded { .. }
        ));
    }
}
