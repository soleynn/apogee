//! What the crate says to a log subscriber when a transfer has to recover.
//!
//! The counters on the progress stream say how many; these say which source, which offset and what
//! went wrong, which is the half a maintainer reading a bug report needs and a progress bar does
//! not. Asserted rather than assumed because a `tracing` call with no subscriber is a no-op, so a
//! site that lost its event, or a field renamed out from under a grep, would fail nothing.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, RetryPolicy, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;

const MIB: u64 = 1024 * 1024;

/// A writer that collects formatted events in memory for the assertions below.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        held.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A current-thread runtime is what makes this capture work: `with_default` installs the subscriber
/// for the calling thread only, so a multi-threaded transfer would emit some of its events on
/// threads that cannot see it. The single-connection engine spawns no tasks of its own, so every
/// event it raises is raised here.
///
/// # Errors
/// Anything that stops the transfer reaching its recovery: a spec the builder refuses, a runtime
/// that will not start, or a download that failed outright instead of recovering.
fn capture_single_connection_download(
    server: &ChaosServer,
    dest: &std::path::Path,
    seed: u64,
    len: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(capture.clone())
                .with_ansi(false),
        )
        .with("apogee_fetch=debug".parse::<Targets>()?);

    // No declared length, so the transfer runs on the single-connection engine.
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        dest,
        Validator::Sha256(body_sha256(seed, len)),
    )
    .build()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            Fetcher::builder()
                .max_connections_per_file(1)
                .retry_policy(
                    RetryPolicy::default()
                        .base_delay(Duration::from_millis(1))
                        .max_delay(Duration::from_millis(5)),
                )
                .stall_timeout(Duration::from_millis(250))
                .build()?
                .download(&spec, None, CancellationToken::new())
                .await?;
            Ok::<(), FetchError>(())
        })
    })?;
    Ok(capture.text())
}

#[test]
fn a_cut_off_body_logs_the_source_the_offset_and_the_cause() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let dest = dir.path().join("out.bin");
    let len = 8 * MIB;
    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    let server = runtime.block_on(async {
        ChaosServer::builder(80, len)
            .drop_after(2 * MIB)
            .chunk(64 * 1024)
            .start()
            .await
            .expect("a chaos server")
    });

    let logged = capture_single_connection_download(&server, &dest, 80, len).unwrap();

    assert!(
        logged.contains("the body was cut off; resuming after a backoff"),
        "no retry event was logged:\n{logged}",
    );
    // The fields are the whole point: an event that says only "retrying" answers nothing a counter
    // did not already.
    for field in ["url=", "attempts=", "at_bytes=", "delay_ms=", "reason="] {
        assert!(logged.contains(field), "{field} missing from:\n{logged}");
    }
}

#[test]
fn a_silent_source_logs_the_deadline_it_passed() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let dest = dir.path().join("out.bin");
    let len = 8 * MIB;
    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    let server = runtime.block_on(async {
        ChaosServer::builder(81, len)
            .stall_after(2 * MIB)
            .chunk(64 * 1024)
            .start()
            .await
            .expect("a chaos server")
    });

    let logged = capture_single_connection_download(&server, &dest, 81, len).unwrap();

    assert!(
        logged.contains("the body went quiet past the inactivity timeout"),
        "no stall event was logged:\n{logged}",
    );
    assert!(
        logged.contains("timeout_ms=250"),
        "the stall event did not name the deadline it passed:\n{logged}",
    );
    // A stall costs an attempt, so the retry it paid for is on the same log.
    assert!(
        logged.contains("resuming after a backoff"),
        "the retry the stall cost was not logged:\n{logged}",
    );
}

/// The control arm: a healthy transfer says nothing at `debug`, so the events above are the fault
/// and not the traffic. Without this, a crate that logged every chunk would pass both tests.
#[test]
fn a_healthy_transfer_logs_nothing_to_triage() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let dest = dir.path().join("out.bin");
    let len = 8 * MIB;
    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    let server = runtime.block_on(async {
        ChaosServer::builder(82, len)
            .chunk(64 * 1024)
            .start()
            .await
            .expect("a chaos server")
    });

    let logged = capture_single_connection_download(&server, &dest, 82, len).unwrap();

    assert!(
        logged.trim().is_empty(),
        "a transfer with nothing wrong logged:\n{logged}",
    );
}
