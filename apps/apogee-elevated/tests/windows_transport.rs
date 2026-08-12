#![cfg(windows)]
//! The two Windows-only pieces: the named-pipe transport, and the elevation hop itself.
//!
//! # What these prove, and what they do not
//!
//! The pipe test proves the whole conversation over the transport that actually ships on this
//! platform: the worker's `--pipe` argument, the connect-back, the framing over a pipe rather than
//! over standard streams, a real apply, and a version file written into a real Windows tree.
//!
//! The hop test proves the plumbing around raising privileges: that the shell command is built and
//! quoted so the worker really starts, that it is handed the pipe name it needs, and that it
//! connects back. It does **not** prove the consent experience. A hosted runner's agent already
//! holds an administrator token, so the request is granted without a dialog and without an integrity
//! transition, and both are the parts a person would actually see. Neither this test nor any other
//! in this repository has run the prompt a user gets.

use std::error::Error;
use std::path::{Path, PathBuf};

use apogee_elevate::{Admission, Session, VersionWrite};
use apogee_zipatch::fixtures;
use sha1::{Digest, Sha1};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio_util::sync::CancellationToken;

/// The version file the fixtures advance, relative to the bound tree.
const VER: &str = "ffxivgame.ver";

/// The block width the synthetic digests are taken over.
const BLOCK_SIZE: usize = 64;

fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apogee-elevated"))
}

fn block_sha1(bytes: &[u8]) -> Admission {
    Admission::BlockSha1 {
        block_size: BLOCK_SIZE as u32,
        hashes: bytes
            .chunks(BLOCK_SIZE)
            .map(|block| {
                Sha1::digest(block)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            })
            .collect(),
    }
}

fn version() -> Option<VersionWrite> {
    Some(VersionWrite {
        path: VER.to_owned(),
        contents: "2024.01.01.0000.0000".to_owned(),
    })
}

/// Apply one fixture patch over an already-open session and check the tree it left.
async fn apply_and_check<R, W>(
    session: &mut Session<R, W>,
    root: &Path,
    patch: &Path,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    session.bind(root).await?;
    let mut frames = 0usize;
    session
        .apply(
            patch,
            block_sha1(bytes),
            version(),
            &CancellationToken::new(),
            |_| frames += 1,
        )
        .await?;
    session.copy_within(VER, "ffxivgame.bck").await?;

    if !root.join(fixtures::DAT0_PATH).exists() {
        return Err("the patch did not reach the sink".into());
    }
    if std::fs::read_to_string(root.join(VER))? != "2024.01.01.0000.0000" {
        return Err("the version file did not advance".into());
    }
    if std::fs::read_to_string(root.join("ffxivgame.bck"))? != "2024.01.01.0000.0000" {
        return Err("the backup was not taken".into());
    }
    if frames == 0 {
        return Err("no progress frame crossed the transport".into());
    }
    Ok(())
}

/// The worker reached over a named pipe applies a patch and writes the version file.
///
/// The pipe is created here rather than through the elevation helper because that helper also raises
/// privileges, which is the part this test is deliberately not exercising. Three lines of
/// `ServerOptions` are duplicated as a result; the connect-back and everything after it is the
/// shipping code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_serves_a_patch_over_a_named_pipe() -> Result<(), Box<dyn Error>> {
    let patch = fixtures::patch_a();
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let path = store.path().join("p.patch");
    std::fs::write(&path, &patch)?;

    let name = format!(r"\\.\pipe\apogee-elevate-test-{}", std::process::id());
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)?;
    let mut child = tokio::process::Command::new(worker())
        .args(["--pipe", &name])
        .kill_on_drop(true)
        .spawn()?;
    server.connect().await?;

    let (reader, writer) = tokio::io::split(server);
    let mut session = Session::open(reader, writer).await?;
    apply_and_check(&mut session, root.path(), &path, &patch).await?;

    // Closing the parent's end is how a worker is told to stop; it must then exit on its own.
    drop(session);
    let status = child.wait().await?;
    assert!(status.success(), "the worker exited with {status}");
    Ok(())
}

/// The elevation request starts the worker, hands it the pipe name, and gets a working session.
///
/// See the module note: on a hosted runner this grants silently, so what is proven here is the
/// plumbing and the quoting, not the consent path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_elevation_request_reaches_a_working_worker() -> Result<(), Box<dyn Error>> {
    let patch = fixtures::patch_a();
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let path = store.path().join("p.patch");
    std::fs::write(&path, &patch)?;

    let mut worker = apogee_elevate::spawn::elevated(&worker()).await?;
    apply_and_check(worker.session(), root.path(), &path, &patch).await?;
    assert_eq!(
        worker.finish().await,
        None,
        "the elevated worker did not exit cleanly"
    );
    Ok(())
}

/// A worker binary that is not there is a typed spawn failure carrying what the shell said, rather
/// than a hang waiting for a connection that will never come.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_absent_worker_binary_fails_the_elevation_request() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("no-such-worker.exe");
    let err = apogee_elevate::spawn::elevated(&missing)
        .await
        .err()
        .ok_or("an absent worker binary must not produce a session")?;
    assert!(
        matches!(err, apogee_elevate::Error::Spawn { .. }),
        "got {err:?}"
    );
    Ok(())
}
