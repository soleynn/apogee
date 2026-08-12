//! Starting a worker and getting a stream to it.
//!
//! Two transports, and the difference between them is the whole platform story. A direct child gets
//! its standard streams piped, which is all that is ever needed where the install tree is already
//! writable. Elevating on Windows cannot use those streams at all: the call that raises privileges
//! is a shell verb, and a shell verb has nowhere to put a redirected handle. So the parent creates a
//! named pipe first, hands the name to the child in its arguments, and the child connects back.
//!
//! Everything above this module is written against the two halves of a stream, so the transport is
//! the only part that differs and the protocol, the worker and the tests are shared.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};

use crate::client::Session;
use crate::error::{Error, Result};

/// The argument that puts a worker on its own standard streams.
pub const STDIO_ARG: &str = "--stdio";

/// The argument that names the pipe a worker must connect back on.
pub const PIPE_ARG: &str = "--pipe";

/// How long to wait for an elevated child to connect back.
///
/// Generous because the wait includes a consent dialog that a person has to read and answer. It is
/// still bounded: a request that is never answered has to end as a typed failure rather than as a
/// launcher that hangs.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(180);

/// The reader half of a worker stream.
pub type WorkerRead = Box<dyn AsyncRead + Send + Unpin>;
/// The writer half of a worker stream.
pub type WorkerWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// A running worker: the session that speaks to it, and the process behind it.
///
/// Boxed halves rather than a type parameter, because the caller holds one of these across a whole
/// install and the two transports produce unrelated stream types.
pub struct Worker {
    session: Session<WorkerRead, WorkerWrite>,
    process: Child,
}

impl Worker {
    /// The session to drive.
    pub fn session(&mut self) -> &mut Session<WorkerRead, WorkerWrite> {
        &mut self.session
    }

    /// Close the stream, wait for the process, and describe how it ended.
    ///
    /// Returns `None` when it exited successfully. Call it after a failure to turn "the worker
    /// stopped answering" into something naming the exit status, which is the only detail a
    /// crashed worker leaves behind.
    pub async fn finish(self) -> Option<String> {
        let Self {
            session,
            mut process,
        } = self;
        // Dropping the session closes the parent's end, which is how a worker is told to exit.
        drop(session);
        match process.wait().await {
            Ok(status) if status.success() => None,
            Ok(status) => Some(format!("the worker process ended with {status}")),
            Err(e) => Some(format!("the worker process could not be waited for: {e}")),
        }
    }
}

/// Start a worker as an ordinary child of this process, over its standard streams.
///
/// It runs with this process's privileges: use it where the tree is already writable, or where the
/// caller has arranged privileges itself.
///
/// # Errors
/// [`Error::Spawn`] if `binary` cannot be started or its streams cannot be taken, and the handshake
/// arms of [`Session::open`].
pub async fn direct(binary: &Path) -> Result<Worker> {
    let spawn_failed = |detail: String, source: Option<std::io::Error>| Error::Spawn {
        detail: format!("{}: {detail}", binary.display()),
        source,
    };
    let mut process = Command::new(binary)
        .arg(STDIO_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Inherited on purpose: the worker's tracing output goes there, and a launcher that
        // swallowed it would lose the only diagnostics a failed privileged apply leaves.
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| spawn_failed("cannot start the worker".to_owned(), Some(e)))?;

    let (Some(stdout), Some(stdin)) = (process.stdout.take(), process.stdin.take()) else {
        return Err(spawn_failed(
            "the worker's standard streams were not piped".to_owned(),
            None,
        ));
    };
    let session = Session::open(
        Box::new(stdout) as WorkerRead,
        Box::new(stdin) as WorkerWrite,
    )
    .await?;
    Ok(Worker { session, process })
}

/// Start a worker with raised privileges, and take the stream it connects back on.
///
/// The consent prompt belongs to the platform: this asks for elevation and waits, it does not
/// suppress, retry or work around a refusal. A user who declines gets [`Error::Spawn`] carrying
/// what the shell reported.
///
/// # Errors
/// [`Error::Spawn`] if the pipe cannot be created, the elevation request is refused, or no worker
/// connects within [`CONNECT_TIMEOUT`], and the handshake arms of [`Session::open`].
#[cfg(windows)]
pub async fn elevated(binary: &Path) -> Result<Worker> {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    let spawn_failed = |detail: String, source: Option<std::io::Error>| Error::Spawn {
        detail: format!("{}: {detail}", binary.display()),
        source,
    };

    // The name is a nonce so a listener cannot be squatted before this one creates it, and
    // `first_pipe_instance` makes a name that somehow already exists an error rather than a second
    // instance of someone else's pipe. The default access control on a pipe created here admits the
    // same user's elevated process, which is exactly the one hop that has to work.
    let name = format!(r"\\.\pipe\apogee-elevate-{}", uuid::Uuid::new_v4().simple());
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .map_err(|e| spawn_failed("cannot create the worker pipe".to_owned(), Some(e)))?;

    let mut process = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-NoLogo",
            "-Command",
            &elevate_script(binary, &name),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| spawn_failed("cannot run the elevation shell".to_owned(), Some(e)))?;
    let mut complaint = process.stderr.take();

    // Three ways this ends: the worker connects, the shell gives up first (a declined prompt is the
    // common one), or nobody answers at all.
    tokio::select! {
        connected = server.connect() => {
            connected.map_err(|e| spawn_failed("the worker pipe failed".to_owned(), Some(e)))?;
        }
        status = process.wait() => {
            let status = status.ok();
            // A person saying no is not a failure to report as one. The shell turns that one case
            // into its own exit code so it can be told apart from a worker that could not start.
            if status.and_then(|s| s.code()) == Some(CONSENT_DECLINED) {
                return Err(Error::Cancelled);
            }
            let mut said = String::new();
            if let Some(stderr) = complaint.as_mut() {
                let _ = stderr.read_to_string(&mut said).await;
            }
            let status = status.map_or_else(
                || "an unknown status".to_owned(),
                |status| status.to_string(),
            );
            let said = said.trim();
            return Err(spawn_failed(
                if said.is_empty() {
                    format!("the elevation request ended with {status} before the worker connected")
                } else {
                    format!("the elevation request failed ({status}): {said}")
                },
                None,
            ));
        }
        () = tokio::time::sleep(CONNECT_TIMEOUT) => {
            return Err(spawn_failed(
                format!("no worker connected within {CONNECT_TIMEOUT:?}"),
                None,
            ));
        }
    }

    let (reader, writer) = tokio::io::split(server);
    let session = Session::open(
        Box::new(reader) as WorkerRead,
        Box::new(writer) as WorkerWrite,
    )
    .await?;
    // The shell waits on the elevated child and re-reports its exit code, so this handle stands in
    // for a process this one is not allowed to hold directly.
    Ok(Worker { session, process })
}

/// The exit code the elevation script reports when the user declined the prompt.
///
/// Windows raises `ERROR_CANCELLED` for a refused consent dialog, and the script re-reports that
/// number rather than inventing one, so the value in the log is the one the platform used. Chosen
/// out of the range a worker can produce: the worker only ever returns success, one, or two.
#[cfg(windows)]
const CONSENT_DECLINED: i32 = 1223;

/// The one-line script that raises privileges and re-reports the worker's exit code.
///
/// `Start-Process -Verb RunAs` is the whole reason a shell is involved: raising privileges is a
/// shell verb, and no process-creation call that this workspace can reach in safe Rust performs it.
/// Doing it through PowerShell keeps the crate free of foreign-function linkage, which is a
/// workspace-wide rule rather than a preference here. `-Wait -PassThru` is what turns the shell into
/// a stand-in for a child this process may not hold a handle to.
///
/// The `catch` exists so that declining the prompt is distinguishable from every other way the
/// request can fail. Without it both arrive as a nonzero exit with a message, and a caller cannot
/// tell a user who said no from a worker that would not start, which is the difference between
/// reporting a stopped operation and reporting a crash.
#[cfg(windows)]
fn elevate_script(binary: &Path, pipe: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; \
         try {{ \
           $p = Start-Process -FilePath {} -ArgumentList {},{} -Verb RunAs -PassThru -Wait; \
           exit $p.ExitCode \
         }} catch [System.ComponentModel.Win32Exception] {{ \
           if ($_.Exception.NativeErrorCode -eq {CONSENT_DECLINED}) {{ exit {CONSENT_DECLINED} }} \
           throw \
         }}",
        single_quote(&binary.display().to_string()),
        single_quote(PIPE_ARG),
        single_quote(pipe),
    )
}

/// Quote a value as a PowerShell single-quoted string.
///
/// Single quotes are the literal form: nothing inside is expanded, so a path is never read as a
/// variable or a subexpression, and the one character that needs escaping is the quote itself,
/// doubled.
#[cfg(windows)]
fn single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// The generated script quotes both the binary and the pipe name, so an install path with
    /// spaces or a quote in it cannot break the command apart or inject another one.
    #[test]
    fn the_elevation_script_quotes_every_value_it_interpolates() {
        let script = elevate_script(
            Path::new(r"C:\Program Files\Apogee's Launcher\apogee-elevated.exe"),
            r"\\.\pipe\apogee-elevate-abc",
        );
        assert!(
            script.contains(r"'C:\Program Files\Apogee''s Launcher\apogee-elevated.exe'"),
            "{script}"
        );
        assert!(
            script.contains(r"'\\.\pipe\apogee-elevate-abc'"),
            "{script}"
        );
        assert!(script.contains("-Verb RunAs"), "{script}");
    }

    /// A value carrying shell metacharacters stays one literal argument.
    #[test]
    fn a_quote_in_a_path_is_doubled_rather_than_closing_the_string() {
        assert_eq!(single_quote("a'; rm -rf /; '"), "'a''; rm -rf /; '''");
        assert_eq!(single_quote("$(whoami)"), "'$(whoami)'");
    }
}
