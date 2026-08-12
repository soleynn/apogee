#![forbid(unsafe_code)]
//! The privileged patch worker.
//!
//! Started by the launcher when the install tree is not writable by the user, and never run by hand.
//! It reads a request stream, applies local patch files it re-verifies itself, and answers with
//! typed progress and a typed result. It fetches nothing, decides nothing, and outlives nothing: it
//! exits when the launcher closes the stream.
//!
//! Two transports, chosen by the one argument it takes. `--stdio` speaks the protocol over its own
//! standard streams, which is what an ordinary child gets. `--pipe <name>` connects back to a named
//! pipe the launcher created, which is the only shape available when the process was started through
//! a shell verb that raises privileges and therefore has nowhere to put a redirected handle.

use std::process::ExitCode;

use apogee_elevate::spawn::{PIPE_ARG, STDIO_ARG};

/// How the worker was told to reach the launcher.
enum Transport {
    /// This process's own standard streams.
    Stdio,
    /// A named pipe the launcher is already listening on.
    Pipe(String),
}

fn main() -> ExitCode {
    let transport = match parse(std::env::args().skip(1)) {
        Ok(transport) => transport,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };

    // A current-thread runtime: the worker handles one request at a time and the apply itself runs
    // on the blocking pool, so extra worker threads would buy nothing.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("apogee-elevated: cannot start a runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(transport)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("apogee-elevated: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Serve until the launcher goes away.
async fn run(transport: Transport) -> Result<(), Box<dyn std::error::Error>> {
    match transport {
        Transport::Stdio => {
            Ok(apogee_elevate::serve(tokio::io::stdin(), tokio::io::stdout()).await?)
        }
        Transport::Pipe(name) => connect_back(&name).await,
    }
}

/// Connect to the pipe the launcher named and serve over it.
#[cfg(windows)]
async fn connect_back(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pipe = tokio::net::windows::named_pipe::ClientOptions::new().open(name)?;
    let (reader, writer) = tokio::io::split(pipe);
    Ok(apogee_elevate::serve(reader, writer).await?)
}

/// Off Windows there is no elevation model and nothing creates such a pipe, so this refuses rather
/// than standing up a second transport with no caller.
#[cfg(not(windows))]
async fn connect_back(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err(format!("this platform has no pipe transport, so {name} cannot be reached").into())
}

/// Read the one argument, or say how to call it.
///
/// Hand-rolled rather than taken from an argument parser: two forms is not a command line, and this
/// binary's dependency list is a statement about what a privileged process can reach.
fn parse(mut args: impl Iterator<Item = String>) -> Result<Transport, String> {
    let usage =
        || format!("apogee-elevated: usage: apogee-elevated ({STDIO_ARG} | {PIPE_ARG} <name>)");
    let first = args.next().ok_or_else(usage)?;
    let transport = match first.as_str() {
        STDIO_ARG => Transport::Stdio,
        PIPE_ARG => Transport::Pipe(args.next().ok_or_else(usage)?),
        _ => return Err(usage()),
    };
    if args.next().is_some() {
        return Err(usage());
    }
    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Transport, String> {
        parse(args.iter().map(|s| (*s).to_owned()))
    }

    /// Exactly the two accepted forms parse, and anything else is a usage error rather than a
    /// silently ignored argument.
    #[test]
    fn only_the_two_transports_parse() {
        assert!(matches!(parsed(&[STDIO_ARG]), Ok(Transport::Stdio)));
        assert!(matches!(
            parsed(&[PIPE_ARG, r"\\.\pipe\x"]),
            Ok(Transport::Pipe(name)) if name == r"\\.\pipe\x"
        ));
        assert!(parsed(&[]).is_err());
        assert!(parsed(&[PIPE_ARG]).is_err());
        assert!(parsed(&[STDIO_ARG, "extra"]).is_err());
        assert!(parsed(&["--apply", "/etc"]).is_err());
    }
}
