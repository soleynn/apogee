//! Out-of-process oracle runner. Invokes a pinned reference build as a separate process and
//! captures its stdout, so reference values can be authored into committed fixtures without the
//! reference ever entering this workspace's build graph.
//!
//! Feature-gated (`oracle`) and never on the CI path: authoring runs on a developer machine or a
//! dedicated job. This module carries no reference-launcher code; the caller supplies the program
//! and arguments (e.g. `dotnet run` against an authoring shim).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

/// Oracle invocation failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OracleError {
    #[error("failed to spawn {program:?}")]
    Spawn {
        program: OsString,
        #[source]
        source: std::io::Error,
    },
    #[error("{program:?} exited with {code}: {stderr}")]
    NonZeroExit {
        program: OsString,
        code: i32,
        stderr: String,
    },
}

/// A configured out-of-process invocation. Build it up, then [`run`](Self::run) it.
#[derive(Debug, Clone)]
pub struct OracleRunner {
    program: OsString,
    args: Vec<OsString>,
    current_dir: Option<PathBuf>,
}

impl OracleRunner {
    /// Start a runner for `program` (e.g. `"dotnet"`).
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
        }
    }

    /// Append one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Append several arguments.
    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Self {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Run in `dir`.
    #[must_use]
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.current_dir = Some(dir.as_ref().to_owned());
        self
    }

    /// Spawn the process, wait, and return its raw stdout. A non-zero exit is an error carrying the
    /// captured stderr.
    ///
    /// There is no wall-clock timeout: a child that never exits blocks until the caller aborts it.
    /// That is acceptable for this interactive authoring path; a wired-in job would add its own bound.
    pub fn run(&self) -> Result<Vec<u8>, OracleError> {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);
        if let Some(dir) = &self.current_dir {
            cmd.current_dir(dir);
        }
        let output = cmd.output().map_err(|source| OracleError::Spawn {
            program: self.program.clone(),
            source,
        })?;
        if !output.status.success() {
            return Err(OracleError::NonZeroExit {
                program: self.program.clone(),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(output.stdout)
    }
}
