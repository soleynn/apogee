//! The launch description and its prepared prefix.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::catalog::RunnerKind;

/// A handle to an installed runner on disk plus how to spawn through it.
#[derive(Debug, Clone)]
pub struct RunnerHandle {
    pub(crate) dir: PathBuf,
    pub(crate) kind: RunnerKind,
    pub(crate) name: String,
}

impl RunnerHandle {
    /// The installed runner directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The runner kind (Proton-via-umu, plain wine, or a custom directory).
    #[must_use]
    pub fn kind(&self) -> RunnerKind {
        self.kind
    }

    /// The runner name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A prepared prefix: the `WINEPREFIX` handed to the runner, plus the runner to launch through.
///
/// At this phase the prefix is only a directory the runner (umu/wine) auto-initializes on first
/// launch; real `wineboot` setup and health checks come later.
#[derive(Debug, Clone)]
pub struct Prefix {
    pub(crate) path: PathBuf,
    pub(crate) runner: RunnerHandle,
}

impl Prefix {
    pub(crate) fn new(path: PathBuf, runner: RunnerHandle) -> Self {
        Self { path, runner }
    }

    /// The prefix directory (the `WINEPREFIX`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The runner this prefix launches through.
    #[must_use]
    pub fn runner(&self) -> &RunnerHandle {
        &self.runner
    }
}

/// A launch about to be spawned. Injectables may wrap or mutate it (program, env, wrappers) via
/// `prepare_launch(&mut LaunchPlan)` before it reaches the spawner.
#[derive(Clone)]
pub struct LaunchPlan {
    program: String,
    args: String,
    env: BTreeMap<String, String>,
    wrappers: Vec<String>,
    dpi_aware: bool,
    prefix: Option<Prefix>,
}

impl LaunchPlan {
    /// A plan to launch `program` (a PE basename, e.g. `ffxiv_dx11.exe`) with the opaque
    /// `encrypted_args` string and the caller's `env` overrides (merged last, so they always win).
    #[must_use]
    pub fn new(
        program: impl Into<String>,
        encrypted_args: impl Into<String>,
        env: BTreeMap<String, String>,
    ) -> Self {
        Self {
            program: program.into(),
            args: encrypted_args.into(),
            env,
            wrappers: Vec::new(),
            dpi_aware: false,
            prefix: None,
        }
    }

    /// Launch into `prefix` (through its runner).
    #[must_use]
    pub fn prefix(mut self, prefix: &Prefix) -> Self {
        self.prefix = Some(prefix.clone());
        self
    }

    /// Set the wrapper commands composed around the runner invocation (gamescope, gamemode, …).
    #[must_use]
    pub fn wrappers(mut self, wrappers: Vec<String>) -> Self {
        self.wrappers = wrappers;
        self
    }

    /// Mark the launch DPI-aware (carried through; inert on Linux until the Windows path lands).
    #[must_use]
    pub fn dpi_aware(mut self, on: bool) -> Self {
        self.dpi_aware = on;
        self
    }

    /// The program (PE basename) to launch.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Replace the program (an injectable may redirect the launch).
    pub fn set_program(&mut self, program: impl Into<String>) {
        self.program = program.into();
    }

    /// The opaque encrypted argument string. Opaque here: the runtime never parses it.
    #[must_use]
    pub fn args(&self) -> &str {
        &self.args
    }

    /// Mutable access to the environment, for an injectable to add variables.
    pub fn env_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.env
    }

    /// Append a wrapper command around the launch.
    pub fn push_wrapper(&mut self, wrapper: impl Into<String>) {
        self.wrappers.push(wrapper.into());
    }
}

/// Redacts the opaque encrypted args (they carry session material) while keeping the rest legible.
impl fmt::Debug for LaunchPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchPlan")
            .field("program", &self.program)
            .field("args", &"<redacted>")
            .field("env", &self.env)
            .field("wrappers", &self.wrappers)
            .field("dpi_aware", &self.dpi_aware)
            .field("prefix", &self.prefix)
            .finish()
    }
}
