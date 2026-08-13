//! The launch description and the prepared prefix it runs in.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::catalog::RunnerKind;

/// An installed runner: where it lives on disk, and which kind it is.
///
/// Built once the runner is on disk, and carried by every [`Prefix`] prepared with it (reachable
/// through [`Prefix::runner`]). There is no public constructor: a runner exists because
/// [`Runtime::prepare`](crate::Runtime::prepare) installed it from the catalog, or because the
/// caller pointed [`Runtime::prepare_custom`](crate::Runtime::prepare_custom) at a directory.
#[derive(Debug, Clone)]
pub struct RunnerHandle {
    pub(crate) dir: PathBuf,
    pub(crate) kind: RunnerKind,
    pub(crate) name: String,
    pub(crate) version: String,
}

impl RunnerHandle {
    /// Assemble a handle for a runner already installed at `dir`.
    pub(crate) fn new(
        dir: PathBuf,
        kind: RunnerKind,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            dir,
            kind,
            name: name.into(),
            version: version.into(),
        }
    }

    /// The installed runner directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The runner kind, which decides what binary starts a program in the prefix.
    #[must_use]
    pub fn kind(&self) -> RunnerKind {
        self.kind
    }

    /// The runner name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The runner version, or `"custom"` for a bring-your-own runner.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// A handle over an arbitrary directory, for in-crate tests.
    #[cfg(test)]
    pub(crate) fn for_test(dir: PathBuf, kind: RunnerKind, name: &str, version: &str) -> Self {
        Self::new(dir, kind, name, version)
    }
}

/// A prepared wine prefix and the runner that launches into it.
///
/// The handle [`Runtime::prepare`](crate::Runtime::prepare) returns, and the one every other method
/// in this crate takes. Holding one means the directory exists, `wineboot` has run in it, and it
/// carries a `prefix.json` naming the runner it was built with.
///
/// It promises nothing beyond that. It is a path and a runner captured once, so nothing re-reads the
/// directory as the handle is cloned and passed on, and what the prefix holds past the wine skeleton
/// is whatever its own record claims ([`components`](Self::components)) rather than anything this
/// type verifies. [`Runtime::check_prefix`](crate::Runtime::check_prefix) is what compares record
/// against disk.
#[derive(Debug, Clone)]
pub struct Prefix {
    pub(crate) path: PathBuf,
    pub(crate) runner: RunnerHandle,
}

impl Prefix {
    /// Pair a prefix directory with the runner that launches into it.
    pub(crate) fn new(path: PathBuf, runner: RunnerHandle) -> Self {
        Self { path, runner }
    }

    /// A prefix handle over an existing directory, for tests in crates that build on this one.
    ///
    /// Behind the `testing` feature, which no shipping build enables: the ordinary constructors go
    /// through `wineboot`, and this hands back a handle over a directory nothing has initialized.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn for_testing(
        path: impl Into<PathBuf>,
        runner_dir: impl Into<PathBuf>,
        kind: RunnerKind,
        name: &str,
        version: &str,
    ) -> Self {
        Self::new(
            path.into(),
            RunnerHandle::new(runner_dir.into(), kind, name, version),
        )
    }

    /// The prefix directory, which is the `WINEPREFIX` the runner is given.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The runner this prefix launches through.
    #[must_use]
    pub fn runner(&self) -> &RunnerHandle {
        &self.runner
    }

    /// The directory holding the live wine files.
    ///
    /// For plain wine this is the prefix itself; Proton via umu relocates them to `<prefix>/pfx`, so
    /// the skeleton, `dosdevices` and the registry files live there instead.
    #[must_use]
    pub(crate) fn wine_root(&self) -> PathBuf {
        if self.runner.kind == RunnerKind::ProtonUmu {
            self.path.join("pfx")
        } else {
            self.path.clone()
        }
    }

    /// The prefix's `C:` drive, where a component installs its files.
    ///
    /// Resolved through the runner's own layout, so a caller never has to know which runner built
    /// the prefix.
    #[must_use]
    pub fn drive_c(&self) -> PathBuf {
        self.wine_root().join("drive_c")
    }

    /// The path to this prefix's `prefix.json` record.
    #[must_use]
    pub fn metadata_path(&self) -> PathBuf {
        self.path.join(crate::metadata::PREFIX_JSON)
    }

    /// The components and verbs this prefix records as installed.
    ///
    /// Each carries a version where the manifest pinned one, and a prefix with no record yet reports
    /// an empty list. This is what makes reapplying a verb or reinstalling a component a no-op, and
    /// what makes an upgraded one not a no-op.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::PrefixJson`](crate::RuntimeError::PrefixJson) if the record exists but is
    /// corrupt, and [`RuntimeError::Io`](crate::RuntimeError::Io) if it cannot be read. A corrupt
    /// record is the caller's decision to make: reading it as "nothing installed" would silently
    /// rerun every install.
    pub fn components(&self) -> Result<Vec<crate::InstalledComponent>, crate::RuntimeError> {
        Ok(self
            .metadata()?
            .map(|meta| meta.components)
            .unwrap_or_default())
    }

    /// Note that `verb` has been applied to this prefix, and report whether that was new.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::PrefixJson`](crate::RuntimeError::PrefixJson) if the existing record is
    /// corrupt or the new one cannot be serialized, and
    /// [`RuntimeError::Io`](crate::RuntimeError::Io) if the record cannot be read or written.
    pub fn record_verb(&self, verb: &str) -> Result<bool, crate::RuntimeError> {
        crate::metadata::record_component(
            &self.metadata_path(),
            crate::metadata::RunnerRef::from(&self.runner),
            verb,
            None,
            crate::SetupStep::VerbApply,
            verb,
        )
    }

    /// Note that component `name` is installed here, at `version` where the manifest pins one.
    ///
    /// Returns whether it was newly recorded; an upgrade replaces the entry and reports `false`.
    ///
    /// # Errors
    ///
    /// As [`record_verb`](Self::record_verb).
    pub fn record_component(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<bool, crate::RuntimeError> {
        let detail = match version {
            Some(version) => format!("{name} {version}"),
            None => name.to_owned(),
        };
        crate::metadata::record_component(
            &self.metadata_path(),
            crate::metadata::RunnerRef::from(&self.runner),
            name,
            version,
            crate::SetupStep::ComponentInstall,
            &detail,
        )
    }

    /// Whether this prefix's registry still holds what `edit` wrote.
    ///
    /// Read out of the prefix's own registry files without starting the runner, which is what makes
    /// it an answer about a prefix that is **not running**: the file is what the last wineserver
    /// flushed, and there is no live registry it is behind. The write path reads `reg add`'s exit
    /// status instead, because that flush is asynchronous and a read taken straight after a write can
    /// still show the value that was there before.
    ///
    /// Total by construction. A prefix with no registry file, a root that no single file holds, and a
    /// value in an encoding this build does not decode all come back as
    /// [`RegistryEffect::Unknown`](crate::RegistryEffect::Unknown) rather than as an absence, since a
    /// caller that reapplies whatever is missing would otherwise reapply it on every launch forever.
    #[must_use]
    pub fn registry_effect(&self, edit: &crate::RegistryEdit) -> crate::RegistryEffect {
        crate::hive::edit_effect(&self.wine_root(), edit)
    }

    /// Whether what `delete` removes is still absent from this prefix's registry.
    ///
    /// On the same terms as [`registry_effect`](Self::registry_effect), with the readings inverted:
    /// finding the target is the removal being gone.
    #[must_use]
    pub fn registry_removal_effect(&self, delete: &crate::RegistryDelete) -> crate::RegistryEffect {
        crate::hive::removal_effect(&self.wine_root(), delete)
    }

    /// The recorded `prefix.json`, or `None` if this prefix has not been initialized yet.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::PrefixJson`](crate::RuntimeError::PrefixJson) if the record is corrupt, and
    /// [`RuntimeError::Io`](crate::RuntimeError::Io) if it cannot be read.
    pub fn metadata(&self) -> Result<Option<crate::metadata::PrefixMetadata>, crate::RuntimeError> {
        crate::metadata::PrefixMetadata::load(&self.metadata_path())
    }

    /// Parse the DOS drive map, for translating between unix and windows paths in process.
    ///
    /// Reads the prefix's `dosdevices/` directory on every call, so a caller translating many paths
    /// should keep the result rather than ask again.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Io`](crate::RuntimeError::Io) if `dosdevices/` cannot be listed.
    #[cfg(target_os = "linux")]
    pub fn drive_map(&self) -> Result<crate::dosdevices::DriveMap, crate::RuntimeError> {
        crate::dosdevices::DriveMap::from_prefix(&self.wine_root())
    }
}

/// A launch about to be spawned: what to run, with which arguments and environment.
///
/// Assembled by the caller, then amended in place by the companion layer (program, argv, env,
/// wrappers) before it reaches the spawner.
#[derive(Clone)]
pub struct LaunchPlan {
    program: String,
    args: String,
    inserted_args: Vec<String>,
    env: BTreeMap<String, String>,
    wrappers: Vec<String>,
    dpi_aware: bool,
    prefix: Option<Prefix>,
    working_dir: Option<PathBuf>,
    supervised: Option<String>,
}

impl LaunchPlan {
    /// A plan to launch `program` with an already-encrypted argument string.
    ///
    /// `program` is what the runner resolves, a PE basename such as `ffxiv_dx11.exe` or a path.
    /// `encrypted_args` reaches the game as one token: this crate is handed that string and neither
    /// builds nor parses it. `env` is applied on top of the prefix's own variables, so it wins.
    ///
    /// The launch is [DPI-aware](Self::dpi_aware) unless the caller says otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::BTreeMap;
    ///
    /// use apogee_runtime::LaunchPlan;
    ///
    /// let plan = LaunchPlan::new("ffxiv_dx11.exe", "//**sqex0003AbCd**//", BTreeMap::new());
    /// assert_eq!(plan.program(), "ffxiv_dx11.exe");
    /// assert!(plan.is_dpi_aware());
    /// assert!(plan.prefix().is_none());
    /// ```
    #[must_use]
    pub fn new(
        program: impl Into<String>,
        encrypted_args: impl Into<String>,
        env: BTreeMap<String, String>,
    ) -> Self {
        Self {
            program: program.into(),
            args: encrypted_args.into(),
            inserted_args: Vec::new(),
            env,
            wrappers: Vec::new(),
            dpi_aware: true,
            prefix: None,
            working_dir: None,
            supervised: None,
        }
    }

    /// Launch into `prefix`, through the runner it was prepared with.
    ///
    /// A plan with no prefix cannot be launched through a runner. The matching getter is
    /// [`prefix`](Self::prefix).
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::collections::BTreeMap;
    /// # use apogee_runtime::{LaunchPlan, Prefix};
    /// # fn demo(prefix: &Prefix, encrypted_args: &str) -> LaunchPlan {
    /// LaunchPlan::new("ffxiv_dx11.exe", encrypted_args, BTreeMap::new()).in_prefix(prefix)
    /// # }
    /// ```
    #[must_use]
    pub fn in_prefix(mut self, prefix: &Prefix) -> Self {
        self.prefix = Some(prefix.clone());
        self
    }

    /// Run the child from `dir`.
    ///
    /// A host path, not a path inside the prefix: an absolute one is unambiguous, a relative one is
    /// resolved against the calling process's own working directory. The game is started from its
    /// install directory so that it resolves its data paths relative to the exe. The matching getter
    /// is [`working_dir`](Self::working_dir).
    #[must_use]
    pub fn in_directory(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Set the wrapper commands composed around the runner invocation (gamescope, gamemode).
    #[must_use]
    pub fn with_wrappers(mut self, wrappers: Vec<String>) -> Self {
        self.wrappers = wrappers;
        self
    }

    /// Mark the launch DPI-aware. On by default.
    ///
    /// Windows-only: it selects the DPI compatibility layer the game runs under, `HighDPIAware` when
    /// on and `DPIUnaware` when off. Nothing reads it elsewhere, because that layer is applied by the
    /// Windows compatibility engine and a launch through a runner never reaches it.
    ///
    /// Off is an explicit `DPIUnaware`, not the absence of a layer: with neither named the
    /// executable's own manifest decides, which is a third behavior and not what either setting
    /// means.
    #[must_use]
    pub fn dpi_aware(mut self, on: bool) -> Self {
        self.dpi_aware = on;
        self
    }

    /// Whether the launch is DPI-aware (see [`dpi_aware`](Self::dpi_aware)).
    #[must_use]
    pub fn is_dpi_aware(&self) -> bool {
        self.dpi_aware
    }

    /// The program to launch, as the runner will resolve it.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Replace the program, for an injectable that redirects the launch through a loader.
    pub fn set_program(&mut self, program: impl Into<String>) {
        self.program = program.into();
    }

    /// The encrypted argument string, which this crate passes on without parsing.
    #[must_use]
    pub fn args(&self) -> &str {
        &self.args
    }

    /// Set the argv tokens that go between the program and the encrypted argument string.
    ///
    /// An injectable that redirects the launch through a loader puts the loader's own flags here.
    /// They are separate from [`args`](Self::args) because that string is one token the game parses
    /// itself: appending to it would hand the game flags meant for the loader, and prepending would
    /// hand the loader the game's arguments as its own.
    pub fn set_inserted_args(&mut self, args: Vec<String>) {
        self.inserted_args = args;
    }

    /// The argv tokens placed between the program and the argument string.
    #[must_use]
    pub fn inserted_args(&self) -> &[String] {
        &self.inserted_args
    }

    /// Name the PE basename to supervise when it is not the program's own.
    ///
    /// A launch redirected through a loader spawns the game as a separate process, so the launcher
    /// has to track the game rather than the loader: without this it would report the launch as over
    /// the moment the loader exited.
    pub fn set_supervised(&mut self, basename: impl Into<String>) {
        self.supervised = Some(basename.into());
    }

    /// The PE basename to supervise, when one was named instead of the program's own.
    #[must_use]
    pub fn supervised(&self) -> Option<&str> {
        self.supervised.as_deref()
    }

    /// The launch environment, as it will be applied on top of the prefix's own.
    #[must_use]
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// Mutable access to the environment, for an injectable to add variables.
    pub fn env_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.env
    }

    /// Append a wrapper command around the launch.
    pub fn push_wrapper(&mut self, wrapper: impl Into<String>) {
        self.wrappers.push(wrapper.into());
    }

    /// The prefix this plan launches into, if one was set.
    #[must_use]
    pub fn prefix(&self) -> Option<&Prefix> {
        self.prefix.as_ref()
    }

    /// The child's working directory, if one was set.
    #[must_use]
    pub fn working_dir(&self) -> Option<&Path> {
        self.working_dir.as_deref()
    }

    /// The wrapper commands composed around the runner invocation.
    #[must_use]
    pub fn wrappers(&self) -> &[String] {
        &self.wrappers
    }
}

/// Redacts the encrypted argument string, which carries session material, and leaves the rest
/// legible.
impl fmt::Debug for LaunchPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchPlan")
            .field("program", &self.program)
            .field("args", &"<redacted>")
            .field("inserted_args", &self.inserted_args)
            .field("supervised", &self.supervised)
            .field("env", &self.env)
            .field("wrappers", &self.wrappers)
            .field("dpi_aware", &self.dpi_aware)
            .field("prefix", &self.prefix)
            .field("working_dir", &self.working_dir)
            .finish()
    }
}
