//! The composition root: the one place every subsystem is constructed, tuned, and injected.

use std::path::PathBuf;
use std::sync::Arc;

use apogee_addons::{Addons, ComponentManifest};
use apogee_fetch::Fetcher;
use apogee_otp::Otp;
use apogee_patcher::{Patcher, PatcherConfig};
use apogee_runtime::{Runtime, RuntimePaths};
use apogee_secrets::Secrets;
use sqex_proto::{ComputerId, Transport};
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::command::{Command, Event};
use crate::error::CoreError;
use crate::flow::{self, FlowContext};
use crate::host::{self, Clock};
use crate::launch::LaunchBackend;
use crate::launch::runtime_backend::RuntimeLauncher;
use crate::model::{Account, Profile, Settings};
use crate::store::{Store, StoreError};
use crate::transport::HttpTransport;

/// Filesystem locations the core reads and writes.
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Where profiles and settings are stored.
    pub store_dir: PathBuf,
    /// Where managed runners are unpacked.
    pub runners_dir: PathBuf,
    /// Where Wine prefixes live.
    pub prefixes_dir: PathBuf,
    /// Where downloaded patches are staged.
    pub patch_store: PathBuf,
}

impl CoreConfig {
    /// A config rooted at one base directory, with the standard subdirectories beneath it. Handy
    /// for a throwaway or test run pointed at a scratch directory.
    #[must_use]
    pub fn with_base(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            store_dir: base.join("store"),
            runners_dir: base.join("runners"),
            prefixes_dir: base.join("prefixes"),
            patch_store: base.join("patches"),
        }
    }

    /// A config resolved from the XDG base-directory environment: configuration under the config
    /// home, runners and prefixes under the data home, staged patches under the cache home.
    #[must_use]
    pub fn from_env() -> Self {
        let data = xdg_dir("XDG_DATA_HOME", ".local/share");
        Self {
            store_dir: xdg_dir("XDG_CONFIG_HOME", ".config").join("apogee"),
            runners_dir: data.join("apogee/runners"),
            prefixes_dir: data.join("apogee/prefixes"),
            patch_store: xdg_dir("XDG_CACHE_HOME", ".cache").join("apogee/patches"),
        }
    }
}

/// Resolve an XDG base directory from `var`, falling back to `$HOME/<fallback>`.
fn xdg_dir(var: &str, fallback: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        PathBuf::from(dir)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(fallback)
    } else {
        PathBuf::from(fallback)
    }
}

/// The launcher core: every subsystem, constructed once and injected.
///
/// The subsystem fields are held so the dependency graph is wired and type-checked from the start;
/// the login-to-play flows that read them arrive in a later change, so the fields are dormant today.
#[allow(dead_code)]
pub struct Core {
    /// The network transport handed to the protocol layer. The composition root assembles the one
    /// concrete transport; tests inject a scripted double through [`Core::with_transport`].
    transport: Arc<dyn Transport>,
    fetcher: Fetcher,
    patcher: Patcher,
    runtime: Runtime,
    /// The launch seam over the runner. Held as a trait object so a test can inject a fake.
    launch: Arc<dyn LaunchBackend>,
    addons: Addons,
    secrets: Secrets,
    otp: Otp,
    store: Store,
    /// The launcher's machine fingerprint, sent on OAuth/frontier requests.
    computer_id: ComputerId,
    /// The wall-clock source the session-cache window is measured against.
    clock: Clock,
    /// Where Wine prefixes live, so the flow can resolve a profile's prefix directory.
    prefixes_dir: PathBuf,
}

impl Core {
    /// Construct and wire every subsystem from `config`.
    ///
    /// # Errors
    /// Returns [`CoreError::Init`] if the network client cannot be built, or the wrapped subsystem
    /// error if a subsystem fails to construct.
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        // The one concrete transport. gzip/deflate are enabled so reqwest negotiates and decompresses
        // the login pages automatically (the request path forwards no accept-encoding of its own).
        // HTTP-version tuning (1.1 for the plain-HTTP patch CDN, 2 for HTTPS hosts) lands with the
        // patch flow; the dual-stack default already applies.
        let client = reqwest::Client::builder()
            .gzip(true)
            .deflate(true)
            .build()
            .map_err(|e| CoreError::Init {
                detail: e.to_string(),
            })?;
        Self::with_transport(config, Arc::new(HttpTransport::new(client)))
    }

    /// Construct and wire every subsystem from `config`, using the injected `transport` in place of
    /// the concrete network client. The composition-root seam that lets a headless test drive the
    /// flows against a scripted transport.
    ///
    /// # Errors
    /// Returns the wrapped subsystem error if a subsystem fails to construct.
    pub fn with_transport(
        config: CoreConfig,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, CoreError> {
        // `config` is consumed here, so move its owned paths into each subsystem rather than clone.
        let CoreConfig {
            store_dir,
            runners_dir,
            prefixes_dir,
            patch_store,
        } = config;
        let store = Store::new(store_dir);

        let fetcher = Fetcher::builder().build()?;
        let runtime = Runtime::new(
            fetcher.clone(),
            RuntimePaths {
                runners: runners_dir.clone(),
                prefixes: prefixes_dir.clone(),
            },
        );
        let launch: Arc<dyn LaunchBackend> =
            Arc::new(RuntimeLauncher::new(runtime.clone(), runners_dir));
        // A patch operation's game root is known only once a profile is chosen; a baseline empty root
        // lets the subsystem graph construct, and a flow supplies the real paths later.
        let patcher = Patcher::new(
            fetcher.clone(),
            PatcherConfig {
                patch_store,
                game_root: PathBuf::new(),
                keep_patches: false,
                ignore_space: false,
            },
        );
        let addons = Addons::new(
            runtime.clone(),
            fetcher.clone(),
            ComponentManifest::default(),
        );
        let secrets = Secrets::new();
        let otp = Otp::new();

        Ok(Self {
            transport,
            fetcher,
            patcher,
            runtime,
            launch,
            addons,
            secrets,
            otp,
            store,
            computer_id: host::computer_id(),
            clock: host::system_clock(),
            prefixes_dir,
        })
    }

    /// Every stored profile.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if the profile directory cannot be read or a profile file is
    /// corrupt.
    pub fn profiles(&self) -> Result<Vec<Profile>, CoreError> {
        Ok(self.store.list_profiles()?)
    }

    /// The launcher-wide settings, defaulting when none is stored yet.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if the settings file is present but corrupt.
    pub fn settings(&self) -> Result<Settings, CoreError> {
        Ok(self.store.load_settings()?)
    }

    /// Persist the launcher-wide settings.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if the settings file cannot be written.
    pub fn save_settings(&self, settings: &Settings) -> Result<(), CoreError> {
        Ok(self.store.save_settings(settings)?)
    }

    /// Persist `profile`, keyed by its id.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if the profile cannot be written.
    pub fn save_profile(&self, profile: &Profile) -> Result<(), CoreError> {
        Ok(self.store.save_profile(profile)?)
    }

    /// Delete the profile with `id`.
    ///
    /// # Errors
    /// Returns [`CoreError::NoProfile`] if no such profile exists, or a [`CoreError::Store`] on an IO
    /// failure.
    pub fn delete_profile(&self, id: Uuid) -> Result<(), CoreError> {
        self.store.delete_profile(id).map_err(|e| match e {
            StoreError::NotFound { .. } => CoreError::NoProfile(id),
            other => other.into(),
        })
    }

    /// The profile with `id`, loaded by key.
    ///
    /// # Errors
    /// Returns [`CoreError::NoProfile`] if no such profile exists, or a [`CoreError::Store`] if its
    /// file is corrupt.
    pub fn profile(&self, id: Uuid) -> Result<Profile, CoreError> {
        self.store.load_profile(id).map_err(|e| match e {
            StoreError::NotFound { .. } => CoreError::NoProfile(id),
            other => other.into(),
        })
    }

    /// Every stored account.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if the account directory cannot be read or an account file is
    /// corrupt.
    pub fn accounts(&self) -> Result<Vec<Account>, CoreError> {
        Ok(self.store.list_accounts()?)
    }

    /// The account with `id`.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if no such account exists or its file is corrupt.
    pub fn account(&self, id: Uuid) -> Result<Account, CoreError> {
        Ok(self.store.load_account(id)?)
    }

    /// Persist `account`, keyed by its id.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if the account cannot be written.
    pub fn save_account(&self, account: &Account) -> Result<(), CoreError> {
        Ok(self.store.save_account(account)?)
    }

    /// Delete the account with `id`.
    ///
    /// # Errors
    /// Returns a [`CoreError::Store`] if no such account exists or on an IO failure.
    pub fn delete_account(&self, id: Uuid) -> Result<(), CoreError> {
        Ok(self.store.delete_account(id)?)
    }

    /// Run `cmd`, yielding the events it produces.
    ///
    /// `execute` drives the async login-to-play flows; synchronous store CRUD is the direct methods
    /// above (`profiles`, `save_profile`, `settings`, ...), not a command.
    ///
    /// The flow runs on a spawned task, so an ambient Tokio runtime must exist. Use
    /// [`Core::execute_cancellable`] to thread a cancellation token (a shell wires Ctrl-C to it).
    pub fn execute(&self, cmd: Command) -> impl Stream<Item = Event> + Unpin {
        self.execute_cancellable(cmd, CancellationToken::new())
    }

    /// Like [`Core::execute`], but honoring `cancel`: cancelling supervises the game down (a targeted
    /// kill) and ends the stream.
    pub fn execute_cancellable(
        &self,
        cmd: Command,
        cancel: CancellationToken,
    ) -> impl Stream<Item = Event> + Unpin {
        let (tx, rx) = mpsc::unbounded_channel();
        let ctx = self.flow_context();
        tokio::spawn(async move { flow::drive(ctx, cmd, tx, cancel).await });
        UnboundedReceiverStream::new(rx)
    }

    /// A snapshot of the injected seams the flow reads, cheap to clone onto the spawned task.
    fn flow_context(&self) -> FlowContext {
        FlowContext {
            transport: self.transport.clone(),
            launch: self.launch.clone(),
            store: self.store.clone(),
            clock: self.clock.clone(),
            computer_id: self.computer_id,
            prefixes_dir: self.prefixes_dir.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{Core, CoreConfig};
    use crate::error::CoreError;
    use crate::model::{Account, AccountKind, Profile};

    fn core() -> (TempDir, Core) {
        let dir = TempDir::new().unwrap();
        let core = Core::new(CoreConfig::with_base(dir.path())).unwrap();
        (dir, core)
    }

    #[test]
    fn a_scripted_transport_can_be_injected() {
        use std::sync::Arc;

        use apogee_test_support::transport::FixtureTransport;

        let dir = TempDir::new().unwrap();
        let transport = Arc::new(FixtureTransport::new([]));
        let core = Core::with_transport(CoreConfig::with_base(dir.path()), transport);
        assert!(core.is_ok());
    }

    #[test]
    fn deleting_a_missing_profile_surfaces_as_no_profile() {
        let (_dir, core) = core();
        let account = Account::new("me@example.invalid", AccountKind::Standard);
        let profile = Profile::new("Main", account.id, "/games/ffxiv".into());
        let id = profile.id;

        core.save_profile(&profile).unwrap();
        assert_eq!(core.profiles().unwrap(), vec![profile]);

        // The first delete removes it; the second finds nothing, and the store's typed miss is
        // mapped to the core's NoProfile carrying the id that was asked for.
        core.delete_profile(id).unwrap();
        match core.delete_profile(id).unwrap_err() {
            CoreError::NoProfile(missing) => assert_eq!(missing, id),
            other => panic!("expected NoProfile, got {other:?}"),
        }
    }
}
