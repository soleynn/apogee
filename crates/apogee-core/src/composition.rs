//! The composition root: the one place every subsystem is constructed, tuned, and injected.

use std::path::PathBuf;
use std::sync::Arc;

use apogee_addons::{Addons, ComponentManifest};
use apogee_fetch::Fetcher;
use apogee_otp::Otp;
use apogee_patcher::{Patcher, PatcherConfig};
use apogee_runtime::{Runtime, RuntimePaths};
use apogee_secrets::Secrets;
use sqex_proto::Transport;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;

use crate::command::{Command, Event};
use crate::error::CoreError;
use crate::model::{Profile, Settings};
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
    addons: Addons,
    secrets: Secrets,
    otp: Otp,
    store: Store,
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
                runners: runners_dir,
                prefixes: prefixes_dir,
            },
        );
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
            addons,
            secrets,
            otp,
            store,
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

    /// Run `cmd`, yielding the events it produces.
    ///
    /// `execute` drives the async login-to-play flows; synchronous store CRUD is the direct methods
    /// above (`profiles`, `save_profile`, `settings`, ...), not a command. The flow arms are stubbed
    /// until they land in a later change.
    pub fn execute(&self, cmd: Command) -> impl Stream<Item = Event> + Unpin {
        let (tx, rx) = mpsc::unbounded_channel();
        self.run(cmd, tx);
        UnboundedReceiverStream::new(rx)
    }

    /// Drive `cmd`'s flow, emitting events on `_tx`. Every arm is a login-to-play flow that lands in a
    /// later change, at which point `_tx` carries its state and progress.
    fn run(&self, cmd: Command, _tx: mpsc::UnboundedSender<Event>) {
        match cmd {
            Command::Login { .. } => todo!("orchestrate the login-to-play flow"),
            Command::PatchAndPlay { .. } => todo!("run preflight, patch, then launch the game"),
            Command::Repair { .. } => todo!("verify and repair the installation"),
            Command::FirstRun(_) => todo!("walk the initial setup"),
            Command::ImportXivLauncher(_) => todo!("import an existing launcher configuration"),
            Command::Frontier(_) => todo!("fetch pre-login news and gate status"),
            Command::SupportBundle => todo!("collect a redacted diagnostic bundle"),
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
