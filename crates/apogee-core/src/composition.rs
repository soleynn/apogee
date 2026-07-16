//! The composition root: the one place every subsystem is constructed, tuned, and injected.

use std::path::PathBuf;

use apogee_addons::{Addons, ComponentManifest};
use apogee_fetch::Fetcher;
use apogee_otp::Otp;
use apogee_patcher::{Patcher, PatcherConfig};
use apogee_runtime::{Runtime, RuntimePaths};
use apogee_secrets::Secrets;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::UnboundedReceiverStream;

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
    /// The one concrete network transport, owned here and handed to the protocol layer.
    transport: HttpTransport,
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
        // `config` is consumed here, so move its owned paths into each subsystem rather than clone.
        let CoreConfig {
            store_dir,
            runners_dir,
            prefixes_dir,
            patch_store,
        } = config;
        let store = Store::new(store_dir);

        // Client tuning (HTTP/1.1 for the plain-HTTP patch CDN, HTTP/2 for HTTPS hosts) lands with
        // the transport's request path; the dual-stack default already applies.
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| CoreError::Init {
                detail: e.to_string(),
            })?;
        let transport = HttpTransport::new(client);

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

    /// Run `cmd`, yielding the events it produces.
    ///
    /// Profile queries and mutations run against the store and surface only failures as events; the
    /// login-to-play flows are not yet built.
    pub fn execute(&self, cmd: Command) -> impl Stream<Item = Event> + Unpin {
        let (tx, rx) = mpsc::unbounded_channel();
        match cmd {
            Command::ListProfiles => {
                if let Err(e) = self.store.list_profiles() {
                    let _ = tx.send(Event::Error(e.into()));
                }
            }
            Command::SaveProfile(profile) => {
                if let Err(e) = self.store.save_profile(&profile) {
                    let _ = tx.send(Event::Error(e.into()));
                }
            }
            Command::DeleteProfile(id) => {
                if let Err(e) = self.store.delete_profile(id) {
                    let event = match e {
                        StoreError::NotFound { .. } => CoreError::NoProfile(id),
                        other => other.into(),
                    };
                    let _ = tx.send(Event::Error(event));
                }
            }
            Command::Login { .. } => todo!("orchestrate the login-to-play flow"),
            Command::PatchAndPlay { .. } => todo!("run preflight, patch, then launch the game"),
            Command::Repair { .. } => todo!("verify and repair the installation"),
            Command::FirstRun(_) => todo!("walk the initial setup"),
            Command::ImportXivLauncher(_) => todo!("import an existing launcher configuration"),
            Command::Frontier(_) => todo!("fetch pre-login news and gate status"),
            Command::SupportBundle => todo!("collect a redacted diagnostic bundle"),
        }
        UnboundedReceiverStream::new(rx)
    }
}
