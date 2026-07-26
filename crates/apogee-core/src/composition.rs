//! The composition root: the one place every subsystem is constructed, tuned, and injected.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

// Restore is unix-only, and so is everything only it needs.
#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::Path;

use apogee_addons::backup::{ArchiveRecord, BackupError, BackupReport, PruneReport, Retain};
#[cfg(unix)]
use apogee_addons::backup::{RestorePlan, RestoreReport, RootLabel};
use apogee_addons::{AddonError, Addons, ComponentManifest};

use crate::addons::AddonBackend;
use crate::addons::addons_backend::AddonsBackend;
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
use crate::patch::PatchBackend;
use crate::patch::patcher_backend::PatcherBackend;
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
    /// Where config backups are written, one directory per profile.
    pub backups_dir: PathBuf,
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
            backups_dir: base.join("backups"),
        }
    }

    /// A config resolved from the XDG base-directory environment: configuration under the config
    /// home, runners and prefixes under the data home, staged patches under the cache home.
    ///
    /// # Errors
    /// [`CoreError::Config`] if a base directory cannot be resolved to an absolute path. The store
    /// holds account ids and the list of programs the launcher executes, so resolving it relative to
    /// the working directory would mean the launcher runs whatever happens to sit beside wherever it
    /// was started from. That is reachable in ordinary setups with no home set: a systemd unit, a
    /// cron entry, `env -i`, or a stripped container.
    pub fn try_from_env() -> Result<Self, CoreError> {
        let data = xdg_dir("XDG_DATA_HOME", ".local/share")?;
        Ok(Self {
            store_dir: xdg_dir("XDG_CONFIG_HOME", ".config")?.join("apogee"),
            runners_dir: data.join("apogee/runners"),
            prefixes_dir: data.join("apogee/prefixes"),
            patch_store: xdg_dir("XDG_CACHE_HOME", ".cache")?.join("apogee/patches"),
            // Data, not cache: a backup that a cache cleaner may delete is not a backup.
            backups_dir: data.join("apogee/backups"),
        })
    }
}

/// Resolve an XDG base directory from `var`, falling back to `$HOME/<fallback>`.
///
/// Refuses anything that is not absolute rather than falling back to a bare relative name.
fn xdg_dir(var: &str, fallback: &str) -> Result<PathBuf, CoreError> {
    let resolved = if let Some(dir) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        PathBuf::from(dir)
    } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(home).join(fallback)
    } else {
        return Err(CoreError::Config {
            reason: "neither the base directory nor a home directory is set",
            var: var.to_owned(),
        });
    };
    if !resolved.is_absolute() {
        return Err(CoreError::Config {
            reason: "the base directory must be an absolute path",
            var: var.to_owned(),
        });
    }
    Ok(resolved)
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
    /// The patch/repair seam over `apogee-patcher`. Held as a trait object so a test can inject a fake.
    patch: Arc<dyn PatchBackend>,
    runtime: Runtime,
    /// The launch seam over the runner. Held as a trait object so a test can inject a fake.
    launch: Arc<dyn LaunchBackend>,
    /// The companion seam over `apogee-addons`. A trait object so a test can inject a fake.
    addons: Arc<dyn AddonBackend>,
    secrets: Secrets,
    otp: Otp,
    store: Store,
    /// The launcher's machine fingerprint, sent on OAuth/frontier requests.
    computer_id: ComputerId,
    /// The wall-clock source the session-cache window is measured against.
    clock: Clock,
    /// Where Wine prefixes live, so the flow can resolve a profile's prefix directory.
    prefixes_dir: PathBuf,
    backups_dir: PathBuf,
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
        // HTTP-version tuning is the reqwest default and is what we want: HTTP/1.1 over the plain-HTTP
        // patch/boot-check CDN, HTTP/2 negotiated via ALPN over the TLS artifact/login hosts. Dual-stack
        // Happy-Eyeballs connect applies throughout.
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
            backups_dir,
        } = config;
        let store = Store::new(store_dir);
        // The keep-patches preference is read once here (a corrupt settings file defaults it off; the
        // corruption surfaces when the shell reads settings). Changing it takes effect next launch.
        let keep_patches = store
            .load_settings()
            .map(|s| s.keep_patches)
            .unwrap_or(false);

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
        // A patch operation's game root is known only once a profile is chosen, so it travels with
        // each request rather than the construction config.
        let patcher = Patcher::new(
            fetcher.clone(),
            PatcherConfig {
                patch_store: patch_store.clone(),
                keep_patches,
                ignore_space: false,
                ..PatcherConfig::default()
            },
        );
        // The catalog-fetch client for repair: separate from the injected `transport` (which serves
        // the login/register/boot-check protocol) and from fetch's download client, it pulls the
        // small signed index manifest. reqwest's default already serves HTTP/1.1 over plain HTTP and
        // negotiates HTTP/2 via ALPN over TLS, which is the patch-CDN-vs-artifact-host split we want.
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| CoreError::Init {
                detail: e.to_string(),
            })?;
        let patch: Arc<dyn PatchBackend> =
            Arc::new(PatcherBackend::new(patcher, http, patch_store));
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
            patch,
            runtime,
            launch,
            addons: Arc::new(AddonsBackend::new(addons)) as Arc<dyn AddonBackend>,
            secrets,
            otp,
            store,
            computer_id: host::computer_id(),
            clock: host::system_clock(),
            prefixes_dir,
            backups_dir,
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

    /// Back up the game config in `profile`'s prefix, then prune to the retention setting.
    ///
    /// Returns the report and the trees that were not covered. A prefix run under more than one
    /// runner can hold more than one config tree; the one the game wrote to last is the one backed
    /// up, and the rest are named rather than silently ignored.
    ///
    /// # Errors
    /// [`CoreError::Store`] if the profile or settings cannot be read, and [`CoreError::Addons`] for
    /// anything the backup itself refuses, including a prefix the game has never written into.
    pub fn backup_config(
        &self,
        profile: Uuid,
        note: Option<String>,
    ) -> Result<(BackupReport, Vec<PathBuf>), CoreError> {
        let record = self.store.load_profile(profile)?;
        let kept = self
            .store
            .load_settings()
            .map(|s| s.backups_kept)
            .unwrap_or(5);
        crate::backup::create(
            &self.prefixes_dir,
            &self.backups_dir,
            &record,
            kept,
            (self.clock)(),
            note,
        )
    }

    /// This profile's backups, newest first.
    ///
    /// # Errors
    /// [`CoreError::Addons`] if the backup directory cannot be read.
    pub fn backups(&self, profile: Uuid) -> Result<Vec<ArchiveRecord>, CoreError> {
        let record = self.store.load_profile(profile)?;
        let dir = crate::backup::profile_dir(&self.backups_dir, &record);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        // Retention's own identification, so listing and pruning agree on what is ours.
        let plan = apogee_addons::backup::plan_prune(&dir, Retain::keep(NonZeroUsize::MAX))
            .map_err(AddonError::Backup)?;
        Ok(plan.ours)
    }

    /// Restore `archive` into the game config tree of `profile`'s prefix.
    ///
    ///
    /// The tree that was there is renamed aside rather than deleted, so this is undone with one
    /// rename; the report says where it went.
    ///
    /// # Errors
    /// [`CoreError::Store`] if the profile cannot be read, and [`CoreError::Addons`] for anything the
    /// restore refuses.
    #[cfg(unix)]
    pub fn restore_config(
        &self,
        profile: Uuid,
        archive: &Path,
    ) -> Result<RestoreReport, CoreError> {
        let profile_record = self.store.load_profile(profile)?;
        let prefix = self
            .prefixes_dir
            .join(crate::flow::prefix_name(&profile_record));
        let target = apogee_addons::backup::game_config_dirs(&prefix)
            .into_iter()
            .next()
            .ok_or_else(|| {
                CoreError::Addons(AddonError::Backup(BackupError::MissingRoot {
                    path: prefix.clone(),
                }))
            })?;
        let mut targets = BTreeMap::new();
        targets.insert(RootLabel::User, target);
        let plan = RestorePlan {
            archive: archive.to_path_buf(),
            targets,
        };
        Ok(apogee_addons::backup::restore(&plan).map_err(AddonError::Backup)?)
    }

    /// Prune `profile`'s backups to `keep`, deleting only archives this launcher wrote.
    ///
    /// # Errors
    /// [`CoreError::Addons`] if the directory cannot be read or an archive cannot be removed.
    pub fn prune_backups(
        &self,
        profile: Uuid,
        keep: NonZeroUsize,
    ) -> Result<PruneReport, CoreError> {
        let record = self.store.load_profile(profile)?;
        let dir = crate::backup::profile_dir(&self.backups_dir, &record);
        Ok(apogee_addons::backup::prune(&dir, Retain::keep(keep)).map_err(AddonError::Backup)?)
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
            patch: self.patch.clone(),
            launch: self.launch.clone(),
            addons: self.addons.clone(),
            store: self.store.clone(),
            clock: self.clock.clone(),
            computer_id: self.computer_id,
            prefixes_dir: self.prefixes_dir.clone(),
            backups_dir: self.backups_dir.clone(),
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
