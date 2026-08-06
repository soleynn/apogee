//! The composition root: the one place every subsystem is constructed, tuned, and injected.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Restore is unix-only, and so is everything only it needs.
#[cfg(unix)]
use std::collections::BTreeMap;

use apogee_addons::backup::{ArchiveRecord, BackupError, BackupReport, PruneReport, Retain};
#[cfg(unix)]
use apogee_addons::backup::{RestorePlan, RestoreReport, RootLabel};
use apogee_addons::{AddonError, AddonPaths, Addons};

use crate::addons::AddonBackend;
use crate::addons::addons_backend::AddonsBackend;
use apogee_fetch::Fetcher;
use apogee_otp::Otp;
use apogee_patcher::{Patcher, PatcherConfig};
use apogee_runtime::{Runtime, RuntimePaths};
use apogee_secrets::{
    BackendReport, EncryptedFile, ForeignKey, Import, ImportSource, Null, Passphrase, Secret,
    SecretKind, Secrets, SecretsError, Unprompted,
};
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
use crate::model::{Account, Profile, SecretBackend, Settings};
use crate::patch::PatchBackend;
use crate::patch::patcher_backend::PatcherBackend;
use crate::steam::{NoSteam, SteamBackend};
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
    /// Where the companion layer keeps what it installs outside a prefix: the last verified copy of the
    /// signed catalog, and the trees an injectable unpacks into. Shared across profiles, because none of
    /// it belongs to any one prefix.
    pub addons_dir: PathBuf,
}

impl CoreConfig {
    /// Where the encrypted fallback store's file goes, if that is the backend in use.
    ///
    /// Beside the accounts it is keyed to, in a directory the store already keeps owner-only. It is
    /// not under the cache home for the obvious reason: a cache cleaner taking it would take every
    /// saved password with it.
    #[must_use]
    pub fn secrets_path(&self) -> PathBuf {
        self.store_dir.join(EncryptedFile::FILE_NAME)
    }

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
            addons_dir: base.join("addons"),
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
            // Data too: what a launch loads into the game is tens of megabytes and is fetched from a
            // third party, so a cache cleaner removing it turns the next launch into a download.
            addons_dir: data.join("apogee/addons"),
        })
    }
}

/// The one concrete transport.
///
/// gzip/deflate are enabled so reqwest negotiates and decompresses the login pages automatically (the
/// request path forwards no accept-encoding of its own). HTTP-version tuning is the reqwest default
/// and is what we want: HTTP/1.1 over the plain-HTTP patch and boot-check CDN, HTTP/2 negotiated via
/// ALPN over the TLS artifact and login hosts. Dual-stack Happy-Eyeballs connect applies throughout.
fn http_transport() -> Result<Arc<dyn Transport>, CoreError> {
    let client = reqwest::Client::builder()
        .gzip(true)
        .deflate(true)
        .build()
        .map_err(|e| CoreError::Init {
            detail: e.to_string(),
        })?;
    Ok(Arc::new(HttpTransport::new(client)))
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

/// What deleting a profile took with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProfileRemoval {
    /// The account that went too, when the profile removed was the last one using it. `None` means
    /// another profile still signs in as that account, so it was left alone.
    pub account_removed: Option<Uuid>,
    /// Whether the account's secrets were actually swept.
    ///
    /// `false` when no store answered at all. Nothing was deleted, and whatever that store holds
    /// for this account has outlived the record naming it, so a caller has to say so rather than
    /// report a clean removal.
    pub secrets_swept: bool,
}

/// What importing another launcher's password did.
///
/// [`Nothing`](Self::Nothing) and [`Unsupported`](Self::Unsupported) both store nothing, and they
/// are still different answers: the first says the other launcher has no password for this account,
/// which is a fact about the user's setup, and the second says this build has no way to look, which
/// is a fact about the target and leaves the question open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportOutcome {
    /// A password was read from the source and stored under this launcher's key.
    Imported,
    /// The source was read and holds nothing for the account.
    Nothing,
    /// The source cannot be read on this target, so nothing was looked at.
    Unsupported,
}

/// Whether a store that failed this way may still be holding the secret.
///
/// The question is not whether the call succeeded but whether anything could be left behind, because
/// the answer decides whether an account may be deleted on top of it. Everything that reached a
/// store and was refused counts as dangerous.
///
/// What is left is the conditions where no store answered at all. Those are *not* proof that nothing
/// is stored: a password saved on a desktop session is still in the keyring when the same account is
/// removed from a TTY with no bus. They are treated as non-blocking anyway, because the alternative
/// is that a user with no keyring can never delete a profile, and the residue is reported instead of
/// assumed away (see [`ProfileRemoval::secrets_swept`]).
///
/// The enum belongs to another crate and is `#[non_exhaustive]`, so an unrecognized condition is
/// assumed to be the dangerous kind. That default is what covers the sealed-file store's two
/// conditions, and it is right for both: a passphrase that did not open the file and a file that will
/// not open at all each leave every secret in it exactly where it was.
fn could_hold_secrets(err: &SecretsError) -> bool {
    !matches!(
        err,
        SecretsError::NoBackend | SecretsError::NoCollection | SecretsError::NotStoring
    )
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
    /// Where a Steam service account's authentication ticket comes from. A trait object because no
    /// build here can mint one yet: what is wired refuses, and says so.
    steam: Arc<dyn SteamBackend>,
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
    /// Where the sealed-file secret store's file goes, whether or not that is the backend in use.
    secrets_path: PathBuf,
}

impl Core {
    /// Construct and wire every subsystem from `config`.
    ///
    /// # Errors
    /// Returns [`CoreError::Init`] if the network client cannot be built, or the wrapped subsystem
    /// error if a subsystem fails to construct.
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        Self::with_passphrase(config, Arc::new(Unprompted))
    }

    /// As [`Core::new`], with the source the sealed-file secret store asks when it has to unlock.
    ///
    /// What a front end that can prompt constructs. [`Core::new`] is the same call with a source
    /// that has nothing to give, which is the honest answer for one that cannot.
    ///
    /// # Errors
    /// As [`Core::new`].
    pub fn with_passphrase(
        config: CoreConfig,
        passphrase: Arc<dyn Passphrase>,
    ) -> Result<Self, CoreError> {
        Self::with_transport_and_passphrase(config, http_transport()?, passphrase)
    }

    /// Construct and wire every subsystem from `config`, using the injected `transport` in place of
    /// the concrete network client. The composition-root seam that lets a headless test drive the
    /// flows against a scripted transport.
    ///
    /// Nothing here can ask for a passphrase, so an install whose settings select the sealed-file
    /// store gets one that reports itself unusable and refuses. That is the honest answer for a
    /// caller that has not wired a prompt; [`Core::with_passphrase`] is the one that has.
    ///
    /// # Errors
    /// Returns the wrapped subsystem error if a subsystem fails to construct.
    pub fn with_transport(
        config: CoreConfig,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, CoreError> {
        Self::with_transport_and_passphrase(config, transport, Arc::new(Unprompted))
    }

    /// Construct and wire every subsystem from `config`, selecting the secret store the stored
    /// settings name and handing the sealed-file backend `passphrase` to ask when it has to unlock.
    ///
    /// The selection lives here rather than in a front end because it is wiring, and the prompt is
    /// injected rather than built here because prompting is presentation. A front end supplies the
    /// one thing only it can.
    ///
    /// The choice is read once. Changing it takes effect on the next launch, and it moves nothing:
    /// whatever the previous backend holds stays there until it is deleted on purpose.
    ///
    /// # Errors
    /// Returns the wrapped subsystem error if a subsystem fails to construct.
    pub fn with_transport_and_passphrase(
        config: CoreConfig,
        transport: Arc<dyn Transport>,
        passphrase: Arc<dyn Passphrase>,
    ) -> Result<Self, CoreError> {
        // A corrupt settings file reads as the default here, the same as every other preference read
        // at construction: the corruption surfaces when the shell reads settings, and defaulting to
        // the platform store is the answer that neither prompts nor invents a file.
        let chosen = Store::new(config.store_dir.clone())
            .load_settings()
            .map(|s| s.secret_backend)
            .unwrap_or_default();
        let secrets = match chosen {
            SecretBackend::Platform => Secrets::new(),
            SecretBackend::EncryptedFile => Secrets::with_backend(Box::new(EncryptedFile::open(
                config.secrets_path(),
                passphrase,
            ))),
            SecretBackend::Nothing => Secrets::with_backend(Box::new(Null::new())),
        };
        Self::with_secrets(config, transport, secrets)
    }

    /// Construct and wire every subsystem from `config`, using the injected `transport` and the
    /// caller's `secrets` in place of the platform credential store.
    ///
    /// The seam a test drives so it never touches whatever keyring is really on the machine, and the
    /// one a caller uses to run against a store the user picked instead of the default.
    ///
    /// # Errors
    /// Returns the wrapped subsystem error if a subsystem fails to construct.
    pub fn with_secrets(
        config: CoreConfig,
        transport: Arc<dyn Transport>,
        secrets: Secrets,
    ) -> Result<Self, CoreError> {
        // Derived before `config` is consumed, and held so a front end can name the sealed store's
        // file without resolving the base directories a second time.
        let secrets_path = config.secrets_path();
        // `config` is consumed here, so move its owned paths into each subsystem rather than clone.
        let CoreConfig {
            store_dir,
            runners_dir,
            prefixes_dir,
            patch_store,
            backups_dir,
            addons_dir,
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
            AddonPaths::new(addons_dir),
        );
        let otp = Otp::new();

        Ok(Self {
            transport,
            fetcher,
            patch,
            runtime,
            launch,
            addons: Arc::new(AddonsBackend::new(addons)) as Arc<dyn AddonBackend>,
            steam: Arc::new(NoSteam) as Arc<dyn SteamBackend>,
            secrets,
            otp,
            store,
            computer_id: host::computer_id(),
            clock: host::system_clock(),
            prefixes_dir,
            backups_dir,
            secrets_path,
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
    /// Deletes the record only. Prefer [`Core::forget_account`], which also clears what the account
    /// left elsewhere.
    ///
    /// # Errors
    /// Returns [`CoreError::NoAccount`] if no such account exists, or a [`CoreError::Store`] on an
    /// IO failure.
    pub fn delete_account(&self, id: Uuid) -> Result<(), CoreError> {
        self.store.delete_account(id).map_err(|e| match e {
            StoreError::NotFound { .. } => CoreError::NoAccount(id),
            other => other.into(),
        })
    }

    /// Delete `id`, and the account behind it if no other profile still signs in as that account.
    ///
    /// The account is shared: two profiles can point at one login, and removing one of them must
    /// leave the other able to sign in. Only the last one out takes the account, its stored secrets,
    /// and its cached session with it.
    ///
    /// The rule lives here rather than in a caller so that every front end deletes the same way. A
    /// shell that reimplemented it would eventually reimplement it differently.
    ///
    /// Nothing is unlinked until the sweep is done. The whole removal is decided first, then the
    /// secrets go, and only then do the records: a failure anywhere before the first unlink leaves
    /// the profile exactly as it was, so the user can unlock the store and run the same command
    /// again. Deleting the profile first would strand the account behind it, and the account is
    /// reachable only *through* a profile.
    ///
    /// # Errors
    /// Returns [`CoreError::NoProfile`] if no such profile exists, [`CoreError::Secrets`] if the
    /// account's secrets could not be swept, or a [`CoreError::Store`] on an IO failure.
    pub fn remove_profile(&self, id: Uuid) -> Result<ProfileRemoval, CoreError> {
        let account = self.profile(id)?.account;
        // Decided before anything is removed, and excluding the profile on its way out: this is the
        // last user of the account if no *other* profile signs in as it.
        let last_user = !self
            .profiles()?
            .iter()
            .any(|p| p.id != id && p.account == account);

        if !last_user {
            self.delete_profile(id)?;
            return Ok(ProfileRemoval {
                account_removed: None,
                secrets_swept: false,
            });
        }

        let secrets_swept = self.forget_secrets(account)?;
        self.delete_profile(id)?;
        self.store.clear_uid_cache(account)?;
        self.delete_account(account)?;
        Ok(ProfileRemoval {
            account_removed: Some(account),
            secrets_swept,
        })
    }

    /// Delete the account with `id`, every secret stored for it, and its cached session.
    ///
    /// Answers whether the secrets were actually swept; see [`Core::forget_secrets`].
    ///
    /// The order is the point. Secrets go first, because they are the only part that cannot be found
    /// again once the record naming them is gone: the store is keyed by the account's id, so an
    /// account deleted while its password survived would leave that password unreachable and
    /// permanent. A sweep that fails therefore stops the deletion, and nothing has been removed yet,
    /// so the caller can retry once the store is reachable.
    ///
    /// # Errors
    /// Returns [`CoreError::Secrets`] if a sweep failed in a way that could have left a secret,
    /// [`CoreError::NoAccount`] if there is no such account, or a [`CoreError::Store`] on an IO
    /// failure.
    pub fn forget_account(&self, id: Uuid) -> Result<bool, CoreError> {
        let swept = self.forget_secrets(id)?;
        self.store.clear_uid_cache(id)?;
        self.delete_account(id)?;
        Ok(swept)
    }

    /// Delete every secret stored for `account`, leaving the account itself.
    ///
    /// What a user asks for when they want to stop the launcher remembering a password without
    /// giving up the login it belongs to.
    ///
    /// Answers `false` when no store answered at all: nothing was deleted, and anything a store
    /// holds for this account is still there. That is not an error, because a machine with no
    /// keyring must still be able to delete its accounts, but it is not a clean sweep either and a
    /// caller has to be able to say which happened.
    ///
    /// # Errors
    /// Returns [`CoreError::Secrets`] if the sweep failed in a way that could have left a secret
    /// behind.
    pub fn forget_secrets(&self, account: Uuid) -> Result<bool, CoreError> {
        match self.secrets.store().forget_account(account) {
            Ok(()) => Ok(true),
            Err(err) if could_hold_secrets(&err) => Err(err.into()),
            Err(_) => Ok(false),
        }
    }

    /// Where the sealed-file secret store keeps its file.
    ///
    /// Answered whatever backend is in use, because a front end offering to create one has to name
    /// the path before there is a store at it.
    #[must_use]
    pub fn secrets_path(&self) -> &Path {
        &self.secrets_path
    }

    /// What the credential store this launcher is using reports about itself.
    ///
    /// Codes, not prose: the caller writes the sentence. Never prompts.
    #[must_use]
    pub fn secrets_report(&self) -> BackendReport {
        self.secrets.store().probe()
    }

    /// Save `value` for `account`, replacing whatever was stored for that kind.
    ///
    /// Write-only by design: there is no matching read on this type. A stored secret is fetched
    /// where it is used, inside the login flow, so no front end ever holds one.
    ///
    /// # Errors
    /// Returns [`CoreError::Secrets`] with [`SecretsError::NotStoring`] if the account is set to
    /// keep nothing, [`CoreError::NoAccount`] if there is no such account, or the store's own
    /// failure.
    pub fn store_secret(
        &self,
        account: Uuid,
        kind: SecretKind,
        value: Secret,
    ) -> Result<(), CoreError> {
        if self.account_or_missing(account)?.never_store {
            return Err(SecretsError::NotStoring.into());
        }
        Ok(self.secrets.store().set(account, kind, value)?)
    }

    /// The account with `id`, reporting a miss as [`CoreError::NoAccount`] rather than as a store
    /// failure. [`Core::account`] predates the distinction and keeps its own contract.
    fn account_or_missing(&self, id: Uuid) -> Result<Account, CoreError> {
        self.store.load_account(id).map_err(|e| match e {
            StoreError::NotFound { .. } => CoreError::NoAccount(id),
            other => other.into(),
        })
    }

    /// Copy the password another launcher saved for `key` into this one's store for `account`.
    ///
    /// Answers what happened, which is three things and not two: a source with no reader on this
    /// target held nothing to copy, but so did a source that was read and was empty, and only the
    /// second of those is news about the user's other launcher. Reads `source` and writes ours; the
    /// other launcher's entry is left exactly as it was, because it is not this program's to remove
    /// and a user may still be running it.
    ///
    /// The refusal is decided before the source is touched. Reading one is not free of consequence:
    /// it connects to the platform credential store, which can raise the unlock prompt, or it opens
    /// the other launcher's plaintext file, and either way it materialises a password in this
    /// process. Doing that and then refusing to keep it is work and exposure spent on an account
    /// whose whole setting is that nothing is kept, and the refusal is a local record lookup.
    ///
    /// # Errors
    /// As [`Core::store_secret`], plus the source's own failure to read.
    pub fn import_password(
        &self,
        account: Uuid,
        source: &dyn ImportSource,
        key: &ForeignKey,
    ) -> Result<ImportOutcome, CoreError> {
        if self.account_or_missing(account)?.never_store {
            return Err(SecretsError::NotStoring.into());
        }
        match source.password(key)? {
            Import::Password(password) => {
                self.store_secret(account, SecretKind::Password, password)?;
                Ok(ImportOutcome::Imported)
            }
            Import::Nothing => Ok(ImportOutcome::Nothing),
            Import::Unsupported => Ok(ImportOutcome::Unsupported),
            // `Import` belongs to another crate and is `#[non_exhaustive]`. Nothing was stored on
            // any arm but the first, so a variant added later reads as nothing found, which is the
            // answer that claims the least.
            _ => Ok(ImportOutcome::Nothing),
        }
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
            steam: self.steam.clone(),
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

    /// An account that keeps nothing must not have the other launcher's password read at all.
    ///
    /// Reading the source is not free: it connects to the platform store, which can raise the
    /// unlock prompt, or opens the other launcher's plaintext file, and either way the password
    /// exists in this process before the refusal arrives. The refusal is a local record lookup, so
    /// the safe order costs nothing.
    #[test]
    fn an_account_that_keeps_nothing_is_refused_before_its_password_is_read() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use apogee_secrets::{ForeignKey, Import, ImportSource, Secret, SecretsError};

        use crate::model::AccountKind;

        struct Counting(AtomicUsize);

        impl ImportSource for Counting {
            fn password(&self, _key: &ForeignKey) -> Result<Import, SecretsError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(Import::Password(Secret::new(b"hunter2".to_vec())))
            }
        }

        let (_dir, core) = core();
        let account = Account {
            never_store: true,
            ..Account::new("keeps nothing", AccountKind::Standard)
        };
        let id = account.id;
        core.save_account(&account).unwrap();

        let source = Counting(AtomicUsize::new(0));
        let err = core
            .import_password(id, &source, &ForeignKey::from_stored_name("someone"))
            .expect_err("an account that keeps nothing must refuse");

        assert!(matches!(err, CoreError::Secrets(SecretsError::NotStoring)));
        assert_eq!(
            source.0.load(Ordering::Relaxed),
            0,
            "the source was read for an account that keeps nothing"
        );
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

    /// The stored preference decides which store is wired, and a run that cannot prompt still has to
    /// come up: a sealed-file store nobody can unlock reports itself unusable rather than failing
    /// construction, which is what keeps the profile and launch verbs working on a machine whose
    /// secrets are behind a passphrase nobody typed.
    ///
    /// Constructing does no I/O against the store, so a preference selecting a file that was never
    /// created reports having nothing to store into rather than being broken.
    #[test]
    fn the_stored_preference_picks_the_backend() {
        use std::sync::Arc;

        use apogee_secrets::{Backend, BackendState};
        use apogee_test_support::transport::FixtureTransport;

        use crate::model::{SecretBackend, Settings};

        let cases = [
            (SecretBackend::Platform, None),
            (
                SecretBackend::EncryptedFile,
                Some((Backend::EncryptedFile, BackendState::NoDefaultCollection)),
            ),
            (
                SecretBackend::Nothing,
                Some((Backend::Null, BackendState::NotStoring)),
            ),
        ];
        for (chosen, expected) in cases {
            let dir = TempDir::new().unwrap();
            let config = CoreConfig::with_base(dir.path());
            let core = Core::with_transport(config.clone(), Arc::new(FixtureTransport::new([])))
                .expect("construct");
            core.save_settings(&Settings {
                secret_backend: chosen,
                ..Settings::default()
            })
            .unwrap();

            let core = Core::with_transport(config, Arc::new(FixtureTransport::new([])))
                .expect("construct");
            if let Some((backend, state)) = expected {
                let report = core.secrets_report();
                assert_eq!(report.backend, backend, "{chosen:?}");
                assert_eq!(report.state, state, "{chosen:?}");
            }
            // The platform arm is deliberately not asserted on: what it reports is a fact about
            // whatever keyring the machine running the tests has, not about this selection.
        }
    }

    /// The path is on-disk contract. A change orphans every store already written under the old one,
    /// with no error at the point of the change.
    #[test]
    fn the_sealed_store_lives_beside_the_accounts_it_is_keyed_to() {
        let config = CoreConfig::with_base("/base");
        assert_eq!(
            config.secrets_path(),
            std::path::Path::new("/base/store/secrets.apsf")
        );
    }

    /// Deleting an account stops when a sweep might have left something. Both of the sealed store's
    /// own conditions have to count as "might", because a file that would not open still holds every
    /// secret that was in it, and an account deleted over one leaves them unreachable forever.
    #[test]
    fn a_store_that_would_not_open_blocks_an_account_deletion() {
        use apogee_secrets::SecretsError;

        assert!(super::could_hold_secrets(&SecretsError::WrongPassphrase));
        assert!(super::could_hold_secrets(&SecretsError::Corrupt {
            detail: "authentication tag"
        }));
        assert!(super::could_hold_secrets(&SecretsError::Locked));
        assert!(!super::could_hold_secrets(&SecretsError::NoCollection));
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

    /// The account lifecycle, driven against an in-memory store.
    ///
    /// Never against the platform one: these call the secret store for real, and the default backend
    /// is whatever keyring the machine running the tests has. A suite that wrote into a developer's
    /// login keyring, or raised its unlock dialog and waited on a human, would be a worse bug than
    /// anything it caught.
    mod lifecycle {
        use std::sync::Arc;

        use apogee_secrets::{
            Call, FailAt, ForeignKey, ForeignSecretsFile, MemoryStore, Secret, SecretKind,
            SecretStore, Secrets, SecretsError,
        };
        use apogee_test_support::transport::FixtureTransport;
        use tempfile::TempDir;
        use uuid::Uuid;

        use super::*;
        use crate::ImportOutcome;

        /// Build a core over `store`, keeping the handle so a test can read back what it recorded.
        fn core_with(store: Arc<MemoryStore>) -> (TempDir, Core) {
            let dir = TempDir::new().unwrap();
            let core = Core::with_secrets(
                CoreConfig::with_base(dir.path()),
                Arc::new(FixtureTransport::new([])),
                Secrets::with_backend(Box::new(SharedStore(Arc::clone(&store)))),
            )
            .unwrap();
            (dir, core)
        }

        /// Lets a test keep a handle on the store the core is using. `Secrets` takes ownership of its
        /// backend, so without this the recorded calls would be unreachable.
        struct SharedStore(Arc<MemoryStore>);

        impl apogee_secrets::SecretStore for SharedStore {
            fn get(&self, account: Uuid, kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
                self.0.get(account, kind)
            }
            fn set(
                &self,
                account: Uuid,
                kind: SecretKind,
                value: Secret,
            ) -> Result<(), SecretsError> {
                self.0.set(account, kind, value)
            }
            fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError> {
                self.0.delete(account, kind)
            }
            fn probe(&self) -> apogee_secrets::BackendReport {
                self.0.probe()
            }
        }

        fn seeded(core: &Core, store: &MemoryStore) -> (Account, Profile) {
            let account = Account::new("me@example.invalid", AccountKind::Standard);
            let profile = Profile::new("Main", account.id, "/games/ffxiv".into());
            core.save_account(&account).unwrap();
            core.save_profile(&profile).unwrap();
            for kind in SecretKind::ALL {
                store
                    .set(account.id, kind, Secret::new(b"stored".to_vec()))
                    .unwrap();
            }
            (account, profile)
        }

        /// Where the cached session for `account` lands under a core built with
        /// [`CoreConfig::with_base`]. Written and read as a path rather than through the store,
        /// which is private: what is being asserted is that no file survives, and that is a fact
        /// about the directory.
        fn uid_cache_path(base: &std::path::Path, account: Uuid) -> std::path::PathBuf {
            base.join("store")
                .join("uid-cache")
                .join(format!("{account}.json"))
        }

        /// The last profile out takes the account with it, and everything the account left behind:
        /// both stored secrets and the cached session. The cache is the one that had no caller on
        /// this path, so an account could be deleted while its session token stayed on disk.
        #[test]
        fn the_last_profile_removed_takes_the_account_and_its_residue() {
            let store = Arc::new(MemoryStore::new());
            let (dir, core) = core_with(Arc::clone(&store));
            let (account, profile) = seeded(&core, &store);
            let cached = uid_cache_path(dir.path(), account.id);
            std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
            std::fs::write(&cached, "{}").unwrap();

            let removal = core.remove_profile(profile.id).unwrap();

            assert_eq!(removal.account_removed, Some(account.id));
            assert!(store.is_empty(), "a secret survived the account");
            assert!(matches!(
                core.account(account.id),
                Err(CoreError::Store { .. } | CoreError::NoAccount(_))
            ));
            assert!(!cached.exists(), "the cached session survived the account");
        }

        /// An account shared by two profiles must survive the first of them. Sweeping its secrets
        /// here would log the other profile out of a login it still has.
        #[test]
        fn a_shared_account_survives_a_profile_that_used_it() {
            let store = Arc::new(MemoryStore::new());
            let (_dir, core) = core_with(Arc::clone(&store));
            let (account, profile) = seeded(&core, &store);
            let second = Profile::new("Alt", account.id, "/games/ffxiv".into());
            core.save_profile(&second).unwrap();

            let removal = core.remove_profile(profile.id).unwrap();

            assert_eq!(removal.account_removed, None);
            assert_eq!(store.len(), SecretKind::ALL.len());
            assert_eq!(core.account(account.id).unwrap().sqex_id, account.sqex_id);
        }

        /// A store that would not give a secret up blocks the deletion rather than orphaning it. The
        /// secrets are keyed by the account id, so an account removed while its password survived
        /// would leave that password with nothing left to name it.
        ///
        /// The profile has to survive too, and that is the half worth pinning: the account is
        /// reachable only through a profile, so a run that unlinked the profile and then failed the
        /// sweep would leave both the account and its secrets with nothing able to address them, and
        /// re-running the same command would report that there is no such profile.
        #[test]
        fn a_sweep_that_could_have_left_a_secret_stops_the_deletion() {
            let store =
                Arc::new(MemoryStore::new().failing(FailAt::Delete(Some(SecretKind::Password))));
            let (_dir, core) = core_with(Arc::clone(&store));
            let (account, profile) = seeded(&core, &store);

            let err = core.remove_profile(profile.id).unwrap_err();

            assert!(matches!(err, CoreError::Secrets(_)), "{err:?}");
            assert_eq!(core.account(account.id).unwrap().sqex_id, account.sqex_id);
            assert_eq!(
                core.profile(profile.id).unwrap().id,
                profile.id,
                "the profile was unlinked before the sweep, so the removal cannot be retried"
            );
            // Both kinds were still attempted. Giving up on the first would leave the other behind.
            assert_eq!(
                store.calls(),
                vec![
                    Call::Set(account.id, SecretKind::Password),
                    Call::Set(account.id, SecretKind::TotpSecret),
                    Call::Delete(account.id, SecretKind::Password),
                    Call::Delete(account.id, SecretKind::TotpSecret),
                ]
            );
        }

        /// The retry the failure path exists to allow. Once the store starts cooperating, the same
        /// command completes: nothing about the first attempt left the profile in a state the second
        /// cannot act on.
        #[test]
        fn a_removal_that_failed_on_the_sweep_succeeds_when_it_is_retried() {
            let failing =
                Arc::new(MemoryStore::new().failing(FailAt::Delete(Some(SecretKind::Password))));
            let (dir, core) = core_with(Arc::clone(&failing));
            let (account, profile) = seeded(&core, &failing);
            core.remove_profile(profile.id).unwrap_err();

            // The same store, now cooperating, reached through a second core over the same files.
            let working = Arc::new(MemoryStore::new());
            let core = Core::with_secrets(
                CoreConfig::with_base(dir.path()),
                Arc::new(FixtureTransport::new([])),
                Secrets::with_backend(Box::new(SharedStore(Arc::clone(&working)))),
            )
            .unwrap();

            let removal = core.remove_profile(profile.id).unwrap();

            assert_eq!(removal.account_removed, Some(account.id));
            assert!(removal.secrets_swept);
        }

        /// A store that answered nothing is reported rather than assumed empty. Its deletes did not
        /// happen, so anything it holds for this account has outlived the record naming it, and a
        /// caller has to be able to say so instead of printing a clean removal.
        #[test]
        fn a_removal_over_an_unreachable_store_says_the_secrets_were_not_swept() {
            let store = Arc::new(
                MemoryStore::new().failing_with(FailAt::Everything, || SecretsError::NoBackend),
            );
            let (_dir, core) = core_with(Arc::clone(&store));
            let account = Account::new("me@example.invalid", AccountKind::Standard);
            let profile = Profile::new("Main", account.id, "/games/ffxiv".into());
            core.save_account(&account).unwrap();
            core.save_profile(&profile).unwrap();

            let removal = core.remove_profile(profile.id).unwrap();

            assert_eq!(removal.account_removed, Some(account.id));
            assert!(
                !removal.secrets_swept,
                "an unreachable store was reported as a clean sweep"
            );
        }

        /// Which conditions block a deletion and which do not, asserted one variant at a time.
        ///
        /// Both directions matter and they fail differently. A condition wrongly treated as
        /// dangerous strands a user with no keyring, who can then never remove a profile; one
        /// wrongly treated as harmless deletes the account on top of a secret the store still holds.
        #[test]
        fn only_a_store_that_answered_blocks_a_deletion() {
            let cases: [(fn() -> SecretsError, bool); 5] = [
                (|| SecretsError::NoBackend, false),
                (|| SecretsError::NoCollection, false),
                (|| SecretsError::NotStoring, false),
                (|| SecretsError::Locked, true),
                (|| SecretsError::Denied, true),
            ];

            for (error, blocks) in cases {
                let store = Arc::new(MemoryStore::new().failing_with(FailAt::Everything, error));
                let (_dir, core) = core_with(Arc::clone(&store));
                let account = Account::new("me@example.invalid", AccountKind::Standard);
                let profile = Profile::new("Main", account.id, "/games/ffxiv".into());
                core.save_account(&account).unwrap();
                core.save_profile(&profile).unwrap();

                let removed = core.remove_profile(profile.id);
                let condition = error();

                assert_eq!(
                    removed.is_err(),
                    blocks,
                    "{condition} blocked the deletion: {blocks}"
                );
                // A blocked deletion leaves the profile behind, which is what makes it retryable.
                assert_eq!(core.profile(profile.id).is_ok(), blocks, "{condition}");
            }
        }

        /// The switch is enforced where the policy lives, not by whatever store happens to be wired:
        /// one `Secrets` serves every account, so a per-account rule cannot be a backend swap.
        #[test]
        fn an_account_set_to_keep_nothing_refuses_a_write() {
            let store = Arc::new(MemoryStore::new());
            let (_dir, core) = core_with(Arc::clone(&store));
            let account = Account {
                never_store: true,
                ..Account::new("me@example.invalid", AccountKind::Standard)
            };
            core.save_account(&account).unwrap();

            let err = core
                .store_secret(
                    account.id,
                    SecretKind::Password,
                    Secret::new(b"pw".to_vec()),
                )
                .unwrap_err();

            assert!(
                matches!(err, CoreError::Secrets(SecretsError::NotStoring)),
                "{err:?}"
            );
            assert!(store.is_empty(), "the refusal still reached the store");
        }

        /// The import reads the other launcher's copy and writes ours. Its copy is not this
        /// program's to remove, and a user who tries this launcher and goes back must find their
        /// old one working.
        #[test]
        fn an_imported_password_is_copied_and_the_source_is_left_alone() {
            let store = Arc::new(MemoryStore::new());
            let (dir, core) = core_with(Arc::clone(&store));
            let account = Account::new("Me@Example.invalid", AccountKind::Standard);
            core.save_account(&account).unwrap();
            let path = dir.path().join("secrets.json");
            std::fs::write(&path, r#"{"me@example.invalid":"imported-pw"}"#).unwrap();
            let source = ForeignSecretsFile::at(&path);
            let key = ForeignKey::from_stored_name(account.sqex_id.to_lowercase());

            assert_eq!(
                core.import_password(account.id, &source, &key).unwrap(),
                ImportOutcome::Imported
            );

            assert_eq!(
                store.stored(account.id, SecretKind::Password),
                Some(b"imported-pw".to_vec())
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                r#"{"me@example.invalid":"imported-pw"}"#,
                "the other launcher's copy was modified"
            );
        }

        /// Nothing to import is an answer, not a failure: it is what a user who never saved a
        /// password there sees, and it must not look like a broken import. `Nothing` specifically,
        /// and not `Unsupported`: a source that was read and held nothing has to stay tellable from
        /// one that was never read, since only the first is news about the other launcher.
        #[test]
        fn an_account_the_other_launcher_never_saved_imports_nothing() {
            let store = Arc::new(MemoryStore::new());
            let (dir, core) = core_with(Arc::clone(&store));
            let account = Account::new("me@example.invalid", AccountKind::Standard);
            core.save_account(&account).unwrap();
            let path = dir.path().join("secrets.json");
            std::fs::write(&path, r#"{"someone-else":"pw"}"#).unwrap();

            let imported = core
                .import_password(
                    account.id,
                    &ForeignSecretsFile::at(&path),
                    &ForeignKey::from_stored_name("me@example.invalid"),
                )
                .unwrap();

            assert_eq!(imported, ImportOutcome::Nothing);
            assert!(store.is_empty());
        }

        /// A source with no reader on this target is its own answer, and it must not be folded into
        /// the one above: the two store the same nothing and mean opposite things to a user.
        #[test]
        fn a_source_that_cannot_be_read_here_is_not_reported_as_nothing_saved() {
            use apogee_secrets::{Import, ImportSource, SecretsError};

            struct NoReader;

            impl ImportSource for NoReader {
                fn password(&self, _key: &ForeignKey) -> Result<Import, SecretsError> {
                    Ok(Import::Unsupported)
                }
            }

            let store = Arc::new(MemoryStore::new());
            let (_dir, core) = core_with(Arc::clone(&store));
            let account = Account::new("me@example.invalid", AccountKind::Standard);
            core.save_account(&account).unwrap();

            let outcome = core
                .import_password(
                    account.id,
                    &NoReader,
                    &ForeignKey::from_stored_name("me@example.invalid"),
                )
                .unwrap();

            assert_eq!(outcome, ImportOutcome::Unsupported);
            assert!(store.is_empty());
        }
    }
}
