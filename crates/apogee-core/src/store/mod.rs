//! Versioned, no-delete persistence.
//!
//! Each entity is a JSON file wrapping a schema version around its data. Loading advances the data
//! through a migration chain to the current version before returning it. A file that will not parse
//! or migrate is copied aside and reported as [`StoreError::Corrupt`]; it is never deleted or
//! overwritten, so a bad file can always be inspected or restored. The single exception is
//! [`Store::install_id`], which replaces its own corrupt file after the copy aside, because what it
//! holds is opaque randomness rather than anything a user could want back; a plain I/O failure
//! (permission denied, an unreadable mount) is not corruption and is never treated as one. Writes are
//! atomic (write-temp-then-rename), so an interrupted save never leaves a half-file the next load
//! misreads.

use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{Account, Profile, Settings};

#[cfg(test)]
mod tests;

/// Persistence failures. A load failure preserves the offending file rather than deleting it.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("{path:?} is corrupt (preserved at {backup:?}): {detail}")]
    Corrupt {
        path: PathBuf,
        backup: PathBuf,
        detail: String,
    },
    #[error("io error at {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("no stored file at {path:?}")]
    NotFound { path: PathBuf },
}

/// The on-disk envelope: a schema version wrapped around the entity data.
#[derive(Serialize, Deserialize)]
struct Stored<T> {
    schema_version: u32,
    data: T,
}

/// Create `dir` and its ancestors owner-only, and narrow it if an earlier build left it readable.
///
/// Narrowing an existing directory rather than only setting the mode on a new one is deliberate: an
/// install made before this was owner-only would otherwise keep exposing the same files forever.
fn private_dir(dir: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .or_else(|err| {
                if err.kind() == ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(err)
                }
            })
            .map_err(io_at(dir))?;
        let mode = fs::metadata(dir).map_err(io_at(dir))?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(mode & 0o700))
                .map_err(io_at(dir))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).map_err(io_at(dir))
    }
}

/// A persisted type that knows its current schema version and how to advance an older one.
trait Migrate: Sized {
    /// The version this build reads and writes.
    const CURRENT_VERSION: u32;

    /// Advance `value` one step, from `from` to `from + 1`. Called repeatedly until the value
    /// reaches [`Migrate::CURRENT_VERSION`]. Returns a human-readable reason on an unknown step.
    fn migrate_step(from: u32, value: serde_json::Value) -> Result<serde_json::Value, String>;
}

impl Migrate for Profile {
    const CURRENT_VERSION: u32 = 4;
    fn migrate_step(from: u32, mut value: serde_json::Value) -> Result<serde_json::Value, String> {
        let obj = value
            .as_object_mut()
            .ok_or_else(|| "profile payload is not a json object".to_string())?;
        match from {
            // Gained the user's own companion tools, starting empty.
            1 => {
                obj.entry("external")
                    .or_insert(serde_json::Value::Array(Vec::new()));
            }
            // Shed the curated companion set, and gained the Dalamud toggle beside the other launch
            // settings. The set is removed rather than left to be ignored: what it named is not
            // installable any more, and a field nothing reads is a field somebody will try to use.
            2 => {
                obj.remove("components");
                let launch = obj
                    .entry("launch")
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                let launch = launch
                    .as_object_mut()
                    .ok_or_else(|| "profile launch settings are not a json object".to_string())?;
                launch
                    .entry("dalamud")
                    .or_insert(serde_json::Value::Bool(false));
            }
            // Gained the graphics and synchronization knobs beside the launch settings that were
            // already there. Each is absent rather than written out, so a profile that has never been
            // touched resolves against the host instead of against a value it never chose.
            3 => {
                let launch = obj
                    .entry("launch")
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                launch
                    .as_object_mut()
                    .ok_or_else(|| "profile launch settings are not a json object".to_string())?;
            }
            other => return Err(format!("no migration from schema version {other}")),
        }
        Ok(value)
    }
}

impl Migrate for Account {
    const CURRENT_VERSION: u32 = 3;
    fn migrate_step(from: u32, mut value: serde_json::Value) -> Result<serde_json::Value, String> {
        let obj = value
            .as_object_mut()
            .ok_or_else(|| "account payload is not a json object".to_string())?;
        match from {
            // Gained the switch that keeps this account's secrets out of the store. Off for an
            // account that predates it: it was saving its password already, and turning that off
            // underneath a user would look like the launcher had forgotten it.
            1 => {
                obj.entry("never_store")
                    .or_insert(serde_json::Value::Bool(false));
            }
            // Nothing to insert. The delivery field gained a third value rather than a new key, so
            // every older file still reads, and this arm exists only so the version moves: a build
            // that predates the new value would otherwise meet it under a version it recognizes,
            // fail to deserialize, and report the file as corrupt instead of as one a newer launcher
            // wrote.
            2 => {}
            other => return Err(format!("no migration from schema version {other}")),
        }
        Ok(value)
    }
}

/// A cached session-registration result for an account, valid until `expires_at`. Persisted so a
/// re-login inside the window skips OAuth and registration and launches straight from the cached
/// token (XL's `UniqueIdCache`, relocated here).
///
/// The `unique_id` is a session-scoped token, not a login credential: it expires with the window and
/// cannot be replayed afterward. Persisting it is the one deliberate exception to the redacted
/// newtype's "callers must not persist" rule; no password or OAuth session id is ever stored here.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UidCacheEntry {
    pub(crate) unique_id: String,
    pub(crate) region: u16,
    pub(crate) max_expansion: u8,
    pub(crate) game_version: String,
    /// Whole seconds since the Unix epoch after which this entry is stale.
    pub(crate) expires_at: u64,
}

impl UidCacheEntry {
    /// Whether this entry is still usable at `now` (seconds since the epoch) for an install at
    /// `game_version`. An install patched since caching changes its version and invalidates the token.
    #[allow(dead_code)]
    pub(crate) fn is_valid(&self, now: u64, game_version: &str) -> bool {
        now < self.expires_at && self.game_version == game_version
    }
}

impl Migrate for UidCacheEntry {
    const CURRENT_VERSION: u32 = 1;
    fn migrate_step(from: u32, _value: serde_json::Value) -> Result<serde_json::Value, String> {
        Err(format!("no migration from schema version {from}"))
    }
}

/// The install id (see [`Store::install_id`]) is a bare identifier with no fields, but it goes
/// through the same versioned envelope as every other entity so a later format has somewhere to go.
impl Migrate for Uuid {
    const CURRENT_VERSION: u32 = 1;
    fn migrate_step(from: u32, _value: serde_json::Value) -> Result<serde_json::Value, String> {
        Err(format!("no migration from schema version {from}"))
    }
}

impl Migrate for Settings {
    const CURRENT_VERSION: u32 = 7;
    fn migrate_step(from: u32, mut value: serde_json::Value) -> Result<serde_json::Value, String> {
        let obj = value
            .as_object_mut()
            .ok_or_else(|| "settings payload is not a json object".to_string())?;
        match from {
            // Gained the "close after launch" preference, defaulting off.
            1 => {
                obj.entry("close_after_launch")
                    .or_insert(serde_json::Value::Bool(false));
            }
            // Gained the "keep patches" preference, defaulting off.
            2 => {
                obj.entry("keep_patches")
                    .or_insert(serde_json::Value::Bool(false));
            }
            // Gained the config-backup retention count.
            3 => {
                obj.entry("backups_kept")
                    .or_insert(serde_json::Value::from(5));
            }
            // Gained the pre-patch capture, on by default.
            4 => {
                obj.entry("backup_before_patch")
                    .or_insert(serde_json::Value::Bool(true));
            }
            // Gained the choice of where secrets are kept. The platform store is what every existing
            // install was already using, so migrating to anything else would move a user off the
            // store their password is actually in.
            5 => {
                obj.entry("secret_backend")
                    .or_insert(serde_json::Value::from("platform"));
            }
            // Gained where a companion pushes a one-time code. The default admits anything on every
            // interface, and inserting it opens nothing: no port is taken until an account is pointed
            // at the listener, which is a separate decision that takes an acknowledgment. A migration
            // that pointed an account there would be opening a port on a machine whose owner never
            // asked for one.
            6 => {
                obj.entry("otp_listener").or_insert(
                    serde_json::to_value(crate::model::ListenerSettings::default()).map_err(
                        |err| format!("the default listener settings do not encode: {err}"),
                    )?,
                );
            }
            other => return Err(format!("no migration from schema version {other}")),
        }
        Ok(value)
    }
}

/// Per-entity storage rooted at one base directory: `profiles/<id>.json`, `accounts/<id>.json`, and
/// `settings.json`. One file per entity keeps a corrupt file's blast radius to a single record.
///
/// A cheap handle over a path: clone it to share (the flow driver holds its own copy). Cloning also
/// shares [`Store::ephemeral_install_id`]'s memoized value, which is the point of that slot: every
/// clone of one `Store` is the same install for the life of the process.
#[derive(Clone)]
pub struct Store {
    base: PathBuf,
    ephemeral_install_id: Arc<Mutex<Option<Uuid>>>,
}

impl Store {
    /// A store rooted at `base`. Directories are created lazily on first write.
    #[must_use]
    pub fn new(base: PathBuf) -> Self {
        Self {
            base,
            ephemeral_install_id: Arc::new(Mutex::new(None)),
        }
    }

    fn profiles_dir(&self) -> PathBuf {
        self.base.join("profiles")
    }

    fn accounts_dir(&self) -> PathBuf {
        self.base.join("accounts")
    }

    fn uid_cache_dir(&self) -> PathBuf {
        self.base.join("uid-cache")
    }

    fn settings_file(&self) -> PathBuf {
        self.base.join("settings.json")
    }

    fn install_id_file(&self) -> PathBuf {
        self.base.join("install-id.json")
    }

    fn profile_path(&self, id: Uuid) -> PathBuf {
        self.profiles_dir().join(format!("{id}.json"))
    }

    fn account_path(&self, id: Uuid) -> PathBuf {
        self.accounts_dir().join(format!("{id}.json"))
    }

    fn uid_cache_path(&self, account: Uuid) -> PathBuf {
        self.uid_cache_dir().join(format!("{account}.json"))
    }

    /// Persist `profile`, keyed by its id.
    pub fn save_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        self.save(&self.profile_path(profile.id), profile)
    }

    /// Load the profile with `id`. A missing profile is [`StoreError::NotFound`].
    pub fn load_profile(&self, id: Uuid) -> Result<Profile, StoreError> {
        self.load(&self.profile_path(id))
    }

    /// Remove the profile with `id`. A missing profile is [`StoreError::NotFound`].
    pub fn delete_profile(&self, id: Uuid) -> Result<(), StoreError> {
        self.remove(self.profile_path(id))
    }

    /// Every stored profile. A missing directory is an empty list, not an error.
    pub fn list_profiles(&self) -> Result<Vec<Profile>, StoreError> {
        self.list_dir(&self.profiles_dir())
    }

    /// Persist `account`, keyed by its id.
    pub fn save_account(&self, account: &Account) -> Result<(), StoreError> {
        self.save(&self.account_path(account.id), account)
    }

    /// Load the account with `id`. A missing account is [`StoreError::NotFound`].
    pub fn load_account(&self, id: Uuid) -> Result<Account, StoreError> {
        self.load(&self.account_path(id))
    }

    /// Every stored account. A missing directory is an empty list, not an error.
    pub fn list_accounts(&self) -> Result<Vec<Account>, StoreError> {
        self.list_dir(&self.accounts_dir())
    }

    /// Remove the account with `id`. A missing account is [`StoreError::NotFound`].
    pub fn delete_account(&self, id: Uuid) -> Result<(), StoreError> {
        self.remove(self.account_path(id))
    }

    /// Delete `path`, mapping a missing file to [`StoreError::NotFound`] (the shared shape for the
    /// entity deletes; `clear_uid_cache`'s missing-is-Ok variant is deliberately separate).
    fn remove(&self, path: PathBuf) -> Result<(), StoreError> {
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StoreError::NotFound { path }),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }

    /// Load and deserialize every `.json` entity in `dir`. A missing directory is an empty list; a
    /// `.corrupt` backup or `.tmp` write-in-progress is skipped.
    fn list_dir<T>(&self, dir: &Path) -> Result<Vec<T>, StoreError>
    where
        T: DeserializeOwned + Migrate,
    {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(StoreError::Io {
                    path: dir.to_path_buf(),
                    source,
                });
            }
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io_at(dir))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                out.push(self.load(&path)?);
            }
        }
        Ok(out)
    }

    /// Persist launcher-wide settings.
    pub fn save_settings(&self, settings: &Settings) -> Result<(), StoreError> {
        self.save(&self.settings_file(), settings)
    }

    /// Load launcher-wide settings, defaulting when none is stored yet.
    pub fn load_settings(&self) -> Result<Settings, StoreError> {
        match self.load(&self.settings_file()) {
            Ok(settings) => Ok(settings),
            Err(StoreError::NotFound { .. }) => Ok(Settings::default()),
            Err(other) => Err(other),
        }
    }

    /// This install's own identifier: a random value minted on the first read and kept from then
    /// on. It is derived from nothing about the machine, which is what makes it safe to present
    /// off-host, and it is not a preference, so it lives here rather than in [`Settings`].
    ///
    /// A stored value that will not parse is replaced rather than reported. Its content is opaque
    /// randomness with nothing in it to recover, the load has already copied the offending bytes
    /// aside, and refusing to start over an unreadable one buys nobody anything. An [`StoreError::Io`]
    /// is a different failure entirely, permission denied, a mount gone away mid-read, with a file
    /// that may well hold the real id: minting fresh over that would silently and permanently rotate
    /// the identity, so it propagates instead.
    pub fn install_id(&self) -> Result<Uuid, StoreError> {
        let path = self.install_id_file();
        match self.load::<Uuid>(&path) {
            Ok(id) => return Ok(id),
            Err(StoreError::NotFound { .. } | StoreError::Corrupt { .. }) => {}
            Err(err) => return Err(err),
        }
        let id = Uuid::new_v4();
        self.save(&path, &id)?;
        Ok(id)
    }

    /// A stand-in for [`Store::install_id`] for the rest of this process, for a caller that already
    /// decided the real one cannot be had (an [`StoreError::Io`] from [`Store::install_id`]). Minted
    /// once and kept in memory for the life of this handle and every clone of it, never written to
    /// disk: a second call, from a second call site, in the same run gets back the same value instead
    /// of a fresh one, matching what "a value good for one run" is supposed to mean. A new process, or
    /// a `Store` built fresh rather than cloned, mints again.
    #[must_use]
    pub fn ephemeral_install_id(&self) -> Uuid {
        let mut slot = self
            .ephemeral_install_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *slot.get_or_insert_with(Uuid::new_v4)
    }

    /// Serialize `value` under the current schema version and write it atomically.
    fn save<T>(&self, path: &Path, value: &T) -> Result<(), StoreError>
    where
        T: Serialize + Migrate,
    {
        if let Some(parent) = path.parent() {
            private_dir(parent)?;
        }
        let envelope = Stored {
            schema_version: T::CURRENT_VERSION,
            data: value,
        };
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| StoreError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(ErrorKind::InvalidData, e),
        })?;

        // Write to a per-write unique temp name opened with create_new: a concurrent save of the same
        // entity cannot truncate our in-flight bytes (each has its own temp), and a pre-existing file
        // or planted symlink at the temp name is rejected (EEXIST) rather than followed. list_profiles
        // ignores non-".json" names, so the temp is never read as an entity.
        let tmp = suffixed(path, &format!("{}.tmp", Uuid::new_v4()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Owner-only from the moment it exists, never widened by a later chmod: these files carry
        // account identity, a live registration id, and the list of programs the launcher executes.
        // The mode travels with the rename, so the entity is private too.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&tmp).map_err(io_at(&tmp))?;
        file.write_all(&bytes).map_err(io_at(&tmp))?;
        file.sync_all().map_err(io_at(&tmp))?;
        drop(file);

        fs::rename(&tmp, path).map_err(io_at(path))?;

        // Fsync the containing directory so the rename (a directory-metadata change) is durable, not
        // just the file's contents; otherwise a crash right after this returns could lose the entry.
        // Best-effort: directories are not uniformly fsync-able across platforms, and the atomic
        // rename already guarantees no torn file.
        if let Some(parent) = path.parent() {
            let _ = fs::File::open(parent).and_then(|dir| dir.sync_all());
        }
        Ok(())
    }

    /// Read `path`, migrate it forward to the current schema version, and deserialize it. Any parse
    /// or migration failure preserves the file aside and reports [`StoreError::Corrupt`].
    fn load<T>(&self, path: &Path) -> Result<T, StoreError>
    where
        T: DeserializeOwned + Migrate,
    {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(StoreError::NotFound {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(StoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };

        let envelope: Stored<serde_json::Value> = match serde_json::from_slice(&bytes) {
            Ok(envelope) => envelope,
            Err(e) => return Err(preserve(path, &bytes, e.to_string())),
        };

        let mut version = envelope.schema_version;
        let mut data = envelope.data;
        while version < T::CURRENT_VERSION {
            data = match T::migrate_step(version, data) {
                Ok(next) => next,
                Err(detail) => {
                    return Err(preserve(
                        path,
                        &bytes,
                        format!("migration from schema version {version}: {detail}"),
                    ));
                }
            };
            version += 1;
        }
        if version > T::CURRENT_VERSION {
            return Err(preserve(
                path,
                &bytes,
                format!(
                    "schema version {version} is newer than supported version {}",
                    T::CURRENT_VERSION
                ),
            ));
        }

        serde_json::from_value(data).map_err(|e| preserve(path, &bytes, e.to_string()))
    }
}

/// The session cache: per-account registration tokens with a validity window. Dormant until the
/// login flow reads and writes them.
#[allow(dead_code)]
impl Store {
    /// Persist the session-cache `entry` for `account`.
    pub fn save_uid_cache(&self, account: Uuid, entry: &UidCacheEntry) -> Result<(), StoreError> {
        self.save(&self.uid_cache_path(account), entry)
    }

    /// The session-cache entry for `account`, or `None` when none is stored. A corrupt entry is
    /// preserved and surfaced as [`StoreError::Corrupt`] (the caller falls back to a full login).
    pub fn load_uid_cache(&self, account: Uuid) -> Result<Option<UidCacheEntry>, StoreError> {
        match self.load(&self.uid_cache_path(account)) {
            Ok(entry) => Ok(Some(entry)),
            Err(StoreError::NotFound { .. }) => Ok(None),
            Err(other) => Err(other),
        }
    }

    /// Drop the session-cache entry for `account`. A missing entry is not an error.
    pub fn clear_uid_cache(&self, account: Uuid) -> Result<(), StoreError> {
        let path = self.uid_cache_path(account);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }
}

/// Copy the original bytes aside to a unique `<path>.<uuid>.corrupt` sidecar (best effort) and build
/// the corrupt error. The sidecar is opened with create_new so a pre-existing file or planted symlink
/// at that name is not followed; the original file is always left untouched, so no-delete holds even
/// if the backup cannot be written.
fn preserve(path: &Path, original: &[u8], detail: String) -> StoreError {
    let backup = suffixed(path, &format!("{}.corrupt", Uuid::new_v4()));
    let _ = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)
        .and_then(|mut file| file.write_all(original));
    StoreError::Corrupt {
        path: path.to_path_buf(),
        backup,
        detail,
    }
}

/// A `.map_err` closure that tags an [`io::Error`] with the `path` it occurred on, so every store
/// `Io` error still names the specific file that failed.
fn io_at(path: &Path) -> impl Fn(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Append `.<suffix>` to a path's full file name (e.g. `settings.json` -> `settings.json.corrupt`).
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}
