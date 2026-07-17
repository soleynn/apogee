//! Versioned, no-delete persistence.
//!
//! Each entity is a JSON file wrapping a schema version around its data. Loading advances the data
//! through a migration chain to the current version before returning it. A file that will not parse
//! or migrate is copied aside and reported as [`StoreError::Corrupt`]; it is never deleted or
//! overwritten, so a bad file can always be inspected or restored. Writes are atomic
//! (write-temp-then-rename), so an interrupted save never leaves a half-file the next load misreads.

use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

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

/// A persisted type that knows its current schema version and how to advance an older one.
trait Migrate: Sized {
    /// The version this build reads and writes.
    const CURRENT_VERSION: u32;

    /// Advance `value` one step, from `from` to `from + 1`. Called repeatedly until the value
    /// reaches [`Migrate::CURRENT_VERSION`]. Returns a human-readable reason on an unknown step.
    fn migrate_step(from: u32, value: serde_json::Value) -> Result<serde_json::Value, String>;
}

impl Migrate for Profile {
    const CURRENT_VERSION: u32 = 1;
    fn migrate_step(from: u32, _value: serde_json::Value) -> Result<serde_json::Value, String> {
        Err(format!("no migration from schema version {from}"))
    }
}

impl Migrate for Account {
    const CURRENT_VERSION: u32 = 1;
    fn migrate_step(from: u32, _value: serde_json::Value) -> Result<serde_json::Value, String> {
        Err(format!("no migration from schema version {from}"))
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

impl Migrate for Settings {
    const CURRENT_VERSION: u32 = 2;
    fn migrate_step(from: u32, mut value: serde_json::Value) -> Result<serde_json::Value, String> {
        match from {
            // Gained the "close after launch" preference, defaulting off.
            1 => {
                let obj = value
                    .as_object_mut()
                    .ok_or_else(|| "settings payload is not a json object".to_string())?;
                obj.entry("close_after_launch")
                    .or_insert(serde_json::Value::Bool(false));
                Ok(value)
            }
            other => Err(format!("no migration from schema version {other}")),
        }
    }
}

/// Per-entity storage rooted at one base directory: `profiles/<id>.json`, `accounts/<id>.json`, and
/// `settings.json`. One file per entity keeps a corrupt file's blast radius to a single record.
///
/// A cheap handle over a path: clone it to share (the flow driver holds its own copy).
#[derive(Clone)]
pub struct Store {
    base: PathBuf,
}

impl Store {
    /// A store rooted at `base`. Directories are created lazily on first write.
    #[must_use]
    pub fn new(base: PathBuf) -> Self {
        Self { base }
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

    /// Serialize `value` under the current schema version and write it atomically.
    fn save<T>(&self, path: &Path, value: &T) -> Result<(), StoreError>
    where
        T: Serialize + Migrate,
    {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(io_at(parent))?;
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
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io_at(&tmp))?;
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
