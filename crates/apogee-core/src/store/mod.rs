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

use crate::model::{Profile, Settings};

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

    fn settings_file(&self) -> PathBuf {
        self.base.join("settings.json")
    }

    fn profile_path(&self, id: Uuid) -> PathBuf {
        self.profiles_dir().join(format!("{id}.json"))
    }

    /// Persist `profile`, keyed by its id.
    pub fn save_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        self.save(&self.profile_path(profile.id), profile)
    }

    /// Remove the profile with `id`. A missing profile is [`StoreError::NotFound`].
    pub fn delete_profile(&self, id: Uuid) -> Result<(), StoreError> {
        let path = self.profile_path(id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StoreError::NotFound { path }),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }

    /// Every stored profile. A missing directory is an empty list, not an error.
    pub fn list_profiles(&self) -> Result<Vec<Profile>, StoreError> {
        let dir = self.profiles_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(StoreError::Io { path: dir, source }),
        };
        let mut profiles = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| StoreError::Io {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            // Only entity files; a `.corrupt` backup or `.tmp` write-in-progress is skipped.
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                profiles.push(self.load(&path)?);
            }
        }
        Ok(profiles)
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
            fs::create_dir_all(parent).map_err(|source| StoreError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let envelope = Stored {
            schema_version: T::CURRENT_VERSION,
            data: value,
        };
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| StoreError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(ErrorKind::InvalidData, e),
        })?;

        let tmp = suffixed(path, "tmp");
        let mut file = fs::File::create(&tmp).map_err(|source| StoreError::Io {
            path: tmp.clone(),
            source,
        })?;
        file.write_all(&bytes).map_err(|source| StoreError::Io {
            path: tmp.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| StoreError::Io {
            path: tmp.clone(),
            source,
        })?;
        drop(file);

        fs::rename(&tmp, path).map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })
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

/// Copy the original bytes aside to `<path>.corrupt` (best effort) and build the corrupt error. The
/// original file is left untouched.
fn preserve(path: &Path, original: &[u8], detail: String) -> StoreError {
    let backup = suffixed(path, "corrupt");
    let _ = fs::write(&backup, original);
    StoreError::Corrupt {
        path: path.to_path_buf(),
        backup,
        detail,
    }
}

/// Append `.<suffix>` to a path's full file name (e.g. `settings.json` -> `settings.json.corrupt`).
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}
