//! `prefix.json`: the self-describing record of what a prefix is — the runner it was built with, its
//! DXVK, its installed components, and its setup history. Written when a prefix is initialized, read
//! by the health check, and updated as higher layers install into the prefix.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{RuntimeError, SetupStep};
use crate::plan::RunnerHandle;

/// The metadata filename, at the prefix root (a sibling of `drive_c`, never inside it).
pub const PREFIX_JSON: &str = "prefix.json";

/// The runner a prefix was built with, as recorded in `prefix.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRef {
    pub name: String,
    pub version: String,
}

impl From<&RunnerHandle> for RunnerRef {
    fn from(handle: &RunnerHandle) -> Self {
        Self {
            name: handle.name().to_owned(),
            version: handle.version().to_owned(),
        }
    }
}

/// The DXVK build installed into a prefix. `None` until the environment matrix installs one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DxvkRef {
    pub version: String,
    #[serde(default)]
    pub nvapi: bool,
}

/// One recorded prefix setup step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupRecord {
    pub step: SetupStep,
    /// When the step ran, RFC 3339 UTC. Diagnostic only; nothing keys off it.
    pub at: String,
    pub ok: bool,
    /// Extra detail, e.g. an installed version. Omitted when not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SetupRecord {
    /// A successful step stamped at the current time.
    pub(crate) fn ok(step: SetupStep) -> Self {
        Self {
            step,
            at: now_rfc3339(),
            ok: true,
            detail: None,
        }
    }
}

/// A prefix's `prefix.json` contents: the source of truth for what the prefix is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixMetadata {
    pub runner: RunnerRef,
    #[serde(default)]
    pub dxvk: Option<DxvkRef>,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub setup_history: Vec<SetupRecord>,
}

impl PrefixMetadata {
    /// A fresh record for a prefix built with `runner`, no DXVK or components yet.
    pub(crate) fn new(runner: RunnerRef) -> Self {
        Self {
            runner,
            dxvk: None,
            components: Vec::new(),
            setup_history: Vec::new(),
        }
    }

    /// Load `prefix.json` from `path`.
    ///
    /// `Ok(None)` if the file does not exist (an uninitialized prefix); `Ok(Some(_))` if it parses;
    /// [`RuntimeError::PrefixJson`] if it exists but is corrupt; [`RuntimeError::Io`] on any other
    /// read error. A corrupt file is a decision for the caller, not silently ignored.
    pub fn load(path: &Path) -> Result<Option<Self>, RuntimeError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(RuntimeError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let meta = serde_json::from_slice(&bytes).map_err(|source| RuntimeError::PrefixJson {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Some(meta))
    }

    /// Write `prefix.json` to `path` atomically: serialize to a temp sibling, then rename over the
    /// target, so a crash mid-write never leaves a half-written record.
    pub(crate) fn save(&self, path: &Path) -> Result<(), RuntimeError> {
        let json = serde_json::to_vec_pretty(self).map_err(|source| RuntimeError::PrefixJson {
            path: path.to_path_buf(),
            source,
        })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json).map_err(|source| RuntimeError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| RuntimeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    /// Append a setup step to the history.
    pub(crate) fn record(&mut self, step: SetupRecord) {
        self.setup_history.push(step);
    }
}

/// The current time as an RFC 3339 UTC string (`YYYY-MM-DDTHH:MM:SSZ`). A clock that is before the
/// epoch (unreachable in practice) formats as the epoch itself rather than failing.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format_rfc3339(secs)
}

/// Format `secs` seconds since the Unix epoch as RFC 3339 UTC.
fn format_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (hour, min, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Days since the Unix epoch → `(year, month, day)`, by Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_known_epochs() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap-day timestamp: 2024-02-29T12:00:00Z.
        assert_eq!(format_rfc3339(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn metadata_round_trips_through_json() {
        let mut meta = PrefixMetadata::new(RunnerRef {
            name: "UMU-Proton".to_owned(),
            version: "9-20".to_owned(),
        });
        meta.record(SetupRecord::ok(SetupStep::WinebootInit));
        meta.dxvk = Some(DxvkRef {
            version: "2.4.1".to_owned(),
            nvapi: true,
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(PREFIX_JSON);
        meta.save(&path).expect("save");

        let loaded = PrefixMetadata::load(&path).expect("load").expect("present");
        assert_eq!(loaded.runner, meta.runner);
        assert_eq!(loaded.dxvk, meta.dxvk);
        assert_eq!(loaded.setup_history.len(), 1);
        assert_eq!(loaded.setup_history[0].step, SetupStep::WinebootInit);
        assert!(loaded.setup_history[0].ok);
    }

    #[test]
    fn load_is_none_when_absent_and_errors_when_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(PREFIX_JSON);
        assert!(PrefixMetadata::load(&path).expect("absent load").is_none());

        std::fs::write(&path, b"{ not json").expect("write corrupt");
        let err = PrefixMetadata::load(&path).expect_err("corrupt");
        assert!(matches!(err, RuntimeError::PrefixJson { .. }));
    }

    #[test]
    fn step_serializes_as_snake_case() {
        let json = serde_json::to_string(&SetupStep::WinebootInit).expect("serialize");
        assert_eq!(json, "\"wineboot_init\"");
        let json = serde_json::to_string(&SetupStep::DxvkInstall).expect("serialize");
        assert_eq!(json, "\"dxvk_install\"");
    }
}
