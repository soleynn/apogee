//! `prefix.json`: the record a prefix keeps of what it is.
//!
//! The runner it was built with, its DXVK, the components and verbs installed into it, and the
//! setup steps that ran. Written when a prefix is initialized, read by the health check, and updated
//! as higher layers install into the prefix.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{RuntimeError, SetupStep};
use crate::plan::RunnerHandle;

/// The metadata filename, written at the prefix root and never inside `drive_c`.
pub const PREFIX_JSON: &str = "prefix.json";

/// The runner a prefix was built with, as recorded in `prefix.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRef {
    /// The runner's name, as its catalog row spells it.
    pub name: String,
    /// The runner's version, `custom` for a runner that did not come from the catalog.
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
    /// The version that was installed, as the catalog row spelled it.
    pub version: String,
    /// Whether the `dxvk-nvapi` companion went in beside it. The health check reads this rather than
    /// looking for the DLL, which a Proton prefix carries either way.
    #[serde(default)]
    pub nvapi: bool,
}

/// One recorded prefix setup step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupRecord {
    /// Which step ran.
    pub step: SetupStep,
    /// When the step ran, RFC 3339 UTC. Diagnostic only; nothing keys off it.
    pub at: String,
    /// Whether it succeeded. Only successful steps are recorded today, so this is always true in a
    /// file the launcher wrote.
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

    /// A successful step carrying a detail (e.g. the installed DXVK version).
    pub(crate) fn ok_with(step: SetupStep, detail: impl Into<String>) -> Self {
        Self {
            step,
            at: now_rfc3339(),
            ok: true,
            detail: Some(detail.into()),
        }
    }
}

/// A component or verb a prefix records as present.
///
/// Serializes untagged: as a bare string when it carries no version, which is what a verb is and
/// what an older build wrote for everything, and as an object when it does. Both spellings
/// deserialize, so a `prefix.json` from before versions were kept still loads.
///
/// The version is what makes "already installed" answerable when a manifest row is bumped. Matching
/// on the name alone would report a prefix as up to date against a row it has never seen, turning a
/// version bump into a no-op instead of an install.
///
/// # Examples
///
/// ```
/// use apogee_runtime::InstalledComponent;
///
/// let verb = InstalledComponent::Name("corefonts".to_owned());
/// assert_eq!(verb.name(), "corefonts");
/// assert_eq!(verb.version(), None);
///
/// let component = InstalledComponent::Versioned {
///     name: "ACT".to_owned(),
///     version: "3.9.0".to_owned(),
/// };
/// assert_eq!(component.version(), Some("3.9.0"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InstalledComponent {
    /// A verb, or a component an older build recorded without a version.
    Name(String),
    /// A component and the version that was installed.
    Versioned {
        /// The component's name.
        name: String,
        /// The version that was installed.
        version: String,
    },
}

impl InstalledComponent {
    /// The component's name, whichever way the record spells it.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) | Self::Versioned { name, .. } => name,
        }
    }

    /// The version recorded, if the record carries one.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Name(_) => None,
            Self::Versioned { version, .. } => Some(version),
        }
    }
}

/// A prefix's `prefix.json` contents: the source of truth for what the prefix is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixMetadata {
    /// The runner the prefix was built with. The health check compares it against the runner a
    /// launch wants.
    pub runner: RunnerRef,
    /// The DXVK build installed into the prefix, absent until one is.
    #[serde(default)]
    pub dxvk: Option<DxvkRef>,
    /// What is installed, one entry per name: a set, not a log.
    #[serde(default)]
    pub components: Vec<InstalledComponent>,
    /// How the prefix got here, in the order the steps ran: a log, not a set.
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

    /// Load `prefix.json` from `path`, `Ok(None)` if there is no file there.
    ///
    /// An absent file is an uninitialized prefix; a corrupt one is a decision for the caller rather
    /// than something to ignore.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::PrefixJson`] if the file exists but does not parse,
    /// [`RuntimeError::Io`] on any read error other than not-found.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::path::Path;
    /// # use apogee_runtime::{PREFIX_JSON, PrefixMetadata, RuntimeError};
    /// # fn demo(prefix_root: &Path) -> Result<(), RuntimeError> {
    /// if let Some(meta) = PrefixMetadata::load(&prefix_root.join(PREFIX_JSON))? {
    ///     let built_with = (&meta.runner.name, &meta.runner.version);
    /// #   let _ = built_with;
    /// }
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// # Errors
    ///
    /// [`RuntimeError::PrefixJson`] if serialization fails, [`RuntimeError::Io`] if the temp file
    /// cannot be written or the rename fails.
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

/// Note `component` as present in the prefix whose record lives at `path`, appending `step`
/// (carrying `detail`) to the history. Returns whether the component was newly added.
///
/// The component list is keyed on the name, so a re-apply or an upgrade replaces the entry rather
/// than adding one, while the history shows both runs: what is installed and what was done to get
/// there are different questions, and conflating them loses the second one. A prefix with no record
/// yet gets one built from `fallback_runner`.
///
/// Read-modify-write against one file, so two installs into the *same* prefix at the same time can
/// lose a record. Nothing in the launcher does that, and the alternative (a lock file inside the
/// prefix) buys a failure mode of its own.
///
/// # Errors
///
/// Whatever [`PrefixMetadata::load`] and [`PrefixMetadata::save`] raise:
/// [`RuntimeError::PrefixJson`] for a record that will not parse or serialize,
/// [`RuntimeError::Io`] for a read or write that fails.
pub(crate) fn record_component(
    path: &Path,
    fallback_runner: RunnerRef,
    component: &str,
    version: Option<&str>,
    step: SetupStep,
    detail: &str,
) -> Result<bool, RuntimeError> {
    let mut meta =
        PrefixMetadata::load(path)?.unwrap_or_else(|| PrefixMetadata::new(fallback_runner));
    let entry = match version {
        Some(version) => InstalledComponent::Versioned {
            name: component.to_owned(),
            version: version.to_owned(),
        },
        None => InstalledComponent::Name(component.to_owned()),
    };
    let added = match meta.components.iter_mut().find(|c| c.name() == component) {
        // Replaced rather than left alone, so an upgraded component's record says which version is
        // actually on disk. Reporting "already there" for a different version is what would make a
        // manifest bump invisible.
        Some(existing) => {
            *existing = entry;
            false
        }
        None => {
            meta.components.push(entry);
            true
        }
    };
    meta.record(SetupRecord::ok_with(step, detail));
    meta.save(path)?;
    Ok(added)
}

/// The current time as an RFC 3339 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// A clock reading before the epoch (unreachable in practice) formats as the epoch itself rather
/// than failing.
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

/// Convert days since the Unix epoch to a `(year, month, day)` triple.
///
/// Howard Hinnant's `civil_from_days`: shifting the year to start in March makes the leap day the
/// last day of it, so the month and day fall out of integer arithmetic with no lookup table.
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

    /// The hand-rolled calendar agrees with known timestamps, including across a leap day, which is
    /// the case a day-count conversion gets wrong.
    #[test]
    fn rfc3339_formats_known_epochs() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap-day timestamp: 2024-02-29T12:00:00Z.
        assert_eq!(format_rfc3339(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    /// A saved record reloads with every field intact, so `prefix.json` is a record and not just a
    /// marker file.
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

    /// The two ways a record can be unreadable stay distinct: no file is an uninitialized prefix,
    /// while a file that will not parse is an error the caller has to decide about.
    #[test]
    fn load_is_none_when_absent_and_errors_when_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(PREFIX_JSON);
        assert!(PrefixMetadata::load(&path).expect("absent load").is_none());

        std::fs::write(&path, b"{ not json").expect("write corrupt");
        let err = PrefixMetadata::load(&path).expect_err("corrupt");
        assert!(matches!(err, RuntimeError::PrefixJson { .. }));
    }

    /// The step names are on-disk contract: rename a variant and every existing prefix's record
    /// stops loading.
    #[test]
    fn step_serializes_as_snake_case() {
        let json = serde_json::to_string(&SetupStep::WinebootInit).expect("serialize");
        assert_eq!(json, "\"wineboot_init\"");
        let json = serde_json::to_string(&SetupStep::DxvkInstall).expect("serialize");
        assert_eq!(json, "\"dxvk_install\"");
        let json = serde_json::to_string(&SetupStep::VerbApply).expect("serialize");
        assert_eq!(json, "\"verb_apply\"");
        let json = serde_json::to_string(&SetupStep::ComponentInstall).expect("serialize");
        assert_eq!(json, "\"component_install\"");
    }

    /// What is installed and what was done to get there are different questions. The component list
    /// is a set, so a re-apply is one entry; the history is a log, so a re-apply is two lines.
    /// Collapsing them either duplicates the list or hides that a step ran twice.
    #[test]
    fn recording_the_same_component_twice_lists_it_once_and_logs_it_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(PREFIX_JSON);
        let runner = RunnerRef {
            name: "wine".to_owned(),
            version: "custom".to_owned(),
        };
        PrefixMetadata::new(runner.clone())
            .save(&path)
            .expect("seed");

        assert!(
            record_component(
                &path,
                runner.clone(),
                "corefonts",
                None,
                SetupStep::VerbApply,
                "corefonts"
            )
            .expect("first"),
            "the first record adds it"
        );
        assert!(
            !record_component(
                &path,
                runner,
                "corefonts",
                None,
                SetupStep::VerbApply,
                "corefonts"
            )
            .expect("second"),
            "the second record reports it was already there"
        );

        let meta = PrefixMetadata::load(&path).expect("load").expect("present");
        assert_eq!(
            meta.components,
            [InstalledComponent::Name("corefonts".to_owned())]
        );
        assert_eq!(
            meta.setup_history
                .iter()
                .filter(|r| r.step == SetupStep::VerbApply)
                .count(),
            2
        );
    }

    /// A prefix whose record was lost still records what is installed into it now, rather than
    /// refusing until someone re-runs a repair.
    #[test]
    fn recording_into_a_prefix_with_no_record_writes_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(PREFIX_JSON);
        let runner = RunnerRef {
            name: "GE-Proton".to_owned(),
            version: "11-1".to_owned(),
        };

        record_component(
            &path,
            runner.clone(),
            "ACT",
            Some("3.9.0"),
            SetupStep::ComponentInstall,
            "ACT 3.9.0",
        )
        .expect("record");
        let meta = PrefixMetadata::load(&path).expect("load").expect("present");
        assert_eq!(meta.runner, runner);
        assert_eq!(meta.components[0].name(), "ACT");
        assert_eq!(meta.components[0].version(), Some("3.9.0"));
        assert_eq!(meta.setup_history[0].detail.as_deref(), Some("ACT 3.9.0"));
    }

    /// A bumped row has to replace the entry rather than sit beside it, or the record would claim
    /// two versions of one component and "which is on disk" would have no answer.
    #[test]
    fn recording_an_upgrade_replaces_the_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(PREFIX_JSON);
        let runner = RunnerRef {
            name: "wine".to_owned(),
            version: "custom".to_owned(),
        };

        for version in ["3.9.0", "3.9.1"] {
            record_component(
                &path,
                runner.clone(),
                "ACT",
                Some(version),
                SetupStep::ComponentInstall,
                &format!("ACT {version}"),
            )
            .expect("record");
        }

        let meta = PrefixMetadata::load(&path).expect("load").expect("present");
        assert_eq!(meta.components.len(), 1);
        assert_eq!(meta.components[0].version(), Some("3.9.1"));
        // Both installs are in the history: the list says what is there, the log says how it got there.
        assert_eq!(meta.setup_history.len(), 2);
    }

    /// A `prefix.json` written before versions were kept has to keep loading, and a bare name is
    /// also how a verb is written now, so the two spellings both have to round-trip.
    #[test]
    fn a_record_without_versions_still_loads_and_a_versioned_one_round_trips() {
        let json = br#"{
          "runner": { "name": "wine", "version": "custom" },
          "components": ["corefonts", { "name": "ACT", "version": "3.9.0" }]
        }"#;
        let meta: PrefixMetadata = serde_json::from_slice(json).expect("an older record loads");
        assert_eq!(
            meta.components[0],
            InstalledComponent::Name("corefonts".to_owned())
        );
        assert_eq!(meta.components[1].version(), Some("3.9.0"));

        let round_tripped: PrefixMetadata =
            serde_json::from_slice(&serde_json::to_vec(&meta).expect("serialize")).expect("parse");
        assert_eq!(round_tripped.components, meta.components);
        // A verb still serializes as a bare string, so nothing older chokes on reading it back.
        let text = serde_json::to_string(&meta).expect("serialize");
        assert!(text.contains("\"corefonts\""), "{text}");
    }
}
