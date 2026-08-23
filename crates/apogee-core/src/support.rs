//! Support-bundle contents and the public system report.
//!
//! This module owns the bytes that may leave the machine for diagnostics. Callers contribute only
//! a small, validated set of shell facts; they never contribute an archive entry. Persisted records
//! are projected through explicit allowlists rather than serialized wholesale, so a future field is
//! excluded until this boundary deliberately admits it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{Profile, Settings};

const MASK: &str = "<redacted>";
const UNKNOWN: &str = "unknown";
const FACT_VALUE_MAX: usize = 1_024;
const LOG_VALUE_MAX: usize = 16 * 1_024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A core-owned item shown in the bundle preview and represented by one archive entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BundlePart {
    /// Host, runtime, runner, and prefix facts intended for public issue reports.
    SystemReport,
    /// Recent structured diagnostic events.
    RecentLogs,
    /// Profile configuration projected through the support-safe schema.
    Profiles,
    /// Launcher-wide settings projected through the support-safe schema.
    Settings,
    /// Render and webview facts known only to the shell.
    ShellFacts,
}

impl BundlePart {
    /// The stable relative name used for this item inside a support archive.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::SystemReport => "system-report.txt",
            Self::RecentLogs => "logs.json",
            Self::Profiles => "profiles.json",
            Self::Settings => "settings.json",
            Self::ShellFacts => "shell.json",
        }
    }
}

/// The complete, stable list a shell presents before creating a support bundle.
#[must_use]
pub fn support_bundle_contents() -> Vec<BundlePart> {
    vec![
        BundlePart::SystemReport,
        BundlePart::RecentLogs,
        BundlePart::Profiles,
        BundlePart::Settings,
        BundlePart::ShellFacts,
    ]
}

/// A shell fact core accepts into a support bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CallerFactName {
    RenderTier,
    RenderReason,
    RenderEscalationCount,
    SessionType,
    DriverVersion,
    WebkitgtkVersion,
    WindowScale,
}

impl CallerFactName {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RenderTier => "render_tier",
            Self::RenderReason => "render_reason",
            Self::RenderEscalationCount => "render_escalation_count",
            Self::SessionType => "session_type",
            Self::DriverVersion => "driver_version",
            Self::WebkitgtkVersion => "webkitgtk_version",
            Self::WindowScale => "window_scale",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "render_tier" => Some(Self::RenderTier),
            "render_reason" => Some(Self::RenderReason),
            "render_escalation_count" => Some(Self::RenderEscalationCount),
            "session_type" => Some(Self::SessionType),
            "driver_version" => Some(Self::DriverVersion),
            "webkitgtk_version" => Some(Self::WebkitgtkVersion),
            "window_scale" => Some(Self::WindowScale),
            _ => None,
        }
    }
}

/// Caller facts after core has applied its name, size, uniqueness, and content policy.
///
/// Unknown names, duplicates, control characters, oversized values, and values shaped like secret
/// assignments are omitted. The rejected count is safe to report because rejected names and values
/// are not retained.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidatedCallerFacts {
    values: BTreeMap<CallerFactName, String>,
    rejected: usize,
}

impl ValidatedCallerFacts {
    /// Validate an untrusted shell fact map. Invalid entries are omitted independently.
    #[must_use]
    pub fn new(facts: Vec<(String, String)>) -> Self {
        let mut values = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut rejected = 0;

        for (raw_name, raw_value) in facts {
            let Some(name) = CallerFactName::parse(&raw_name) else {
                rejected += 1;
                continue;
            };
            if !seen.insert(name)
                || raw_value.len() > FACT_VALUE_MAX
                || raw_value.chars().any(char::is_control)
            {
                rejected += 1;
                continue;
            }

            let value = if contains_sensitive_assignment(&raw_value) {
                rejected += 1;
                MASK.to_owned()
            } else {
                raw_value
            };
            values.insert(name, value);
        }

        Self { values, rejected }
    }

    /// How many caller entries were omitted or replaced.
    #[must_use]
    pub const fn rejected(&self) -> usize {
        self.rejected
    }

    fn snapshot(&self, home: Option<&Path>) -> Value {
        let mut values = serde_json::Map::new();
        for (name, value) in &self.values {
            values.insert(
                name.as_str().to_owned(),
                Value::String(rewrite_home(value, home)),
            );
        }
        values.insert(
            "rejected_fact_count".to_owned(),
            Value::from(self.rejected as u64),
        );
        Value::Object(values)
    }
}

/// Deterministic inputs to the public system report.
///
/// These are already-resolved facts. Discovery stays in the runtime and composition layers, which
/// can also inject fixed values in tests without consulting the current machine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemReportInput {
    pub application_version: String,
    pub target: String,
    pub operating_system: Option<String>,
    pub kernel: Option<String>,
    pub architecture: Option<String>,
    pub gpu: Option<String>,
    pub driver: Option<String>,
    pub runner: Option<String>,
    pub prefix_state: Option<String>,
}

/// Compose the public system report in a stable field order.
#[must_use]
pub fn system_report(input: &SystemReportInput, home: Option<&Path>) -> String {
    let fields = [
        (
            "application.version",
            Some(input.application_version.as_str()),
        ),
        ("build.target", Some(input.target.as_str())),
        ("host.os", input.operating_system.as_deref()),
        ("host.kernel", input.kernel.as_deref()),
        ("host.architecture", input.architecture.as_deref()),
        ("graphics.gpu", input.gpu.as_deref()),
        ("graphics.driver", input.driver.as_deref()),
        ("runtime.runner", input.runner.as_deref()),
        ("runtime.prefix", input.prefix_state.as_deref()),
    ];

    let mut report = String::new();
    for (name, value) in fields {
        let value = value.unwrap_or(UNKNOWN);
        let value = if contains_sensitive_assignment(value) {
            MASK.to_owned()
        } else {
            rewrite_home(value, home)
        };
        report.push_str(name);
        report.push('=');
        report.push_str(&quoted(&value));
        report.push('\n');
    }
    report
}

/// One recent structured diagnostic event supplied by the in-memory log ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticRecord {
    pub level: String,
    pub target: String,
    pub message: String,
    #[serde(default)]
    pub fields: Vec<(String, String)>,
}

/// All core-owned inputs from which support archive entries are assembled.
#[derive(Debug)]
pub struct SupportBundleInput<'a> {
    pub profiles: &'a [Profile],
    pub settings: &'a Settings,
    pub system: &'a SystemReportInput,
    pub logs: &'a [DiagnosticRecord],
    pub caller_facts: &'a ValidatedCallerFacts,
    pub home: Option<&'a Path>,
}

/// One ready-to-write archive entry. No caller can provide its name or bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    part: BundlePart,
    bytes: Vec<u8>,
}

impl BundleEntry {
    #[must_use]
    pub const fn part(&self) -> BundlePart {
        self.part
    }

    #[must_use]
    pub const fn file_name(&self) -> &'static str {
        self.part.file_name()
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The deterministic, redacted entry set that composition writes into the chosen archive format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportArchive {
    entries: Vec<BundleEntry>,
}

impl SupportArchive {
    #[must_use]
    pub fn entries(&self) -> &[BundleEntry] {
        &self.entries
    }
}

/// Failures while encoding the core-owned support entry set.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SupportError {
    #[error("support bundle part {part:?} could not be encoded: {source}")]
    Encode {
        part: BundlePart,
        #[source]
        source: serde_json::Error,
    },
    #[error("support bundle filesystem error at {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("support bundle container could not be written: {0}")]
    Archive(#[from] zip::result::ZipError),
}

/// Assemble every support-bundle entry after applying the redaction policy.
///
/// The returned entries have stable names and ordering. A container writer receives only this value,
/// never caller-provided bytes, so ZIP, tar, or another packaging choice cannot bypass redaction.
pub fn assemble_support_archive(
    input: &SupportBundleInput<'_>,
) -> Result<SupportArchive, SupportError> {
    let profiles = Value::Array(
        input
            .profiles
            .iter()
            .map(|profile| profile_snapshot(profile, input.home))
            .collect(),
    );
    let settings = settings_snapshot(input.settings);
    let logs = Value::Array(
        input
            .logs
            .iter()
            .map(|record| diagnostic_snapshot(record, input.home))
            .collect(),
    );
    let shell = input.caller_facts.snapshot(input.home);

    let entries = vec![
        BundleEntry {
            part: BundlePart::SystemReport,
            bytes: system_report(input.system, input.home).into_bytes(),
        },
        json_entry(BundlePart::RecentLogs, &logs)?,
        json_entry(BundlePart::Profiles, &profiles)?,
        json_entry(BundlePart::Settings, &settings)?,
        json_entry(BundlePart::ShellFacts, &shell)?,
    ];
    Ok(SupportArchive { entries })
}

/// Write a core-assembled entry set as a deterministic ZIP archive.
///
/// The destination is published by rename only after every entry and the container footer have
/// been flushed. An existing destination is left untouched.
pub fn write_support_bundle(
    destination: impl AsRef<Path>,
    archive: &SupportArchive,
) -> Result<(), SupportError> {
    let destination = destination.as_ref();
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| SupportError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut temporary = destination.as_os_str().to_owned();
    temporary.push(format!(".tmp-{}-{sequence}", std::process::id()));
    let temporary = PathBuf::from(temporary);
    let result = write_temporary(&temporary, archive).and_then(|()| {
        if destination.exists() {
            return Err(SupportError::Io {
                path: destination.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "destination already exists",
                ),
            });
        }
        std::fs::rename(&temporary, destination).map_err(|source| SupportError::Io {
            path: destination.to_path_buf(),
            source,
        })
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn write_temporary(path: &Path, archive: &SupportArchive) -> Result<(), SupportError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| SupportError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::DEFAULT
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default());
    for entry in archive.entries() {
        writer.start_file(entry.file_name(), options)?;
        writer
            .write_all(entry.bytes())
            .map_err(|source| SupportError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    let file = writer.finish()?;
    file.sync_all().map_err(|source| SupportError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn json_entry(part: BundlePart, value: &Value) -> Result<BundleEntry, SupportError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|source| SupportError::Encode { part, source })?;
    bytes.push(b'\n');
    Ok(BundleEntry { part, bytes })
}

fn profile_snapshot(profile: &Profile, home: Option<&Path>) -> Value {
    let external: Vec<Value> = profile
        .external
        .iter()
        .map(|addon| {
            json!({
                "program": rewrite_home(&addon.program().to_string_lossy(), home),
                "args": masked_values(addon.args().len()),
                "run_in": addon.run_in(),
                "trigger": addon.trigger(),
                "enabled": addon.enabled(),
            })
        })
        .collect();
    let gamescope = profile.launch.gamescope.as_ref().map(|gamescope| {
        json!({
            "width": gamescope.width,
            "height": gamescope.height,
            "refresh": gamescope.refresh,
            "fullscreen": gamescope.fullscreen,
            "hdr": gamescope.hdr,
            "extra": masked_values(gamescope.extra.len()),
        })
    });
    let extra_env: Vec<Value> = profile
        .launch
        .extra_env
        .iter()
        .map(|(key, _)| json!({"key": key, "value": MASK}))
        .collect();

    json!({
        "name": rewrite_home(&profile.name, home),
        "game_path": rewrite_home(&profile.game_path.to_string_lossy(), home),
        "runner": profile.runner,
        "prefix": {"name": profile.prefix.name},
        "external": external,
        "launch": {
            "region": profile.launch.region,
            "extra_args": masked_values(profile.launch.extra_args.len()),
            "extra_env": extra_env,
            "wrappers": masked_values(profile.launch.wrappers.len()),
            "sync": profile.launch.sync,
            "hud": profile.launch.hud,
            "gpu": profile.launch.gpu,
            "nvapi": profile.launch.nvapi,
            "gamescope": gamescope,
            "gamemode": profile.launch.gamemode,
            "dalamud": profile.launch.dalamud,
        }
    })
}

fn settings_snapshot(settings: &Settings) -> Value {
    json!({
        "language": settings.language,
        "close_after_launch": settings.close_after_launch,
        "secret_backend": settings.secret_backend,
        "keep_patches": settings.keep_patches,
        "backups_kept": settings.backups_kept,
        "backup_before_patch": settings.backup_before_patch,
        "frontier_poll_seconds": settings.frontier_poll_seconds,
        "otp_listener": {
            "bind": settings.otp_listener.bind,
            "port": settings.otp_listener.port,
            "sources": settings.otp_listener.sources,
            "wait_seconds": settings.otp_listener.wait_seconds,
        }
    })
}

fn diagnostic_snapshot(record: &DiagnosticRecord, home: Option<&Path>) -> Value {
    let message = if contains_sensitive_assignment(&record.message) {
        MASK.to_owned()
    } else {
        rewrite_home(&bounded(&record.message, LOG_VALUE_MAX), home)
    };
    let mut fields = serde_json::Map::new();
    for (name, value) in &record.fields {
        if excluded_diagnostic_field(name) {
            continue;
        }
        let value = if contains_sensitive_assignment(value) {
            MASK.to_owned()
        } else {
            rewrite_home(&bounded(value, LOG_VALUE_MAX), home)
        };
        fields.insert(name.clone(), Value::String(value));
    }
    json!({
        "level": bounded(&record.level, 32),
        "target": bounded(&record.target, 256),
        "message": message,
        "fields": fields,
    })
}

fn masked_values(count: usize) -> Vec<&'static str> {
    vec![MASK; count]
}

fn bounded(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("\"{MASK}\""))
}

fn excluded_diagnostic_field(name: &str) -> bool {
    let normalized = normalize_name(name);
    matches!(
        normalized.as_str(),
        "password"
            | "passphrase"
            | "otp"
            | "otp_code"
            | "one_time_code"
            | "totp"
            | "totp_secret"
            | "secret"
            | "session"
            | "session_id"
            | "uid"
            | "unique_id"
            | "x_patch_unique_id"
            | "stored"
            | "stored_blob"
            | "body"
            | "raw_body"
            | "request_body"
            | "response_body"
            | "se_response"
            | "raw_se_body"
    ) || [
        "_password",
        "_passphrase",
        "_otp",
        "_totp",
        "_secret",
        "_token",
        "_session_id",
        "_unique_id",
        "_uid",
        "_body",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
}

fn normalize_name(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| match character {
            '-' | '.' | ' ' => '_',
            other => other,
        })
        .collect()
}

fn contains_sensitive_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("_stored_") || lower.contains("x-patch-unique-id") {
        return true;
    }

    const NAMES: [&str; 13] = [
        "password",
        "passphrase",
        "otp",
        "otp_code",
        "totp",
        "totp_secret",
        "secret",
        "session",
        "session_id",
        "uid",
        "unique_id",
        "authorization",
        "bearer",
    ];
    NAMES.iter().any(|name| {
        ["=", ":", "=\"", ":\"", "='", ":'"]
            .iter()
            .any(|separator| lower.contains(&format!("{name}{separator}")))
    })
}

fn rewrite_home(value: &str, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return value.to_owned();
    };
    let home = home.to_string_lossy();
    if home.is_empty() {
        return value.to_owned();
    }

    let mut candidates = vec![home.to_string()];
    let alternate = if home.contains('\\') {
        home.replace('\\', "/")
    } else {
        home.replace('/', "\\")
    };
    if alternate != home {
        candidates.push(alternate);
    }

    let mut rewritten = value.to_owned();
    for candidate in candidates {
        rewritten = replace_path_prefix(&rewritten, &candidate);
    }
    rewritten
}

fn replace_path_prefix(value: &str, home: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(relative) = find_home(&value[cursor..], home) {
        let start = cursor + relative;
        let end = start + home.len();
        let before_ok = start == 0
            || value[..start]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_alphanumeric());
        let after_ok = end == value.len()
            || value[end..]
                .chars()
                .next()
                .is_none_or(|character| matches!(character, '/' | '\\'));
        if before_ok && after_ok {
            output.push_str(&value[cursor..start]);
            output.push('~');
            cursor = end;
        } else {
            output.push_str(&value[cursor..end]);
            cursor = end;
        }
    }
    output.push_str(&value[cursor..]);
    output
}

#[cfg(windows)]
fn find_home(value: &str, home: &str) -> Option<usize> {
    value.char_indices().find_map(|(start, _)| {
        value
            .get(start..start.saturating_add(home.len()))
            .filter(|candidate| candidate.eq_ignore_ascii_case(home))
            .map(|_| start)
    })
}

#[cfg(not(windows))]
fn find_home(value: &str, home: &str) -> Option<usize> {
    value.find(home)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use apogee_addons::{ExternalAddon, RunIn, Trigger};
    use apogee_runtime::Gamescope;

    use super::*;
    use crate::model::Profile;

    fn test_home() -> PathBuf {
        std::env::temp_dir().join("apogee-support-home")
    }

    fn fixture_profile(home: &Path) -> Profile {
        let mut profile = Profile::new(
            "Token Knight and the Password Managers",
            uuid::Uuid::parse_str("8bc0192e-959f-4d51-9a2a-1620f6adb59e").unwrap(),
            home.join("Games/FINAL FANTASY XIV Online"),
        );
        profile.id = uuid::Uuid::parse_str("5cda625d-a777-4a15-8f01-f6a2ec956632").unwrap();
        profile.launch.extra_env = vec![("API_TOKEN".to_owned(), "env-planted-token".to_owned())];
        profile.launch.extra_args = vec!["arg-planted-token".to_owned()];
        profile.launch.wrappers = vec!["wrapper-planted-token".to_owned()];
        profile.launch.gamescope = Some(Gamescope {
            extra: vec!["gamescope-planted-token".to_owned()],
            ..Gamescope::default()
        });
        profile.external.push(
            ExternalAddon::new(
                home.join("Tools/token-helper"),
                vec!["external-planted-token".to_owned()],
                RunIn::Host,
                Trigger::OnClose,
            )
            .unwrap(),
        );
        profile
    }

    fn fixture_system(home: &Path) -> SystemReportInput {
        SystemReportInput {
            application_version: "0.5.0".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            operating_system: Some("Linux".to_owned()),
            kernel: Some("6.12.0-token-bucket".to_owned()),
            architecture: Some("x86_64".to_owned()),
            gpu: Some("Token Graphics 7900".to_owned()),
            driver: Some("Mesa 25.1".to_owned()),
            runner: Some(home.join("runners/wine").to_string_lossy().into_owned()),
            prefix_state: Some("healthy".to_owned()),
        }
    }

    #[test]
    fn preview_and_entry_order_are_the_same_stable_contract() {
        let parts = support_bundle_contents();
        assert_eq!(
            parts
                .iter()
                .map(|part| part.file_name())
                .collect::<Vec<_>>(),
            [
                "system-report.txt",
                "logs.json",
                "profiles.json",
                "settings.json",
                "shell.json",
            ]
        );
    }

    #[test]
    fn caller_facts_are_allowlisted_and_sensitive_assignments_are_masked() {
        let facts = ValidatedCallerFacts::new(vec![
            ("render_tier".to_owned(), "software-token-path".to_owned()),
            (
                "render_reason".to_owned(),
                "session_id=caller-planted-session".to_owned(),
            ),
            ("password".to_owned(), "caller-planted-password".to_owned()),
            ("render_tier".to_owned(), "duplicate".to_owned()),
            ("window_scale".to_owned(), "1.5\nforged=true".to_owned()),
        ]);
        let snapshot = facts.snapshot(None);
        let rendered = serde_json::to_string(&snapshot).unwrap();

        assert_eq!(facts.rejected(), 4);
        assert_eq!(snapshot["render_tier"], "software-token-path");
        assert_eq!(snapshot["render_reason"], MASK);
        assert!(!rendered.contains("caller-planted"));
        assert!(!rendered.contains("password"));
        assert!(!rendered.contains("duplicate"));
        assert!(!rendered.contains("forged"));
    }

    #[test]
    fn system_report_is_deterministic_public_text() {
        let home = test_home();
        let report = system_report(&fixture_system(&home), Some(&home));
        let runner = rewrite_home(&home.join("runners/wine").to_string_lossy(), Some(&home));

        assert_eq!(
            report,
            format!(
                concat!(
                    "application.version=\"0.5.0\"\n",
                    "build.target=\"x86_64-unknown-linux-gnu\"\n",
                    "host.os=\"Linux\"\n",
                    "host.kernel=\"6.12.0-token-bucket\"\n",
                    "host.architecture=\"x86_64\"\n",
                    "graphics.gpu=\"Token Graphics 7900\"\n",
                    "graphics.driver=\"Mesa 25.1\"\n",
                    "runtime.runner={}\n",
                    "runtime.prefix=\"healthy\"\n",
                ),
                quoted(&runner)
            )
        );
        assert!(!report.contains(&home.to_string_lossy().into_owned()));
    }

    #[test]
    fn archive_projection_masks_free_form_values_and_hard_excludes_authentication_data() {
        let home = test_home();
        let profile = fixture_profile(&home);
        let profile_id = profile.id.to_string();
        let account_id = profile.account.to_string();
        let home_literal = home.to_string_lossy().into_owned();
        let settings = Settings::default();
        let system = fixture_system(&home);
        let facts = ValidatedCallerFacts::new(vec![
            ("render_tier".to_owned(), "software".to_owned()),
            ("password".to_owned(), "caller-planted-password".to_owned()),
            ("otp".to_owned(), "464646".to_owned()),
            ("totp_secret".to_owned(), "totp-planted-secret".to_owned()),
            ("session_id".to_owned(), "session-planted-id".to_owned()),
            ("unique_id".to_owned(), "uid-planted-id".to_owned()),
            ("raw_se_body".to_owned(), "raw-planted-body".to_owned()),
            (
                "driver_version".to_owned(),
                "_STORED_=sealed-blob".to_owned(),
            ),
        ]);
        let logs = vec![DiagnosticRecord {
            level: "INFO".to_owned(),
            target: "apogee_core::token_bucket".to_owned(),
            message: format!("Token cache at {}/cache is healthy", home.display()),
            fields: vec![
                ("status_code".to_owned(), "200".to_owned()),
                ("session_id".to_owned(), "log-planted-session".to_owned()),
                ("response_body".to_owned(), "log-planted-body".to_owned()),
            ],
        }];
        let archive = assemble_support_archive(&SupportBundleInput {
            profiles: &[profile],
            settings: &settings,
            system: &system,
            logs: &logs,
            caller_facts: &facts,
            home: Some(&home),
        })
        .unwrap();
        let text = archive
            .entries()
            .iter()
            .map(|entry| String::from_utf8_lossy(entry.bytes()))
            .collect::<String>();

        for forbidden in [
            "env-planted-token",
            "arg-planted-token",
            "wrapper-planted-token",
            "gamescope-planted-token",
            "external-planted-token",
            "caller-planted-password",
            "totp-planted-secret",
            "session-planted-id",
            "uid-planted-id",
            "raw-planted-body",
            "sealed-blob",
            "log-planted-session",
            "log-planted-body",
            &profile_id,
            &account_id,
            &home_literal,
        ] {
            assert!(!text.contains(forbidden), "bundle leaked {forbidden:?}");
        }
        assert!(text.contains("API_TOKEN"), "environment keys must survive");
        assert!(
            text.contains(MASK),
            "free-form values must be visibly masked"
        );
        assert!(text.contains("Token Knight and the Password Managers"));
        assert!(text.contains("Token cache at ~/cache is healthy"));
        assert!(text.contains("status_code"));
    }

    #[test]
    fn home_rewrite_respects_component_boundaries() {
        let home = test_home();
        let literal = home.to_string_lossy();
        assert_eq!(
            rewrite_home(&format!("{literal}/game"), Some(&home)),
            "~/game"
        );
        assert_eq!(
            rewrite_home(&format!("path={literal}"), Some(&home)),
            "path=~"
        );
        assert_eq!(
            rewrite_home(&format!("{literal}a/game"), Some(&home)),
            format!("{literal}a/game")
        );
        assert_eq!(
            rewrite_home(&format!("x{literal}/game"), Some(&home)),
            format!("x{literal}/game")
        );
    }
}
