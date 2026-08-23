//! Read-only discovery and selective import of XIVLauncher account metadata.
//!
//! Scanning is deliberately separate from applying. A scan produces stable findings that a shell
//! can present without exposing credentials. An apply accepts only finding identifiers from that
//! scan, reads the source again, and refuses to write anything when either source file changed.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{
    Account, AccountKind, OtpDelivery, Profile, STEAM_APP_ID, STEAM_FREE_TRIAL_APP_ID,
};
use crate::store::{Store, StoreError};

const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;

fn accounts_file() -> &'static str {
    "accountsList.json"
}

fn config_file() -> &'static str {
    "launcherConfigV3.json"
}

/// Environment paths used to locate common XIVLauncher data directories.
///
/// Keeping the values explicit makes discovery deterministic and lets callers report exactly which
/// roots were considered. [`ImportEnvironment::current`] is the process-environment adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportEnvironment {
    pub xdg_config_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub appdata: Option<PathBuf>,
}

impl ImportEnvironment {
    /// Capture the path variables relevant to import discovery.
    #[must_use]
    pub fn current() -> Self {
        Self {
            xdg_config_home: env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            home: env::var_os("HOME")
                .or_else(|| env::var_os("USERPROFILE"))
                .map(PathBuf::from),
            appdata: env::var_os("APPDATA").map(PathBuf::from),
        }
    }

    /// Candidate directories in stable preference order, without relative paths or duplicates.
    #[must_use]
    pub fn candidate_roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(path) = self.xdg_config_home.as_deref() {
            push_absolute_unique(&mut roots, path.join("XIVLauncher"));
        }
        if let Some(path) = self.home.as_deref() {
            push_absolute_unique(&mut roots, path.join(".xlcore"));
            push_absolute_unique(
                &mut roots,
                path.join(".var/app/dev.goats.xivlauncher/.xlcore"),
            );
        }
        if let Some(path) = self.appdata.as_deref() {
            push_absolute_unique(&mut roots, path.join("XIVLauncher"));
        }
        roots
    }
}

/// Discover common XIVLauncher data directories from the current process environment.
#[must_use]
pub fn candidate_roots() -> Vec<PathBuf> {
    ImportEnvironment::current().candidate_roots()
}

fn push_absolute_unique(roots: &mut Vec<PathBuf>, candidate: PathBuf) {
    if candidate.is_absolute() && !roots.iter().any(|root| root == &candidate) {
        roots.push(candidate);
    }
}

/// A stable, opaque identifier for one scan finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ImportFindingId(String);

impl ImportFindingId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A fingerprint over the presence and exact bytes of both supported source files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ImportFingerprint(String);

impl ImportFingerprint {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which source file or account row produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ImportLocation {
    AccountsFile,
    AccountRow { index: usize },
    ConfigFile,
}

/// Why a source item cannot be selected for import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ImportIssue {
    MalformedJson,
    ExpectedArray,
    ExpectedObject,
    MissingUserName,
    InvalidUserName,
    InvalidUseOtp,
    InvalidSteamAccount,
    InvalidSavePassword,
    DuplicateAccount { first: ImportFindingId },
    MissingGamePath,
    InvalidGamePath,
    InvalidFreeTrial,
}

/// Account metadata safe to display before import. It intentionally contains no credential fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCandidate {
    pub sqex_id: String,
    pub kind: AccountKind,
    pub use_otp: bool,
    pub never_store: bool,
    /// Present when the launcher configuration supplied a usable absolute game directory.
    pub game_path: Option<PathBuf>,
}

/// One independently reportable result from scanning the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFinding {
    pub id: ImportFindingId,
    pub location: ImportLocation,
    pub result: ImportFindingResult,
}

/// A selectable candidate or a typed reason the source item was skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ImportFindingResult {
    Candidate(ImportCandidate),
    Skipped(ImportIssue),
}

/// A read-only snapshot of one candidate directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportScan {
    pub source: PathBuf,
    pub fingerprint: ImportFingerprint,
    pub findings: Vec<ImportFinding>,
}

impl ImportScan {
    /// Build a plan from selectable finding ids. Unknown and skipped ids are rejected.
    pub fn plan(
        &self,
        accepted: impl IntoIterator<Item = ImportFindingId>,
    ) -> Result<ImportPlan, XivImportError> {
        let selectable: BTreeSet<_> = self
            .findings
            .iter()
            .filter_map(|finding| {
                matches!(&finding.result, ImportFindingResult::Candidate(_))
                    .then_some(finding.id.clone())
            })
            .collect();
        let accepted: BTreeSet<_> = accepted.into_iter().collect();
        if let Some(id) = accepted.iter().find(|id| !selectable.contains(*id)) {
            return Err(XivImportError::FindingNotSelectable { id: id.clone() });
        }
        Ok(ImportPlan {
            source: self.source.clone(),
            fingerprint: self.fingerprint.clone(),
            accepted,
        })
    }
}

/// A selection against one exact source snapshot.
///
/// It carries only a path, fingerprint, and finding ids. Account metadata is reconstructed by the
/// apply-time rescan, so credential-like source fields cannot accidentally enter a persisted plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportPlan {
    pub source: PathBuf,
    pub fingerprint: ImportFingerprint,
    pub accepted: BTreeSet<ImportFindingId>,
}

/// Whether an imported entity was created or matched an existing deterministic duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportWrite {
    Created,
    Existing,
}

/// Apply result for one selected finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedFinding {
    pub finding: ImportFindingId,
    pub account: Uuid,
    pub account_write: ImportWrite,
    pub profile: Option<Uuid>,
    pub profile_write: Option<ImportWrite>,
}

/// The complete result of applying a plan in finding-id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportApplyReport {
    pub applied: Vec<AppliedFinding>,
}

/// Import failures. Source parse problems are findings; this enum is reserved for boundaries that
/// make a trustworthy scan or apply impossible.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum XivImportError {
    #[error("import source contains neither supported file at {path:?}")]
    NoSource { path: PathBuf },
    #[error("import source exceeds {max_bytes} bytes at {path:?}")]
    SourceTooLarge { path: PathBuf, max_bytes: u64 },
    #[error("io error while reading import source at {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("import finding is not selectable: {id:?}")]
    FindingNotSelectable { id: ImportFindingId },
    #[error("import source changed after it was scanned at {path:?}")]
    SourceChanged { path: PathBuf },
    #[error("import identity collides with a different stored entity: {id}")]
    IdentityCollision { id: Uuid },
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Scan the two supported files directly beneath `source`, without walking child directories.
pub fn scan(source: impl AsRef<Path>) -> Result<ImportScan, XivImportError> {
    let source = source.as_ref().to_path_buf();
    let accounts_path = source.join(accounts_file());
    let config_path = source.join(config_file());
    let accounts = read_bounded(&accounts_path)?;
    let config = read_bounded(&config_path)?;
    if accounts.is_none() && config.is_none() {
        return Err(XivImportError::NoSource { path: source });
    }

    let fingerprint = fingerprint(accounts.as_deref(), config.as_deref());
    let mut findings = Vec::new();
    let config_data = parse_config(config.as_deref(), &mut findings);
    parse_accounts(accounts.as_deref(), config_data.as_ref(), &mut findings);
    Ok(ImportScan {
        source,
        fingerprint,
        findings,
    })
}

/// Apply a plan after proving the source is byte-for-byte the snapshot that was reviewed.
///
/// The source directory and its files are opened read-only. Existing entities are matched in UUID
/// order, making duplicate handling independent of filesystem enumeration order.
pub fn apply(store: &Store, plan: &ImportPlan) -> Result<ImportApplyReport, XivImportError> {
    let current = scan(&plan.source)?;
    if current.fingerprint != plan.fingerprint {
        return Err(XivImportError::SourceChanged {
            path: plan.source.clone(),
        });
    }

    let candidates: BTreeMap<_, _> = current
        .findings
        .into_iter()
        .filter_map(|finding| match finding.result {
            ImportFindingResult::Candidate(candidate) => Some((finding.id, candidate)),
            ImportFindingResult::Skipped(_) => None,
        })
        .collect();
    if let Some(id) = plan
        .accepted
        .iter()
        .find(|id| !candidates.contains_key(*id))
    {
        return Err(XivImportError::FindingNotSelectable { id: id.clone() });
    }

    let mut accounts = store.list_accounts()?;
    accounts.sort_by_key(|account| account.id);
    let mut profiles = store.list_profiles()?;
    profiles.sort_by_key(|profile| profile.id);
    let mut applied = Vec::with_capacity(plan.accepted.len());

    for id in &plan.accepted {
        let candidate = &candidates[id];
        let (account, account_write) = match accounts
            .iter()
            .find(|account| accounts_match(account, candidate))
            .cloned()
        {
            Some(account) => (account, ImportWrite::Existing),
            None => {
                let account = account_from_candidate(id, candidate);
                refuse_account_collision(&accounts, &account)?;
                store.save_account(&account)?;
                accounts.push(account.clone());
                accounts.sort_by_key(|entry| entry.id);
                (account, ImportWrite::Created)
            }
        };

        let (profile, profile_write) = match candidate.game_path.as_ref() {
            None => (None, None),
            Some(game_path) => match profiles
                .iter()
                .find(|profile| profile.account == account.id && profile.game_path == *game_path)
                .cloned()
            {
                Some(profile) => (Some(profile.id), Some(ImportWrite::Existing)),
                None => {
                    let profile = profile_from_candidate(id, &account, game_path.clone());
                    refuse_profile_collision(&profiles, &profile)?;
                    store.save_profile(&profile)?;
                    profiles.push(profile.clone());
                    profiles.sort_by_key(|entry| entry.id);
                    (Some(profile.id), Some(ImportWrite::Created))
                }
            },
        };
        applied.push(AppliedFinding {
            finding: id.clone(),
            account: account.id,
            account_write,
            profile,
            profile_write,
        });
    }

    Ok(ImportApplyReport { applied })
}

fn refuse_account_collision(
    accounts: &[Account],
    proposed: &Account,
) -> Result<(), XivImportError> {
    if accounts
        .iter()
        .any(|existing| existing.id == proposed.id && existing != proposed)
    {
        return Err(XivImportError::IdentityCollision { id: proposed.id });
    }
    Ok(())
}

fn refuse_profile_collision(
    profiles: &[Profile],
    proposed: &Profile,
) -> Result<(), XivImportError> {
    if profiles
        .iter()
        .any(|existing| existing.id == proposed.id && existing != proposed)
    {
        return Err(XivImportError::IdentityCollision { id: proposed.id });
    }
    Ok(())
}

fn account_from_candidate(id: &ImportFindingId, candidate: &ImportCandidate) -> Account {
    Account {
        id: entity_id("account", id),
        sqex_id: candidate.sqex_id.clone(),
        kind: candidate.kind.clone(),
        use_otp: candidate.use_otp,
        never_store: candidate.never_store,
        otp_delivery: OtpDelivery::Ask,
    }
}

fn profile_from_candidate(id: &ImportFindingId, account: &Account, game_path: PathBuf) -> Profile {
    let mut profile = Profile::new(account.sqex_id.clone(), account.id, game_path);
    profile.id = entity_id("profile", id);
    profile
}

fn entity_id(kind: &str, finding: &ImportFindingId) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"apogee-xiv-import-entity\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(finding.as_str().as_bytes());
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Mark this as a name-derived UUID with the RFC 4122 variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn accounts_match(account: &Account, candidate: &ImportCandidate) -> bool {
    normalize_user_name(&account.sqex_id) == normalize_user_name(&candidate.sqex_id)
        && account.kind == candidate.kind
}

#[derive(Debug, Clone)]
struct ConfigData {
    game_path: Option<PathBuf>,
    free_trial: bool,
}

fn parse_config(bytes: Option<&[u8]>, findings: &mut Vec<ImportFinding>) -> Option<ConfigData> {
    let bytes = bytes?;
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => {
            push_skipped(
                findings,
                ImportLocation::ConfigFile,
                "config-malformed",
                ImportIssue::MalformedJson,
            );
            return None;
        }
    };
    let Some(object) = value.as_object() else {
        push_skipped(
            findings,
            ImportLocation::ConfigFile,
            "config-object",
            ImportIssue::ExpectedObject,
        );
        return None;
    };

    let free_trial = match optional_bool(object, "IsFt") {
        Ok(value) => value.unwrap_or(false),
        Err(()) => {
            push_skipped(
                findings,
                ImportLocation::ConfigFile,
                "config-free-trial",
                ImportIssue::InvalidFreeTrial,
            );
            false
        }
    };
    let game_path = match field_case_insensitive(object, "GamePath") {
        None | Some(Value::Null) => {
            push_skipped(
                findings,
                ImportLocation::ConfigFile,
                "config-game-path-missing",
                ImportIssue::MissingGamePath,
            );
            None
        }
        Some(value) => match parse_game_path(value) {
            Some(path) => Some(path),
            None => {
                push_skipped(
                    findings,
                    ImportLocation::ConfigFile,
                    "config-game-path-invalid",
                    ImportIssue::InvalidGamePath,
                );
                None
            }
        },
    };
    Some(ConfigData {
        game_path,
        free_trial,
    })
}

fn parse_game_path(value: &Value) -> Option<PathBuf> {
    let raw = match value {
        Value::String(raw) => Some(raw.as_str()),
        Value::Object(object) => ["FullName", "fullName", "OriginalPath", "originalPath"]
            .iter()
            .find_map(|name| field_case_insensitive(object, name)?.as_str()),
        _ => None,
    }?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(raw);
    path.is_absolute().then_some(path)
}

fn parse_accounts(
    bytes: Option<&[u8]>,
    config: Option<&ConfigData>,
    findings: &mut Vec<ImportFinding>,
) {
    let Some(bytes) = bytes else {
        return;
    };
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => {
            push_skipped(
                findings,
                ImportLocation::AccountsFile,
                "accounts-malformed",
                ImportIssue::MalformedJson,
            );
            return;
        }
    };
    let Some(rows) = value.as_array() else {
        push_skipped(
            findings,
            ImportLocation::AccountsFile,
            "accounts-array",
            ImportIssue::ExpectedArray,
        );
        return;
    };

    let mut first_by_account = BTreeMap::<String, ImportFindingId>::new();
    let mut id_occurrences = BTreeMap::<String, usize>::new();
    for (index, row) in rows.iter().enumerate() {
        let location = ImportLocation::AccountRow { index };
        let Some(object) = row.as_object() else {
            findings.push(ImportFinding {
                id: skipped_row_id(index, &ImportIssue::ExpectedObject),
                location,
                result: ImportFindingResult::Skipped(ImportIssue::ExpectedObject),
            });
            continue;
        };
        let candidate = match account_candidate(object, config) {
            Ok(candidate) => candidate,
            Err(issue) => {
                findings.push(ImportFinding {
                    id: skipped_row_id(index, &issue),
                    location,
                    result: ImportFindingResult::Skipped(issue),
                });
                continue;
            }
        };
        // Only mapped, non-secret metadata participates. Unknown source fields may contain a
        // password or the last successful one-time code and must not become even a hashed verifier
        // in a plan.
        let canonical = candidate_id_material(&candidate);
        let occurrence = id_occurrences.entry(canonical.clone()).or_default();
        let id = finding_id("account-row", &canonical, *occurrence);
        *occurrence += 1;
        let key = account_key(&candidate);
        if let Some(first) = first_by_account.get(&key) {
            findings.push(ImportFinding {
                id,
                location,
                result: ImportFindingResult::Skipped(ImportIssue::DuplicateAccount {
                    first: first.clone(),
                }),
            });
        } else {
            first_by_account.insert(key, id.clone());
            findings.push(ImportFinding {
                id,
                location,
                result: ImportFindingResult::Candidate(candidate),
            });
        }
    }
}

fn candidate_id_material(candidate: &ImportCandidate) -> String {
    let game_path = candidate
        .game_path
        .as_deref()
        .map_or_else(String::new, |path| path.to_string_lossy().into_owned());
    format!(
        "{}\0{}\0{}\0{}",
        account_key(candidate),
        candidate.use_otp,
        candidate.never_store,
        game_path
    )
}

fn skipped_row_id(index: usize, issue: &ImportIssue) -> ImportFindingId {
    finding_id("account-row-skipped", issue_key(issue), index)
}

fn issue_key(issue: &ImportIssue) -> &'static str {
    match issue {
        ImportIssue::MalformedJson => "malformed-json",
        ImportIssue::ExpectedArray => "expected-array",
        ImportIssue::ExpectedObject => "expected-object",
        ImportIssue::MissingUserName => "missing-user-name",
        ImportIssue::InvalidUserName => "invalid-user-name",
        ImportIssue::InvalidUseOtp => "invalid-use-otp",
        ImportIssue::InvalidSteamAccount => "invalid-steam-account",
        ImportIssue::InvalidSavePassword => "invalid-save-password",
        ImportIssue::DuplicateAccount { .. } => "duplicate-account",
        ImportIssue::MissingGamePath => "missing-game-path",
        ImportIssue::InvalidGamePath => "invalid-game-path",
        ImportIssue::InvalidFreeTrial => "invalid-free-trial",
    }
}

fn account_candidate(
    object: &Map<String, Value>,
    config: Option<&ConfigData>,
) -> Result<ImportCandidate, ImportIssue> {
    let sqex_id = match field_case_insensitive(object, "UserName") {
        None | Some(Value::Null) => return Err(ImportIssue::MissingUserName),
        Some(Value::String(value)) if !value.trim().is_empty() => {
            normalize_user_name(value.as_str())
        }
        Some(_) => return Err(ImportIssue::InvalidUserName),
    };
    let use_otp = optional_bool(object, "UseOtp")
        .map_err(|()| ImportIssue::InvalidUseOtp)?
        .unwrap_or(false);
    let steam = optional_bool(object, "UseSteamServiceAccount")
        .map_err(|()| ImportIssue::InvalidSteamAccount)?
        .unwrap_or(false);
    let save_password = optional_bool(object, "SavePassword")
        .map_err(|()| ImportIssue::InvalidSavePassword)?
        .unwrap_or(false);
    let free_trial = config.is_some_and(|config| config.free_trial);
    let kind = match (steam, free_trial) {
        (false, false) => AccountKind::Standard,
        (false, true) => AccountKind::FreeTrial,
        (true, false) => AccountKind::Steam {
            app_id: STEAM_APP_ID,
        },
        (true, true) => AccountKind::Steam {
            app_id: STEAM_FREE_TRIAL_APP_ID,
        },
    };
    Ok(ImportCandidate {
        sqex_id,
        kind,
        use_otp,
        never_store: !save_password,
        game_path: config.and_then(|config| config.game_path.clone()),
    })
}

fn optional_bool(object: &Map<String, Value>, name: &str) -> Result<Option<bool>, ()> {
    match field_case_insensitive(object, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("true") => Ok(Some(true)),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("false") => Ok(Some(false)),
        Some(_) => Err(()),
    }
}

fn field_case_insensitive<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value))
}

fn account_key(candidate: &ImportCandidate) -> String {
    let kind = match &candidate.kind {
        AccountKind::Standard => "standard:0".to_string(),
        AccountKind::FreeTrial => "trial:0".to_string(),
        AccountKind::Steam { app_id } => format!("steam:{app_id}"),
    };
    format!("{}\0{kind}", normalize_user_name(&candidate.sqex_id))
}

fn normalize_user_name(value: &str) -> String {
    value.trim().to_lowercase()
}

fn push_skipped(
    findings: &mut Vec<ImportFinding>,
    location: ImportLocation,
    key: &str,
    issue: ImportIssue,
) {
    findings.push(ImportFinding {
        id: finding_id("source", key, 0),
        location,
        result: ImportFindingResult::Skipped(issue),
    });
}

fn finding_id(kind: &str, canonical: &str, occurrence: usize) -> ImportFindingId {
    let mut digest = Sha256::new();
    digest.update(b"apogee-xiv-import-finding\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(canonical.as_bytes());
    digest.update(b"\0");
    digest.update(occurrence.to_le_bytes());
    ImportFindingId(hex(&digest.finalize()))
}

fn fingerprint(accounts: Option<&[u8]>, config: Option<&[u8]>) -> ImportFingerprint {
    let mut digest = Sha256::new();
    digest.update(b"apogee-xiv-import-source\0");
    fingerprint_file(&mut digest, accounts_file(), accounts);
    fingerprint_file(&mut digest, config_file(), config);
    ImportFingerprint(hex(&digest.finalize()))
}

fn fingerprint_file(digest: &mut Sha256, name: &str, bytes: Option<&[u8]>) {
    digest.update(name.as_bytes());
    digest.update(b"\0");
    match bytes {
        Some(bytes) => {
            digest.update([1]);
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        }
        None => digest.update([0]),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, XivImportError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(XivImportError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let metadata = file.metadata().map_err(|source| XivImportError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(XivImportError::SourceTooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_SOURCE_BYTES,
        });
    }

    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.by_ref()
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| XivImportError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(XivImportError::SourceTooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_SOURCE_BYTES,
        });
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn write_sources(root: &Path, accounts: &str, game_path: &Path) {
        fs::write(root.join(accounts_file()), accounts).expect("write accounts fixture");
        let config = serde_json::json!({
            "GamePath": game_path,
            "IsFt": false,
        });
        fs::write(
            root.join(config_file()),
            serde_json::to_vec(&config).expect("serialize config fixture"),
        )
        .expect("write config fixture");
    }

    #[test]
    fn candidate_discovery_is_ordered_absolute_and_deduplicated() {
        let temp = TempDir::new().expect("temp directory");
        let root = temp.path().to_path_buf();
        let environment = ImportEnvironment {
            xdg_config_home: Some(root.clone()),
            home: Some(root.clone()),
            appdata: Some(root.clone()),
        };

        assert_eq!(
            environment.candidate_roots(),
            vec![
                root.join("XIVLauncher"),
                root.join(".xlcore"),
                root.join(".var/app/dev.goats.xivlauncher/.xlcore"),
            ]
        );

        let relative = ImportEnvironment {
            xdg_config_home: Some(PathBuf::from("relative")),
            ..ImportEnvironment::default()
        };
        assert!(relative.candidate_roots().is_empty());
    }

    #[test]
    fn scan_reports_bad_rows_and_collapses_source_duplicates() {
        let source = TempDir::new().expect("source temp directory");
        let game = TempDir::new().expect("game temp directory");
        write_sources(
            source.path(),
            r#"[
                {"UserName":"One@Example.invalid","UseOtp":true,"SavePassword":true},
                42,
                {"UserName":"one@example.invalid","UseOtp":false,"SavePassword":false},
                {"UseOtp":false},
                {"UserName":"two@example.invalid","UseSteamServiceAccount":"false"}
            ]"#,
            game.path(),
        );

        let first = scan(source.path()).expect("scan succeeds");
        let second = scan(source.path()).expect("repeat scan succeeds");
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.findings, second.findings);
        assert_eq!(
            first
                .findings
                .iter()
                .filter(|finding| matches!(&finding.result, ImportFindingResult::Candidate(_)))
                .count(),
            2
        );
        assert!(first.findings.iter().any(|finding| matches!(
            finding.result,
            ImportFindingResult::Skipped(ImportIssue::ExpectedObject)
        )));
        assert!(first.findings.iter().any(|finding| matches!(
            finding.result,
            ImportFindingResult::Skipped(ImportIssue::DuplicateAccount { .. })
        )));
        assert!(first.findings.iter().any(|finding| matches!(
            finding.result,
            ImportFindingResult::Skipped(ImportIssue::MissingUserName)
        )));
    }

    #[test]
    fn plan_contains_only_source_proof_and_stable_ids() {
        let source = TempDir::new().expect("source temp directory");
        let game = TempDir::new().expect("game temp directory");
        write_sources(
            source.path(),
            r#"[{"UserName":"private-user","Password":"must-not-leak","LastSuccessfulOtp":"123456"}]"#,
            game.path(),
        );
        let scan = scan(source.path()).expect("scan succeeds");
        let id = scan
            .findings
            .iter()
            .find_map(|finding| {
                matches!(&finding.result, ImportFindingResult::Candidate(_))
                    .then_some(finding.id.clone())
            })
            .expect("candidate finding");
        let plan = scan.plan([id]).expect("plan succeeds");
        let json = serde_json::to_string(&plan).expect("serialize plan");

        assert!(!json.contains("must-not-leak"));
        assert!(!json.contains("123456"));
        assert!(!json.contains("private-user"));

        fs::write(
            source.path().join(accounts_file()),
            r#"[{"UserName":"private-user","Password":"different-secret","LastSuccessfulOtp":"654321"}]"#,
        )
        .expect("replace credential-like fields");
        let changed = super::scan(source.path()).expect("rescan succeeds");
        let changed_id = changed
            .findings
            .iter()
            .find_map(|finding| {
                matches!(&finding.result, ImportFindingResult::Candidate(_))
                    .then_some(finding.id.clone())
            })
            .expect("candidate finding");
        assert_eq!(
            changed_id,
            plan.accepted.iter().next().expect("accepted id").clone()
        );
        assert_ne!(changed.fingerprint, plan.fingerprint);
    }

    #[test]
    fn apply_refuses_a_changed_source_without_writing() {
        let source = TempDir::new().expect("source temp directory");
        let game = TempDir::new().expect("game temp directory");
        let destination = TempDir::new().expect("destination temp directory");
        write_sources(
            source.path(),
            r#"[{"UserName":"one@example.invalid"}]"#,
            game.path(),
        );
        let scan = scan(source.path()).expect("scan succeeds");
        let id = scan
            .findings
            .iter()
            .find_map(|finding| {
                matches!(&finding.result, ImportFindingResult::Candidate(_))
                    .then_some(finding.id.clone())
            })
            .expect("candidate finding");
        let plan = scan.plan([id]).expect("plan succeeds");
        fs::write(
            source.path().join(accounts_file()),
            r#"[{"UserName":"changed@example.invalid"}]"#,
        )
        .expect("change source fixture");
        let store = Store::new(destination.path().to_path_buf());

        assert!(matches!(
            apply(&store, &plan),
            Err(XivImportError::SourceChanged { .. })
        ));
        assert!(store.list_accounts().expect("list accounts").is_empty());
        assert!(store.list_profiles().expect("list profiles").is_empty());
    }

    #[test]
    fn apply_is_read_only_and_reuses_deterministic_duplicates() {
        let source = TempDir::new().expect("source temp directory");
        let game = TempDir::new().expect("game temp directory");
        let destination = TempDir::new().expect("destination temp directory");
        write_sources(
            source.path(),
            r#"[{"UserName":"One@Example.invalid","UseOtp":true,"SavePassword":true}]"#,
            game.path(),
        );
        let before_accounts = fs::read(source.path().join(accounts_file())).expect("read source");
        let before_config = fs::read(source.path().join(config_file())).expect("read source");
        let scan = scan(source.path()).expect("scan succeeds");
        let accepted: Vec<_> = scan
            .findings
            .iter()
            .filter_map(|finding| {
                matches!(&finding.result, ImportFindingResult::Candidate(_))
                    .then_some(finding.id.clone())
            })
            .collect();
        let plan = scan.plan(accepted).expect("plan succeeds");
        let store = Store::new(destination.path().to_path_buf());

        let first = apply(&store, &plan).expect("first apply succeeds");
        let second = apply(&store, &plan).expect("second apply succeeds");
        assert_eq!(first.applied.len(), 1);
        assert_eq!(first.applied[0].account_write, ImportWrite::Created);
        assert_eq!(first.applied[0].profile_write, Some(ImportWrite::Created));
        assert_eq!(second.applied[0].account, first.applied[0].account);
        assert_eq!(second.applied[0].profile, first.applied[0].profile);
        assert_eq!(second.applied[0].account_write, ImportWrite::Existing);
        assert_eq!(second.applied[0].profile_write, Some(ImportWrite::Existing));
        assert_eq!(store.list_accounts().expect("list accounts").len(), 1);
        assert_eq!(store.list_profiles().expect("list profiles").len(), 1);
        assert_eq!(
            fs::read(source.path().join(accounts_file())).expect("read source"),
            before_accounts
        );
        assert_eq!(
            fs::read(source.path().join(config_file())).expect("read source"),
            before_config
        );
    }

    #[test]
    fn oversized_source_is_rejected_before_json_parsing() {
        let source = TempDir::new().expect("source temp directory");
        let file = File::create(source.path().join(accounts_file())).expect("create source");
        file.set_len(MAX_SOURCE_BYTES + 1)
            .expect("extend source fixture");

        assert!(matches!(
            scan(source.path()),
            Err(XivImportError::SourceTooLarge { .. })
        ));
    }
}
