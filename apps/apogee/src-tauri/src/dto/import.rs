//! Preview and apply results for configuration import.

use apogee_core::{
    AccountKind, AppliedFinding, ImportApplyReport, ImportCandidate, ImportData, ImportFinding,
    ImportFindingResult, ImportIssue, ImportLocation, ImportScan, ImportWrite,
};
use serde::Serialize;
use ts_rs::TS;

use super::path::PathDto;

/// The result of scanning or applying one import source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum ImportDto {
    Scan(ImportScanDto),
    Applied(ImportApplyReportDto),
    Unknown,
}

impl From<&ImportData> for ImportDto {
    fn from(data: &ImportData) -> Self {
        match data {
            ImportData::Scan(scan) => Self::Scan(ImportScanDto::from(scan)),
            ImportData::Applied(report) => Self::Applied(ImportApplyReportDto::from(report)),
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportScanDto {
    source: PathDto,
    fingerprint: String,
    findings: Vec<ImportFindingDto>,
}

impl From<&ImportScan> for ImportScanDto {
    fn from(scan: &ImportScan) -> Self {
        Self {
            source: PathDto::from(scan.source.as_path()),
            fingerprint: scan.fingerprint.as_str().to_owned(),
            findings: scan.findings.iter().map(ImportFindingDto::from).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(super) struct ImportFindingDto {
    id: String,
    location: ImportLocationDto,
    result: ImportFindingResultDto,
}

impl From<&ImportFinding> for ImportFindingDto {
    fn from(finding: &ImportFinding) -> Self {
        Self {
            id: finding.id.as_str().to_owned(),
            location: ImportLocationDto::from(finding.location),
            result: ImportFindingResultDto::from(&finding.result),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum ImportLocationDto {
    AccountsFile,
    AccountRow { index: usize },
    ConfigFile,
    Unknown,
}

impl From<ImportLocation> for ImportLocationDto {
    fn from(location: ImportLocation) -> Self {
        match location {
            ImportLocation::AccountsFile => Self::AccountsFile,
            ImportLocation::AccountRow { index } => Self::AccountRow { index },
            ImportLocation::ConfigFile => Self::ConfigFile,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum ImportFindingResultDto {
    Candidate(ImportCandidateDto),
    Skipped(ImportIssueDto),
    Unknown,
}

impl From<&ImportFindingResult> for ImportFindingResultDto {
    fn from(result: &ImportFindingResult) -> Self {
        match result {
            ImportFindingResult::Candidate(candidate) => {
                Self::Candidate(ImportCandidateDto::from(candidate))
            }
            ImportFindingResult::Skipped(issue) => Self::Skipped(ImportIssueDto::from(issue)),
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(super) struct ImportCandidateDto {
    square_enix_id: String,
    account_kind: AccountKindDto,
    use_otp: bool,
    never_store: bool,
    game_path: Option<PathDto>,
}

impl From<&ImportCandidate> for ImportCandidateDto {
    fn from(candidate: &ImportCandidate) -> Self {
        Self {
            square_enix_id: candidate.sqex_id.clone(),
            account_kind: AccountKindDto::from(&candidate.kind),
            use_otp: candidate.use_otp,
            never_store: candidate.never_store,
            game_path: candidate.game_path.as_deref().map(PathDto::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum ImportIssueDto {
    MalformedJson,
    ExpectedArray,
    ExpectedObject,
    MissingUserName,
    InvalidUserName,
    InvalidUseOtp,
    InvalidSteamAccount,
    InvalidSavePassword,
    DuplicateAccount { first: String },
    MissingGamePath,
    InvalidGamePath,
    InvalidFreeTrial,
    Unknown,
}

impl From<&ImportIssue> for ImportIssueDto {
    fn from(issue: &ImportIssue) -> Self {
        match issue {
            ImportIssue::MalformedJson => Self::MalformedJson,
            ImportIssue::ExpectedArray => Self::ExpectedArray,
            ImportIssue::ExpectedObject => Self::ExpectedObject,
            ImportIssue::MissingUserName => Self::MissingUserName,
            ImportIssue::InvalidUserName => Self::InvalidUserName,
            ImportIssue::InvalidUseOtp => Self::InvalidUseOtp,
            ImportIssue::InvalidSteamAccount => Self::InvalidSteamAccount,
            ImportIssue::InvalidSavePassword => Self::InvalidSavePassword,
            ImportIssue::DuplicateAccount { first } => Self::DuplicateAccount {
                first: first.as_str().to_owned(),
            },
            ImportIssue::MissingGamePath => Self::MissingGamePath,
            ImportIssue::InvalidGamePath => Self::InvalidGamePath,
            ImportIssue::InvalidFreeTrial => Self::InvalidFreeTrial,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportApplyReportDto {
    applied: Vec<AppliedFindingDto>,
}

impl From<&ImportApplyReport> for ImportApplyReportDto {
    fn from(report: &ImportApplyReport) -> Self {
        Self {
            applied: report.applied.iter().map(AppliedFindingDto::from).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(super) struct AppliedFindingDto {
    finding: String,
    account: String,
    account_write: ImportWriteDto,
    profile: Option<String>,
    profile_write: Option<ImportWriteDto>,
}

impl From<&AppliedFinding> for AppliedFindingDto {
    fn from(finding: &AppliedFinding) -> Self {
        Self {
            finding: finding.finding.as_str().to_owned(),
            account: finding.account.to_string(),
            account_write: ImportWriteDto::from(finding.account_write),
            profile: finding.profile.map(|profile| profile.to_string()),
            profile_write: finding.profile_write.map(ImportWriteDto::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub(super) enum ImportWriteDto {
    Created,
    Existing,
}

impl From<ImportWrite> for ImportWriteDto {
    fn from(write: ImportWrite) -> Self {
        match write {
            ImportWrite::Created => Self::Created,
            ImportWrite::Existing => Self::Existing,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum AccountKindDto {
    Standard,
    Steam { app_id: u32 },
    FreeTrial,
    Unknown,
}

impl From<&AccountKind> for AccountKindDto {
    fn from(kind: &AccountKind) -> Self {
        match kind {
            AccountKind::Standard => Self::Standard,
            AccountKind::Steam { app_id } => Self::Steam { app_id: *app_id },
            AccountKind::FreeTrial => Self::FreeTrial,
            _ => Self::Unknown,
        }
    }
}
