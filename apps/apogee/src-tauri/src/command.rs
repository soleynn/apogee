//! The shell-owned request shape and its one-way conversion into core commands.

use std::path::PathBuf;

use apogee_core::{
    Command, FirstRunRequest, FirstRunTransition, FrontierQuery, ImportPlan, ImportXivLauncher,
    OtpSource, PasswordSource, PrefixAction, Repo, Uuid,
};
use serde::Deserialize;
use ts_rs::TS;

use crate::dto::first_run::{
    AccountChoiceDto, CredentialBackendReadingDto, CredentialChoiceDto, FirstRunImportCandidateDto,
    GameCandidateDto, GameChoiceDto, ImportDecisionDto, LegibilityDto, ReadyActionDto,
    RunnerAndPrefixChoiceDto, RunnerReadingDto,
};
use crate::dto::path::PathDto;
use crate::dto::secrets::SecretBytes;

/// Where the core should get the account password for this run.
#[derive(Deserialize, TS)]
#[serde(tag = "kind", content = "bytes", rename_all = "camelCase")]
pub(crate) enum PasswordSourceDto {
    Stored,
    Provided(#[ts(type = "number[]")] SecretBytes),
}

impl PasswordSourceDto {
    fn into_core(self) -> PasswordSource {
        match self {
            Self::Stored => PasswordSource::Stored,
            Self::Provided(bytes) => PasswordSource::Provided(bytes.into_secret()),
        }
    }
}

/// Where the core should get a one-time password for this run.
#[derive(Deserialize, TS)]
#[serde(tag = "kind", content = "bytes", rename_all = "camelCase")]
pub(crate) enum OtpSourceDto {
    Totp,
    Manual(#[ts(type = "number[]")] SecretBytes),
    Listener,
}

impl OtpSourceDto {
    fn into_core(self) -> OtpSource {
        match self {
            Self::Totp => OtpSource::Totp,
            Self::Manual(bytes) => OtpSource::Manual(bytes.into_secret()),
            Self::Listener => OtpSource::Listener,
        }
    }
}

/// Commands accepted from the webview. Each arm only converts shape; all decisions remain in core.
#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(export, export_to = "Command.ts")]
pub(crate) enum CommandDto {
    Login {
        #[ts(type = "string")]
        profile: Uuid,
        password: PasswordSourceDto,
        otp: OtpSourceDto,
    },
    Launch {
        #[ts(type = "string")]
        profile: Uuid,
    },
    PatchAndPlay {
        #[ts(type = "string")]
        profile: Uuid,
        password: PasswordSourceDto,
        otp: OtpSourceDto,
    },
    Patch {
        #[ts(type = "string")]
        profile: Uuid,
        password: PasswordSourceDto,
        otp: OtpSourceDto,
    },
    Install {
        #[ts(type = "string")]
        profile: Uuid,
        password: PasswordSourceDto,
        otp: OtpSourceDto,
    },
    Repair {
        #[ts(type = "string")]
        profile: Uuid,
        local_indexes: Vec<LocalIndexDto>,
    },
    Prefix {
        #[ts(type = "string")]
        profile: Uuid,
        action: PrefixActionDto,
    },
    FirstRun {
        request: FirstRunRequestDto,
    },
    ImportXivLauncher {
        request: ImportXivLauncherDto,
    },
    Frontier {
        query: FrontierQueryDto,
    },
    SupportBundle {
        facts: Vec<CallerFactDto>,
    },
}

impl CommandDto {
    pub(crate) fn into_core(self) -> Result<Command, CommandDtoError> {
        Ok(match self {
            Self::Login {
                profile,
                password,
                otp,
            } => Command::Login {
                profile,
                password: password.into_core(),
                otp: otp.into_core(),
            },
            Self::Launch { profile } => Command::Launch { profile },
            Self::PatchAndPlay {
                profile,
                password,
                otp,
            } => Command::PatchAndPlay {
                profile,
                password: password.into_core(),
                otp: otp.into_core(),
            },
            Self::Patch {
                profile,
                password,
                otp,
            } => Command::Patch {
                profile,
                password: password.into_core(),
                otp: otp.into_core(),
            },
            Self::Install {
                profile,
                password,
                otp,
            } => Command::Install {
                profile,
                password: password.into_core(),
                otp: otp.into_core(),
            },
            Self::Repair {
                profile,
                local_indexes,
            } => Command::Repair {
                profile,
                local_indexes: local_indexes
                    .into_iter()
                    .map(LocalIndexDto::into_core)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            Self::Prefix { profile, action } => Command::Prefix {
                profile,
                action: action.into_core(),
            },
            Self::FirstRun { request } => Command::FirstRun(request.into_core()?),
            Self::ImportXivLauncher { request } => Command::ImportXivLauncher(request.into_core()?),
            Self::Frontier { query } => Command::Frontier(query.into_core()),
            Self::SupportBundle { facts } => Command::SupportBundle {
                facts: facts
                    .into_iter()
                    .map(|fact| (fact.name, fact.value))
                    .collect(),
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandDtoError {
    UnsupportedFirstRunValue,
    UnsupportedPathEncoding,
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalIndexDto {
    repo: RepoDto,
    path: PathDto,
}

impl LocalIndexDto {
    fn into_core(self) -> Result<(Repo, PathBuf), CommandDtoError> {
        Ok((
            self.repo.into_core(),
            self.path
                .into_path()
                .map_err(|_| CommandDtoError::UnsupportedPathEncoding)?,
        ))
    }
}

#[derive(Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum RepoDto {
    Boot,
    Game,
    Expansion { number: u8 },
}

impl RepoDto {
    fn into_core(self) -> Repo {
        match self {
            Self::Boot => Repo::Boot,
            Self::Game => Repo::Game,
            Self::Expansion { number } => Repo::Expansion(number),
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum PrefixActionDto {
    Create,
    Check,
    Fix,
    Recreate { backup_config: bool },
}

impl PrefixActionDto {
    fn into_core(self) -> PrefixAction {
        match self {
            Self::Create => PrefixAction::Create,
            Self::Check => PrefixAction::Check,
            Self::Fix => PrefixAction::Fix,
            Self::Recreate { backup_config } => PrefixAction::Recreate { backup_config },
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub(crate) enum FirstRunRequestDto {
    Read,
    Advance(FirstRunTransitionDto),
}

impl FirstRunRequestDto {
    fn into_core(self) -> Result<FirstRunRequest, CommandDtoError> {
        Ok(match self {
            Self::Read => FirstRunRequest::Read,
            Self::Advance(transition) => FirstRunRequest::Advance(transition.into_core()?),
        })
    }
}

/// The accepted first-run transitions, mirrored so their field casing remains shell-owned.
#[derive(Deserialize, TS)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub(crate) enum FirstRunTransitionDto {
    ConfirmLegibility(LegibilityDto),
    RecordImportDiscovery(Vec<FirstRunImportCandidateDto>),
    DecideImport(ImportDecisionDto),
    SaveAccount(AccountChoiceDto),
    RecordGameCandidates(Vec<GameCandidateDto>),
    SelectGame(GameChoiceDto),
    RecordCredentialBackends(Vec<CredentialBackendReadingDto>),
    SelectCredential(CredentialChoiceDto),
    RecordRunners(Vec<RunnerReadingDto>),
    FinishRunnerAndPrefix(RunnerAndPrefixChoiceDto),
    StartReady(ReadyActionDto),
}

impl FirstRunTransitionDto {
    fn into_core(self) -> Result<FirstRunTransition, CommandDtoError> {
        let unsupported = || CommandDtoError::UnsupportedFirstRunValue;
        Ok(match self {
            Self::ConfirmLegibility(reading) => {
                FirstRunTransition::ConfirmLegibility(reading.into_core().ok_or_else(unsupported)?)
            }
            Self::RecordImportDiscovery(candidates) => FirstRunTransition::RecordImportDiscovery(
                candidates
                    .into_iter()
                    .map(FirstRunImportCandidateDto::into_core)
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(unsupported)?,
            ),
            Self::DecideImport(decision) => {
                FirstRunTransition::DecideImport(decision.into_core().ok_or_else(unsupported)?)
            }
            Self::SaveAccount(account) => {
                FirstRunTransition::SaveAccount(account.into_core().ok_or_else(unsupported)?)
            }
            Self::RecordGameCandidates(candidates) => FirstRunTransition::RecordGameCandidates(
                candidates
                    .into_iter()
                    .map(GameCandidateDto::into_core)
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(unsupported)?,
            ),
            Self::SelectGame(game) => {
                FirstRunTransition::SelectGame(game.into_core().ok_or_else(unsupported)?)
            }
            Self::RecordCredentialBackends(backends) => {
                FirstRunTransition::RecordCredentialBackends(
                    backends
                        .into_iter()
                        .map(CredentialBackendReadingDto::into_core)
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(unsupported)?,
                )
            }
            Self::SelectCredential(credential) => FirstRunTransition::SelectCredential(
                credential.into_core().ok_or_else(unsupported)?,
            ),
            Self::RecordRunners(runners) => FirstRunTransition::RecordRunners(
                runners
                    .into_iter()
                    .map(RunnerReadingDto::into_core)
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(unsupported)?,
            ),
            Self::FinishRunnerAndPrefix(choice) => FirstRunTransition::FinishRunnerAndPrefix(
                choice.into_core().ok_or_else(unsupported)?,
            ),
            Self::StartReady(action) => {
                FirstRunTransition::StartReady(action.into_core().ok_or_else(unsupported)?)
            }
        })
    }
}

#[derive(Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum ImportXivLauncherDto {
    Scan { path: PathDto },
    Apply { plan: ImportPlanDto },
}

impl ImportXivLauncherDto {
    fn into_core(self) -> Result<ImportXivLauncher, CommandDtoError> {
        Ok(match self {
            Self::Scan { path } => ImportXivLauncher::Scan(
                path.into_path()
                    .map_err(|_| CommandDtoError::UnsupportedPathEncoding)?,
            ),
            Self::Apply { plan } => ImportXivLauncher::Apply(plan.into_core()?),
        })
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportPlanDto {
    source: PathDto,
    fingerprint: String,
    accepted: Vec<String>,
}

impl ImportPlanDto {
    fn into_core(self) -> Result<ImportPlan, CommandDtoError> {
        Ok(ImportPlan::from_selection_parts(
            self.source
                .into_path()
                .map_err(|_| CommandDtoError::UnsupportedPathEncoding)?,
            self.fingerprint,
            self.accepted,
        ))
    }
}

#[derive(Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum FrontierQueryDto {
    News,
    Gate { wait: bool },
    Banners,
}

impl FrontierQueryDto {
    fn into_core(self) -> FrontierQuery {
        match self {
            Self::News => FrontierQuery::News,
            Self::Gate { wait } => FrontierQuery::Gate { wait },
            Self::Banners => FrontierQuery::Banners,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CallerFactDto {
    name: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "00000000-0000-0000-0000-000000000000";

    fn parse(json: &str) -> Option<Command> {
        serde_json::from_str::<CommandDto>(json)
            .ok()
            .and_then(|command| command.into_core().ok())
    }

    #[test]
    fn every_command_arm_accepts_the_shell_wire_shape() {
        let commands = [
            format!(
                r#"{{"kind":"login","profile":"{PROFILE}","password":{{"kind":"stored"}},"otp":{{"kind":"totp"}}}}"#
            ),
            format!(r#"{{"kind":"launch","profile":"{PROFILE}"}}"#),
            format!(
                r#"{{"kind":"patchAndPlay","profile":"{PROFILE}","password":{{"kind":"provided","bytes":[112,119]}},"otp":{{"kind":"manual","bytes":[49,50,51,52,53,54]}}}}"#
            ),
            format!(
                r#"{{"kind":"patch","profile":"{PROFILE}","password":{{"kind":"stored"}},"otp":{{"kind":"listener"}}}}"#
            ),
            format!(
                r#"{{"kind":"install","profile":"{PROFILE}","password":{{"kind":"stored"}},"otp":{{"kind":"totp"}}}}"#
            ),
            format!(
                r#"{{"kind":"repair","profile":"{PROFILE}","localIndexes":[{{"repo":{{"kind":"expansion","number":2}},"path":{{"display":"index.apzi","value":{{"kind":"utf8","value":"index.apzi"}}}}}}]}}"#
            ),
            format!(
                r#"{{"kind":"prefix","profile":"{PROFILE}","action":{{"kind":"recreate","backupConfig":true}}}}"#
            ),
            r#"{"kind":"firstRun","request":{"kind":"advance","value":{"kind":"confirmLegibility","value":{"gpu":null,"driver":null,"session":"wayland","renderTier":1}}}}"#.to_owned(),
            r#"{"kind":"importXivLauncher","request":{"kind":"scan","path":{"display":"import-root","value":{"kind":"utf8","value":"import-root"}}}}"#.to_owned(),
            r#"{"kind":"frontier","query":{"kind":"gate","wait":true}}"#.to_owned(),
            r#"{"kind":"supportBundle","facts":[{"name":"render_tier","value":"1"}]}"#.to_owned(),
        ];

        for command in commands {
            assert!(parse(&command).is_some(), "did not accept {command}");
        }
    }

    #[test]
    fn unsupported_first_run_fallbacks_are_rejected_before_core() {
        let command = r#"{"kind":"firstRun","request":{"kind":"advance","value":{"kind":"saveAccount","value":{"squareEnixId":"person","kind":"unknown","neverSavePassword":true,"steamClient":"notRequired"}}}}"#;

        assert!(parse(command).is_none());
    }
}
