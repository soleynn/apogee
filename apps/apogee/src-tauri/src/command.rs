//! The shell-owned request shape and its one-way conversion into core commands.

use apogee_core::{
    Command, FirstRunRequest, FirstRunTransition, FrontierQuery, GameChoice, ImportDecision,
    ImportXivLauncher, OtpSource, PasswordSource, PrefixAction, Uuid,
};
use serde::Deserialize;
use ts_rs::TS;

use crate::dto::first_run::{AccountChoiceDto, CredentialChoiceDto, LegibilityDto, ReadyActionDto};
use crate::dto::secrets::SecretBytes;
use crate::navigation::NavigationState;

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
    rename_all_fields = "camelCase",
    deny_unknown_fields
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
        #[ts(type = "string | null")]
        profile: Option<Uuid>,
        facts: Vec<CallerFactDto>,
    },
}

impl CommandDto {
    pub(crate) fn into_core(
        self,
        navigation: &NavigationState,
    ) -> Result<Command, CommandDtoError> {
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
            Self::Repair { profile } => Command::Repair {
                profile,
                local_indexes: Vec::new(),
            },
            Self::Prefix { profile, action } => Command::Prefix {
                profile,
                action: action.into_core(),
            },
            Self::FirstRun { request } => Command::FirstRun(request.into_core(navigation)?),
            Self::ImportXivLauncher { request } => {
                Command::ImportXivLauncher(request.into_core(navigation)?)
            }
            Self::Frontier { query } => Command::Frontier(query.into_core()),
            Self::SupportBundle { profile, facts } => Command::SupportBundle {
                profile,
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
    UnknownFolder,
    UnknownImportScan,
    UnknownFirstRunSelection,
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
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum FirstRunRequestDto {
    Read,
    Advance(FirstRunTransitionDto),
}

impl FirstRunRequestDto {
    fn into_core(self, navigation: &NavigationState) -> Result<FirstRunRequest, CommandDtoError> {
        Ok(match self {
            Self::Read => FirstRunRequest::Read,
            Self::Advance(transition) => {
                FirstRunRequest::Advance(transition.into_core(navigation)?)
            }
        })
    }
}

/// The accepted first-run transitions, mirrored so their field casing remains shell-owned.
#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum FirstRunTransitionDto {
    ConfirmLegibility(LegibilityDto),
    DecideImport(FirstRunImportDecisionDto),
    SaveAccount(AccountChoiceDto),
    SelectGame(FirstRunGameChoiceDto),
    SelectCredential(CredentialChoiceDto),
    StartReady(ReadyActionDto),
}

impl FirstRunTransitionDto {
    fn into_core(
        self,
        navigation: &NavigationState,
    ) -> Result<FirstRunTransition, CommandDtoError> {
        let unsupported = || CommandDtoError::UnsupportedFirstRunValue;
        Ok(match self {
            Self::ConfirmLegibility(reading) => {
                FirstRunTransition::ConfirmLegibility(reading.into_core().ok_or_else(unsupported)?)
            }
            Self::DecideImport(decision) => {
                FirstRunTransition::DecideImport(decision.into_core(navigation)?)
            }
            Self::SaveAccount(account) => {
                FirstRunTransition::SaveAccount(account.into_core().ok_or_else(unsupported)?)
            }
            Self::SelectGame(game) => FirstRunTransition::SelectGame(game.into_core(navigation)?),
            Self::SelectCredential(credential) => FirstRunTransition::SelectCredential(
                credential.into_core().ok_or_else(unsupported)?,
            ),
            Self::StartReady(action) => {
                FirstRunTransition::StartReady(action.into_core().ok_or_else(unsupported)?)
            }
        })
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "choice",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum FirstRunImportDecisionDto {
    Import {
        #[ts(type = "string")]
        candidate: Uuid,
    },
    Skip,
}

impl FirstRunImportDecisionDto {
    fn into_core(self, navigation: &NavigationState) -> Result<ImportDecision, CommandDtoError> {
        match self {
            Self::Import { candidate } => navigation
                .first_run_import(candidate)
                .ok_or(CommandDtoError::UnknownFirstRunSelection),
            Self::Skip => Ok(ImportDecision::Skip),
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "choice",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum FirstRunGameChoiceDto {
    Existing {
        #[ts(type = "string")]
        candidate: Uuid,
    },
    Install {
        #[ts(type = "string")]
        folder: Uuid,
        approximate_bytes: u64,
        exact_download_bytes: u64,
    },
}

impl FirstRunGameChoiceDto {
    fn into_core(self, navigation: &NavigationState) -> Result<GameChoice, CommandDtoError> {
        match self {
            Self::Existing { candidate } => navigation
                .first_run_game(candidate)
                .ok_or(CommandDtoError::UnknownFirstRunSelection),
            Self::Install {
                folder,
                approximate_bytes,
                exact_download_bytes,
            } => Ok(GameChoice::Install {
                path: navigation
                    .folder(folder)
                    .ok_or(CommandDtoError::UnknownFolder)?,
                approximate_bytes,
                exact_download_bytes,
            }),
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum ImportXivLauncherDto {
    Scan {
        #[ts(type = "string")]
        folder: Uuid,
    },
    Apply {
        #[ts(type = "string")]
        scan: Uuid,
        accepted: Vec<String>,
    },
}

impl ImportXivLauncherDto {
    fn into_core(self, navigation: &NavigationState) -> Result<ImportXivLauncher, CommandDtoError> {
        Ok(match self {
            Self::Scan { folder } => ImportXivLauncher::Scan(
                navigation
                    .folder(folder)
                    .ok_or(CommandDtoError::UnknownFolder)?,
            ),
            Self::Apply { scan, accepted } => ImportXivLauncher::Apply(
                navigation
                    .import_plan(scan, accepted)
                    .ok_or(CommandDtoError::UnknownImportScan)?,
            ),
        })
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

/// Every leaf operation the generic `execute` IPC command accepts.
///
/// The inventory is derived from the same generated discriminants the webview uses. Adding a
/// command, subcommand, or first-run decision therefore changes this set without a second manual
/// list that can drift.
#[cfg(test)]
pub(crate) fn operation_ids() -> std::collections::BTreeSet<String> {
    let mut operations = tagged_kinds::<CommandDto>();
    for family in ["prefix", "firstRun", "importXivLauncher", "frontier"] {
        operations.remove(family);
    }
    operations.extend(
        tagged_kinds::<PrefixActionDto>()
            .into_iter()
            .map(|kind| format!("prefix.{kind}")),
    );
    operations.extend(
        tagged_kinds::<FirstRunRequestDto>()
            .into_iter()
            .filter(|kind| kind != "advance")
            .map(|kind| format!("firstRun.{kind}")),
    );
    operations.extend(
        tagged_kinds::<FirstRunTransitionDto>()
            .into_iter()
            .map(|kind| format!("firstRun.advance.{kind}")),
    );
    operations.extend(
        tagged_kinds::<ImportXivLauncherDto>()
            .into_iter()
            .map(|kind| format!("importXivLauncher.{kind}")),
    );
    operations.extend(
        tagged_kinds::<FrontierQueryDto>()
            .into_iter()
            .map(|kind| format!("frontier.{kind}")),
    );
    operations
}

#[cfg(test)]
fn tagged_kinds<T: TS>() -> std::collections::BTreeSet<String> {
    let declaration = T::decl(&ts_rs::Config::default());
    let marker = r#""kind": ""#;
    declaration
        .split(marker)
        .skip(1)
        .filter_map(|tail| tail.split('"').next().map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "00000000-0000-0000-0000-000000000000";

    fn parse(json: &str, navigation: &NavigationState) -> Option<Command> {
        serde_json::from_str::<CommandDto>(json)
            .ok()
            .and_then(|command| command.into_core(navigation).ok())
    }

    #[test]
    fn every_command_arm_accepts_the_shell_wire_shape() {
        let navigation = NavigationState::default();
        let folder = navigation.register_folder("import-root".into()).id();
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
            format!(r#"{{"kind":"repair","profile":"{PROFILE}"}}"#),
            format!(
                r#"{{"kind":"prefix","profile":"{PROFILE}","action":{{"kind":"recreate","backupConfig":true}}}}"#
            ),
            r#"{"kind":"firstRun","request":{"kind":"advance","value":{"kind":"confirmLegibility","value":{"gpu":null,"driver":null,"session":"wayland","renderTier":1}}}}"#.to_owned(),
            format!(r#"{{"kind":"importXivLauncher","request":{{"kind":"scan","folder":"{folder}"}}}}"#),
            r#"{"kind":"frontier","query":{"kind":"gate","wait":true}}"#.to_owned(),
            r#"{"kind":"supportBundle","facts":[{"name":"render_tier","value":"1"}]}"#.to_owned(),
        ];

        for command in commands {
            assert!(
                parse(&command, &navigation).is_some(),
                "did not accept {command}"
            );
        }
    }

    #[test]
    fn unsupported_first_run_fallbacks_are_rejected_before_core() {
        let command = r#"{"kind":"firstRun","request":{"kind":"advance","value":{"kind":"saveAccount","value":{"squareEnixId":"person","kind":"unknown","neverSavePassword":true,"steamClient":"notRequired"}}}}"#;

        assert!(parse(command, &NavigationState::default()).is_none());
    }

    #[test]
    fn backend_owned_first_run_readings_are_not_accepted_from_the_webview() {
        let command = r#"{"kind":"firstRun","request":{"kind":"advance","value":{"kind":"recordRunners","value":[]}}}"#;

        assert!(parse(command, &NavigationState::default()).is_none());
    }

    #[test]
    fn first_run_paths_must_be_process_local_capabilities() {
        let import = r#"{"kind":"firstRun","request":{"kind":"advance","value":{"kind":"decideImport","value":{"choice":"import","path":"candidate"}}}}"#;
        let game = r#"{"kind":"firstRun","request":{"kind":"advance","value":{"kind":"selectGame","value":{"choice":"existing","path":"game","state":{"state":"current"}}}}}"#;

        assert!(parse(import, &NavigationState::default()).is_none());
        assert!(parse(game, &NavigationState::default()).is_none());
    }

    #[test]
    fn first_run_capabilities_restore_the_observed_core_values() {
        let navigation = NavigationState::default();
        let import_path = std::path::PathBuf::from("private/import");
        let game_path = std::path::PathBuf::from("private/game");
        let checkpoint = apogee_core::FirstRunCheckpoint {
            import: apogee_core::ImportState::Candidates(vec![
                apogee_core::FirstRunImportCandidate {
                    path: import_path.clone(),
                    source: apogee_core::FirstRunImportSource::Core,
                },
            ]),
            game_candidates: vec![apogee_core::GameCandidate {
                path: game_path.clone(),
                state: apogee_core::GameCandidateState::Current {
                    installed_bytes: 42,
                },
            }],
            ..apogee_core::FirstRunCheckpoint::default()
        };
        let snapshot = navigation.replace_first_run(&checkpoint);
        let import = snapshot.import_id(0).expect("import capability");
        let game = snapshot.game_id(0).expect("game capability");
        let import_command = format!(
            r#"{{"kind":"firstRun","request":{{"kind":"advance","value":{{"kind":"decideImport","value":{{"choice":"import","candidate":"{import}"}}}}}}}}"#
        );
        let game_command = format!(
            r#"{{"kind":"firstRun","request":{{"kind":"advance","value":{{"kind":"selectGame","value":{{"choice":"existing","candidate":"{game}"}}}}}}}}"#
        );

        assert!(matches!(
            parse(&import_command, &navigation),
            Some(Command::FirstRun(FirstRunRequest::Advance(
                FirstRunTransition::DecideImport(ImportDecision::Import(path))
            ))) if path == import_path
        ));
        assert!(matches!(
            parse(&game_command, &navigation),
            Some(Command::FirstRun(FirstRunRequest::Advance(
                FirstRunTransition::SelectGame(GameChoice::Existing {
                    path,
                    state: apogee_core::ExistingGameState::Current,
                })
            ))) if path == game_path
        ));
    }

    #[test]
    fn repair_and_import_reject_frontend_paths() {
        let repair = format!(
            r#"{{"kind":"repair","profile":"{PROFILE}","localIndexes":[{{"path":"index.apzi"}}]}}"#
        );
        let import =
            r#"{"kind":"importXivLauncher","request":{"kind":"scan","path":"import-root"}}"#;

        assert!(serde_json::from_str::<CommandDto>(&repair).is_err());
        assert!(serde_json::from_str::<CommandDto>(import).is_err());
    }

    #[test]
    fn operation_inventory_is_derived_from_every_nested_command_family() {
        let operations = operation_ids();

        assert!(operations.contains("login"));
        assert!(operations.contains("prefix.recreate"));
        assert!(operations.contains("firstRun.advance.confirmLegibility"));
        assert!(operations.contains("importXivLauncher.apply"));
        assert!(operations.contains("frontier.gate"));
        assert_eq!(operations.len(), 23);
    }

    #[test]
    fn generated_command_contract_contains_no_path_type() {
        let declaration = CommandDto::decl(&ts_rs::Config::default());
        let first_run = FirstRunTransitionDto::decl(&ts_rs::Config::default());
        let import = ImportXivLauncherDto::decl(&ts_rs::Config::default());

        assert!(!declaration.contains("PathDto"));
        assert!(!first_run.contains("PathDto"));
        assert!(!import.contains("PathDto"));
    }
}
