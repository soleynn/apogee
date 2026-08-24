//! Pure state and transitions for resumable first-run setup.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The ordered setup steps a shell can render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FirstRunStep {
    Legibility,
    Import,
    Account,
    Game,
    CredentialBackend,
    RunnerAndPrefix,
    Ready,
}

/// The current position derived from a persisted checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FirstRunPosition {
    Step(FirstRunStep),
    WaitingForImportDiscovery,
    Complete,
}

/// Facts shown while a person confirms that the window is legible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegibilityReading {
    pub gpu: Option<String>,
    pub driver: Option<String>,
    pub session: SessionType,
    pub render_tier: u8,
}

/// The display-server session in which the window was confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SessionType {
    Wayland,
    X11,
    Windows,
    Unknown,
}

/// The result of looking for configuration that can be imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
#[non_exhaustive]
pub enum ImportState {
    #[default]
    DiscoveryPending,
    NoneFound,
    Candidates(Vec<FirstRunImportCandidate>),
    Complete(ImportDecision),
}

/// A configuration directory found by import discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstRunImportCandidate {
    pub path: PathBuf,
    pub source: FirstRunImportSource,
}

/// The installation shape that supplied an import candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FirstRunImportSource {
    Native,
    Core,
    Flatpak,
}

/// The person's decision after import discovery finds candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "choice", content = "value")]
#[non_exhaustive]
pub enum ImportDecision {
    Import(PathBuf),
    Skip,
}

/// The account information first-run setup may persist.
///
/// Passwords are deliberately absent from this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChoice {
    pub square_enix_id: String,
    pub kind: FirstRunAccountKind,
    pub never_save_password: bool,
    pub steam_client: SteamClientReading,
}

/// Account kinds that change login and launch behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FirstRunAccountKind {
    Standard,
    Steam,
    FreeTrial,
}

/// Whether the Steam client needed by a Steam account was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SteamClientReading {
    Present,
    Missing,
    NotRequired,
}

/// A game location that has been inspected rather than guessed by a shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameCandidate {
    pub path: PathBuf,
    pub state: GameCandidateState,
}

/// The verified state of a game candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
#[non_exhaustive]
pub enum GameCandidateState {
    Current { installed_bytes: u64 },
    NeedsUpdate(PatchReading),
    NotAGame,
    Unreadable { code: String },
}

/// A verified patch reading used by setup summaries and the ready action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchReading {
    pub count: u32,
    pub bytes: u64,
}

/// The selected game location and the verified work required there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "choice", content = "value")]
#[non_exhaustive]
pub enum GameChoice {
    Existing {
        path: PathBuf,
        state: ExistingGameState,
    },
    Install {
        path: PathBuf,
        approximate_bytes: u64,
        exact_download_bytes: u64,
    },
}

/// The verified state carried forward for an existing installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
#[non_exhaustive]
pub enum ExistingGameState {
    Current,
    NeedsUpdate(PatchReading),
}

/// A credential backend and its current usability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBackendReading {
    pub backend: CredentialBackend,
    pub state: CredentialBackendState,
}

/// Credential storage implementations offered during setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialBackend {
    SecretService,
    EncryptedFile,
    WindowsCredentialManager,
}

/// Whether a backend is ready, needs interaction, or cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
#[non_exhaustive]
pub enum CredentialBackendState {
    Ready,
    NeedsPassphrase,
    Unavailable { code: String },
}

/// The credential-storage outcome chosen during setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "choice", content = "value")]
#[non_exhaustive]
pub enum CredentialChoice {
    SaveIn(CredentialBackend),
    DoNotSave,
}

/// A runner row that can be rendered without duplicating recommendation rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerReading {
    pub selection: FirstRunRunnerSelection,
    pub version: Option<String>,
    pub recommended: bool,
    pub available: bool,
}

/// The runner selected for the new profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
#[non_exhaustive]
pub enum FirstRunRunnerSelection {
    Managed { name: String, version: String },
    SystemWine { version: Option<String> },
}

/// The persisted result of runner selection and prefix preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerAndPrefixChoice {
    pub runner: FirstRunRunnerSelection,
    pub prefix: PrefixOutcome,
}

/// Prefix preparation either succeeds or continues with an explicit degraded state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
#[non_exhaustive]
pub enum PrefixOutcome {
    Ready,
    ContinueWithoutPrefix { code: String },
}

/// The launch action that ends the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action", content = "value")]
#[non_exhaustive]
pub enum ReadyAction {
    Play,
    UpdateAndPlay(PatchReading),
    InstallAndPlay { bytes: u64 },
}

/// Whether the final action is still waiting or has been started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
#[non_exhaustive]
pub enum ReadyState {
    #[default]
    Pending,
    Started(ReadyAction),
}

/// Persisted progress through setup.
///
/// Each completed value is sufficient to resume at the first incomplete required step. Current
/// discovery rows can be refreshed independently before their corresponding choice is persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FirstRunCheckpoint {
    pub legibility: Option<LegibilityReading>,
    #[serde(default)]
    pub import: ImportState,
    pub account: Option<AccountChoice>,
    pub game_candidates: Vec<GameCandidate>,
    pub game: Option<GameChoice>,
    pub credential_backends: Vec<CredentialBackendReading>,
    pub credential: Option<CredentialChoice>,
    pub runners: Vec<RunnerReading>,
    pub runner_and_prefix: Option<RunnerAndPrefixChoice>,
    #[serde(default)]
    pub ready: ReadyState,
}

/// A pure state change accepted by [`transition`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FirstRunTransition {
    ConfirmLegibility(LegibilityReading),
    RecordImportDiscovery(Vec<FirstRunImportCandidate>),
    DecideImport(ImportDecision),
    SaveAccount(AccountChoice),
    RecordGameCandidates(Vec<GameCandidate>),
    SelectGame(GameChoice),
    RecordCredentialBackends(Vec<CredentialBackendReading>),
    SelectCredential(CredentialChoice),
    RecordRunners(Vec<RunnerReading>),
    FinishRunnerAndPrefix(RunnerAndPrefixChoice),
    StartReady(ReadyAction),
}

/// A rejected first-run transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FirstRunTransitionError {
    #[error("first-run transition is not valid at {position:?}")]
    WrongPosition { position: FirstRunPosition },
    #[error("import candidate was not returned by discovery: {path}")]
    UnknownImportCandidate { path: PathBuf },
    #[error("game candidate was not returned by verification: {path}")]
    UnknownGameCandidate { path: PathBuf },
    #[error("game candidate is not a usable installation: {path}")]
    UnusableGameCandidate { path: PathBuf },
    #[error("credential backend is not ready: {backend:?}")]
    CredentialBackendNotReady { backend: CredentialBackend },
    #[error("runner is not available: {runner:?}")]
    RunnerNotAvailable { runner: FirstRunRunnerSelection },
    #[error("ready action does not match the verified game state")]
    ReadyActionMismatch,
}

/// Select the first incomplete required setup step.
pub fn first_incomplete(checkpoint: &FirstRunCheckpoint) -> FirstRunPosition {
    if checkpoint.legibility.is_none() {
        return FirstRunPosition::Step(FirstRunStep::Legibility);
    }
    match &checkpoint.import {
        ImportState::DiscoveryPending => return FirstRunPosition::WaitingForImportDiscovery,
        ImportState::Candidates(candidates) if !candidates.is_empty() => {
            return FirstRunPosition::Step(FirstRunStep::Import);
        }
        ImportState::NoneFound | ImportState::Complete(_) | ImportState::Candidates(_) => {}
    }
    if checkpoint.account.is_none() {
        return FirstRunPosition::Step(FirstRunStep::Account);
    }
    if checkpoint.game.is_none() {
        return FirstRunPosition::Step(FirstRunStep::Game);
    }
    if checkpoint.credential.is_none() {
        return FirstRunPosition::Step(FirstRunStep::CredentialBackend);
    }
    if checkpoint.runner_and_prefix.is_none() {
        return FirstRunPosition::Step(FirstRunStep::RunnerAndPrefix);
    }
    match checkpoint.ready {
        ReadyState::Pending => FirstRunPosition::Step(FirstRunStep::Ready),
        ReadyState::Started(_) => FirstRunPosition::Complete,
    }
}

/// Derive the only valid final action from the verified game choice.
pub fn ready_action(checkpoint: &FirstRunCheckpoint) -> Option<ReadyAction> {
    match checkpoint.game.as_ref()? {
        GameChoice::Existing {
            state: ExistingGameState::Current,
            ..
        } => Some(ReadyAction::Play),
        GameChoice::Existing {
            state: ExistingGameState::NeedsUpdate(patches),
            ..
        } => Some(ReadyAction::UpdateAndPlay(*patches)),
        GameChoice::Install {
            exact_download_bytes,
            ..
        } => Some(ReadyAction::InstallAndPlay {
            bytes: *exact_download_bytes,
        }),
    }
}

/// Apply one setup transition without performing I/O.
pub fn transition(
    checkpoint: &FirstRunCheckpoint,
    change: FirstRunTransition,
) -> Result<FirstRunCheckpoint, FirstRunTransitionError> {
    let position = first_incomplete(checkpoint);
    let mut next = checkpoint.clone();
    match change {
        FirstRunTransition::ConfirmLegibility(reading)
            if position == FirstRunPosition::Step(FirstRunStep::Legibility) =>
        {
            next.legibility = Some(reading);
        }
        FirstRunTransition::RecordImportDiscovery(candidates)
            if position == FirstRunPosition::WaitingForImportDiscovery =>
        {
            next.import = if candidates.is_empty() {
                ImportState::NoneFound
            } else {
                ImportState::Candidates(candidates)
            };
        }
        FirstRunTransition::DecideImport(decision)
            if position == FirstRunPosition::Step(FirstRunStep::Import) =>
        {
            if let ImportDecision::Import(path) = &decision {
                let known = matches!(
                    &next.import,
                    ImportState::Candidates(candidates)
                        if candidates.iter().any(|candidate| candidate.path == *path)
                );
                if !known {
                    return Err(FirstRunTransitionError::UnknownImportCandidate {
                        path: path.clone(),
                    });
                }
            }
            next.import = ImportState::Complete(decision);
        }
        FirstRunTransition::SaveAccount(account)
            if position == FirstRunPosition::Step(FirstRunStep::Account) =>
        {
            next.account = Some(account);
        }
        FirstRunTransition::RecordGameCandidates(candidates)
            if position == FirstRunPosition::Step(FirstRunStep::Game) =>
        {
            next.game_candidates = candidates;
        }
        FirstRunTransition::SelectGame(game)
            if position == FirstRunPosition::Step(FirstRunStep::Game) =>
        {
            validate_game_choice(&next, &game)?;
            next.game = Some(game);
        }
        FirstRunTransition::RecordCredentialBackends(backends)
            if position == FirstRunPosition::Step(FirstRunStep::CredentialBackend) =>
        {
            next.credential_backends = backends;
        }
        FirstRunTransition::SelectCredential(credential)
            if position == FirstRunPosition::Step(FirstRunStep::CredentialBackend) =>
        {
            if let CredentialChoice::SaveIn(backend) = credential {
                let ready = next.credential_backends.iter().any(|reading| {
                    reading.backend == backend && reading.state == CredentialBackendState::Ready
                });
                if !ready {
                    return Err(FirstRunTransitionError::CredentialBackendNotReady { backend });
                }
            }
            next.credential = Some(credential);
        }
        FirstRunTransition::RecordRunners(runners)
            if position == FirstRunPosition::Step(FirstRunStep::RunnerAndPrefix) =>
        {
            next.runners = runners;
        }
        FirstRunTransition::FinishRunnerAndPrefix(choice)
            if position == FirstRunPosition::Step(FirstRunStep::RunnerAndPrefix) =>
        {
            let available = next
                .runners
                .iter()
                .any(|reading| reading.selection == choice.runner && reading.available);
            if !available {
                return Err(FirstRunTransitionError::RunnerNotAvailable {
                    runner: choice.runner,
                });
            }
            next.runner_and_prefix = Some(choice);
        }
        FirstRunTransition::StartReady(action)
            if position == FirstRunPosition::Step(FirstRunStep::Ready) =>
        {
            if ready_action(checkpoint) != Some(action) {
                return Err(FirstRunTransitionError::ReadyActionMismatch);
            }
            next.ready = ReadyState::Started(action);
        }
        _ => return Err(FirstRunTransitionError::WrongPosition { position }),
    }
    Ok(next)
}

fn validate_game_choice(
    checkpoint: &FirstRunCheckpoint,
    choice: &GameChoice,
) -> Result<(), FirstRunTransitionError> {
    let GameChoice::Existing { path, state } = choice else {
        return Ok(());
    };
    let Some(candidate) = checkpoint
        .game_candidates
        .iter()
        .find(|candidate| candidate.path == *path)
    else {
        return Err(FirstRunTransitionError::UnknownGameCandidate { path: path.clone() });
    };
    let matches = match (&candidate.state, state) {
        (GameCandidateState::Current { .. }, ExistingGameState::Current) => true,
        (
            GameCandidateState::NeedsUpdate(candidate_patches),
            ExistingGameState::NeedsUpdate(selected_patches),
        ) => candidate_patches == selected_patches,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(FirstRunTransitionError::UnusableGameCandidate { path: path.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legibility() -> LegibilityReading {
        LegibilityReading {
            gpu: Some("Example GPU".to_owned()),
            driver: Some("1.2.3".to_owned()),
            session: SessionType::Wayland,
            render_tier: 0,
        }
    }

    fn account() -> AccountChoice {
        AccountChoice {
            square_enix_id: "meteor".to_owned(),
            kind: FirstRunAccountKind::Standard,
            never_save_password: true,
            steam_client: SteamClientReading::NotRequired,
        }
    }

    fn runner() -> RunnerAndPrefixChoice {
        RunnerAndPrefixChoice {
            runner: FirstRunRunnerSelection::Managed {
                name: "example".to_owned(),
                version: "1".to_owned(),
            },
            prefix: PrefixOutcome::Ready,
        }
    }

    fn runner_reading() -> RunnerReading {
        let choice = runner();
        RunnerReading {
            selection: choice.runner,
            version: Some("1".to_owned()),
            recommended: true,
            available: true,
        }
    }

    fn through_account() -> FirstRunCheckpoint {
        FirstRunCheckpoint {
            legibility: Some(legibility()),
            import: ImportState::NoneFound,
            account: Some(account()),
            ..FirstRunCheckpoint::default()
        }
    }

    fn through_runner(game: GameChoice) -> FirstRunCheckpoint {
        FirstRunCheckpoint {
            game: Some(game),
            credential: Some(CredentialChoice::DoNotSave),
            runner_and_prefix: Some(runner()),
            ..through_account()
        }
    }

    #[test]
    fn default_checkpoint_starts_at_legibility() {
        assert_eq!(
            first_incomplete(&FirstRunCheckpoint::default()),
            FirstRunPosition::Step(FirstRunStep::Legibility)
        );
    }

    #[test]
    fn import_discovery_is_waited_for_and_an_empty_result_skips_the_step() {
        let after_legibility = transition(
            &FirstRunCheckpoint::default(),
            FirstRunTransition::ConfirmLegibility(legibility()),
        )
        .expect("legibility transition");
        assert_eq!(
            first_incomplete(&after_legibility),
            FirstRunPosition::WaitingForImportDiscovery
        );

        let after_discovery = transition(
            &after_legibility,
            FirstRunTransition::RecordImportDiscovery(Vec::new()),
        )
        .expect("discovery transition");
        assert_eq!(
            first_incomplete(&after_discovery),
            FirstRunPosition::Step(FirstRunStep::Account)
        );
    }

    #[test]
    fn found_import_requires_a_decision_and_rejects_an_unknown_path() {
        let candidate = FirstRunImportCandidate {
            path: PathBuf::from("known"),
            source: FirstRunImportSource::Core,
        };
        let mut checkpoint = FirstRunCheckpoint {
            legibility: Some(legibility()),
            import: ImportState::Candidates(vec![candidate]),
            ..FirstRunCheckpoint::default()
        };
        assert_eq!(
            first_incomplete(&checkpoint),
            FirstRunPosition::Step(FirstRunStep::Import)
        );
        assert_eq!(
            transition(
                &checkpoint,
                FirstRunTransition::DecideImport(ImportDecision::Import(PathBuf::from("other")))
            ),
            Err(FirstRunTransitionError::UnknownImportCandidate {
                path: PathBuf::from("other")
            })
        );

        checkpoint = transition(
            &checkpoint,
            FirstRunTransition::DecideImport(ImportDecision::Skip),
        )
        .expect("skip transition");
        assert_eq!(
            first_incomplete(&checkpoint),
            FirstRunPosition::Step(FirstRunStep::Account)
        );
    }

    #[test]
    fn resume_always_selects_the_first_incomplete_required_step() {
        let mut checkpoint = through_account();
        assert_eq!(
            first_incomplete(&checkpoint),
            FirstRunPosition::Step(FirstRunStep::Game)
        );
        checkpoint.game = Some(GameChoice::Existing {
            path: PathBuf::from("game"),
            state: ExistingGameState::Current,
        });
        assert_eq!(
            first_incomplete(&checkpoint),
            FirstRunPosition::Step(FirstRunStep::CredentialBackend)
        );
        checkpoint.credential = Some(CredentialChoice::DoNotSave);
        assert_eq!(
            first_incomplete(&checkpoint),
            FirstRunPosition::Step(FirstRunStep::RunnerAndPrefix)
        );
        checkpoint.runner_and_prefix = Some(runner());
        assert_eq!(
            first_incomplete(&checkpoint),
            FirstRunPosition::Step(FirstRunStep::Ready)
        );
    }

    #[test]
    fn steam_without_a_client_is_typed_and_does_not_block_account_completion() {
        let checkpoint = FirstRunCheckpoint {
            legibility: Some(legibility()),
            import: ImportState::NoneFound,
            ..FirstRunCheckpoint::default()
        };
        let steam = AccountChoice {
            kind: FirstRunAccountKind::Steam,
            steam_client: SteamClientReading::Missing,
            ..account()
        };
        let next = transition(&checkpoint, FirstRunTransition::SaveAccount(steam.clone()))
            .expect("account transition");
        assert_eq!(next.account, Some(steam));
        assert_eq!(
            first_incomplete(&next),
            FirstRunPosition::Step(FirstRunStep::Game)
        );
    }

    #[test]
    fn candidate_failures_are_data_and_do_not_complete_game_selection() {
        let checkpoint = through_account();
        let next = transition(
            &checkpoint,
            FirstRunTransition::RecordGameCandidates(vec![GameCandidate {
                path: PathBuf::from("empty"),
                state: GameCandidateState::NotAGame,
            }]),
        )
        .expect("candidate transition");
        assert_eq!(next.game_candidates[0].state, GameCandidateState::NotAGame);
        assert_eq!(
            first_incomplete(&next),
            FirstRunPosition::Step(FirstRunStep::Game)
        );
    }

    #[test]
    fn a_failed_prefix_can_continue_in_a_known_degraded_state() {
        let mut checkpoint = through_account();
        checkpoint.game = Some(GameChoice::Existing {
            path: PathBuf::from("game"),
            state: ExistingGameState::Current,
        });
        checkpoint.credential = Some(CredentialChoice::DoNotSave);
        checkpoint.runners = vec![RunnerReading {
            selection: FirstRunRunnerSelection::SystemWine {
                version: Some("10.0".to_owned()),
            },
            version: Some("10.0".to_owned()),
            recommended: false,
            available: true,
        }];
        let choice = RunnerAndPrefixChoice {
            runner: FirstRunRunnerSelection::SystemWine {
                version: Some("10.0".to_owned()),
            },
            prefix: PrefixOutcome::ContinueWithoutPrefix {
                code: "prefix-create-failed".to_owned(),
            },
        };
        let next = transition(
            &checkpoint,
            FirstRunTransition::FinishRunnerAndPrefix(choice.clone()),
        )
        .expect("prefix transition");
        assert_eq!(next.runner_and_prefix, Some(choice));
        assert_eq!(
            first_incomplete(&next),
            FirstRunPosition::Step(FirstRunStep::Ready)
        );
    }

    #[test]
    fn existing_game_selection_must_match_a_verified_candidate() {
        let checkpoint = through_account();
        let choice = GameChoice::Existing {
            path: PathBuf::from("unknown"),
            state: ExistingGameState::Current,
        };
        assert_eq!(
            transition(&checkpoint, FirstRunTransition::SelectGame(choice)),
            Err(FirstRunTransitionError::UnknownGameCandidate {
                path: PathBuf::from("unknown")
            })
        );

        let checkpoint = FirstRunCheckpoint {
            game_candidates: vec![GameCandidate {
                path: PathBuf::from("empty"),
                state: GameCandidateState::NotAGame,
            }],
            ..through_account()
        };
        assert_eq!(
            transition(
                &checkpoint,
                FirstRunTransition::SelectGame(GameChoice::Existing {
                    path: PathBuf::from("empty"),
                    state: ExistingGameState::Current,
                })
            ),
            Err(FirstRunTransitionError::UnusableGameCandidate {
                path: PathBuf::from("empty")
            })
        );
    }

    #[test]
    fn unavailable_credentials_and_runners_cannot_complete_their_steps() {
        let mut checkpoint = through_account();
        checkpoint.game = Some(GameChoice::Install {
            path: PathBuf::from("new"),
            approximate_bytes: 100,
            exact_download_bytes: 90,
        });
        checkpoint.credential_backends = vec![CredentialBackendReading {
            backend: CredentialBackend::SecretService,
            state: CredentialBackendState::Unavailable {
                code: "locked".to_owned(),
            },
        }];
        assert_eq!(
            transition(
                &checkpoint,
                FirstRunTransition::SelectCredential(CredentialChoice::SaveIn(
                    CredentialBackend::SecretService
                ))
            ),
            Err(FirstRunTransitionError::CredentialBackendNotReady {
                backend: CredentialBackend::SecretService
            })
        );

        checkpoint.credential = Some(CredentialChoice::DoNotSave);
        checkpoint.runners = vec![RunnerReading {
            available: false,
            ..runner_reading()
        }];
        let runner = runner();
        assert_eq!(
            transition(
                &checkpoint,
                FirstRunTransition::FinishRunnerAndPrefix(runner.clone())
            ),
            Err(FirstRunTransitionError::RunnerNotAvailable {
                runner: runner.runner
            })
        );
    }

    #[test]
    fn ready_action_is_derived_for_all_game_states() {
        let current = through_runner(GameChoice::Existing {
            path: PathBuf::from("current"),
            state: ExistingGameState::Current,
        });
        let patches = PatchReading {
            count: 7,
            bytes: 4_200,
        };
        let update = through_runner(GameChoice::Existing {
            path: PathBuf::from("old"),
            state: ExistingGameState::NeedsUpdate(patches),
        });
        let install = through_runner(GameChoice::Install {
            path: PathBuf::from("new"),
            approximate_bytes: 100_000,
            exact_download_bytes: 91_000,
        });

        assert_eq!(ready_action(&current), Some(ReadyAction::Play));
        assert_eq!(
            ready_action(&update),
            Some(ReadyAction::UpdateAndPlay(patches))
        );
        assert_eq!(
            ready_action(&install),
            Some(ReadyAction::InstallAndPlay { bytes: 91_000 })
        );
    }

    #[test]
    fn ready_transition_rejects_a_shell_selected_action() {
        let checkpoint = through_runner(GameChoice::Existing {
            path: PathBuf::from("game"),
            state: ExistingGameState::Current,
        });
        assert_eq!(
            transition(
                &checkpoint,
                FirstRunTransition::StartReady(ReadyAction::InstallAndPlay { bytes: 1 })
            ),
            Err(FirstRunTransitionError::ReadyActionMismatch)
        );

        let complete = transition(
            &checkpoint,
            FirstRunTransition::StartReady(ReadyAction::Play),
        )
        .expect("ready transition");
        assert_eq!(first_incomplete(&complete), FirstRunPosition::Complete);
    }

    #[test]
    fn later_transitions_cannot_bypass_an_incomplete_step() {
        let checkpoint = FirstRunCheckpoint::default();
        assert_eq!(
            transition(
                &checkpoint,
                FirstRunTransition::SelectCredential(CredentialChoice::DoNotSave)
            ),
            Err(FirstRunTransitionError::WrongPosition {
                position: FirstRunPosition::Step(FirstRunStep::Legibility)
            })
        );
    }

    #[test]
    fn checkpoint_round_trip_preserves_the_resume_position() {
        let checkpoint = through_runner(GameChoice::Existing {
            path: PathBuf::from("game"),
            state: ExistingGameState::Current,
        });
        let encoded = serde_json::to_vec(&checkpoint).expect("serialize checkpoint");
        let decoded: FirstRunCheckpoint =
            serde_json::from_slice(&encoded).expect("deserialize checkpoint");
        assert_eq!(decoded, checkpoint);
        assert_eq!(
            first_incomplete(&decoded),
            FirstRunPosition::Step(FirstRunStep::Ready)
        );
    }
}
