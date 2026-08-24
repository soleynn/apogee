//! Persisted first-run state in the shell-owned wire format.

use apogee_core::{
    AccountChoice, CredentialBackend, CredentialBackendReading, CredentialBackendState,
    CredentialChoice, ExistingGameState, FirstRunAccountKind, FirstRunCheckpoint,
    FirstRunImportCandidate, FirstRunImportSource, FirstRunRunnerSelection, GameCandidate,
    GameCandidateState, GameChoice, ImportDecision, ImportState, LegibilityReading, PatchReading,
    PrefixOutcome, ReadyAction, ReadyState, RunnerAndPrefixChoice, RunnerReading, SessionType,
    SteamClientReading,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::path::PathDto;

/// Everything needed to resume or render initial setup.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirstRunDto {
    legibility: Option<LegibilityDto>,
    import: ImportStateDto,
    account: Option<AccountChoiceDto>,
    game_candidates: Vec<GameCandidateDto>,
    game: Option<GameChoiceDto>,
    credential_backends: Vec<CredentialBackendReadingDto>,
    credential: Option<CredentialChoiceDto>,
    runners: Vec<RunnerReadingDto>,
    runner_and_prefix: Option<RunnerAndPrefixChoiceDto>,
    ready: ReadyStateDto,
}

impl From<&FirstRunCheckpoint> for FirstRunDto {
    fn from(checkpoint: &FirstRunCheckpoint) -> Self {
        Self {
            legibility: checkpoint.legibility.as_ref().map(LegibilityDto::from),
            import: ImportStateDto::from(&checkpoint.import),
            account: checkpoint.account.as_ref().map(AccountChoiceDto::from),
            game_candidates: checkpoint
                .game_candidates
                .iter()
                .map(GameCandidateDto::from)
                .collect(),
            game: checkpoint.game.as_ref().map(GameChoiceDto::from),
            credential_backends: checkpoint
                .credential_backends
                .iter()
                .map(CredentialBackendReadingDto::from)
                .collect(),
            credential: checkpoint
                .credential
                .as_ref()
                .map(CredentialChoiceDto::from),
            runners: checkpoint
                .runners
                .iter()
                .map(RunnerReadingDto::from)
                .collect(),
            runner_and_prefix: checkpoint
                .runner_and_prefix
                .as_ref()
                .map(RunnerAndPrefixChoiceDto::from),
            ready: ReadyStateDto::from(&checkpoint.ready),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegibilityDto {
    gpu: Option<String>,
    driver: Option<String>,
    session: SessionTypeDto,
    render_tier: u8,
}

impl From<&LegibilityReading> for LegibilityDto {
    fn from(reading: &LegibilityReading) -> Self {
        Self {
            gpu: reading.gpu.clone(),
            driver: reading.driver.clone(),
            session: SessionTypeDto::from(reading.session),
            render_tier: reading.render_tier,
        }
    }
}

impl LegibilityDto {
    pub(crate) fn into_core(self) -> Option<LegibilityReading> {
        Some(LegibilityReading {
            gpu: self.gpu,
            driver: self.driver,
            session: self.session.into_core()?,
            render_tier: self.render_tier,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub(super) enum SessionTypeDto {
    Wayland,
    X11,
    Windows,
    Unknown,
}

impl From<SessionType> for SessionTypeDto {
    fn from(session: SessionType) -> Self {
        match session {
            SessionType::Wayland => Self::Wayland,
            SessionType::X11 => Self::X11,
            SessionType::Windows => Self::Windows,
            SessionType::Unknown => Self::Unknown,
            _ => Self::Unknown,
        }
    }
}

impl SessionTypeDto {
    fn into_core(self) -> Option<SessionType> {
        match self {
            Self::Wayland => Some(SessionType::Wayland),
            Self::X11 => Some(SessionType::X11),
            Self::Windows => Some(SessionType::Windows),
            Self::Unknown => Some(SessionType::Unknown),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum ImportStateDto {
    DiscoveryPending,
    NoneFound,
    Candidates(Vec<FirstRunImportCandidateDto>),
    Complete(ImportDecisionDto),
    Unknown,
}

impl From<&ImportState> for ImportStateDto {
    fn from(state: &ImportState) -> Self {
        match state {
            ImportState::DiscoveryPending => Self::DiscoveryPending,
            ImportState::NoneFound => Self::NoneFound,
            ImportState::Candidates(candidates) => Self::Candidates(
                candidates
                    .iter()
                    .map(FirstRunImportCandidateDto::from)
                    .collect(),
            ),
            ImportState::Complete(decision) => Self::Complete(ImportDecisionDto::from(decision)),
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirstRunImportCandidateDto {
    path: PathDto,
    source: FirstRunImportSourceDto,
}

impl From<&FirstRunImportCandidate> for FirstRunImportCandidateDto {
    fn from(candidate: &FirstRunImportCandidate) -> Self {
        Self {
            path: PathDto::from(candidate.path.as_path()),
            source: FirstRunImportSourceDto::from(candidate.source),
        }
    }
}

impl FirstRunImportCandidateDto {
    pub(crate) fn into_core(self) -> Option<FirstRunImportCandidate> {
        Some(FirstRunImportCandidate {
            path: self.path.into_path().ok()?,
            source: self.source.into_core()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub(super) enum FirstRunImportSourceDto {
    Native,
    Core,
    Flatpak,
    Unknown,
}

impl From<FirstRunImportSource> for FirstRunImportSourceDto {
    fn from(source: FirstRunImportSource) -> Self {
        match source {
            FirstRunImportSource::Native => Self::Native,
            FirstRunImportSource::Core => Self::Core,
            FirstRunImportSource::Flatpak => Self::Flatpak,
            _ => Self::Unknown,
        }
    }
}

impl FirstRunImportSourceDto {
    fn into_core(self) -> Option<FirstRunImportSource> {
        match self {
            Self::Native => Some(FirstRunImportSource::Native),
            Self::Core => Some(FirstRunImportSource::Core),
            Self::Flatpak => Some(FirstRunImportSource::Flatpak),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "choice",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum ImportDecisionDto {
    Import(PathDto),
    Skip,
    Unknown,
}

impl From<&ImportDecision> for ImportDecisionDto {
    fn from(decision: &ImportDecision) -> Self {
        match decision {
            ImportDecision::Import(path) => Self::Import(PathDto::from(path.as_path())),
            ImportDecision::Skip => Self::Skip,
            _ => Self::Unknown,
        }
    }
}

impl ImportDecisionDto {
    pub(crate) fn into_core(self) -> Option<ImportDecision> {
        match self {
            Self::Import(path) => Some(ImportDecision::Import(path.into_path().ok()?)),
            Self::Skip => Some(ImportDecision::Skip),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountChoiceDto {
    square_enix_id: String,
    kind: FirstRunAccountKindDto,
    never_save_password: bool,
    steam_client: SteamClientReadingDto,
}

impl From<&AccountChoice> for AccountChoiceDto {
    fn from(choice: &AccountChoice) -> Self {
        Self {
            square_enix_id: choice.square_enix_id.clone(),
            kind: FirstRunAccountKindDto::from(choice.kind),
            never_save_password: choice.never_save_password,
            steam_client: SteamClientReadingDto::from(choice.steam_client),
        }
    }
}

impl AccountChoiceDto {
    pub(crate) fn into_core(self) -> Option<AccountChoice> {
        Some(AccountChoice {
            square_enix_id: self.square_enix_id,
            kind: self.kind.into_core()?,
            never_save_password: self.never_save_password,
            steam_client: self.steam_client.into_core()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub(super) enum FirstRunAccountKindDto {
    Standard,
    Steam,
    FreeTrial,
    Unknown,
}

impl From<FirstRunAccountKind> for FirstRunAccountKindDto {
    fn from(kind: FirstRunAccountKind) -> Self {
        match kind {
            FirstRunAccountKind::Standard => Self::Standard,
            FirstRunAccountKind::Steam => Self::Steam,
            FirstRunAccountKind::FreeTrial => Self::FreeTrial,
            _ => Self::Unknown,
        }
    }
}

impl FirstRunAccountKindDto {
    fn into_core(self) -> Option<FirstRunAccountKind> {
        match self {
            Self::Standard => Some(FirstRunAccountKind::Standard),
            Self::Steam => Some(FirstRunAccountKind::Steam),
            Self::FreeTrial => Some(FirstRunAccountKind::FreeTrial),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub(super) enum SteamClientReadingDto {
    Present,
    Missing,
    NotRequired,
    Unknown,
}

impl From<SteamClientReading> for SteamClientReadingDto {
    fn from(reading: SteamClientReading) -> Self {
        match reading {
            SteamClientReading::Present => Self::Present,
            SteamClientReading::Missing => Self::Missing,
            SteamClientReading::NotRequired => Self::NotRequired,
            _ => Self::Unknown,
        }
    }
}

impl SteamClientReadingDto {
    fn into_core(self) -> Option<SteamClientReading> {
        match self {
            Self::Present => Some(SteamClientReading::Present),
            Self::Missing => Some(SteamClientReading::Missing),
            Self::NotRequired => Some(SteamClientReading::NotRequired),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GameCandidateDto {
    path: PathDto,
    state: GameCandidateStateDto,
}

impl From<&GameCandidate> for GameCandidateDto {
    fn from(candidate: &GameCandidate) -> Self {
        Self {
            path: PathDto::from(candidate.path.as_path()),
            state: GameCandidateStateDto::from(&candidate.state),
        }
    }
}

impl GameCandidateDto {
    pub(crate) fn into_core(self) -> Option<GameCandidate> {
        Some(GameCandidate {
            path: self.path.into_path().ok()?,
            state: self.state.into_core()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum GameCandidateStateDto {
    Current { installed_bytes: u64 },
    NeedsUpdate(PatchReadingDto),
    NotAGame,
    Unreadable { code: String },
    Unknown,
}

impl From<&GameCandidateState> for GameCandidateStateDto {
    fn from(state: &GameCandidateState) -> Self {
        match state {
            GameCandidateState::Current { installed_bytes } => Self::Current {
                installed_bytes: *installed_bytes,
            },
            GameCandidateState::NeedsUpdate(reading) => {
                Self::NeedsUpdate(PatchReadingDto::from(*reading))
            }
            GameCandidateState::NotAGame => Self::NotAGame,
            GameCandidateState::Unreadable { code } => Self::Unreadable { code: code.clone() },
            _ => Self::Unknown,
        }
    }
}

impl GameCandidateStateDto {
    fn into_core(self) -> Option<GameCandidateState> {
        match self {
            Self::Current { installed_bytes } => {
                Some(GameCandidateState::Current { installed_bytes })
            }
            Self::NeedsUpdate(reading) => {
                Some(GameCandidateState::NeedsUpdate(reading.into_core()))
            }
            Self::NotAGame => Some(GameCandidateState::NotAGame),
            Self::Unreadable { code } => Some(GameCandidateState::Unreadable { code }),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PatchReadingDto {
    count: u32,
    bytes: u64,
}

impl From<PatchReading> for PatchReadingDto {
    fn from(reading: PatchReading) -> Self {
        Self {
            count: reading.count,
            bytes: reading.bytes,
        }
    }
}

impl PatchReadingDto {
    fn into_core(self) -> PatchReading {
        PatchReading {
            count: self.count,
            bytes: self.bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "choice",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum GameChoiceDto {
    Existing {
        path: PathDto,
        state: ExistingGameStateDto,
    },
    Install {
        path: PathDto,
        approximate_bytes: u64,
        exact_download_bytes: u64,
    },
    Unknown,
}

impl From<&GameChoice> for GameChoiceDto {
    fn from(choice: &GameChoice) -> Self {
        match choice {
            GameChoice::Existing { path, state } => Self::Existing {
                path: PathDto::from(path.as_path()),
                state: ExistingGameStateDto::from(*state),
            },
            GameChoice::Install {
                path,
                approximate_bytes,
                exact_download_bytes,
            } => Self::Install {
                path: PathDto::from(path.as_path()),
                approximate_bytes: *approximate_bytes,
                exact_download_bytes: *exact_download_bytes,
            },
            _ => Self::Unknown,
        }
    }
}

impl GameChoiceDto {
    pub(crate) fn into_core(self) -> Option<GameChoice> {
        match self {
            Self::Existing { path, state } => Some(GameChoice::Existing {
                path: path.into_path().ok()?,
                state: state.into_core()?,
            }),
            Self::Install {
                path,
                approximate_bytes,
                exact_download_bytes,
            } => Some(GameChoice::Install {
                path: path.into_path().ok()?,
                approximate_bytes,
                exact_download_bytes,
            }),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum ExistingGameStateDto {
    Current,
    NeedsUpdate(PatchReadingDto),
    Unknown,
}

impl From<ExistingGameState> for ExistingGameStateDto {
    fn from(state: ExistingGameState) -> Self {
        match state {
            ExistingGameState::Current => Self::Current,
            ExistingGameState::NeedsUpdate(reading) => {
                Self::NeedsUpdate(PatchReadingDto::from(reading))
            }
            _ => Self::Unknown,
        }
    }
}

impl ExistingGameStateDto {
    fn into_core(self) -> Option<ExistingGameState> {
        match self {
            Self::Current => Some(ExistingGameState::Current),
            Self::NeedsUpdate(reading) => Some(ExistingGameState::NeedsUpdate(reading.into_core())),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialBackendReadingDto {
    backend: CredentialBackendDto,
    state: CredentialBackendStateDto,
}

impl From<&CredentialBackendReading> for CredentialBackendReadingDto {
    fn from(reading: &CredentialBackendReading) -> Self {
        Self {
            backend: CredentialBackendDto::from(reading.backend),
            state: CredentialBackendStateDto::from(&reading.state),
        }
    }
}

impl CredentialBackendReadingDto {
    pub(crate) fn into_core(self) -> Option<CredentialBackendReading> {
        Some(CredentialBackendReading {
            backend: self.backend.into_core()?,
            state: self.state.into_core()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub(crate) enum CredentialBackendDto {
    SecretService,
    EncryptedFile,
    WindowsCredentialManager,
    Unknown,
}

impl From<CredentialBackend> for CredentialBackendDto {
    fn from(backend: CredentialBackend) -> Self {
        match backend {
            CredentialBackend::SecretService => Self::SecretService,
            CredentialBackend::EncryptedFile => Self::EncryptedFile,
            CredentialBackend::WindowsCredentialManager => Self::WindowsCredentialManager,
            _ => Self::Unknown,
        }
    }
}

impl CredentialBackendDto {
    fn into_core(self) -> Option<CredentialBackend> {
        match self {
            Self::SecretService => Some(CredentialBackend::SecretService),
            Self::EncryptedFile => Some(CredentialBackend::EncryptedFile),
            Self::WindowsCredentialManager => Some(CredentialBackend::WindowsCredentialManager),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum CredentialBackendStateDto {
    Ready,
    NeedsPassphrase,
    Unavailable { code: String },
    Unknown,
}

impl From<&CredentialBackendState> for CredentialBackendStateDto {
    fn from(state: &CredentialBackendState) -> Self {
        match state {
            CredentialBackendState::Ready => Self::Ready,
            CredentialBackendState::NeedsPassphrase => Self::NeedsPassphrase,
            CredentialBackendState::Unavailable { code } => {
                Self::Unavailable { code: code.clone() }
            }
            _ => Self::Unknown,
        }
    }
}

impl CredentialBackendStateDto {
    fn into_core(self) -> Option<CredentialBackendState> {
        match self {
            Self::Ready => Some(CredentialBackendState::Ready),
            Self::NeedsPassphrase => Some(CredentialBackendState::NeedsPassphrase),
            Self::Unavailable { code } => Some(CredentialBackendState::Unavailable { code }),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "choice",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum CredentialChoiceDto {
    SaveIn(CredentialBackendDto),
    DoNotSave,
    Unknown,
}

impl From<&CredentialChoice> for CredentialChoiceDto {
    fn from(choice: &CredentialChoice) -> Self {
        match choice {
            CredentialChoice::SaveIn(backend) => Self::SaveIn(CredentialBackendDto::from(*backend)),
            CredentialChoice::DoNotSave => Self::DoNotSave,
            _ => Self::Unknown,
        }
    }
}

impl CredentialChoiceDto {
    pub(crate) fn into_core(self) -> Option<CredentialChoice> {
        match self {
            Self::SaveIn(backend) => Some(CredentialChoice::SaveIn(backend.into_core()?)),
            Self::DoNotSave => Some(CredentialChoice::DoNotSave),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunnerReadingDto {
    selection: FirstRunRunnerSelectionDto,
    version: Option<String>,
    recommended: bool,
    available: bool,
}

impl From<&RunnerReading> for RunnerReadingDto {
    fn from(reading: &RunnerReading) -> Self {
        Self {
            selection: FirstRunRunnerSelectionDto::from(&reading.selection),
            version: reading.version.clone(),
            recommended: reading.recommended,
            available: reading.available,
        }
    }
}

impl RunnerReadingDto {
    pub(crate) fn into_core(self) -> Option<RunnerReading> {
        Some(RunnerReading {
            selection: self.selection.into_core()?,
            version: self.version,
            recommended: self.recommended,
            available: self.available,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum FirstRunRunnerSelectionDto {
    Managed { name: String, version: String },
    SystemWine { version: Option<String> },
    Unknown,
}

impl From<&FirstRunRunnerSelection> for FirstRunRunnerSelectionDto {
    fn from(selection: &FirstRunRunnerSelection) -> Self {
        match selection {
            FirstRunRunnerSelection::Managed { name, version } => Self::Managed {
                name: name.clone(),
                version: version.clone(),
            },
            FirstRunRunnerSelection::SystemWine { version } => Self::SystemWine {
                version: version.clone(),
            },
            _ => Self::Unknown,
        }
    }
}

impl FirstRunRunnerSelectionDto {
    fn into_core(self) -> Option<FirstRunRunnerSelection> {
        match self {
            Self::Managed { name, version } => {
                Some(FirstRunRunnerSelection::Managed { name, version })
            }
            Self::SystemWine { version } => Some(FirstRunRunnerSelection::SystemWine { version }),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunnerAndPrefixChoiceDto {
    runner: FirstRunRunnerSelectionDto,
    prefix: PrefixOutcomeDto,
}

impl From<&RunnerAndPrefixChoice> for RunnerAndPrefixChoiceDto {
    fn from(choice: &RunnerAndPrefixChoice) -> Self {
        Self {
            runner: FirstRunRunnerSelectionDto::from(&choice.runner),
            prefix: PrefixOutcomeDto::from(&choice.prefix),
        }
    }
}

impl RunnerAndPrefixChoiceDto {
    pub(crate) fn into_core(self) -> Option<RunnerAndPrefixChoice> {
        Some(RunnerAndPrefixChoice {
            runner: self.runner.into_core()?,
            prefix: self.prefix.into_core()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum PrefixOutcomeDto {
    Ready,
    ContinueWithoutPrefix { code: String },
    Unknown,
}

impl From<&PrefixOutcome> for PrefixOutcomeDto {
    fn from(outcome: &PrefixOutcome) -> Self {
        match outcome {
            PrefixOutcome::Ready => Self::Ready,
            PrefixOutcome::ContinueWithoutPrefix { code } => {
                Self::ContinueWithoutPrefix { code: code.clone() }
            }
            _ => Self::Unknown,
        }
    }
}

impl PrefixOutcomeDto {
    fn into_core(self) -> Option<PrefixOutcome> {
        match self {
            Self::Ready => Some(PrefixOutcome::Ready),
            Self::ContinueWithoutPrefix { code } => {
                Some(PrefixOutcome::ContinueWithoutPrefix { code })
            }
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(super) enum ReadyStateDto {
    Pending,
    Started(ReadyActionDto),
    Unknown,
}

impl From<&ReadyState> for ReadyStateDto {
    fn from(state: &ReadyState) -> Self {
        match state {
            ReadyState::Pending => Self::Pending,
            ReadyState::Started(action) => Self::Started(ReadyActionDto::from(*action)),
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(
    tag = "action",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum ReadyActionDto {
    Play,
    UpdateAndPlay(PatchReadingDto),
    InstallAndPlay { bytes: u64 },
    Unknown,
}

impl From<ReadyAction> for ReadyActionDto {
    fn from(action: ReadyAction) -> Self {
        match action {
            ReadyAction::Play => Self::Play,
            ReadyAction::UpdateAndPlay(reading) => {
                Self::UpdateAndPlay(PatchReadingDto::from(reading))
            }
            ReadyAction::InstallAndPlay { bytes } => Self::InstallAndPlay { bytes },
            _ => Self::Unknown,
        }
    }
}

impl ReadyActionDto {
    pub(crate) fn into_core(self) -> Option<ReadyAction> {
        match self {
            Self::Play => Some(ReadyAction::Play),
            Self::UpdateAndPlay(reading) => Some(ReadyAction::UpdateAndPlay(reading.into_core())),
            Self::InstallAndPlay { bytes } => Some(ReadyAction::InstallAndPlay { bytes }),
            Self::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_checkpoint_keeps_every_pending_state_explicit() {
        let dto = FirstRunDto::from(&FirstRunCheckpoint::default());

        assert_eq!(dto.legibility, None);
        assert_eq!(dto.import, ImportStateDto::DiscoveryPending);
        assert_eq!(dto.ready, ReadyStateDto::Pending);
    }
}
