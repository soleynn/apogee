#![forbid(unsafe_code)]
//! The launcher core: the composition root that owns the domain model, versioned persistence, and
//! the command/event surface the shells drive.
//!
//! This is the only crate permitted to see every subsystem. It constructs each once, injects it,
//! owns the concrete network transport, and exposes a single [`Core::execute`] surface that yields
//! a stream of [`Event`]s. Profiles and settings persist through a versioned store that migrates
//! forward and never deletes on a load failure. Login-to-play is orchestrated entirely behind the
//! command surface, including credential resolution, patching, launch, and terminal outcomes.

mod addons;
mod backup;
mod code;
mod command;
mod composition;
mod error;
mod first_run;
mod flow;
mod frontier;
mod host;
mod launch;
mod model;
mod patch;
mod redirect;
mod setup;
mod status;
mod steam;
mod store;
mod support;
mod transport;
mod trust;
mod xiv_import;

pub use apogee_addons::backup::{ArchiveRecord, BackupReport, PruneReport};
pub use apogee_addons::backup::{RestoreReport, RestoredRoot};
// Under its own name: the addon layer already has a public `AddonOutcome`, and re-exporting a second,
// different type under that name gives a shell two things it cannot tell apart from the import alone.
pub use apogee_addons::{
    AddonEvent, ExternalAddon, ExternalAddonProblem, Outcome, RunIn, SetupEvent, Trigger,
};
// Three names only: a shell chooses where a code comes from, renders what an imported secret will not
// be accepted for, and says that the user asked for a port on their network to be opened. The handle,
// the profile, the code, the clock offset, the listener and its configuration all stay behind the
// core, which is why the pushed-code source carries no payload.
pub use apogee_fetch::Recoveries;
pub use apogee_otp::{Deviation, ListenerConsent, OtpSource};
// `Repo` rides along because `Command::Repair`'s local-index overrides are keyed by it: a shell
// naming a repo must be able to name the type without depending on `apogee-patcher` itself.
pub use apogee_patcher::{PatchProgress, PreflightError, Repo};
pub use apogee_runtime::{
    BenchError, BenchStats, CatalogViewEntry, FrameLog, Gamescope, GpuSelect, HealthIssue, Hud,
    PrefixHealth, ProgramStatus, SyncChoice, SyncStatus,
};
#[cfg(unix)]
pub use apogee_runtime::{
    CompatTool, CompatToolInstall, DeckModel, HostIdentity, SteamInstall, installed_compat_tool,
    remove_compat_tool, steam_installs,
};
pub use apogee_secrets::{
    Backend, BackendReport, BackendState, Consent, EncryptedFile, FileState,
    ForeignCredentialStore, ForeignKey, ForeignSecretsFile, Import, ImportSource, KdfCost,
    Passphrase, Sandbox, Secret, SecretKind, SecretStore, Secrets, SecretsError, Unprompted,
};
pub use code::{ALL_CODES, StableCode};
pub use command::{
    BannerData, Command, Event, FirstRunRequest, FlowState, FrontierData, FrontierQuery, GateData,
    ImportData, ImportXivLauncher, LaunchProgramExit, NewsData, NewsRow, Notice, PasswordSource,
    PrefixAction, PrefixReport, Progress, RunOutcome, SupportBundleData,
};
pub use composition::{
    Core, CoreConfig, Defaults, ImportOutcome, ProfileRemoval, ProfileRemovalPlan, SecretSweep,
};
pub use error::CoreError;
pub use first_run::{
    AccountChoice, CredentialBackend, CredentialBackendReading, CredentialBackendState,
    CredentialChoice, ExistingGameState, FirstRunAccountKind, FirstRunCheckpoint,
    FirstRunImportCandidate, FirstRunImportSource, FirstRunPosition, FirstRunRunnerSelection,
    FirstRunStep, FirstRunTransition, FirstRunTransitionError, GameCandidate, GameCandidateState,
    GameChoice, ImportDecision, ImportState, LegibilityReading, PatchReading, PrefixOutcome,
    ReadyAction, ReadyState, RunnerAndPrefixChoice, RunnerReading, SessionType, SteamClientReading,
    first_incomplete, ready_action,
};
pub use model::{
    Account, AccountKind, LaunchSettings, ListenerSettings, ListenerSources, OtpDelivery,
    PrefixSelection, Profile, Region, RunnerSelection, STEAM_APP_ID, STEAM_FREE_TRIAL_APP_ID,
    SecretBackend, Settings,
};
pub use setup::{Provenance, ResolvedSetup, SetupValue};
pub use sqex_proto::Transport;
pub use status::{NextAction, NextCommand, NextVerb, PendingReading};
pub use store::StoreError;
pub use support::{
    BundlePart, CallerFactName, DiagnosticRecord, SupportArchive, SupportError, SystemReportInput,
    ValidatedCallerFacts, assemble_support_archive, encode_support_bundle, support_bundle_contents,
    system_report, write_support_bundle,
};
pub use uuid::Uuid;
pub use xiv_import::{
    AppliedFinding, ImportApplyReport, ImportCandidate, ImportEnvironment, ImportFinding,
    ImportFindingId, ImportFindingResult, ImportFingerprint, ImportIssue, ImportLocation,
    ImportPlan, ImportScan, ImportWrite, XivImportError,
    candidate_roots as xivlauncher_candidate_roots, scan as scan_xivlauncher,
};
