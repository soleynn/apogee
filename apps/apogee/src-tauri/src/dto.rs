//! Shell-owned serialization of the core event stream.

use std::net::IpAddr;

use apogee_core::{
    AddonEvent, Event, FlowState, Notice, Outcome, PatchProgress, PrefixReport, ProgramStatus,
    Recoveries, Repo, RunOutcome, SetupEvent, StableCode,
};
use serde::Serialize;

/// One frame sent to the webview.
///
/// The stable code is always present. Unknown future variants remain visible as an `unknown` frame
/// instead of disappearing, while errors deliberately cross with no `Display` text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum EventDto {
    State {
        code: &'static str,
        state: StateDto,
    },
    Progress {
        code: &'static str,
        completed: u64,
        total: u64,
        recoveries: RecoveriesDto,
    },
    Patch {
        code: &'static str,
        patch: PatchDto,
    },
    Addon {
        code: &'static str,
        addon: AddonDto,
    },
    Setup {
        code: &'static str,
        setup: SetupDto,
    },
    Frontier {
        code: &'static str,
    },
    Prefix {
        code: &'static str,
        issues: Vec<&'static str>,
        missing_setup: Option<Vec<String>>,
    },
    Notice {
        code: &'static str,
        notice: NoticeDto,
    },
    LaunchProgramExited {
        code: &'static str,
        program: String,
        status: ProgramStatusDto,
    },
    Error {
        code: &'static str,
    },
    Outcome {
        code: &'static str,
        outcome: OutcomeDto,
    },
    Unknown {
        code: &'static str,
    },
}

impl From<&Event> for EventDto {
    fn from(event: &Event) -> Self {
        let code = event.code();
        match event {
            Event::State(state) => Self::State {
                code,
                state: StateDto::from(state),
            },
            Event::Progress(progress) => Self::Progress {
                code,
                completed: progress.completed,
                total: progress.total,
                recoveries: RecoveriesDto::from(progress.recoveries),
            },
            Event::Patch(patch) => Self::Patch {
                code,
                patch: PatchDto::from(patch),
            },
            Event::Addon(addon) => Self::Addon {
                code,
                addon: AddonDto::from(addon),
            },
            Event::Setup(setup) => Self::Setup {
                code,
                setup: SetupDto::from(setup),
            },
            Event::Frontier(_) => Self::Frontier { code },
            Event::Prefix(report) => prefix(code, report),
            Event::Notice(notice) => Self::Notice {
                code,
                notice: NoticeDto::from(notice),
            },
            Event::LaunchProgramExited(exit) => Self::LaunchProgramExited {
                code,
                program: exit.program.clone(),
                status: ProgramStatusDto::from(exit.status),
            },
            Event::Error(_) => Self::Error { code },
            Event::Outcome(outcome) => Self::Outcome {
                code,
                outcome: OutcomeDto::from(*outcome),
            },
            _ => Self::Unknown { code },
        }
    }
}

fn prefix(code: &'static str, report: &PrefixReport) -> EventDto {
    EventDto::Prefix {
        code,
        issues: report.health.issues.iter().map(StableCode::code).collect(),
        missing_setup: report.missing_setup.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum StateDto {
    NeedsPassword,
    NeedsOtp,
    WaitingForOtpWindow { seconds: u64 },
    WaitingForPushedCode { port: u16, seconds: u64 },
    PushedCodeReceived { from: IpAddr },
    NeedsTerms,
    NoService,
    NeedsLogin,
    NeedsBootPatch,
    PatchesPending { count: u32, bytes: u64 },
    VersionNotServiced,
    BackingUp,
    PreparingPrefix,
    Patching,
    Repairing,
    CheckingPrefix,
    NoPrefix,
    FixingPrefix,
    RecreatingPrefix,
    Launching,
    Running,
    SupervisingAddons,
    Exited,
    Cancelled,
    Unknown { code: &'static str },
}

impl From<&FlowState> for StateDto {
    fn from(state: &FlowState) -> Self {
        match state {
            FlowState::NeedsPassword => Self::NeedsPassword,
            FlowState::NeedsOtp => Self::NeedsOtp,
            FlowState::WaitingForOtpWindow { seconds } => {
                Self::WaitingForOtpWindow { seconds: *seconds }
            }
            FlowState::WaitingForPushedCode { port, seconds } => Self::WaitingForPushedCode {
                port: *port,
                seconds: *seconds,
            },
            FlowState::PushedCodeReceived { from } => Self::PushedCodeReceived { from: *from },
            FlowState::NeedsTerms => Self::NeedsTerms,
            FlowState::NoService => Self::NoService,
            FlowState::NeedsLogin => Self::NeedsLogin,
            FlowState::NeedsBootPatch => Self::NeedsBootPatch,
            FlowState::PatchesPending { count, bytes } => Self::PatchesPending {
                count: *count,
                bytes: *bytes,
            },
            FlowState::VersionNotServiced => Self::VersionNotServiced,
            FlowState::BackingUp => Self::BackingUp,
            FlowState::PreparingPrefix => Self::PreparingPrefix,
            FlowState::Patching => Self::Patching,
            FlowState::Repairing => Self::Repairing,
            FlowState::CheckingPrefix => Self::CheckingPrefix,
            FlowState::NoPrefix => Self::NoPrefix,
            FlowState::FixingPrefix => Self::FixingPrefix,
            FlowState::RecreatingPrefix => Self::RecreatingPrefix,
            FlowState::Launching => Self::Launching,
            FlowState::Running => Self::Running,
            FlowState::SupervisingAddons => Self::SupervisingAddons,
            FlowState::Exited => Self::Exited,
            FlowState::Cancelled => Self::Cancelled,
            _ => Self::Unknown { code: state.code() },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveriesDto {
    retries: u32,
    rotations: u32,
    stalls: u32,
    blocks_refetched: u32,
    sources_dropped: u32,
    demoted: bool,
}

impl From<Recoveries> for RecoveriesDto {
    fn from(value: Recoveries) -> Self {
        Self {
            retries: value.retries,
            rotations: value.rotations,
            stalls: value.stalls,
            blocks_refetched: value.blocks_refetched,
            sources_dropped: value.sources_dropped,
            demoted: value.demoted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum PatchDto {
    Downloading {
        repo: String,
        index: u32,
        bytes_done: u64,
        total: Option<u64>,
        recoveries: RecoveriesDto,
    },
    Applying {
        repo: String,
        index: u32,
        bytes_done: u64,
    },
    Applied {
        repo: String,
        index: u32,
        version: String,
    },
    Verifying {
        repo: String,
        attempt: u32,
    },
    Refetching {
        repo: String,
        attempt: u32,
        bytes: u64,
    },
    Quarantining {
        repo: String,
        count: usize,
    },
    Repaired {
        repo: String,
        version: String,
    },
}

impl From<&PatchProgress> for PatchDto {
    fn from(progress: &PatchProgress) -> Self {
        match progress {
            PatchProgress::Downloading {
                repo,
                index,
                bytes_done,
                total,
                recoveries,
            } => Self::Downloading {
                repo: repo_label(*repo),
                index: *index,
                bytes_done: *bytes_done,
                total: *total,
                recoveries: RecoveriesDto::from(*recoveries),
            },
            PatchProgress::Applying {
                repo,
                index,
                bytes_done,
            } => Self::Applying {
                repo: repo_label(*repo),
                index: *index,
                bytes_done: *bytes_done,
            },
            PatchProgress::Applied {
                repo,
                index,
                version,
            } => Self::Applied {
                repo: repo_label(*repo),
                index: *index,
                version: version.clone(),
            },
            PatchProgress::Verifying { repo, attempt } => Self::Verifying {
                repo: repo_label(*repo),
                attempt: *attempt,
            },
            PatchProgress::Refetching {
                repo,
                attempt,
                bytes,
            } => Self::Refetching {
                repo: repo_label(*repo),
                attempt: *attempt,
                bytes: *bytes,
            },
            PatchProgress::Quarantining { repo, count } => Self::Quarantining {
                repo: repo_label(*repo),
                count: *count,
            },
            PatchProgress::Repaired { repo, version } => Self::Repaired {
                repo: repo_label(*repo),
                version: version.clone(),
            },
        }
    }
}

fn repo_label(repo: Repo) -> String {
    match repo {
        Repo::Boot => "boot".to_owned(),
        Repo::Game => "game".to_owned(),
        Repo::Expansion(number) => format!("ex{number}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum NoticeDto {
    ClockSkew { seconds: i64 },
    OtpListenerFlood { from: IpAddr, refused: u32 },
    Unknown,
}

impl From<&Notice> for NoticeDto {
    fn from(notice: &Notice) -> Self {
        match notice {
            Notice::ClockSkew { seconds } => Self::ClockSkew { seconds: *seconds },
            Notice::OtpListenerFlood { from, refused } => Self::OtpListenerFlood {
                from: *from,
                refused: *refused,
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub(crate) enum ProgramStatusDto {
    Code(i32),
    Signal(i32),
}

impl From<ProgramStatus> for ProgramStatusDto {
    fn from(status: ProgramStatus) -> Self {
        match status {
            ProgramStatus::Code(code) => Self::Code(code),
            ProgramStatus::Signal(signal) => Self::Signal(signal),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum OutcomeDto {
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

impl From<RunOutcome> for OutcomeDto {
    fn from(outcome: RunOutcome) -> Self {
        match outcome {
            RunOutcome::Succeeded => Self::Succeeded,
            RunOutcome::Failed => Self::Failed,
            RunOutcome::Cancelled => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum AddonDto {
    Started {
        program: String,
        pid: i32,
    },
    AlreadyRunning {
        program: String,
        pid: i32,
    },
    Stopped {
        program: String,
        pid: i32,
    },
    Finished {
        program: String,
        outcome: AddonOutcomeDto,
    },
    Failed {
        program: String,
        reason: String,
    },
    StillWaiting {
        program: String,
        seconds: u64,
    },
    Loaded {
        what: String,
    },
    NotConfirmed {
        what: String,
        waited_seconds: u64,
        evidence: String,
    },
    Unknown {
        code: &'static str,
    },
}

impl From<&AddonEvent> for AddonDto {
    fn from(event: &AddonEvent) -> Self {
        match event {
            AddonEvent::Started { program, pid, .. } => Self::Started {
                program: program.to_string_lossy().into_owned(),
                pid: *pid,
            },
            AddonEvent::AlreadyRunning { program, pid, .. } => Self::AlreadyRunning {
                program: program.to_string_lossy().into_owned(),
                pid: *pid,
            },
            AddonEvent::Stopped { program, pid, .. } => Self::Stopped {
                program: program.to_string_lossy().into_owned(),
                pid: *pid,
            },
            AddonEvent::Finished {
                program, outcome, ..
            } => Self::Finished {
                program: program.to_string_lossy().into_owned(),
                outcome: AddonOutcomeDto::from(outcome),
            },
            AddonEvent::Failed {
                program, reason, ..
            } => Self::Failed {
                program: program.to_string_lossy().into_owned(),
                reason: reason.clone(),
            },
            AddonEvent::StillWaiting {
                program, seconds, ..
            } => Self::StillWaiting {
                program: program.to_string_lossy().into_owned(),
                seconds: *seconds,
            },
            AddonEvent::Loaded { what, .. } => Self::Loaded { what: what.clone() },
            AddonEvent::NotConfirmed {
                what,
                waited,
                evidence,
                ..
            } => Self::NotConfirmed {
                what: what.clone(),
                waited_seconds: waited.as_secs(),
                evidence: evidence.to_string_lossy().into_owned(),
            },
            _ => Self::Unknown { code: event.code() },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum AddonOutcomeDto {
    Started { pid: i32 },
    AlreadyRunning { pid: i32 },
    Disabled,
    Completed { code: Option<i32> },
    Cancelled,
    Failed { reason: String },
    Unknown,
}

impl From<&Outcome> for AddonOutcomeDto {
    fn from(outcome: &Outcome) -> Self {
        match outcome {
            Outcome::Started { pid, .. } => Self::Started { pid: *pid },
            Outcome::AlreadyRunning { pid, .. } => Self::AlreadyRunning { pid: *pid },
            Outcome::Disabled => Self::Disabled,
            Outcome::Completed { code, .. } => Self::Completed { code: *code },
            Outcome::Cancelled => Self::Cancelled,
            Outcome::Failed { reason, .. } => Self::Failed {
                reason: reason.clone(),
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum SetupDto {
    Downloading {
        what: String,
        bytes_done: u64,
        total: Option<u64>,
        recoveries: RecoveriesDto,
    },
    Installing {
        what: String,
        version: String,
    },
    Installed {
        what: String,
    },
    AlreadyPresent {
        what: String,
    },
    Applying {
        verb: String,
        reason: String,
    },
    Reapplying {
        verb: String,
        because: String,
    },
    Applied {
        verb: String,
    },
    Caveat {
        what: String,
        note: String,
    },
    Failed {
        what: String,
        reason: String,
    },
    CatalogUnavailable {
        detail: String,
        using_cached: bool,
    },
    Stopped {
        applied: usize,
    },
    Unknown {
        code: &'static str,
    },
}

impl From<&SetupEvent> for SetupDto {
    fn from(event: &SetupEvent) -> Self {
        match event {
            SetupEvent::Downloading {
                what,
                bytes_done,
                total,
                recoveries,
            } => Self::Downloading {
                what: what.clone(),
                bytes_done: *bytes_done,
                total: *total,
                recoveries: RecoveriesDto::from(*recoveries),
            },
            SetupEvent::Installing { what, version } => Self::Installing {
                what: what.clone(),
                version: version.clone(),
            },
            SetupEvent::Installed { what } => Self::Installed { what: what.clone() },
            SetupEvent::AlreadyPresent { what } => Self::AlreadyPresent { what: what.clone() },
            SetupEvent::Applying { verb, reason } => Self::Applying {
                verb: verb.clone(),
                reason: reason.clone(),
            },
            SetupEvent::Reapplying { verb, because } => Self::Reapplying {
                verb: verb.clone(),
                because: because.clone(),
            },
            SetupEvent::Applied { verb } => Self::Applied { verb: verb.clone() },
            SetupEvent::Caveat { what, note } => Self::Caveat {
                what: what.clone(),
                note: note.clone(),
            },
            SetupEvent::Failed { what, reason } => Self::Failed {
                what: what.clone(),
                reason: reason.clone(),
            },
            SetupEvent::CatalogUnavailable {
                detail,
                using_cached,
            } => Self::CatalogUnavailable {
                detail: detail.clone(),
                using_cached: *using_cached,
            },
            SetupEvent::Stopped { applied, .. } => Self::Stopped { applied: *applied },
            _ => Self::Unknown { code: event.code() },
        }
    }
}
