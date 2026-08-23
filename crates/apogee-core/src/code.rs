//! Stable presentation codes for every backend value a shell renders.

#![deny(clippy::wildcard_enum_match_arm)]

use apogee_addons::{AddonEvent, SetupEvent};
use apogee_otp::Deviation;
use apogee_patcher::PreflightError;
use apogee_runtime::HealthIssue;
use apogee_secrets::BackendState;

use crate::{CoreError, Event, FlowState, RunOutcome};

/// A stable, localization-safe identifier for a backend value.
///
/// Codes describe variants, never their data. They are suitable for presentation-table and
/// translation keys and must not contain paths, excerpts, credentials, or other runtime values.
pub trait StableCode {
    /// Return this value's stable presentation code.
    fn code(&self) -> &'static str;
}

impl StableCode for Event {
    fn code(&self) -> &'static str {
        match self {
            Self::State(state) => state.code(),
            Self::Progress(_) => "event-progress",
            Self::Patch(_) => "event-patch",
            Self::Addon(event) => event.code(),
            Self::Setup(event) => event.code(),
            Self::Frontier(_) => "event-frontier",
            Self::Prefix(_) => "event-prefix",
            Self::Notice(crate::Notice::ClockSkew { .. }) => "notice-clock-skew",
            Self::Notice(crate::Notice::OtpListenerFlood { .. }) => "notice-otp-listener-flood",
            Self::LaunchProgramExited(_) => "event-launch-program-exited",
            Self::Error(error) => error.code(),
            Self::Outcome(RunOutcome::Succeeded) => "event-outcome-succeeded",
            Self::Outcome(RunOutcome::Failed) => "event-outcome-failed",
            Self::Outcome(RunOutcome::Cancelled) => "event-outcome-cancelled",
        }
    }
}

impl StableCode for FlowState {
    fn code(&self) -> &'static str {
        match self {
            Self::NeedsPassword => "state-needs-password",
            Self::NeedsOtp => "state-needs-otp",
            Self::WaitingForOtpWindow { .. } => "state-waiting-for-otp-window",
            Self::WaitingForPushedCode { .. } => "state-waiting-for-pushed-code",
            Self::PushedCodeReceived { .. } => "state-pushed-code-received",
            Self::NeedsTerms => "state-needs-terms",
            Self::NoService => "state-no-service",
            Self::NeedsLogin => "state-needs-login",
            Self::NeedsBootPatch => "state-needs-boot-patch",
            Self::PatchesPending { .. } => "state-patches-pending",
            Self::VersionNotServiced => "state-version-not-serviced",
            Self::BackingUp => "state-backing-up",
            Self::PreparingPrefix => "state-preparing-prefix",
            Self::Patching => "state-patching",
            Self::Repairing => "state-repairing",
            Self::CheckingPrefix => "state-checking-prefix",
            Self::NoPrefix => "state-no-prefix",
            Self::FixingPrefix => "state-fixing-prefix",
            Self::RecreatingPrefix => "state-recreating-prefix",
            Self::Launching => "state-launching",
            Self::Running => "state-running",
            Self::SupervisingAddons => "state-supervising-addons",
            Self::Exited => "state-exited",
            Self::Cancelled => "state-cancelled",
        }
    }
}

impl StableCode for CoreError {
    fn code(&self) -> &'static str {
        match self {
            Self::Store(_) => "err-store",
            Self::Proto(error) => proto_code(error),
            Self::Fetch(_) => "err-fetch",
            Self::Patch(_) => "err-patch",
            Self::Runtime(_) => "err-runtime",
            Self::Addons(_) => "err-addons",
            Self::Addon { .. } => "err-addon",
            Self::Config { .. } => "err-config",
            Self::Secrets(_) => "err-secrets",
            Self::Otp(_) => "err-otp",
            Self::Crypto(_) => "err-crypto",
            Self::NoSteam => "err-no-steam",
            Self::NoTickSource => "err-no-tick-source",
            Self::NoProfile(_) => "err-no-profile",
            Self::NoAccount(_) => "err-no-account",
            Self::InvalidCredential => "err-invalid-credential",
            Self::Import { .. } => "err-import",
            Self::Init { .. } => "err-init",
            Self::Launch { .. } => "err-launch",
            Self::PatchIncomplete { .. } => "err-patch-incomplete",
            Self::Repair { .. } => "err-repair",
        }
    }
}

#[allow(clippy::wildcard_enum_match_arm)]
fn proto_code(error: &sqex_proto::ProtoError) -> &'static str {
    match error {
        sqex_proto::ProtoError::Transport(_) => "err-proto-transport",
        sqex_proto::ProtoError::InvalidResponse { .. } => "err-proto-invalid-response",
        sqex_proto::ProtoError::PatchListParse { .. } => "err-proto-patch-list-parse",
        sqex_proto::ProtoError::OauthFailed { .. } => "err-proto-oauth-failed",
        sqex_proto::ProtoError::SteamLinkNeeded => "err-proto-steam-link-needed",
        sqex_proto::ProtoError::SteamWrongAccount { .. } => "err-proto-steam-wrong-account",
        sqex_proto::ProtoError::StoredNotFound { .. } => "err-proto-stored-not-found",
        sqex_proto::ProtoError::LaunchParamsUnparseable { .. } => {
            "err-proto-launch-params-unparseable"
        }
        sqex_proto::ProtoError::InvalidVersionFiles { .. } => "err-proto-invalid-version-files",
        // `ProtoError` is foreign and non-exhaustive. The fallback keeps a shell able to render a
        // newer dependency's value until this crate is rebuilt with an explicit stable code for it.
        _ => "err-proto-unknown",
    }
}

impl StableCode for SetupEvent {
    #[allow(clippy::wildcard_enum_match_arm)]
    fn code(&self) -> &'static str {
        match self {
            Self::Downloading { .. } => "setup-downloading",
            Self::Installing { .. } => "setup-installing",
            Self::Installed { .. } => "setup-installed",
            Self::AlreadyPresent { .. } => "setup-already-present",
            Self::Applying { .. } => "setup-applying",
            Self::Reapplying { .. } => "setup-reapplying",
            Self::Applied { .. } => "setup-applied",
            Self::Caveat { .. } => "setup-caveat",
            Self::Failed { .. } => "setup-failed",
            Self::CatalogUnavailable { .. } => "setup-catalog-unavailable",
            Self::Stopped { .. } => "setup-stopped",
            // Foreign non-exhaustive enums require a wildcard outside their defining crate.
            _ => "setup-unknown",
        }
    }
}

impl StableCode for AddonEvent {
    #[allow(clippy::wildcard_enum_match_arm)]
    fn code(&self) -> &'static str {
        match self {
            Self::Started { .. } => "addon-started",
            Self::AlreadyRunning { .. } => "addon-already-running",
            Self::Stopped { .. } => "addon-stopped",
            Self::Finished { .. } => "addon-finished",
            Self::Failed { .. } => "addon-failed",
            Self::StillWaiting { .. } => "addon-still-waiting",
            Self::Loaded { .. } => "addon-loaded",
            Self::NotConfirmed { .. } => "addon-not-confirmed",
            _ => "addon-unknown",
        }
    }
}

impl StableCode for HealthIssue {
    #[allow(clippy::wildcard_enum_match_arm)]
    fn code(&self) -> &'static str {
        match self {
            Self::MissingSkeleton { .. } => "health-missing-skeleton",
            Self::DriveMapping { .. } => "health-drive-mapping",
            Self::RunnerMismatch { .. } => "health-runner-mismatch",
            Self::MissingDxvkDll { .. } => "health-missing-dxvk-dll",
            Self::MissingNvapi => "health-missing-nvapi",
            _ => "health-unknown",
        }
    }
}

impl StableCode for BackendState {
    #[allow(clippy::wildcard_enum_match_arm)]
    fn code(&self) -> &'static str {
        match self {
            Self::Ready => "backend-ready",
            Self::Locked => "backend-locked",
            Self::NoDefaultCollection => "backend-no-default-collection",
            Self::NoSessionBus => "backend-no-session-bus",
            Self::NoProvider => "backend-no-provider",
            Self::SandboxDenied => "backend-sandbox-denied",
            Self::NotStoring => "backend-not-storing",
            Self::Unreachable => "backend-unreachable",
            _ => "backend-unknown",
        }
    }
}

impl StableCode for PreflightError {
    #[allow(clippy::wildcard_enum_match_arm)]
    fn code(&self) -> &'static str {
        match self {
            Self::NotEnoughSpace { .. } => "preflight-not-enough-space",
            Self::GameRunning => "preflight-game-running",
            _ => "preflight-unknown",
        }
    }
}

impl StableCode for Deviation {
    #[allow(clippy::wildcard_enum_match_arm)]
    fn code(&self) -> &'static str {
        match self {
            Self::Algorithm { .. } => "deviation-algorithm",
            Self::Digits { .. } => "deviation-digits",
            Self::Period { .. } => "deviation-period",
            _ => "deviation-unknown",
        }
    }
}

/// Every stable code this build can emit, sorted bytewise and containing no duplicates.
pub const ALL_CODES: &[&str] = &[
    "addon-already-running",
    "addon-failed",
    "addon-finished",
    "addon-loaded",
    "addon-not-confirmed",
    "addon-started",
    "addon-still-waiting",
    "addon-stopped",
    "addon-unknown",
    "backend-locked",
    "backend-no-default-collection",
    "backend-no-provider",
    "backend-no-session-bus",
    "backend-not-storing",
    "backend-ready",
    "backend-sandbox-denied",
    "backend-unknown",
    "backend-unreachable",
    "deviation-algorithm",
    "deviation-digits",
    "deviation-period",
    "deviation-unknown",
    "err-addon",
    "err-addons",
    "err-config",
    "err-crypto",
    "err-fetch",
    "err-import",
    "err-init",
    "err-invalid-credential",
    "err-launch",
    "err-no-account",
    "err-no-profile",
    "err-no-steam",
    "err-no-tick-source",
    "err-otp",
    "err-patch",
    "err-patch-incomplete",
    "err-proto-invalid-response",
    "err-proto-invalid-version-files",
    "err-proto-launch-params-unparseable",
    "err-proto-oauth-failed",
    "err-proto-patch-list-parse",
    "err-proto-steam-link-needed",
    "err-proto-steam-wrong-account",
    "err-proto-stored-not-found",
    "err-proto-transport",
    "err-proto-unknown",
    "err-repair",
    "err-runtime",
    "err-secrets",
    "err-store",
    "event-frontier",
    "event-launch-program-exited",
    "event-outcome-cancelled",
    "event-outcome-failed",
    "event-outcome-succeeded",
    "event-patch",
    "event-prefix",
    "event-progress",
    "health-drive-mapping",
    "health-missing-dxvk-dll",
    "health-missing-nvapi",
    "health-missing-skeleton",
    "health-runner-mismatch",
    "health-unknown",
    "notice-clock-skew",
    "notice-otp-listener-flood",
    "preflight-game-running",
    "preflight-not-enough-space",
    "preflight-unknown",
    "setup-already-present",
    "setup-applied",
    "setup-applying",
    "setup-catalog-unavailable",
    "setup-caveat",
    "setup-downloading",
    "setup-failed",
    "setup-installed",
    "setup-installing",
    "setup-reapplying",
    "setup-stopped",
    "setup-unknown",
    "state-backing-up",
    "state-cancelled",
    "state-checking-prefix",
    "state-exited",
    "state-fixing-prefix",
    "state-launching",
    "state-needs-boot-patch",
    "state-needs-login",
    "state-needs-otp",
    "state-needs-password",
    "state-needs-terms",
    "state-no-prefix",
    "state-no-service",
    "state-patches-pending",
    "state-patching",
    "state-preparing-prefix",
    "state-pushed-code-received",
    "state-recreating-prefix",
    "state-repairing",
    "state-running",
    "state-supervising-addons",
    "state-version-not-serviced",
    "state-waiting-for-otp-window",
    "state-waiting-for-pushed-code",
];

#[cfg(test)]
mod tests {
    use super::{ALL_CODES, StableCode};
    use crate::{Event, FlowState, RunOutcome};

    fn assert_catalogued<T: StableCode>(value: &T) {
        assert!(
            ALL_CODES.binary_search(&value.code()).is_ok(),
            "missing code {:?}",
            value.code()
        );
    }

    #[test]
    fn all_codes_are_sorted_and_unique() {
        assert!(ALL_CODES.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn representative_leaf_codes_are_public_and_catalogued() {
        let values = [
            Event::State(FlowState::NeedsPassword),
            Event::Outcome(RunOutcome::Succeeded),
        ];
        let codes: Vec<_> = values.iter().map(StableCode::code).collect();
        assert_eq!(codes, ["state-needs-password", "event-outcome-succeeded"]);
        assert!(
            codes
                .iter()
                .all(|code| ALL_CODES.binary_search(code).is_ok())
        );

        assert_catalogued(&crate::CoreError::Proto(
            sqex_proto::ProtoError::OauthFailed {
                excerpt: String::new(),
            },
        ));
        assert_catalogued(&apogee_runtime::HealthIssue::MissingNvapi);
        assert_catalogued(&apogee_secrets::BackendState::Ready);
        assert_catalogued(&apogee_patcher::PreflightError::GameRunning);
        assert_catalogued(&apogee_otp::Deviation::Digits {
            offered: 8,
            accepted: 6,
        });
    }

    #[test]
    fn every_flow_state_code_is_catalogued() {
        let states = [
            FlowState::NeedsPassword,
            FlowState::NeedsOtp,
            FlowState::WaitingForOtpWindow { seconds: 1 },
            FlowState::WaitingForPushedCode {
                port: 1,
                seconds: 1,
            },
            FlowState::PushedCodeReceived {
                from: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            },
            FlowState::NeedsTerms,
            FlowState::NoService,
            FlowState::NeedsLogin,
            FlowState::NeedsBootPatch,
            FlowState::PatchesPending { count: 1, bytes: 1 },
            FlowState::VersionNotServiced,
            FlowState::BackingUp,
            FlowState::PreparingPrefix,
            FlowState::Patching,
            FlowState::Repairing,
            FlowState::CheckingPrefix,
            FlowState::NoPrefix,
            FlowState::FixingPrefix,
            FlowState::RecreatingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::SupervisingAddons,
            FlowState::Exited,
            FlowState::Cancelled,
        ];
        for state in states {
            assert_catalogued(&state);
        }
    }
}
