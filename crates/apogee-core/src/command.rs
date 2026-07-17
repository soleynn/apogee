//! The command/event surface both shells drive.
//!
//! A shell issues a [`Command`] and renders the [`Event`]s it yields; it never branches on business
//! rules. Dispositions a user must act on (needs a one-time password, terms not accepted, service
//! down) are [`FlowState`] values the shell narrates, not failures.

use std::fmt;
use std::path::PathBuf;

use apogee_otp::OtpSource;
use apogee_secrets::Secret;
use uuid::Uuid;

use crate::error::CoreError;

/// A request from a shell to the core.
///
/// These are the async, event-emitting flows. Synchronous store CRUD (list/save/delete profiles,
/// load/save settings) is the direct methods on [`Core`](crate::Core), not a command.
///
/// `Debug` is hand-written to redact the credential-bearing fields: the write-only [`Secret`]
/// password and the one-time-password code can never reach a log through `{:?}`.
#[non_exhaustive]
pub enum Command {
    /// Authenticate the profile's account and register the session, caching the result. Does not
    /// launch. The password is provided by the shell (write-only, never persisted); the one-time
    /// password is sourced as specified.
    Login {
        profile: Uuid,
        password: Secret,
        otp: OtpSource,
    },
    /// Launch the profile's game from a still-valid cached session, skipping authentication. Emits
    /// [`FlowState::NeedsLogin`] when no valid session is cached.
    Launch {
        profile: Uuid,
    },
    /// Authenticate (or reuse a cached session), register, and launch the game in one flow.
    PatchAndPlay {
        profile: Uuid,
        password: Secret,
        otp: OtpSource,
    },
    Repair {
        profile: Uuid,
    },
    FirstRun(FirstRunStep),
    ImportXivLauncher(PathBuf),
    /// Fetch pre-login display data (news, gate status, banners).
    Frontier(FrontierQuery),
    SupportBundle,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Login { profile, otp, .. } => f
                .debug_struct("Login")
                .field("profile", profile)
                .field("password", &"<redacted>")
                .field("otp", &otp_label(otp))
                .finish(),
            Command::Launch { profile } => {
                f.debug_struct("Launch").field("profile", profile).finish()
            }
            Command::PatchAndPlay { profile, otp, .. } => f
                .debug_struct("PatchAndPlay")
                .field("profile", profile)
                .field("password", &"<redacted>")
                .field("otp", &otp_label(otp))
                .finish(),
            Command::Repair { profile } => {
                f.debug_struct("Repair").field("profile", profile).finish()
            }
            Command::FirstRun(step) => f.debug_tuple("FirstRun").field(step).finish(),
            Command::ImportXivLauncher(path) => {
                f.debug_tuple("ImportXivLauncher").field(path).finish()
            }
            Command::Frontier(query) => f.debug_tuple("Frontier").field(query).finish(),
            Command::SupportBundle => f.write_str("SupportBundle"),
        }
    }
}

/// The variant name of an [`OtpSource`], never its code, for a redacted `Debug`.
fn otp_label(otp: &OtpSource) -> &'static str {
    match otp {
        OtpSource::Totp => "Totp",
        OtpSource::Manual(_) => "Manual",
        OtpSource::Listener(_) => "Listener",
    }
}

/// A message emitted while a [`Command`] runs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    State(FlowState),
    Progress(Progress),
    Frontier(FrontierData),
    Error(CoreError),
}

/// Where a login-to-play flow currently stands. The shell narrates these; none is a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowState {
    /// A one-time password is required but none was usable.
    NeedsOtp,
    /// The account must accept the terms of service before playing.
    NeedsTerms,
    /// No active service on the account, or the login server is closed.
    NoService,
    /// A launch was asked for but no valid cached session exists; log in first.
    NeedsLogin,
    /// A boot patch is required before the game can register (registration returned 409).
    NeedsBootPatch,
    /// The game is out of date: patches are pending (count and total bytes). Applied by a later flow.
    PatchesPending { count: u32, bytes: u64 },
    /// The installed version is no longer serviced (registration returned 410).
    VersionNotServiced,
    /// Patches are being applied.
    Patching,
    /// The game is being prepared and spawned.
    Launching,
    /// The game process is running.
    Running,
    /// The game process has exited (no exit status is available for a non-child descendant).
    Exited,
}

/// A completion ratio relayed from a subsystem. Numeric only: the shell supplies any label.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    pub completed: u64,
    pub total: u64,
}

/// Which pre-login display surface a [`Command::Frontier`] asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrontierQuery {
    News,
    Gate,
    Banners,
}

/// Pre-login display data returned for a [`FrontierQuery`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FrontierData {}

/// A step in the initial setup walk.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FirstRunStep {
    Start,
}
