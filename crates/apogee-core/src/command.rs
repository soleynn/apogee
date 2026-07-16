//! The command/event surface both shells drive.
//!
//! A shell issues a [`Command`] and renders the [`Event`]s it yields; it never branches on business
//! rules. Dispositions a user must act on (needs a one-time password, terms not accepted, service
//! down) are [`FlowState`] values the shell narrates, not failures.

use std::path::PathBuf;

use apogee_otp::OtpSource;
use uuid::Uuid;

use crate::error::CoreError;

/// A request from a shell to the core.
///
/// These are the async, event-emitting flows. Synchronous store CRUD (list/save/delete profiles,
/// load/save settings) is the direct methods on [`Core`](crate::Core), not a command.
#[derive(Debug)]
#[non_exhaustive]
pub enum Command {
    /// Log in with the given profile's account, sourcing the one-time password as specified.
    Login {
        profile: Uuid,
        otp: OtpSource,
    },
    PatchAndPlay {
        profile: Uuid,
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
    NeedsOtp,
    NeedsTerms,
    NoService,
    Patching,
    Launching,
    Running,
    Exited { code: i32 },
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
