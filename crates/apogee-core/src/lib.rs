#![forbid(unsafe_code)]
//! The launcher core: the composition root that owns the domain model, versioned persistence, and
//! the command/event surface the shells drive.
//!
//! This is the only crate permitted to see every subsystem. It constructs each once, injects it,
//! owns the concrete network transport, and exposes a single [`Core::execute`] surface that yields
//! a stream of [`Event`]s. Profiles and settings persist through a versioned store that migrates
//! forward and never deletes on a load failure. The login-to-play orchestration arrives in a later
//! change; its command arms are stubbed today.

mod addons;
mod backup;
mod command;
mod composition;
mod error;
mod flow;
mod host;
mod launch;
mod model;
mod patch;
mod store;
mod transport;

pub use apogee_addons::backup::{ArchiveRecord, BackupReport, PruneReport};
#[cfg(unix)]
pub use apogee_addons::backup::{RestoreReport, RestoredRoot};
// Under its own name: the addon layer already has a public `AddonOutcome`, and re-exporting a second,
// different type under that name gives a shell two things it cannot tell apart from the import alone.
pub use apogee_addons::{AddonEvent, ExternalAddon, Outcome, RunIn, SetupEvent, Trigger};
pub use apogee_otp::OtpSource;
pub use apogee_patcher::PatchProgress;
pub use apogee_runtime::{BenchError, BenchStats, FrameLog};
#[cfg(unix)]
pub use apogee_runtime::{
    CompatTool, CompatToolInstall, DeckModel, HostIdentity, SteamInstall, installed_compat_tool,
    remove_compat_tool, steam_installs,
};
pub use apogee_secrets::Secret;
pub use command::{Command, Event, FirstRunStep, FlowState, FrontierData, FrontierQuery, Progress};
pub use composition::{Core, CoreConfig};
pub use error::CoreError;
pub use model::{
    Account, AccountKind, LaunchSettings, PrefixSelection, Profile, Region, RunnerSelection,
    Settings,
};
pub use sqex_proto::Transport;
pub use store::StoreError;
pub use uuid::Uuid;
