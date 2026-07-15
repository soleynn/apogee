#![forbid(unsafe_code)]
//! The launcher core: the composition root that owns the domain model, versioned persistence, and
//! the command/event surface the shells drive.
//!
//! This is the only crate permitted to see every subsystem. It constructs each once, injects it,
//! owns the concrete network transport, and exposes a single [`Core::execute`] surface that yields
//! a stream of [`Event`]s. Profiles and settings persist through a versioned store that migrates
//! forward and never deletes on a load failure. The login-to-play orchestration arrives in a later
//! change; its command arms are stubbed today.

mod command;
mod composition;
mod error;
mod model;
mod store;
mod transport;

pub use apogee_otp::OtpSource;
pub use command::{Command, Event, FirstRunStep, FlowState, FrontierData, FrontierQuery, Progress};
pub use composition::{Core, CoreConfig};
pub use error::CoreError;
pub use model::{
    Account, AccountKind, ComponentSelection, LaunchSettings, PrefixSelection, Profile, Region,
    RunnerSelection, Settings,
};
pub use store::StoreError;
pub use transport::HttpTransport;
pub use uuid::Uuid;
