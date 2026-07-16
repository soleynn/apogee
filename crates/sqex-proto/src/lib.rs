#![forbid(unsafe_code)]
//! SE launcher network protocol: OAuth login, version and boot checks, patchlist parsing.
//!
//! The crate is transport-free: it takes an injected [`Transport`] and names neither `reqwest` nor
//! `tokio`. It implements the unauthenticated surfaces (identities, the boot-version check, the
//! patchlist parser, and the frontier status/news endpoints), the OAuth login flow, and session
//! registration (the version report and the UID handshake). Reading an install's `.ver` files for the
//! version report is the crate's only filesystem access.

mod bootver;
mod error;
mod frontier;
mod identity;
mod oauth;
mod patchlist;
mod register;
mod time;
mod transport;
mod version;

pub use bootver::check_boot_version;
pub use error::{ProtoError, Step};
pub use frontier::{FrontierContext, GateStatus, check_gate_status, check_login_status};
pub use identity::{
    ClientContext, ComputerId, PATCHER_USER_AGENT, frontier_referer, launcher_user_agent,
};
pub use oauth::{
    Authenticated, Credentials, LaunchParams, LoginFlow, LoginKind, OauthContext, SessionId,
    begin_login, parse_launch_params, scrape_stored,
};
pub use patchlist::{BlockHashes, PatchListEntry, parse_patch_list};
pub use register::{Registration, UniqueId, register_session};
pub use time::LauncherTime;
pub use transport::{
    ProtoRequest, ProtoResponse, RequestBody, Transport, TransportError,
    debug_assert_header_fidelity,
};
pub use version::{InstallPaths, SanityKind, VersionRepo, VersionReport};
