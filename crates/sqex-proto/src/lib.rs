#![forbid(unsafe_code)]
//! SE launcher network protocol: OAuth login, version and boot checks, patchlist parsing.
//!
//! The crate is transport-free: it takes an injected [`Transport`] and names neither `reqwest` nor
//! `tokio`. This phase implements the unauthenticated surfaces (identities, the boot-version check, the
//! patchlist parser, and the frontier status/news endpoints); login and session registration land in
//! later phases.

mod error;
mod identity;
mod patchlist;
mod transport;

pub use error::{ProtoError, Step};
pub use identity::{ComputerId, PATCHER_USER_AGENT, frontier_referer, launcher_user_agent};
pub use patchlist::{BlockHashes, PatchListEntry, parse_patch_list};
pub use transport::{
    ProtoRequest, ProtoResponse, Transport, TransportError, debug_assert_header_fidelity,
};
