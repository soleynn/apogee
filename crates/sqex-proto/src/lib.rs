#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! A reimplementation of Square Enix's FFXIV launcher network protocol: OAuth login, version and
//! boot checks, patchlist parsing.
//!
//! The crate is transport-free: every request goes through an injected [`Transport`], and the
//! crate names neither `reqwest` nor `tokio`. It implements the unauthenticated surfaces (client
//! identities, the boot-version check, the patchlist parser, the frontier gate/login status
//! endpoints), the OAuth login flow, and session registration (the version report and the UID
//! handshake). Reading an install's `.ver` files for the version report
//! ([`VersionReport::from_install`]) is the crate's only filesystem access. `gen_token` (behind the
//! `gen-token` feature) is a dormant, opt-in surface: SE disables the code path it exercises on the
//! live service, so nothing here calls it by default.
//!
//! # Layout
//!
//! - [`check_boot_version`] asks whether the boot component is current; [`register_session`]
//!   reports the installed version and, for a current game, receives the [`UniqueId`] that
//!   authorizes patch downloads. Both surface pending patches as [`PatchListEntry`] values,
//!   produced by [`parse_patch_list`].
//! - [`begin_login`] and [`LoginFlow::submit`] carry out the OAuth login flow, taking
//!   [`Credentials`] or a Steam [`ObfuscatedTicket`] via [`LoginKind`] and yielding an
//!   [`Authenticated`] session.
//! - [`check_gate_status`] and [`check_login_status`] fetch the frontier's world-gate and
//!   login-server status ([`GateStatus`]) ahead of a login attempt.
//! - [`ComputerId`], [`launcher_user_agent`], and [`frontier_referer`] reproduce the identity
//!   strings SE fingerprints; [`LauncherTime`] is the injected clock every timestamp is rendered
//!   from.
//! - [`ProtoError`] is the single error type every fallible surface returns; [`Transport`] is the
//!   seam a consumer implements to give the crate a way onto the wire.
//!
//! # Examples
//!
//! Deriving the identity values a request carries, and the timestamp it's stamped with:
//!
//! ```
//! use sqex_proto::{ComputerId, LauncherTime, launcher_user_agent};
//!
//! let computer_id = ComputerId::from_facts("host", "user", "os", 4);
//! let user_agent = launcher_user_agent(&computer_id);
//! assert!(user_agent.starts_with("SQEXAuthor/2.0.0"));
//!
//! let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
//! assert_eq!(now.boot_check_timestamp(), "2024-01-02-03-40");
//! ```
//!
//! Driving a login to completion against a scripted [`Transport`], then reading the resulting
//! session id (see [`LoginFlow::submit`]'s own doc for the full example this abbreviates):
//!
//! ```
//! # fn block_on<F: std::future::Future>(fut: F) -> F::Output {
//! #     let mut fut = std::pin::pin!(fut);
//! #     let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
//! #     loop {
//! #         if let std::task::Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
//! #             return val;
//! #         }
//! #     }
//! # }
//! use sqex_proto::{
//!     ClientContext, ComputerId, Credentials, LauncherTime, LoginKind, OauthContext,
//!     ProtoRequest, ProtoResponse, Transport, TransportError, begin_login,
//! };
//!
//! struct TopPage;
//!
//! #[async_trait::async_trait]
//! impl Transport for TopPage {
//!     async fn execute(&self, _req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
//!         let body = r#"<input type="hidden" name="_STORED_" value="opaqueblob">"#;
//!         Ok(ProtoResponse::new(200, body.as_bytes().to_vec()))
//!     }
//! }
//!
//! let id = ComputerId::from_facts("host", "user", "os", 4);
//! let context = OauthContext {
//!     client: ClientContext {
//!         computer_id: &id,
//!         language: "en-us",
//!         accept_language: "en-us,en;q=0.9",
//!         referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
//!     },
//!     lng: "en",
//!     region: 3,
//! };
//! let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
//! let kind = LoginKind::Standard { free_trial: false };
//! let flow = block_on(begin_login(&TopPage, &context, &now, kind)).unwrap();
//! assert!(flow.server_date().is_none());
//! ```

mod bootver;
mod error;
mod frontier;
#[cfg(feature = "gen-token")]
mod gen_token;
mod http_date;
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
#[cfg(feature = "gen-token")]
pub use gen_token::gen_token;
pub use http_date::parse_http_date;
pub use identity::{
    ClientContext, ComputerId, PATCHER_USER_AGENT, frontier_referer, launcher_user_agent,
};
pub use oauth::{
    Authenticated, Credentials, LaunchParams, LoginFlow, LoginKind, OauthContext, SessionId,
    begin_login, parse_launch_params, scrape_stored,
};
pub use patchlist::{BlockHashes, PatchListEntry, parse_patch_list};
pub use register::{Registration, UniqueId, register_session};
// A Steam login is begun with these, so a consumer can build one without naming the crypto crate.
pub use sqex_crypto::{ObfuscatedTicket, ServerTime};
pub use time::LauncherTime;
pub use transport::{
    NEGOTIATED_HEADERS, ProtoRequest, ProtoResponse, RequestBody, Transport, TransportError,
    check_header_fidelity,
};
pub use version::{
    BASE_GAME_VERSION, InstallPaths, SanityKind, VersionRepo, VersionReport, decode_ver,
};
