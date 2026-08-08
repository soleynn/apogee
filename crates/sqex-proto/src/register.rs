//! Session registration: the version-report POST and the UID handshake.
//!
//! After login, the client reports its installed version to `patch-gamever` and, if the game is
//! current, receives an `X-Patch-Unique-Id` that authorizes patch downloads. The dispositions SE
//! can answer with are modeled as [`Registration`] values (a boot patch is pending, the version is
//! no longer serviced, or the session is registered with any pending game patches); only a response
//! that fits none of them is a [`ProtoError`].

use std::fmt;

use http::{HeaderName, HeaderValue, Method};
use zeroize::Zeroizing;

use crate::error::{ProtoError, Step};
use crate::identity::PATCHER_USER_AGENT;
use crate::oauth::Authenticated;
use crate::patchlist::{PatchListEntry, parse_patch_list};
use crate::transport::{
    ProtoRequest, ProtoResponse, RequestBody, Transport, TransportError, parse_base,
};
use crate::version::VersionReport;

const GAME_VERSION_BASE: &str = "https://patch-gamever.ffxiv.com/http/win32/ffxivneo_release_game";

const UNIQUE_ID_HEADER: &str = "x-patch-unique-id";

/// The `X-Patch-Unique-Id` credential authorizing patch downloads, redacted in
/// [`Debug`](fmt::Debug) and held zeroizing so it scrubs on drop.
///
/// The only way to obtain one is a successful [`register_session`], via
/// [`Registration::Registered`].
///
/// # Examples
///
/// See [`register_session`]'s example.
pub struct UniqueId(Zeroizing<String>);

impl UniqueId {
    /// The unique id's text, for use in a request that must carry it (e.g.
    /// [`gen_token`](crate::gen_token)).
    ///
    /// # Examples
    ///
    /// See [`register_session`]'s example.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for UniqueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UniqueId(redacted)")
    }
}

/// The disposition [`register_session`] resolved to.
///
/// # Examples
///
/// See [`register_session`]'s example.
#[derive(Debug)]
pub enum Registration {
    /// The session registered. The game is current if `pending_patches` is empty, or has a chain
    /// of patches to apply otherwise.
    Registered {
        /// The credential authorizing patch downloads.
        unique_id: UniqueId,
        /// Pending game patches, in application order. Empty when the game is already current.
        pending_patches: Vec<PatchListEntry>,
    },
    /// The boot component must be patched before the game can register (SE answered `409`).
    NeedsBootPatch,
    /// The installed game version is no longer serviced (SE answered `410`).
    VersionNotServiced,
}

/// Report the installed version named by `report` under `auth`'s session, registering it with SE.
///
/// Classifies the response by the reference launcher's branch order: `409` is a pending boot
/// patch, `410` an unserviced version, an `X-Patch-Unique-Id` header a registration (with any
/// pending game patches parsed from the body), and anything else a
/// [`ProtoError::InvalidResponse`]. The status is not otherwise gated: a current game answers `204
/// No Content` and a pending one a `200` with a patchlist (both observed against the live
/// service), so the UID header, not a specific status, marks success.
///
/// # Errors
///
/// Returns [`ProtoError::Transport`] if the request could not be sent. Returns
/// [`ProtoError::InvalidResponse`] if SE answers with neither `409`/`410` nor an
/// `X-Patch-Unique-Id` header, or if a `200`/`204` body carrying pending patches fails to parse.
///
/// # Examples
///
/// A full login-to-registration flow, showing how [`Authenticated`] and [`UniqueId`] are actually
/// obtained (both require a prior step; neither has a public constructor):
///
/// ```
/// # fn block_on<F: std::future::Future>(fut: F) -> F::Output {
/// #     let mut fut = std::pin::pin!(fut);
/// #     let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
/// #     loop {
/// #         if let std::task::Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
/// #             return val;
/// #         }
/// #     }
/// # }
/// use std::sync::atomic::{AtomicU32, Ordering};
///
/// use sqex_proto::{
///     ClientContext, ComputerId, Credentials, LauncherTime, LoginKind, OauthContext,
///     ProtoRequest, ProtoResponse, Registration, Transport, TransportError, VersionReport,
///     begin_login, register_session,
/// };
///
/// // A scripted transport: top page, then the login callback, then the registration response.
/// struct ScriptedSession(AtomicU32);
///
/// #[async_trait::async_trait]
/// impl Transport for ScriptedSession {
///     async fn execute(&self, _req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
///         Ok(match self.0.fetch_add(1, Ordering::SeqCst) {
///             0 => ProtoResponse::new(
///                 200,
///                 r#"<input type="hidden" name="_STORED_" value="opaqueblob">"#
///                     .as_bytes()
///                     .to_vec(),
///             ),
///             1 => ProtoResponse::new(
///                 200,
///                 "window.external.user(\"login=auth,ok,sid,abc123,terms,1,region,2,x,x,\
///                  playable,1,x,x,maxex,3\")"
///                     .as_bytes()
///                     .to_vec(),
///             ),
///             _ => ProtoResponse::new(200, Vec::new())
///                 .with_header(http::HeaderName::from_static("x-patch-unique-id"), "uid123".parse().unwrap()),
///         })
///     }
/// }
///
/// let transport = ScriptedSession(AtomicU32::new(0));
/// let id = ComputerId::from_facts("host", "user", "os", 4);
/// let context = OauthContext {
///     client: ClientContext {
///         computer_id: &id,
///         language: "en-us",
///         accept_language: "en-us,en;q=0.9",
///         referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
///     },
///     lng: "en",
///     region: 3,
/// };
/// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
/// let flow = block_on(begin_login(&transport, &context, &now, LoginKind::Standard { free_trial: false }))
///     .unwrap();
/// let creds = Credentials {
///     sqexid: "player1",
///     password: "hunter2",
///     otp: None,
/// };
/// let authenticated = block_on(flow.submit(creds)).unwrap();
///
/// let hashes = std::array::from_fn(|i| (i as u64, format!("{i:040x}")));
/// let report = VersionReport::from_parts("2024.03.01.0000.0000".to_owned(), "b", hashes, &[]);
/// let registration = block_on(register_session(&transport, &authenticated, &report)).unwrap();
/// match registration {
///     Registration::Registered { unique_id, pending_patches } => {
///         assert_eq!(unique_id.expose(), "uid123");
///         assert!(pending_patches.is_empty());
///     }
///     _ => panic!("expected Registered"),
/// }
/// ```
pub async fn register_session(
    transport: &dyn Transport,
    auth: &Authenticated,
    report: &VersionReport,
) -> Result<Registration, ProtoError> {
    let request = build_request(auth, report)?;
    let response = transport.execute(request).await?;

    match response.status {
        409 => Ok(Registration::NeedsBootPatch),
        410 => Ok(Registration::VersionNotServiced),
        _ => match unique_id(&response) {
            Some(unique_id) => {
                // An empty body means the game is current; anything else is a game patchlist. This is
                // exact-empty (not whitespace-trimmed), so a stray non-empty body fails loudly in the
                // parser rather than being read as "current" - except for a leading byte-order mark,
                // stripped first the same way `check_boot_version` strips one (`bootver.rs`), so a
                // BOM-only body reads as empty instead of reaching the parser and failing with
                // "patchlist too short".
                let decoded = String::from_utf8_lossy(&response.body);
                let body = decoded.strip_prefix('\u{feff}').unwrap_or(&decoded);
                let pending_patches = if body.is_empty() {
                    Vec::new()
                } else {
                    parse_patch_list(body)?
                };
                Ok(Registration::Registered {
                    unique_id,
                    pending_patches,
                })
            }
            // The request URL carries the live session id as its last path segment, so a response
            // that reflects it back (a 404 page naming what it could not find) would carry the id
            // into the excerpt.
            None => Err(ProtoError::invalid_response(
                Step::Register,
                &response,
                &[auth.session_id().expose()],
            )),
        },
    }
}

fn unique_id(response: &ProtoResponse) -> Option<UniqueId> {
    let header = HeaderName::from_static(UNIQUE_ID_HEADER);
    let value = response.header(&header)?;
    let text = value.to_str().ok().filter(|text| !text.trim().is_empty())?;
    Some(UniqueId(Zeroizing::new(text.to_owned())))
}

// Headers match the exact set and order the reference launcher sends: no Host (the transport supplies
// it) and no Content-Type. `accept`/`accept-encoding` are the one exception: see bootver.rs's
// build_request and crate::NEGOTIATED_HEADERS for why the identical `*/*` is declared despite the
// reference sending neither.
fn build_request(
    auth: &Authenticated,
    report: &VersionReport,
) -> Result<ProtoRequest, TransportError> {
    let mut url = parse_base(GAME_VERSION_BASE, "invalid game-version base URL")?;
    url.path_segments_mut()
        .map_err(|()| TransportError::new("game-version base URL cannot be a base"))?
        .push(report.game_version())
        .push(auth.session_id().expose());

    Ok(ProtoRequest::new(Method::POST, url)
        .header(
            HeaderName::from_static("connection"),
            HeaderValue::from_static("Keep-Alive"),
        )
        .header(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static(PATCHER_USER_AGENT),
        )
        .header(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("*/*"),
        )
        .header(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate"),
        )
        .header(
            HeaderName::from_static("x-hash-check"),
            HeaderValue::from_static("enabled"),
        )
        .body(RequestBody::new(report.body().as_bytes().to_vec())))
}
