//! Session registration: the version-report POST and the UID handshake.
//!
//! After login, the client reports its installed version to `patch-gamever` and, if the game is
//! current, receives an `X-Patch-Unique-Id` that authorizes patch downloads. The dispositions SE can
//! answer with are modeled as [`Registration`] values (a boot patch is pending, the version is no
//! longer serviced, or the session is registered with any pending game patches); only a response that
//! fits none of them is a [`ProtoError`].

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

/// Base of the session-registration endpoint; the game version and session id are appended as path
/// segments. HTTPS: the report and the issued UID authorize patch downloads.
const GAME_VERSION_BASE: &str = "https://patch-gamever.ffxiv.com/http/win32/ffxivneo_release_game";

/// The response header carrying the patch-download credential.
const UNIQUE_ID_HEADER: &str = "x-patch-unique-id";

/// The patch-download credential issued at registration. Zeroized on drop, redacted in `Debug`, and
/// never serialized; downstream reads it into patch requests via [`UniqueId::expose`].
pub struct UniqueId(Zeroizing<String>);

impl UniqueId {
    /// The raw unique id. Secret-adjacent (it authorizes patch downloads), so callers must not persist
    /// or log it.
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

/// The outcome of session registration. Each arm is an expected disposition the caller narrates, not a
/// failure: [`Registration::Registered`] carries the UID and any pending game patches (empty when the
/// game is current); [`Registration::NeedsBootPatch`] and [`Registration::VersionNotServiced`] end the
/// flow with no UID.
#[derive(Debug)]
pub enum Registration {
    /// The session is registered. `pending_patches` is empty when the game is current, else the game
    /// patches to apply, in list order.
    Registered {
        /// The patch-download credential.
        unique_id: UniqueId,
        /// Pending game patches, in list order; empty when the game is current.
        pending_patches: Vec<PatchListEntry>,
    },
    /// Boot needs patching (or the boot EXEs were tampered with); no UID is issued.
    NeedsBootPatch,
    /// This game version is no longer serviced; terminal.
    VersionNotServiced,
}

/// Register the session with a version report, returning SE's disposition.
///
/// Posts `report` to `patch-gamever` under the login's session id and classifies the response by the
/// reference launcher's branch order: `409` is a pending boot patch, `410` an unserviced version, an
/// `X-Patch-Unique-Id` header a registration (with any pending game patches parsed from the body), and
/// anything else a [`ProtoError::InvalidResponse`]. The status is not otherwise gated: a current game
/// answers `204 No Content` and a pending one a `200` with a patchlist (both observed against the live
/// service), so the UID header, not a specific status, marks success.
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
                // parser rather than being read as "current".
                let pending_patches = if response.body.is_empty() {
                    Vec::new()
                } else {
                    let body = String::from_utf8_lossy(&response.body);
                    parse_patch_list(&body)?
                };
                Ok(Registration::Registered {
                    unique_id,
                    pending_patches,
                })
            }
            None => Err(ProtoError::invalid_response(Step::Register, &response)),
        },
    }
}

/// Read the `X-Patch-Unique-Id` header into a redacted newtype. A header value that is not visible
/// ASCII is treated as absent (defensive: a real UID is hex).
fn unique_id(response: &ProtoResponse) -> Option<UniqueId> {
    let header = HeaderName::from_static(UNIQUE_ID_HEADER);
    let value = response.header(&header)?;
    let text = value.to_str().ok()?;
    Some(UniqueId(Zeroizing::new(text.to_owned())))
}

/// Build the registration POST: `{base}/{gamever}/{sessionId}` with the patcher identity and the
/// report body. Headers are the exact set and order the reference launcher sends: no `Host` (the
/// transport supplies it) and no `Content-Type`.
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
            HeaderName::from_static("x-hash-check"),
            HeaderValue::from_static("enabled"),
        )
        .body(RequestBody::new(report.body().as_bytes().to_vec())))
}
