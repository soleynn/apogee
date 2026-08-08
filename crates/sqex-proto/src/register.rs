// Session registration: the version-report POST and the UID handshake. After login, the client
// reports its installed version to patch-gamever and, if the game is current, receives an
// X-Patch-Unique-Id that authorizes patch downloads. The dispositions SE can answer with are modeled
// as Registration values (a boot patch is pending, the version is no longer serviced, or the session
// is registered with any pending game patches); only a response that fits none of them is a
// ProtoError.

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

pub struct UniqueId(Zeroizing<String>);

impl UniqueId {
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

#[derive(Debug)]
pub enum Registration {
    Registered {
        unique_id: UniqueId,
        pending_patches: Vec<PatchListEntry>,
    },
    NeedsBootPatch,
    VersionNotServiced,
}

// Classifies the response by the reference launcher's branch order: 409 is a pending boot patch, 410
// an unserviced version, an X-Patch-Unique-Id header a registration (with any pending game patches
// parsed from the body), and anything else a ProtoError::InvalidResponse. The status is not otherwise
// gated: a current game answers 204 No Content and a pending one a 200 with a patchlist (both observed
// against the live service), so the UID header, not a specific status, marks success.
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
