//! Per-request HTTP header policy.
//!
//! Different downloads want different request headers: a Square Enix patch chunk must carry the
//! game's patch-client `User-Agent` (and, for a session-bound game patch, its unique id), while an
//! Apogee artifact fetch carries none of that. The policy rides on the [`DownloadSpec`] and is applied
//! per request, never on the shared client, so one spec's headers never leak onto another's transfer.
//!
//! [`DownloadSpec`]: crate::DownloadSpec

use reqwest::RequestBuilder;
use reqwest::header::USER_AGENT;

/// The `User-Agent` Square Enix's patch delivery expects on every patch request.
const SE_PATCH_USER_AGENT: &str = "FFXIV PATCH CLIENT";
/// The session-scoped patch identifier a game-patch request may carry.
const X_PATCH_UNIQUE_ID: &str = "X-Patch-Unique-Id";

/// How a download's requests are decorated with HTTP headers. Selected on the
/// [`DownloadSpec`](crate::DownloadSpec); `None` there means no extra headers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HeaderPolicy {
    /// Square Enix patch delivery: `User-Agent: FFXIV PATCH CLIENT`, plus the session's
    /// `X-Patch-Unique-Id` when one is supplied (game patches carry it; boot patches do not).
    SePatch { unique_id: Option<String> },
    /// An Apogee artifact fetch (runner, component, manifest): no Square Enix headers.
    Manifest,
    /// Caller-supplied header name/value pairs, applied verbatim.
    Custom(Vec<(String, String)>),
}

/// Apply `policy` to a request builder. Header names here never collide with the `Range`/`If-Range`
/// the transfer sets, so ordering against those is irrelevant.
#[allow(dead_code)] // wired at the request-construction sites with the engine changes
pub(crate) fn apply_headers(mut req: RequestBuilder, policy: Option<&HeaderPolicy>) -> RequestBuilder {
    match policy {
        Some(HeaderPolicy::SePatch { unique_id }) => {
            req = req.header(USER_AGENT, SE_PATCH_USER_AGENT);
            if let Some(id) = unique_id {
                req = req.header(X_PATCH_UNIQUE_ID, id);
            }
        }
        Some(HeaderPolicy::Manifest) | None => {}
        Some(HeaderPolicy::Custom(pairs)) => {
            for (name, value) in pairs {
                req = req.header(name.as_str(), value.as_str());
            }
        }
    }
    req
}
