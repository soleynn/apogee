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
/// [`DownloadSpec`](crate::DownloadSpec); `None` there means no extra headers, which is what every
/// Apogee artifact fetch (runner, component, manifest) uses.
///
/// One variant today, and both the enum and the variant's field list stay open: the next header
/// Square Enix delivery may want (a per-patch token, say) lands as a field or a variant here without
/// a breaking change. Two variants that never grew a caller (a no-op artifact policy, a verbatim
/// name/value list) were removed before this surface froze; under `#[non_exhaustive]`, re-adding one
/// is additive if a caller ever appears.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HeaderPolicy {
    /// Square Enix patch delivery: `User-Agent: FFXIV PATCH CLIENT`, plus the session's
    /// `X-Patch-Unique-Id` when one is supplied (game patches carry it; boot patches do not).
    /// Constructed through [`se_patch`](Self::se_patch): the field list is `#[non_exhaustive]`, so
    /// a later header input widens the constructor rather than breaking every literal.
    #[non_exhaustive]
    SePatch {
        /// The session's `X-Patch-Unique-Id`; `None` for a boot patch, which carries none.
        unique_id: Option<String>,
    },
}

impl HeaderPolicy {
    /// The Square Enix patch-delivery policy, carrying the session's `X-Patch-Unique-Id` when one is
    /// supplied (game patches carry it; boot patches pass `None`).
    #[must_use]
    pub fn se_patch(unique_id: Option<String>) -> Self {
        Self::SePatch { unique_id }
    }
}

/// Apply `policy` to a request builder. No policy sets `Range`/`If-Range`, so ordering against the
/// headers the transfer itself adds is irrelevant.
pub(crate) fn apply_headers(
    mut req: RequestBuilder,
    policy: Option<&HeaderPolicy>,
) -> RequestBuilder {
    match policy {
        Some(HeaderPolicy::SePatch { unique_id }) => {
            req = req.header(USER_AGENT, SE_PATCH_USER_AGENT);
            if let Some(id) = unique_id {
                req = req.header(X_PATCH_UNIQUE_ID, id);
            }
        }
        None => {}
    }
    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;

    /// The headers `apply_headers` would put on a request under `policy`.
    fn applied(policy: Option<&HeaderPolicy>) -> HeaderMap {
        let req = apply_headers(reqwest::Client::new().get("http://host.invalid/f"), policy)
            .build()
            .unwrap();
        req.headers().clone()
    }

    #[test]
    fn se_patch_sets_the_patch_client_ua_and_optional_unique_id() {
        let with_id = applied(Some(&HeaderPolicy::se_patch(Some("abc".to_owned()))));
        assert_eq!(with_id.get(USER_AGENT).unwrap(), SE_PATCH_USER_AGENT);
        assert_eq!(with_id.get(X_PATCH_UNIQUE_ID).unwrap(), "abc");

        let no_id = applied(Some(&HeaderPolicy::se_patch(None)));
        assert_eq!(no_id.get(USER_AGENT).unwrap(), SE_PATCH_USER_AGENT);
        assert!(no_id.get(X_PATCH_UNIQUE_ID).is_none());
    }

    #[test]
    fn no_policy_adds_no_user_agent() {
        assert!(applied(None).get(USER_AGENT).is_none());
    }
}
