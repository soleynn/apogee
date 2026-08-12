//! Per-request HTTP header policy.
//!
//! Applied per request rather than on the shared client, so one download's headers never leak onto
//! another's transfer.

use reqwest::RequestBuilder;
use reqwest::header::USER_AGENT;

/// The `User-Agent` Square Enix's patch delivery expects on every patch request.
const SE_PATCH_USER_AGENT: &str = "FFXIV PATCH CLIENT";
/// The session-scoped patch identifier a game-patch request may carry.
const X_PATCH_UNIQUE_ID: &str = "X-Patch-Unique-Id";

/// How a download's requests are decorated with HTTP headers, selected on
/// [`DownloadSpec`](crate::DownloadSpec). `None` there means no extra headers, which is what every
/// Apogee artifact fetch (runner, component, manifest) uses. `#[non_exhaustive]`: a future header
/// need can land as a new variant without a breaking change.
// A no-op artifact policy and a verbatim name/value-list variant were tried and dropped before this
// surface froze; `#[non_exhaustive]` leaves room to re-add either if a caller ever appears.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HeaderPolicy {
    /// Square Enix patch delivery: `User-Agent: FFXIV PATCH CLIENT`, plus the session's
    /// `X-Patch-Unique-Id` when one is supplied (game patches carry it; boot patches do not).
    /// Constructed only through [`se_patch`](Self::se_patch): its field list is separately
    /// `#[non_exhaustive]`, so a later header input can widen it without a breaking change (the
    /// enum's own `#[non_exhaustive]` already rules out an external literal).
    #[non_exhaustive]
    SePatch {
        /// The session's `X-Patch-Unique-Id`; `None` for a boot patch, which carries none.
        unique_id: Option<String>,
    },
}

impl HeaderPolicy {
    /// The Square Enix patch-delivery policy, carrying the session's `X-Patch-Unique-Id` when one is
    /// supplied (game patches carry it; boot patches pass `None`).
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_fetch::HeaderPolicy;
    ///
    /// let _boot_patch = HeaderPolicy::se_patch(None);
    /// let _game_patch = HeaderPolicy::se_patch(Some("session-id".to_owned()));
    /// ```
    #[must_use]
    pub fn se_patch(unique_id: Option<String>) -> Self {
        Self::SePatch { unique_id }
    }
}

/// Applies `policy` to `req`; no policy sets `Range`/`If-Range`, so calling this before or after a
/// `Range` header doesn't matter.
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

    /// The headers [`apply_headers`] would put on a request under `policy`.
    fn applied(policy: Option<&HeaderPolicy>) -> HeaderMap {
        let req = apply_headers(reqwest::Client::new().get("http://host.invalid/f"), policy)
            .build()
            .unwrap();
        req.headers().clone()
    }

    /// Both branches: the UA is always set, and `X-Patch-Unique-Id` follows `unique_id`.
    #[test]
    fn se_patch_sets_the_patch_client_ua_and_optional_unique_id() {
        let with_id = applied(Some(&HeaderPolicy::se_patch(Some("abc".to_owned()))));
        assert_eq!(with_id.get(USER_AGENT).unwrap(), SE_PATCH_USER_AGENT);
        assert_eq!(with_id.get(X_PATCH_UNIQUE_ID).unwrap(), "abc");

        let no_id = applied(Some(&HeaderPolicy::se_patch(None)));
        assert_eq!(no_id.get(USER_AGENT).unwrap(), SE_PATCH_USER_AGENT);
        assert!(no_id.get(X_PATCH_UNIQUE_ID).is_none());
    }

    /// No policy means no `User-Agent` override.
    #[test]
    fn no_policy_adds_no_user_agent() {
        assert!(applied(None).get(USER_AGENT).is_none());
    }
}
