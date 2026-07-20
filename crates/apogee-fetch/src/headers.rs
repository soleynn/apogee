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
        Some(HeaderPolicy::Manifest) | None => {}
        Some(HeaderPolicy::Custom(pairs)) => {
            for (name, value) in pairs {
                req = req.header(name.as_str(), value.as_str());
            }
        }
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
        let with_id = applied(Some(&HeaderPolicy::SePatch {
            unique_id: Some("abc".to_owned()),
        }));
        assert_eq!(with_id.get(USER_AGENT).unwrap(), SE_PATCH_USER_AGENT);
        assert_eq!(with_id.get(X_PATCH_UNIQUE_ID).unwrap(), "abc");

        let no_id = applied(Some(&HeaderPolicy::SePatch { unique_id: None }));
        assert_eq!(no_id.get(USER_AGENT).unwrap(), SE_PATCH_USER_AGENT);
        assert!(no_id.get(X_PATCH_UNIQUE_ID).is_none());
    }

    #[test]
    fn custom_applies_each_pair_verbatim() {
        let headers = applied(Some(&HeaderPolicy::Custom(vec![
            ("X-A".to_owned(), "1".to_owned()),
            ("X-B".to_owned(), "2".to_owned()),
        ])));
        assert_eq!(headers.get("x-a").unwrap(), "1");
        assert_eq!(headers.get("x-b").unwrap(), "2");
    }

    #[test]
    fn manifest_and_none_add_no_user_agent() {
        assert!(
            applied(Some(&HeaderPolicy::Manifest))
                .get(USER_AGENT)
                .is_none()
        );
        assert!(applied(None).get(USER_AGENT).is_none());
    }
}
