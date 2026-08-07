//! `gen_token`: tokenize a patch URL for download.
//!
//! Dormant on the live service: the reference launcher ships this request path disabled ("waiting on
//! SE to patch this"), so nothing has ever observed a real response from it. The request shape below
//! (`POST http://patch-gamever.ffxiv.com/gen_token`, the patcher identity, the session's
//! `X-Patch-Unique-Id` as a header, the patch URL as the body) is transcribed from the reference
//! source and nothing more; no disposition beyond "the body is a tokenized URL string" is invented.
//!
//! [`gen_token`] is not called from [`register_session`](crate::register_session) or any other surface
//! in this crate: reaching it is an explicit, opt-in call, and it stays that way until a live response
//! has actually been observed and can be pinned against a fixture the way every other endpoint here is.

use http::{HeaderName, HeaderValue, Method};

use crate::error::{ProtoError, Step};
use crate::identity::PATCHER_USER_AGENT;
use crate::register::UniqueId;
use crate::transport::{
    ProtoRequest, RequestBody, Transport, TransportError, dynamic_header, parse_base,
};

/// The `gen_token` endpoint. Plain HTTP per the reference launcher, unlike the HTTPS `patch-gamever`
/// version-report endpoint it shares a host with.
const GEN_TOKEN_URL: &str = "http://patch-gamever.ffxiv.com/gen_token";

/// The request header carrying the patch-download credential `register_session` issued.
const UNIQUE_ID_HEADER: &str = "x-patch-unique-id";

/// Ask SE to tokenize `patch_url`, presenting `unique_id` as the authorizing credential.
///
/// On success, the response body is returned verbatim (lossily decoded) as the tokenized URL; nothing
/// about its shape is validated beyond that, since no real response has ever been captured to validate
/// against. Any status other than `200 OK` is a [`ProtoError::InvalidResponse`]; the excerpt is scrubbed
/// of `unique_id`, the one secret-adjacent value this step puts on the wire, in case a reflected error
/// page echoes the request headers back.
pub async fn gen_token(
    transport: &dyn Transport,
    unique_id: &UniqueId,
    patch_url: &str,
) -> Result<String, ProtoError> {
    let request = build_request(unique_id, patch_url)?;
    let response = transport.execute(request).await?;

    if !response.is_ok() {
        return Err(ProtoError::invalid_response(
            Step::GenToken,
            &response,
            &[unique_id.expose()],
        ));
    }

    Ok(String::from_utf8_lossy(&response.body).into_owned())
}

/// Build the `gen_token` POST: the patcher identity, the UID header, and `patch_url` as the body.
fn build_request(unique_id: &UniqueId, patch_url: &str) -> Result<ProtoRequest, TransportError> {
    let url = parse_base(GEN_TOKEN_URL, "invalid gen_token URL")?;

    Ok(ProtoRequest::new(Method::POST, url)
        .header(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static(PATCHER_USER_AGENT),
        )
        .header(
            HeaderName::from_static(UNIQUE_ID_HEADER),
            dynamic_header(unique_id.expose())?,
        )
        .body(RequestBody::new(patch_url.as_bytes().to_vec())))
}
