// `gen_token`: tokenize a patch URL for download. Dormant on the live service: the reference launcher
// ships this request path disabled ("waiting on SE to patch this"), so nothing has ever observed a
// real response from it. The request shape below is transcribed from the reference source and nothing
// more; no disposition beyond "the body is a tokenized URL string" is invented.
//
// Not called from register_session or any other surface in this crate: reaching it is an explicit,
// opt-in call, and it stays that way until a live response has actually been observed and can be
// pinned against a fixture the way every other endpoint here is.

use http::{HeaderName, HeaderValue, Method};

use crate::error::{ProtoError, Step};
use crate::identity::PATCHER_USER_AGENT;
use crate::register::UniqueId;
use crate::transport::{
    ProtoRequest, RequestBody, Transport, TransportError, dynamic_header, parse_base,
};

const GEN_TOKEN_URL: &str = "http://patch-gamever.ffxiv.com/gen_token";

const UNIQUE_ID_HEADER: &str = "x-patch-unique-id";

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
