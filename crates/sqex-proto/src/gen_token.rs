//! `gen_token`: tokenize a patch URL for download.
//!
//! Dormant on the live service: the reference launcher ships this request path disabled ("waiting
//! on SE to patch this"), so nothing has ever observed a real response from it. The request shape
//! [`gen_token`] builds is transcribed from the reference source and nothing more; no disposition
//! beyond "the body is a tokenized URL string" is invented.
//!
//! [`gen_token`] is not called from [`register_session`](crate::register_session) or any other
//! surface in this crate: reaching it is an explicit, opt-in call, and it stays that way until a
//! live response has actually been observed and can be pinned against a fixture the way every other
//! endpoint here is.

use http::{HeaderName, HeaderValue, Method};

use crate::error::{ProtoError, Step};
use crate::identity::PATCHER_USER_AGENT;
use crate::register::UniqueId;
use crate::transport::{
    ProtoRequest, RequestBody, Transport, TransportError, dynamic_header, parse_base,
};

const GEN_TOKEN_URL: &str = "http://patch-gamever.ffxiv.com/gen_token";

const UNIQUE_ID_HEADER: &str = "x-patch-unique-id";

/// Ask SE to tokenize `patch_url`, presenting `unique_id` as the authorizing credential.
///
/// On success, the response body is returned verbatim (lossily decoded) as the tokenized URL;
/// nothing about its shape is validated beyond that, since no real response has ever been captured
/// to validate against.
///
/// # Errors
///
/// Returns [`ProtoError::Transport`] if the request could not be sent, or
/// [`ProtoError::InvalidResponse`] if SE answers with a status other than `200`.
///
/// # Examples
///
/// `UniqueId` has no public constructor; the one used here comes from a scripted
/// [`register_session`](crate::register_session) call, the same as in that function's own example.
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
///     begin_login, gen_token, register_session,
/// };
///
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
///             2 => ProtoResponse::new(200, Vec::new()).with_header(
///                 http::HeaderName::from_static("x-patch-unique-id"),
///                 "uid123".parse().unwrap(),
///             ),
///             _ => ProtoResponse::new(200, b"tokenized-url".to_vec()),
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
/// let Registration::Registered { unique_id, .. } =
///     block_on(register_session(&transport, &authenticated, &report)).unwrap()
/// else {
///     panic!("expected Registered");
/// };
///
/// let tokenized = block_on(gen_token(&transport, &unique_id, "http://example.invalid/patch")).unwrap();
/// assert_eq!(tokenized, "tokenized-url");
/// ```
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
