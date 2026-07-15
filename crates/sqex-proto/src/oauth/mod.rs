//! The OAuth login flow.
//!
//! Login is two coupled requests. The top page (`begin_login`) yields an opaque `_STORED_` blob and
//! the server `Date`; the submit (`LoginFlow::submit`) echoes `_STORED_` back with the credentials and
//! returns the `launchParams` callback, parsed into a typed [`Authenticated`]. Because step two needs
//! state from step one, the two live behind a flow object that borrows the transport rather than two
//! free functions the caller would have to thread state between.
//!
//! Credentials pass through borrowed memory only ([`Credentials`]), are written once into a zeroizing
//! request body, and never land in an owned struct or an error excerpt. The session id is redacted in
//! `Debug` and never serialized. Expected dispositions (no service, terms not yet accepted) are booleans
//! on [`Authenticated`], not errors.

use std::fmt;

use http::{HeaderName, HeaderValue, Method};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use url::Url;
use zeroize::Zeroizing;

use crate::error::{ProtoError, Step, scrubbed_excerpt};
use crate::identity::ClientContext;
use crate::time::LauncherTime;
use crate::transport::{
    ProtoRequest, ProtoResponse, RequestBody, Transport, TransportError, dynamic_header, parse_base,
};

mod scan;
#[cfg(test)]
mod tests;

use scan::{CallbackReject, is_restartup, parse_login_callback};
pub use scan::{LaunchParams, parse_launch_params, scrape_stored};

const TOP_URL: &str = "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/top";
const LOGIN_SEND_URL: &str = "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/login.send";
/// The fixed IE-era `Accept:` the launcher's embedded browser control sends. It is part of the
/// fingerprint, so it is reproduced verbatim.
const OAUTH_ACCEPT: &str = "image/gif, image/jpeg, image/pjpeg, application/x-ms-application, \
    application/xaml+xml, application/x-ms-xbap, */*";
const RSID_COOKIE: &str = "_rsid=\"\"";
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// The RFC 3986 unreserved set: everything else is percent-encoded. The launcher escapes form fields
/// this way (SE's `EscapeDataString`), not with `+`-for-space form encoding.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The per-install, per-locale values a login carries.
pub struct OauthContext<'a> {
    /// The shared client identity and locale plumbing.
    pub client: ClientContext<'a>,
    /// The top-page `lng` query value (XL sends `en`).
    pub lng: &'a str,
    /// The top-page `rgn` query value (XL sends `3`).
    pub region: u16,
}

/// Which login variant to begin. `#[non_exhaustive]` so a Steam variant can join without a break.
#[derive(Clone)]
#[non_exhaustive]
pub enum LoginKind {
    /// A standard username/password (optionally OTP) login. `free_trial` sets the top-page `isft` flag.
    Standard { free_trial: bool },
}

/// Borrowed login credentials. Deliberately implements no `Debug`/`Clone`/`Serialize`: it is borrowed
/// only to build the one submit body and never stored, so it cannot appear in a log or an error.
pub struct Credentials<'a> {
    pub sqexid: &'a str,
    pub password: &'a str,
    pub otp: Option<&'a str>,
}

/// The OAuth session id. Zeroized on drop, redacted in `Debug`, and never serialized; the next stage
/// reads it into a URL path segment via [`SessionId::expose`].
pub struct SessionId(Zeroizing<String>);

impl SessionId {
    /// The raw session id. Secret-adjacent (it authorizes the next stage), so callers must not persist
    /// or log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(redacted)")
    }
}

/// A completed login. Constructed only with a session id, so an authenticated-but-no-session state is
/// unrepresentable. `playable` and `terms_accepted` are expected dispositions the caller narrates, not
/// errors.
#[derive(Debug)]
pub struct Authenticated {
    session_id: SessionId,
    pub region: u16,
    pub max_expansion: u8,
    pub playable: bool,
    pub terms_accepted: bool,
}

impl Authenticated {
    /// The OAuth session id.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

/// A login in progress: the state step two needs, plus the borrowed transport it runs on. Holds the
/// `_STORED_` blob in zeroizing memory and never prints it.
pub struct LoginFlow<'t> {
    transport: &'t dyn Transport,
    top_url: Url,
    stored: Zeroizing<String>,
    server_date: Option<String>,
    steam_linked_id: Option<String>,
    user_agent: String,
    accept_language: String,
}

impl fmt::Debug for LoginFlow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginFlow")
            .field("server_date", &self.server_date)
            .field("steam_linked", &self.steam_linked_id.is_some())
            .finish_non_exhaustive()
    }
}

impl LoginFlow<'_> {
    /// The top page's `Date` response header, if the transport surfaced it. An upstream consumer uses
    /// it to generate an OTP with clock-skew correction before [`LoginFlow::submit`].
    #[must_use]
    pub fn server_date(&self) -> Option<&str> {
        self.server_date.as_deref()
    }

    /// The Steam-linked SE id scraped from the top page, if any. Always `None` for a standard login.
    #[must_use]
    pub fn steam_linked_id(&self) -> Option<&str> {
        self.steam_linked_id.as_deref()
    }

    /// Submit the credentials and parse the login result.
    ///
    /// The credentials are written once into a zeroizing form body and dropped when this returns. A
    /// non-success callback is [`ProtoError::OauthFailed`] with an excerpt scrubbed of the submitted
    /// credentials; a malformed `launchParams` list is [`ProtoError::LaunchParamsUnparseable`].
    pub async fn submit(&self, creds: Credentials<'_>) -> Result<Authenticated, ProtoError> {
        let otp = creds.otp.unwrap_or("");

        // Assemble the form body directly into zeroizing memory, percent-encoding each field.
        let mut body = Zeroizing::new(String::with_capacity(256));
        body.push_str("_STORED_=");
        body.extend(utf8_percent_encode(self.stored.as_str(), UNRESERVED));
        body.push_str("&sqexid=");
        body.extend(utf8_percent_encode(creds.sqexid, UNRESERVED));
        body.push_str("&password=");
        body.extend(utf8_percent_encode(creds.password, UNRESERVED));
        body.push_str("&otppw=");
        body.extend(utf8_percent_encode(otp, UNRESERVED));

        let request = self.build_login_request(RequestBody::new(body.as_bytes().to_vec()))?;
        let response = self.transport.execute(request).await?;

        if !response.is_ok() {
            return Err(ProtoError::InvalidResponse {
                step: Step::OauthLogin,
                status: response.status,
                excerpt: scrubbed_excerpt(
                    &response.body,
                    &[creds.sqexid, creds.password, otp, self.stored.as_str()],
                ),
            });
        }

        let text = String::from_utf8_lossy(&response.body);
        match parse_login_callback(&text) {
            Ok(params) => Ok(Authenticated {
                session_id: SessionId(params.session_id),
                region: params.region,
                max_expansion: params.max_expansion,
                playable: params.playable,
                terms_accepted: params.terms_accepted,
            }),
            Err(CallbackReject::NotAuthOk { message }) => {
                // Surface only SE's own structured failure message (still scrubbed, as defense in
                // depth), never the raw response page. The raw page is attacker-influenced and could
                // reflect a submitted credential in a re-encoded form a verbatim scrub misses, and it
                // carries no triage the structured message lacks. No login callback at all yields an
                // empty excerpt.
                let excerpt = message
                    .map(|m| {
                        scrubbed_excerpt(
                            m.as_bytes(),
                            &[creds.sqexid, creds.password, otp, self.stored.as_str()],
                        )
                    })
                    .unwrap_or_default();
                Err(ProtoError::OauthFailed { excerpt })
            }
            Err(CallbackReject::Unparseable { got_fields }) => {
                Err(ProtoError::LaunchParamsUnparseable { got_fields })
            }
        }
    }

    /// The launcher's submit header set, in order. The referer is the step-one URL verbatim.
    fn build_login_request(&self, body: RequestBody) -> Result<ProtoRequest, TransportError> {
        let url = parse_base(LOGIN_SEND_URL, "invalid login URL")?;
        Ok(ProtoRequest::new(Method::POST, url)
            .header(
                HeaderName::from_static("user-agent"),
                dynamic_header(&self.user_agent)?,
            )
            .header(
                HeaderName::from_static("accept"),
                HeaderValue::from_static(OAUTH_ACCEPT),
            )
            .header(
                HeaderName::from_static("accept-encoding"),
                HeaderValue::from_static("gzip, deflate"),
            )
            .header(
                HeaderName::from_static("accept-language"),
                dynamic_header(&self.accept_language)?,
            )
            .header(
                HeaderName::from_static("cookie"),
                HeaderValue::from_static(RSID_COOKIE),
            )
            .header(
                HeaderName::from_static("referer"),
                dynamic_header(self.top_url.as_str())?,
            )
            .header(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static(FORM_CONTENT_TYPE),
            )
            .body(body))
    }
}

/// Fetch the login top page: build the fingerprinted request, then lift `_STORED_`, the server `Date`,
/// and the Steam-relink signal out of the response.
pub async fn begin_login<'t>(
    transport: &'t dyn Transport,
    context: &OauthContext<'_>,
    now: &LauncherTime,
    kind: LoginKind,
) -> Result<LoginFlow<'t>, ProtoError> {
    let LoginKind::Standard { free_trial } = kind;

    let (user_agent, referer) = context.client.user_agent_and_referer(now);

    let top_url = build_top_url(context, free_trial)?;
    let request = build_top_request(
        top_url.clone(),
        &user_agent,
        context.client.accept_language,
        &referer,
    )?;
    let response = transport.execute(request).await?;

    if !response.is_ok() {
        return Err(ProtoError::invalid_response(Step::OauthTop, &response));
    }

    let text = String::from_utf8_lossy(&response.body);

    // A standard login sends no Steam ticket, so `restartup` here is an anomalous response, not the
    // Steam relink signal (which the Steam variant maps to `SteamLinkNeeded`).
    if is_restartup(&text) {
        return Err(ProtoError::invalid_response(Step::OauthTop, &response));
    }

    let stored = scrape_stored(&text)?.to_owned();
    let server_date = read_date(&response);

    Ok(LoginFlow {
        transport,
        top_url,
        stored: Zeroizing::new(stored),
        server_date,
        steam_linked_id: None,
        user_agent,
        accept_language: context.client.accept_language.to_owned(),
    })
}

fn build_top_url(context: &OauthContext<'_>, free_trial: bool) -> Result<Url, TransportError> {
    let mut url = parse_base(TOP_URL, "invalid top URL")?;
    url.query_pairs_mut()
        .append_pair("lng", context.lng)
        .append_pair("rgn", &context.region.to_string())
        .append_pair("isft", if free_trial { "1" } else { "0" })
        .append_pair("cssmode", "1")
        .append_pair("isnew", "1")
        .append_pair("launchver", "3");
    Ok(url)
}

/// The launcher's top-page header set, in order.
fn build_top_request(
    url: Url,
    user_agent: &str,
    accept_language: &str,
    referer: &str,
) -> Result<ProtoRequest, TransportError> {
    Ok(ProtoRequest::new(Method::GET, url)
        .header(
            HeaderName::from_static("user-agent"),
            dynamic_header(user_agent)?,
        )
        .header(
            HeaderName::from_static("accept"),
            HeaderValue::from_static(OAUTH_ACCEPT),
        )
        .header(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate"),
        )
        .header(
            HeaderName::from_static("accept-language"),
            dynamic_header(accept_language)?,
        )
        .header(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static(RSID_COOKIE),
        )
        .header(HeaderName::from_static("referer"), dynamic_header(referer)?))
}

/// The `Date` response header as an owned string, if the transport surfaced it.
fn read_date(response: &ProtoResponse) -> Option<String> {
    response
        .header(&http::header::DATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
