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
use sqex_crypto::ObfuscatedTicket;
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

use scan::{CallbackReject, is_restartup, parse_login_callback, scrape_steam_id};
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

/// Which login variant to begin. `#[non_exhaustive]` so a further variant can join without a break.
///
/// Not `Clone`: the Steam arm owns a bearer ticket that deliberately cannot be copied.
#[non_exhaustive]
pub enum LoginKind {
    /// A standard username/password (optionally OTP) login. `free_trial` sets the top-page `isft` flag.
    Standard { free_trial: bool },
    /// A Steam service account. The ticket rides in the top-page query and the page answers with the
    /// SE account it is linked to, which [`LoginFlow::submit`] checks the submitted username against.
    /// `free_trial` is independent of the ticket: the launcher sets `isft` from the app id it
    /// initialized Steam with, and sends both flags together.
    Steam {
        ticket: ObfuscatedTicket,
        free_trial: bool,
    },
}

impl LoginKind {
    /// The top-page `isft` flag for this variant.
    fn free_trial(&self) -> bool {
        match self {
            Self::Standard { free_trial } | Self::Steam { free_trial, .. } => *free_trial,
        }
    }

    /// The ticket a Steam login carries, or `None` for a standard one.
    fn ticket(&self) -> Option<&ObfuscatedTicket> {
        match self {
            Self::Standard { .. } => None,
            Self::Steam { ticket, .. } => Some(ticket),
        }
    }
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
    /// credentials; a malformed `launchParams` list is [`ProtoError::LaunchParamsUnparseable`]. On a
    /// Steam login a username naming a different account than the ticket's is
    /// [`ProtoError::SteamWrongAccount`], raised before anything is sent.
    pub async fn submit(&self, creds: Credentials<'_>) -> Result<Authenticated, ProtoError> {
        let otp = creds.otp.unwrap_or("");
        let sqexid = self.submitted_username(creds.sqexid)?;

        // Assemble the form body directly into zeroizing memory, percent-encoding each field.
        let mut body = Zeroizing::new(String::with_capacity(256));
        body.push_str("_STORED_=");
        body.extend(utf8_percent_encode(self.stored.as_str(), UNRESERVED));
        body.push_str("&sqexid=");
        body.extend(utf8_percent_encode(sqexid, UNRESERVED));
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
                    // Both usernames: a Steam login submits the page's own id, which differs from the
                    // caller's by case, and a verbatim scrub matches neither for the other.
                    &[
                        sqexid,
                        creds.sqexid,
                        creds.password,
                        otp,
                        self.stored.as_str(),
                    ],
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
                            // Both usernames: a Steam login submits the page's own id, which differs from the
                            // caller's by case, and a verbatim scrub matches neither for the other.
                            &[
                                sqexid,
                                creds.sqexid,
                                creds.password,
                                otp,
                                self.stored.as_str(),
                            ],
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

    /// The username this flow submits, given the one the caller offered.
    ///
    /// A standard login submits the caller's. A Steam login submits the id the top page reported the
    /// ticket is linked to, having first checked the caller meant that account: the ticket already
    /// decides which SE account the login lands on, so submitting a different username would either
    /// fail confusingly or sign the user into an account they did not pick. The comparison is
    /// case-insensitive, matching the launcher (`Launcher.cs:572`), because SE ids are.
    ///
    /// # Errors
    ///
    /// [`ProtoError::SteamWrongAccount`] when the two name different accounts, carrying only a masked
    /// hint: the linked id is another account's identifier and the caller has just proved they do not
    /// know it.
    fn submitted_username<'a>(&'a self, offered: &'a str) -> Result<&'a str, ProtoError> {
        let Some(linked) = self.steam_linked_id.as_deref() else {
            return Ok(offered);
        };
        if linked.eq_ignore_ascii_case(offered) {
            Ok(linked)
        } else {
            Err(ProtoError::SteamWrongAccount {
                expected_hint: mask_id(linked),
            })
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
    let (user_agent, referer) = context.client.user_agent_and_referer(now);

    let top_url = build_top_url(context, &kind)?;
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
    let steam = kind.ticket().is_some();

    if is_restartup(&text) {
        // With a ticket on the query this is SE saying the Steam account has no SE account behind it,
        // the one disposition a user can act on. Without one there was no account to link, so the same
        // page is an anomalous response rather than a relink prompt.
        return Err(if steam {
            ProtoError::SteamLinkNeeded
        } else {
            ProtoError::invalid_response(Step::OauthTop, &response)
        });
    }

    // Read before `_STORED_` so a Steam page that answers without an id fails before the flow exists
    // to submit credentials through. An id is the only thing the submitted username can be checked
    // against, and the launcher submits the id itself, so there is nothing to send without one.
    let steam_linked_id = if steam {
        Some(
            scrape_steam_id(&text)
                .ok_or_else(|| ProtoError::invalid_response(Step::OauthTop, &response))?
                .to_owned(),
        )
    } else {
        None
    };

    let stored = scrape_stored(&text)?.to_owned();
    let server_date = read_date(&response);

    Ok(LoginFlow {
        transport,
        top_url,
        stored: Zeroizing::new(stored),
        server_date,
        steam_linked_id,
        user_agent,
        accept_language: context.client.accept_language.to_owned(),
    })
}

fn build_top_url(context: &OauthContext<'_>, kind: &LoginKind) -> Result<Url, TransportError> {
    let mut url = parse_base(TOP_URL, "invalid top URL")?;
    url.query_pairs_mut()
        .append_pair("lng", context.lng)
        .append_pair("rgn", &context.region.to_string())
        .append_pair("isft", if kind.free_trial() { "1" } else { "0" })
        .append_pair("cssmode", "1")
        .append_pair("isnew", "1")
        .append_pair("launchver", "3");

    if let Some(ticket) = kind.ticket() {
        // Appended to the query text rather than through the form-encoding serializer above, which
        // would escape the chunk separator (`,` becomes `%2C`; the padding `*` it happens to leave
        // alone). The launcher concatenates the ticket in verbatim, and SE compares what arrives
        // against what it issued, so an escaped separator is a rejected login. Re-setting the query
        // re-encodes nothing: what `set_query` escapes (space, `"`, `#`, `<`, `>`, controls) appears
        // neither in what the serializer emitted above nor in the ticket, whose alphabet is base64's
        // with `-_*` and the separator.
        let mut query = url.query().unwrap_or_default().to_owned();
        query.push_str("&issteam=1&session_ticket=");
        query.push_str(ticket.text());
        query.push_str("&ticket_size=");
        query.push_str(&ticket.length().to_string());
        url.set_query(Some(&query));
    }

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

/// A recognizable but non-disclosing form of an account id: its first and last characters around a
/// fixed mask.
///
/// Fixed rather than one `*` per hidden character, so the hint does not report the id's length, and
/// nothing under three characters survives at all. The user is being told which account the ticket
/// belongs to; the id itself belongs to whoever linked it and is not the caller's to read back.
fn mask_id(id: &str) -> String {
    let mut chars = id.chars();
    match (chars.next(), chars.next_back()) {
        (Some(first), Some(last)) if id.chars().count() > 2 => format!("{first}***{last}"),
        _ => "***".to_owned(),
    }
}

/// The `Date` response header as an owned string, if the transport surfaced it.
fn read_date(response: &ProtoResponse) -> Option<String> {
    response
        .header(&http::header::DATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
