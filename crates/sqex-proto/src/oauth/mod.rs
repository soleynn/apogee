// The OAuth login flow. Login is two coupled requests. The top page (begin_login) yields an opaque
// _STORED_ blob and the server Date; the submit (LoginFlow::submit) echoes _STORED_ back with the
// credentials and returns the launchParams callback, parsed into a typed Authenticated. Because step
// two needs state from step one, the two live behind a flow object that borrows the transport rather
// than two free functions the caller would have to thread state between.
//
// Credentials pass through borrowed memory only (Credentials), are written once into a zeroizing
// request body, and never land in an owned struct or an error excerpt. The session id is redacted in
// Debug and never serialized. Expected dispositions (no service, terms not yet accepted) are booleans
// on Authenticated, not errors.

use std::fmt;
use std::time::SystemTime;

use http::{HeaderName, HeaderValue, Method};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sqex_crypto::ObfuscatedTicket;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{ProtoError, Step, scrubbed_excerpt};
use crate::http_date::parse_http_date;
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
const OAUTH_ACCEPT: &str = "image/gif, image/jpeg, image/pjpeg, application/x-ms-application, \
    application/xaml+xml, application/x-ms-xbap, */*";
const RSID_COOKIE: &str = "_rsid=\"\"";
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
// Both OAuth steps ask to keep the connection, as the reference launcher does on each
// (Launcher.cs:475,566). The submit step alone asks not to be cached (Launcher.cs:567): it is the one
// POST whose answer is a one-shot login result rather than a page.
const KEEP_ALIVE: &str = "Keep-Alive";
const NO_CACHE: &str = "no-cache";

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub struct OauthContext<'a> {
    pub client: ClientContext<'a>,
    pub lng: &'a str,
    pub region: u16,
}

#[non_exhaustive]
pub enum LoginKind {
    Standard {
        free_trial: bool,
    },
    Steam {
        ticket: ObfuscatedTicket,
        free_trial: bool,
    },
}

impl LoginKind {
    fn free_trial(&self) -> bool {
        match self {
            Self::Standard { free_trial } | Self::Steam { free_trial, .. } => *free_trial,
        }
    }

    fn ticket(&self) -> Option<&ObfuscatedTicket> {
        match self {
            Self::Standard { .. } => None,
            Self::Steam { ticket, .. } => Some(ticket),
        }
    }
}

pub struct Credentials<'a> {
    pub sqexid: &'a str,
    pub password: &'a str,
    pub otp: Option<&'a str>,
}

pub struct SessionId(Zeroizing<String>);

impl SessionId {
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

#[derive(Debug)]
pub struct Authenticated {
    session_id: SessionId,
    pub region: u16,
    pub max_expansion: u8,
    pub playable: bool,
    pub terms_accepted: bool,
}

impl Authenticated {
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

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
    #[must_use]
    pub fn server_date(&self) -> Option<&str> {
        self.server_date.as_deref()
    }

    #[must_use]
    pub fn server_time(&self) -> Option<SystemTime> {
        parse_http_date(self.server_date.as_deref()?)
    }

    #[must_use]
    pub fn steam_linked_id(&self) -> Option<&str> {
        self.steam_linked_id.as_deref()
    }

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

    // A standard login submits the caller's username verbatim. A Steam login submits the id the top
    // page reported the ticket is linked to, having first checked the caller meant that account: the
    // ticket already decides which SE account the login lands on, so submitting a different username
    // would either fail confusingly or sign the user into an account they did not pick. The comparison
    // is case-insensitive, matching the launcher's OrdinalIgnoreCase fold (Launcher.cs:572), because SE
    // ids are.
    fn submitted_username<'a>(&'a self, offered: &'a str) -> Result<&'a str, ProtoError> {
        let Some(linked) = self.steam_linked_id.as_deref() else {
            return Ok(offered);
        };
        if eq_ordinal_ignore_case(linked, offered) {
            Ok(linked)
        } else {
            Err(ProtoError::SteamWrongAccount {
                expected_hint: mask_id(linked),
            })
        }
    }

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
            .header(
                HeaderName::from_static("connection"),
                HeaderValue::from_static(KEEP_ALIVE),
            )
            .header(
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static(NO_CACHE),
            )
            .body(body))
    }
}

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

    // The ticket is a bearer credential and rides in the top-page query unescaped, so any page that
    // echoes the request URL back reflects it. Scrubbing it by value here, and passing the same list
    // into `scrape_stored` below, covers a page that reflects the ticket text alone; `excerpt` redacts
    // the query parameter by shape for the re-encoded case. Empty for a standard login, which the scrub
    // skips.
    let ticket_text = kind.ticket().map_or("", ObfuscatedTicket::text);
    let secrets = [ticket_text];

    if !response.is_ok() {
        return Err(ProtoError::invalid_response(
            Step::OauthTop,
            &response,
            &secrets,
        ));
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
            ProtoError::invalid_response(Step::OauthTop, &response, &secrets)
        });
    }

    // Read before `_STORED_` so a Steam page that answers without an id fails before the flow exists
    // to submit credentials through. An id is the only thing the submitted username can be checked
    // against, and the launcher submits the id itself, so there is nothing to send without one.
    let steam_linked_id = if steam {
        Some(
            scrape_steam_id(&text)
                .ok_or_else(|| ProtoError::invalid_response(Step::OauthTop, &response, &secrets))?
                .to_owned(),
        )
    } else {
        None
    };

    let stored = scrape_stored(&text, &secrets)?.to_owned();
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
        .header(HeaderName::from_static("referer"), dynamic_header(referer)?)
        .header(
            HeaderName::from_static("connection"),
            HeaderValue::from_static(KEEP_ALIVE),
        ))
}

// The launcher compares with .NET's OrdinalIgnoreCase (Launcher.cs:572), which folds case per code
// point using simple, one-to-one uppercase mapping. Neither of Rust's ready-made folds is that rule:
// `eq_ignore_ascii_case` folds only A-Z (refuses a non-ASCII id the launcher accepts), and
// `to_uppercase` folds further (e.g. expanding ß to SS where .NET leaves ß, accepting a pair the
// launcher refuses). `fold` below reproduces the rule instead, correcting `to_uppercase` for its known
// divergences from OrdinalIgnoreCase.
//
// Both directions verified exhaustively: every one of the ~1.1M valid Unicode scalar values was
// grouped by `fold` and diffed against .NET 10's own OrdinalIgnoreCase grouping of the same range (via
// StringComparer.OrdinalIgnoreCase, not a candidate-pair guess), with zero remaining divergence in
// either direction.
fn eq_ordinal_ignore_case(left: &str, right: &str) -> bool {
    left.chars().map(fold).eq(right.chars().map(fold))
}

// - Over-matching: Unicode's simple uppercase mapping folds some code points .NET's ordinal fold does
//   not (the Turkish dotless i U+0131, the long s U+017F, and the block U+16EBB..=U+16ED3). Folding
//   them the general way would weaken the check SteamWrongAccount exists to enforce, so they are left
//   untouched here.
// - Under-matching: the Greek iota-subscript case pairs (below) have no single-char uppercase form at
//   all, so the general rule falls through to identity and leaves every pair distinct, where .NET
//   folds them through a simple one-to-one table.
fn fold(c: char) -> char {
    if let Some(mapped) = iota_subscript_fold(c) {
        return mapped;
    }
    if matches!(c, '\u{0131}' | '\u{017F}' | '\u{16EBB}'..='\u{16ED3}') {
        return c;
    }
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

// The Greek iota-subscript case pairs `fold` cannot resolve through `char::to_uppercase`, mapped to
// their ypogegrammeni (lowercase, iota-subscript) member so both sides of a pair land on the same
// value. Verified pair-by-pair against a real .NET 10 OrdinalIgnoreCase comparison.
fn iota_subscript_fold(c: char) -> Option<char> {
    match c {
        '\u{1F88}' => Some('\u{1F80}'),
        '\u{1F89}' => Some('\u{1F81}'),
        '\u{1F8A}' => Some('\u{1F82}'),
        '\u{1F8B}' => Some('\u{1F83}'),
        '\u{1F8C}' => Some('\u{1F84}'),
        '\u{1F8D}' => Some('\u{1F85}'),
        '\u{1F8E}' => Some('\u{1F86}'),
        '\u{1F8F}' => Some('\u{1F87}'),
        '\u{1F98}' => Some('\u{1F90}'),
        '\u{1F99}' => Some('\u{1F91}'),
        '\u{1F9A}' => Some('\u{1F92}'),
        '\u{1F9B}' => Some('\u{1F93}'),
        '\u{1F9C}' => Some('\u{1F94}'),
        '\u{1F9D}' => Some('\u{1F95}'),
        '\u{1F9E}' => Some('\u{1F96}'),
        '\u{1F9F}' => Some('\u{1F97}'),
        '\u{1FA8}' => Some('\u{1FA0}'),
        '\u{1FA9}' => Some('\u{1FA1}'),
        '\u{1FAA}' => Some('\u{1FA2}'),
        '\u{1FAB}' => Some('\u{1FA3}'),
        '\u{1FAC}' => Some('\u{1FA4}'),
        '\u{1FAD}' => Some('\u{1FA5}'),
        '\u{1FAE}' => Some('\u{1FA6}'),
        '\u{1FAF}' => Some('\u{1FA7}'),
        '\u{1FBC}' => Some('\u{1FB3}'),
        '\u{1FCC}' => Some('\u{1FC3}'),
        '\u{1FFC}' => Some('\u{1FF3}'),
        '\u{1F80}'..='\u{1F87}'
        | '\u{1F90}'..='\u{1F97}'
        | '\u{1FA0}'..='\u{1FA7}'
        | '\u{1FB3}'
        | '\u{1FC3}'
        | '\u{1FF3}' => Some(c),
        _ => None,
    }
}

// Fixed rather than one `*` per hidden character, so the hint does not report the id's length. The
// user is being told which account the ticket belongs to; the id itself belongs to whoever linked it
// and is not the caller's to read back.
fn mask_id(id: &str) -> String {
    let mut chars = id.chars();
    match (chars.next(), chars.next_back()) {
        (Some(first), Some(last)) if id.chars().count() > 2 => format!("{first}***{last}"),
        _ => "***".to_owned(),
    }
}

fn read_date(response: &ProtoResponse) -> Option<String> {
    response
        .header(&http::header::DATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
