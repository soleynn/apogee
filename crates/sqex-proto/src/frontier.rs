//! Frontier status endpoints.
//!
//! The frontier serves the launcher's world-gate and login-server status. These payloads gate whether
//! a login is even attempted, so they are typed; they parse leniently (unknown fields ignored) because
//! SE adds fields additively, and a strict-parse canary over a committed fixture surfaces such
//! additions as a visible-but-green diff.
//!
//! `status` is modeled as the reference does, a bool; SE's exact open/closed encoding is a schema
//! detail to confirm against a real capture. The frontier also serves display data (news, banners,
//! notices, world status); those endpoints are added once their payloads are captured, so their lenient
//! schemas can be pinned from fact rather than guessed.

use http::{HeaderName, HeaderValue, Method};
use serde::Deserialize;
use url::Url;

use crate::error::{ProtoError, Step, excerpt};
use crate::identity::{ComputerId, frontier_referer, launcher_user_agent};
use crate::time::LauncherTime;
use crate::transport::{ProtoRequest, ProtoResponse, Transport, TransportError, dynamic_header};

const FRONTIER_ORIGIN: &str = "https://launcher.finalfantasyxiv.com";
const GATE_STATUS_URL: &str = "https://frontier.ffxiv.com/worldStatus/gate_status.json";
const LOGIN_STATUS_URL: &str = "https://frontier.ffxiv.com/worldStatus/login_status.json";
const HTTP_OK: u16 = 200;

/// A world-gate or login-server status. `status` is open/closed; `message` and `news` are display
/// strings. Fields SE may add are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GateStatus {
    pub status: bool,
    pub message: Vec<String>,
    pub news: Vec<String>,
}

/// The per-install, per-locale values a frontier request carries.
pub struct FrontierContext<'a> {
    /// The launcher computer-id, embedded in the user agent.
    pub computer_id: &'a ComputerId,
    /// The client language code (e.g. `en-us`), used for the referer and the gate-status query.
    pub language: &'a str,
    /// The `Accept-Language` header value.
    pub accept_language: &'a str,
    /// The referer URL template, with `{lang}` and `{time}` placeholders.
    pub referer_template: &'a str,
}

/// Fetch the world-gate status (world maintenance).
pub async fn check_gate_status(
    transport: &dyn Transport,
    context: &FrontierContext<'_>,
    now: &LauncherTime,
) -> Result<GateStatus, ProtoError> {
    let mut url =
        Url::parse(GATE_STATUS_URL).map_err(|_| TransportError::new("invalid gate-status URL"))?;
    url.query_pairs_mut()
        .append_pair("lang", context.language)
        .append_pair("_", &now.cache_buster().to_string());

    let response = transport.execute(build_request(url, context, now)?).await?;
    parse_status(&response, Step::GateStatus)
}

/// Fetch the login-server status. Unlike the gate status, this endpoint takes no `lang`.
pub async fn check_login_status(
    transport: &dyn Transport,
    context: &FrontierContext<'_>,
    now: &LauncherTime,
) -> Result<GateStatus, ProtoError> {
    let mut url = Url::parse(LOGIN_STATUS_URL)
        .map_err(|_| TransportError::new("invalid login-status URL"))?;
    url.query_pairs_mut()
        .append_pair("_", &now.cache_buster().to_string());

    let response = transport.execute(build_request(url, context, now)?).await?;
    parse_status(&response, Step::LoginStatus)
}

/// The launcher's frontier request header set, in order. `gate`/`login` send no `Accept` (their
/// content type is unset), so it is omitted here.
fn build_request(
    url: Url,
    context: &FrontierContext<'_>,
    now: &LauncherTime,
) -> Result<ProtoRequest, TransportError> {
    let user_agent = launcher_user_agent(context.computer_id);
    let referer = frontier_referer(
        context.referer_template,
        context.language,
        &now.referer_timestamp(),
    );

    Ok(ProtoRequest::new(Method::GET, url)
        .header(
            HeaderName::from_static("user-agent"),
            dynamic_header(&user_agent)?,
        )
        .header(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate"),
        )
        .header(
            HeaderName::from_static("accept-language"),
            dynamic_header(context.accept_language)?,
        )
        .header(
            HeaderName::from_static("origin"),
            HeaderValue::from_static(FRONTIER_ORIGIN),
        )
        .header(
            HeaderName::from_static("referer"),
            dynamic_header(&referer)?,
        )
        .header(
            HeaderName::from_static("connection"),
            HeaderValue::from_static("Keep-Alive"),
        ))
}

fn parse_status(response: &ProtoResponse, step: Step) -> Result<GateStatus, ProtoError> {
    if response.status != HTTP_OK {
        return Err(ProtoError::InvalidResponse {
            step,
            status: response.status,
            excerpt: excerpt(&response.body),
        });
    }
    serde_json::from_slice(&response.body).map_err(|_| ProtoError::InvalidResponse {
        step,
        status: response.status,
        excerpt: excerpt(&response.body),
    })
}

#[cfg(test)]
mod tests {
    use super::GateStatus;

    #[test]
    fn parses_an_open_gate_status() {
        let status: GateStatus =
            serde_json::from_str(r#"{"status": true, "message": [], "news": ["patch 7.1"]}"#)
                .unwrap();
        assert!(status.status);
        assert_eq!(status.news, ["patch 7.1"]);
    }

    #[test]
    fn ignores_unknown_fields() {
        let status: GateStatus =
            serde_json::from_str(r#"{"status": false, "added_by_se": 42, "message": ["maint"]}"#)
                .unwrap();
        assert!(!status.status);
        assert_eq!(status.message, ["maint"]);
    }

    #[test]
    fn defaults_missing_fields() {
        let status: GateStatus = serde_json::from_str("{}").unwrap();
        assert!(!status.status);
        assert!(status.message.is_empty());
        assert!(status.news.is_empty());
    }
}
