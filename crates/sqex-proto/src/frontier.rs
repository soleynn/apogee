//! Frontier status endpoints: the world-gate and login-server status.
//!
//! These payloads gate whether a login is even attempted, so they are typed as [`GateStatus`]; they
//! parse leniently (unknown fields ignored) because SE adds fields additively, and a strict-parse
//! canary test over a committed fixture surfaces such additions as a visible-but-green diff rather
//! than a silent one. The frontier also serves display data (news, banners, notices, world status);
//! those endpoints are deliberately unimplemented here, added once their payloads are captured, so
//! their lenient schemas can be pinned from fact rather than guessed.
//!
//! Leniency is bounded by the reference launcher's own deserializer rather than pushed as far as it
//! will go, because these two endpoints decide whether the launcher believes the servers are up and
//! an invented reading is worse than a reported failure: every shape the reference accepts is
//! accepted here too (see [`GateStatus::status`]'s doc for the full list), and every shape it
//! rejects stays an error. This was measured against the reference's `GateStatus.cs` through its
//! `Newtonsoft.Json` deserializer, shape by shape, rather than guessed at.

use std::fmt;

use http::{HeaderName, HeaderValue, Method};
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Unexpected, Visitor};
use url::Url;

use crate::error::{ProtoError, Step};
use crate::identity::ClientContext;
use crate::time::LauncherTime;
use crate::transport::{
    ProtoRequest, ProtoResponse, Transport, TransportError, dynamic_header, parse_base,
};

const FRONTIER_ORIGIN: &str = "https://launcher.finalfantasyxiv.com";
const GATE_STATUS_URL: &str = "https://frontier.ffxiv.com/worldStatus/gate_status.json";
const LOGIN_STATUS_URL: &str = "https://frontier.ffxiv.com/worldStatus/login_status.json";

/// A world-gate or login-server status: whether the service is open, plus any display strings.
///
/// Missing fields default (an absent field reads the same as its zero value: closed, no messages,
/// no news), and fields SE may add are ignored.
///
/// # Examples
///
/// ```
/// use sqex_proto::GateStatus;
///
/// let status: GateStatus = serde_json::from_str(r#"{"status": 1, "news": ["patch 7.1"]}"#).unwrap();
/// assert!(status.status);
/// assert_eq!(status.news, ["patch 7.1"]);
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GateStatus {
    /// Whether the service is open.
    ///
    /// SE sends this as an integer (`0` closed, non-zero open) as the reference reads it (`status
    /// != 0`), though a JSON bool, a float, or the string `"true"`/`"false"` (case-insensitive,
    /// trimmed) is also accepted, matching every shape the reference launcher's own deserializer
    /// takes. A numeric string, free text, and an explicit `null` are refused, also matching the
    /// reference: none of the three carries an open/closed reading this crate could infer without
    /// inventing one, and the caller acts on the answer.
    #[serde(deserialize_with = "deserialize_open_flag")]
    pub status: bool,
    /// Display strings shown alongside the status (e.g. a maintenance notice).
    #[serde(deserialize_with = "deserialize_display_list")]
    pub message: Vec<String>,
    /// Display strings for current news items.
    #[serde(deserialize_with = "deserialize_display_list")]
    pub news: Vec<String>,
}

fn deserialize_open_flag<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    struct OpenFlag;
    impl Visitor<'_> for OpenFlag {
        type Value = bool;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str(r#"a number, a boolean, or "true"/"false" as an open flag"#)
        }

        fn visit_bool<E>(self, v: bool) -> Result<bool, E> {
            Ok(v)
        }

        fn visit_u64<E>(self, v: u64) -> Result<bool, E> {
            Ok(v != 0)
        }

        fn visit_i64<E>(self, v: i64) -> Result<bool, E> {
            Ok(v != 0)
        }

        fn visit_f64<E>(self, v: f64) -> Result<bool, E> {
            Ok(v != 0.0)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<bool, E> {
            // The reference parses the string through .NET's `bool.TryParse`, which trims and folds
            // case but reads no numeral: `"1"` is an error there, so it is one here.
            let flag = v.trim();
            if flag.eq_ignore_ascii_case("true") {
                Ok(true)
            } else if flag.eq_ignore_ascii_case("false") {
                Ok(false)
            } else {
                Err(E::invalid_value(Unexpected::Str(v), &self))
            }
        }
    }
    deserializer.deserialize_any(OpenFlag)
}

fn deserialize_display_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct DisplayList;
    impl<'de> Visitor<'de> for DisplayList {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a list of display strings or null")
        }

        fn visit_unit<E>(self) -> Result<Vec<String>, E> {
            Ok(Vec::new())
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            // No `with_capacity` from `size_hint`: the length is the server's to claim and this parse
            // runs before anything has vouched for the response.
            let mut items = Vec::new();
            while let Some(DisplayItem(item)) = seq.next_element()? {
                items.extend(item);
            }
            Ok(items)
        }
    }
    deserializer.deserialize_any(DisplayList)
}

struct DisplayItem(Option<String>);

impl<'de> Deserialize<'de> for DisplayItem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Item;
        impl Visitor<'_> for Item {
            type Value = Option<String>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a display string or another JSON scalar")
            }

            fn visit_str<E>(self, v: &str) -> Result<Option<String>, E> {
                Ok(Some(v.to_owned()))
            }

            fn visit_bool<E>(self, v: bool) -> Result<Option<String>, E> {
                Ok(Some(v.to_string()))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Option<String>, E> {
                Ok(Some(v.to_string()))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Option<String>, E> {
                Ok(Some(v.to_string()))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Option<String>, E> {
                Ok(Some(v.to_string()))
            }

            fn visit_unit<E>(self) -> Result<Option<String>, E> {
                Ok(None)
            }
        }
        deserializer.deserialize_any(Item).map(DisplayItem)
    }
}

/// The per-install, per-locale values a frontier request carries.
///
/// # Examples
///
/// ```
/// use sqex_proto::{ClientContext, ComputerId, FrontierContext};
///
/// let id = ComputerId::from_facts("host", "user", "os", 4);
/// let context = FrontierContext {
///     client: ClientContext {
///         computer_id: &id,
///         language: "en-us",
///         accept_language: "en-us,en;q=0.9",
///         referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
///     },
/// };
/// assert_eq!(context.client.language, "en-us");
/// ```
pub struct FrontierContext<'a> {
    /// The shared client identity and locale plumbing.
    pub client: ClientContext<'a>,
}

/// Fetch the world-gate status (world maintenance).
///
/// # Errors
///
/// Returns [`ProtoError::Transport`] if the request could not be sent, or
/// [`ProtoError::InvalidResponse`] if SE answers with a non-`200` status or a body that does not
/// deserialize as a [`GateStatus`].
///
/// # Examples
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
/// use sqex_proto::{
///     ClientContext, ComputerId, FrontierContext, LauncherTime, ProtoRequest, ProtoResponse,
///     Transport, TransportError, check_gate_status,
/// };
///
/// struct OpenGate;
///
/// #[async_trait::async_trait]
/// impl Transport for OpenGate {
///     async fn execute(&self, _req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
///         Ok(ProtoResponse::new(200, br#"{"status":1}"#.to_vec()))
///     }
/// }
///
/// let id = ComputerId::from_facts("host", "user", "os", 4);
/// let context = FrontierContext {
///     client: ClientContext {
///         computer_id: &id,
///         language: "en-us",
///         accept_language: "en-us,en;q=0.9",
///         referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
///     },
/// };
/// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
/// let status = block_on(check_gate_status(&OpenGate, &context, &now)).unwrap();
/// assert!(status.status);
/// ```
pub async fn check_gate_status(
    transport: &dyn Transport,
    context: &FrontierContext<'_>,
    now: &LauncherTime,
) -> Result<GateStatus, ProtoError> {
    let mut url = parse_base(GATE_STATUS_URL, "invalid gate-status URL")?;
    url.query_pairs_mut()
        .append_pair("lang", context.client.language)
        .append_pair("_", &now.cache_buster().to_string());

    let response = transport.execute(build_request(url, context, now)?).await?;
    parse_status(&response, Step::GateStatus)
}

/// Fetch the login-server status. Unlike [`check_gate_status`], this endpoint takes no `lang`.
///
/// # Errors
///
/// Returns [`ProtoError::Transport`] if the request could not be sent, or
/// [`ProtoError::InvalidResponse`] if SE answers with a non-`200` status or a body that does not
/// deserialize as a [`GateStatus`].
///
/// # Examples
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
/// use sqex_proto::{
///     ClientContext, ComputerId, FrontierContext, LauncherTime, ProtoRequest, ProtoResponse,
///     Transport, TransportError, check_login_status,
/// };
///
/// struct DownLogin;
///
/// #[async_trait::async_trait]
/// impl Transport for DownLogin {
///     async fn execute(&self, _req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
///         Ok(ProtoResponse::new(200, br#"{"status":0}"#.to_vec()))
///     }
/// }
///
/// let id = ComputerId::from_facts("host", "user", "os", 4);
/// let context = FrontierContext {
///     client: ClientContext {
///         computer_id: &id,
///         language: "en-us",
///         accept_language: "en-us,en;q=0.9",
///         referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
///     },
/// };
/// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
/// let status = block_on(check_login_status(&DownLogin, &context, &now)).unwrap();
/// assert!(!status.status);
/// ```
pub async fn check_login_status(
    transport: &dyn Transport,
    context: &FrontierContext<'_>,
    now: &LauncherTime,
) -> Result<GateStatus, ProtoError> {
    let mut url = parse_base(LOGIN_STATUS_URL, "invalid login-status URL")?;
    url.query_pairs_mut()
        .append_pair("_", &now.cache_buster().to_string());

    let response = transport.execute(build_request(url, context, now)?).await?;
    parse_status(&response, Step::LoginStatus)
}

// `accept` is declared even though the reference launcher sends neither it nor Accept-Encoding on
// gate/login (their content type is unset): see bootver.rs's build_request and
// crate::NEGOTIATED_HEADERS for why the identical `*/*` is declared anyway.
fn build_request(
    url: Url,
    context: &FrontierContext<'_>,
    now: &LauncherTime,
) -> Result<ProtoRequest, TransportError> {
    let (user_agent, referer) = context.client.user_agent_and_referer(now);

    Ok(ProtoRequest::new(Method::GET, url)
        .header(
            HeaderName::from_static("user-agent"),
            dynamic_header(&user_agent)?,
        )
        .header(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("*/*"),
        )
        .header(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate"),
        )
        .header(
            HeaderName::from_static("accept-language"),
            dynamic_header(context.client.accept_language)?,
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
    // No secrets to scrub: the frontier requests are unauthenticated, carrying only the locale and the
    // computer id.
    if !response.is_ok() {
        return Err(ProtoError::invalid_response(step, response, &[]));
    }
    serde_json::from_slice(&response.body)
        .map_err(|_| ProtoError::invalid_response(step, response, &[]))
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
    fn parses_the_integer_open_flag_the_endpoint_sends() {
        // The live login-status endpoint returns `{"status":1}` (an integer, not a JSON bool).
        let open: GateStatus = serde_json::from_str(r#"{"status":1}"#).unwrap();
        assert!(open.status);
        let closed: GateStatus = serde_json::from_str(r#"{"status":0}"#).unwrap();
        assert!(!closed.status);
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

    #[test]
    fn reads_the_whole_integer_range_as_an_open_flag() {
        let negative: GateStatus = serde_json::from_str(r#"{"status":-1}"#).unwrap();
        assert!(negative.status);
        let huge: GateStatus = serde_json::from_str(r#"{"status":18446744073709551615}"#).unwrap();
        assert!(huge.status);
    }

    #[test]
    fn reads_a_float_open_flag() {
        let closed: GateStatus = serde_json::from_str(r#"{"status":0.0}"#).unwrap();
        assert!(!closed.status);
        let open: GateStatus = serde_json::from_str(r#"{"status":2.5}"#).unwrap();
        assert!(open.status);
    }

    #[test]
    fn reads_a_boolean_string_open_flag() {
        for body in [
            r#"{"status":"true"}"#,
            r#"{"status":"TRUE"}"#,
            r#"{"status":" true "}"#,
        ] {
            let status: GateStatus = serde_json::from_str(body).unwrap();
            assert!(status.status, "{body}");
        }
        let closed: GateStatus = serde_json::from_str(r#"{"status":"False"}"#).unwrap();
        assert!(!closed.status);
    }

    #[test]
    fn refuses_a_flag_string_that_is_not_a_boolean() {
        for body in [
            r#"{"status":"0"}"#,
            r#"{"status":"1"}"#,
            r#"{"status":"maintenance"}"#,
            r#"{"status":""}"#,
        ] {
            assert!(serde_json::from_str::<GateStatus>(body).is_err(), "{body}");
        }
    }

    #[test]
    fn refuses_a_null_or_structured_open_flag() {
        for body in [r#"{"status":null}"#, r#"{"status":{}}"#, r#"{"status":[]}"#] {
            assert!(serde_json::from_str::<GateStatus>(body).is_err(), "{body}");
        }
    }

    #[test]
    fn reads_a_null_display_list_as_empty() {
        let status: GateStatus =
            serde_json::from_str(r#"{"status":1,"message":null,"news":null}"#).unwrap();
        assert!(status.status);
        assert!(status.message.is_empty());
        assert!(status.news.is_empty());
    }

    #[test]
    fn renders_non_string_display_list_elements() {
        let status: GateStatus =
            serde_json::from_str(r#"{"status":1,"message":["maint",5,true,1.5,null]}"#).unwrap();
        assert_eq!(status.message, ["maint", "5", "true", "1.5"]);
    }

    #[test]
    fn refuses_a_display_list_that_is_not_a_list_of_scalars() {
        for body in [
            r#"{"status":1,"message":"maint"}"#,
            r#"{"status":1,"message":{}}"#,
            r#"{"status":1,"message":[{}]}"#,
            r#"{"status":1,"news":[[]]}"#,
        ] {
            assert!(serde_json::from_str::<GateStatus>(body).is_err(), "{body}");
        }
    }
}
