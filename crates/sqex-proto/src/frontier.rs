//! Frontier status endpoints.
//!
//! The frontier serves the launcher's world-gate and login-server status. These payloads gate whether
//! a login is even attempted, so they are typed; they parse leniently (unknown fields ignored) because
//! SE adds fields additively, and a strict-parse canary over a committed fixture surfaces such
//! additions as a visible-but-green diff.
//!
//! `status` is SE's open/closed flag, sent as an integer (`0` closed, non-zero open) as the reference
//! reads it (`status != 0`). The frontier also serves display data (news, banners, notices, world
//! status); those endpoints are added once their payloads are captured, so their lenient schemas can be
//! pinned from fact rather than guessed.
//!
//! Leniency here is bounded by the reference launcher's own deserializer rather than pushed as far as
//! it will go, because these two endpoints decide whether the launcher believes the servers are up and
//! an invented reading is worse than a reported failure. Every shape the reference accepts is accepted:
//! a float or `"true"`/`"false"` open flag, a `null` display list, and a non-string scalar list element
//! rendered as its JSON text. Every shape it rejects stays an error: a numeric or free-text `status`
//! string, an explicit `null` `status`, and any list or object where a scalar belongs. Measured against
//! `GateStatus.cs` through its `Newtonsoft.Json` deserializer, shape by shape.

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

/// A world-gate or login-server status. `status` is open/closed; `message` and `news` are display
/// strings. Fields SE may add are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GateStatus {
    #[serde(deserialize_with = "deserialize_open_flag")]
    pub status: bool,
    #[serde(deserialize_with = "deserialize_display_list")]
    pub message: Vec<String>,
    #[serde(deserialize_with = "deserialize_display_list")]
    pub news: Vec<String>,
}

/// Deserialize SE's open/closed flag. The frontier sends it as an integer (`0` closed, non-zero open),
/// matching the reference launcher's `status != 0`; a JSON bool, a float, and the strings `"true"` and
/// `"false"` are accepted too, which is every shape the reference's own deserializer takes.
///
/// A numeric string, free text, and an explicit `null` are refused, also matching the reference. None
/// of the three carries an open/closed reading this crate could infer without inventing one, and the
/// caller acts on the answer: guessing here would tell a user the servers are down when they are up.
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

/// Deserialize a list of display strings. SE sends an array; an explicit `null` reads as empty, the
/// same as an absent field under the container's `serde(default)`, and a non-string scalar element
/// renders as its JSON text. Both match the reference launcher, which drops a `null` list and coerces a
/// scalar element on the way into its `List<string>`.
///
/// An object or array where a scalar belongs is still an error, again as the reference has it: it is a
/// schema change rather than a type wobble, and the strict-parse canary over the committed fixture is
/// the intended way to learn about one.
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

/// One element of a display list: any JSON scalar, rendered as text. A `null` element carries nothing
/// to display and has no `String` to become, so it drops out of the list.
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
pub struct FrontierContext<'a> {
    pub client: ClientContext<'a>,
}

/// Fetch the world-gate status (world maintenance).
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

/// Fetch the login-server status. Unlike the gate status, this endpoint takes no `lang`.
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

/// The launcher's frontier request header set, in order. `gate`/`login` send no `Accept` (their
/// content type is unset), so it is omitted here.
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
    if !response.is_ok() {
        return Err(ProtoError::invalid_response(step, response));
    }
    serde_json::from_slice(&response.body).map_err(|_| ProtoError::invalid_response(step, response))
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

    /// Any integer the flag can arrive as reads through `!= 0`, at both ends of the range.
    #[test]
    fn reads_the_whole_integer_range_as_an_open_flag() {
        let negative: GateStatus = serde_json::from_str(r#"{"status":-1}"#).unwrap();
        assert!(negative.status);
        let huge: GateStatus = serde_json::from_str(r#"{"status":18446744073709551615}"#).unwrap();
        assert!(huge.status);
    }

    /// A float flag: the reference's deserializer takes one, so this one does.
    #[test]
    fn reads_a_float_open_flag() {
        let closed: GateStatus = serde_json::from_str(r#"{"status":0.0}"#).unwrap();
        assert!(!closed.status);
        let open: GateStatus = serde_json::from_str(r#"{"status":2.5}"#).unwrap();
        assert!(open.status);
    }

    /// `"true"`/`"false"` are the only strings the reference reads, trimmed and case-folded.
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

    /// The other string shapes stay errors. A numeral is the tempting one, and the reference refuses it
    /// too; reading `"0"` as closed would be this crate inventing an answer the server did not give.
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

    /// An explicit `null` flag is an error, not the closed default: absent means the server said
    /// nothing, `null` means it said something this crate cannot read.
    #[test]
    fn refuses_a_null_or_structured_open_flag() {
        for body in [r#"{"status":null}"#, r#"{"status":{}}"#, r#"{"status":[]}"#] {
            assert!(serde_json::from_str::<GateStatus>(body).is_err(), "{body}");
        }
    }

    /// A `null` display list degrades to empty instead of failing the whole object, matching both the
    /// reference and this struct's own default for an absent list.
    #[test]
    fn reads_a_null_display_list_as_empty() {
        let status: GateStatus =
            serde_json::from_str(r#"{"status":1,"message":null,"news":null}"#).unwrap();
        assert!(status.status);
        assert!(status.message.is_empty());
        assert!(status.news.is_empty());
    }

    /// A scalar element renders as its JSON text; a `null` element has nothing to render and drops.
    #[test]
    fn renders_non_string_display_list_elements() {
        let status: GateStatus =
            serde_json::from_str(r#"{"status":1,"message":["maint",5,true,1.5,null]}"#).unwrap();
        assert_eq!(status.message, ["maint", "5", "true", "1.5"]);
    }

    /// A list that is not a list, or an element that is not a scalar, is a schema change rather than a
    /// type wobble; the strict-parse canary over the committed fixture is how that should surface.
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
