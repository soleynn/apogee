// The OAuth page scanners. Hand-written, anchored scanners read the SE login pages: two lift attribute
// values out of the top page (the opaque _STORED_ blob, and on a Steam login the linked account id),
// the third reads the launchParams list out of the success callback. All see hostile input over the
// wire, so they follow the patchlist parser's discipline: fixed ASCII anchors, bounded search windows,
// length-capped captures, and no panics on any byte sequence. Their errors carry a count or a
// length-capped page excerpt, never the submitted secrets or the session id.

use zeroize::Zeroizing;

use crate::error::{ProtoError, scrubbed_excerpt};

const STORED_ANCHOR: &str = "name=\"_STORED_\"";
const VALUE_OPEN: &str = "value=\"";
const ATTR_WINDOW: usize = 64;
const MAX_STORED: usize = 4096;
// The page also carries the *visible* login form's own sqexid input, whose value is empty, so
// anchoring on the name alone would find the wrong element and read a blank id. The hidden-input shape
// is the one XL matches (Launcher.cs:502), and its working in the wild is the only evidence for the
// markup: no capture of a real Steam top page exists here, so this is unverified against live SE.
const STEAM_ID_ANCHOR: &str = "name=\"sqexid\" type=\"hidden\"";
const MAX_STEAM_ID: usize = 128;
const CALLBACK_OPEN: &str = "window.external.user(\"login=auth,";
const RESTARTUP_MARKER: &str = "window.external.user(\"restartup\")";
// Bounds both branches the callback content splits into: the launchParams list (parse_launch_params
// copies `sid` out of it verbatim, which later rides into an error's secret-scrub list) and the
// failure message. A real callback runs under 150 bytes.
const MAX_CALLBACK: usize = 1024;

// The launch parameters SE returns on a successful login. `session_id` authorizes the next stage, so
// this type deliberately implements no Debug/Display/Serialize: it is a transient parse result,
// consumed immediately into the redacted session-id type, and never logged. The id is held zeroizing
// so it scrubs on drop.
pub struct LaunchParams {
    pub session_id: Zeroizing<String>,
    pub terms_accepted: bool,
    pub region: u16,
    pub playable: bool,
    pub max_expansion: u8,
}

// Any `message` is SE's own failure text, borrowed straight out of the response body: the flow scrubs
// the submitted credentials out of it before surfacing, so this cannot leak them, and it must reach
// that scrub whole. A caller that copied or length-capped `message` before scrubbing would hand the
// redactor text it never saw the true tail of -- see error::scrubbed_excerpt's doc for the bug this
// borrow exists to prevent.
#[derive(Debug)]
pub(crate) enum CallbackReject<'a> {
    NotAuthOk { message: Option<&'a str> },
    Unparseable { got_fields: usize },
}

pub fn scrape_stored<'h>(html: &'h str, secrets: &[&str]) -> Result<&'h str, ProtoError> {
    attribute_value(html, STORED_ANCHOR, MAX_STORED)
        .filter(|stored| !stored.is_empty())
        .ok_or_else(|| ProtoError::StoredNotFound {
            excerpt: scrubbed_excerpt(html.as_bytes(), secrets),
        })
}

pub(crate) fn scrape_steam_id(html: &str) -> Option<&str> {
    attribute_value(html, STEAM_ID_ANCHOR, MAX_STEAM_ID).filter(|id| !id.is_empty())
}

fn attribute_value<'h>(html: &'h str, anchor: &str, max: usize) -> Option<&'h str> {
    let at = html.find(anchor)?;
    let after = &html[at + anchor.len()..];

    let open = after.find(VALUE_OPEN).filter(|&p| p <= ATTR_WINDOW)?;
    if after[..open].contains(['<', '>']) {
        return None;
    }
    let value = &after[open + VALUE_OPEN.len()..];

    let end = value.find('"').filter(|&e| e <= max)?;
    Some(&value[..end])
}

pub(crate) fn is_restartup(html: &str) -> bool {
    html.contains(RESTARTUP_MARKER)
}

pub(crate) fn parse_login_callback(body: &str) -> Result<LaunchParams, CallbackReject<'_>> {
    let start = body
        .find(CALLBACK_OPEN)
        .ok_or(CallbackReject::NotAuthOk { message: None })?;
    let rest = &body[start + CALLBACK_OPEN.len()..];
    let end = rest
        .find('"')
        .filter(|&e| e <= MAX_CALLBACK)
        .ok_or(CallbackReject::NotAuthOk { message: None })?;
    let content = &rest[..end];

    if let Some(params) = content.strip_prefix("ok,") {
        return parse_launch_params(params)
            .map_err(|got_fields| CallbackReject::Unparseable { got_fields });
    }

    // A failure callback `ng,{type},{message}`: surface the human message, dropping the type token.
    let after_status = content.strip_prefix("ng,").unwrap_or(content);
    let detail = after_status
        .split_once(',')
        .map_or(after_status, |(_type, message)| message);
    Err(CallbackReject::NotAuthOk {
        message: Some(detail),
    })
}

enum KeyLookup<'a> {
    Found(&'a str),
    Absent,
    Ambiguous,
}

fn by_key<'a>(fields: &[&'a str], key: &str) -> KeyLookup<'a> {
    let mut pairs = fields
        .iter()
        .step_by(2)
        .enumerate()
        .filter(|(_, name)| **name == key);
    let Some((pair, _)) = pairs.next() else {
        return KeyLookup::Absent;
    };
    if pairs.next().is_some() {
        return KeyLookup::Ambiguous;
    }
    fields
        .get(pair * 2 + 1)
        .map_or(KeyLookup::Absent, |value| KeyLookup::Found(value))
}

// The list is `key,value,key,value,...`; XL reads the values positionally (idx 1 sid, 3 terms, 5
// region, 9 playable, 13 maxex), never looking at the key names. This reads each field in a fixed
// precedence: (1) the documented position, when the key sits beside it (the canonical shape, and the
// same bytes XL reads); (2) otherwise the pair carrying that key, wherever it moved to, so a reorder
// or a trimmed field still parses; (3) otherwise, with the key nowhere in the list, the documented
// position anyway, so a renamed key still parses. A key appearing more than once away from its
// documented position resolves to no value at all, rather than a first-match-wins guess.
pub fn parse_launch_params(params: &str) -> Result<LaunchParams, usize> {
    let fields: Vec<&str> = params.split(',').collect();
    let got = fields.len();

    // Even indices are keys, the following odd index the value, so a value at `idx` is keyed at
    // `idx - 1`; every documented index below is odd.
    let at = |key: &str, idx: usize| -> Option<&str> {
        if fields.get(idx - 1).is_some_and(|name| *name == key) {
            return fields.get(idx).copied();
        }
        match by_key(&fields, key) {
            KeyLookup::Found(value) => Some(value),
            KeyLookup::Absent => fields.get(idx).copied(),
            KeyLookup::Ambiguous => None,
        }
    };

    let session_id = at("sid", 1).filter(|s| !s.is_empty()).ok_or(got)?;
    let terms = at("terms", 3).ok_or(got)?;
    let region = at("region", 5)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(got)?;
    let playable = at("playable", 9).ok_or(got)?;
    let max_expansion = at("maxex", 13)
        .and_then(|s| s.parse::<u8>().ok())
        .ok_or(got)?;

    Ok(LaunchParams {
        session_id: Zeroizing::new(session_id.to_owned()),
        // "0" is the only value that reads as not-accepted / not-playable.
        terms_accepted: terms != "0",
        region,
        playable: playable != "0",
        max_expansion,
    })
}
