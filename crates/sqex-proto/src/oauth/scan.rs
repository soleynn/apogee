//! The OAuth page scanners.
//!
//! Two hand-written, anchored scanners read the SE login pages: one lifts the opaque `_STORED_` blob
//! out of the top page, the other reads the `launchParams` list out of the success callback. Both see
//! hostile input over plain HTTP, so they follow the patchlist parser's discipline: fixed ASCII
//! anchors, bounded search windows, length-capped captures, and no panics on any byte sequence. They
//! hold no transport and no credentials, and their errors carry a count or a length-capped page
//! excerpt, never the submitted secrets or the session id.

use zeroize::Zeroizing;

use crate::error::{ProtoError, excerpt};

/// The attribute that anchors the `_STORED_` input on the top page (XL: `PatchListParser`-style
/// anchored scan of `name="_STORED_" value="(...)"`).
const STORED_ANCHOR: &str = "name=\"_STORED_\"";
/// The value-attribute opener that follows the name anchor in the same tag.
const VALUE_OPEN: &str = "value=\"";
/// How many bytes may sit between the name anchor and `value="` (they are adjacent in a well-formed
/// tag; the window tolerates minor whitespace but rejects a `value="` from a different element).
const ATTR_WINDOW: usize = 64;
/// The most bytes the `_STORED_` capture keeps before giving up: the blob is opaque but bounded, so a
/// missing closing quote cannot make the capture run away.
const MAX_STORED: usize = 4096;
/// The login callback wrapper. The status field (`ok` / `ng`) and its payload run from here to the
/// next `"`. Double-quoted, so the single-quoted commented-out samples on the page do not match.
const CALLBACK_OPEN: &str = "window.external.user(\"login=auth,";
/// The Steam relink callback (`restartup`). A standard login never triggers it.
const RESTARTUP_MARKER: &str = "window.external.user(\"restartup\")";
/// The most characters kept from a failure message, bounding the capture on hostile input.
const MAX_MESSAGE: usize = 512;

/// The launch parameters SE returns on a successful login. `session_id` authorizes the next stage, so
/// this type deliberately implements no `Debug`/`Display`/`Serialize`: it is a transient parse result,
/// consumed immediately into the redacted session-id type, and never logged. The id is held zeroizing
/// so it scrubs on drop.
pub struct LaunchParams {
    pub session_id: Zeroizing<String>,
    pub terms_accepted: bool,
    pub region: u16,
    pub playable: bool,
    pub max_expansion: u8,
}

/// Why a `login.send` body was not a usable success callback. Any `message` is SE's own failure text;
/// the flow scrubs the submitted credentials out of it before surfacing, so this cannot leak them.
#[derive(Debug)]
pub(crate) enum CallbackReject {
    /// Not the `login=auth,ok,...` success callback. `message` is the `login=auth,ng,{type},{message}`
    /// failure text when one was found, or `None` when no login callback was present at all.
    NotAuthOk { message: Option<String> },
    /// The success callback was present but its `launchParams` list was too short or malformed.
    /// `got_fields` is a count only.
    Unparseable { got_fields: usize },
}

/// Lift the `_STORED_` blob out of the login top page.
///
/// Anchors on `name="_STORED_"`, then reads the `value="..."` that follows within a bounded window,
/// capturing up to the closing quote under a hard length cap. Any miss is a [`ProtoError::StoredNotFound`]
/// carrying a length-capped page excerpt (the top page carries no submitted credentials). The returned
/// slice borrows `html`.
pub fn scrape_stored(html: &str) -> Result<&str, ProtoError> {
    let not_found = || ProtoError::StoredNotFound {
        excerpt: excerpt(html.as_bytes()),
    };

    let anchor = html.find(STORED_ANCHOR).ok_or_else(not_found)?;
    let after = &html[anchor + STORED_ANCHOR.len()..];

    // `find` returns an ASCII boundary, so every slice below lands between ASCII delimiters and can
    // never split a multi-byte character.
    let vpos = after
        .find(VALUE_OPEN)
        .filter(|&p| p <= ATTR_WINDOW)
        .ok_or_else(not_found)?;
    let value = &after[vpos + VALUE_OPEN.len()..];

    let end = value
        .find('"')
        .filter(|&e| e <= MAX_STORED)
        .ok_or_else(not_found)?;
    Ok(&value[..end])
}

/// Whether the top page asked the client to relink a Steam account.
pub(crate) fn is_restartup(html: &str) -> bool {
    html.contains(RESTARTUP_MARKER)
}

/// Peel the `login=auth,{status},...` callback out of a `login.send` body. A `login=auth,ok,` payload
/// is parsed as launch params; a `login=auth,ng,{type},{message}` payload yields the failure message;
/// no callback at all yields [`CallbackReject::NotAuthOk`] with no message.
pub(crate) fn parse_login_callback(body: &str) -> Result<LaunchParams, CallbackReject> {
    let start = body
        .find(CALLBACK_OPEN)
        .ok_or(CallbackReject::NotAuthOk { message: None })?;
    let rest = &body[start + CALLBACK_OPEN.len()..];
    let end = rest
        .find('"')
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
        message: Some(detail.chars().take(MAX_MESSAGE).collect()),
    })
}

/// Parse the comma-separated `launchParams` list.
///
/// The list is `key,value,key,value,...`; XL reads the values positionally (idx 1 `sid`, 3 `terms`,
/// 5 `region`, 9 `playable`, 13 `maxex`). This reads by key with a positional fallback, so a trailing
/// field trim or a reorder that keeps the keys still parses. A list too short to yield the required
/// fields is rejected. `Err` is the number of comma-separated fields found (never their contents,
/// which include the session id).
pub fn parse_launch_params(params: &str) -> Result<LaunchParams, usize> {
    let fields: Vec<&str> = params.split(',').collect();
    let got = fields.len();

    // Even indices are keys, the following odd index the value. Fall back to the documented positional
    // index only when the key is absent.
    let by_key = |key: &str| -> Option<&str> {
        fields
            .iter()
            .step_by(2)
            .position(|k| *k == key)
            .and_then(|pair| fields.get(pair * 2 + 1))
            .copied()
    };
    let at = |key: &str, idx: usize| by_key(key).or_else(|| fields.get(idx).copied());

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
