//! The OAuth page scanners.
//!
//! Hand-written, anchored scanners read the SE login pages: two lift attribute values out of the top
//! page (the opaque `_STORED_` blob, and on a Steam login the linked account id), the third reads the
//! `launchParams` list out of the success callback. All see hostile input over plain HTTP, so they
//! follow the patchlist parser's discipline: fixed ASCII anchors, bounded search windows,
//! length-capped captures, and no panics on any byte sequence. They hold no transport and no
//! credentials, and their errors carry a count or a length-capped page excerpt, never the submitted
//! secrets or the session id.

use zeroize::Zeroizing;

use crate::error::{ProtoError, scrubbed_excerpt};

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
/// The attribute pair that anchors the Steam-linked id. The page also carries the *visible* login
/// form's `<input class="item-input" name="sqexid" id="sqexid" type="text" value="">`, whose value is
/// empty, so anchoring on the name alone would find the wrong element and read a blank id. The
/// hidden-input shape is the one XL matches (`Launcher.cs:502`), and its working in the wild is the
/// only evidence for the markup: no capture of a Steam top page exists here.
const STEAM_ID_ANCHOR: &str = "name=\"sqexid\" type=\"hidden\"";
/// The most bytes the linked-id capture keeps. SE ids are short; the page caps its own input at 16
/// characters, and this leaves room for an address-shaped one.
const MAX_STEAM_ID: usize = 128;
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
    /// The OAuth session id: becomes the session-registration path segment and `DEV.TestSID`.
    pub session_id: Zeroizing<String>,
    /// Whether the account has accepted SE's terms of service.
    pub terms_accepted: bool,
    /// The account's region, forwarded to the launch args (`SYS.Region`).
    pub region: u16,
    /// Whether the account has an active service.
    pub playable: bool,
    /// The entitled maximum expansion.
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
/// capturing up to the closing quote under a hard length cap. An empty capture is a miss, as it is for
/// the (crate-private) Steam-linked-id scan: a blank blob is not a session, and carrying one into the
/// submit would defer the real diagnosis (a page that no longer has the shape this scanner reads) to a
/// later, vaguer failure. Any miss is a [`ProtoError::StoredNotFound`] carrying a length-capped page
/// excerpt, scrubbed of `secrets`: the top page carries no submitted credentials, but a Steam login's
/// request query carries a bearer ticket the page can reflect back. Callers pass the same list they
/// scrub their own OAuth-top excerpts with. The returned slice borrows `html`.
pub fn scrape_stored<'h>(html: &'h str, secrets: &[&str]) -> Result<&'h str, ProtoError> {
    attribute_value(html, STORED_ANCHOR, MAX_STORED)
        .filter(|stored| !stored.is_empty())
        .ok_or_else(|| ProtoError::StoredNotFound {
            excerpt: scrubbed_excerpt(html.as_bytes(), secrets),
        })
}

/// Lift the SE account id the Steam ticket is linked to out of the login top page.
///
/// Present only on a `issteam=1` top page; a standard page carries the empty visible input this
/// deliberately does not match ([`STEAM_ID_ANCHOR`]). `None` covers both the missing element and an
/// empty value, which the flow treats alike: without an id there is nothing to check the submitted
/// username against, and submitting anyway would send credentials to a page whose account is unknown.
pub(crate) fn scrape_steam_id(html: &str) -> Option<&str> {
    attribute_value(html, STEAM_ID_ANCHOR, MAX_STEAM_ID).filter(|id| !id.is_empty())
}

/// The `value="…"` following `anchor` within a bounded window, capped at `max` bytes.
///
/// The window is also scoped to the anchor's own element: a `<` or `>` before `value="` means the scan
/// has walked out of that tag, and the next element's value describes a different input. Nothing in
/// HTML fixes attribute order, so a page that emits `value=` ahead of `name=` reads as a miss rather
/// than as its neighbour's value, which on a real top page is the empty visible sqexid input.
///
/// `find` returns an ASCII boundary and every delimiter here is ASCII, so no slice can split a
/// multi-byte character. A closing quote past the cap reads as absent rather than truncating, so a
/// page with no closing quote cannot hand back a runaway capture.
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

/// What a key names when the list is searched by key rather than read at its documented position.
enum KeyLookup<'a> {
    /// Exactly one pair carries the key, and it has a value.
    Found(&'a str),
    /// No pair carries the key (or the one that does is a dangling final field): the documented
    /// position decides instead.
    Absent,
    /// Two or more pairs carry the key, so no value can be attributed to it.
    Ambiguous,
}

/// The value paired with `key`, searching the whole list.
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

/// Parse the comma-separated `launchParams` list.
///
/// The list is `key,value,key,value,...`; XL reads the values positionally (idx 1 `sid`, 3 `terms`,
/// 5 `region`, 9 `playable`, 13 `maxex`), never looking at the key names. This reads each field in a
/// fixed precedence:
///
/// 1. the documented position, when the key sits beside it (the canonical shape, and the same bytes XL
///    reads);
/// 2. otherwise the pair carrying that key, wherever it moved to, so a reorder or a trimmed field
///    still parses;
/// 3. otherwise, with the key nowhere in the list, the documented position anyway, so a renamed key
///    still parses.
///
/// A key appearing more than once away from its documented position resolves to no value at all: two
/// pairs claim the name, reading either would be a guess, and a first-match-wins search would let the
/// earlier one silently override the value XL would read. A list too short to yield the required
/// fields is rejected the same way. `Err` is the number of comma-separated fields found (never their
/// contents, which include the session id).
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
