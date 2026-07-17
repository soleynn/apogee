//! Scripted login and registration exchanges for driving the login flow without a network.
//!
//! Each helper returns a [`ProtoResponse`] shaped like a real Square Enix answer for one step of the
//! flow, so a test can script a [`crate::transport::FixtureTransport`] for any branch (open/closed
//! service, terms not accepted, no active service, current game, pending patches, boot patch needed,
//! version not serviced). Bodies are sanitized synthetic markup, not captures; the parsers they feed
//! are oracle-pinned elsewhere.

use http::header::DATE;
use http::{HeaderName, HeaderValue};
use sqex_proto::ProtoResponse;

/// The `Date` header stamped on the OAuth top page (the flow uses it for TOTP clock-skew correction).
const SERVER_DATE: &str = "Wed, 09 Jul 2025 12:00:00 GMT";

/// The response header carrying the registration unique id.
const UID_HEADER: &str = "x-patch-unique-id";

/// A login-server status page reporting the service is open.
#[must_use]
pub fn login_status_open() -> ProtoResponse {
    ProtoResponse::new(200, br#"{"status": true}"#.to_vec())
}

/// A login-server status page reporting the service is closed, carrying a maintenance `message`.
#[must_use]
pub fn login_status_closed(message: &str) -> ProtoResponse {
    let body = format!(r#"{{"status": false, "message": ["{message}"], "news": []}}"#);
    ProtoResponse::new(200, body.into_bytes())
}

/// The OAuth top page carrying the hidden `_STORED_` blob and a `Date` header.
#[must_use]
pub fn oauth_top(stored: &str) -> ProtoResponse {
    let body = format!(
        r#"<html><body><form><input type="hidden" name="_STORED_" value="{stored}"></form></body></html>"#
    );
    ProtoResponse::new(200, body.into_bytes())
        .with_header(DATE, HeaderValue::from_static(SERVER_DATE))
}

/// The `window.external.user(...)` result line, with per-field values chosen by the caller.
fn oauth_user_body(
    session_id: &str,
    terms: u8,
    region: u16,
    playable: u8,
    max_expansion: u8,
) -> String {
    format!(
        r#"<script>window.external.user("login=auth,ok,sid,{session_id},terms,{terms},region,{region},etmadd,0,playable,{playable},ps3pkg,0,maxex,{max_expansion},product,ffxiv");</script>"#
    )
}

/// A successful submit: authenticated, terms accepted, active service.
#[must_use]
pub fn submit_success(session_id: &str, region: u16, max_expansion: u8) -> ProtoResponse {
    ProtoResponse::new(
        200,
        oauth_user_body(session_id, 1, region, 1, max_expansion).into_bytes(),
    )
}

/// A submit where authentication succeeded but the terms of service are not yet accepted.
#[must_use]
pub fn submit_terms_not_accepted(
    session_id: &str,
    region: u16,
    max_expansion: u8,
) -> ProtoResponse {
    ProtoResponse::new(
        200,
        oauth_user_body(session_id, 0, region, 1, max_expansion).into_bytes(),
    )
}

/// A submit where authentication succeeded but the account has no active service.
#[must_use]
pub fn submit_no_service(session_id: &str, region: u16, max_expansion: u8) -> ProtoResponse {
    ProtoResponse::new(
        200,
        oauth_user_body(session_id, 1, region, 0, max_expansion).into_bytes(),
    )
}

/// A submit that failed authentication (the `login=auth,ng,...` callback), which the OAuth parser
/// reports as `ProtoError::OauthFailed`. The message is credential-free.
#[must_use]
pub fn submit_auth_failed() -> ProtoResponse {
    ProtoResponse::new(
        200,
        br#"<script>window.external.user("login=auth,ng,err,authentication failed");</script>"#
            .to_vec(),
    )
}

/// Attach the registration unique-id header to `response`.
fn with_uid(response: ProtoResponse, unique_id: &str) -> ProtoResponse {
    let value =
        HeaderValue::from_str(unique_id).unwrap_or_else(|_| HeaderValue::from_static("invalid"));
    response.with_header(HeaderName::from_static(UID_HEADER), value)
}

/// A registration response for a current game: `204 No Content` with the UID header and no body
/// (the shape the live service returns for an up-to-date install).
#[must_use]
pub fn register_current(unique_id: &str) -> ProtoResponse {
    with_uid(ProtoResponse::new(204, Vec::new()), unique_id)
}

/// A registration response reporting pending game patches: `200` with the UID header and a multipart
/// patch list built from `entries` (each a nine-field patch line, e.g. [`synthetic_patch_entry`]).
#[must_use]
pub fn register_with_patches(unique_id: &str, entries: &[&str]) -> ProtoResponse {
    with_uid(ProtoResponse::new(200, game_patchlist(entries)), unique_id)
}

/// A registration response requiring a boot patch first (`409 Conflict`).
#[must_use]
pub fn register_needs_boot() -> ProtoResponse {
    ProtoResponse::new(409, Vec::new())
}

/// A registration response for a version Square Enix no longer services (`410 Gone`).
#[must_use]
pub fn register_not_serviced() -> ProtoResponse {
    ProtoResponse::new(410, Vec::new())
}

/// A nine-field game patch entry of `length` bytes at `version_id`, for building
/// [`register_with_patches`] bodies. Two per-block SHA1s so the parser records hashes.
#[must_use]
pub fn synthetic_patch_entry(length: u64, version_id: &str) -> String {
    let h1 = "a".repeat(40);
    let h2 = "b".repeat(40);
    format!(
        "{length}\t0\t0\t0\tD{version_id}\tsha1\t52428800\t{h1},{h2}\t\
         http://patch-dl.example.invalid/game/synthetic/D{version_id}.patch"
    )
}

/// Wrap nine-field game patch entries in the multipart envelope the patch-list parser expects.
fn game_patchlist(entries: &[&str]) -> Vec<u8> {
    let boundary = "--SYNTHETIC_BOUNDARY_APOGEE";
    let mut body = String::new();
    for header in [
        boundary,
        "Content-Type: application/octet-stream",
        "Content-Location: ffxivpatch/synthetic/metainfo/x.http",
        "X-Patch-Length: 0",
        "",
    ] {
        body.push_str(header);
        body.push_str("\r\n");
    }
    for entry in entries {
        body.push_str(entry);
        body.push_str("\r\n");
    }
    body.push_str(boundary);
    body.push_str("--\r\n");
    body.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqex_proto::parse_patch_list;

    #[test]
    fn pending_patch_body_parses_through_the_real_patch_list_parser() {
        let response = register_with_patches(
            "UID-TOKEN",
            &[
                &synthetic_patch_entry(52_430_000, "2024.03.28.0000.0001"),
                &synthetic_patch_entry(10, "2024.03.28.0000.0002"),
            ],
        );
        let body = String::from_utf8(response.body).unwrap();
        let entries = parse_patch_list(&body).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].length, 52_430_000);
        assert_eq!(entries[1].length, 10);
        assert!(entries[0].hashes.is_some());
    }

    #[test]
    fn register_dispositions_carry_the_expected_status() {
        assert_eq!(register_current("UID").status, 204);
        assert_eq!(register_needs_boot().status, 409);
        assert_eq!(register_not_serviced().status, 410);
    }
}
