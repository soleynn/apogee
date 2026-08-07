//! Scripted login and registration exchanges for driving the login flow without a network.
//!
//! Each helper returns a [`ProtoResponse`] shaped like a real Square Enix answer for one step of the
//! flow, so a test can script a [`crate::transport::FixtureTransport`] for any branch (open/closed
//! service, terms not accepted, no active service, current game, pending patches, boot patch needed,
//! version not serviced). Bodies are sanitized synthetic markup, not captures; the parsers they feed
//! are oracle-pinned elsewhere.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::DATE;
use http::{HeaderName, HeaderValue};
use sqex_proto::ProtoResponse;

/// The scripted values a current-game login scenario assumes, so a test can pin the same session id,
/// unique id, and install versions into its fixtures, its game install, and its assertions.
pub const SESSION_ID: &str = "SESSIONXYZ";
pub const UNIQUE_ID: &str = "UID-TOKEN-0123456789";
pub const BOOT_VERSION: &str = "2024.02.01.0000.0000";
pub const GAME_VERSION: &str = "2024.03.28.0000.0000";
/// The SE account a Steam top page reports its ticket is linked to. Cased unlike the stored account
/// id on purpose: the page's spelling is the canonical one, and the check against it ignores case.
pub const STEAM_LINKED_ID: &str = "TestUser";

/// The `Date` header stamped on the OAuth top page, which is where the login flow reads the clock it
/// derives a one-time code against.
///
/// A fixed instant rather than the wall clock, and that is what makes a generated code assertable.
/// The correction is an offset, not a pinned instant: the flow measures `this - now` and the mint
/// then reads `now` again, so the two readings cancel and what the code is derived for collapses onto
/// this constant, whatever the machine running the test believes the time is.
const SERVER_DATE: &str = "Wed, 09 Jul 2025 12:00:00 GMT";

/// [`SERVER_DATE`] in seconds since the epoch, for a test computing the code the flow will send.
///
/// It sits on a thirty-second boundary on purpose. What the flow actually derives for is this instant
/// plus however long the run takes to reach the mint, so starting a window here leaves the whole of
/// one before the counter moves, instead of the fraction of a second an arbitrary instant would.
pub const SERVER_UNIX_SECS: u64 = 1_752_062_400;

/// [`SERVER_UNIX_SECS`] as an instant.
#[must_use]
pub fn server_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(SERVER_UNIX_SECS)
}

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
    top_page(stored).with_header(DATE, HeaderValue::from_static(SERVER_DATE))
}

/// [`oauth_top`] stamped with a clock the caller chooses, for driving a login whose skew is a known
/// quantity.
#[must_use]
pub fn oauth_top_at(stored: &str, at: SystemTime) -> ProtoResponse {
    let stamp = http_date(at);
    // The formatter emits printable ASCII and nothing else, so there is no instant it can name that
    // a header value cannot carry.
    let value = HeaderValue::from_str(&stamp).unwrap_or_else(|_| unreachable!("{stamp:?}"));
    top_page(stored).with_header(DATE, value)
}

/// [`oauth_top`] from a server that stamped no clock on its answer at all.
#[must_use]
pub fn oauth_top_undated(stored: &str) -> ProtoResponse {
    top_page(stored)
}

/// [`oauth_top`] carrying `date` verbatim, for driving what a caller does with a stamp it cannot
/// read. Every well-formed instant goes through [`oauth_top_at`] instead.
#[must_use]
pub fn oauth_top_stamped(stored: &str, date: &'static str) -> ProtoResponse {
    top_page(stored).with_header(DATE, HeaderValue::from_static(date))
}

/// The top page's body, before any header is stamped on it.
fn top_page(stored: &str) -> ProtoResponse {
    let body = format!(
        r#"<html><body><form><input type="hidden" name="_STORED_" value="{stored}"></form></body></html>"#
    );
    ProtoResponse::new(200, body.into_bytes())
}

/// An instant as the `IMF-fixdate` a server stamps on a response.
///
/// Written out rather than shared with the reader in `sqex-proto`: a formatter and a parser built
/// from one table agree with each other whether or not either agrees with the specification, and this
/// is the input that decides which code a test expects.
fn http_date(at: SystemTime) -> String {
    const DAY_NAMES: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    // An instant before the epoch is not one any of this is asked to render, and reads as the epoch.
    let seconds = at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // 1970-01-01 was a Thursday, which is why the table above starts there. Both indices below are
    // remainders of their own table's length, so neither can leave it.
    let day_name = DAY_NAMES[usize::try_from(days % 7).unwrap_or_default()];

    // Howard Hinnant's civil_from_days, in the positive half only: eras of four hundred years, with
    // March as the first month so a leap day falls at the end of the shifted year.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);

    format!(
        "{day_name}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        MONTHS[usize::try_from(month.saturating_sub(1) % 12).unwrap_or_default()],
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60,
    )
}

/// The OAuth top page a Steam login gets: the same blob, plus the hidden input naming the SE account
/// the ticket is linked to. The empty visible username field is there too, since the scanner has to
/// pass over it to find the hidden one.
#[must_use]
pub fn oauth_top_steam(stored: &str, linked: &str) -> ProtoResponse {
    let body = format!(
        r#"<html><body><form><input class="item-input" name="sqexid" id="sqexid" type="text" value="">
        <input name="sqexid" type="hidden" value="{linked}"/>
        <input type="hidden" name="_STORED_" value="{stored}"></form></body></html>"#
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
    with_uid(
        ProtoResponse::new(200, multipart_envelope(entries)),
        unique_id,
    )
}

/// A registration response requiring a boot patch first (`409 Conflict`).
#[must_use]
pub fn register_needs_boot() -> ProtoResponse {
    ProtoResponse::new(409, Vec::new())
}

/// The boot-version check response for a pending boot patch: a `200` body wrapping `entries` (each a
/// six-field boot patch line, e.g. [`synthetic_boot_entry`]) in the multipart envelope the patch-list
/// parser expects. Boot entries carry no per-block hashes.
#[must_use]
pub fn boot_patchlist(entries: &[&str]) -> ProtoResponse {
    ProtoResponse::new(200, multipart_envelope(entries))
}

/// The boot-version check response for a current boot component: `204 No Content`, the shape the
/// live service sends (`check_boot_version` also tolerates an empty `200` body).
#[must_use]
pub fn boot_current() -> ProtoResponse {
    ProtoResponse::new(204, Vec::new())
}

/// A six-field boot patch entry of `length` bytes at `version_id`, for building [`boot_patchlist`]
/// bodies. Boot entries carry no hashes; the URL sits in field 5 (boot integrity rides on ZiPatch
/// chunk CRCs, not per-block SHA1s).
#[must_use]
pub fn synthetic_boot_entry(length: u64, version_id: &str) -> String {
    format!(
        "{length}\t0\t0\t0\tD{version_id}\t\
         http://patch-dl.example.invalid/boot/2b5cbc63/D{version_id}.patch"
    )
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

/// Wrap patchlist entries (game or boot) in the multipart envelope the patch-list parser expects.
fn multipart_envelope(entries: &[&str]) -> Vec<u8> {
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
    fn boot_patchlist_body_parses_as_hashless_boot_entries() {
        let response = boot_patchlist(&[
            &synthetic_boot_entry(1_024, "2024.02.01.0000.0001"),
            &synthetic_boot_entry(2_048, "2024.02.01.0000.0002"),
        ]);
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        let entries = parse_patch_list(&body).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].length, 1_024);
        assert!(entries[0].hashes.is_none(), "boot entries carry no hashes");
        assert!(entries[1].url.contains("/boot/"));
    }

    #[test]
    fn boot_current_reports_no_pending_patches() {
        assert_eq!(boot_current().status, 204);
        assert!(boot_current().body.is_empty());
    }

    #[test]
    fn register_dispositions_carry_the_expected_status() {
        assert_eq!(register_current("UID").status, 204);
        assert_eq!(register_needs_boot().status, 409);
        assert_eq!(register_not_serviced().status, 410);
    }

    /// The formatter and the constant name one instant. Everything a flow test asserts about a
    /// generated code rests on those two agreeing, and they are written down independently.
    #[test]
    fn the_stamped_clock_and_its_constant_are_the_same_instant() {
        assert_eq!(http_date(server_time()), SERVER_DATE);
        assert_eq!(SERVER_UNIX_SECS % 30, 0, "the fixture starts a code window");
    }

    /// Round-tripped through the reader that will actually see it, so a formatter that agrees only
    /// with itself is caught here rather than as a wrong code in a flow test.
    #[test]
    fn what_is_stamped_is_what_the_protocol_crate_reads_back() {
        for offset in [0, 1, 59, 60, 86_399, 86_400, 951_868_800, 1_800_000_000] {
            let at = UNIX_EPOCH + Duration::from_secs(offset);
            assert_eq!(
                sqex_proto::parse_http_date(&http_date(at)),
                Some(at),
                "{offset}"
            );
        }
    }

    /// A leap day and the day either side of it, which is where a calendar conversion written from
    /// the wrong direction lands one day out.
    #[test]
    fn a_leap_day_formats_as_itself() {
        let leap_day = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(http_date(leap_day), "Thu, 29 Feb 2024 00:00:00 GMT");
        assert_eq!(
            http_date(leap_day - Duration::from_secs(86_400)),
            "Wed, 28 Feb 2024 00:00:00 GMT"
        );
        assert_eq!(
            http_date(leap_day + Duration::from_secs(86_400)),
            "Fri, 01 Mar 2024 00:00:00 GMT"
        );
    }

    /// The three top pages differ in exactly one thing: whether and when the server says it is.
    #[test]
    fn the_top_pages_differ_only_in_the_clock_they_carry() {
        let dated = oauth_top("BLOB");
        let undated = oauth_top_undated("BLOB");
        let chosen = oauth_top_at("BLOB", server_time() + Duration::from_secs(45));

        assert_eq!(dated.body, undated.body);
        assert_eq!(dated.body, chosen.body);
        assert!(undated.header(&DATE).is_none());
        assert_eq!(
            dated.header(&DATE).and_then(|v| v.to_str().ok()),
            Some(SERVER_DATE)
        );
        assert_eq!(
            chosen
                .header(&DATE)
                .and_then(|v| v.to_str().ok())
                .and_then(sqex_proto::parse_http_date),
            Some(server_time() + Duration::from_secs(45))
        );
    }
}
