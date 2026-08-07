//! Unit tests for the OAuth page scanners. Inputs are synthetic (no SE bytes); the flow itself is
//! exercised end-to-end through the fixture transport in `tests/oauth.rs`.

use proptest::prelude::*;

use super::scan::{
    CallbackReject, is_restartup, parse_launch_params, parse_login_callback, scrape_steam_id,
    scrape_stored,
};
use super::{eq_ordinal_ignore_case, mask_id};
use crate::error::ProtoError;

const FULL_PARAMS: &str =
    "sid,SESSIONABC,terms,1,region,3,etmadd,0,playable,1,ps3pkg,0,maxex,4,product,xyz";

#[test]
fn scrape_stored_lifts_the_value_past_other_attributes() {
    let html = r#"<input type="hidden" name="_STORED_" value="blob-12345">"#;
    assert_eq!(scrape_stored(html, &[]).unwrap(), "blob-12345");
}

#[test]
fn scrape_stored_without_the_anchor_is_stored_not_found() {
    let html = r#"<form><input name="user" value="x"></form>"#;
    assert!(matches!(
        scrape_stored(html, &[]),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_with_an_unterminated_value_is_stored_not_found() {
    let html = r#"<input name="_STORED_" value="never-closed"#;
    assert!(matches!(
        scrape_stored(html, &[]),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_rejects_a_value_beyond_the_attribute_window() {
    let html = format!(r#"<input name="_STORED_" {}value="late">"#, " ".repeat(100));
    assert!(matches!(
        scrape_stored(&html, &[]),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_caps_a_runaway_value() {
    // A closing quote past the length cap is treated as absent, so the capture cannot run away.
    let html = format!(r#"<input name="_STORED_" value="{}">"#, "x".repeat(5000));
    assert!(matches!(
        scrape_stored(&html, &[]),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_rejects_an_empty_value() {
    // An empty blob is not a session. Accepting one submits a blank `_STORED_` and turns the real
    // diagnosis, a top page that no longer has the shape this scanner reads, into a vaguer failure one
    // request later.
    let html = r#"<input type="hidden" name="_STORED_" value="">"#;
    assert!(matches!(
        scrape_stored(html, &[]),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_does_not_read_a_neighbouring_element() {
    // Nothing in HTML fixes attribute order, so a page emitting `value=` before `name=` walks the
    // window out of the `_STORED_` tag and into the next element, whose value belongs to a different
    // input. Here that neighbour holds a value, so only the tag-boundary check refuses it.
    let html =
        r#"<input value="REALSTOREDBLOB" name="_STORED_"><input name="sqexid" value="someone">"#;
    assert!(matches!(
        scrape_stored(html, &[]),
        Err(ProtoError::StoredNotFound { .. })
    ));
    // The reported shape: on a real top page that neighbour is the empty visible sqexid input.
    let empty_neighbour =
        r#"<input value="REALSTOREDBLOB" name="_STORED_"><input name="sqexid" value="">"#;
    assert!(matches!(
        scrape_stored(empty_neighbour, &[]),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_scrubs_a_secret_reflected_with_no_labelling_prefix() {
    // No `_STORED_` anchor, so this is the caller's error path; the page reflects a bare secret
    // (a Steam ticket echoed with no `session_ticket=` prefix a shape-based redaction could key on),
    // so only a caller-supplied scrub list catches it.
    let html = r#"<html>debug: rejected ticket SECRETTICKET123</html>"#;
    let Err(ProtoError::StoredNotFound { excerpt }) = scrape_stored(html, &["SECRETTICKET123"])
    else {
        panic!("expected StoredNotFound");
    };
    assert!(!excerpt.contains("SECRETTICKET123"), "leaked: {excerpt}");
    assert!(excerpt.contains("[redacted]"), "{excerpt}");
}

/// The visible login form's own username input, present on every top page including a Steam one.
const VISIBLE_INPUT: &str =
    r#"<input class="item-input" name="sqexid" id="sqexid" type="text" value="" tabindex="1">"#;

#[test]
fn steam_id_is_read_from_the_hidden_input() {
    let html = format!(
        r#"{VISIBLE_INPUT}<input name="sqexid" type="hidden" value="linked@example.invalid"/>"#
    );
    assert_eq!(scrape_steam_id(&html), Some("linked@example.invalid"));
}

#[test]
fn steam_id_ignores_the_visible_input() {
    // The empty visible input precedes the hidden one on the page and carries the same `name`. An
    // anchor that matched it would read a blank id, and the flow would submit against no account.
    assert_eq!(scrape_steam_id(VISIBLE_INPUT), None);
}

#[test]
fn steam_id_treats_an_empty_value_as_absent() {
    let html = r#"<input name="sqexid" type="hidden" value=""/>"#;
    assert_eq!(scrape_steam_id(html), None);
}

#[test]
fn steam_id_caps_a_runaway_value() {
    let html = format!(
        r#"<input name="sqexid" type="hidden" value="{}">"#,
        "x".repeat(500)
    );
    assert_eq!(scrape_steam_id(&html), None);
}

#[test]
fn a_masked_id_keeps_the_ends_and_reports_no_length() {
    assert_eq!(mask_id("testuser"), "t***r");
    // Two ids of different lengths mask alike, so the hint cannot be counted back to one.
    assert_eq!(mask_id("tr"), "***");
    assert_eq!(mask_id("t"), "***");
    assert_eq!(mask_id(""), "***");
}

#[test]
fn account_ids_fold_case_past_ascii() {
    // The launcher's `OrdinalIgnoreCase` reads these as one account; an ASCII-only fold refuses them
    // and the login never reaches the server that would have accepted it.
    assert!(eq_ordinal_ignore_case("café-account", "CAFÉ-ACCOUNT"));
    assert!(eq_ordinal_ignore_case("ÅÄÖ", "åäö"));
    assert!(eq_ordinal_ignore_case("linked-account", "LINKED-ACCOUNT"));
}

#[test]
fn account_ids_fold_no_further_than_the_launcher_does() {
    // .NET's ordinal casing is one code point to one code point: `ß` has no single-char uppercase, so
    // it stays itself and does not match `SS`. Rust's `to_uppercase` would expand it and call these
    // the same account, accepting a pair the launcher refuses.
    assert!(!eq_ordinal_ignore_case("straße", "STRASSE"));
    // Nor does it keep the first character of an expansion it cannot use: that would fold `ß` to `S`
    // and equate two letters .NET holds apart.
    assert!(!eq_ordinal_ignore_case("ß", "S"));
    // Different letters, not different cases of one.
    assert!(!eq_ordinal_ignore_case("é", "e"));
    assert!(!eq_ordinal_ignore_case("linked-account", "someone-else"));
}

#[test]
fn the_turkish_dotless_i_and_long_s_do_not_fold_to_their_lookalike() {
    // Unicode's simple uppercase mapping sends U+0131 to 'I' and U+017F to 'S', but a real .NET
    // OrdinalIgnoreCase run refuses both: folding them the general way would let an id typed with the
    // wrong letter pass as a match for one typed with the right one, weakening the check this
    // comparison exists to enforce. Verified against a real `dotnet` run.
    assert!(!eq_ordinal_ignore_case("\u{0131}", "I"));
    assert!(!eq_ordinal_ignore_case("\u{0131}", "i"));
    assert!(!eq_ordinal_ignore_case("\u{017F}", "S"));
    assert!(!eq_ordinal_ignore_case("\u{017F}", "s"));
}

#[test]
fn the_greek_iota_subscript_pairs_fold_together() {
    // Each pair's full Unicode uppercase mapping expands to two characters (a base letter plus
    // capital iota), so the general single-char fold leaves every pair distinct; a real .NET
    // OrdinalIgnoreCase run folds them together anyway. One pair from each of the three eight-wide
    // blocks, plus all three bare-iota-subscript singles: the whole reachable block, not just the
    // finding's headline example.
    assert!(eq_ordinal_ignore_case("\u{1F80}", "\u{1F88}"));
    assert!(eq_ordinal_ignore_case("\u{1F87}", "\u{1F8F}"));
    assert!(eq_ordinal_ignore_case("\u{1F90}", "\u{1F98}"));
    assert!(eq_ordinal_ignore_case("\u{1F97}", "\u{1F9F}"));
    assert!(eq_ordinal_ignore_case("\u{1FA0}", "\u{1FA8}"));
    assert!(eq_ordinal_ignore_case("\u{1FA7}", "\u{1FAF}"));
    assert!(eq_ordinal_ignore_case("\u{1FB3}", "\u{1FBC}"));
    assert!(eq_ordinal_ignore_case("\u{1FC3}", "\u{1FCC}"));
    assert!(eq_ordinal_ignore_case("\u{1FF3}", "\u{1FFC}"));
    // A pair from two different blocks must still not fold together.
    assert!(!eq_ordinal_ignore_case("\u{1F80}", "\u{1F90}"));
    assert!(!eq_ordinal_ignore_case("\u{1FB3}", "\u{1FC3}"));
}

#[test]
fn a_masked_id_splits_on_characters_not_bytes() {
    // A byte-indexed mask would panic here, and a byte count would call this id four long.
    assert_eq!(mask_id("héllo"), "h***o");
    assert_eq!(mask_id("åä"), "***");
}

#[test]
fn launch_params_reads_by_key() {
    let params = parse_launch_params(FULL_PARAMS).unwrap();
    assert_eq!(params.session_id.as_str(), "SESSIONABC");
    assert!(params.terms_accepted);
    assert_eq!(params.region, 3);
    assert!(params.playable);
    assert_eq!(params.max_expansion, 4);
}

#[test]
fn launch_params_falls_back_to_position_when_keys_are_unknown() {
    // Keys renamed so only the positional fallback can resolve the fields.
    let params = parse_launch_params("k0,SID,k2,1,k4,3,k6,0,k8,1,k10,0,k12,4").unwrap();
    assert_eq!(params.session_id.as_str(), "SID");
    assert_eq!(params.region, 3);
    assert_eq!(params.max_expansion, 4);
}

#[test]
fn launch_params_reads_the_documented_position_when_the_key_confirms_it() {
    // Only the key text at index 6 is renamed; the real playable pair (8/9) is untouched, so a
    // positional read still says playable. A search that took the first pair named `playable` would
    // read index 7 instead and call an entitled account unplayable.
    let params = parse_launch_params(
        "sid,SESSIONABC,terms,1,region,3,playable,0,playable,1,ps3pkg,0,maxex,4,product,xyz",
    )
    .unwrap();
    assert!(params.playable);
}

#[test]
fn launch_params_finds_a_key_that_moved_off_its_position() {
    // A leading pair shifts every documented index by one, so nothing is where XL would read it and
    // the key search resolves the whole list.
    let params = parse_launch_params(
        "pad,0,sid,SHIFTED,terms,1,region,3,etmadd,0,playable,1,ps3pkg,0,maxex,4",
    )
    .unwrap();
    assert_eq!(params.session_id.as_str(), "SHIFTED");
    assert_eq!(params.region, 3);
    assert!(params.playable);
    assert_eq!(params.max_expansion, 4);
}

#[test]
fn launch_params_rejects_a_key_duplicated_off_its_position() {
    // The same shifted list, with a second `sid` pair. Two pairs claim the name and neither sits at
    // the documented position, so there is no value to attribute to it: first-match-wins would hand
    // back `FIRST`, an attacker-or-error-chosen session id, with no signal.
    let params = "pad,0,sid,FIRST,sid,SECOND,terms,1,region,3,etmadd,0,playable,1,ps3pkg,0,maxex,4";
    assert!(parse_launch_params(params).is_err());
}

#[test]
fn launch_params_reads_zero_as_no_terms_and_no_service() {
    let params =
        parse_launch_params("sid,X,terms,0,region,3,etmadd,0,playable,0,ps3pkg,0,maxex,4").unwrap();
    assert!(!params.terms_accepted);
    assert!(!params.playable);
}

#[test]
fn launch_params_rejects_a_too_short_list() {
    // `LaunchParams` implements no `Debug`/`PartialEq` (it holds the session id), so match the shape.
    assert!(matches!(parse_launch_params("sid,X,terms,1"), Err(4)));
}

#[test]
fn launch_params_rejects_a_non_numeric_region() {
    let params = "sid,X,terms,1,region,ZZ,etmadd,0,playable,1,ps3pkg,0,maxex,4";
    assert!(parse_launch_params(params).is_err());
}

#[test]
fn launch_params_rejects_an_empty_session_id() {
    // A blank sid value must be rejected by the non-empty guard, not accepted as an empty session.
    // The list is otherwise full-length, so a rejection here is the sid guard, not a too-short list.
    let params = "sid,,terms,1,region,3,etmadd,0,playable,1,ps3pkg,0,maxex,4";
    assert!(parse_launch_params(params).is_err());
}

#[test]
fn login_callback_reads_a_success_body() {
    let body = format!(r#"<script>window.external.user("login=auth,ok,{FULL_PARAMS}");</script>"#);
    let params = parse_login_callback(&body).unwrap();
    assert_eq!(params.session_id.as_str(), "SESSIONABC");
    assert_eq!(params.region, 3);
}

#[test]
fn login_callback_rejects_a_page_without_a_callback() {
    let body = r#"<html><body>The password you entered is incorrect.</body></html>"#;
    assert!(matches!(
        parse_login_callback(body),
        Err(CallbackReject::NotAuthOk { message: None })
    ));
}

#[test]
fn login_callback_extracts_the_failure_message() {
    let body = r#"<script>window.external.user("login=auth,ng,err,ID or password is incorrect.");</script>"#;
    match parse_login_callback(body) {
        Err(CallbackReject::NotAuthOk {
            message: Some(message),
        }) => assert_eq!(message, "ID or password is incorrect."),
        _ => panic!("expected a failure message"),
    }
}

#[test]
fn login_callback_caps_a_runaway_success_payload() {
    // A closing quote past MAX_CALLBACK is treated as absent, the same way an oversized
    // `attribute_value` capture is: a huge `sid` field cannot ride the callback into `LaunchParams`
    // (and, downstream, into an error's secret-scrub list).
    let huge_sid = "x".repeat(20_000);
    let body = format!(
        r#"window.external.user("login=auth,ok,sid,{huge_sid},terms,1,region,3,etmadd,0,playable,1,ps3pkg,0,maxex,4");"#
    );
    assert!(matches!(
        parse_login_callback(&body),
        Err(CallbackReject::NotAuthOk { message: None })
    ));
}

#[test]
fn login_callback_flags_a_truncated_param_list() {
    let body = r#"window.external.user("login=auth,ok,sid,ABC");"#;
    assert!(matches!(
        parse_login_callback(body),
        Err(CallbackReject::Unparseable { got_fields: 2 })
    ));
}

#[test]
fn restartup_is_detected_only_when_present() {
    assert!(is_restartup(
        r#"<script>window.external.user("restartup");</script>"#
    ));
    assert!(!is_restartup(
        r#"<script>window.external.user("login=auth,ok,x");</script>"#
    ));
}

#[test]
fn full_parse_is_pinned() {
    let params = parse_launch_params(FULL_PARAMS).unwrap();
    let rendered = format!(
        "session_id={} terms={} region={} playable={} maxex={}",
        params.session_id.as_str(),
        params.terms_accepted,
        params.region,
        params.playable,
        params.max_expansion,
    );
    insta::assert_snapshot!(rendered);
}

proptest! {
    #[test]
    fn scrape_stored_never_panics(s in ".{0,300}") {
        let _ = scrape_stored(&s, &[]);
    }

    #[test]
    fn scrape_steam_id_never_panics(s in ".{0,300}") {
        let _ = scrape_steam_id(&s);
    }

    #[test]
    fn mask_id_never_panics(s in ".{0,300}") {
        let masked = mask_id(&s);
        prop_assert!(masked.chars().count() <= 5);
    }

    #[test]
    fn parse_launch_params_never_panics(s in ".{0,300}") {
        let _ = parse_launch_params(&s);
    }

    #[test]
    fn parse_login_callback_never_panics(s in ".{0,300}") {
        let _ = parse_login_callback(&s);
    }
}
