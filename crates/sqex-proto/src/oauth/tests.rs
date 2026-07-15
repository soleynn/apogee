//! Unit tests for the OAuth page scanners. Inputs are synthetic (no SE bytes); the flow itself is
//! exercised end-to-end through the fixture transport in `tests/oauth.rs`.

use proptest::prelude::*;

use super::scan::{
    CallbackReject, is_restartup, parse_launch_params, parse_login_callback, scrape_stored,
};
use crate::error::ProtoError;

const FULL_PARAMS: &str =
    "sid,SESSIONABC,terms,1,region,3,etmadd,0,playable,1,ps3pkg,0,maxex,4,product,xyz";

#[test]
fn scrape_stored_lifts_the_value_past_other_attributes() {
    let html = r#"<input type="hidden" name="_STORED_" value="blob-12345">"#;
    assert_eq!(scrape_stored(html).unwrap(), "blob-12345");
}

#[test]
fn scrape_stored_without_the_anchor_is_stored_not_found() {
    let html = r#"<form><input name="user" value="x"></form>"#;
    assert!(matches!(
        scrape_stored(html),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_with_an_unterminated_value_is_stored_not_found() {
    let html = r#"<input name="_STORED_" value="never-closed"#;
    assert!(matches!(
        scrape_stored(html),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_rejects_a_value_beyond_the_attribute_window() {
    let html = format!(r#"<input name="_STORED_" {}value="late">"#, " ".repeat(100));
    assert!(matches!(
        scrape_stored(&html),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn scrape_stored_caps_a_runaway_value() {
    // A closing quote past the length cap is treated as absent, so the capture cannot run away.
    let html = format!(r#"<input name="_STORED_" value="{}">"#, "x".repeat(5000));
    assert!(matches!(
        scrape_stored(&html),
        Err(ProtoError::StoredNotFound { .. })
    ));
}

#[test]
fn launch_params_reads_by_key() {
    let params = parse_launch_params(FULL_PARAMS).unwrap();
    assert_eq!(params.session_id, "SESSIONABC");
    assert!(params.terms_accepted);
    assert_eq!(params.region, 3);
    assert!(params.playable);
    assert_eq!(params.max_expansion, 4);
}

#[test]
fn launch_params_falls_back_to_position_when_keys_are_unknown() {
    // Keys renamed so only the positional fallback can resolve the fields.
    let params = parse_launch_params("k0,SID,k2,1,k4,3,k6,0,k8,1,k10,0,k12,4").unwrap();
    assert_eq!(params.session_id, "SID");
    assert_eq!(params.region, 3);
    assert_eq!(params.max_expansion, 4);
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
fn login_callback_reads_a_success_body() {
    let body = format!(r#"<script>window.external.user("login=auth,ok,{FULL_PARAMS}");</script>"#);
    let params = parse_login_callback(&body).unwrap();
    assert_eq!(params.session_id, "SESSIONABC");
    assert_eq!(params.region, 3);
}

#[test]
fn login_callback_rejects_a_failure_page() {
    let body = r#"<html><body>The password you entered is incorrect.</body></html>"#;
    assert!(matches!(
        parse_login_callback(body),
        Err(CallbackReject::NotAuthOk)
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
        params.session_id,
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
        let _ = scrape_stored(&s);
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
