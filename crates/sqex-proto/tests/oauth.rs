//! OAuth login integration tests: the top-page and submit requests are asserted byte-for-byte through
//! the fixture transport (the drift alarm), the flow's dispositions are checked, and the failure paths
//! are proven to keep the submitted credentials out of the error excerpt.
//!
//! The request-byte goldens use synthetic bodies (the request is ours regardless). The parser is also
//! run against committed fixtures under `fixtures/oauth_*.html`: sanitized captures of a real login
//! (credentials removed, the session id and `_STORED_` blob replaced with same-shape fakes), which pin
//! the scanners against genuine Square Enix page markup.

use apogee_test_support::rt::block_on;
use apogee_test_support::transport::{FixtureTransport, canonical_request};
use http::HeaderValue;
use sqex_proto::{
    ClientContext, ComputerId, Credentials, LauncherTime, LoginKind, OauthContext, ProtoError,
    ProtoResponse, Step, begin_login,
};

const ACCEPT: &str = "image/gif, image/jpeg, image/pjpeg, application/x-ms-application, \
    application/xaml+xml, application/x-ms-xbap, */*";
const UA: &str = "SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)";
const TOP_URL: &str = "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/top\
    ?lng=en&rgn=3&isft=0&cssmode=1&isnew=1&launchver=3";
const SERVER_DATE: &str = "Wed, 09 Jul 2025 12:00:00 GMT";

fn fixed_time() -> LauncherTime {
    LauncherTime::from_parts(2024, 1, 2, 3, 47, 1_704_164_820_000)
}

fn computer_id() -> ComputerId {
    ComputerId::from_facts("APOGEE-TEST", "apogee", "TESTOS-1.0", 8)
}

fn context(id: &ComputerId) -> OauthContext<'_> {
    OauthContext {
        client: ClientContext {
            computer_id: id,
            language: "en-us",
            accept_language: "en-US,en;q=0.9",
            referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
        },
        lng: "en",
        region: 3,
    }
}

fn top_page(stored: &str) -> String {
    format!(
        r#"<html><body><form><input type="hidden" name="_STORED_" value="{stored}"></form></body></html>"#
    )
}

fn success_body(session_id: &str) -> String {
    format!(
        r#"<script>window.external.user("login=auth,ok,sid,{session_id},terms,1,region,3,etmadd,0,playable,1,ps3pkg,0,maxex,4,product,ffxiv");</script>"#
    )
}

fn top_response(stored: &str) -> ProtoResponse {
    ProtoResponse::new(200, top_page(stored).into_bytes())
        .with_header(http::header::DATE, HeaderValue::from_static(SERVER_DATE))
}

#[test]
fn a_standard_login_builds_both_fingerprinted_requests() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        top_response("STOREDBLOB"),
        ProtoResponse::new(200, success_body("SESSIONXYZ").into_bytes()),
    ]);

    let auth = block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Standard { free_trial: false },
        )
        .await
        .unwrap();
        assert_eq!(flow.server_date(), Some(SERVER_DATE));
        assert_eq!(flow.steam_linked_id(), None);
        flow.submit(Credentials {
            sqexid: "testuser",
            password: "hunter2",
            otp: None,
        })
        .await
        .unwrap()
    });

    assert_eq!(auth.session_id().expose(), "SESSIONXYZ");
    assert_eq!(auth.region, 3);
    assert_eq!(auth.max_expansion, 4);
    assert!(auth.playable);
    assert!(auth.terms_accepted);

    let recorded = transport.recorded();
    assert_eq!(
        canonical_request(&recorded[0]),
        [
            &format!("GET {TOP_URL}"),
            &format!("user-agent: {UA}"),
            &format!("accept: {ACCEPT}"),
            "accept-encoding: gzip, deflate",
            "accept-language: en-US,en;q=0.9",
            r#"cookie: _rsid="""#,
            "referer: https://launcher.finalfantasyxiv.com/v700/?rc_lang=en_us&time=2024-01-02-03-47",
            "",
        ]
        .join("\n")
    );
    assert_eq!(
        canonical_request(&recorded[1]),
        [
            "POST https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/login.send",
            &format!("user-agent: {UA}"),
            &format!("accept: {ACCEPT}"),
            "accept-encoding: gzip, deflate",
            "accept-language: en-US,en;q=0.9",
            r#"cookie: _rsid="""#,
            &format!("referer: {TOP_URL}"),
            "content-type: application/x-www-form-urlencoded",
            "",
            "_STORED_=STOREDBLOB&sqexid=testuser&password=hunter2&otppw=",
        ]
        .join("\n")
    );
}

#[test]
fn an_otp_is_sent_in_the_submit_body() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        top_response("S"),
        ProtoResponse::new(200, success_body("SID").into_bytes()),
    ]);

    block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Standard { free_trial: false },
        )
        .await
        .unwrap();
        flow.submit(Credentials {
            sqexid: "user",
            password: "pw",
            otp: Some("123456"),
        })
        .await
        .unwrap()
    });

    let recorded = transport.recorded();
    let body = String::from_utf8(recorded[1].body.as_ref().unwrap().as_bytes().to_vec()).unwrap();
    assert_eq!(body, "_STORED_=S&sqexid=user&password=pw&otppw=123456");
}

#[test]
fn a_wrong_password_is_oauth_failed_with_a_scrubbed_excerpt() {
    let id = computer_id();
    // SE's structured `ng` message is the only page text ever surfaced; prove a credential reflected
    // inside it is scrubbed.
    let transport = FixtureTransport::new([
        top_response("STOREDBLOB"),
        ProtoResponse::new(
            200,
            br#"<script>window.external.user("login=auth,ng,err,Login failed for testuser using wrongpass");</script>"#.to_vec(),
        ),
    ]);

    let err = block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Standard { free_trial: false },
        )
        .await
        .unwrap();
        flow.submit(Credentials {
            sqexid: "testuser",
            password: "wrongpass",
            otp: None,
        })
        .await
        .unwrap_err()
    });

    let ProtoError::OauthFailed { excerpt } = err else {
        panic!("expected OauthFailed, got {err:?}");
    };
    assert!(!excerpt.contains("testuser"), "sqexid leaked: {excerpt}");
    assert!(!excerpt.contains("wrongpass"), "password leaked: {excerpt}");
    assert!(excerpt.contains("[redacted]"));
}

#[test]
fn a_top_page_without_stored_is_stored_not_found() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(
        200,
        b"<html><body>no token here</body></html>".to_vec(),
    ));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Standard { free_trial: false },
    ))
    .unwrap_err();
    assert!(matches!(err, ProtoError::StoredNotFound { .. }));
}

#[test]
fn a_restartup_on_a_standard_login_is_an_invalid_response() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(
        200,
        br#"<script>window.external.user("restartup");</script>"#.to_vec(),
    ));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Standard { free_trial: false },
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::OauthTop,
            ..
        }
    ));
}

#[test]
fn a_non_200_top_page_is_an_invalid_response() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(503, b"maintenance".to_vec()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Standard { free_trial: false },
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::OauthTop,
            status: 503,
            ..
        }
    ));
}

// The sanitized session id committed in fixtures/oauth_login_ok.html.
const FIXTURE_SID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef01234567";

#[test]
fn a_real_captured_login_parses_to_authenticated() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, include_bytes!("fixtures/oauth_top.html").to_vec())
            .with_header(http::header::DATE, HeaderValue::from_static(SERVER_DATE)),
        ProtoResponse::new(200, include_bytes!("fixtures/oauth_login_ok.html").to_vec()),
    ]);

    let auth = block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Standard { free_trial: false },
        )
        .await
        .unwrap();
        assert_eq!(flow.server_date(), Some(SERVER_DATE));
        flow.submit(Credentials {
            sqexid: "user",
            password: "pw",
            otp: None,
        })
        .await
        .unwrap()
    });

    assert_eq!(auth.session_id().expose(), FIXTURE_SID);
    assert_eq!(auth.region, 2);
    assert_eq!(auth.max_expansion, 5);
    assert!(auth.playable);
    assert!(auth.terms_accepted);

    // The `_STORED_` blob scraped from the real top page is echoed into the submit body.
    let recorded = transport.recorded();
    let body = String::from_utf8(recorded[1].body.as_ref().unwrap().as_bytes().to_vec()).unwrap();
    assert!(
        body.contains("_STORED_=00112233"),
        "submit body did not carry the scraped _STORED_: {body}"
    );
}

#[test]
fn a_real_captured_failure_page_is_oauth_failed() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, include_bytes!("fixtures/oauth_top.html").to_vec())
            .with_header(http::header::DATE, HeaderValue::from_static(SERVER_DATE)),
        ProtoResponse::new(
            200,
            include_bytes!("fixtures/oauth_wrong_password.html").to_vec(),
        ),
    ]);

    let err = block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Standard { free_trial: false },
        )
        .await
        .unwrap();
        flow.submit(Credentials {
            sqexid: "user",
            password: "wrong",
            otp: None,
        })
        .await
        .unwrap_err()
    });

    let ProtoError::OauthFailed { excerpt } = err else {
        panic!("expected OauthFailed, got {err:?}");
    };
    assert!(
        excerpt.contains("ID or password is incorrect"),
        "excerpt: {excerpt}"
    );
}

#[test]
fn a_real_captured_login_carries_an_otp_in_the_submit_body() {
    // A genuine 2FA login returns the same top and success pages as a no-OTP login (confirmed by
    // capture: byte-identical to oauth_top.html / oauth_login_ok.html), because the one-time password
    // is a request-side field only. So this replays the real fixtures but submits an OTP, proving the
    // code rides in the real request body alongside the scraped `_STORED_`, and that the top page's
    // `Date` (the input to skew-corrected code generation) is surfaced.
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, include_bytes!("fixtures/oauth_top.html").to_vec())
            .with_header(http::header::DATE, HeaderValue::from_static(SERVER_DATE)),
        ProtoResponse::new(200, include_bytes!("fixtures/oauth_login_ok.html").to_vec()),
    ]);

    let auth = block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Standard { free_trial: false },
        )
        .await
        .unwrap();
        assert_eq!(flow.server_date(), Some(SERVER_DATE));
        flow.submit(Credentials {
            sqexid: "user",
            password: "pw",
            otp: Some("135791"),
        })
        .await
        .unwrap()
    });

    assert_eq!(auth.session_id().expose(), FIXTURE_SID);
    assert!(auth.playable);

    let recorded = transport.recorded();
    let body = String::from_utf8(recorded[1].body.as_ref().unwrap().as_bytes().to_vec()).unwrap();
    assert!(
        body.contains("_STORED_=00112233"),
        "submit body did not carry the scraped _STORED_: {body}"
    );
    assert!(
        body.ends_with("&otppw=135791"),
        "submit body did not carry the otp: {body}"
    );
}
