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
use sqex_crypto::CryptoError;
// The ticket types through the re-export, which is how a consumer that has only this crate reaches
// them.
use sqex_proto::{
    ClientContext, ComputerId, Credentials, LauncherTime, LoginKind, OauthContext,
    ObfuscatedTicket, ProtoError, ProtoResponse, ServerTime, Step, begin_login,
};

const ACCEPT: &str = "image/gif, image/jpeg, image/pjpeg, application/x-ms-application, \
    application/xaml+xml, application/x-ms-xbap, */*";
const UA: &str = "SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)";
const TOP_URL: &str = "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/top\
    ?lng=en&rgn=3&isft=0&cssmode=1&isnew=1&launchver=3";
const SERVER_DATE: &str = "Wed, 09 Jul 2025 12:00:00 GMT";
/// [`SERVER_DATE`] as the instant a consumer reads back off the page.
///
/// Written out rather than derived from the header above, so what pins the reader is a value worked
/// out somewhere other than the code being tested.
const SERVER_UNIX_SECS: u64 = 1_752_062_400;

/// [`SERVER_DATE`] as an instant.
fn server_instant() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(SERVER_UNIX_SECS)
}

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

/// The SE account the fixture Steam pages report the ticket is linked to.
const LINKED_ID: &str = "linked-account";

/// A Steam top page: the standard one plus the hidden input naming the linked account.
fn steam_top_response(stored: &str, linked: &str) -> ProtoResponse {
    let body = format!(
        r#"<html><body><form><input class="item-input" name="sqexid" id="sqexid" type="text" value="">
        <input name="sqexid" type="hidden" value="{linked}"/>
        <input type="hidden" name="_STORED_" value="{stored}"></form></body></html>"#
    );
    ProtoResponse::new(200, body.into_bytes())
        .with_header(http::header::DATE, HeaderValue::from_static(SERVER_DATE))
}

/// A ticket long enough to carry both characters the query must not escape: 204 raw bytes expand to a
/// 416-byte block, which base64 pads (a `*`) and overruns the 300-character chunk (a `,`).
fn long_ticket() -> Result<ObfuscatedTicket, CryptoError> {
    let raw: Vec<u8> = (0..204u32).map(|i| (i % 251) as u8).collect();
    ObfuscatedTicket::from_auth_ticket(&raw, ServerTime(1_700_000_000))
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
        assert_eq!(flow.server_time(), Some(server_instant()));
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
            "connection: Keep-Alive",
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
            "connection: Keep-Alive",
            "cache-control: no-cache",
            "",
            "_STORED_=STOREDBLOB&sqexid=testuser&password=hunter2&otppw=",
        ]
        .join("\n")
    );
}

/// The two headers the reference launcher sends on this flow that were missing here.
///
/// Stated separately from the byte goldens above on purpose: a golden records what this crate emits,
/// so it agreed with the code the whole time the headers were absent. This one records what the
/// oracle emits (`Launcher.cs:475` for the top page, `:566-567` for the submit), which is the thing
/// the goldens are supposed to be checked against. Header fidelity on the login path is bit-exact
/// where SE plausibly sniffs, and a missing header is as visible as a wrong one.
#[test]
fn both_oauth_requests_keep_the_connection_and_the_submit_refuses_a_cache() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        top_response("STOREDBLOB"),
        ProtoResponse::new(200, success_body("SESSIONXYZ").into_bytes()),
    ]);

    block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Standard { free_trial: false },
        )
        .await
        .expect("the top page");
        flow.submit(Credentials {
            sqexid: "testuser",
            password: "hunter2",
            otp: None,
        })
        .await
        .expect("the submit")
    });

    let recorded = transport.recorded();
    let header = |request: &sqex_proto::ProtoRequest, name: &str| {
        request
            .headers
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| String::from_utf8_lossy(v.as_bytes()).into_owned())
    };

    assert_eq!(
        header(&recorded[0], "connection").as_deref(),
        Some("Keep-Alive")
    );
    assert_eq!(
        header(&recorded[1], "connection").as_deref(),
        Some("Keep-Alive")
    );
    // The oracle asks only the submit not to be cached, so the top page must not carry it either.
    assert_eq!(
        header(&recorded[1], "cache-control").as_deref(),
        Some("no-cache")
    );
    assert_eq!(header(&recorded[0], "cache-control"), None);
}

#[test]
fn a_steam_login_carries_the_ticket_unescaped_and_submits_the_linked_id() {
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let (text, size) = (ticket.text().to_owned(), ticket.length());
    let transport = FixtureTransport::new([
        steam_top_response("STOREDBLOB", LINKED_ID),
        ProtoResponse::new(200, success_body("SESSIONXYZ").into_bytes()),
    ]);

    block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Steam {
                ticket,
                free_trial: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(flow.steam_linked_id(), Some(LINKED_ID));
        // Cased differently from the page's id: SE ids are case-insensitive, so this is the same
        // account and must be accepted.
        flow.submit(Credentials {
            sqexid: "LINKED-ACCOUNT",
            password: "hunter2",
            otp: None,
        })
        .await
        .unwrap()
    });

    let recorded = transport.recorded();
    let request = canonical_request(&recorded[0]);
    let query = format!("&issteam=1&session_ticket={text}&ticket_size={size}");
    assert!(
        request.starts_with(&format!("GET {TOP_URL}{query}\n")),
        "top request: {request}"
    );
    // The separator is what form encoding would have escaped, so it is the one worth checking, and it
    // is asserted present on the ticket first: a ticket that stopped carrying one would otherwise make
    // the escaping check vacuous. (The padding `*` rides along unescaped either way.)
    assert!(text.contains(','), "ticket carried no separator: {text}");
    assert!(text.contains('*'), "ticket carried no padding: {text}");
    assert!(!request.contains("%2C"), "separator escaped: {request}");
    // The reported size is the encoded length before chunking, so it is short of the text by exactly
    // the separators. A caller that passed the text's length instead would be off by one here.
    assert_eq!(size, text.len() - text.matches(',').count());

    // The page's own id is submitted, not the caller's spelling of it.
    let body = String::from_utf8(recorded[1].body.as_ref().unwrap().as_bytes().to_vec()).unwrap();
    assert_eq!(
        body,
        format!("_STORED_=STOREDBLOB&sqexid={LINKED_ID}&password=hunter2&otppw=")
    );
}

#[test]
fn a_steam_free_trial_sets_isft_beside_the_ticket() {
    let id = computer_id();
    let transport = FixtureTransport::once(steam_top_response("S", LINKED_ID));

    block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket: long_ticket().unwrap(),
            free_trial: true,
        },
    ))
    .unwrap();

    let request = canonical_request(&transport.recorded()[0]);
    assert!(request.contains("&isft=1&"), "top request: {request}");
    assert!(request.contains("&issteam=1&"), "top request: {request}");
}

#[test]
fn a_steam_login_against_another_account_is_refused_before_the_submit() {
    let id = computer_id();
    let transport = FixtureTransport::once(steam_top_response("STOREDBLOB", LINKED_ID));

    let err = block_on(async {
        let flow = begin_login(
            &transport,
            &context(&id),
            &fixed_time(),
            LoginKind::Steam {
                ticket: long_ticket().unwrap(),
                free_trial: false,
            },
        )
        .await
        .unwrap();
        flow.submit(Credentials {
            sqexid: "someone-else",
            password: "hunter2",
            otp: None,
        })
        .await
        .unwrap_err()
    });

    let ProtoError::SteamWrongAccount { expected_hint } = err else {
        panic!("expected SteamWrongAccount, got {err:?}");
    };
    assert_eq!(expected_hint, "l***t");
    // One request only: the credentials were never sent to a page whose account the caller did not
    // name. The fixture transport holds a single response and would panic on a second request.
    assert_eq!(transport.recorded().len(), 1);
}

#[test]
fn a_restartup_on_a_steam_login_is_the_relink_signal() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(
        200,
        br#"<script>window.external.user("restartup");</script>"#.to_vec(),
    ));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket: long_ticket().unwrap(),
            free_trial: false,
        },
    ))
    .unwrap_err();
    assert!(matches!(err, ProtoError::SteamLinkNeeded));
}

#[test]
fn a_steam_top_page_without_a_linked_id_is_an_invalid_response() {
    let id = computer_id();
    // The standard page: `_STORED_` is there to be scraped, but no account is named. Answering it
    // would leave nothing to check the submitted username against.
    let transport = FixtureTransport::once(top_response("STOREDBLOB"));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket: long_ticket().unwrap(),
            free_trial: false,
        },
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
        assert_eq!(flow.server_time(), Some(server_instant()));
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
        assert_eq!(flow.server_time(), Some(server_instant()));
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
