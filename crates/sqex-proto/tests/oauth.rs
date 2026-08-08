// OAuth login integration tests: the top-page and submit requests are asserted byte-for-byte through
// the fixture transport (the drift alarm), the flow's dispositions are checked, and the failure paths
// are proven to keep the submitted credentials out of the error excerpt.
//
// The request-byte goldens use synthetic bodies (the request is ours regardless). The parser is also
// run against committed fixtures under fixtures/oauth_*.html: sanitized captures of a real login
// (credentials removed, the session id and _STORED_ blob replaced with same-shape fakes), which pin
// the scanners against genuine Square Enix page markup.

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
const SERVER_UNIX_SECS: u64 = 1_752_062_400;

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

const LINKED_ID: &str = "linked-account";

fn steam_top_response(stored: &str, linked: &str) -> ProtoResponse {
    let body = format!(
        r#"<html><body><form><input class="item-input" name="sqexid" id="sqexid" type="text" value="">
        <input name="sqexid" type="hidden" value="{linked}"/>
        <input type="hidden" name="_STORED_" value="{stored}"></form></body></html>"#
    );
    ProtoResponse::new(200, body.into_bytes())
        .with_header(http::header::DATE, HeaderValue::from_static(SERVER_DATE))
}

fn long_ticket() -> Result<ObfuscatedTicket, CryptoError> {
    let raw: Vec<u8> = (0..204u32).map(|i| (i % 251) as u8).collect();
    ObfuscatedTicket::from_auth_ticket(&raw, ServerTime(1_700_000_000))
}

fn secret_of_len(len: usize) -> String {
    (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect()
}

// Mirrors error.rs's private LEAK_FRAGMENT_LEN: a flat cap rather than a fraction of the secret's
// length, because none of the three redaction bugs found across PRs #131/#135/#138 leaked a fixed
// proportion of the secret.
const LEAK_FRAGMENT_LEN: usize = 16;

fn assert_no_partial_leak(text: &str, secret: &str) {
    let chars: Vec<char> = secret.chars().collect();
    let threshold = chars.len().clamp(1, LEAK_FRAGMENT_LEN);
    for window in chars.windows(threshold) {
        let fragment: String = window.iter().collect();
        assert!(
            !text.contains(&fragment),
            "partial leak: {fragment:?} (fragment of a {}-char secret) survives in {text:?}",
            chars.len()
        );
    }
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

const LINKED_ID_NON_ASCII: &str = "café-account";

#[test]
fn a_steam_login_folds_a_non_ascii_id_like_the_launcher() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        steam_top_response("STOREDBLOB", LINKED_ID_NON_ASCII),
        ProtoResponse::new(200, success_body("SESSIONXYZ").into_bytes()),
    ]);

    block_on(async {
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
        // The launcher's comparison folds this to the page's id and submits; an ASCII-only one refuses
        // the account the ticket is actually linked to, and `submit` returns `SteamWrongAccount`.
        flow.submit(Credentials {
            sqexid: "CAFÉ-ACCOUNT",
            password: "hunter2",
            otp: None,
        })
        .await
        .unwrap()
    });

    let recorded = transport.recorded();
    let body = String::from_utf8(recorded[1].body.as_ref().unwrap().as_bytes().to_vec()).unwrap();
    assert_eq!(
        body,
        "_STORED_=STOREDBLOB&sqexid=caf%C3%A9-account&password=hunter2&otppw="
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
fn a_username_that_prefixes_the_password_is_still_scrubbed() {
    let id = computer_id();
    // The submitted form reflected back by a 400 (a WAF block, an edge error page). The credentials
    // are prefix-shaped on purpose: the username is a literal prefix of the password, of the OTP, and
    // of the `_STORED_` blob. Redacting one secret at a time over a shared buffer eats the shared span
    // first, leaving each longer secret's tail in plaintext.
    let transport = FixtureTransport::new([
        top_response("aliceSTOREDBLOB"),
        ProtoResponse::new(
            400,
            b"rejected form _STORED_=aliceSTOREDBLOB&sqexid=alice&password=alice123!&otppw=alice42"
                .to_vec(),
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
            sqexid: "alice",
            password: "alice123!",
            otp: Some("alice42"),
        })
        .await
        .unwrap_err()
    });

    let ProtoError::InvalidResponse { excerpt, .. } = &err else {
        panic!("expected InvalidResponse, got {err:?}");
    };
    assert_eq!(
        excerpt,
        "rejected form _STORED_=[redacted]&sqexid=[redacted]&password=[redacted]&otppw=[redacted]"
    );
}

#[test]
fn a_reflected_top_url_does_not_leak_the_steam_ticket() {
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let text = ticket.text().to_owned();
    let size = ticket.length();
    // A non-200 whose body echoes the request URI back. The ticket rides in that URI unescaped, and it
    // is a bearer credential `sqex-crypto` refuses to `Display` at all.
    let body = format!(
        "Bad Request: {TOP_URL}&issteam=1&session_ticket={text}&ticket_size={size}\nreference #42"
    );
    let transport = FixtureTransport::once(ProtoResponse::new(400, body.into_bytes()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket,
            free_trial: false,
        },
    ))
    .unwrap_err();

    let ProtoError::InvalidResponse { excerpt, .. } = &err else {
        panic!("expected InvalidResponse, got {err:?}");
    };
    // The parameter lands ~50 characters inside the excerpt's window, so an unredacted excerpt carries
    // a long contiguous run of the real ticket.
    assert!(!excerpt.contains(&text[..16]), "ticket leaked: {excerpt}");
    assert!(
        excerpt.contains("session_ticket=[redacted]"),
        "excerpt: {excerpt}"
    );
}

#[test]
fn a_bare_reflected_ticket_is_scrubbed_by_value() {
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let text = ticket.text().to_owned();
    // The ticket echoed on its own, with no parameter name to redact by shape: the flow holds the
    // ticket at this arm, so the excerpt scrubs it by value as well.
    let body = format!("upstream rejected ticket {text}");
    let transport = FixtureTransport::once(ProtoResponse::new(400, body.into_bytes()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket,
            free_trial: false,
        },
    ))
    .unwrap_err();

    let ProtoError::InvalidResponse { excerpt, .. } = &err else {
        panic!("expected InvalidResponse, got {err:?}");
    };
    assert_eq!(excerpt, "upstream rejected ticket [redacted]");
}

#[test]
fn a_top_page_that_reflects_the_ticket_does_not_leak_it_when_stored_is_missing() {
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let text = ticket.text().to_owned();
    // The same reflection on a 200 page that carries a linked id but no `_STORED_`. This excerpt is
    // built by the page scanner, which is handed the page and never the ticket, so only a redaction by
    // shape can catch it.
    let body = format!(
        "Error: {TOP_URL}&issteam=1&session_ticket={text}\n\
         <input name=\"sqexid\" type=\"hidden\" value=\"{LINKED_ID}\"/>"
    );
    let transport = FixtureTransport::once(ProtoResponse::new(200, body.into_bytes()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket,
            free_trial: false,
        },
    ))
    .unwrap_err();

    let ProtoError::StoredNotFound { excerpt } = &err else {
        panic!("expected StoredNotFound, got {err:?}");
    };
    assert!(!excerpt.contains(&text[..16]), "ticket leaked: {excerpt}");
}

#[test]
fn a_bare_reflected_ticket_does_not_leak_when_stored_is_missing() {
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let text = ticket.text().to_owned();
    // The ticket echoed with no `session_ticket=` prefix to redact by shape, on a 200 page that
    // carries a linked id but no `_STORED_`: only a caller-supplied scrub list catches this one.
    let body = format!(
        "Error: upstream rejected ticket {text}\n\
         <input name=\"sqexid\" type=\"hidden\" value=\"{LINKED_ID}\"/>"
    );
    let transport = FixtureTransport::once(ProtoResponse::new(200, body.into_bytes()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket,
            free_trial: false,
        },
    ))
    .unwrap_err();

    let ProtoError::StoredNotFound { excerpt } = &err else {
        panic!("expected StoredNotFound, got {err:?}");
    };
    assert!(!excerpt.contains(&text[..16]), "ticket leaked: {excerpt}");
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

// The tests below drive every `ProtoError` variant that can carry redacted, attacker-influenced text
// through the real public API (`begin_login`/`LoginFlow::submit`), with adversarial secrets shaped to
// have tripped each of the three distinct credential-leak bugs found across PRs #131, #135, and #138:
// the original whole-buffer-replace-order bug (a secret that is a literal prefix of a longer one),
// the window-straddle bug (a secret reflected a second time far enough in to land past the window one
// redaction's shrinkage budgets for), and the truncation-bypass bug (an upstream length cap, like the
// OAuth failure message's now-removed `MAX_MESSAGE`, that ran before the redactor ever saw the whole
// secret). None of these call `scrubbed_excerpt`/`redact_secrets` directly: that style of test is
// exactly what let the second and third bugs slip past the first two review rounds.

#[test]
fn oauth_failed_scrubs_a_stored_blob_the_old_message_cap_would_have_cut() {
    // The confirmed truncation-bypass repro: the `_STORED_` blob scraped from the top page, reflected
    // once in the OAuth "ng" failure message, far enough in that the now-removed MAX_MESSAGE=512
    // pre-truncation in `oauth::scan::parse_login_callback` would have cut the message mid-secret
    // before it ever reached `scrubbed_excerpt`. That bug leaked 488 of a 720-char blob verbatim; this
    // uses the same 720-char shape. `scrubbed_excerpt`'s own window (`EXCERPT_MAX_CHARS + secret_len -
    // 1`, here 919) only ever protects a secret it is handed whole, so this test would pass for the
    // wrong reason (the window happening to be big enough) unless the message truly reaches it uncapped
    // — which is exactly the property `parse_login_callback` returning a borrow rather than an owned,
    // pre-truncated `String` is meant to guarantee.
    let id = computer_id();
    let blob = secret_of_len(720);
    let transport = FixtureTransport::new([
        top_response(&blob),
        ProtoResponse::new(
            200,
            format!(
                r#"<script>window.external.user("login=auth,ng,err,upstream rejected _STORED_={blob}");</script>"#
            )
            .into_bytes(),
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
    assert_no_partial_leak(&excerpt, &blob);
}

#[test]
fn oauth_failed_scrubs_a_password_reflected_twice_past_the_window() {
    // The window-straddle bug's shape, driven through `OauthFailed` specifically: no test drove this
    // variant through the real API with a secret long enough to matter before.
    let id = computer_id();
    let password = secret_of_len(90);
    let filler = "-".repeat(150);
    let transport = FixtureTransport::new([
        top_response("STOREDBLOB"),
        ProtoResponse::new(
            200,
            format!(
                r#"<script>window.external.user("login=auth,ng,err,rejected {password} again {filler}{password}");</script>"#
            )
            .into_bytes(),
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
            password: &password,
            otp: None,
        })
        .await
        .unwrap_err()
    });

    let ProtoError::OauthFailed { excerpt } = err else {
        panic!("expected OauthFailed, got {err:?}");
    };
    assert_no_partial_leak(&excerpt, &password);
}

#[test]
fn submit_scrubs_a_password_reflected_three_times_past_the_window() {
    // The window-straddle bug's shape, driven through submit's `InvalidResponse` arm (`Step::
    // OauthLogin`) rather than by calling `scrubbed_excerpt` directly.
    let id = computer_id();
    let password = secret_of_len(90);
    let mid1 = format!("&why={}", "-".repeat(15));
    let mid2 = format!("&again={}", "-".repeat(13));
    let body = format!("400: rejected form password={password}{mid1}{password}{mid2}{password}");
    let transport = FixtureTransport::new([
        top_response("STOREDBLOB"),
        ProtoResponse::new(400, body.into_bytes()),
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
            password: &password,
            otp: None,
        })
        .await
        .unwrap_err()
    });

    let ProtoError::InvalidResponse { excerpt, .. } = &err else {
        panic!("expected InvalidResponse, got {err:?}");
    };
    assert_no_partial_leak(excerpt, &password);
}

#[test]
fn a_reflected_top_url_does_not_leak_the_steam_ticket_past_the_window() {
    // The window-straddle bug's shape, driven through `begin_login`'s `OauthTop` `InvalidResponse` arm
    // with two reflections rather than the one `a_reflected_top_url_does_not_leak_the_steam_ticket`
    // uses.
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let text = ticket.text().to_owned();
    let filler = " ".repeat(150);
    let body = format!("Bad Request: reference {text}{filler}{text}");
    let transport = FixtureTransport::once(ProtoResponse::new(400, body.into_bytes()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket,
            free_trial: false,
        },
    ))
    .unwrap_err();

    let ProtoError::InvalidResponse { excerpt, .. } = &err else {
        panic!("expected InvalidResponse, got {err:?}");
    };
    assert_no_partial_leak(excerpt, &text);
}

#[test]
fn a_top_page_without_stored_does_not_leak_a_twice_reflected_ticket() {
    // The window-straddle bug's shape, driven through `scrape_stored`'s `StoredNotFound` arm with two
    // reflections rather than the one reflection the existing bare-ticket coverage uses. The prefix and
    // filler are short on purpose: a long prefix (this page's real markup) pushes the straddled leak
    // toward the tail of the window, and the final `EXCERPT_MAX_CHARS` cut then trims most or all of it
    // away before this test ever sees it, so a test built against the real markup shape would pass
    // whether or not the guard it means to check is even present. Confirmed by temporarily disabling
    // the guard: the real-markup shape stayed green while this tight one went red.
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let text = ticket.text().to_owned();
    let filler = " ".repeat(20);
    // The hidden linked-id input has to be present and short: `begin_login` reads the Steam-linked id
    // before `_STORED_`, so a page missing it fails at that earlier `OauthTop` check instead of ever
    // reaching `scrape_stored`.
    let body =
        format!(r#"<input name="sqexid" type="hidden" value="id"/>ticket {text}{filler}{text}"#);
    let transport = FixtureTransport::once(ProtoResponse::new(200, body.into_bytes()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket,
            free_trial: false,
        },
    ))
    .unwrap_err();

    let ProtoError::StoredNotFound { excerpt } = &err else {
        panic!("expected StoredNotFound, got {err:?}");
    };
    assert_no_partial_leak(excerpt, &text);
}

#[test]
fn a_real_markup_top_page_without_stored_does_not_leak_a_twice_reflected_ticket() {
    // The real top-page markup shape (an anchor and a neighbouring input) reflecting the ticket twice.
    // Kept alongside the tight version above because it is the shape an actual SE response would carry,
    // even though its long prefix means it alone would not catch a disabled guard (see that test's
    // comment).
    let id = computer_id();
    let ticket = long_ticket().unwrap();
    let text = ticket.text().to_owned();
    let filler = " ".repeat(150);
    let body = format!(
        "<html>debug: rejected ticket {text}{filler}{text}\n\
         <input name=\"sqexid\" type=\"hidden\" value=\"{LINKED_ID}\"/></html>"
    );
    let transport = FixtureTransport::once(ProtoResponse::new(200, body.into_bytes()));

    let err = block_on(begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Steam {
            ticket,
            free_trial: false,
        },
    ))
    .unwrap_err();

    let ProtoError::StoredNotFound { excerpt } = &err else {
        panic!("expected StoredNotFound, got {err:?}");
    };
    assert_no_partial_leak(excerpt, &text);
}
