
use apogee_test_support::rt::block_on;
use apogee_test_support::transport::{FixtureTransport, canonical_request};
use http::{HeaderName, HeaderValue};
use sqex_proto::{
    ClientContext, ComputerId, Credentials, LauncherTime, LoginKind, OauthContext, ProtoError,
    ProtoResponse, Registration, Step, TransportError, VersionReport, begin_login, gen_token,
    register_session,
};

const UID: &str = "UID-TOKEN-0123456789";
const PATCH_URL: &str = "http://patch-dl.example.invalid/game/4e9a232b/D2024.03.28.0000.0001.patch";

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

async fn register() -> Result<Registration, ProtoError> {
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, top_page("STOREDBLOB").into_bytes()),
        ProtoResponse::new(200, success_body("SESSIONXYZ").into_bytes()),
        ProtoResponse::new(200, Vec::new()).with_header(
            HeaderName::from_static("x-patch-unique-id"),
            HeaderValue::from_static(UID),
        ),
    ]);

    let flow = begin_login(
        &transport,
        &context(&id),
        &fixed_time(),
        LoginKind::Standard { free_trial: false },
    )
    .await?;
    let auth = flow
        .submit(Credentials {
            sqexid: "user",
            password: "pw",
            otp: None,
        })
        .await?;
    let report = VersionReport::from_parts(
        "2024.03.28.0000.0000".to_owned(),
        "2024.02.01.0000.0000",
        std::array::from_fn(|i| (i as u64, format!("{i:040x}"))),
        &[],
    );
    register_session(&transport, &auth, &report).await
}

#[test]
fn builds_the_fingerprinted_request() {
    let unique_id = match block_on(register()).expect("registration") {
        Registration::Registered { unique_id, .. } => unique_id,
        other => panic!("expected Registered, got {other:?}"),
    };
    let transport = FixtureTransport::once(ProtoResponse::new(200, b"TOKENIZED_URL".to_vec()));

    let token = block_on(gen_token(&transport, &unique_id, PATCH_URL)).expect("gen_token");
    assert_eq!(token, "TOKENIZED_URL");

    let recorded = transport.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        canonical_request(&recorded[0]),
        format!(
            "POST http://patch-gamever.ffxiv.com/gen_token\n\
             user-agent: FFXIV PATCH CLIENT\n\
             x-patch-unique-id: {UID}\n\
             \n\
             {PATCH_URL}"
        )
    );
}

#[test]
fn a_non_200_status_is_an_invalid_response() {
    let unique_id = match block_on(register()).expect("registration") {
        Registration::Registered { unique_id, .. } => unique_id,
        other => panic!("expected Registered, got {other:?}"),
    };
    let transport = FixtureTransport::once(ProtoResponse::new(503, b"maintenance".to_vec()));

    let err = block_on(gen_token(&transport, &unique_id, PATCH_URL)).expect_err("503");
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::GenToken,
            status: 503,
            ..
        }
    ));
}

#[test]
fn a_reflected_unique_id_does_not_leak_into_the_excerpt() {
    // A hypothetical error page echoing the request headers back would reflect the UID; the excerpt
    // scrub covers it the same way register_session's does for the session id in its URL.
    let unique_id = match block_on(register()).expect("registration") {
        Registration::Registered { unique_id, .. } => unique_id,
        other => panic!("expected Registered, got {other:?}"),
    };
    let body = format!("<html>rejected header x-patch-unique-id: {UID}</html>");
    let transport = FixtureTransport::once(ProtoResponse::new(400, body.into_bytes()));

    let err = block_on(gen_token(&transport, &unique_id, PATCH_URL)).expect_err("400");
    let ProtoError::InvalidResponse { excerpt, .. } = &err else {
        panic!("expected InvalidResponse, got {err:?}");
    };
    assert!(!excerpt.contains(UID), "uid leaked: {excerpt}");
    assert!(excerpt.contains("[redacted]"), "excerpt: {excerpt}");
}

#[test]
fn a_transport_failure_propagates() {
    let unique_id = match block_on(register()).expect("registration") {
        Registration::Registered { unique_id, .. } => unique_id,
        other => panic!("expected Registered, got {other:?}"),
    };
    let transport = FixtureTransport::failing(TransportError::new("connection refused"));

    let err =
        block_on(gen_token(&transport, &unique_id, PATCH_URL)).expect_err("transport failure");
    assert!(matches!(err, ProtoError::Transport(_)));
}
