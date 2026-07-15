//! Frontier integration tests: the gate/login requests are asserted byte-for-byte through the fixture
//! transport, the body is parsed, and a strict-parse canary over the committed fixture guards against
//! silent schema drift.

use apogee_test_support::rt::block_on;
use apogee_test_support::transport::{FixtureTransport, canonical_request};
use sqex_proto::{
    ComputerId, FrontierContext, LauncherTime, ProtoError, ProtoResponse, Step, check_gate_status,
    check_login_status,
};

fn fixed_time() -> LauncherTime {
    LauncherTime::from_parts(2024, 1, 2, 3, 47, 1_704_164_820_000)
}

fn computer_id() -> ComputerId {
    ComputerId::from_facts("APOGEE-TEST", "apogee", "TESTOS-1.0", 8)
}

fn context<'a>(id: &'a ComputerId) -> FrontierContext<'a> {
    FrontierContext {
        computer_id: id,
        language: "en-us",
        accept_language: "en-US,en;q=0.9",
        referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
    }
}

#[test]
fn gate_status_builds_the_fingerprinted_request() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(
        200,
        br#"{"status": true, "message": [], "news": []}"#.to_vec(),
    ));
    block_on(check_gate_status(&transport, &context(&id), &fixed_time())).unwrap();

    let recorded = transport.recorded();
    assert_eq!(
        canonical_request(&recorded[0]),
        "GET https://frontier.ffxiv.com/worldStatus/gate_status.json?lang=en-us&_=1704164820000\n\
         user-agent: SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)\n\
         accept-encoding: gzip, deflate\n\
         accept-language: en-US,en;q=0.9\n\
         origin: https://launcher.finalfantasyxiv.com\n\
         referer: https://launcher.finalfantasyxiv.com/v700/?rc_lang=en_us&time=2024-01-02-03-47\n\
         connection: Keep-Alive\n"
    );
}

#[test]
fn login_status_omits_the_lang_query() {
    let id = computer_id();
    let transport =
        FixtureTransport::once(ProtoResponse::new(200, br#"{"status": true}"#.to_vec()));
    block_on(check_login_status(&transport, &context(&id), &fixed_time())).unwrap();

    let recorded = transport.recorded();
    assert_eq!(
        recorded[0].url.as_str(),
        "https://frontier.ffxiv.com/worldStatus/login_status.json?_=1704164820000"
    );
}

#[test]
fn gate_status_parses_a_closed_gate() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(
        200,
        br#"{"status": false, "message": ["Scheduled maintenance"], "news": []}"#.to_vec(),
    ));
    let status = block_on(check_gate_status(&transport, &context(&id), &fixed_time())).unwrap();
    assert!(!status.status);
    assert_eq!(status.message, ["Scheduled maintenance"]);
}

#[test]
fn a_non_200_status_is_an_invalid_response() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(500, b"oops".to_vec()));
    let err = block_on(check_gate_status(&transport, &context(&id), &fixed_time())).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::GateStatus,
            status: 500,
            ..
        }
    ));
}

/// Mirrors the shape of `GateStatus` but rejects unknown fields; parsing the committed fixture with it
/// is the canary that a real capture gaining a field surfaces as a test failure, prompting a model
/// update.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictGateStatus {
    #[allow(dead_code)]
    status: bool,
    #[allow(dead_code)]
    message: Vec<String>,
    #[allow(dead_code)]
    news: Vec<String>,
}

#[test]
fn committed_fixture_matches_the_known_schema() {
    let fixture = include_str!("fixtures/gate_status.json");
    let parsed: Result<StrictGateStatus, _> = serde_json::from_str(fixture);
    assert!(parsed.is_ok());
}

#[test]
fn strict_parse_flags_an_added_field() {
    let drifted = r#"{"status": true, "message": [], "news": [], "new_field": 1}"#;
    assert!(serde_json::from_str::<StrictGateStatus>(drifted).is_err());
}
