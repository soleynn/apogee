use apogee_test_support::rt::block_on;
use apogee_test_support::transport::{FixtureTransport, canonical_request};
use sqex_proto::{
    ClientContext, ComputerId, FrontierContext, LauncherTime, ProtoError, ProtoResponse, Step,
    check_gate_status, check_login_status, fetch_banners, fetch_news, fetch_notices,
    fetch_world_status,
};

fn fixed_time() -> LauncherTime {
    LauncherTime::from_parts(2024, 1, 2, 3, 47, 1_704_164_820_000)
}

fn computer_id() -> ComputerId {
    ComputerId::from_facts("APOGEE-TEST", "apogee", "TESTOS-1.0", 8)
}

fn context<'a>(id: &'a ComputerId) -> FrontierContext<'a> {
    FrontierContext {
        client: ClientContext {
            computer_id: id,
            language: "en-us",
            accept_language: "en-US,en;q=0.9",
            referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
        },
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
         accept: */*\n\
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
fn gate_status_degrades_a_wobbly_payload_end_to_end() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(
        200,
        br#"{"status": 1.0, "message": null, "news": ["patch 7.1", 7]}"#.to_vec(),
    ));
    let status = block_on(check_gate_status(&transport, &context(&id), &fixed_time())).unwrap();
    assert!(status.status);
    assert!(status.message.is_empty());
    assert_eq!(status.news, ["patch 7.1", "7"]);
}

#[test]
fn gate_status_reports_an_unreadable_flag_rather_than_guessing() {
    let id = computer_id();
    let transport = FixtureTransport::once(ProtoResponse::new(
        200,
        br#"{"status": "maintenance"}"#.to_vec(),
    ));
    let err = block_on(check_gate_status(&transport, &context(&id), &fixed_time())).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::GateStatus,
            status: 200,
            ..
        }
    ));
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

fn captured_body(fixture: &str) -> Result<Vec<u8>, serde_json::Error> {
    let capture: serde_json::Value = serde_json::from_str(fixture)?;
    serde_json::to_vec(&capture["body"])
}

#[test]
fn display_endpoints_build_the_captured_urls_and_parse_their_rows() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(
            200,
            captured_body(include_str!("fixtures/frontier/news_headline_en_us.json")).unwrap(),
        ),
        ProtoResponse::new(
            200,
            captured_body(include_str!("fixtures/frontier/topics_banner_en_us.json")).unwrap(),
        ),
        ProtoResponse::new(
            200,
            captured_body(include_str!("fixtures/frontier/notice_message_en_us.json")).unwrap(),
        ),
        ProtoResponse::new(
            200,
            captured_body(include_str!("fixtures/frontier/world_status.json")).unwrap(),
        ),
    ]);
    let context = context(&id);

    let news = block_on(fetch_news(&transport, &context, &fixed_time())).unwrap();
    let banners = block_on(fetch_banners(&transport, &context, &fixed_time())).unwrap();
    let notices = block_on(fetch_notices(&transport, &context, &fixed_time())).unwrap();
    let worlds = block_on(fetch_world_status(&transport, &context, &fixed_time())).unwrap();

    assert_eq!(news.news.len(), 5);
    assert_eq!(news.topics.len(), 5);
    assert_eq!(news.pinned.len(), 4);
    assert_eq!(banners.banner.len(), 5);
    assert!(notices.contents.is_empty());
    assert_eq!(worlds.data.len(), 4);
    assert_eq!(worlds.data[0].dc[0].world[0].name, "Louisoix");

    let urls: Vec<_> = transport
        .recorded()
        .iter()
        .map(|request| request.url.as_str().to_owned())
        .collect();
    assert_eq!(
        urls,
        [
            "https://frontier.ffxiv.com/news/headline.json?lang=en-us&media=pcapp&_=1704164820000",
            "https://frontier.ffxiv.com/v2/topics/en-us/banner.json?lang=en-us&media=pcapp&_=1704164820000",
            "https://frontier.ffxiv.com/v2/notice/en-us/message.json?_=1704164820000",
            "https://frontier.ffxiv.com/v2/world/status.json?_=1704164820000",
        ]
    );
}

#[test]
fn display_parsers_default_missing_fields_and_ignore_additions() {
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, br#"{"news":[{"title":"one","future":7}]}"#.to_vec()),
        ProtoResponse::new(200, br#"{"future":true}"#.to_vec()),
    ]);
    let context = context(&id);

    let news = block_on(fetch_news(&transport, &context, &fixed_time())).unwrap();
    let banners = block_on(fetch_banners(&transport, &context, &fixed_time())).unwrap();

    assert_eq!(news.news[0].title, "one");
    assert!(news.news[0].id.is_empty());
    assert!(news.topics.is_empty());
    assert!(banners.banner.is_empty());
}

#[test]
fn oversized_display_payload_is_refused_before_json_parsing() {
    let id = computer_id();
    let transport =
        FixtureTransport::once(ProtoResponse::new(200, vec![b' '; 4 * 1024 * 1024 + 1]));

    let err = block_on(fetch_news(&transport, &context(&id), &fixed_time())).unwrap_err();

    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::News,
            status: 200,
            ..
        }
    ));
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictCapture<T> {
    #[allow(dead_code)]
    note: String,
    #[allow(dead_code)]
    endpoint: String,
    #[allow(dead_code)]
    request: StrictRequest,
    #[allow(dead_code)]
    response: StrictResponse,
    body: T,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRequest {
    #[allow(dead_code)]
    method: String,
    #[allow(dead_code)]
    url: String,
    #[allow(dead_code)]
    query: serde_json::Map<String, serde_json::Value>,
    #[allow(dead_code)]
    headers: StrictRequestHeaders,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRequestHeaders {
    #[serde(rename = "user-agent")]
    #[allow(dead_code)]
    user_agent: String,
    #[allow(dead_code)]
    accept: String,
    #[serde(rename = "accept-encoding")]
    #[allow(dead_code)]
    accept_encoding: String,
    #[serde(rename = "accept-language")]
    #[allow(dead_code)]
    accept_language: String,
    #[allow(dead_code)]
    origin: String,
    #[allow(dead_code)]
    referer: String,
    #[allow(dead_code)]
    connection: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictResponse {
    #[allow(dead_code)]
    captured: String,
    #[allow(dead_code)]
    status: u16,
    #[allow(dead_code)]
    headers: serde_json::Map<String, serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHeadlines {
    news: Vec<StrictHeadline>,
    topics: Vec<StrictHeadline>,
    pinned: Vec<StrictHeadline>,
    banner: Vec<StrictHeadline>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHeadline {
    #[allow(dead_code)]
    date: String,
    #[allow(dead_code)]
    title: String,
    #[allow(dead_code)]
    url: String,
    #[allow(dead_code)]
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    tag: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBanners {
    banner: Vec<StrictBanner>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBanner {
    #[allow(dead_code)]
    lsb_banner: String,
    #[allow(dead_code)]
    link: String,
    #[allow(dead_code)]
    order_priority: String,
    #[allow(dead_code)]
    fix_order: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictNotices {
    contents: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictWorldStatus {
    data: Vec<StrictWorldRegion>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictWorldRegion {
    #[allow(dead_code)]
    name: String,
    dc: Vec<StrictDataCenter>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictDataCenter {
    #[allow(dead_code)]
    name: String,
    world: Vec<StrictWorld>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictWorld {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    status: i64,
    #[allow(dead_code)]
    category: i64,
    #[allow(dead_code)]
    create: bool,
}

#[test]
fn display_captures_match_the_strict_recorded_schemas() {
    let en: StrictCapture<StrictHeadlines> =
        serde_json::from_str(include_str!("fixtures/frontier/news_headline_en_us.json")).unwrap();
    let ja: StrictCapture<StrictHeadlines> =
        serde_json::from_str(include_str!("fixtures/frontier/news_headline_ja.json")).unwrap();
    let banners: StrictCapture<StrictBanners> =
        serde_json::from_str(include_str!("fixtures/frontier/topics_banner_en_us.json")).unwrap();
    let banners_ja: StrictCapture<StrictBanners> =
        serde_json::from_str(include_str!("fixtures/frontier/topics_banner_ja.json")).unwrap();
    let notices: StrictCapture<StrictNotices> =
        serde_json::from_str(include_str!("fixtures/frontier/notice_message_en_us.json")).unwrap();
    let notices_ja: StrictCapture<StrictNotices> =
        serde_json::from_str(include_str!("fixtures/frontier/notice_message_ja.json")).unwrap();
    let worlds: StrictCapture<StrictWorldStatus> =
        serde_json::from_str(include_str!("fixtures/frontier/world_status.json")).unwrap();

    assert_eq!(en.body.news.len(), 5);
    assert_eq!(ja.body.topics.len(), 5);
    assert_eq!(en.body.pinned.len(), 4);
    assert!(en.body.banner.is_empty());
    assert_eq!(banners.body.banner.len(), 5);
    assert_eq!(banners_ja.body.banner.len(), 5);
    assert!(notices.body.contents.is_empty());
    assert!(notices_ja.body.contents.is_empty());
    assert_eq!(worlds.body.data[0].dc[0].world.len(), 8);
}
