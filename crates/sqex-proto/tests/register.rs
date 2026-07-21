//! Session-registration integration tests, driven through the fixture transport.
//!
//! Each disposition test drives a full login (so it can obtain an [`Authenticated`], whose fields are
//! private and only produced by the flow) and then registers, scripting the registration response. The
//! POST is asserted byte-for-byte (the drift alarm). The version-report bytes are golden-matched
//! against the reference launcher for a synthetic install, and the sanity gate is proven to reject a
//! corrupt install before any registration request.

use apogee_test_support::golden::assert_golden_bytes;
use apogee_test_support::rt::block_on;
use apogee_test_support::sandbox::build_game_install;
use apogee_test_support::transport::{FixtureTransport, canonical_request};
use http::{HeaderName, HeaderValue};
use sqex_proto::{
    Authenticated, BASE_GAME_VERSION, ClientContext, ComputerId, Credentials, InstallPaths,
    LauncherTime, LoginKind, OauthContext, ProtoError, ProtoResponse, Registration, SanityKind,
    Step, VersionRepo, VersionReport, begin_login, register_session,
};

const BOOT_VER: &str = "2024.02.01.0000.0000";
const GAME_VER: &str = "2024.03.28.0000.0000";
const EX1: &str = "2024.03.28.0001.0000";
const SESSION_ID: &str = "SESSIONXYZ";
const UID: &str = "UID-TOKEN-0123456789";

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

/// The four boot EXE contents used by the goldens. `ffxivupdater64.exe` is empty to pin that EXEs are
/// hashed, not sanity-checked (`sha1("") = da39a3ee…`).
fn exes() -> [&'static [u8]; 4] {
    [b"boot" as &[u8], b"boot64", b"launcher64", b""]
}

/// Remove the game tree (its `.ver` and the whole `sqpack` subtree) from an install, leaving the boot
/// component present. This is the state install-from-nothing reaches once the boot component is brought
/// up but before the game is. `?`-based (no unwrap) so it satisfies the integration-test helper lint.
fn strip_game_tree(root: &std::path::Path) -> std::io::Result<()> {
    std::fs::remove_file(root.join("game/ffxivgame.ver"))?;
    std::fs::remove_dir_all(root.join("game/sqpack"))?;
    Ok(())
}

/// A version report built purely (no filesystem), used for the request golden and the disposition
/// tests. `game_version` becomes the URL segment; the body is asserted against the drift golden.
fn request_report() -> VersionReport {
    VersionReport::from_parts(
        GAME_VER.to_owned(),
        BOOT_VER,
        std::array::from_fn(|i| (i as u64, format!("{i:040x}"))),
        &[],
    )
}

/// A registration response with `status`, carrying the UID header and `body`.
fn uid_response_status(status: u16, body: Vec<u8>) -> ProtoResponse {
    ProtoResponse::new(status, body).with_header(
        HeaderName::from_static("x-patch-unique-id"),
        HeaderValue::from_static(UID),
    )
}

/// A `200` registration response carrying the UID header and `body`.
fn uid_response(body: Vec<u8>) -> ProtoResponse {
    uid_response_status(200, body)
}

/// Wrap synthetic nine-field game entries in the multipart envelope the parser expects.
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

/// A nine-field game patchlist entry with two per-block SHA1s.
fn game_entry() -> String {
    let h1 = "a".repeat(40);
    let h2 = "b".repeat(40);
    format!(
        "52430000\t0\t0\t0\tD2024.03.28.0000.0001\tsha1\t52428800\t{h1},{h2}\t\
         http://patch-dl.example.invalid/game/4e9a232b/D2024.03.28.0000.0001.patch"
    )
}

/// Drive the OAuth flow (top page + submit) to an [`Authenticated`], through a transport already
/// scripted with the top and login responses. Uses `?` (no unwrap) so it satisfies the integration-test
/// helper lint; a scripting mistake surfaces as the returned error, not a panic.
async fn login(transport: &FixtureTransport, id: &ComputerId) -> Result<Authenticated, ProtoError> {
    let flow = begin_login(
        transport,
        &context(id),
        &fixed_time(),
        LoginKind::Standard { free_trial: false },
    )
    .await?;
    flow.submit(Credentials {
        sqexid: "user",
        password: "pw",
        otp: None,
    })
    .await
}

/// Drive login then registration through one transport scripted with `[top, login, register]`,
/// returning the transport (for request inspection) and the registration outcome.
fn login_then_register(
    register: ProtoResponse,
) -> (FixtureTransport, Result<Registration, ProtoError>) {
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, top_page("STOREDBLOB").into_bytes()),
        ProtoResponse::new(200, success_body(SESSION_ID).into_bytes()),
        register,
    ]);

    let outcome = block_on(async {
        let auth = login(&transport, &id).await?;
        register_session(&transport, &auth, &request_report()).await
    });

    (transport, outcome)
}

#[test]
fn register_posts_the_fingerprinted_request() {
    let (transport, outcome) = login_then_register(uid_response(Vec::new()));
    outcome.expect("registration");

    let recorded = transport.recorded();
    assert_eq!(recorded.len(), 3);
    let expected = format!(
        "POST https://patch-gamever.ffxiv.com/http/win32/ffxivneo_release_game/{GAME_VER}/{SESSION_ID}\n\
         connection: Keep-Alive\n\
         user-agent: FFXIV PATCH CLIENT\n\
         x-hash-check: enabled\n\
         \n\
         {}",
        request_report().body()
    );
    assert_eq!(canonical_request(&recorded[2]), expected);
}

#[test]
fn uid_with_empty_body_is_registered_with_no_patches() {
    let (_transport, outcome) = login_then_register(uid_response(Vec::new()));
    match outcome.expect("registration") {
        Registration::Registered {
            unique_id,
            pending_patches,
        } => {
            assert_eq!(unique_id.expose(), UID);
            assert!(pending_patches.is_empty());
        }
        other => panic!("expected Registered, got {other:?}"),
    }
}

#[test]
fn a_204_no_content_is_registered_with_no_patches() {
    // The live service answers a current game with 204 No Content and the UID header (observed against
    // the real endpoint), not 200. Since registration keys on the UID header rather than a status, 204
    // registers with no pending patches; this pins that a status gate is never reintroduced.
    let (_transport, outcome) = login_then_register(uid_response_status(204, Vec::new()));
    match outcome.expect("registration") {
        Registration::Registered {
            pending_patches, ..
        } => assert!(pending_patches.is_empty()),
        other => panic!("expected Registered, got {other:?}"),
    }
}

/// The response mirrors the sanitized capture in `fixtures/register_current.txt`: 204 No Content with
/// the real observed header set (unique id redacted) and an empty body.
fn real_current_capture() -> ProtoResponse {
    ProtoResponse::new(204, Vec::new())
        .with_header(
            HeaderName::from_static("x-patch-module"),
            HeaderValue::from_static("ZiPatch"),
        )
        .with_header(
            HeaderName::from_static("x-protocol"),
            HeaderValue::from_static("http"),
        )
        .with_header(
            HeaderName::from_static("x-latest-version"),
            HeaderValue::from_static("2026.06.18.0000.0000"),
        )
        .with_header(
            HeaderName::from_static("x-patch-unique-id"),
            HeaderValue::from_static(UID),
        )
}

#[test]
fn a_real_current_registration_capture_is_registered_with_no_patches() {
    // Grounded on a live 204 capture (fixtures/register_current.txt): the full observed header set,
    // not just the unique id in isolation, must still register cleanly with no pending patches.
    let (_transport, outcome) = login_then_register(real_current_capture());
    match outcome.expect("registration") {
        Registration::Registered {
            unique_id,
            pending_patches,
        } => {
            assert_eq!(unique_id.expose(), UID);
            assert!(pending_patches.is_empty());
        }
        other => panic!("expected Registered, got {other:?}"),
    }
}

#[test]
fn uid_with_patchlist_is_registered_with_pending_patches() {
    let (_transport, outcome) = login_then_register(uid_response(game_patchlist(&[&game_entry()])));
    match outcome.expect("registration") {
        Registration::Registered {
            pending_patches, ..
        } => {
            assert_eq!(pending_patches.len(), 1);
            assert_eq!(pending_patches[0].length, 52_430_000);
            assert!(pending_patches[0].hashes.is_some());
        }
        other => panic!("expected Registered, got {other:?}"),
    }
}

#[test]
fn conflict_status_is_needs_boot_patch() {
    // 409 short-circuits before the UID check: even a response that also carries a UID header and a body
    // is NeedsBootPatch, not Registered. This pins that the status match precedes the UID read.
    let response = ProtoResponse::new(409, b"boot patch pending".to_vec()).with_header(
        HeaderName::from_static("x-patch-unique-id"),
        HeaderValue::from_static(UID),
    );
    let (_transport, outcome) = login_then_register(response);
    assert!(matches!(
        outcome.expect("disposition"),
        Registration::NeedsBootPatch
    ));
}

#[test]
fn gone_status_is_version_not_serviced() {
    let (_transport, outcome) = login_then_register(ProtoResponse::new(410, Vec::new()));
    assert!(matches!(
        outcome.expect("disposition"),
        Registration::VersionNotServiced
    ));
}

#[test]
fn no_uid_header_is_invalid_response() {
    // A 200 without the UID header is not success: SE's contract is the header, not the status.
    let (_transport, outcome) =
        login_then_register(ProtoResponse::new(200, b"unexpected".to_vec()));
    let err = outcome.expect_err("missing uid");
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::Register,
            status: 200,
            ..
        }
    ));
}

#[test]
fn a_whitespace_body_with_uid_is_not_treated_as_current() {
    // Exact-empty, not trimmed: a whitespace body with a UID goes to the patchlist parser and fails
    // loudly rather than being read as "game is current".
    let (_transport, outcome) = login_then_register(uid_response(b"  \r\n".to_vec()));
    let err = outcome.expect_err("whitespace body");
    assert!(matches!(err, ProtoError::PatchListParse { .. }));
}

#[test]
fn non_ascii_uid_header_is_invalid_response() {
    // A UID header present but not visible ASCII is treated as absent (its `to_str` fails), so the
    // response is an invalid one, never a lossily-decoded credential.
    let response = ProtoResponse::new(200, Vec::new()).with_header(
        HeaderName::from_static("x-patch-unique-id"),
        HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
    );
    let (_transport, outcome) = login_then_register(response);
    let err = outcome.expect_err("garbage uid");
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::Register,
            status: 200,
            ..
        }
    ));
}

#[test]
fn a_transport_failure_propagates() {
    // Script only the two login responses; the registration call finds the transport exhausted, which
    // surfaces as a transport error.
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, top_page("STOREDBLOB").into_bytes()),
        ProtoResponse::new(200, success_body(SESSION_ID).into_bytes()),
    ]);

    let err = block_on(async {
        let auth = login(&transport, &id).await?;
        register_session(&transport, &auth, &request_report()).await
    })
    .expect_err("exhausted transport");

    assert!(matches!(err, ProtoError::Transport(_)));
}

#[test]
fn version_report_bytes_match_xl_for_a_synthetic_install() {
    // Byte-identity against the reference launcher's GetVersionReport (Launcher.cs:266-368): the boot
    // line carries each EXE's length and lowercase SHA1, then a tab-separated line per expansion, with a
    // trailing LF. ffxivupdater64.exe is empty, pinning that EXEs are hashed, not sanity-checked.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1, "2023.09.19.0000.0000"])
        .expect("install");
    let report = VersionReport::from_install(&InstallPaths::new(dir.path()), 2).expect("report");

    assert_eq!(report.game_version(), GAME_VER);
    assert_golden_bytes(
        report.body().as_bytes(),
        concat!(
            "2024.02.01.0000.0000=",
            "ffxivboot.exe/4/5c73b0c6f476ded38de389f894770f06f4d02b2f,",
            "ffxivboot64.exe/6/40154fb132681be4f678662604e05aac4a090bf2,",
            "ffxivlauncher64.exe/10/c2259ffc29178a21729049759f7a790d542f9d40,",
            "ffxivupdater64.exe/0/da39a3ee5e6b4b0d3255bfef95601890afd80709\n",
            "ex1\t2024.03.28.0001.0000\n",
            "ex2\t2023.09.19.0000.0000\n",
        )
        .as_bytes(),
    );
}

#[test]
fn version_report_with_no_expansions_is_boot_line_only() {
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[]).expect("install");
    let report = VersionReport::from_install(&InstallPaths::new(dir.path()), 0).expect("report");
    assert_eq!(report.body().matches('\n').count(), 1);
    assert!(report.body().ends_with('\n'));
    assert!(!report.body().contains("ex1"));
}

#[test]
fn version_report_clamps_expansions_at_five() {
    // Six expansions installed but the report carries at most five.
    let dir = build_game_install(
        BOOT_VER,
        exes(),
        GAME_VER,
        &["e1", "e2", "e3", "e4", "e5", "e6"],
    )
    .expect("install");
    let report = VersionReport::from_install(&InstallPaths::new(dir.path()), 6).expect("report");
    let ex_lines = report
        .body()
        .lines()
        .filter(|l| l.starts_with("ex"))
        .count();
    assert_eq!(ex_lines, 5);
    assert!(report.body().contains("ex5\te5\n"));
    assert!(!report.body().contains("ex6"));
}

#[test]
fn a_missing_required_ver_is_rejected() {
    // Entitled to two expansions but ex2 is not installed: rejected, never silently base-versioned.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    let err =
        VersionReport::from_install(&InstallPaths::new(dir.path()), 2).expect_err("missing ex2");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Ex(2),
            kind: SanityKind::Missing,
        }
    ));
}

#[test]
fn a_ver_newline_is_invalid_version_files() {
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(
        dir.path().join("game/ffxivgame.ver"),
        "2024.03.28.0000.0000\n",
    )
    .expect("corrupt game ver");
    let err = VersionReport::from_install(&InstallPaths::new(dir.path()), 1).expect_err("newline");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Game,
            kind: SanityKind::ContainsNewline,
        }
    ));
}

#[test]
fn an_empty_ver_is_invalid_version_files() {
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(dir.path().join("game/sqpack/ex1/ex1.ver"), "").expect("empty ex1 ver");
    let err = VersionReport::from_install(&InstallPaths::new(dir.path()), 1).expect_err("empty");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Ex(1),
            kind: SanityKind::Empty,
        }
    ));
}

#[test]
fn an_all_nul_ver_is_invalid_version_files() {
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(dir.path().join("boot/ffxivboot.ver"), [0u8, 0, 0, 0]).expect("nul boot ver");
    let err = VersionReport::from_install(&InstallPaths::new(dir.path()), 1).expect_err("all nul");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Boot,
            kind: SanityKind::AllNul,
        }
    ));
}

#[test]
fn an_absent_bck_is_ignored() {
    // The default install carries no `.bck` files; the report builds cleanly.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    assert!(VersionReport::from_install(&InstallPaths::new(dir.path()), 1).is_ok());
}

#[test]
fn a_corrupt_bck_is_invalid_version_files() {
    // A present but corrupt boot backup is caught even though the report never reads its contents.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(dir.path().join("boot/ffxivboot.bck"), [0u8, 0]).expect("nul bck");
    let err =
        VersionReport::from_install(&InstallPaths::new(dir.path()), 1).expect_err("corrupt bck");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Boot,
            kind: SanityKind::AllNul,
        }
    ));
}

#[test]
fn a_corrupt_expansion_bck_is_invalid_version_files() {
    // The `.bck` gate covers expansions too, exercising the ex{n}.bck path construction.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(dir.path().join("game/sqpack/ex1/ex1.bck"), [0u8, 0]).expect("nul ex bck");
    let err =
        VersionReport::from_install(&InstallPaths::new(dir.path()), 1).expect_err("corrupt ex bck");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Ex(1),
            kind: SanityKind::AllNul,
        }
    ));
}

#[test]
fn an_unreadable_ver_is_invalid_version_files() {
    // A directory where a `.ver` file belongs makes the read fail with a non-not-found error, which is
    // the Unreadable kind. A directory (not a mode-000 file) keeps the test reliable when CI is root.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    let ver = dir.path().join("game/ffxivgame.ver");
    std::fs::remove_file(&ver).expect("remove game ver");
    std::fs::create_dir(&ver).expect("dir in place of game ver");
    let err =
        VersionReport::from_install(&InstallPaths::new(dir.path()), 1).expect_err("unreadable");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Game,
            kind: SanityKind::Unreadable,
        }
    ));
}

#[test]
fn a_sanity_violation_stops_before_registration() {
    // A corrupt install fails report construction, so the login's two requests are the only traffic;
    // register_session is never reached.
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, top_page("STOREDBLOB").into_bytes()),
        ProtoResponse::new(200, success_body(SESSION_ID).into_bytes()),
    ]);
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(
        dir.path().join("game/ffxivgame.ver"),
        "2024.03.28.0000.0000\n",
    )
    .expect("corrupt game ver");
    let paths = InstallPaths::new(dir.path());

    let err = block_on(async {
        let auth = login(&transport, &id).await?;
        // Report construction fails here; the registration call below is never reached.
        let report = VersionReport::from_install(&paths, auth.max_expansion)?;
        register_session(&transport, &auth, &report).await
    })
    .expect_err("corrupt install");

    assert!(matches!(err, ProtoError::InvalidVersionFiles { .. }));
    assert_eq!(transport.recorded().len(), 2);
}

#[test]
fn install_mode_reports_base_for_absent_game_and_expansions() {
    // Install-from-nothing after the boot component is up: the game and expansion `.ver` files are
    // absent, so the report carries BASE_GAME_VERSION for the game version (the URL segment) and every
    // expansion line, while the boot line still names the installed boot version and the four EXEs. The
    // bytes are byte-identical to what the reference launcher's non-forced register sends for this
    // state, its per-repo Repository.GetVer base-fallback (Repository.cs:67-76).
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    strip_game_tree(dir.path()).expect("strip game tree");
    let report =
        VersionReport::from_install_or_base(&InstallPaths::new(dir.path()), 2).expect("report");

    assert_eq!(report.game_version(), BASE_GAME_VERSION);
    assert_golden_bytes(
        report.body().as_bytes(),
        concat!(
            "2024.02.01.0000.0000=",
            "ffxivboot.exe/4/5c73b0c6f476ded38de389f894770f06f4d02b2f,",
            "ffxivboot64.exe/6/40154fb132681be4f678662604e05aac4a090bf2,",
            "ffxivlauncher64.exe/10/c2259ffc29178a21729049759f7a790d542f9d40,",
            "ffxivupdater64.exe/0/da39a3ee5e6b4b0d3255bfef95601890afd80709\n",
            "ex1\t2012.01.01.0000.0000\n",
            "ex2\t2012.01.01.0000.0000\n",
        )
        .as_bytes(),
    );
}

#[test]
fn install_mode_reads_a_present_version_verbatim() {
    // Base-fallback is per-repository, not a blanket base report: a repository whose `.ver` is present
    // is reported as-is. On a complete install, install-mode and the strict path produce the same game
    // and expansion versions; they differ only in how they treat an absent or corrupt file.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    let report =
        VersionReport::from_install_or_base(&InstallPaths::new(dir.path()), 1).expect("report");

    assert_eq!(report.game_version(), GAME_VER);
    assert!(report.body().contains(&format!("ex1\t{EX1}\n")));
    assert!(!report.body().contains(BASE_GAME_VERSION));
}

#[test]
fn install_mode_still_requires_the_boot_exes() {
    // The boot line is never base-filled: the four boot EXEs must be present to be hashed, matching the
    // reference launcher (which throws on a missing boot EXE even when forcing the base version).
    // Install-from-nothing brings up the boot component first, so this holds by the time the game is
    // reported at the sentinel.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    strip_game_tree(dir.path()).expect("strip game tree");
    std::fs::remove_file(dir.path().join("boot/ffxivboot64.exe")).expect("remove a boot exe");
    let err = VersionReport::from_install_or_base(&InstallPaths::new(dir.path()), 1)
        .expect_err("missing boot exe");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Boot,
            kind: SanityKind::Missing,
        }
    ));
}

#[test]
fn install_mode_accepts_what_the_strict_path_rejects() {
    // The one behavioral divergence, pinned as opt-in: an absent game `.ver` is a repairable fault to
    // the strict path but the sentinel to install-mode. Same install, two constructors, two outcomes.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    strip_game_tree(dir.path()).expect("strip game tree");
    let paths = InstallPaths::new(dir.path());

    let strict =
        VersionReport::from_install(&paths, 1).expect_err("strict rejects a missing game ver");
    assert!(matches!(
        strict,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Game,
            kind: SanityKind::Missing,
        }
    ));

    let install = VersionReport::from_install_or_base(&paths, 1).expect("install-mode base-fills");
    assert_eq!(install.game_version(), BASE_GAME_VERSION);
}

#[test]
fn install_mode_ignores_the_bck_gate() {
    // Install-mode consults no `.bck`: a corrupt backup that the strict path rejects is invisible here
    // (the strict path's tamper posture does not apply to an install being brought up from nothing).
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(dir.path().join("boot/ffxivboot.bck"), [0u8, 0]).expect("nul bck");
    assert!(VersionReport::from_install_or_base(&InstallPaths::new(dir.path()), 1).is_ok());
}

#[test]
fn boot_version_or_sentinel_reports_base_when_absent() {
    // The boot-check counterpart: an absent boot `.ver` reports the sentinel so the server returns the
    // full boot chain into an empty install.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::remove_file(dir.path().join("boot/ffxivboot.ver")).expect("remove boot ver");
    let version = InstallPaths::new(dir.path())
        .boot_version_or_sentinel()
        .expect("boot version");
    assert_eq!(version, BASE_GAME_VERSION);
}

#[test]
fn boot_version_or_sentinel_reads_a_present_version() {
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    let version = InstallPaths::new(dir.path())
        .boot_version_or_sentinel()
        .expect("boot version");
    assert_eq!(version, BOOT_VER);
}

#[test]
fn boot_version_or_sentinel_treats_whitespace_as_base() {
    // A whitespace-only boot `.ver` is the sentinel, mirroring the reference launcher's GetVer.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::write(dir.path().join("boot/ffxivboot.ver"), "  \r\n\t").expect("whitespace boot ver");
    let version = InstallPaths::new(dir.path())
        .boot_version_or_sentinel()
        .expect("boot version");
    assert_eq!(version, BASE_GAME_VERSION);
}

#[test]
fn boot_version_is_strict_about_a_missing_repo() {
    // The default boot-version read keeps the strict posture: an absent boot repository is a repairable
    // fault, never a silent base-version substitution.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    std::fs::remove_file(dir.path().join("boot/ffxivboot.ver")).expect("remove boot ver");
    let err = InstallPaths::new(dir.path())
        .boot_version()
        .expect_err("missing boot ver");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Boot,
            kind: SanityKind::Missing,
        }
    ));
}

#[test]
fn boot_version_or_sentinel_surfaces_an_unreadable_file() {
    // A present-but-unreadable boot `.ver` is not silently base-versioned: even install-mode reports it
    // as a repairable fault (only an absent or whitespace file is the sentinel). A directory in place of
    // the file makes the read fail with a non-not-found error and stays reliable when CI runs as root.
    let dir = build_game_install(BOOT_VER, exes(), GAME_VER, &[EX1]).expect("install");
    let ver = dir.path().join("boot/ffxivboot.ver");
    std::fs::remove_file(&ver).expect("remove boot ver");
    std::fs::create_dir(&ver).expect("dir in place of boot ver");
    let err = InstallPaths::new(dir.path())
        .boot_version_or_sentinel()
        .expect_err("unreadable boot ver");
    assert!(matches!(
        err,
        ProtoError::InvalidVersionFiles {
            repo: VersionRepo::Boot,
            kind: SanityKind::Unreadable,
        }
    ));
}
