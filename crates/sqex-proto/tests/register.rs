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
    ClientContext, ComputerId, Credentials, InstallPaths, LauncherTime, LoginKind, OauthContext,
    ProtoError, ProtoResponse, Registration, SanityKind, Step, VersionRepo, VersionReport,
    begin_login, register_session,
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

/// A registration response carrying the UID header and `body`.
fn uid_response(body: Vec<u8>) -> ProtoResponse {
    ProtoResponse::new(200, body).with_header(
        HeaderName::from_static("x-patch-unique-id"),
        HeaderValue::from_static(UID),
    )
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

/// Drive login then registration through one transport scripted with `[top, login, register]`,
/// returning the transport (for request inspection) and the registration outcome. The login legs use
/// `?` so a scripting mistake surfaces as the outcome rather than a panic in this helper.
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
    // 409 short-circuits before the UID check, even with a body present.
    let (_transport, outcome) =
        login_then_register(ProtoResponse::new(409, b"boot patch pending".to_vec()));
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
fn a_transport_failure_propagates() {
    // Script only the two login responses; the registration call finds the transport exhausted, which
    // surfaces as a transport error.
    let id = computer_id();
    let transport = FixtureTransport::new([
        ProtoResponse::new(200, top_page("STOREDBLOB").into_bytes()),
        ProtoResponse::new(200, success_body(SESSION_ID).into_bytes()),
    ]);

    let err = block_on(async {
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
        // Report construction fails here; the registration call below is never reached.
        let report = VersionReport::from_install(&paths, auth.max_expansion)?;
        register_session(&transport, &auth, &report).await
    })
    .expect_err("corrupt install");

    assert!(matches!(err, ProtoError::InvalidVersionFiles { .. }));
    assert_eq!(transport.recorded().len(), 2);
}
