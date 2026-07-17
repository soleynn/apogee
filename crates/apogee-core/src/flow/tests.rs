//! Headless flow tests: every login branch driven against the fixture transport and a fake launch
//! backend, plus the session-cache fast path. No network, no real process.

use std::sync::Arc;
use std::time::Duration;

use apogee_otp::OtpSource;
use apogee_secrets::Secret;
use apogee_test_support::login_fixtures as fx;
use apogee_test_support::sandbox::build_game_install;
use apogee_test_support::transport::FixtureTransport;
use sqex_proto::{ProtoResponse, Transport};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{FlowContext, drive, language_id, launch_arguments};
use crate::command::{Command, Event, FlowState};
use crate::host;
use crate::launch::LaunchBackend;
use crate::launch::fake::FakeLaunchBackend;
use crate::model::{Account, AccountKind, Profile, Settings};
use crate::store::{Store, UidCacheEntry};

const BOOT_VER: &str = "2024.02.01.0000.0000";
const GAME_VER: &str = "2024.03.28.0000.0000";
const SESSION_ID: &str = "SESSIONXYZ";
const UID: &str = "UID-TOKEN-0123456789";
const REGION: u16 = 3;
const MAX_EXPANSION: u8 = 4;
const NOW: u64 = 1_000;

/// A game install whose expansion count matches the fixtures' `maxex`, so `from_install` succeeds.
fn game_install() -> TempDir {
    build_game_install(
        BOOT_VER,
        [b"boot" as &[u8], b"boot64", b"launcher64", b""],
        GAME_VER,
        &[
            "2024.03.28.0001.0000",
            "2024.03.28.0002.0000",
            "2024.03.28.0003.0000",
            "2024.03.28.0004.0000",
        ],
    )
    .unwrap()
}

/// A stored profile + account over a real game install, plus a scratch store and prefixes directory.
struct Harness {
    _game: TempDir,
    _store_dir: TempDir,
    prefixes: TempDir,
    store: Store,
    profile: Uuid,
    account: Uuid,
}

fn harness(use_otp: bool) -> Harness {
    harness_customized(use_otp, |_| {})
}

/// Like [`harness`], but the profile can be customized (runner, launch env/wrappers, prefix) before
/// it is saved.
fn harness_customized(use_otp: bool, customize: impl FnOnce(&mut Profile)) -> Harness {
    let game = game_install();
    let store_dir = TempDir::new().unwrap();
    let prefixes = TempDir::new().unwrap();
    let store = Store::new(store_dir.path().to_path_buf());

    let account = Account {
        use_otp,
        ..Account::new("testuser", AccountKind::Standard)
    };
    let mut profile = Profile::new("Main", account.id, game.path().to_path_buf());
    customize(&mut profile);
    store.save_account(&account).unwrap();
    store.save_profile(&profile).unwrap();

    Harness {
        _game: game,
        _store_dir: store_dir,
        prefixes,
        store,
        profile: profile.id,
        account: account.id,
    }
}

fn context(
    h: &Harness,
    transport: Arc<dyn Transport>,
    launch: Arc<dyn LaunchBackend>,
    now: u64,
) -> FlowContext {
    FlowContext {
        transport,
        launch,
        store: h.store.clone(),
        clock: Arc::new(move || now),
        computer_id: host::computer_id(),
        prefixes_dir: h.prefixes.path().to_path_buf(),
    }
}

async fn run(ctx: FlowContext, cmd: Command) -> Vec<Event> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    drive(ctx, cmd, tx, CancellationToken::new()).await;
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

fn states(events: &[Event]) -> Vec<FlowState> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::State(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn errors(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Error(err) => Some(err.to_string()),
            _ => None,
        })
        .collect()
}

fn secret(password: &str) -> Secret {
    Secret::new(password.as_bytes().to_vec())
}

/// The four scripted responses of a successful login → current-game registration.
fn login_then_current() -> [ProtoResponse; 4] {
    [
        fx::login_status_open(),
        fx::oauth_top("STOREDBLOB"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::register_current(UID),
    ]
}

/// A no-OTP login command for `profile`.
fn login_no_otp(profile: Uuid) -> Command {
    Command::Login {
        profile,
        password: secret("pw"),
        otp: OtpSource::Manual(String::new()),
    }
}

/// A no-OTP play command for `profile`.
fn play_no_otp(profile: Uuid) -> Command {
    Command::PatchAndPlay {
        profile,
        password: secret("pw"),
        otp: OtpSource::Manual(String::new()),
    }
}

/// Drive `cmd` with a caller-supplied cancellation token (for the Ctrl-C path), collecting events.
async fn run_with_cancel(ctx: FlowContext, cmd: Command, cancel: CancellationToken) -> Vec<Event> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    drive(ctx, cmd, tx, cancel).await;
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn use_otp_without_a_usable_code_asks_for_one_before_any_request() {
    let h = harness(true);
    let transport = Arc::new(FixtureTransport::new([]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Totp,
        },
    )
    .await;

    assert_eq!(states(&events), [FlowState::NeedsOtp]);
    assert_eq!(transport.recorded().len(), 0, "no request before the OTP");
}

#[tokio::test]
async fn a_manual_otp_is_sent_and_the_session_is_cached() {
    let h = harness(true);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Manual("123456".to_string()),
        },
    )
    .await;

    assert!(errors(&events).is_empty(), "login should succeed");
    // Login does not launch: no launch states.
    assert!(states(&events).is_empty());

    let recorded = transport.recorded();
    assert_eq!(recorded.len(), 4);
    let submit =
        String::from_utf8_lossy(recorded[2].body.as_ref().unwrap().as_bytes()).into_owned();
    assert!(submit.contains("otppw=123456"), "otp code sent: {submit}");

    // The session was cached for the account.
    let cached = h.store.load_uid_cache(h.account).unwrap().unwrap();
    assert_eq!(cached.unique_id, UID);
    assert_eq!(cached.region, REGION);
    assert_eq!(cached.max_expansion, MAX_EXPANSION);
    assert_eq!(cached.game_version, GAME_VER);
}

#[tokio::test]
async fn terms_not_accepted_is_narrated() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_terms_not_accepted(SESSION_ID, REGION, MAX_EXPANSION),
    ]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;

    assert_eq!(states(&events), [FlowState::NeedsTerms]);
    assert_eq!(transport.recorded().len(), 3, "no registration after terms");
}

#[tokio::test]
async fn a_closed_login_server_is_no_service() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([fx::login_status_closed(
        "Maintenance",
    )]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;

    assert_eq!(states(&events), [FlowState::NoService]);
    assert_eq!(transport.recorded().len(), 1, "stops at the gate");
}

#[tokio::test]
async fn an_inactive_service_is_no_service() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_no_service(SESSION_ID, REGION, MAX_EXPANSION),
    ]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;

    assert_eq!(states(&events), [FlowState::NoService]);
}

#[tokio::test]
async fn a_boot_patch_requirement_is_narrated() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::register_needs_boot(),
    ]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;

    assert_eq!(states(&events), [FlowState::NeedsBootPatch]);
}

#[tokio::test]
async fn pending_game_patches_are_summed_and_narrated() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::register_with_patches(
            UID,
            &[
                &fx::synthetic_patch_entry(52_430_000, "2024.03.28.0000.0001"),
                &fx::synthetic_patch_entry(10, "2024.03.28.0000.0002"),
            ],
        ),
    ]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;

    assert_eq!(
        states(&events),
        [FlowState::PatchesPending {
            count: 2,
            bytes: 52_430_010,
        }]
    );
}

#[tokio::test]
async fn a_current_game_launches_straight_through() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch.clone(), NOW);

    let events = run(
        ctx,
        Command::PatchAndPlay {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Manual(String::new()),
        },
    )
    .await;

    assert_eq!(
        states(&events),
        [FlowState::Launching, FlowState::Running, FlowState::Exited]
    );
    let request = launch.last_request().unwrap();
    assert!(request.program.ends_with("/game/ffxiv_dx11.exe"));
    assert!(request.working_dir.ends_with("game"));
    assert!(request.encrypted_args.starts_with("//**sqex0003"));
}

#[tokio::test]
async fn launch_without_a_cached_session_asks_to_log_in_first() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, Command::Launch { profile: h.profile }).await;

    assert_eq!(states(&events), [FlowState::NeedsLogin]);
    assert_eq!(transport.recorded().len(), 0);
}

#[tokio::test]
async fn a_launch_inside_the_cache_window_skips_the_network() {
    let h = harness(false);

    // First, a full play populates the session cache.
    let first_transport = Arc::new(FixtureTransport::new(login_then_current()));
    let first_launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, first_transport.clone(), first_launch, NOW);
    let events = run(
        ctx,
        Command::PatchAndPlay {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Manual(String::new()),
        },
    )
    .await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    // Later, still inside the window, a bare launch reuses the cache and makes zero requests.
    let later_transport = Arc::new(FixtureTransport::new([]));
    let later_launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(
        &h,
        later_transport.clone(),
        later_launch.clone(),
        NOW + 3_600,
    );
    let events = run(ctx, Command::Launch { profile: h.profile }).await;

    assert_eq!(
        states(&events),
        [FlowState::Launching, FlowState::Running, FlowState::Exited]
    );
    assert_eq!(
        later_transport.recorded().len(),
        0,
        "a cached launch makes no requests"
    );
    assert_eq!(later_launch.launch_count(), 1);
}

#[tokio::test]
async fn an_unknown_profile_is_a_typed_error() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch, NOW);

    let events = run(
        ctx,
        Command::Launch {
            profile: Uuid::new_v4(),
        },
    )
    .await;
    assert_eq!(errors(&events).len(), 1);
}

#[tokio::test]
async fn a_version_no_longer_serviced_is_narrated() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::register_not_serviced(),
    ]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;
    assert_eq!(states(&events), [FlowState::VersionNotServiced]);
}

#[tokio::test]
async fn a_rejected_password_surfaces_as_one_error() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_auth_failed(),
    ]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;
    assert!(
        states(&events).is_empty(),
        "an auth failure is an error, not a disposition"
    );
    assert_eq!(errors(&events).len(), 1);
    assert_eq!(
        transport.recorded().len(),
        3,
        "no registration after a failed submit"
    );
}

#[tokio::test]
async fn an_unreadable_install_surfaces_as_one_error_on_the_login_path() {
    let empty = TempDir::new().unwrap();
    let path = empty.path().to_path_buf();
    let h = harness_customized(false, move |p| p.game_path = path);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
    ]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;
    assert_eq!(errors(&events).len(), 1, "a bad install surfaces one error");
    assert_eq!(
        transport.recorded().len(),
        3,
        "the version report is read before registration"
    );
}

#[tokio::test]
async fn a_profile_referencing_a_missing_account_is_a_typed_error() {
    let h = harness(false);
    // Drop the account the profile points at, leaving it dangling.
    h.store.delete_account(h.account).unwrap();
    let transport = Arc::new(FixtureTransport::new([]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, login_no_otp(h.profile)).await;
    let errs = errors(&events);
    assert_eq!(errs.len(), 1);
    assert!(
        errs[0].contains("no account"),
        "expected NoAccount, got {errs:?}"
    );
    assert_eq!(
        transport.recorded().len(),
        0,
        "resolution fails before any request"
    );
}

#[tokio::test]
async fn launch_carries_the_profile_env_and_wrappers() {
    let h = harness_customized(false, |p| {
        p.launch.extra_env = vec![("DXVK_HUD".to_string(), "fps".to_string())];
        p.launch.wrappers = vec!["gamescope".to_string()];
    });
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let request = launch.last_request().unwrap();
    assert_eq!(request.env.get("DXVK_HUD").map(String::as_str), Some("fps"));
    assert_eq!(request.wrappers, vec!["gamescope".to_string()]);
}

#[tokio::test]
async fn close_after_launch_detaches_without_supervising() {
    let h = harness(false);
    h.store
        .save_settings(&Settings {
            language: "en".to_string(),
            close_after_launch: true,
        })
        .unwrap();
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    // A running backend would block wait() forever; detach must return before ever awaiting it.
    let launch = Arc::new(FakeLaunchBackend::running());
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = tokio::time::timeout(Duration::from_secs(5), run(ctx, play_no_otp(h.profile)))
        .await
        .expect("close_after_launch must not block on supervision");

    assert_eq!(states(&events), [FlowState::Launching, FlowState::Running]);
    assert!(
        !launch.was_killed(),
        "a detached launch does not kill the game"
    );
}

#[tokio::test]
async fn cancelling_a_running_launch_kills_the_game_and_exits() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let launch = Arc::new(FakeLaunchBackend::running());
    let ctx = context(&h, transport, launch.clone(), NOW);

    // A pre-cancelled token: the supervise select! takes its cancel arm the moment it is reached,
    // deterministically exercising the kill path without racing on timing.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let events = tokio::time::timeout(
        Duration::from_secs(5),
        run_with_cancel(ctx, play_no_otp(h.profile), cancel),
    )
    .await
    .expect("cancel must unblock the supervised launch");

    assert_eq!(
        states(&events),
        [FlowState::Launching, FlowState::Running, FlowState::Exited]
    );
    assert!(launch.was_killed(), "cancel must kill the running game");
}

#[tokio::test]
async fn a_corrupt_cache_is_cleared_and_launch_asks_to_log_in() {
    let h = harness(false);
    let dir = h._store_dir.path().join("uid-cache");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{}.json", h.account)), b"{ not valid json").unwrap();

    let transport = Arc::new(FixtureTransport::new([]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch, NOW);

    let events = run(ctx, Command::Launch { profile: h.profile }).await;
    assert_eq!(states(&events), [FlowState::NeedsLogin]);
    assert_eq!(transport.recorded().len(), 0);
    // The corrupt entry was cleared, so a repeat launch would not keep re-preserving it.
    assert_eq!(h.store.load_uid_cache(h.account).unwrap(), None);
}

#[tokio::test]
async fn a_corrupt_cache_falls_back_to_a_full_login_on_play() {
    let h = harness(false);
    let dir = h._store_dir.path().join("uid-cache");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{}.json", h.account)), b"garbage").unwrap();

    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));
    assert_eq!(
        transport.recorded().len(),
        4,
        "a corrupt cache forces a full login"
    );
    assert_eq!(launch.launch_count(), 1);
}

#[test]
fn language_id_maps_client_languages() {
    assert_eq!(language_id("ja"), 0);
    assert_eq!(language_id("en"), 1);
    assert_eq!(language_id("de"), 2);
    assert_eq!(language_id("fr"), 3);
    assert_eq!(
        language_id("zz"),
        1,
        "an unknown language defaults to English"
    );
}

#[test]
fn launch_arguments_carry_the_fixed_set_in_order() {
    let session = UidCacheEntry {
        unique_id: "UID-XYZ".to_string(),
        region: 7,
        max_expansion: 4,
        game_version: "2024.03.28.0000.0000".to_string(),
        expires_at: 0,
    };
    // The plaintext form pins the byte-identity-critical set: order, DEV.TestSID = the unique id,
    // SYS.Region, the language byte, and the game version.
    assert_eq!(
        launch_arguments(&session, 3).build_plain(),
        " DEV.DataPathType=1 DEV.MaxEntitledExpansionID=4 DEV.TestSID=UID-XYZ DEV.UseSqPack=1 \
         SYS.Region=7 language=3 resetConfig=0 ver=2024.03.28.0000.0000"
    );
}
