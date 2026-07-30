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

use apogee_patcher::{PatchProgress, Repo};

use super::{FlowContext, drive, language_id, launch_arguments, read_repo_ver};
use crate::addons::AddonBackend;
use crate::addons::fake::{AddonCall, FakeAddons};
use crate::command::{Command, Event, FlowState, PrefixAction};
use crate::host;
use crate::launch::LaunchBackend;
use crate::launch::fake::FakeLaunchBackend;
use crate::model::{Account, AccountKind, Profile, Settings};
use crate::patch::PatchBackend;
use crate::patch::fake::FakePatchBackend;
use crate::store::{Store, UidCacheEntry};
use apogee_addons::{ExternalAddon, RunIn, Trigger};

use fx::{BOOT_VERSION, GAME_VERSION, SESSION_ID, UNIQUE_ID};

const REGION: u16 = 3;
const MAX_EXPANSION: u8 = 4;
const NOW: u64 = 1_000;

/// A game install whose expansion count matches the fixtures' `maxex`, so `from_install` succeeds.
fn game_install() -> TempDir {
    build_game_install(
        BOOT_VERSION,
        [b"boot" as &[u8], b"boot64", b"launcher64", b""],
        GAME_VERSION,
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
    backups: TempDir,
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
    let backups = TempDir::new().unwrap();
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
        backups,
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
    context_with(h, transport, Arc::new(FakePatchBackend::new()), launch, now)
}

/// Like [`context`], but with an explicit patch backend the caller can inspect after the flow runs.
fn context_with(
    h: &Harness,
    transport: Arc<dyn Transport>,
    patch: Arc<dyn PatchBackend>,
    launch: Arc<dyn LaunchBackend>,
    now: u64,
) -> FlowContext {
    context_with_addons(
        h,
        transport,
        patch,
        launch,
        Arc::new(FakeAddons::new()),
        now,
    )
}

/// Like [`context_with`], but with an explicit addon backend the caller can inspect afterwards.
fn context_with_addons(
    h: &Harness,
    transport: Arc<dyn Transport>,
    patch: Arc<dyn PatchBackend>,
    launch: Arc<dyn LaunchBackend>,
    addons: Arc<dyn AddonBackend>,
    now: u64,
) -> FlowContext {
    FlowContext {
        transport,
        patch,
        launch,
        addons,
        store: h.store.clone(),
        clock: Arc::new(move || now),
        computer_id: host::computer_id(),
        prefixes_dir: h.prefixes.path().to_path_buf(),
        backups_dir: h.backups.path().to_path_buf(),
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

/// The prefix reports a run emitted, in order.
fn health_reports(events: &[Event]) -> Vec<apogee_runtime::PrefixHealth> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::PrefixHealth(health) => Some(health.clone()),
            _ => None,
        })
        .collect()
}

fn secret(password: &str) -> Secret {
    Secret::new(password.as_bytes().to_vec())
}

/// The `PatchProgress` frames relayed onto the event stream.
fn patch_frames(events: &[Event]) -> Vec<PatchProgress> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Patch(p) => Some(p.clone()),
            _ => None,
        })
        .collect()
}

/// A nine-field game patch entry with a caller-chosen URL, so a test can steer its repo (the base
/// game vs. an `ex{n}` expansion) through the classifier.
fn game_entry(length: u64, version: &str, url: &str) -> String {
    let h1 = "a".repeat(40);
    let h2 = "b".repeat(40);
    format!("{length}\t0\t0\t0\tD{version}\tsha1\t52428800\t{h1},{h2}\t{url}")
}

/// A patch command that applies pending patches without launching.
fn patch_cmd(profile: Uuid) -> Command {
    Command::Patch {
        profile,
        password: secret("pw"),
        otp: OtpSource::Manual(String::new()),
    }
}

/// An install-from-nothing command.
fn install_cmd(profile: Uuid) -> Command {
    Command::Install {
        profile,
        password: secret("pw"),
        otp: OtpSource::Manual(String::new()),
    }
}

/// The four scripted responses of a successful login → current-game registration. `Login` neither
/// patches nor launches, so no boot check precedes its registration.
fn login_then_current() -> [ProtoResponse; 4] {
    [
        fx::login_status_open(),
        fx::oauth_top("STOREDBLOB"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::register_current(UNIQUE_ID),
    ]
}

/// The same for a flow that patches: boot is checked, and found current, before registering.
fn play_then_current() -> [ProtoResponse; 5] {
    [
        fx::login_status_open(),
        fx::oauth_top("STOREDBLOB"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::boot_current(),
        fx::register_current(UNIQUE_ID),
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
    assert_eq!(cached.unique_id, UNIQUE_ID);
    assert_eq!(cached.region, REGION);
    assert_eq!(cached.max_expansion, MAX_EXPANSION);
    assert_eq!(cached.game_version, GAME_VERSION);
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
            UNIQUE_ID,
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
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
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
        [
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::Exited
        ]
    );
    let plan = launch.last_plan().unwrap();
    assert!(plan.program().ends_with("/game/ffxiv_dx11.exe"));
    assert!(plan.working_dir().is_some_and(|dir| dir.ends_with("game")));
    assert!(plan.args().starts_with("//**sqex0003"));
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
    let first_transport = Arc::new(FixtureTransport::new(play_then_current()));
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
        [
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::Exited
        ]
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
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let plan = launch.last_plan().unwrap();
    assert_eq!(plan.env().get("DXVK_HUD").map(String::as_str), Some("fps"));
    assert_eq!(plan.wrappers(), ["gamescope".to_string()]);
}

/// The synchronization primitive is resolved from what the runner that built the prefix can actually
/// do, not from the kernel alone. A host with the kernel support but a runner build without it must
/// fall back rather than select ntsync, because selecting ntsync sets no variable at all: the launch
/// would run with neither esync nor fsync while every report said otherwise.
#[tokio::test]
async fn a_runner_without_ntsync_launches_with_a_fallback_rather_than_with_nothing() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(
        FakeLaunchBackend::exiting().reporting(apogee_runtime::HostCaps {
            ntsync: false,
            fsync: true,
        }),
    );
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let plan = launch.last_plan().unwrap();
    assert_eq!(plan.env().get("WINEFSYNC").map(String::as_str), Some("1"));
}

/// The other side of the same resolution: where the runner does support it, the launch carries no
/// synchronization variable, because that is how ntsync is selected.
#[tokio::test]
async fn a_runner_with_ntsync_launches_carrying_no_sync_variable() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(
        FakeLaunchBackend::exiting().reporting(apogee_runtime::HostCaps {
            ntsync: true,
            fsync: true,
        }),
    );
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let plan = launch.last_plan().unwrap();
    assert!(!plan.env().contains_key("WINEFSYNC"));
    assert!(!plan.env().contains_key("WINEESYNC"));
}

/// Checking reports and changes nothing. The report reaches the shell as one value, because the whole
/// point is the list a user decides about.
#[tokio::test]
async fn checking_a_prefix_reports_its_drift_and_changes_nothing() {
    let h = harness(false);
    let drift = apogee_runtime::PrefixHealth {
        issues: vec![apogee_runtime::HealthIssue::MissingSkeleton {
            path: std::path::PathBuf::from("/prefix/system.reg"),
        }],
    };
    let launch = Arc::new(
        FakeLaunchBackend::exiting().with_health(drift, apogee_runtime::PrefixHealth::default()),
    );
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new(vec![])),
        launch.clone(),
        NOW,
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Check,
        },
    )
    .await;

    assert!(states(&events).contains(&FlowState::CheckingPrefix));
    assert!(
        !states(&events).contains(&FlowState::NoPrefix),
        "there was one to examine"
    );
    assert_eq!(health_reports(&events).len(), 1);
    assert_eq!(health_reports(&events)[0].issues.len(), 1);
    assert!(!launch.was_fixed(), "a check fixes nothing");
    assert!(!launch.was_recreated(), "a check destroys nothing");
}

/// A prefix that was never created and one with nothing wrong are different answers, and reporting
/// them identically leaves a user unable to tell which they got.
#[tokio::test]
async fn a_prefix_that_does_not_exist_says_so_rather_than_reporting_nothing_wrong() {
    let h = harness(false);
    // The double has no prefix at all, which is the same shape the real backend reports for one that
    // was never created.
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new(vec![])),
        launch.clone(),
        NOW,
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Check,
        },
    )
    .await;

    assert!(states(&events).contains(&FlowState::NoPrefix));
    assert!(
        health_reports(&events).is_empty(),
        "nothing was examined, so nothing is reported about it"
    );
}

/// Fixing applies the resolutions that leave the prefix in place and reports what is left, so a
/// problem no targeted fix covers is still in front of the user afterwards rather than silently gone.
#[tokio::test]
async fn fixing_a_prefix_reports_what_is_left_and_never_recreates() {
    let h = harness(false);
    let before = apogee_runtime::PrefixHealth {
        issues: vec![
            apogee_runtime::HealthIssue::MissingSkeleton {
                path: std::path::PathBuf::from("/prefix/system.reg"),
            },
            apogee_runtime::HealthIssue::RunnerMismatch {
                recorded: apogee_runtime::RunnerRef {
                    name: "GE-Proton".to_string(),
                    version: "11-1".to_string(),
                },
                expected: apogee_runtime::RunnerRef {
                    name: "wine-xiv".to_string(),
                    version: "10.8".to_string(),
                },
            },
        ],
    };
    // Only the first has a targeted fix; the runner change is left behind on purpose.
    let after = apogee_runtime::PrefixHealth {
        issues: vec![before.issues[1].clone()],
    };
    let launch = Arc::new(FakeLaunchBackend::exiting().with_health(before, after));
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new(vec![])),
        launch.clone(),
        NOW,
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Fix,
        },
    )
    .await;

    assert!(states(&events).contains(&FlowState::FixingPrefix));
    assert!(launch.was_fixed());
    assert!(
        !launch.was_recreated(),
        "the destructive one is never reached by fixing"
    );
    let residual = health_reports(&events);
    assert_eq!(residual.len(), 1);
    assert_eq!(
        residual[0].issues.len(),
        1,
        "what no targeted fix covers is still reported"
    );
}

/// The destructive one happens only when it is the action that was asked for.
#[tokio::test]
async fn recreating_is_the_only_action_that_destroys_the_prefix() {
    let h = harness(false);
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new(vec![])),
        launch.clone(),
        NOW,
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Recreate,
        },
    )
    .await;

    assert!(states(&events).contains(&FlowState::RecreatingPrefix));
    assert!(launch.was_recreated());
    assert!(errors(&events).is_empty());
}

/// Creating one is what a launch does first, reachable on its own so a user can pay that cost before
/// they want to play rather than during.
#[tokio::test]
async fn creating_a_prefix_prepares_it_without_launching() {
    let h = harness(false);
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new(vec![])),
        launch.clone(),
        NOW,
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Create,
        },
    )
    .await;

    assert!(states(&events).contains(&FlowState::PreparingPrefix));
    assert_eq!(launch.prepared().len(), 1);
    assert_eq!(launch.launch_count(), 0, "nothing was launched");
}

/// A prefix that has graphics translation installed launches with the overrides that activate it,
/// and with its shader cache pointed somewhere prefix-specific. Placing the files is one half; a
/// launch that does not override the libraries to them loads the prefix's built-in ones instead.
#[tokio::test]
async fn a_prefix_with_graphics_translation_launches_with_it_activated() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(
        FakeLaunchBackend::exiting().with_dxvk(apogee_runtime::DxvkEnv {
            state_cache: Some(std::path::PathBuf::from("/prefix/dxvk_cache")),
            nvapi: false,
        }),
    );
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let plan = launch.last_plan().unwrap();
    assert_eq!(
        plan.env().get("WINEDLLOVERRIDES").map(String::as_str),
        Some("d3d10core,d3d11,d3d9,dxgi=native")
    );
    assert_eq!(
        plan.env().get("DXVK_STATE_CACHE_PATH").map(String::as_str),
        Some("/prefix/dxvk_cache")
    );
}

/// A prefix without it overrides nothing, rather than pointing the game at libraries that are not
/// there.
#[tokio::test]
async fn a_prefix_without_graphics_translation_overrides_nothing() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));
    assert!(
        !launch
            .last_plan()
            .unwrap()
            .env()
            .contains_key("WINEDLLOVERRIDES")
    );
}

/// The knobs a profile persists reach the launch, so what a user set is what the game runs with.
#[tokio::test]
async fn the_profile_knobs_reach_the_launch() {
    let h = harness_customized(false, |p| {
        p.launch.hud = apogee_runtime::Hud::Mango;
        p.launch.gpu = apogee_runtime::GpuSelect::NvidiaPrime;
        p.launch.gamemode = true;
        p.launch.gamescope = Some(apogee_runtime::Gamescope {
            width: Some(1280),
            height: Some(800),
            fullscreen: true,
            ..apogee_runtime::Gamescope::default()
        });
    });
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let plan = launch.last_plan().unwrap();
    assert_eq!(plan.env().get("MANGOHUD").map(String::as_str), Some("1"));
    assert_eq!(
        plan.env()
            .get("__NV_PRIME_RENDER_OFFLOAD")
            .map(String::as_str),
        Some("1")
    );
    // The nested compositor wraps the whole invocation, and its arguments end at the separator, so
    // the ordering is what makes the game the thing being wrapped rather than one of its arguments.
    assert_eq!(
        plan.wrappers(),
        [
            "gamescope",
            "-W",
            "1280",
            "-H",
            "800",
            "-f",
            "--",
            "gamemoderun"
        ]
    );
}

/// A profile's own variable still wins over the one the host resolution computed for it.
#[tokio::test]
async fn a_profile_variable_outranks_the_computed_one() {
    let h = harness_customized(false, |p| {
        p.launch.extra_env = vec![("WINEFSYNC".to_string(), "0".to_string())];
    });
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(
        FakeLaunchBackend::exiting().reporting(apogee_runtime::HostCaps {
            ntsync: false,
            fsync: true,
        }),
    );
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let plan = launch.last_plan().unwrap();
    assert_eq!(plan.env().get("WINEFSYNC").map(String::as_str), Some("0"));
}

#[tokio::test]
async fn close_after_launch_detaches_without_supervising() {
    let h = harness(false);
    h.store
        .save_settings(&Settings {
            language: "en".to_string(),
            close_after_launch: true,
            keep_patches: false,
            backups_kept: 5,
            backup_before_patch: false,
        })
        .unwrap();
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    // A running backend would block wait() forever; detach must return before ever awaiting it.
    let launch = Arc::new(FakeLaunchBackend::running());
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = tokio::time::timeout(Duration::from_secs(5), run(ctx, play_no_otp(h.profile)))
        .await
        .expect("close_after_launch must not block on supervision");

    assert_eq!(
        states(&events),
        [
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running
        ]
    );
    assert!(
        !launch.was_killed(),
        "a detached launch does not kill the game"
    );
}

/// A login that lands on one pending game patch, then reports current. The boot check precedes the
/// register loop, so it is scripted once even though registration happens twice.
fn login_then_patch() -> [ProtoResponse; 6] {
    [
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::boot_current(),
        fx::register_with_patches(
            UNIQUE_ID,
            &[&game_entry(
                1_000,
                "2024.03.28.0001.0000",
                "http://patch-dl.example.invalid/game/4e9a232b/D2024.03.28.0001.0000.patch",
            )],
        ),
        fx::register_current(UNIQUE_ID),
    ]
}

/// Write a config tree into the prefix the launcher will derive for this profile, so there is
/// something to capture.
fn plant_config(h: &Harness) -> std::path::PathBuf {
    let profile = h.store.load_profile(h.profile).unwrap();
    let config = h
        .prefixes
        .path()
        .join(crate::flow::prefix_name(&profile))
        .join("drive_c/users/steamuser/Documents/My Games/FINAL FANTASY XIV - A Realm Reborn");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("FFXIV.cfg"), "cfg").unwrap();
    config
}

/// A patch is the moment settings are most likely to be rewritten, so the launcher captures them
/// first. Once per flow, not once per repo.
#[tokio::test]
async fn patching_captures_the_settings_first() {
    let h = harness(false);
    plant_config(&h);
    let transport = Arc::new(FixtureTransport::new(login_then_patch()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch, NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    let states = states(&events);

    let backing = states
        .iter()
        .position(|s| *s == FlowState::BackingUp)
        .expect("the capture is announced");
    let patching = states
        .iter()
        .position(|s| *s == FlowState::Patching)
        .expect("patching happens");
    assert!(backing < patching, "captured after patching: {states:?}");
    assert_eq!(
        states
            .iter()
            .filter(|s| **s == FlowState::BackingUp)
            .count(),
        1,
        "captured more than once: {states:?}"
    );

    let archives: Vec<_> = std::fs::read_dir(h.backups.path().join(h.profile.to_string()))
        .expect("a backup directory")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(archives.len(), 1, "expected one archive");
}

/// Turning it off means exactly that: no capture, and no state claiming one happened.
#[tokio::test]
async fn a_patch_captures_nothing_when_the_setting_is_off() {
    let h = harness(false);
    plant_config(&h);
    h.store
        .save_settings(&Settings {
            backup_before_patch: false,
            ..Settings::default()
        })
        .unwrap();
    let transport = Arc::new(FixtureTransport::new(login_then_patch()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch, NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert!(!states(&events).contains(&FlowState::BackingUp));
    assert!(!h.backups.path().join(h.profile.to_string()).exists());
}

/// A prefix the game has never written into is the ordinary state before a first launch. Nothing is
/// captured, and nothing claims otherwise: announcing it would say a backup was taken, and reporting
/// it would fail an install that is going fine.
#[tokio::test]
async fn a_prefix_with_no_settings_yet_neither_captures_nor_complains() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(login_then_patch()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch, NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert!(!states(&events).contains(&FlowState::BackingUp));
    assert!(
        !events.iter().any(|e| matches!(e, Event::Error(_))),
        "a first-run patch reported an error: {events:?}"
    );
}

/// Companions start once the game is up, and are torn down when it exits. The order is the flow's
/// responsibility: a tool that looks for the game has to find it.
#[tokio::test]
async fn companions_start_after_the_game_and_are_torn_down_when_it_exits() {
    let h = harness(false);
    let mut profile = h.store.load_profile(h.profile).unwrap();
    profile.external.push(
        ExternalAddon::new(
            "/opt/act/act.sh",
            vec![],
            RunIn::Host,
            Trigger::WithGame {
                keep_after_close: false,
            },
        )
        .unwrap(),
    );
    h.store.save_profile(&profile).unwrap();

    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        transport,
        Arc::new(FakePatchBackend::new()),
        launch,
        addons.clone(),
        NOW,
    );

    let events = run(ctx, play_no_otp(h.profile)).await;

    assert_eq!(
        addons.calls(),
        [
            // The prefix is prepared before the game starts, and this profile does not ask for Dalamud.
            AddonCall::Prepared {
                prefix: false,
                dalamud: false,
            },
            AddonCall::Started {
                game_pid: std::process::id().cast_signed(),
                count: 1,
            },
            AddonCall::GameClosed,
        ]
    );
    // The profile's list reached the seam, and the game was up before it did: `Running` is emitted from
    // `launch_game` between the launch and the companion start, so its position among the states is what
    // says the ordering held.
    assert_eq!(
        states(&events),
        [
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::Exited
        ]
    );
    assert_eq!(
        addons.started_programs(),
        [std::path::PathBuf::from("/opt/act/act.sh")]
    );
}

/// A cancelled launch stops what was started but never runs the tools that expect a session which
/// actually happened.
#[tokio::test]
async fn a_cancelled_launch_abandons_its_companions() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::running());
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        transport,
        Arc::new(FakePatchBackend::new()),
        launch,
        addons.clone(),
        NOW,
    );

    let cancel = CancellationToken::new();
    let on_cancel = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        on_cancel.cancel();
    });
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::time::timeout(
        Duration::from_secs(5),
        drive(ctx, play_no_otp(h.profile), tx, cancel),
    )
    .await
    .expect("a cancelled launch must finish");

    assert!(
        addons.calls().contains(&AddonCall::Abandoned),
        "expected the companions to be abandoned, got {:?}",
        addons.calls()
    );
    assert!(!addons.calls().contains(&AddonCall::GameClosed));
}

/// Detaching after launch is conditional on owing nothing. Detaching with companions still to stop
/// would leave them running with nothing left that knows about them.
#[tokio::test]
async fn close_after_launch_stays_attached_when_teardown_is_owed() {
    let h = harness(false);
    h.store
        .save_settings(&Settings {
            language: "en".to_string(),
            close_after_launch: true,
            keep_patches: false,
            backups_kept: 5,
            backup_before_patch: false,
        })
        .unwrap();
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let addons = Arc::new(FakeAddons::new().with_work());
    let ctx = context_with_addons(
        &h,
        transport,
        Arc::new(FakePatchBackend::new()),
        launch,
        addons.clone(),
        NOW,
    );

    let events = tokio::time::timeout(Duration::from_secs(5), run(ctx, play_no_otp(h.profile)))
        .await
        .expect("the launch must finish");

    assert!(
        states(&events).contains(&FlowState::SupervisingAddons),
        "staying attached must be visible, got {:?}",
        states(&events)
    );
    assert!(addons.calls().contains(&AddonCall::GameClosed));
}

/// With nothing owed, detaching is exactly the behavior it was before companions existed.
#[tokio::test]
async fn close_after_launch_still_detaches_when_nothing_is_owed() {
    let h = harness(false);
    h.store
        .save_settings(&Settings {
            language: "en".to_string(),
            close_after_launch: true,
            keep_patches: false,
            backups_kept: 5,
            backup_before_patch: false,
        })
        .unwrap();
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    // Running, so awaiting the game would block forever: detaching must not await it.
    let launch = Arc::new(FakeLaunchBackend::running());
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        transport,
        Arc::new(FakePatchBackend::new()),
        launch,
        addons.clone(),
        NOW,
    );

    let events = tokio::time::timeout(Duration::from_secs(5), run(ctx, play_no_otp(h.profile)))
        .await
        .expect("detaching must not block on supervision");

    assert_eq!(
        states(&events),
        [
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running
        ]
    );
    assert!(!addons.calls().contains(&AddonCall::GameClosed));
}

/// A companion that failed has to reach the shell, which only learns about failure from the event
/// stream. A report nobody reads is the same as no report.
#[tokio::test]
async fn a_companion_failure_reaches_the_event_stream() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let addons = Arc::new(FakeAddons::new().failing("no such file"));
    let ctx = context_with_addons(
        &h,
        transport,
        Arc::new(FakePatchBackend::new()),
        launch,
        addons,
        NOW,
    );

    let events = run(ctx, play_no_otp(h.profile)).await;

    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::Error(crate::error::CoreError::Addon { reason, .. }) if reason == "no such file"
        )),
        "a failed companion must be reported, got {events:?}"
    );
}

#[tokio::test]
async fn cancelling_a_running_launch_kills_the_game_and_exits() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
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
        [
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::Exited
        ]
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

    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport.clone(), launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));
    assert_eq!(
        transport.recorded().len(),
        5,
        "a corrupt cache forces a full login"
    );
    assert_eq!(launch.launch_count(), 1);
}

#[test]
fn read_repo_ver_canonicalizes_so_it_matches_the_catalog_key() {
    let dir = TempDir::new().unwrap();
    let game = dir.path().join("game");
    std::fs::create_dir_all(&game).unwrap();

    // A UTF-8 BOM-prefixed `.ver` (EF BB BF …): a plain read_to_string + trim would keep the
    // zero-width BOM (U+FEFF is not whitespace), and the catalog's exact-match lookup would miss.
    std::fs::write(
        game.join("ffxivgame.ver"),
        b"\xEF\xBB\xBF2024.03.28.0000.0000",
    )
    .unwrap();
    assert_eq!(
        read_repo_ver(dir.path(), Repo::Game).as_deref(),
        Some("2024.03.28.0000.0000"),
        "the BOM must be stripped to match the registration/catalog version"
    );

    // Absent and empty repos are `None` (not part of a repair plan).
    assert_eq!(read_repo_ver(dir.path(), Repo::Boot), None);
    let boot = dir.path().join("boot");
    std::fs::create_dir_all(&boot).unwrap();
    std::fs::write(boot.join("ffxivboot.ver"), b"   ").unwrap();
    assert_eq!(read_repo_ver(dir.path(), Repo::Boot), None);
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

#[tokio::test]
async fn patches_pending_continue_to_launch() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::boot_current(),
        fx::register_with_patches(
            UNIQUE_ID,
            &[
                &game_entry(
                    1_000,
                    "2024.03.28.0001.0000",
                    "http://patch-dl.example.invalid/game/4e9a232b/D2024.03.28.0001.0000.patch",
                ),
                &game_entry(
                    2_000,
                    "2024.03.28.0001.0000",
                    "http://patch-dl.example.invalid/game/ex1/6b936f08/D2024.03.28.0001.0000.patch",
                ),
            ],
        ),
        fx::register_current(UNIQUE_ID),
    ]));
    let patch = Arc::new(FakePatchBackend::new());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with(&h, transport.clone(), patch.clone(), launch, NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;

    assert!(
        errors(&events).is_empty(),
        "patch-then-play should succeed: {:?}",
        errors(&events)
    );
    assert_eq!(
        states(&events),
        [
            FlowState::Patching,
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::Exited
        ]
    );
    // The game patchlist split into a base-game set and an ex1 set, base first.
    assert_eq!(patch.installed_repos(), [Repo::Game, Repo::Expansion(1)]);
    // Auth (3) + boot check + register-pending + re-register-current = 6 requests, then launch.
    assert_eq!(transport.recorded().len(), 6);
    assert!(
        patch_frames(&events)
            .iter()
            .any(|p| matches!(p, PatchProgress::Applied { .. })),
        "an apply frame reached the stream"
    );
}

#[tokio::test]
async fn a_stale_boot_is_patched_before_registering() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::boot_patchlist(&[&fx::synthetic_boot_entry(4_096, "2024.02.01.0000.0001")]),
        fx::register_current(UNIQUE_ID),
    ]));
    let patch = Arc::new(FakePatchBackend::new());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with(&h, transport.clone(), patch.clone(), launch, NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;

    assert!(
        errors(&events).is_empty(),
        "boot should be patched before registering, then launch: {:?}",
        errors(&events)
    );
    assert_eq!(
        states(&events),
        [
            FlowState::Patching,
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::Exited
        ]
    );
    assert_eq!(patch.installed_repos(), [Repo::Boot]);
    // Auth (3), boot check (patches), register (current) = 5. Registration is never asked to
    // discover the stale boot, because it answers that 410 rather than 409.
    assert_eq!(transport.recorded().len(), 5);
}

/// Boot checks clean, yet registration still demands a boot patch. That is the reference launcher's
/// documented tamper case (boot EXEs whose hashes no longer match), not ordinary staleness, and it
/// has no recovery: the flow stops instead of spinning the register loop.
#[tokio::test]
async fn a_boot_demand_with_nothing_offered_stops_rather_than_spinning() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::boot_current(),
        fx::register_needs_boot(),
        fx::boot_current(),
    ]));
    let patch = Arc::new(FakePatchBackend::new());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with(&h, transport.clone(), patch.clone(), launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;

    assert_eq!(
        errors(&events).len(),
        1,
        "a boot demand the boot server will not satisfy is an error"
    );
    assert!(patch.installed_repos().is_empty());
    assert_eq!(launch.launch_count(), 0);
}

#[tokio::test]
async fn install_from_nothing_reaches_launch() {
    // An empty target directory: no boot EXEs, no `.ver` files.
    let empty = TempDir::new().unwrap();
    let path = empty.path().to_path_buf();
    let h = harness_customized(false, move |p| p.game_path = path);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        // Boot is brought up first (from the sentinel), so the game report can hash its EXEs.
        fx::boot_patchlist(&[&fx::synthetic_boot_entry(4_096, "2024.02.01.0000.0000")]),
        fx::register_with_patches(
            UNIQUE_ID,
            &[&game_entry(
                5_000,
                "2024.03.28.0000.0000",
                "http://patch-dl.example.invalid/game/4e9a232b/D2024.03.28.0000.0000.patch",
            )],
        ),
        fx::register_current(UNIQUE_ID),
    ]));
    let patch = Arc::new(FakePatchBackend::new());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with(&h, transport.clone(), patch.clone(), launch, NOW);

    let events = run(ctx, install_cmd(h.profile)).await;

    assert!(
        errors(&events).is_empty(),
        "install-from-nothing should reach launch: {:?}",
        errors(&events)
    );
    assert_eq!(
        states(&events),
        [
            FlowState::Patching,
            FlowState::PreparingPrefix,
            FlowState::Launching,
            FlowState::Running,
            FlowState::Exited
        ]
    );
    // Boot brought up before the base game.
    assert_eq!(patch.installed_repos(), [Repo::Boot, Repo::Game]);
    // The previously-empty directory now carries the materialized version files.
    assert!(empty.path().join("boot/ffxivboot.ver").is_file());
    assert!(empty.path().join("game/ffxivgame.ver").is_file());
}

#[tokio::test]
async fn patch_applies_pending_without_launching() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top("S"),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::boot_current(),
        fx::register_with_patches(
            UNIQUE_ID,
            &[&game_entry(
                1_000,
                "2024.03.28.0001.0000",
                "http://patch-dl.example.invalid/game/4e9a232b/D2024.03.28.0001.0000.patch",
            )],
        ),
        fx::register_current(UNIQUE_ID),
    ]));
    let patch = Arc::new(FakePatchBackend::new());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with(&h, transport.clone(), patch.clone(), launch.clone(), NOW);

    let events = run(ctx, patch_cmd(h.profile)).await;

    assert!(errors(&events).is_empty());
    assert_eq!(
        states(&events),
        [FlowState::Patching],
        "patch applies pending but never launches"
    );
    assert_eq!(patch.installed_repos(), [Repo::Game]);
    assert_eq!(launch.launch_count(), 0, "patch does not launch");
}

/// Ctrl-C during a patch. Patching is the longest stretch of a real run, so it is the phase a user is
/// most likely to stop, and the patcher spells the stop in its own taxonomy. Read as anything but a
/// cancellation it becomes an error on the stream and a non-zero exit, which tells a user who stopped
/// the download themselves that their install is broken.
#[tokio::test]
async fn stopping_a_patch_is_narrated_rather_than_failed() {
    let h = harness(false);
    let transport = Arc::new(FixtureTransport::new(login_then_patch()));
    let patch = Arc::new(FakePatchBackend::new().cancelling());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with(&h, transport, patch.clone(), launch.clone(), NOW);

    let events = run(ctx, patch_cmd(h.profile)).await;

    assert_eq!(
        patch.installs().len(),
        1,
        "the run has to have reached the patcher for this to be the path under test"
    );
    assert!(
        errors(&events).is_empty(),
        "a patch the user stopped is not a failure: {:?}",
        errors(&events)
    );
    assert_eq!(states(&events), [FlowState::Patching, FlowState::Cancelled]);
    assert_eq!(launch.launch_count(), 0);
}

#[tokio::test]
async fn repair_plans_every_installed_repo_and_streams_progress() {
    let h = harness(false); // the install carries boot, game, and ex1..ex4
    let transport = Arc::new(FixtureTransport::new([]));
    let patch = Arc::new(FakePatchBackend::new());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with(&h, transport.clone(), patch.clone(), launch, NOW);

    let events = run(ctx, Command::Repair { profile: h.profile }).await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert_eq!(states(&events), [FlowState::Repairing]);
    assert_eq!(transport.recorded().len(), 0, "repair does not log in");

    let plans = patch.repairs();
    assert_eq!(plans.len(), 1);
    let repos: Vec<Repo> = plans[0].repos.iter().map(|r| r.repo).collect();
    assert_eq!(
        repos,
        [
            Repo::Boot,
            Repo::Game,
            Repo::Expansion(1),
            Repo::Expansion(2),
            Repo::Expansion(3),
            Repo::Expansion(4),
        ]
    );
    let frames = patch_frames(&events);
    assert_eq!(
        frames
            .iter()
            .filter(|p| matches!(p, PatchProgress::Verifying { .. }))
            .count(),
        6
    );
    assert!(frames.iter().any(|p| matches!(
        p,
        PatchProgress::Repaired {
            repo: Repo::Boot,
            ..
        }
    )));
}

#[tokio::test]
async fn repair_of_an_empty_install_is_a_typed_error() {
    let empty = TempDir::new().unwrap();
    let path = empty.path().to_path_buf();
    let h = harness_customized(false, move |p| p.game_path = path);
    let transport = Arc::new(FixtureTransport::new([]));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch, NOW);

    let events = run(ctx, Command::Repair { profile: h.profile }).await;
    assert!(states(&events).is_empty());
    assert_eq!(errors(&events).len(), 1, "nothing installed to verify");
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

/// The toggle is the whole of the opt-in. What the seam is handed decides whether the distribution is
/// contacted at all, so a profile that leaves it off must not even ask for it: nothing downstream
/// re-checks the setting, and a launch that asked would have already made the request.
#[tokio::test]
async fn a_profile_with_dalamud_off_never_asks_for_it() {
    let h = harness(false);
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        Arc::new(FixtureTransport::new(play_then_current())),
        Arc::new(FakePatchBackend::new()),
        Arc::new(FakeLaunchBackend::exiting()),
        addons.clone(),
        NOW,
    );

    run(ctx, play_no_otp(h.profile)).await;

    assert!(
        addons.calls().contains(&AddonCall::Prepared {
            prefix: false,
            dalamud: false,
        }),
        "the launch asked for an injectable nobody enabled: {:?}",
        addons.calls()
    );
}

/// And with it on, the launch says so. The prefix is still prepared either way: the setup the catalog
/// publishes is hygiene, not something the toggle gates.
#[tokio::test]
async fn a_profile_with_dalamud_on_asks_for_it_on_every_launch() {
    let h = harness_customized(false, |profile| profile.launch.dalamud = true);
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        Arc::new(FixtureTransport::new(play_then_current())),
        Arc::new(FakePatchBackend::new()),
        Arc::new(FakeLaunchBackend::exiting()),
        addons.clone(),
        NOW,
    );

    run(ctx, play_no_otp(h.profile)).await;

    assert!(
        addons.calls().contains(&AddonCall::Prepared {
            prefix: false,
            dalamud: true,
        }),
        "{:?}",
        addons.calls()
    );
}

/// The prefix is brought up to date before the game is spawned, not after. A launch that started the
/// game first would apply its own hygiene to a prefix the game was already running in.
#[tokio::test]
async fn the_prefix_is_prepared_before_the_game_is_spawned() {
    let h = harness(false);
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        Arc::new(FixtureTransport::new(play_then_current())),
        Arc::new(FakePatchBackend::new()),
        launch.clone(),
        addons.clone(),
        NOW,
    );

    run(ctx, play_no_otp(h.profile)).await;

    let profile = h.store.load_profile(h.profile).unwrap();
    assert_eq!(
        launch.prepared(),
        [h.prefixes.path().join(super::prefix_name(&profile))],
        "the launch prepared the profile's own prefix"
    );
    assert_eq!(
        addons.calls().first(),
        Some(&AddonCall::Prepared {
            prefix: false,
            dalamud: false,
        }),
        "the setup pass is the first thing the seam is asked for: {:?}",
        addons.calls()
    );
}

/// What an injectable composes onto the plan is what gets spawned. Without this the whole seam could be
/// wired up and its result quietly dropped between the flow and the runner.
#[tokio::test]
async fn what_an_injectable_composes_reaches_the_spawn() {
    let h = harness_customized(false, |profile| profile.launch.dalamud = true);
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let addons = Arc::new(FakeAddons::new().inserting("--mode=inject"));
    let ctx = context_with_addons(
        &h,
        Arc::new(FixtureTransport::new(play_then_current())),
        Arc::new(FakePatchBackend::new()),
        launch.clone(),
        addons,
        NOW,
    );

    run(ctx, play_no_otp(h.profile)).await;

    let plan = launch.last_plan().expect("a launch happened");
    assert_eq!(plan.inserted_args(), ["--mode=inject".to_owned()]);
    assert!(
        plan.args().starts_with("//**sqex0003"),
        "the game's own argument string is still there and still last"
    );
}

/// Ctrl-C while the prefix is being created. Preparing it is the longest part of a first launch, so it
/// is the phase a user is most likely to stop, and the runner reports it as a setup step that did not
/// finish rather than as a stopped download. Read as a failure, the one thing a user does deliberately
/// ends in a non-zero exit.
#[tokio::test]
async fn stopping_a_prefix_while_it_is_being_created_is_narrated_rather_than_failed() {
    let h = harness(false);
    let launch = Arc::new(FakeLaunchBackend::cancelled_while_preparing());
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        Arc::new(FixtureTransport::new(play_then_current())),
        Arc::new(FakePatchBackend::new()),
        launch.clone(),
        addons.clone(),
        NOW,
    );

    let events = run(ctx, play_no_otp(h.profile)).await;

    assert_eq!(
        launch.prepared().len(),
        1,
        "the run has to have reached prefix preparation for this to be the path under test"
    );
    assert!(
        errors(&events).is_empty(),
        "a prefix the user stopped is not a failure: {:?}",
        errors(&events)
    );
    assert_eq!(
        states(&events),
        [FlowState::PreparingPrefix, FlowState::Cancelled]
    );
    // Nothing was spawned and nothing was set up: there is no prefix to do either in.
    assert_eq!(launch.launch_count(), 0);
    assert!(addons.calls().is_empty(), "{:?}", addons.calls());
}
