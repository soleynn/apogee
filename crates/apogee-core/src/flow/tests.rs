//! Headless flow tests: every login branch driven against the fixture transport and a fake launch
//! backend, plus the session-cache fast path. No network, no real process.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use apogee_otp::{ClockSkew, Otp, OtpSource, TotpParams};
use apogee_secrets::{MemoryStore, Secret, SecretKind, SecretStore};
use apogee_test_support::login_fixtures as fx;
use apogee_test_support::sandbox::build_game_install;
use apogee_test_support::transport::FixtureTransport;
use sqex_proto::{ProtoResponse, Transport};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use apogee_patcher::{PatchProgress, Repo};

use super::{FlowContext, client_context, drive, language_id, launch_arguments, read_repo_ver};
use crate::addons::AddonBackend;
use crate::addons::fake::{AddonCall, FakeAddons};
use crate::command::{Command, Event, FlowState, Notice, PrefixAction};
use crate::host;
use crate::launch::LaunchBackend;
use crate::launch::fake::FakeLaunchBackend;
use crate::model::{
    Account, AccountKind, ListenerSettings, ListenerSources, Profile, STEAM_APP_ID, SecretBackend,
    Settings,
};
use crate::patch::PatchBackend;
use crate::patch::fake::FakePatchBackend;
use crate::steam::fake::FakeSteam;
use crate::steam::{NoSteam, SteamBackend};
use crate::store::{Store, UidCacheEntry};
use apogee_addons::{ExternalAddon, RunIn, Trigger};

use fx::{BOOT_VERSION, GAME_VERSION, SESSION_ID, STEAM_LINKED_ID, UNIQUE_ID};

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

/// Like [`harness`], but the account is licensed some way other than a standard one.
fn harness_account(kind: AccountKind) -> Harness {
    harness_full(false, kind, |_| {})
}

/// Like [`harness`], but the profile can be customized (runner, launch env/wrappers, prefix) before
/// it is saved.
fn harness_customized(use_otp: bool, customize: impl FnOnce(&mut Profile)) -> Harness {
    harness_full(use_otp, AccountKind::Standard, customize)
}

fn harness_full(use_otp: bool, kind: AccountKind, customize: impl FnOnce(&mut Profile)) -> Harness {
    let game = game_install();
    let store_dir = TempDir::new().unwrap();
    let prefixes = TempDir::new().unwrap();
    let backups = TempDir::new().unwrap();
    let store = Store::new(store_dir.path().to_path_buf());

    let account = Account {
        use_otp,
        ..Account::new("testuser", kind)
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
    context_with_steam(h, transport, patch, launch, addons, Arc::new(NoSteam), now)
}

/// Like [`context_with_addons`], but with an explicit ticket source. A build wires the refusing one;
/// a test that drives a Steam login substitutes a fake.
fn context_with_steam(
    h: &Harness,
    transport: Arc<dyn Transport>,
    patch: Arc<dyn PatchBackend>,
    launch: Arc<dyn LaunchBackend>,
    addons: Arc<dyn AddonBackend>,
    steam: Arc<dyn SteamBackend>,
    now: u64,
) -> FlowContext {
    context_with_otp(
        h,
        transport,
        patch,
        launch,
        addons,
        steam,
        Otp::new(Arc::new(MemoryStore::new())),
        now,
    )
}

/// Like [`context_with_steam`], but over a caller-built one-time-password handle, so a test can seed
/// the store it reads from before the flow runs.
#[allow(clippy::too_many_arguments)]
fn context_with_otp(
    h: &Harness,
    transport: Arc<dyn Transport>,
    patch: Arc<dyn PatchBackend>,
    launch: Arc<dyn LaunchBackend>,
    addons: Arc<dyn AddonBackend>,
    steam: Arc<dyn SteamBackend>,
    otp: Otp,
    now: u64,
) -> FlowContext {
    FlowContext {
        transport,
        patch,
        launch,
        addons,
        steam,
        otp,
        store: h.store.clone(),
        clock: Arc::new(move || now),
        computer_id: host::computer_id(&h.store),
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
fn health_reports(events: &[Event]) -> Vec<crate::command::PrefixReport> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Prefix(report) => Some(report.clone()),
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
        otp: OtpSource::Manual(Secret::new(Vec::new())),
    }
}

/// An install-from-nothing command.
fn install_cmd(profile: Uuid) -> Command {
    Command::Install {
        profile,
        password: secret("pw"),
        otp: OtpSource::Manual(Secret::new(Vec::new())),
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
        otp: OtpSource::Manual(Secret::new(Vec::new())),
    }
}

/// A no-OTP play command for `profile`.
fn play_no_otp(profile: Uuid) -> Command {
    Command::PatchAndPlay {
        profile,
        password: secret("pw"),
        otp: OtpSource::Manual(Secret::new(Vec::new())),
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

/// The base32 secret these tests derive codes from: the example key from the format's own
/// documentation, doubled to reach the length a key has to be. Synthetic, and never a real one.
fn totp_seed() -> &'static str {
    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
}

/// A one-time-password handle over an in-memory store already holding `account`'s secret, so a login
/// derives a code with no keyring anywhere near it.
fn otp_with_secret(account: Uuid) -> Otp {
    let store = MemoryStore::new();
    let params = TotpParams::parse(totp_seed()).unwrap();
    store
        .set(account, SecretKind::TotpSecret, params.into_secret())
        .unwrap();
    Otp::new(Arc::new(store))
}

/// A one-time-password handle over an empty store.
///
/// A login that takes its code from the listener never reads the store at all, so an empty one is
/// what the arrangement under test actually has: if the flow ever reached for a secret here, it would
/// find nothing and the test would say so.
fn otp_empty() -> Otp {
    Otp::new(Arc::new(MemoryStore::new()))
}

/// A context over the usual fakes, with the caller's one-time-password handle.
fn context_otp(h: &Harness, transport: Arc<dyn Transport>, otp: Otp, now: u64) -> FlowContext {
    context_with_otp(
        h,
        transport,
        Arc::new(FakePatchBackend::new()),
        Arc::new(FakeLaunchBackend::exiting()),
        Arc::new(FakeAddons::new()),
        Arc::new(NoSteam),
        otp,
        now,
    )
}

/// The one-time-password field of the recorded OAuth submit, which is the third request of a login.
fn submitted_otp(transport: &FixtureTransport) -> Option<String> {
    let recorded = transport.recorded();
    let body = recorded.get(2)?.body.as_ref()?.as_bytes().to_vec();
    String::from_utf8_lossy(&body)
        .split('&')
        .find_map(|field| field.strip_prefix("otppw=").map(str::to_owned))
}

/// The zero-interaction case: an account set to generate logs in from what is stored, with nothing
/// asked for and nothing typed.
#[tokio::test]
async fn a_stored_secret_logs_in_without_asking_for_a_code() {
    let h = harness(true);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp_with_secret(h.account), NOW);

    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Totp,
        },
    )
    .await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert!(
        !states(&events).contains(&FlowState::NeedsOtp),
        "a stored secret was still asked about: {:?}",
        states(&events)
    );
    let sent = submitted_otp(&transport).expect("a generated code was submitted");
    assert_eq!(sent.len(), 6, "{sent}");
    assert!(sent.bytes().all(|b| b.is_ascii_digit()), "{sent}");
    // The digits themselves, not just their shape. The scripted page's clock is a constant this host
    // does not share, so a login that derived against its own clock, or against the offset with its
    // sign inverted, sends six perfectly well-formed digits that are not these.
    assert_eq!(sent, code_for_the_scripted_clock());
    assert_eq!(
        h.store
            .load_uid_cache(h.account)
            .unwrap()
            .unwrap()
            .unique_id,
        UNIQUE_ID
    );
}

/// The code a login through the scripted top page will derive, for the window that page's clock
/// falls in.
///
/// The tests below can name it exactly because the correction is an offset rather than a pinned
/// instant: the flow measures the page's clock against this host's, then the mint reads this host's
/// clock again, so the two readings cancel and what is left is the page's own. The page's clock is
/// [`fx::SERVER_UNIX_SECS`], which starts a window, so the whole of one has to elapse inside the run
/// before the counter moves.
fn code_for_the_scripted_clock() -> String {
    let params = TotpParams::parse(totp_seed()).unwrap();
    params
        .code(fx::server_time(), ClockSkew::NONE)
        .unwrap()
        .expose()
        .to_owned()
}

/// How long a run said it was holding for, if it said so at all.
fn otp_hold(events: &[Event]) -> Option<u64> {
    states(events).into_iter().find_map(|state| match state {
        FlowState::WaitingForOtpWindow { seconds } => Some(seconds),
        _ => None,
    })
}

/// A code the login server has already seen is not sent a second time. The flow says how long it is
/// holding for, holds for exactly that long, and then sends the next window's code, which is what
/// the guard exists to produce.
///
/// Virtual time, so the wait costs the suite nothing and the clock the assertion reads is the one
/// the sleep ran on. The seeded record is what a login that had just happened would have left
/// behind, and it is seeded for the window the scripted page's clock falls in, because that is the
/// clock the flow derives against.
#[tokio::test(start_paused = true)]
async fn a_code_the_server_has_seen_is_not_sent_again() {
    let h = harness(true);
    let otp = otp_with_secret(h.account);
    let params = TotpParams::parse(totp_seed()).unwrap();
    let already = params.code(fx::server_time(), ClockSkew::NONE).unwrap();
    let repeat = already.expose().to_owned();
    otp.submitted(h.account, &already);

    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp, NOW);

    let started = tokio::time::Instant::now();
    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Totp,
        },
    )
    .await;
    let elapsed = started.elapsed();

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    // The page's clock starts a window and the guard steps over one window at a time, so the hold is
    // what is left of the window that clock opened. Not pinned to the whole thirty: the two clock
    // readings the correction is made of cancel only to the second, and whatever real time passes
    // between them comes off the hold. What has to be exact is that the run waited out the wait it
    // announced, which is the property a shell's progress bar rests on.
    let waited = otp_hold(&events).expect("the flow should have said it was holding");
    assert!((1..=30).contains(&waited), "held for {waited} seconds");
    assert_eq!(
        elapsed.as_secs(),
        waited,
        "the run narrated a {waited}s hold and took {elapsed:?}"
    );
    let sent = submitted_otp(&transport).expect("a generated code was submitted");
    assert_ne!(
        sent, repeat,
        "the code the server already saw was sent again"
    );
    let next = params
        .code(fx::server_time() + Duration::from_secs(30), ClockSkew::NONE)
        .unwrap();
    assert_eq!(
        sent,
        next.expose(),
        "the hold ended on something other than the next window's code"
    );
}

/// A second login in the same window does not send the same code again.
///
/// The guard only works if the flow records what it put on the wire, and the record is written by
/// the login rather than by the mint: a code that reached the server has been seen whether or not
/// the login succeeded. Two runs through one handle, which is what the composition root hands every
/// login of a session.
#[tokio::test(start_paused = true)]
async fn a_second_login_in_one_window_sends_a_different_code() {
    let h = harness(true);
    let otp = otp_with_secret(h.account);

    let first_transport = Arc::new(FixtureTransport::new(login_then_current()));
    let events = run(
        context_otp(&h, first_transport.clone(), otp.clone(), NOW),
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Totp,
        },
    )
    .await;
    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert!(otp_hold(&events).is_none(), "the first login held");
    let first = submitted_otp(&first_transport).expect("a generated code was submitted");

    let second_transport = Arc::new(FixtureTransport::new(login_then_current()));
    let events = run(
        context_otp(&h, second_transport.clone(), otp, NOW),
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Totp,
        },
    )
    .await;
    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    let second = submitted_otp(&second_transport).expect("a generated code was submitted");

    assert_ne!(
        first, second,
        "the code the first login sent was sent again, so nothing recorded it"
    );
    assert!(
        otp_hold(&events).is_some(),
        "the second login sent a different code without saying it had held"
    );
}

/// A run stopped while it holds for the next window stops there.
///
/// The hold is the only wall-clock wait in a login and the one moment a shell tells a user to sit
/// still, so it is the moment cancel gets pressed. Ignoring the token there would spend the whole
/// hold, log in anyway, and cache a session for a run that was stopped.
#[tokio::test(start_paused = true)]
async fn a_run_stopped_while_it_holds_never_logs_in() {
    let h = harness(true);
    let otp = otp_with_secret(h.account);
    let params = TotpParams::parse(totp_seed()).unwrap();
    let already = params.code(fx::server_time(), ClockSkew::NONE).unwrap();
    otp.submitted(h.account, &already);

    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp, NOW);

    let cancel = CancellationToken::new();
    cancel.cancel();
    let events = run_with_cancel(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Totp,
        },
        cancel,
    )
    .await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert!(
        states(&events).contains(&FlowState::Cancelled),
        "{:?}",
        states(&events)
    );
    // The login server's own clock decides which window to hold for, so a login has asked for the
    // top page by the time it knows it is holding at all. What it must not have done is submit: the
    // two recorded requests are the service check and that page, and nothing followed them.
    assert_eq!(
        transport.recorded().len(),
        2,
        "a stopped run submitted credentials"
    );
    assert!(h.store.load_uid_cache(h.account).unwrap().is_none());
}

/// The advisories a run raised, in order.
fn notices(events: &[Event]) -> Vec<Notice> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Notice(notice) => Some(*notice),
            _ => None,
        })
        .collect()
}

/// A clock a login server would have if this host's were badly wrong in the other direction.
///
/// A constant rather than an offset from the wall clock, for the reason [`fx::SERVER_UNIX_SECS`] is
/// one: what a login derives for collapses onto whatever the page said, so a constant there makes
/// the code a constant here. The pair covers both signs, since the scripted page's own clock is
/// already behind any host running this.
///
/// Mid-window rather than on a boundary, which the sibling can afford to be and this cannot. The
/// offset is measured by truncation, so a server ahead of this host is read as a second less ahead
/// than it is, and the instant derived for is the second before the one named. On a boundary that
/// second belongs to the previous window, whose last second is inside the freshness floor, so the
/// mint steps forward and lands back on the right window for the wrong reason: the test would pass
/// while measuring nothing, and go red the day that floor changed. Fifteen seconds in, the second
/// before is the same window and the equality holds on its own.
const SERVER_AHEAD_UNIX: u64 = 2_082_758_415;

/// The codes this host's own clock could produce for a run that began at `started`.
///
/// Two of them because a window may have turned over inside the run. Both are this host's rather than
/// the login server's, which is the whole of what an uncorrected login is being checked for, and the
/// scripted clock's code is neither.
fn local_codes(started: SystemTime) -> Vec<String> {
    let params = TotpParams::parse(totp_seed()).unwrap();
    [started, SystemTime::now()]
        .into_iter()
        .map(|at| {
            params
                .code(at, ClockSkew::NONE)
                .unwrap()
                .expose()
                .to_owned()
        })
        .collect()
}

/// A login through a page whose clock is scripted, and the code it derived.
async fn login_against(h: &Harness, top: ProtoResponse) -> (Vec<Event>, Option<String>) {
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        top,
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::register_current(UNIQUE_ID),
    ]));
    let ctx = context_otp(h, transport.clone(), otp_with_secret(h.account), NOW);
    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Totp,
        },
    )
    .await;
    let sent = submitted_otp(&transport);
    (events, sent)
}

/// The acceptance case: a host whose clock is far enough out that its own codes would be refused
/// still logs in, because the code went out for the window the login server is in, and the user is
/// told which of the two clocks is wrong.
///
/// The offset is named from the server's side (it is ahead), so an implementation that measured
/// `local - server` sends the code for an instant the same distance the other way and fails the
/// equality below. That inversion is the sharpest trap here: both directions produce six well-formed
/// digits and nothing else in the workspace would catch it.
#[tokio::test]
async fn a_host_whose_clock_is_wrong_logs_in_against_the_servers_and_is_told() {
    let h = harness(true);
    let ahead = SystemTime::UNIX_EPOCH + Duration::from_secs(SERVER_AHEAD_UNIX);
    let (events, sent) = login_against(&h, fx::oauth_top_at("STOREDBLOB", ahead)).await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    let params = TotpParams::parse(totp_seed()).unwrap();
    assert_eq!(
        sent.as_deref(),
        Some(params.code(ahead, ClockSkew::NONE).unwrap().expose()),
        "the code was not derived against the login server's clock"
    );
    match notices(&events).as_slice() {
        [Notice::ClockSkew { seconds }] => assert!(
            *seconds > ClockSkew::ADVISORY_SECONDS,
            "the notice named {seconds}s, which is not a drift worth raising"
        ),
        other => panic!("expected one clock notice, got {other:?}"),
    }
    assert!(h.store.load_uid_cache(h.account).unwrap().is_some());
}

/// The other direction. Separate from the case above rather than folded into it, because a sign
/// dropped somewhere between the header and the counter still passes a test that only ever measures
/// one way.
#[tokio::test]
async fn a_server_clock_behind_this_host_reads_as_a_negative_offset() {
    let h = harness(true);
    let behind = fx::server_time();
    let (events, sent) = login_against(&h, fx::oauth_top_at("STOREDBLOB", behind)).await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    let params = TotpParams::parse(totp_seed()).unwrap();
    assert_eq!(
        sent.as_deref(),
        Some(params.code(behind, ClockSkew::NONE).unwrap().expose())
    );
    match notices(&events).as_slice() {
        [Notice::ClockSkew { seconds }] => assert!(
            *seconds < -ClockSkew::ADVISORY_SECONDS,
            "a server behind this host was reported as {seconds}s"
        ),
        other => panic!("expected one clock notice, got {other:?}"),
    }
}

/// A clock that agrees is not worth a sentence. Without this the notice is indistinguishable from
/// one raised on every login, which is the version a user learns to ignore.
#[tokio::test]
async fn a_clock_that_agrees_with_the_login_server_is_not_mentioned() {
    let h = harness(true);
    let started = SystemTime::now();
    let (events, sent) = login_against(&h, fx::oauth_top_at("STOREDBLOB", started)).await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert_eq!(notices(&events), Vec::new());
    let sent = sent.expect("a generated code was submitted");
    assert!(
        local_codes(started).contains(&sent),
        "a login against an agreeing clock sent a code for another window"
    );
}

/// A page that carries no clock at all costs the correction and not the login: the code goes out for
/// this host's own window, which is what every login did before there was anything to correct
/// against, and nothing is said because nothing was measured.
#[tokio::test]
async fn a_login_page_with_no_clock_still_logs_in_against_this_host() {
    let h = harness(true);
    let started = SystemTime::now();
    let (events, sent) = login_against(&h, fx::oauth_top_undated("STOREDBLOB")).await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert_eq!(notices(&events), Vec::new());
    let sent = sent.expect("a generated code was submitted");
    assert!(local_codes(started).contains(&sent));
    assert!(h.store.load_uid_cache(h.account).unwrap().is_some());
}

/// A stamp in a shape the reader does not take answers the same way an absent one does. The reader
/// refuses the two obsolete forms, so this is the shape a real server would have to send to reach
/// that path, and the login has to survive it.
#[tokio::test]
async fn a_clock_stamped_in_a_form_that_cannot_be_read_is_not_a_correction() {
    let h = harness(true);
    let started = SystemTime::now();
    let (events, sent) = login_against(
        &h,
        fx::oauth_top_stamped("STOREDBLOB", "Wednesday, 09-Jul-25 12:00:00 GMT"),
    )
    .await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert_eq!(notices(&events), Vec::new());
    let sent = sent.expect("a generated code was submitted");
    assert!(local_codes(started).contains(&sent));
}

/// A typed code came off a device with a clock of its own, so this host's disagreement with the
/// login server says nothing about it and is not raised. The login is otherwise a skewed one.
#[tokio::test]
async fn a_typed_code_is_sent_untouched_and_raises_nothing() {
    let h = harness(true);
    let transport = Arc::new(FixtureTransport::new([
        fx::login_status_open(),
        fx::oauth_top_at("STOREDBLOB", fx::server_time() + Duration::from_secs(3_600)),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::register_current(UNIQUE_ID),
    ]));
    let ctx = context_otp(&h, transport.clone(), otp_with_secret(h.account), NOW);

    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Manual(Secret::new(b"424242".to_vec())),
        },
    )
    .await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert_eq!(notices(&events), Vec::new());
    assert_eq!(submitted_otp(&transport).as_deref(), Some("424242"));
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
            otp: OtpSource::Manual(Secret::from_string("123456".to_owned())),
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
            otp: OtpSource::Manual(Secret::new(Vec::new())),
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
            otp: OtpSource::Manual(Secret::new(Vec::new())),
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
    assert_eq!(health_reports(&events)[0].health.issues.len(), 1);
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
        residual[0].health.issues.len(),
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

/// Preparing a prefix ahead of time has to leave it where a launch would leave it. Bringing up the
/// runner is only half of that: what the signed catalog publishes is the other half, and a prefix
/// that has one without the other is a state no launch ever produces, waiting to be finished off by
/// the first launch that was supposed to have nothing left to do.
#[rstest::rstest]
#[case(PrefixAction::Create)]
#[case(PrefixAction::Recreate)]
#[tokio::test]
async fn a_prefix_built_on_its_own_gets_the_setup_a_launch_would_apply(
    #[case] action: PrefixAction,
) {
    let h = harness(false);
    let addons = Arc::new(FakeAddons::new());
    let ctx = context_with_addons(
        &h,
        Arc::new(FixtureTransport::new(vec![])),
        Arc::new(FakePatchBackend::new()),
        Arc::new(FakeLaunchBackend::exiting()),
        addons.clone(),
        NOW,
    );

    run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action,
        },
    )
    .await;

    assert!(
        addons
            .calls()
            .iter()
            .any(|call| matches!(call, AddonCall::SetupApplied { .. })),
        "the catalog's setup was never applied: {:?}",
        addons.calls()
    );
}

/// A prefix examined against a catalog it has none of, so the check has both halves to report and the
/// fix has something to apply.
fn missing_setup_context(
    h: &Harness,
    addons: Arc<FakeAddons>,
    launch: Arc<FakeLaunchBackend>,
) -> FlowContext {
    context_with_addons(
        h,
        Arc::new(FixtureTransport::new(vec![])),
        Arc::new(FakePatchBackend::new()),
        launch,
        addons,
        NOW,
    )
}

/// A prefix intact in every way the runtime can see, missing every verb the catalog publishes. The
/// bug this is here for: the runtime's half is the only half that used to be reported, so a prefix
/// with none of its setup came back as nothing wrong.
#[tokio::test]
async fn a_prefix_missing_the_published_setup_is_not_reported_as_healthy() {
    let h = harness(false);
    let intact = apogee_runtime::PrefixHealth::default();
    let addons = Arc::new(FakeAddons::new().missing_setup(&["no-desktop-integration"], &[]));
    let ctx = missing_setup_context(
        &h,
        addons,
        Arc::new(FakeLaunchBackend::exiting().with_health(intact.clone(), intact)),
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Check,
        },
    )
    .await;

    let report = &health_reports(&events)[0];
    assert!(report.health.is_healthy(), "nothing structural is wrong");
    assert_eq!(
        report.missing_setup.as_deref(),
        Some(["no-desktop-integration".to_owned()].as_slice())
    );
    assert!(
        !report.nothing_wrong(),
        "a prefix with none of its setup is not a prefix with nothing wrong"
    );
}

/// A catalog nobody could read is a question left open, not an answer of "none". Reporting the
/// unanswered half as an empty one is the same bug in a smaller place: a check that could not look
/// coming back as a clean bill.
#[tokio::test]
async fn a_catalog_that_could_not_be_read_is_not_a_clean_bill() {
    let h = harness(false);
    let intact = apogee_runtime::PrefixHealth::default();
    let ctx = missing_setup_context(
        &h,
        Arc::new(FakeAddons::new().without_a_catalog()),
        Arc::new(FakeLaunchBackend::exiting().with_health(intact.clone(), intact)),
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Check,
        },
    )
    .await;

    let report = &health_reports(&events)[0];
    assert!(report.missing_setup.is_none());
    assert!(!report.nothing_wrong());
}

/// A check answers the question about the prefix as it is. Applying setup while reporting what is
/// missing would change what is being reported, and the answer would be about a prefix that no longer
/// exists by the time the user reads it.
#[tokio::test]
async fn examining_a_prefix_applies_no_setup() {
    let h = harness(false);
    let intact = apogee_runtime::PrefixHealth::default();
    let addons = Arc::new(FakeAddons::new().missing_setup(&["no-desktop-integration"], &[]));
    let ctx = missing_setup_context(
        &h,
        addons.clone(),
        Arc::new(FakeLaunchBackend::exiting().with_health(intact.clone(), intact)),
    );

    run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Check,
        },
    )
    .await;

    assert_eq!(
        addons.calls(),
        [AddonCall::SetupExamined { prefix: false }],
        "a question about a prefix changed it"
    );
}

/// The fix applies what the check reports. A problem named by one command and untouched by the one
/// that exists to resolve it is a report a user cannot act on, and the setup half was exactly that
/// until the check started naming it.
#[tokio::test]
async fn fixing_a_prefix_applies_the_setup_the_check_reports_missing() {
    let h = harness(false);
    let intact = apogee_runtime::PrefixHealth::default();
    // One verb applies, the other cannot: what a fix could not resolve is still in front of the user.
    let addons = Arc::new(FakeAddons::new().missing_setup(&["applies", "cannot"], &["cannot"]));
    let ctx = missing_setup_context(
        &h,
        addons.clone(),
        Arc::new(FakeLaunchBackend::exiting().with_health(intact.clone(), intact)),
    );

    let events = run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action: PrefixAction::Fix,
        },
    )
    .await;

    assert_eq!(
        addons.calls(),
        [AddonCall::SetupApplied { prefix: false }],
        "the fix did not apply the setup the check names"
    );
    let report = &health_reports(&events)[0];
    assert_eq!(
        report.missing_setup.as_deref(),
        Some(["cannot".to_owned()].as_slice()),
        "what the fix could not apply is still reported"
    );
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

/// What a profile chose about the `dxvk-nvapi` companion reaches the prefix that would install it.
///
/// The opt-in has no other route. What decided it before was the prefix's own record, and the only
/// thing that writes that record is the install that reads it, so a prefix built without the
/// companion could never be told to get one and every launch read back the `false` the last one
/// wrote. The assertion is on what crossed the launch seam because that is the last point in this
/// crate where the setting is still visible.
#[rstest::rstest]
#[case(false)]
#[case(true)]
#[tokio::test]
async fn a_launch_asks_its_prefix_for_the_companion_the_profile_chose(#[case] nvapi: bool) {
    let h = harness_customized(false, |profile| profile.launch.nvapi = nvapi);
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(&h, transport, launch.clone(), NOW);

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(states(&events).last(), Some(&FlowState::Exited));

    let asked: Vec<bool> = launch.requested().iter().map(|r| r.nvapi).collect();
    assert_eq!(
        asked,
        [nvapi],
        "the profile's choice did not reach the prefix"
    );
}

/// Every prefix verb carries it too, not only a launch. Without that, the one command that exists to
/// bring a prefix up to what a launch would leave it is the one command that cannot.
#[rstest::rstest]
#[case(PrefixAction::Create)]
#[case(PrefixAction::Check)]
#[case(PrefixAction::Fix)]
#[case(PrefixAction::Recreate)]
#[tokio::test]
async fn every_prefix_verb_carries_the_companion_the_profile_chose(#[case] action: PrefixAction) {
    let h = harness_customized(false, |profile| profile.launch.nvapi = true);
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new(vec![])),
        launch.clone(),
        NOW,
    );

    run(
        ctx,
        Command::Prefix {
            profile: h.profile,
            action,
        },
    )
    .await;

    let asked: Vec<bool> = launch.requested().iter().map(|r| r.nvapi).collect();
    assert_eq!(asked, [true], "the verb dropped the profile's choice");
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
            secret_backend: SecretBackend::Platform,
            keep_patches: false,
            backups_kept: 5,
            backup_before_patch: false,
            otp_listener: ListenerSettings::default(),
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
            otp_listener: ListenerSettings::default(),
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
                // Nothing redirected this launch, so there is no companion to confirm.
                confirming: false,
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
            secret_backend: SecretBackend::Platform,
            keep_patches: false,
            backups_kept: 5,
            backup_before_patch: false,
            otp_listener: ListenerSettings::default(),
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
            secret_backend: SecretBackend::Platform,
            keep_patches: false,
            backups_kept: 5,
            backup_before_patch: false,
            otp_listener: ListenerSettings::default(),
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

#[test]
fn client_context_pins_the_reference_launchers_seed_zero_accept_language() {
    // `ApiHelpers.GenerateAcceptLanguage()` (ApiHelpers.cs:14-41) is unrelated to the client's
    // configured game language; its one call site (App.xaml.cs:135) always draws seed 0, and
    // .NET's seeded `Random(int)` is stable across .NET versions, so every fresh XIVLauncher
    // install lands on the same value: the bare `"ja"` entry from its `codes` pool.
    let h = harness(false);
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new([])),
        Arc::new(FakeLaunchBackend::exiting()),
        NOW,
    );
    assert_eq!(client_context(&ctx).accept_language, "ja");
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
        launch_arguments(&session, 3, false).build_plain(),
        " DEV.DataPathType=1 DEV.MaxEntitledExpansionID=4 DEV.TestSID=UID-XYZ DEV.UseSqPack=1 \
         SYS.Region=7 language=3 resetConfig=0 ver=2024.03.28.0000.0000"
    );
}

#[test]
fn launch_arguments_append_the_steam_flag_last() {
    let session = UidCacheEntry {
        unique_id: "UID-XYZ".to_string(),
        region: 7,
        max_expansion: 4,
        game_version: "2024.03.28.0000.0000".to_string(),
        expires_at: 0,
    };
    // Appended after the fixed set rather than sorted into it: the reference launcher builds it that
    // way, and the game reads the list in order.
    assert!(
        launch_arguments(&session, 3, true)
            .build_plain()
            .ends_with(" ver=2024.03.28.0000.0000 IsSteam=1")
    );
}

/// A play scenario for a Steam account: the top page names the linked account.
fn steam_play_then_current() -> [ProtoResponse; 5] {
    [
        fx::login_status_open(),
        fx::oauth_top_steam("STOREDBLOB", STEAM_LINKED_ID),
        fx::submit_success(SESSION_ID, REGION, MAX_EXPANSION),
        fx::boot_current(),
        fx::register_current(UNIQUE_ID),
    ]
}

#[tokio::test]
async fn a_steam_account_mints_a_ticket_and_flags_the_launch() {
    const APP_ID: u32 = 39_210;
    let h = harness_account(AccountKind::Steam { app_id: APP_ID });
    let steam = Arc::new(FakeSteam::new());
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let transport = Arc::new(FixtureTransport::new(steam_play_then_current()));
    let ctx = context_with_steam(
        &h,
        transport.clone(),
        Arc::new(FakePatchBackend::new()),
        launch.clone(),
        Arc::new(FakeAddons::new()),
        steam.clone(),
        NOW,
    );

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(errors(&events), Vec::<String>::new());
    assert_eq!(steam.requested(), vec![APP_ID], "ticket minted for the app");

    // The ticket reached the top page, and the login submitted the id the page named rather than the
    // stored spelling of it.
    let recorded = transport.recorded();
    let top = recorded[1].url.as_str();
    assert!(top.contains("&issteam=1&session_ticket="), "top url: {top}");
    assert!(top.contains("&ticket_size="), "top url: {top}");
    assert!(
        top.contains("isft=0"),
        "a paid app is not a free trial: {top}"
    );
    let body = String::from_utf8(recorded[2].body.as_ref().unwrap().as_bytes().to_vec()).unwrap();
    assert!(
        body.contains(&format!("sqexid={STEAM_LINKED_ID}&")),
        "submit body: {body}"
    );

    // Both halves of what the game is told, the argument and the variable set beside it.
    let plan = launch.last_plan().unwrap();
    assert_eq!(
        plan.env()
            .get("IS_FFXIV_LAUNCH_FROM_STEAM")
            .map(String::as_str),
        Some("1")
    );
    assert!(
        decrypt_launch_args(plan.args()).ends_with(" /IsSteam =1"),
        "the launch arguments did not carry the steam flag"
    );
}

#[tokio::test]
async fn a_standard_account_launches_with_neither_steam_flag() {
    let h = harness(false);
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context(
        &h,
        Arc::new(FixtureTransport::new(play_then_current())),
        launch.clone(),
        NOW,
    );

    run(ctx, play_no_otp(h.profile)).await;

    let plan = launch.last_plan().unwrap();
    assert!(!plan.env().contains_key("IS_FFXIV_LAUNCH_FROM_STEAM"));
    assert!(!decrypt_launch_args(plan.args()).contains("IsSteam"));
}

#[tokio::test]
async fn a_free_trial_account_flags_the_top_page_without_a_ticket() {
    let h = harness_account(AccountKind::FreeTrial);
    let steam = Arc::new(FakeSteam::new());
    let transport = Arc::new(FixtureTransport::new(play_then_current()));
    let ctx = context_with_steam(
        &h,
        transport.clone(),
        Arc::new(FakePatchBackend::new()),
        Arc::new(FakeLaunchBackend::exiting()),
        Arc::new(FakeAddons::new()),
        steam.clone(),
        NOW,
    );

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(errors(&events), Vec::<String>::new());

    let recorded = transport.recorded();
    let top = recorded[1].url.as_str();
    assert!(top.contains("isft=1"), "top url: {top}");
    assert!(!top.contains("issteam"), "no ticket without Steam: {top}");
    assert!(steam.requested().is_empty(), "a trial minted no ticket");
}

#[tokio::test]
async fn a_steam_account_with_no_client_reachable_says_so_before_logging_in() {
    let h = harness_account(AccountKind::Steam {
        app_id: STEAM_APP_ID,
    });
    // One response scripted, the service-open gate that precedes a login. The top page is not, so a
    // flow that got as far as asking for one would panic the fixture transport instead of passing.
    let transport = Arc::new(FixtureTransport::new([fx::login_status_open()]));
    let ctx = context(
        &h,
        transport.clone(),
        Arc::new(FakeLaunchBackend::exiting()),
        NOW,
    );

    let events = run(ctx, play_no_otp(h.profile)).await;
    assert_eq!(
        errors(&events),
        vec!["this build cannot obtain a Steam authentication ticket"]
    );
    assert_eq!(transport.recorded().len(), 1, "no login was attempted");
}

#[tokio::test]
async fn a_profile_that_sets_the_steam_variable_itself_keeps_its_value() {
    // The computed entry is an addition to what the profile asked for, not an override of it: the
    // free-form arm outranks anything the launcher decides on the user's behalf.
    let game = game_install();
    let h = harness_full(
        false,
        AccountKind::Steam {
            app_id: STEAM_APP_ID,
        },
        |p| {
            p.game_path = game.path().to_path_buf();
            p.launch
                .extra_env
                .push(("IS_FFXIV_LAUNCH_FROM_STEAM".to_owned(), "0".to_owned()));
        },
    );
    let launch = Arc::new(FakeLaunchBackend::exiting());
    let ctx = context_with_steam(
        &h,
        Arc::new(FixtureTransport::new(steam_play_then_current())),
        Arc::new(FakePatchBackend::new()),
        launch.clone(),
        Arc::new(FakeAddons::new()),
        Arc::new(FakeSteam::new()),
        NOW,
    );

    run(ctx, play_no_otp(h.profile)).await;

    let plan = launch.last_plan().unwrap();
    assert_eq!(
        plan.env()
            .get("IS_FFXIV_LAUNCH_FROM_STEAM")
            .map(String::as_str),
        Some("0")
    );
}

/// The plaintext behind an encrypted launch-argument string.
///
/// The key is the top half of a tick read from the host clock as the launch was built, so no test can
/// know it in advance. It is only sixteen bits wide, though, and the wrapper publishes four of them in
/// its checksum character, so the remaining 4096 are simply tried: the one that decrypts to the `T`
/// argument the builder always leads with is the key. Restating the checksum table here only narrows
/// the search; a table that disagreed with the crate's would slow this down, not mislead it.
fn decrypt_launch_args(encrypted: &str) -> String {
    const CHECKSUM_TABLE: [char; 16] = [
        'f', 'X', '1', 'p', 'G', 't', 'd', 'S', '5', 'C', 'A', 'P', '4', '_', 'V', 'L',
    ];

    let body = encrypted
        .strip_prefix("//**sqex0003")
        .and_then(|s| s.strip_suffix("**//"))
        .expect("not an encrypted argument string");
    let (base64, checksum) = body.split_at(body.len() - 1);
    let nibble = CHECKSUM_TABLE
        .iter()
        .position(|c| checksum.starts_with(*c))
        .expect("checksum character outside the table") as u32;
    let ciphertext = sqex_crypto::sqex_base64::decode(base64).expect("undecodable body");

    for high in 0..0x1000u32 {
        let key = (high << 20) | (nibble << 16);
        let mut hex = [0u8; 8];
        for (i, slot) in hex.iter_mut().enumerate() {
            slot.clone_from(&b"0123456789abcdef"[((key >> (28 - 4 * i)) & 0xF) as usize]);
        }
        let plain = sqex_crypto::LegacyBlowfish::new(&hex).decrypt(&ciphertext);
        if plain.starts_with(b" /T =") {
            return String::from_utf8_lossy(&plain)
                .trim_end_matches('\0')
                .to_string();
        }
    }
    panic!("no key produced the argument plaintext");
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
        addons.clone(),
        NOW,
    );

    run(ctx, play_no_otp(h.profile)).await;

    let plan = launch.last_plan().expect("a launch happened");
    assert_eq!(plan.inserted_args(), ["--mode=inject".to_owned()]);
    assert!(
        plan.args().starts_with("//**sqex0003"),
        "the game's own argument string is still there and still last"
    );
    // The other half of the same seam. What proves the companion came up is the companion layer's
    // answer to composing the launch, so a flow that dropped it would leave every launch unconfirmed
    // with nothing failing.
    assert!(
        addons.calls().iter().any(|call| matches!(
            call,
            AddonCall::Started {
                confirming: true,
                ..
            }
        )),
        "the launch started without the proof to watch for: {:?}",
        addons.calls()
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

// --- a code pushed to the local listener --------------------------------------------------------

/// Point this machine's listener at an ephemeral loopback port.
///
/// Ephemeral because two of these tests run at once under the runner, and the real port is one a
/// developer may well have a launcher sitting on. The port that was actually taken comes back on the
/// waiting state, which is the only reason that state carries it.
fn listen_on_ephemeral(h: &Harness, sources: ListenerSources) {
    let mut settings = h.store.load_settings().unwrap_or_default();
    settings.otp_listener = ListenerSettings {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 0,
        sources,
        wait_seconds: 20,
    };
    h.store.save_settings(&settings).unwrap();
}

/// Start a run and hand back its event stream, so a test can act while the flow is still going.
///
/// [`run`] drains after the fact, which cannot drive a flow that is waiting on the test to do
/// something.
fn spawn_run(
    ctx: FlowContext,
    cmd: Command,
    cancel: CancellationToken,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<Event>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (tokio::spawn(drive(ctx, cmd, tx, cancel)), rx)
}

/// Pull events until one matches, keeping everything seen on the way.
async fn await_state(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    seen: &mut Vec<Event>,
    want: impl Fn(&FlowState) -> bool,
) -> Option<FlowState> {
    while let Some(event) = rx.recv().await {
        let matched = match &event {
            Event::State(state) if want(state) => Some(state.clone()),
            _ => None,
        };
        seen.push(event);
        if matched.is_some() {
            return matched;
        }
    }
    None
}

/// Drain whatever is left once a run has finished.
fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>, seen: &mut Vec<Event>) {
    while let Ok(event) = rx.try_recv() {
        seen.push(event);
    }
}

/// The port a run said it was listening on.
fn listening_port(state: &FlowState) -> Option<u16> {
    match state {
        FlowState::WaitingForPushedCode { port, .. } => Some(*port),
        _ => None,
    }
}

/// Push `bytes` from a chosen loopback address, so a test can be two devices at once.
async fn push_from(from: Ipv4Addr, port: u16, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(std::net::SocketAddr::new(IpAddr::V4(from), 0))?;
    let mut stream = socket.connect((Ipv4Addr::LOCALHOST, port).into()).await?;
    stream.write_all(bytes).await?;
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await?;
    Ok(answer)
}

/// Push `code` at the loopback listener on `port`, the way a companion app would.
async fn push_code(port: u16, code: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    stream
        .write_all(
            format!("GET /ffxivlauncher/{code} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
        )
        .await?;
    stream.flush().await
}

/// A code pushed from the network reaches the submit, and the session is cached.
///
/// The analogue of the typed-code case: nothing is derived, nothing is asked for, and what goes on
/// the wire is exactly what arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_code_reaches_the_submit() {
    let h = harness(true);
    listen_on_ephemeral(&h, ListenerSources::Any);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp_empty(), NOW);

    let (task, mut rx) = spawn_run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Listener,
        },
        CancellationToken::new(),
    );

    let mut events = Vec::new();
    let waiting = await_state(&mut rx, &mut events, |state| {
        matches!(state, FlowState::WaitingForPushedCode { .. })
    })
    .await
    .expect("the flow never opened the listener");
    let port = listening_port(&waiting).expect("the waiting state carried no port");
    push_code(port, "246810").await.unwrap();

    task.await.unwrap();
    drain(&mut rx, &mut events);

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert_eq!(
        submitted_otp(&transport).as_deref(),
        Some("246810"),
        "the pushed code did not reach the submit"
    );
    assert!(
        states(&events).contains(&FlowState::PushedCodeReceived {
            from: IpAddr::V4(Ipv4Addr::LOCALHOST)
        }),
        "the arrival was not narrated: {:?}",
        states(&events)
    );
    assert_eq!(
        h.store
            .load_uid_cache(h.account)
            .unwrap()
            .unwrap()
            .unique_id,
        UNIQUE_ID
    );
}

/// A pushed code raises no clock advisory.
///
/// It was derived on the phone against the phone's clock, so this host's disagreement with the login
/// server is not something this login worked around and not something to say. The same property the
/// typed-code path already has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_code_raises_no_clock_notice() {
    let h = harness(true);
    listen_on_ephemeral(&h, ListenerSources::Any);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    // A host clock far from the scripted page's, which is what would raise the advisory on a login
    // that derived its own code.
    let ctx = context_otp(&h, transport.clone(), otp_empty(), NOW);

    let (task, mut rx) = spawn_run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Listener,
        },
        CancellationToken::new(),
    );

    let mut events = Vec::new();
    let waiting = await_state(&mut rx, &mut events, |state| {
        matches!(state, FlowState::WaitingForPushedCode { .. })
    })
    .await
    .expect("the flow never opened the listener");
    push_code(listening_port(&waiting).unwrap(), "135791")
        .await
        .unwrap();

    task.await.unwrap();
    drain(&mut rx, &mut events);

    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Notice(Notice::ClockSkew { .. }))),
        "a login that derived nothing raised a clock advisory"
    );
}

/// Nothing is bound before the maintenance gate.
///
/// The ordering decision, made a test. Opening a port for a login that is about to be abandoned is
/// the thing this avoids, and the worse half is making someone walk to their phone and only then
/// hear that the login server is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_bound_before_the_maintenance_gate() {
    let h = harness(true);
    listen_on_ephemeral(&h, ListenerSources::Any);
    let transport = Arc::new(FixtureTransport::new([fx::login_status_closed(
        "Maintenance",
    )]));
    let ctx = context_otp(&h, transport, otp_empty(), NOW);

    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Listener,
        },
    )
    .await;

    assert_eq!(states(&events), [FlowState::NoService]);
    assert!(
        !states(&events)
            .iter()
            .any(|state| matches!(state, FlowState::WaitingForPushedCode { .. })),
        "a port was opened for a login the gate stopped"
    );
}

/// A wait nobody answered leaves the account owing a code, and is not a failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_nobody_answered_needs_an_otp() {
    let h = harness(true);
    let mut settings = h.store.load_settings().unwrap_or_default();
    settings.otp_listener = ListenerSettings {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 0,
        sources: ListenerSources::Any,
        wait_seconds: 0,
    };
    h.store.save_settings(&settings).unwrap();
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp_empty(), NOW);

    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Listener,
        },
    )
    .await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert!(
        states(&events).contains(&FlowState::NeedsOtp),
        "{:?}",
        states(&events)
    );
    assert_eq!(submitted_otp(&transport), None, "something was submitted");
}

/// A pin that admits nobody opens no port at all.
///
/// Fail-closed, and answered as the same disposition as an account with no way to produce a code.
/// Only a hand-edited settings file reaches this, because the shell refuses to write it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_allowlist_does_not_open_a_port() {
    let h = harness(true);
    listen_on_ephemeral(
        &h,
        ListenerSources::Only {
            addresses: Vec::new(),
        },
    );
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp_empty(), NOW);

    let events = run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Listener,
        },
    )
    .await;

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert!(states(&events).contains(&FlowState::NeedsOtp));
    assert!(
        !states(&events)
            .iter()
            .any(|state| matches!(state, FlowState::WaitingForPushedCode { .. })),
        "a port was opened for a pin that admits nobody"
    );
    assert_eq!(submitted_otp(&transport), None);
}

/// A run stopped while it waited for a phone logs in with nothing and caches nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_wait_never_logs_in() {
    let h = harness(true);
    listen_on_ephemeral(&h, ListenerSources::Any);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp_empty(), NOW);
    let cancel = CancellationToken::new();

    let (task, mut rx) = spawn_run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Listener,
        },
        cancel.clone(),
    );

    let mut events = Vec::new();
    await_state(&mut rx, &mut events, |state| {
        matches!(state, FlowState::WaitingForPushedCode { .. })
    })
    .await
    .expect("the flow never opened the listener");
    cancel.cancel();

    task.await.unwrap();
    drain(&mut rx, &mut events);

    assert!(states(&events).contains(&FlowState::Cancelled));
    assert_eq!(submitted_otp(&transport), None, "a stopped run submitted");
    assert!(h.store.load_uid_cache(h.account).unwrap().is_none());
}

/// A flood during a login is narrated, and the login still succeeds.
///
/// Section 4's gate at flow level. The crate's own test proves the listener survives; this proves the
/// advisory reaches a shell, which is the only way a user learns that something on their network was
/// hammering the port while they logged in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_during_a_login_is_narrated_and_the_login_succeeds() {
    let h = harness(true);
    listen_on_ephemeral(&h, ListenerSources::Any);
    let transport = Arc::new(FixtureTransport::new(login_then_current()));
    let ctx = context_otp(&h, transport.clone(), otp_empty(), NOW);

    let (task, mut rx) = spawn_run(
        ctx,
        Command::Login {
            profile: h.profile,
            password: secret("hunter2"),
            otp: OtpSource::Listener,
        },
        CancellationToken::new(),
    );

    let mut events = Vec::new();
    let waiting = await_state(&mut rx, &mut events, |state| {
        matches!(state, FlowState::WaitingForPushedCode { .. })
    })
    .await
    .expect("the flow never opened the listener");
    let port = listening_port(&waiting).expect("the waiting state carried no port");

    // Complete request lines that are not deliverable codes, from a second loopback address, until
    // that source is refused. None of them can win the race, so what is left is the flood.
    let flooder = Ipv4Addr::new(127, 0, 0, 2);
    let mut throttled = false;
    for _ in 0..64 {
        if push_from(flooder, port, b"GET /ffxivlauncher/12345 HTTP/1.1\r\n\r\n")
            .await
            .is_ok_and(|answer| answer.starts_with(b"HTTP/1.0 429"))
        {
            throttled = true;
            break;
        }
    }
    assert!(throttled, "the listener never refused the flooding source");

    push_code(port, "482913").await.unwrap();
    task.await.unwrap();
    drain(&mut rx, &mut events);

    assert!(errors(&events).is_empty(), "{:?}", errors(&events));
    assert_eq!(submitted_otp(&transport).as_deref(), Some("482913"));
    let flood_notice = events.iter().find_map(|event| match event {
        Event::Notice(Notice::OtpListenerFlood { from, refused }) => Some((*from, *refused)),
        _ => None,
    });
    let Some((from, refused)) = flood_notice else {
        panic!("the flood was not narrated: {:?}", events);
    };
    assert_eq!(from, IpAddr::V4(flooder));
    assert!(refused > 0, "the advisory counted nothing");
}
