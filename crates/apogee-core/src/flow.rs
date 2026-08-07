//! The login-to-play orchestration: a typed async state machine over the injected subsystems.
//!
//! [`drive`] runs one [`Command`] to completion, emitting [`Event`]s. It reads the injected seams
//! through a cheap [`FlowContext`] clone (so the whole flow runs on a spawned task), narrating each
//! disposition as a [`FlowState`] rather than a failure. The session cache lets a re-login inside its
//! window skip authentication and registration entirely.

use std::path::Path;
use std::sync::Arc;

use apogee_otp::{ClockSkew, Code, Otp, OtpError, OtpSource};
use apogee_patcher::{InstallRequest, Repo, SePatch};
use apogee_runtime::{EnvConfig, LaunchPlan, compute_environment};
use apogee_secrets::Secret;
use sqex_crypto::{ArgKey, ArgumentBuilder, ObfuscatedTicket, ServerTime};
use sqex_proto::{
    Authenticated, ClientContext, ComputerId, Credentials, FrontierContext, InstallPaths,
    LoginKind, OauthContext, PatchListEntry, Registration, Transport, VersionReport, begin_login,
    check_boot_version, check_login_status, register_session,
};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::addons::AddonBackend;
use crate::command::{Command, Event, FlowState, PrefixAction};
use crate::error::CoreError;
use crate::host::{self, Clock};
use crate::launch::LaunchBackend;
use crate::model::{Account, AccountKind, Profile, Region, STEAM_FREE_TRIAL_APP_ID, Settings};
use crate::patch::{PatchBackend, RepairPlan, RepairRepoPlan, classify_repo, repo_ver_path};
use crate::steam::SteamBackend;
use crate::store::{Store, StoreError, UidCacheEntry};

/// The most register→patch rounds a single flow will attempt before giving up. The normal chain is
/// at most three (boot patch → game patch → current); the cap only guards against a server that keeps
/// answering "still pending" without progress.
const MAX_REGISTER_ROUNDS: usize = 8;

/// Whether a patch flow updates an existing install or brings one up from nothing. The mode selects
/// the version-report posture (strict vs. base-sentinel) and whether the session-cache fast path and
/// the up-front boot bring-up apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallMode {
    /// Patch an existing install: strict version reporting, and a valid cached session skips the work.
    Update,
    /// Install into an empty directory: report the base sentinel so Square Enix returns the full
    /// chain, bring boot up before the first registration, and never take the cache fast path.
    FromNothing,
}

/// A cached session stays usable for one day, matching the reference launcher's window.
const UID_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// The injected seams a flow reads, cloned onto the spawned task. Every field is a cheap handle.
#[derive(Clone)]
pub(crate) struct FlowContext {
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) patch: Arc<dyn PatchBackend>,
    pub(crate) launch: Arc<dyn LaunchBackend>,
    pub(crate) addons: Arc<dyn AddonBackend>,
    pub(crate) steam: Arc<dyn SteamBackend>,
    /// Where a generated one-time code comes from, and what remembers the last one submitted.
    pub(crate) otp: Otp,
    pub(crate) store: Store,
    pub(crate) clock: Clock,
    pub(crate) computer_id: ComputerId,
    pub(crate) prefixes_dir: std::path::PathBuf,
    pub(crate) backups_dir: std::path::PathBuf,
}

/// Run `cmd` to completion, emitting its events on `tx`. A failure becomes an [`Event::Error`]; a run
/// the token stopped becomes [`FlowState::Cancelled`], which is not one.
pub(crate) async fn drive(
    ctx: FlowContext,
    cmd: Command,
    tx: UnboundedSender<Event>,
    cancel: CancellationToken,
) {
    let outcome = match cmd {
        Command::Login {
            profile,
            password,
            otp,
        } => login(&ctx, profile, password, otp, &tx, &cancel).await,
        Command::Launch { profile } => launch_cached(&ctx, profile, &tx, &cancel).await,
        Command::PatchAndPlay {
            profile,
            password,
            otp,
        } => {
            play(
                &ctx,
                profile,
                password,
                otp,
                InstallMode::Update,
                true,
                &tx,
                &cancel,
            )
            .await
        }
        Command::Patch {
            profile,
            password,
            otp,
        } => {
            play(
                &ctx,
                profile,
                password,
                otp,
                InstallMode::Update,
                false,
                &tx,
                &cancel,
            )
            .await
        }
        Command::Install {
            profile,
            password,
            otp,
        } => {
            play(
                &ctx,
                profile,
                password,
                otp,
                InstallMode::FromNothing,
                true,
                &tx,
                &cancel,
            )
            .await
        }
        Command::Repair { profile } => repair(&ctx, profile, &tx, &cancel).await,
        Command::Prefix { profile, action } => prefix(&ctx, profile, action, &tx, &cancel).await,
        Command::FirstRun(_) => todo!("walk the initial setup"),
        Command::ImportXivLauncher(_) => todo!("import an existing launcher configuration"),
        Command::Frontier(_) => todo!("fetch pre-login news and gate status"),
        Command::SupportBundle => todo!("collect a redacted diagnostic bundle"),
    };
    match outcome {
        Ok(()) => {}
        // Read here rather than at each call site, so every flow that carries the token reports being
        // stopped the same way: one disposition on the stream, and nothing a shell counts as a failure.
        Err(error) if is_cancellation(&error) => emit(&tx, FlowState::Cancelled),
        Err(error) => {
            let _ = tx.send(Event::Error(error));
        }
    }
}

/// Whether `error` is the run stopping because it was asked to, rather than something going wrong.
///
/// Each subsystem spells cancellation in its own taxonomy, so the reading is per-variant rather than a
/// query on the token: a run can be cancelled and still fail for an unrelated reason first, and that
/// failure is the one worth reporting.
///
/// The one that spells it a single way is read here. The other two spell it several ways each and
/// answer for themselves, because restating their lists here is how one of them gets missed: the
/// runtime has four spellings (a stopped download, a `wineboot` the token interrupted, a setup program
/// killed mid-run, a wait for the game that gave up because it was asked to), and a first run spends
/// most of its time creating a prefix, so the one it would cost is the one a user is most likely to
/// stop. The addon layer has two, for the same shape of reason.
///
/// There is no arm for a bare [`CoreError::Fetch`]. Every download a command makes belongs to a
/// subsystem and arrives in that subsystem's taxonomy; the one place fetch's own error reaches this
/// type unwrapped is building the HTTP client while a [`FlowContext`] is assembled, which happens
/// before there is a command to stop.
fn is_cancellation(error: &CoreError) -> bool {
    match error {
        CoreError::Patch(apogee_patcher::PatchError::Cancelled) => true,
        CoreError::Runtime(error) => error.is_cancellation(),
        CoreError::Addons(error) => error.is_cancellation(),
        _ => false,
    }
}

/// Authenticate and register once, narrating the resulting disposition. Does not patch or launch: a
/// pending boot patch, pending game patches, or an unserviced version surface as [`FlowState`]s the
/// shell reads; a current game caches its session. (Patching is [`Command::PatchAndPlay`]'s job.)
async fn login(
    ctx: &FlowContext,
    profile_id: Uuid,
    password: Secret,
    otp: OtpSource,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let (profile, account) = resolve(ctx, profile_id)?;
    let Some(auth) = authenticate(ctx, &profile, &account, password, otp, tx, cancel).await? else {
        return Ok(());
    };
    let report = build_report(InstallMode::Update, &profile.game_path, auth.max_expansion)?;
    match register_session(&*ctx.transport, &auth, &report).await? {
        Registration::NeedsBootPatch => emit(tx, FlowState::NeedsBootPatch),
        Registration::VersionNotServiced => emit(tx, FlowState::VersionNotServiced),
        Registration::Registered {
            unique_id,
            pending_patches,
        } => {
            if pending_patches.is_empty() {
                let session = build_session(ctx, &auth, &report, unique_id.expose());
                ctx.store.save_uid_cache(profile.account, &session)?;
            } else {
                let (count, bytes) = summarize(&pending_patches);
                emit(tx, FlowState::PatchesPending { count, bytes });
            }
        }
    }
    Ok(())
}

/// Bring the install current (applying any pending patches), then optionally launch.
///
/// `mode` selects an ordinary update or an install-from-nothing; `launch` distinguishes the play
/// flows (`PatchAndPlay`, `Install`) from the patch-only flow (`Patch`). The session-cache fast path
/// applies only to an updating play: a still-valid cached session means the install is current, so a
/// launch skips authentication and patching entirely.
#[allow(clippy::too_many_arguments)]
async fn play(
    ctx: &FlowContext,
    profile_id: Uuid,
    password: Secret,
    otp: OtpSource,
    mode: InstallMode,
    launch: bool,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let (profile, account) = resolve(ctx, profile_id)?;
    if mode == InstallMode::Update
        && launch
        && let Some(session) = valid_cached_session(ctx, &profile)?
    {
        return launch_game(ctx, &profile, &account, &session, tx, cancel).await;
    }
    let Some(auth) = authenticate(ctx, &profile, &account, password, otp, tx, cancel).await? else {
        return Ok(());
    };
    let Some(session) = patch_to_current(ctx, &profile, &auth, mode, tx, cancel).await? else {
        return Ok(());
    };
    if launch {
        launch_game(ctx, &profile, &account, &session, tx, cancel).await?;
    }
    Ok(())
}

/// Verify the profile's install against its signed block indexes and re-fetch only the broken ranges.
async fn repair(
    ctx: &FlowContext,
    profile_id: Uuid,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let (profile, _account) = resolve(ctx, profile_id)?;
    let repos = installed_repos(&profile.game_path);
    if repos.is_empty() {
        return Err(CoreError::Repair {
            detail: "no installed repositories to verify".to_owned(),
        });
    }
    emit(tx, FlowState::Repairing);
    let plan = RepairPlan {
        game_root: profile.game_path.clone(),
        repos,
    };
    let outcome = ctx.patch.repair(plan, cancel, tx).await?;
    tracing::debug!(
        repos = outcome.repos.len(),
        bytes = outcome.bytes_refetched,
        quarantined = outcome.quarantined.len(),
        "repair complete"
    );
    Ok(())
}

/// Launch from a still-valid cached session, or narrate that a login is needed first.
async fn launch_cached(
    ctx: &FlowContext,
    profile_id: Uuid,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let (profile, account) = resolve(ctx, profile_id)?;
    match valid_cached_session(ctx, &profile)? {
        Some(session) => launch_game(ctx, &profile, &account, &session, tx, cancel).await,
        None => {
            emit(tx, FlowState::NeedsLogin);
            Ok(())
        }
    }
}

/// The authenticate step (OTP gate → login-status gate → OAuth submit → terms/service gates). Returns
/// the completed login, or `None` when a disposition (needs-otp/terms/service/cancelled) was narrated
/// and the flow should stop.
#[allow(clippy::too_many_arguments)]
async fn authenticate(
    ctx: &FlowContext,
    profile: &Profile,
    account: &Account,
    password: Secret,
    otp: OtpSource,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<Option<Authenticated>, CoreError> {
    // A generated code is owned for the rest of the call, so `Credentials::otp` can borrow it across
    // the submit await exactly as it borrows a typed one. Minting here, before any request, keeps
    // the reuse guard's wait outside the login server's own window; the correction against server
    // time arrives when the top page's `Date` is plumbed through.
    let minted: Option<Code> = if account.use_otp && matches!(otp, OtpSource::Totp) {
        match mint_totp(ctx, account.id, tx, cancel).await? {
            Some(code) => Some(code),
            // A disposition the mint has already narrated: nothing stored to derive a code from, or
            // a run stopped while it held for the next window. Neither is a failure.
            None => return Ok(None),
        }
    } else {
        None
    };

    // The one-time password: either the code just generated or the one that was typed. Borrowed out
    // of whichever holds it rather than copied out, so the erased buffer is the only one this
    // process holds.
    let otp_code = match (account.use_otp, &otp, &minted) {
        (false, _, _) => None,
        (true, _, Some(code)) => Some(code.expose()),
        (true, OtpSource::Manual(code), _) if !code.is_empty() => {
            Some(std::str::from_utf8(code.expose()).map_err(|_| CoreError::InvalidCredential)?)
        }
        (true, _, _) => {
            emit(tx, FlowState::NeedsOtp);
            return Ok(None);
        }
    };
    let password =
        std::str::from_utf8(password.expose()).map_err(|_| CoreError::InvalidCredential)?;

    let now = host::launcher_time_now();

    // Pre-flight: the login server must be open.
    if !check_login_status(&*ctx.transport, &frontier_context(ctx), &now)
        .await?
        .status
    {
        emit(tx, FlowState::NoService);
        return Ok(None);
    }

    // OAuth.
    let oauth = oauth_context(ctx, oauth_region(profile.launch.region));
    let flow = begin_login(
        &*ctx.transport,
        &oauth,
        &now,
        login_kind(ctx, account).await?,
    )
    .await?;
    let submitted = flow
        .submit(Credentials {
            sqexid: &account.sqex_id,
            password,
            otp: otp_code,
        })
        .await;
    // Recorded whichever way the submit went. The login server has seen the code either way, and it
    // is the server's replay rule this guards against, not our own success.
    if let Some(code) = &minted {
        ctx.otp.submitted(account.id, code);
    }
    let auth = submitted?;
    if !auth.terms_accepted {
        emit(tx, FlowState::NeedsTerms);
        return Ok(None);
    }
    if !auth.playable {
        emit(tx, FlowState::NoService);
        return Ok(None);
    }
    Ok(Some(auth))
}

/// Derive this account's code, holding out whatever wait the mint asks for.
///
/// `None` is a disposition this narrates itself: either nothing is stored to derive a code from (the
/// answer is to type one or to import a secret) or the run was stopped while it held. The wait is
/// the library's answer rather than its own sleep, because only this side holds the runtime, the
/// event channel and the token; it is bounded by the windows the mint will step over.
async fn mint_totp(
    ctx: &FlowContext,
    account: Uuid,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<Option<Code>, CoreError> {
    // No correction yet: server time is not in hand until the OAuth top page has answered, which is
    // past the point a code has to exist. The instant the code is derived from is read inside the
    // mint, after the store has answered, because that read can sit on an unlock prompt for as long
    // as the user takes to notice it.
    match ctx.otp.mint(account, ClockSkew::NONE).await {
        Ok(minted) => {
            let wait = minted.wait();
            if !wait.is_zero() {
                emit(
                    tx,
                    FlowState::WaitingForOtpWindow {
                        seconds: wait.as_secs(),
                    },
                );
                // The only wall-clock wait in a login, and the one moment a shell tells a user to
                // sit still, so it is the moment cancel gets pressed. A sleep that ignored the token
                // would go on to log in and cache a session for a run that was stopped.
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = cancel.cancelled() => {
                        emit(tx, FlowState::Cancelled);
                        return Ok(None);
                    }
                }
            }
            Ok(Some(minted.into_code()))
        }
        Err(OtpError::NoSecret) => {
            emit(tx, FlowState::NeedsOtp);
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

/// Which login variant an account logs in with, minting a Steam ticket when it needs one.
///
/// The free-trial flag and the ticket are independent on the wire, and for a Steam account the app id
/// decides both: a ticket is minted against the app the licence belongs to, and the trial app is the
/// one that also flags the login.
async fn login_kind(ctx: &FlowContext, account: &Account) -> Result<LoginKind, CoreError> {
    Ok(match account.kind {
        AccountKind::Standard => LoginKind::Standard { free_trial: false },
        AccountKind::FreeTrial => LoginKind::Standard { free_trial: true },
        AccountKind::Steam { app_id } => {
            let ticket = ctx.steam.auth_ticket(app_id).await?;
            LoginKind::Steam {
                ticket: ObfuscatedTicket::from_auth_ticket(
                    ticket.raw.expose(),
                    ServerTime(ticket.server_time),
                )?,
                free_trial: app_id == STEAM_FREE_TRIAL_APP_ID,
            }
        }
    })
}

/// Drive the register→patch loop until the install is current, applying pending boot and game patches
/// through the patch backend. Returns the launch-ready cached session, or `None` when a terminal
/// disposition (version not serviced) was narrated and the flow should stop.
///
/// The loop is the core-owned boot→re-register→game sequence: each registration answers current
/// (done), needs-a-boot-patch (apply boot, re-register), or pending-game-patches (apply per repo,
/// re-register). An install-from-nothing brings boot up before the first registration, since the
/// version report must hash boot EXEs an empty directory lacks.
async fn patch_to_current(
    ctx: &FlowContext,
    profile: &Profile,
    auth: &Authenticated,
    mode: InstallMode,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<Option<UidCacheEntry>, CoreError> {
    let mut patching_announced = false;

    if mode == InstallMode::FromNothing {
        announce_patching(ctx, profile, tx, &mut patching_announced);
    }

    // Boot is brought current before the first registration rather than in reaction to one. A
    // registration carrying an out-of-date boot is answered 410, which is terminal, so the
    // `NeedsBootPatch` arm below never sees an ordinary stale boot; it stays as the tamper case the
    // reference launcher documents (boot EXEs whose hashes no longer match after boot is current).
    ensure_boot_current(ctx, profile, mode, tx, cancel, &mut patching_announced).await?;

    for _round in 0..MAX_REGISTER_ROUNDS {
        // Cancellation is threaded through the patch backend (an in-flight install honors it) and the
        // launch supervisor, not by aborting a registration mid-flight, so no explicit check here.
        let report = build_report(mode, &profile.game_path, auth.max_expansion)?;
        match register_session(&*ctx.transport, auth, &report).await? {
            Registration::VersionNotServiced => {
                emit(tx, FlowState::VersionNotServiced);
                return Ok(None);
            }
            Registration::NeedsBootPatch => {
                if !ensure_boot_current(ctx, profile, mode, tx, cancel, &mut patching_announced)
                    .await?
                {
                    // Registration demands a boot patch, but the boot server offers none: a
                    // contradiction (tampered boot EXEs, or a stuck server). Stop rather than spin.
                    return Err(CoreError::PatchIncomplete {
                        detail: "registration requires a boot patch but none is offered".to_owned(),
                    });
                }
            }
            Registration::Registered {
                unique_id,
                pending_patches,
            } => {
                if pending_patches.is_empty() {
                    let session = build_session(ctx, auth, &report, unique_id.expose());
                    ctx.store.save_uid_cache(profile.account, &session)?;
                    return Ok(Some(session));
                }
                announce_patching(ctx, profile, tx, &mut patching_announced);
                install_game_patches(
                    ctx,
                    profile,
                    unique_id.expose(),
                    &pending_patches,
                    tx,
                    cancel,
                )
                .await?;
            }
        }
    }

    Err(CoreError::PatchIncomplete {
        detail: format!(
            "the install did not reach a current version after {MAX_REGISTER_ROUNDS} registration rounds"
        ),
    })
}

/// Bring the boot repository current: fetch its patchlist and, if any patches are pending, apply them
/// through the patch backend. Returns whether any boot patch was applied (`false` when boot is already
/// current). `mode` selects the strict boot version read or the base-sentinel install-from-nothing one.
///
/// Announces patching itself, once a patch is known to be pending, so that a boot check finding
/// nothing to do stays free of side effects.
async fn ensure_boot_current(
    ctx: &FlowContext,
    profile: &Profile,
    mode: InstallMode,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
    announced: &mut bool,
) -> Result<bool, CoreError> {
    let paths = InstallPaths::new(&profile.game_path);
    let boot_version = match mode {
        InstallMode::Update => paths.boot_version()?,
        InstallMode::FromNothing => paths.boot_version_or_sentinel()?,
    };
    let now = host::launcher_time_now();
    let patches = check_boot_version(&*ctx.transport, &boot_version, &now).await?;
    if patches.is_empty() {
        return Ok(false);
    }
    announce_patching(ctx, profile, tx, announced);
    let request = InstallRequest {
        repo: Repo::Boot,
        game_root: profile.game_path.clone(),
        patches,
        headers: SePatch::boot(),
    };
    ctx.patch.install(request, cancel, tx).await?;
    Ok(true)
}

/// Apply a game patchlist by splitting it into per-repo ordered sets (base game, then expansions) and
/// installing each through the patch backend. Each set carries the session's patch-download credential.
async fn install_game_patches(
    ctx: &FlowContext,
    profile: &Profile,
    unique_id: &str,
    pending: &[PatchListEntry],
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    for (repo, patches) in group_by_repo(pending) {
        let request = InstallRequest {
            repo,
            game_root: profile.game_path.clone(),
            patches,
            headers: SePatch::new(unique_id),
        };
        ctx.patch.install(request, cancel, tx).await?;
    }
    Ok(())
}

/// Emit [`FlowState::Patching`] the first time a flow reaches a patch operation, capturing the game's
/// settings first when that is asked for.
///
/// This is the one place every patch path passes through, which is what makes it the place to capture
/// from: a patch is the moment settings are most likely to be rewritten, and it happens once per flow
/// rather than once per repo.
///
/// A capture that fails never fails the patch. It is reported and the patch proceeds, because
/// refusing to update a game over a settings snapshot would be the worse trade, and a silent skip
/// would leave the user believing they had one.
fn announce_patching(
    ctx: &FlowContext,
    profile: &Profile,
    tx: &UnboundedSender<Event>,
    announced: &mut bool,
) {
    if *announced {
        return;
    }
    *announced = true;

    let settings = ctx.store.load_settings().unwrap_or_default();
    // A prefix the game has never written into has nothing to capture. That is the ordinary state
    // before a first launch, not a failure, so it is neither announced nor reported: doing either
    // would tell the user a backup was attempted, and reporting it would fail an install that is
    // going perfectly well.
    let has_config =
        !apogee_addons::backup::game_config_dirs(&ctx.prefixes_dir.join(prefix_name(profile)))
            .is_empty();
    if settings.backup_before_patch && has_config {
        emit(tx, FlowState::BackingUp);
        match crate::backup::create(
            &ctx.prefixes_dir,
            &ctx.backups_dir,
            profile,
            settings.backups_kept,
            (ctx.clock)(),
            Some("before patching".to_owned()),
        ) {
            Ok((report, _)) => {
                tracing::debug!(archive = ?report.archive, "captured the game settings");
            }
            Err(error) => {
                let _ = tx.send(Event::Error(error));
            }
        }
    }
    emit(tx, FlowState::Patching);
}

/// Build the registration version report for `mode`: strict for an update (a missing repo is a fault),
/// base-sentinel for an install-from-nothing (a missing repo reports the base version so Square Enix
/// returns its full chain).
fn build_report(
    mode: InstallMode,
    game_path: &Path,
    max_expansion: u8,
) -> Result<VersionReport, CoreError> {
    let paths = InstallPaths::new(game_path);
    Ok(match mode {
        InstallMode::Update => VersionReport::from_install(&paths, max_expansion)?,
        InstallMode::FromNothing => VersionReport::from_install_or_base(&paths, max_expansion)?,
    })
}

/// Assemble the cache entry for a registered session, valid for one day from now.
fn build_session(
    ctx: &FlowContext,
    auth: &Authenticated,
    report: &VersionReport,
    unique_id: &str,
) -> UidCacheEntry {
    UidCacheEntry {
        unique_id: unique_id.to_owned(),
        region: auth.region,
        max_expansion: auth.max_expansion,
        game_version: report.game_version().to_owned(),
        expires_at: (ctx.clock)() + UID_CACHE_TTL_SECS,
    }
}

/// The count and total byte size of a pending patch set, for [`FlowState::PatchesPending`].
fn summarize(patches: &[PatchListEntry]) -> (u32, u64) {
    let bytes = patches.iter().map(|p| p.length).sum();
    let count = u32::try_from(patches.len()).unwrap_or(u32::MAX);
    (count, bytes)
}

/// Split a game patchlist into per-repo ordered sets, base game first then expansions ascending. SE
/// list order is preserved within each repo (the patcher applies each set in order).
fn group_by_repo(pending: &[PatchListEntry]) -> Vec<(Repo, Vec<PatchListEntry>)> {
    let mut groups: Vec<(Repo, Vec<PatchListEntry>)> = Vec::new();
    for entry in pending {
        let repo = repo_of(&entry.url);
        match groups.iter_mut().find(|(r, _)| *r == repo) {
            Some((_, set)) => set.push(entry.clone()),
            None => groups.push((repo, vec![entry.clone()])),
        }
    }
    groups.sort_by_key(|(repo, _)| repo_order(*repo));
    groups
}

/// Classify a game-patchlist entry's URL into its repo (the reference launcher's `GetRepo` rule; see
/// [`classify_repo`]). Parses the URL to match on path segments, falling back to a raw split when it
/// will not parse.
fn repo_of(url: &str) -> Repo {
    match Url::parse(url) {
        Ok(parsed) => classify_repo(parsed.path_segments().into_iter().flatten()),
        Err(_) => classify_repo(url.split('/')),
    }
}

/// A total order over repos for deterministic per-repo apply: boot, base game, then expansions.
fn repo_order(repo: Repo) -> u16 {
    match repo {
        Repo::Boot => 0,
        Repo::Game => 1,
        Repo::Expansion(n) => 2 + u16::from(n),
        _ => u16::MAX,
    }
}

/// The repos present in an install, each with its current `.ver`, for a repair plan. Boot and game are
/// checked first, then any expansion whose `.ver` is present and non-empty.
fn installed_repos(game_root: &Path) -> Vec<RepairRepoPlan> {
    let mut repos = Vec::new();
    for repo in [Repo::Boot, Repo::Game] {
        if let Some(version) = read_repo_ver(game_root, repo) {
            repos.push(RepairRepoPlan { repo, version });
        }
    }
    for n in 1..=5u8 {
        let repo = Repo::Expansion(n);
        if let Some(version) = read_repo_ver(game_root, repo) {
            repos.push(RepairRepoPlan { repo, version });
        }
    }
    repos
}

/// Read a repo's current `.ver` (canonical, trimmed) from the standard install layout, or `None` when
/// it is absent or empty. Decodes through `sqex_proto::decode_ver` (lossy UTF-8, one leading BOM
/// stripped) so the version matches the registration report and the signed index catalog's key
/// byte-for-byte; a plain `read_to_string` would keep a BOM (`trim` does not remove U+FEFF) or fail on
/// a non-UTF-8 byte, and either would then miss the catalog's exact-match lookup.
fn read_repo_ver(game_root: &Path, repo: Repo) -> Option<String> {
    let bytes = std::fs::read(repo_ver_path(game_root, repo)?).ok()?;
    let text = sqex_proto::decode_ver(&bytes);
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Prepare the prefix, compose the launch, spawn it through the launch backend, and supervise the game.
///
/// The prefix is prepared as its own step rather than inside the spawn, because what is launched is
/// decided in between: the prefix is brought up to the setup the signed catalog publishes, and whatever
/// the profile loads into the game composes itself onto the plan. Neither can happen without a prefix in
/// hand, and neither is allowed to fail the launch.
async fn launch_game(
    ctx: &FlowContext,
    profile: &Profile,
    account: &Account,
    session: &UidCacheEntry,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let settings = ctx.store.load_settings()?;
    let game_dir = profile.game_path.join("game");
    let prefix_dir = ctx.prefixes_dir.join(prefix_name(profile));

    emit(tx, FlowState::PreparingPrefix);
    let prepared = ctx
        .launch
        .prepare(&profile.runner, &prefix_dir, cancel, tx)
        .await?;

    let steam = is_steam(account);
    let environment = compute_environment(
        &launch_env(profile, prepared.dxvk.clone(), steam),
        &prepared.caps,
    );
    let mut plan = LaunchPlan::new(
        game_dir.join("ffxiv_dx11.exe").to_string_lossy(),
        build_launch_args(session, language_id(&settings.language), steam)?,
        environment.vars,
    )
    .in_directory(&game_dir)
    .with_wrappers(environment.wrappers);
    if let Some(prefix) = &prepared.prefix {
        plan = plan.prefix(prefix);
    }
    ctx.addons
        .prepare_launch(
            prepared.prefix,
            dalamud_config(profile, session, &settings),
            &mut plan,
            cancel,
            tx,
        )
        .await;

    emit(tx, FlowState::Launching);
    let handle = ctx.launch.launch(plan, cancel, tx).await?;
    tracing::debug!(pid = handle.game_pid(), "game process running");
    emit(tx, FlowState::Running);

    // Started once the game is up, so a companion that looks for it finds it.
    let addons = ctx
        .addons
        .start(
            handle.game_pid(),
            handle.prefix(),
            profile.external.clone(),
            cancel,
            tx,
        )
        .await;

    // Closing after launch detaches the launcher, but only when nothing is owed at exit: detaching
    // with companions still to stop would leave them running with nothing left that knows about them.
    if settings.close_after_launch {
        if !addons.has_work() {
            return Ok(());
        }
        emit(tx, FlowState::SupervisingAddons);
    }

    // Bound rather than propagated, because the teardown has to run on the failing paths too. An
    // early return here is exactly how a launch leaves companions behind.
    let result = tokio::select! {
        result = handle.wait() => result,
        () = cancel.cancelled() => handle.kill().await,
    };
    let failures = if cancel.is_cancelled() {
        addons.abandon(cancel).await
    } else {
        addons.game_closed(cancel).await
    };
    for failure in failures {
        let _ = tx.send(Event::Error(failure));
    }
    result?;
    emit(tx, FlowState::Exited);
    Ok(())
}

/// The still-valid cached session for `profile`, or `None`. Stale, expired, or corrupt entries are
/// cleared so a bare launch falls back to a full login cleanly.
fn valid_cached_session(
    ctx: &FlowContext,
    profile: &Profile,
) -> Result<Option<UidCacheEntry>, CoreError> {
    let session = match ctx.store.load_uid_cache(profile.account) {
        Ok(Some(session)) => session,
        Ok(None) => return Ok(None),
        // A corrupt entry is preserved by the store; clear it so a bare launch stops minting a fresh
        // sidecar every run, then fall back to a full login. A transient read error is left in place
        // (it may read next time).
        Err(StoreError::Corrupt { .. }) => {
            let _ = ctx.store.clear_uid_cache(profile.account);
            return Ok(None);
        }
        Err(_) => return Ok(None),
    };
    // The install's version must still match the cached token; an unreadable install means no fast
    // path this run (the entry is left in place).
    let Ok(report) = VersionReport::from_install(
        &InstallPaths::new(&profile.game_path),
        session.max_expansion,
    ) else {
        return Ok(None);
    };
    if session.is_valid((ctx.clock)(), report.game_version()) {
        Ok(Some(session))
    } else {
        let _ = ctx.store.clear_uid_cache(profile.account);
        Ok(None)
    }
}

/// Load the profile and its account, mapping a missing record to the typed not-found error.
fn resolve(ctx: &FlowContext, profile_id: Uuid) -> Result<(Profile, Account), CoreError> {
    let profile = ctx.store.load_profile(profile_id).map_err(|e| match e {
        StoreError::NotFound { .. } => CoreError::NoProfile(profile_id),
        other => other.into(),
    })?;
    let account_id = profile.account;
    let account = ctx.store.load_account(account_id).map_err(|e| match e {
        StoreError::NotFound { .. } => CoreError::NoAccount(account_id),
        other => other.into(),
    })?;
    Ok((profile, account))
}

/// Whether this account's game runs as a Steam launch: the extra argument and environment entry
/// below, and nothing else about the launch, hang off it.
fn is_steam(account: &Account) -> bool {
    matches!(account.kind, AccountKind::Steam { .. })
}

/// The ordered game arguments, encrypted under a fresh tick key.
///
/// # Errors
///
/// [`CoreError::NoTickSource`] on a host with no clock the game can re-derive the key from.
fn build_launch_args(
    session: &UidCacheEntry,
    language: u8,
    steam: bool,
) -> Result<String, CoreError> {
    let tick = host::game_tick()?;
    Ok(launch_arguments(session, language, steam).build_encrypted(&ArgKey::from_tick(tick)))
}

/// The ordered game arguments before encryption. `DEV.TestSID` is the registration unique id (not the
/// OAuth session id), and the fixed set and order match the reference launcher (byte-identity oracle),
/// including `IsSteam` trailing the fixed set on a Steam launch.
fn launch_arguments(session: &UidCacheEntry, language: u8, steam: bool) -> ArgumentBuilder {
    let args = ArgumentBuilder::new()
        .add("DEV.DataPathType", "1")
        .add(
            "DEV.MaxEntitledExpansionID",
            session.max_expansion.to_string(),
        )
        .add("DEV.TestSID", &session.unique_id)
        .add("DEV.UseSqPack", "1")
        .add("SYS.Region", session.region.to_string())
        .add("language", language.to_string())
        .add("resetConfig", "0")
        .add("ver", &session.game_version);
    if steam {
        args.add("IsSteam", "1")
    } else {
        args
    }
}

/// Work on a profile's prefix without launching anything.
///
/// Each action narrates its own disposition and, where it has one, ends with the report of what is
/// wrong. Nothing here decides on the user's behalf: a check changes nothing, a fix applies only the
/// resolutions that leave the prefix in place, and the destructive one happens only when it is the
/// action that was asked for.
async fn prefix(
    ctx: &FlowContext,
    profile_id: Uuid,
    action: PrefixAction,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let profile = ctx.store.load_profile(profile_id)?;
    let prefix_dir = ctx.prefixes_dir.join(prefix_name(&profile));

    match action {
        PrefixAction::Create => {
            emit(tx, FlowState::PreparingPrefix);
            ctx.launch
                .prepare(&profile.runner, &prefix_dir, cancel, tx)
                .await?;
        }
        PrefixAction::Check => {
            emit(tx, FlowState::CheckingPrefix);
            match ctx
                .launch
                .check_prefix(&profile.runner, &prefix_dir, cancel, tx)
                .await?
            {
                Some(health) => {
                    let _ = tx.send(Event::PrefixHealth(health));
                }
                None => emit(tx, FlowState::NoPrefix),
            }
        }
        PrefixAction::Fix => {
            emit(tx, FlowState::FixingPrefix);
            if let Some(residual) = ctx
                .launch
                .fix_prefix(&profile.runner, &prefix_dir, cancel, tx)
                .await?
            {
                // What is left after the fix, which is what a user has to decide about. An empty
                // report is the fix having resolved everything.
                let _ = tx.send(Event::PrefixHealth(residual));
            }
        }
        PrefixAction::Recreate => {
            emit(tx, FlowState::RecreatingPrefix);
            ctx.launch
                .recreate_prefix(&profile.runner, &prefix_dir, cancel, tx)
                .await?;
        }
    }
    Ok(())
}

/// The launch environment a profile asks for, before the host resolves it.
///
/// The profile's own variables and wrapper commands go in as the free-form arms, which the matrix
/// merges last and innermost respectively, so a user's setting still outranks anything computed for
/// them. Note that the addon layer composes onto the plan *after* this, so what it contributes
/// outranks both: setup a launch cannot run without is not a preference.
fn launch_env(profile: &Profile, dxvk: Option<apogee_runtime::DxvkEnv>, steam: bool) -> EnvConfig {
    let mut env: std::collections::BTreeMap<String, String> =
        profile.launch.extra_env.iter().cloned().collect();
    if steam {
        // The reference launcher sets this beside the `IsSteam` argument, both being what the game
        // sees when its own boot binary is started as a Steam launch. Inserted only where the profile
        // has not spoken, so the free-form arm keeps outranking what is computed for it.
        env.entry("IS_FFXIV_LAUNCH_FROM_STEAM".to_owned())
            .or_insert_with(|| "1".to_owned());
    }
    EnvConfig {
        sync: profile.launch.sync,
        hud: profile.launch.hud.clone(),
        gpu: profile.launch.gpu.clone(),
        gamescope: profile.launch.gamescope.clone(),
        gamemode: profile.launch.gamemode,
        env,
        wrappers: profile.launch.wrappers.clone(),
        dxvk,
    }
}

/// The prefix directory name for a profile: its named prefix, or the profile id when unnamed.
pub(crate) fn prefix_name(profile: &Profile) -> String {
    if profile.prefix.name.is_empty() {
        profile.id.to_string()
    } else {
        profile.prefix.name.clone()
    }
}

/// What this launch loads into the game, or `None` when the profile's toggle is off.
///
/// `None` is what keeps a launch from contacting the distribution at all, so it is the whole of the
/// opt-in: nothing downstream re-checks the setting.
fn dalamud_config(
    profile: &Profile,
    session: &UidCacheEntry,
    settings: &Settings,
) -> Option<apogee_addons::DalamudConfig> {
    profile
        .launch
        .dalamud
        .then(|| apogee_addons::DalamudConfig {
            language: apogee_addons::ClientLanguage::from_ordinal(language_id(&settings.language)),
            // The version the session was registered against, which is the install's own. A release
            // built for another one reads the client's memory at offsets that have moved.
            game_version: session.game_version.clone(),
            ..apogee_addons::DalamudConfig::default()
        })
}

/// The game's numeric language id (Japanese 0, English 1, German 2, French 3), defaulting English.
fn language_id(language: &str) -> u8 {
    match language {
        "ja" => 0,
        "de" => 2,
        "fr" => 3,
        _ => 1,
    }
}

/// The OAuth region code. Only the global region is wired today.
fn oauth_region(_region: Region) -> u16 {
    3
}

fn client_context(ctx: &FlowContext) -> ClientContext<'_> {
    ClientContext {
        computer_id: &ctx.computer_id,
        language: "en-us",
        accept_language: "en-US,en;q=0.9",
        referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
    }
}

fn frontier_context(ctx: &FlowContext) -> FrontierContext<'_> {
    FrontierContext {
        client: client_context(ctx),
    }
}

fn oauth_context(ctx: &FlowContext, region: u16) -> OauthContext<'_> {
    OauthContext {
        client: client_context(ctx),
        lng: "en",
        region,
    }
}

fn emit(tx: &UnboundedSender<Event>, state: FlowState) {
    let _ = tx.send(Event::State(state));
}

#[cfg(test)]
mod tests;
