//! The login-to-play orchestration: a typed async state machine over the injected subsystems.
//!
//! [`drive`] runs one [`Command`] to completion, emitting [`Event`]s. It reads the injected seams
//! through a cheap [`FlowContext`] clone (so the whole flow runs on a spawned task), narrating each
//! disposition as a [`FlowState`] rather than a failure. The session cache lets a re-login inside its
//! window skip authentication and registration entirely.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use apogee_otp::OtpSource;
use apogee_patcher::{InstallRequest, Repo, SePatch};
use apogee_secrets::Secret;
use sqex_crypto::{ArgKey, ArgumentBuilder, TickCount};
use sqex_proto::{
    Authenticated, ClientContext, ComputerId, Credentials, FrontierContext, InstallPaths,
    LoginKind, OauthContext, PatchListEntry, Registration, Transport, VersionReport, begin_login,
    check_boot_version, check_login_status, register_session,
};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::command::{Command, Event, FlowState};
use crate::error::CoreError;
use crate::host::{self, Clock};
use crate::launch::{LaunchBackend, LaunchRequest};
use crate::model::{Account, Profile, Region};
use crate::patch::{PatchBackend, RepairPlan, RepairRepoPlan, classify_repo, repo_ver_path};
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
    pub(crate) store: Store,
    pub(crate) clock: Clock,
    pub(crate) computer_id: ComputerId,
    pub(crate) prefixes_dir: std::path::PathBuf,
}

/// Run `cmd` to completion, emitting its events on `tx`. A failure becomes an [`Event::Error`].
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
        } => login(&ctx, profile, password, otp, &tx).await,
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
        Command::FirstRun(_) => todo!("walk the initial setup"),
        Command::ImportXivLauncher(_) => todo!("import an existing launcher configuration"),
        Command::Frontier(_) => todo!("fetch pre-login news and gate status"),
        Command::SupportBundle => todo!("collect a redacted diagnostic bundle"),
    };
    if let Err(error) = outcome {
        let _ = tx.send(Event::Error(error));
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
) -> Result<(), CoreError> {
    let (profile, account) = resolve(ctx, profile_id)?;
    let Some(auth) = authenticate(ctx, &profile, &account, password, otp, tx).await? else {
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
        return launch_game(ctx, &profile, &session, tx, cancel).await;
    }
    let Some(auth) = authenticate(ctx, &profile, &account, password, otp, tx).await? else {
        return Ok(());
    };
    let Some(session) = patch_to_current(ctx, &profile, &auth, mode, tx, cancel).await? else {
        return Ok(());
    };
    if launch {
        launch_game(ctx, &profile, &session, tx, cancel).await?;
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
    let (profile, _account) = resolve(ctx, profile_id)?;
    match valid_cached_session(ctx, &profile)? {
        Some(session) => launch_game(ctx, &profile, &session, tx, cancel).await,
        None => {
            emit(tx, FlowState::NeedsLogin);
            Ok(())
        }
    }
}

/// The authenticate step (OTP gate → login-status gate → OAuth submit → terms/service gates). Returns
/// the completed login, or `None` when a disposition (needs-otp/terms/service) was narrated and the
/// flow should stop.
async fn authenticate(
    ctx: &FlowContext,
    profile: &Profile,
    account: &Account,
    password: Secret,
    otp: OtpSource,
    tx: &UnboundedSender<Event>,
) -> Result<Option<Authenticated>, CoreError> {
    // The one-time password: only a manually entered code is honored for now.
    let otp_code = match (account.use_otp, &otp) {
        (false, _) => None,
        (true, OtpSource::Manual(code)) if !code.is_empty() => Some(code.clone()),
        (true, _) => {
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
        LoginKind::Standard { free_trial: false },
    )
    .await?;
    let auth = flow
        .submit(Credentials {
            sqexid: &account.sqex_id,
            password,
            otp: otp_code.as_deref(),
        })
        .await?;
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
        announce_patching(tx, &mut patching_announced);
        ensure_boot_current(ctx, profile, mode, tx, cancel).await?;
    }

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
                announce_patching(tx, &mut patching_announced);
                if !ensure_boot_current(ctx, profile, mode, tx, cancel).await? {
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
                announce_patching(tx, &mut patching_announced);
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
async fn ensure_boot_current(
    ctx: &FlowContext,
    profile: &Profile,
    mode: InstallMode,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
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

/// Emit [`FlowState::Patching`] the first time a flow reaches a patch operation.
fn announce_patching(tx: &UnboundedSender<Event>, announced: &mut bool) {
    if !*announced {
        emit(tx, FlowState::Patching);
        *announced = true;
    }
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

/// Build the encrypted launch arguments, spawn through the launch backend, and supervise the game.
async fn launch_game(
    ctx: &FlowContext,
    profile: &Profile,
    session: &UidCacheEntry,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let settings = ctx.store.load_settings()?;
    let game_dir = profile.game_path.join("game");
    let request = LaunchRequest {
        runner: profile.runner.clone(),
        prefix_dir: ctx.prefixes_dir.join(prefix_name(profile)),
        program: game_dir
            .join("ffxiv_dx11.exe")
            .to_string_lossy()
            .into_owned(),
        working_dir: game_dir,
        encrypted_args: build_launch_args(session, language_id(&settings.language)),
        env: launch_env(profile),
        wrappers: profile.launch.wrappers.clone(),
    };

    emit(tx, FlowState::Launching);
    let handle = ctx.launch.launch(request, cancel, tx).await?;
    tracing::debug!(pid = handle.game_pid(), "game process running");
    emit(tx, FlowState::Running);

    // Closing after launch detaches the launcher; otherwise supervise until the game exits or the
    // caller cancels (Ctrl-C), in which case the game is killed.
    if settings.close_after_launch {
        return Ok(());
    }
    tokio::select! {
        result = handle.wait() => result?,
        () = cancel.cancelled() => handle.kill().await?,
    }
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

/// The ordered game arguments, encrypted under a fresh tick key.
fn build_launch_args(session: &UidCacheEntry, language: u8) -> String {
    launch_arguments(session, language)
        .build_encrypted(&ArgKey::from_tick(TickCount::now_for_game()))
}

/// The ordered game arguments before encryption. `DEV.TestSID` is the registration unique id (not the
/// OAuth session id), and the fixed set and order match the reference launcher (byte-identity oracle).
fn launch_arguments(session: &UidCacheEntry, language: u8) -> ArgumentBuilder {
    ArgumentBuilder::new()
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
        .add("ver", &session.game_version)
}

/// The launch environment: the profile's extra variables (DXVK passthrough, etc.).
fn launch_env(profile: &Profile) -> BTreeMap<String, String> {
    profile.launch.extra_env.iter().cloned().collect()
}

/// The prefix directory name for a profile: its named prefix, or the profile id when unnamed.
fn prefix_name(profile: &Profile) -> String {
    if profile.prefix.name.is_empty() {
        profile.id.to_string()
    } else {
        profile.prefix.name.clone()
    }
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
