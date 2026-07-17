//! The login-to-play orchestration: a typed async state machine over the injected subsystems.
//!
//! [`drive`] runs one [`Command`] to completion, emitting [`Event`]s. It reads the injected seams
//! through a cheap [`FlowContext`] clone (so the whole flow runs on a spawned task), narrating each
//! disposition as a [`FlowState`] rather than a failure. The session cache lets a re-login inside its
//! window skip authentication and registration entirely.

use std::collections::BTreeMap;
use std::sync::Arc;

use apogee_otp::OtpSource;
use apogee_secrets::Secret;
use sqex_crypto::{ArgKey, ArgumentBuilder, TickCount};
use sqex_proto::{
    ClientContext, ComputerId, Credentials, FrontierContext, InstallPaths, LoginKind, OauthContext,
    Registration, Transport, VersionReport, begin_login, check_login_status, register_session,
};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::command::{Command, Event, FlowState};
use crate::error::CoreError;
use crate::host::{self, Clock};
use crate::launch::{LaunchBackend, LaunchRequest};
use crate::model::{Account, Profile, Region};
use crate::store::{Store, StoreError, UidCacheEntry};

/// A cached session stays usable for one day, matching the reference launcher's window.
const UID_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// The injected seams a flow reads, cloned onto the spawned task. Every field is a cheap handle.
#[derive(Clone)]
pub(crate) struct FlowContext {
    pub(crate) transport: Arc<dyn Transport>,
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
        } => play(&ctx, profile, password, otp, &tx, &cancel).await,
        Command::Repair { .. } => todo!("verify and repair the installation"),
        Command::FirstRun(_) => todo!("walk the initial setup"),
        Command::ImportXivLauncher(_) => todo!("import an existing launcher configuration"),
        Command::Frontier(_) => todo!("fetch pre-login news and gate status"),
        Command::SupportBundle => todo!("collect a redacted diagnostic bundle"),
    };
    if let Err(error) = outcome {
        let _ = tx.send(Event::Error(error));
    }
}

/// Authenticate and register, caching the result. Does not launch.
async fn login(
    ctx: &FlowContext,
    profile_id: Uuid,
    password: Secret,
    otp: OtpSource,
    tx: &UnboundedSender<Event>,
) -> Result<(), CoreError> {
    let (profile, account) = resolve(ctx, profile_id)?;
    let _ = authenticate_and_register(ctx, &profile, &account, password, otp, tx).await?;
    Ok(())
}

/// Authenticate (or reuse a cached session) and launch.
async fn play(
    ctx: &FlowContext,
    profile_id: Uuid,
    password: Secret,
    otp: OtpSource,
    tx: &UnboundedSender<Event>,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    let (profile, account) = resolve(ctx, profile_id)?;
    if let Some(session) = valid_cached_session(ctx, &profile)? {
        return launch_game(ctx, &profile, &session, tx, cancel).await;
    }
    if let Some(session) =
        authenticate_and_register(ctx, &profile, &account, password, otp, tx).await?
    {
        launch_game(ctx, &profile, &session, tx, cancel).await?;
    }
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

/// The full authenticate → register step. Returns the launch-ready cached session, or `None` when a
/// terminal disposition (needs-otp/terms/service, needs-boot-patch, patches-pending, not-serviced)
/// was emitted and the flow should stop.
async fn authenticate_and_register(
    ctx: &FlowContext,
    profile: &Profile,
    account: &Account,
    password: Secret,
    otp: OtpSource,
    tx: &UnboundedSender<Event>,
) -> Result<Option<UidCacheEntry>, CoreError> {
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

    // Session registration.
    let report =
        VersionReport::from_install(&InstallPaths::new(&profile.game_path), auth.max_expansion)?;
    match register_session(&*ctx.transport, &auth, &report).await? {
        Registration::NeedsBootPatch => {
            emit(tx, FlowState::NeedsBootPatch);
            Ok(None)
        }
        Registration::VersionNotServiced => {
            emit(tx, FlowState::VersionNotServiced);
            Ok(None)
        }
        Registration::Registered {
            unique_id,
            pending_patches,
        } => {
            if !pending_patches.is_empty() {
                let bytes = pending_patches.iter().map(|p| p.length).sum();
                let count = u32::try_from(pending_patches.len()).unwrap_or(u32::MAX);
                emit(tx, FlowState::PatchesPending { count, bytes });
                return Ok(None);
            }
            let session = UidCacheEntry {
                unique_id: unique_id.expose().to_owned(),
                region: auth.region,
                max_expansion: auth.max_expansion,
                game_version: report.game_version().to_owned(),
                expires_at: (ctx.clock)() + UID_CACHE_TTL_SECS,
            };
            ctx.store.save_uid_cache(profile.account, &session)?;
            Ok(Some(session))
        }
    }
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
