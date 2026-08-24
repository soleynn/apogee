//! Early renderer selection and the two-part proof that the selected mode is visible.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

const RENDER_FILE: &str = "render.json";
#[cfg(unix)]
const RENDER_MARKER: &str = "APOGEE_RENDER_TIER";
const SAFE_RENDER_ENV: &str = "APOGEE_SAFE_RENDER";
const MACHINE_TIMEOUT: Duration = Duration::from_secs(2);
const HUMAN_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_TIER: u8 = 3;
const MAX_ESCALATIONS: u8 = 3;

#[cfg(unix)]
const TIER_VARIABLES: &[&str] = &[
    "__NV_DISABLE_EXPLICIT_SYNC",
    "WEBKIT_DISABLE_DMABUF_RENDERER",
    "WEBKIT_DISABLE_COMPOSITING_MODE",
    "LIBGL_ALWAYS_SOFTWARE",
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum RenderError {
    #[error("the launcher configuration directory is unavailable")]
    Config,
    #[error("render state at {path:?} could not be read or written")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("render state at {path:?} is corrupt")]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("render tier {value:?} is not one of 0, 1, 2, or 3")]
    InvalidTier { value: OsString },
    #[cfg(unix)]
    #[error("the render child marker does not match the persisted attempt")]
    MarkerMismatch,
    #[cfg(unix)]
    #[error("the launcher could not restart with render tier {tier}")]
    Exec {
        tier: u8,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RenderReason {
    Attempting,
    Confirmed,
    MachineTimeout,
    HumanTimeout,
    WindowClosed,
    BuilderFailed,
}

impl RenderReason {
    const fn code(self) -> &'static str {
        match self {
            Self::Attempting => "attempting",
            Self::Confirmed => "confirmed",
            Self::MachineTimeout => "machine_timeout",
            Self::HumanTimeout => "human_timeout",
            Self::WindowClosed => "window_closed",
            Self::BuilderFailed => "builder_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RenderRecord {
    attempted: u8,
    confirmed: Option<u8>,
    reason: RenderReason,
    session: RenderSessionType,
    driver: Option<String>,
    webkit_version: Option<String>,
    escalations: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "RenderSessionType.ts")]
pub(crate) enum RenderSessionType {
    Wayland,
    X11,
    Windows,
    Unknown,
}

impl RenderSessionType {
    const fn label(self) -> &'static str {
        match self {
            Self::Wayland => "wayland",
            Self::X11 => "x11",
            Self::Windows => "windows",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) const fn into_core(self) -> apogee_core::SessionType {
        match self {
            Self::Wayland => apogee_core::SessionType::Wayland,
            Self::X11 => apogee_core::SessionType::X11,
            Self::Windows => apogee_core::SessionType::Windows,
            Self::Unknown => apogee_core::SessionType::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderProbe {
    gpu: Option<String>,
    driver: Option<String>,
    session: RenderSessionType,
    webkit_version: Option<String>,
    proprietary_nvidia: bool,
    glx_vendor: Option<String>,
    dri_prime: Option<String>,
}

impl RenderProbe {
    fn from_host() -> Self {
        probe_with(
            Path::new("/sys"),
            |name| std::env::var_os(name),
            |path| fs::read_link(path).ok(),
        )
    }

    const fn starting_tier(&self) -> u8 {
        if self.proprietary_nvidia {
            match self.session {
                RenderSessionType::Wayland => 1,
                RenderSessionType::X11 => 2,
                RenderSessionType::Windows | RenderSessionType::Unknown => 0,
            }
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenderTier(u8);

impl RenderTier {
    fn new(value: u8) -> Option<Self> {
        (value <= MAX_TIER).then_some(Self(value))
    }

    const fn value(self) -> u8 {
        self.0
    }

    fn variables(self) -> Vec<(&'static str, &'static str)> {
        let mut vars = vec![("GTK_THEME", "Adwaita:dark")];
        if self.0 >= 1 {
            vars.push(("__NV_DISABLE_EXPLICIT_SYNC", "1"));
        }
        if self.0 >= 2 {
            vars.push(("WEBKIT_DISABLE_DMABUF_RENDERER", "1"));
        }
        if self.0 >= 3 {
            vars.push(("WEBKIT_DISABLE_COMPOSITING_MODE", "1"));
            vars.push(("LIBGL_ALWAYS_SOFTWARE", "1"));
        }
        vars
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderOverrides {
    report: bool,
    forced: Option<RenderTier>,
}

impl RenderOverrides {
    fn parse(args: &[OsString], safe_env: Option<&OsStr>) -> Result<Self, RenderError> {
        let mut report = false;
        let mut explicit = None;
        let mut safe = safe_env == Some(OsStr::new("1"));
        for arg in args {
            if arg == "--render-report" {
                report = true;
            } else if arg == "--safe-render" {
                safe = true;
            } else if let Some(value) = arg
                .to_str()
                .and_then(|value| value.strip_prefix("--render-tier="))
            {
                explicit = Some(parse_tier(OsStr::new(value))?);
            }
        }
        Ok(Self {
            report,
            forced: explicit.or_else(|| safe.then_some(RenderTier(MAX_TIER))),
        })
    }
}

fn parse_tier(value: &OsStr) -> Result<RenderTier, RenderError> {
    let tier = value
        .to_str()
        .and_then(|value| value.parse::<u8>().ok())
        .and_then(RenderTier::new)
        .ok_or_else(|| RenderError::InvalidTier {
            value: value.to_os_string(),
        })?;
    Ok(tier)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderPlan {
    Launch { tier: RenderTier, escalations: u8 },
    Terminal,
}

fn plan(
    previous: Option<&RenderRecord>,
    starting_tier: RenderTier,
    forced: Option<RenderTier>,
) -> RenderPlan {
    if let Some(tier) = forced {
        return RenderPlan::Launch {
            tier,
            escalations: previous.map_or(0, |record| record.escalations),
        };
    }
    let Some(previous) = previous else {
        return RenderPlan::Launch {
            tier: starting_tier,
            escalations: 0,
        };
    };
    if previous.reason == RenderReason::Confirmed {
        return RenderPlan::Launch {
            tier: RenderTier(previous.attempted),
            escalations: previous.escalations,
        };
    }
    if previous.attempted >= MAX_TIER || previous.escalations >= MAX_ESCALATIONS {
        return RenderPlan::Terminal;
    }
    RenderPlan::Launch {
        tier: RenderTier(previous.attempted.saturating_add(1).min(MAX_TIER)),
        escalations: previous.escalations.saturating_add(1).min(MAX_ESCALATIONS),
    }
}

/// The pre-window state retained through the Tauri event loop.
pub(crate) enum RenderPreflight {
    Continue(RenderMonitor),
    Exit(ExitCode),
}

pub(crate) fn preflight() -> Result<RenderPreflight, RenderError> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let overrides = RenderOverrides::parse(&args, std::env::var_os(SAFE_RENDER_ENV).as_deref())?;
    let path = render_path()?;
    if overrides.report {
        print_report(load_record(&path)?.as_ref());
        return Ok(RenderPreflight::Exit(ExitCode::SUCCESS));
    }

    let probe = RenderProbe::from_host();
    #[cfg(unix)]
    {
        if let Some(marker) = std::env::var_os(RENDER_MARKER) {
            let tier = parse_tier(&marker)?;
            let record = load_record(&path)?.ok_or(RenderError::MarkerMismatch)?;
            if record.attempted != tier.value() {
                return Err(RenderError::MarkerMismatch);
            }
            return Ok(RenderPreflight::Continue(RenderMonitor::new(
                path, record, probe,
            )));
        }

        let previous = load_record(&path)?;
        let starting_tier = RenderTier(probe.starting_tier());
        match plan(previous.as_ref(), starting_tier, overrides.forced) {
            RenderPlan::Terminal => {
                show_terminal_fallback();
                Ok(RenderPreflight::Exit(ExitCode::FAILURE))
            }
            RenderPlan::Launch { tier, escalations } => {
                let record = RenderRecord {
                    attempted: tier.value(),
                    confirmed: previous.as_ref().and_then(|value| value.confirmed),
                    reason: RenderReason::Attempting,
                    session: probe.session,
                    driver: probe.driver.clone(),
                    webkit_version: probe.webkit_version.clone(),
                    escalations,
                };
                save_record(&path, &record)?;
                exec_tier(tier, &args)
            }
        }
    }
    #[cfg(not(unix))]
    {
        let tier = RenderTier(0);
        let record = RenderRecord {
            attempted: tier.value(),
            confirmed: Some(tier.value()),
            reason: RenderReason::Confirmed,
            session: probe.session,
            driver: probe.driver.clone(),
            webkit_version: probe.webkit_version.clone(),
            escalations: 0,
        };
        Ok(RenderPreflight::Continue(RenderMonitor::new(
            path, record, probe,
        )))
    }
}

fn render_path() -> Result<PathBuf, RenderError> {
    apogee_core::CoreConfig::try_from_env()
        .map(|config| config.store_dir.join(RENDER_FILE))
        .map_err(|_| RenderError::Config)
}

fn load_record(path: &Path) -> Result<Option<RenderRecord>, RenderError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RenderError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let record = serde_json::from_slice(&bytes).map_err(|source| RenderError::Corrupt {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some(record))
}

fn save_record(path: &Path, record: &RenderRecord) -> Result<(), RenderError> {
    let parent = path.parent().ok_or_else(|| RenderError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other("render state has no parent directory"),
    })?;
    fs::create_dir_all(parent).map_err(|source| RenderError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary = parent.join(format!(".{RENDER_FILE}.{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(record).map_err(|source| RenderError::Corrupt {
        path: path.to_path_buf(),
        source,
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .map_err(|source| RenderError::Io {
            path: temporary.clone(),
            source,
        })?;
    file.write_all(&bytes).map_err(|source| RenderError::Io {
        path: temporary.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| RenderError::Io {
        path: temporary.clone(),
        source,
    })?;
    fs::rename(&temporary, path).map_err(|source| RenderError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(unix)]
fn exec_tier(tier: RenderTier, args: &[OsString]) -> Result<RenderPreflight, RenderError> {
    use std::os::unix::process::CommandExt;

    let executable = std::env::current_exe().map_err(|source| RenderError::Exec {
        tier: tier.value(),
        source,
    })?;
    let mut command = std::process::Command::new(executable);
    command.args(args);
    for variable in TIER_VARIABLES {
        command.env_remove(variable);
    }
    command.env(RENDER_MARKER, tier.value().to_string());
    for (name, value) in tier.variables() {
        command.env(name, value);
    }
    let source = command.exec();
    Err(RenderError::Exec {
        tier: tier.value(),
        source,
    })
}

#[cfg(target_os = "linux")]
fn show_terminal_fallback() {
    let _ = rfd::MessageDialog::new()
        .set_title("Apogee could not create a readable window")
        .set_description(
            "Start the launcher with --safe-render, or use apogee-cli to play without a window.\n\nFlatpak: flatpak override --user --env=APOGEE_SAFE_RENDER=1 io.github.soleynn.apogee",
        )
        .set_level(rfd::MessageLevel::Error)
        .show();
}

#[cfg(all(unix, not(target_os = "linux")))]
fn show_terminal_fallback() {
    eprintln!("Apogee could not create a readable window. Use --safe-render or apogee-cli.");
}

fn print_report(record: Option<&RenderRecord>) {
    if let Some(record) = record {
        println!("render_tier={}", record.attempted);
        println!("render_reason={}", record.reason.code());
        println!("render_escalation_count={}", record.escalations);
        println!("session_type={}", record.session.label());
        println!(
            "driver_version={}",
            record.driver.as_deref().unwrap_or("unknown")
        );
        println!(
            "webkitgtk_version={}",
            record.webkit_version.as_deref().unwrap_or("unknown")
        );
    } else {
        println!("render_report=unavailable");
    }
    println!("safe_render=--safe-render");
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "RenderStatus.ts")]
pub(crate) struct RenderStatusDto {
    tier: u8,
    reason: &'static str,
    escalations: u8,
    session: RenderSessionType,
    gpu: Option<String>,
    driver: Option<String>,
    webkit_version: Option<String>,
    glx_vendor: Option<String>,
    dri_prime: Option<String>,
    requires_confirmation: bool,
}

struct MonitorState {
    path: Option<PathBuf>,
    record: RenderRecord,
    probe: RenderProbe,
    machine_acknowledged: bool,
    human_acknowledged: bool,
    requires_human: bool,
    retry_requested: bool,
}

#[derive(Clone)]
pub(crate) struct RenderMonitor(Arc<Mutex<MonitorState>>);

impl RenderMonitor {
    fn new(path: PathBuf, record: RenderRecord, probe: RenderProbe) -> Self {
        let requires_human = record.confirmed != Some(record.attempted);
        Self(Arc::new(Mutex::new(MonitorState {
            path: Some(path),
            record,
            probe,
            machine_acknowledged: false,
            human_acknowledged: !requires_human,
            requires_human,
            retry_requested: false,
        })))
    }

    fn for_test(record: RenderRecord, probe: RenderProbe, requires_human: bool) -> Self {
        Self(Arc::new(Mutex::new(MonitorState {
            path: None,
            record,
            probe,
            machine_acknowledged: false,
            human_acknowledged: !requires_human,
            requires_human,
            retry_requested: false,
        })))
    }

    pub(crate) fn disabled() -> Self {
        let probe = RenderProbe {
            gpu: None,
            driver: None,
            session: if cfg!(windows) {
                RenderSessionType::Windows
            } else {
                RenderSessionType::Unknown
            },
            webkit_version: None,
            proprietary_nvidia: false,
            glx_vendor: None,
            dri_prime: None,
        };
        let record = RenderRecord {
            attempted: 0,
            confirmed: Some(0),
            reason: RenderReason::Confirmed,
            session: probe.session,
            driver: None,
            webkit_version: None,
            escalations: 0,
        };
        Self::for_test(record, probe, false)
    }

    pub(crate) fn title(&self) -> String {
        let tier = self.lock().record.attempted;
        if tier == 0 {
            "Apogee".to_owned()
        } else {
            format!("Apogee (render tier {tier})")
        }
    }

    pub(crate) fn tier(&self) -> u8 {
        self.lock().record.attempted
    }

    pub(crate) fn status(&self) -> RenderStatusDto {
        let state = self.lock();
        RenderStatusDto {
            tier: state.record.attempted,
            reason: state.record.reason.code(),
            escalations: state.record.escalations,
            session: state.record.session,
            gpu: state.probe.gpu.clone(),
            driver: state.record.driver.clone(),
            webkit_version: state.record.webkit_version.clone(),
            glx_vendor: state.probe.glx_vendor.clone(),
            dri_prime: state.probe.dri_prime.clone(),
            requires_confirmation: state.requires_human,
        }
    }

    pub(crate) fn legibility_reading(&self) -> apogee_core::LegibilityReading {
        let state = self.lock();
        apogee_core::LegibilityReading {
            gpu: state.probe.gpu.clone(),
            driver: state.record.driver.clone(),
            session: state.record.session.into_core(),
            render_tier: Some(state.record.attempted),
        }
    }

    pub(crate) fn support_facts(&self) -> Vec<(String, String)> {
        let state = self.lock();
        vec![
            ("render_tier".to_owned(), state.record.attempted.to_string()),
            (
                "render_reason".to_owned(),
                state.record.reason.code().to_owned(),
            ),
            (
                "render_escalation_count".to_owned(),
                state.record.escalations.to_string(),
            ),
            (
                "session_type".to_owned(),
                state.record.session.label().to_owned(),
            ),
            (
                "driver_version".to_owned(),
                state
                    .record
                    .driver
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            ),
            (
                "webkitgtk_version".to_owned(),
                state
                    .record
                    .webkit_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            ),
        ]
    }

    pub(crate) fn start(&self, app: tauri::AppHandle) {
        let machine = self.clone();
        let machine_app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(MACHINE_TIMEOUT).await;
            if machine.machine_missing() {
                machine.fail_and_exit(RenderReason::MachineTimeout, &machine_app);
            }
        });
        if self.lock().requires_human {
            let human = self.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(HUMAN_TIMEOUT).await;
                if human.human_missing() {
                    human.fail_and_exit(RenderReason::HumanTimeout, &app);
                }
            });
        }
    }

    pub(crate) fn acknowledge_machine(&self) -> Result<(), RenderError> {
        {
            let mut state = self.lock();
            state.machine_acknowledged = true;
        }
        self.confirm_if_complete()
    }

    pub(crate) fn acknowledge_human(&self) -> Result<(), RenderError> {
        {
            let mut state = self.lock();
            state.human_acknowledged = true;
        }
        self.confirm_if_complete()
    }

    pub(crate) fn record_window_closed(&self) -> Result<(), RenderError> {
        let state = self.lock();
        let failed = state.retry_requested;
        let requires_human = state.requires_human;
        drop(state);
        if requires_human && !failed {
            self.record_failure(RenderReason::WindowClosed)?;
        }
        Ok(())
    }

    pub(crate) fn record_builder_failure(&self) -> Result<(), RenderError> {
        self.record_failure(RenderReason::BuilderFailed)
    }

    pub(crate) fn retry_requested(&self) -> bool {
        self.lock().retry_requested
    }

    #[cfg(unix)]
    pub(crate) fn retry_exec(&self) -> Result<RenderPreflight, RenderError> {
        let state = self.lock();
        if state.record.attempted >= MAX_TIER || state.record.escalations >= MAX_ESCALATIONS {
            drop(state);
            show_terminal_fallback();
            return Ok(RenderPreflight::Exit(ExitCode::FAILURE));
        }
        let tier = RenderTier(state.record.attempted.saturating_add(1).min(MAX_TIER));
        let record = RenderRecord {
            attempted: tier.value(),
            confirmed: state.record.confirmed,
            reason: RenderReason::Attempting,
            session: state.probe.session,
            driver: state.probe.driver.clone(),
            webkit_version: state.probe.webkit_version.clone(),
            escalations: state
                .record
                .escalations
                .saturating_add(1)
                .min(MAX_ESCALATIONS),
        };
        let path = state.path.clone().ok_or(RenderError::MarkerMismatch)?;
        drop(state);
        save_record(&path, &record)?;
        let args = std::env::args_os().skip(1).collect::<Vec<_>>();
        exec_tier(tier, &args)
    }

    fn machine_missing(&self) -> bool {
        let state = self.lock();
        !state.machine_acknowledged && !state.retry_requested
    }

    fn human_missing(&self) -> bool {
        let state = self.lock();
        state.requires_human && !state.human_acknowledged && !state.retry_requested
    }

    fn confirm_if_complete(&self) -> Result<(), RenderError> {
        let mut state = self.lock();
        if !state.machine_acknowledged || !state.human_acknowledged || state.retry_requested {
            return Ok(());
        }
        state.record.confirmed = Some(state.record.attempted);
        state.record.reason = RenderReason::Confirmed;
        state.requires_human = false;
        if let Some(path) = state.path.as_deref() {
            save_record(path, &state.record)?;
        }
        Ok(())
    }

    fn record_failure(&self, reason: RenderReason) -> Result<(), RenderError> {
        let mut state = self.lock();
        state.record.reason = reason;
        state.retry_requested = true;
        if let Some(path) = state.path.as_deref() {
            save_record(path, &state.record)?;
        }
        Ok(())
    }

    fn fail_and_exit(&self, reason: RenderReason, app: &tauri::AppHandle) {
        if let Err(error) = self.record_failure(reason) {
            tracing::error!(%error, "could not persist the failed renderer attempt");
        }
        app.exit(75);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MonitorState> {
        match self.0.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[tauri::command]
pub(crate) async fn render_status(
    state: tauri::State<'_, crate::ShellState>,
) -> Result<RenderStatusDto, crate::IpcErrorDto> {
    Ok(state.render.status())
}

#[tauri::command]
pub(crate) async fn render_ok(
    state: tauri::State<'_, crate::ShellState>,
) -> Result<(), crate::IpcErrorDto> {
    state
        .render
        .acknowledge_machine()
        .map_err(|_| crate::IpcErrorDto::shell("shell.render.persist-failed"))
}

#[tauri::command]
pub(crate) async fn confirm_render(
    state: tauri::State<'_, crate::ShellState>,
) -> Result<(), crate::IpcErrorDto> {
    state
        .render
        .acknowledge_human()
        .map_err(|_| crate::IpcErrorDto::shell("shell.render.persist-failed"))
}

fn probe_with<F, L>(sys_root: &Path, env: F, read_link: L) -> RenderProbe
where
    F: Fn(&str) -> Option<OsString>,
    L: Fn(&Path) -> Option<PathBuf>,
{
    let session = session_type(&env);
    let mut proprietary_nvidia = false;
    let mut gpu = None;
    let drm = sys_root.join("class/drm");
    if let Ok(entries) = fs::read_dir(&drm) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(index) = name.strip_prefix("card") else {
                continue;
            };
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let driver = entry.path().join("device/driver");
            let is_nvidia = read_link(&driver)
                .and_then(|path| path.file_name().map(OsStr::to_owned))
                .is_some_and(|name| name == "nvidia");
            if is_nvidia {
                proprietary_nvidia = true;
                let device = fs::read_to_string(entry.path().join("device/device"))
                    .ok()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty());
                gpu = Some(
                    device.map_or_else(|| "NVIDIA".to_owned(), |device| format!("NVIDIA {device}")),
                );
            }
        }
    }
    let driver = proprietary_nvidia
        .then(|| fs::read_to_string(sys_root.join("module/nvidia/version")).ok())
        .flatten()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    RenderProbe {
        gpu,
        driver,
        session,
        webkit_version: webkit_version(),
        proprietary_nvidia,
        glx_vendor: env("__GLX_VENDOR_LIBRARY_NAME").and_then(|value| value.into_string().ok()),
        dri_prime: env("DRI_PRIME").and_then(|value| value.into_string().ok()),
    }
}

fn session_type<F>(env: &F) -> RenderSessionType
where
    F: Fn(&str) -> Option<OsString>,
{
    if cfg!(windows) {
        return RenderSessionType::Windows;
    }
    match env("XDG_SESSION_TYPE").as_deref() {
        Some(value) if value.eq_ignore_ascii_case("wayland") => RenderSessionType::Wayland,
        Some(value) if value.eq_ignore_ascii_case("x11") => RenderSessionType::X11,
        _ if env("WAYLAND_DISPLAY").is_some() => RenderSessionType::Wayland,
        _ if env("DISPLAY").is_some() => RenderSessionType::X11,
        _ => RenderSessionType::Unknown,
    }
}

#[cfg(target_os = "linux")]
fn webkit_version() -> Option<String> {
    wry::webview_version().ok()
}

#[cfg(not(target_os = "linux"))]
fn webkit_version() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(session: RenderSessionType, nvidia: bool) -> RenderProbe {
        RenderProbe {
            gpu: nvidia.then(|| "NVIDIA".to_owned()),
            driver: nvidia.then(|| "555.1".to_owned()),
            session,
            webkit_version: Some("2.48".to_owned()),
            proprietary_nvidia: nvidia,
            glx_vendor: None,
            dri_prime: None,
        }
    }

    fn record(tier: u8, reason: RenderReason, escalations: u8) -> RenderRecord {
        RenderRecord {
            attempted: tier,
            confirmed: (reason == RenderReason::Confirmed).then_some(tier),
            reason,
            session: RenderSessionType::Wayland,
            driver: None,
            webkit_version: None,
            escalations,
        }
    }

    #[test]
    fn starting_tier_uses_every_nvidia_session_rule() {
        assert_eq!(probe(RenderSessionType::Wayland, true).starting_tier(), 1);
        assert_eq!(probe(RenderSessionType::X11, true).starting_tier(), 2);
        assert_eq!(probe(RenderSessionType::Unknown, true).starting_tier(), 0);
        assert_eq!(probe(RenderSessionType::Wayland, false).starting_tier(), 0);
    }

    #[test]
    fn tiers_are_cumulative_and_software_is_the_last_rung() {
        assert_eq!(RenderTier(0).variables(), [("GTK_THEME", "Adwaita:dark")]);
        assert_eq!(
            RenderTier(3).variables(),
            [
                ("GTK_THEME", "Adwaita:dark"),
                ("__NV_DISABLE_EXPLICIT_SYNC", "1"),
                ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
                ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
                ("LIBGL_ALWAYS_SOFTWARE", "1"),
            ]
        );
    }

    #[test]
    fn planner_reuses_confirmation_and_escalates_only_failed_attempts() {
        assert_eq!(
            plan(None, RenderTier(1), None),
            RenderPlan::Launch {
                tier: RenderTier(1),
                escalations: 0
            }
        );
        assert_eq!(
            plan(
                Some(&record(1, RenderReason::Confirmed, 1)),
                RenderTier(0),
                None
            ),
            RenderPlan::Launch {
                tier: RenderTier(1),
                escalations: 1
            }
        );
        assert_eq!(
            plan(
                Some(&record(1, RenderReason::MachineTimeout, 1)),
                RenderTier(0),
                None
            ),
            RenderPlan::Launch {
                tier: RenderTier(2),
                escalations: 2
            }
        );
        assert_eq!(
            plan(
                Some(&record(3, RenderReason::HumanTimeout, 2)),
                RenderTier(0),
                None
            ),
            RenderPlan::Terminal
        );
    }

    #[test]
    fn explicit_tier_wins_over_safe_mode_and_bad_values_fail_closed() {
        let args = [
            OsString::from("--safe-render"),
            OsString::from("--render-tier=2"),
        ];
        let parsed = RenderOverrides::parse(&args, Some(OsStr::new("1"))).unwrap();
        assert_eq!(parsed.forced, Some(RenderTier(2)));
        assert!(RenderOverrides::parse(&[OsString::from("--render-tier=4")], None).is_err());
    }

    #[test]
    fn persisted_state_round_trips_and_corruption_is_not_defaulted() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join(RENDER_FILE);
        let expected = record(2, RenderReason::Confirmed, 1);
        save_record(&path, &expected).unwrap();
        assert_eq!(load_record(&path).unwrap(), Some(expected));
        fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            load_record(&path),
            Err(RenderError::Corrupt { .. })
        ));
    }

    #[test]
    fn probe_checks_all_cards_and_excludes_nouveau() {
        let temp = tempfile::TempDir::new().unwrap();
        let sys = temp.path();
        let drm = sys.join("class/drm");
        fs::create_dir_all(drm.join("card0/device")).unwrap();
        fs::create_dir_all(drm.join("card1/device")).unwrap();
        fs::write(drm.join("card1/device/device"), "0x1234\n").unwrap();
        fs::create_dir_all(sys.join("module/nvidia")).unwrap();
        fs::write(sys.join("module/nvidia/version"), "555.42\n").unwrap();

        let observed = probe_with(
            sys,
            |name| (name == "XDG_SESSION_TYPE").then(|| OsString::from("wayland")),
            |path| {
                if path.ends_with("card0/device/driver") {
                    Some(PathBuf::from("nouveau"))
                } else if path.ends_with("card1/device/driver") {
                    Some(PathBuf::from("nvidia"))
                } else {
                    None
                }
            },
        );
        assert!(observed.proprietary_nvidia);
        assert_eq!(observed.gpu.as_deref(), Some("NVIDIA 0x1234"));
        assert_eq!(observed.driver.as_deref(), Some("555.42"));
        assert_eq!(observed.starting_tier(), if cfg!(windows) { 0 } else { 1 });
    }

    #[test]
    fn machine_and_human_acknowledgements_are_distinct() {
        let mut pending = record(1, RenderReason::Attempting, 0);
        pending.confirmed = Some(0);
        let monitor =
            RenderMonitor::for_test(pending, probe(RenderSessionType::Wayland, true), true);
        monitor.acknowledge_machine().unwrap();
        assert_eq!(monitor.status().reason, "attempting");
        assert!(monitor.status().requires_confirmation);
        monitor.acknowledge_human().unwrap();
        assert_eq!(monitor.status().reason, "confirmed");
        assert!(!monitor.status().requires_confirmation);
    }

    #[test]
    fn support_facts_are_the_fixed_native_six() {
        let monitor = RenderMonitor::for_test(
            record(2, RenderReason::Confirmed, 1),
            probe(RenderSessionType::X11, true),
            false,
        );
        let facts = monitor.support_facts();
        assert_eq!(facts.len(), 6);
        assert_eq!(facts[0], ("render_tier".to_owned(), "2".to_owned()));
        assert_eq!(facts[3], ("session_type".to_owned(), "wayland".to_owned()));
    }
}
