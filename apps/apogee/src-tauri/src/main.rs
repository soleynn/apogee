#![forbid(unsafe_code)]
// Keeps a console window from opening beside the window on Windows. Only in a release build, so a
// debug run still has somewhere to print.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! The desktop shell: one window, the frontend it loads, and the commands that frontend invokes.
//!
//! It holds no launcher rules. What it does is issue commands to `apogee-core` and render the events
//! that come back, and the types it puts on the wire are declared here rather than borrowed from the
//! domain model, so the JSON the frontend binds to is this crate's to change.
//!
//! The startup snapshot and primary login-to-play flow are the first implemented slice.

mod command;
mod dto;
mod supervisor;

use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use apogee_core::{Core, CoreConfig, Region, StableCode, Uuid};
use serde::Serialize;
use tauri::Manager;
use tauri::ipc::Channel;

use command::CommandDto;
use dto::EventDto;
use supervisor::Runs;

/// The first thing the frontend asks for.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Startup {
    /// This binary's version, as its manifest declares it.
    version: &'static str,
    /// The service region a profile connects to when nothing has chosen one.
    default_region: &'static str,
}

#[tauri::command]
fn startup() -> Startup {
    Startup {
        version: env!("CARGO_PKG_VERSION"),
        default_region: region_label(Region::default()),
    }
}

enum CoreStatus {
    Starting,
    Ready(Arc<Core>),
    Failed(&'static str),
}

struct ShellState {
    core: Mutex<CoreStatus>,
    runs: Runs,
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            core: Mutex::new(CoreStatus::Starting),
            runs: Runs::default(),
        }
    }
}

impl ShellState {
    fn install_core(&self, core: Result<Core, apogee_core::CoreError>) {
        if let Ok(mut slot) = self.core.lock() {
            *slot = match core {
                Ok(core) => CoreStatus::Ready(Arc::new(core)),
                Err(error) => CoreStatus::Failed(error.code()),
            };
        }
    }

    fn ready_core(&self) -> Result<Arc<Core>, ShellError> {
        let slot = self
            .core
            .lock()
            .map_err(|_| ShellError::new("shell.state.unavailable"))?;
        match &*slot {
            CoreStatus::Starting => Err(ShellError::new("shell.core.starting")),
            CoreStatus::Ready(core) => Ok(Arc::clone(core)),
            CoreStatus::Failed(code) => Err(ShellError::new(code)),
        }
    }
}

/// A failure at the IPC boundary. Only a stable code crosses; core's display text can carry paths
/// and protocol excerpts and is never serialized here.
#[derive(Serialize)]
struct ShellError {
    code: &'static str,
}

impl ShellError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

/// Start one core command and relay its event stream over `on_event` until core closes it.
#[tauri::command]
async fn execute(
    state: tauri::State<'_, ShellState>,
    run_id: Uuid,
    command: CommandDto,
    on_event: Channel<EventDto>,
) -> Result<(), ShellError> {
    let core = state.ready_core()?;
    let cancel = state
        .runs
        .start(run_id)
        .map_err(|_| ShellError::new("shell.run.duplicate"))?;
    supervisor::drive(core.as_ref(), command.into_core(), cancel, &on_event).await;
    state.runs.finish(run_id);
    Ok(())
}

/// Ask a running core command to stop at its cancellation boundary.
#[tauri::command]
async fn cancel(state: tauri::State<'_, ShellState>, run_id: Uuid) -> Result<bool, ShellError> {
    state
        .runs
        .cancel(run_id)
        .map_err(|_| ShellError::new("shell.state.unavailable"))
}

/// The wildcard arm is required rather than defensive: `Region` is `#[non_exhaustive]`, so a variant
/// added to the domain model has to reach a frontend built before it existed.
fn region_label(region: Region) -> &'static str {
    match region {
        Region::Global => "global",
        Region::Korea => "korea",
        Region::China => "china",
        _ => "unknown",
    }
}

fn main() -> ExitCode {
    // The context macro builds the window's context on a thread of its own, for the larger stack,
    // and ends the process itself if that thread panics. Nothing here can reach around that, so the
    // one lint the table denies is carved out over the one statement that expands the macro. It is
    // an `expect` rather than an `allow` so that the day the macro stops doing it, this line is
    // reported as no longer needed instead of sitting here unread.
    #[expect(
        clippy::exit,
        reason = "the context macro's own failure path ends the process"
    )]
    let context = tauri::generate_context!();

    match tauri::Builder::default()
        .manage(ShellState::default())
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn_blocking(move || {
                let core = CoreConfig::try_from_env().and_then(Core::new);
                handle.state::<ShellState>().install_core(core);
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![startup, execute, cancel])
        .run(context)
    {
        Ok(()) => ExitCode::SUCCESS,
        // A return code rather than a panic: the builder fails on a window that cannot be created,
        // which is the condition the render fallback reads to try the next way of drawing one.
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_region_has_a_label() {
        assert_eq!(region_label(Region::Global), "global");
        assert_eq!(region_label(Region::Korea), "korea");
        assert_eq!(region_label(Region::China), "china");
    }

    #[test]
    fn the_default_region_reaches_the_frontend_named() {
        let startup = startup();
        assert_eq!(startup.default_region, "global");
        assert_eq!(startup.version, env!("CARGO_PKG_VERSION"));
    }
}
