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
//! Startup store reads and the complete command/event stream use the same core instance.

mod command;
mod direct;
mod dto;
mod mutation;
mod passphrase;
mod secrets;
mod supervisor;

use std::future::Future;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use apogee_core::{Core, CoreConfig, Uuid};
use tauri::ipc::Channel;
use tauri::{Emitter, Manager};
use tokio::sync::{Notify, OnceCell, OwnedSemaphorePermit, Semaphore};

use command::CommandDto;
use dto::secrets::SecretsReportDto;
use dto::startup::StartupDto;
use dto::{EventWireDto, IpcErrorDto};
use supervisor::{RunAdmissionError, RunClass, Runs};

// One declaration feeds both Tauri's handler and the parity test. Adding an IPC command in only one
// place is therefore impossible: the committed shell/CLI table must grow before this crate passes.
macro_rules! ipc_surface {
    ($consumer:ident) => {
        $consumer! {
            startup,
            secrets_report,
            direct::next_action,
            direct::defaults,
            direct::resolved_setup,
            direct::runner_catalog,
            direct::dxvk_catalog,
            direct::system_report,
            direct::support_bundle_contents,
            secrets::secrets_file_status,
            secrets::unlock_secrets_file,
            secrets::create_secrets_file,
            secrets::change_secrets_file_passphrase,
            secrets::remove_secrets_file,
            secrets::seal_secrets_file,
            secrets::answer_passphrase_prompt,
            mutation::update_account,
            mutation::update_profile,
            mutation::update_settings,
            mutation::store_password,
            mutation::import_totp_secret,
            mutation::use_pushed_codes,
            mutation::disable_pushed_codes,
            mutation::delete_secret,
            mutation::forget_secrets,
            mutation::set_never_store,
            mutation::plan_profile_removal,
            mutation::cancel_profile_removal,
            mutation::remove_profile,
            execute,
            cancel,
        }
    };
}

macro_rules! tauri_handler {
    ($($handler:path),+ $(,)?) => {
        tauri::generate_handler![$($handler),+]
    };
}

#[cfg(test)]
macro_rules! handler_paths {
    ($($handler:path),+ $(,)?) => {
        &[$(stringify!($handler)),+]
    };
}

#[cfg(test)]
const IPC_HANDLER_PATHS: &[&str] = ipc_surface!(handler_paths);

struct TauriPromptEmitter {
    handle: tauri::AppHandle,
}

impl passphrase::PromptEmitter for TauriPromptEmitter {
    fn emit(
        &self,
        event: &'static str,
        prompt: &passphrase::PassphrasePromptDto,
    ) -> Result<(), passphrase::PromptEmitError> {
        self.handle
            .emit_to("main", event, prompt)
            .map_err(|_| passphrase::PromptEmitError::new())
    }
}

enum CoreStatus {
    Starting,
    Ready(Arc<Core>),
    Failed(IpcErrorDto),
}

struct ShellState {
    core: Mutex<CoreStatus>,
    core_ready: Notify,
    #[cfg(test)]
    core_waiting: Notify,
    startup: OnceCell<StartupDto>,
    direct_reads: Arc<Semaphore>,
    passphrases: Arc<passphrase::PromptBroker>,
    removal_plans: Arc<mutation::RemovalPlans>,
    runs: Runs,
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            core: Mutex::new(CoreStatus::Starting),
            core_ready: Notify::new(),
            #[cfg(test)]
            core_waiting: Notify::new(),
            startup: OnceCell::new(),
            direct_reads: Arc::new(Semaphore::new(4)),
            passphrases: Arc::new(passphrase::PromptBroker::default()),
            removal_plans: Arc::new(mutation::RemovalPlans::default()),
            runs: Runs::default(),
        }
    }
}

impl ShellState {
    #[cfg(test)]
    fn install_core(&self, core: Result<Core, apogee_core::CoreError>) {
        self.install_core_result(core.map_err(|error| IpcErrorDto::core(&error)));
    }

    fn install_core_result(&self, core: Result<Core, IpcErrorDto>) {
        let mut slot = match self.core.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = match core {
            Ok(core) => CoreStatus::Ready(Arc::new(core)),
            Err(error) => CoreStatus::Failed(error),
        };
        drop(slot);
        self.core_ready.notify_waiters();
    }

    fn install_core_failure(&self, error: IpcErrorDto) {
        let mut slot = match self.core.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = CoreStatus::Failed(error);
        drop(slot);
        self.core_ready.notify_waiters();
    }

    async fn ready_core(&self) -> Result<Arc<Core>, IpcErrorDto> {
        loop {
            let ready = self.core_ready.notified();
            {
                let slot = match self.core.lock() {
                    Ok(slot) => slot,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match &*slot {
                    CoreStatus::Starting => {
                        #[cfg(test)]
                        self.core_waiting.notify_waiters();
                    }
                    CoreStatus::Ready(core) => return Ok(Arc::clone(core)),
                    CoreStatus::Failed(error) => return Err(error.clone()),
                }
            }
            ready.await;
        }
    }

    async fn initial_snapshot(&self) -> Result<StartupDto, IpcErrorDto> {
        self.startup
            .get_or_try_init(|| async {
                let core = self.ready_core().await?;
                run_blocking(move || StartupDto::read(&core)).await?
            })
            .await
            .cloned()
    }

    async fn ready_core_after<T, B>(&self, bootstrap: B) -> Result<Arc<Core>, IpcErrorDto>
    where
        B: Future<Output = Result<T, IpcErrorDto>>,
    {
        bootstrap.await?;
        self.ready_core().await
    }

    async fn ready_core_for_direct_read(
        &self,
    ) -> Result<(Arc<Core>, OwnedSemaphorePermit), IpcErrorDto> {
        let core = self.ready_core().await?;
        let permit = Arc::clone(&self.direct_reads)
            .acquire_owned()
            .await
            .map_err(|_| IpcErrorDto::shell("shell.state.unavailable"))?;
        Ok((core, permit))
    }

    fn mutation_lease(&self) -> Result<supervisor::MutationLease, IpcErrorDto> {
        self.runs.start_mutation().map_err(run_admission_error)
    }
}

/// Read the complete local store only after composition finishes. Failed reads remain retryable
/// after recovery; the first successful snapshot is fixed before any flow starts.
#[tauri::command]
async fn startup(state: tauri::State<'_, ShellState>) -> Result<StartupDto, IpcErrorDto> {
    startup_snapshot(&state).await
}

async fn startup_snapshot(state: &ShellState) -> Result<StartupDto, IpcErrorDto> {
    state.initial_snapshot().await
}

/// Probe the configured credential backend away from the window thread.
#[tauri::command]
async fn secrets_report(
    state: tauri::State<'_, ShellState>,
) -> Result<SecretsReportDto, IpcErrorDto> {
    secrets_report_snapshot(&state).await
}

async fn secrets_report_snapshot(state: &ShellState) -> Result<SecretsReportDto, IpcErrorDto> {
    let (core, _permit) = state.ready_core_for_direct_read().await?;
    run_blocking(move || SecretsReportDto::new(&core.secrets_report(), core.secrets_path())).await
}

async fn run_blocking<T, F>(task: F) -> Result<T, IpcErrorDto>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|_| IpcErrorDto::shell("shell.task.failed"))
}

async fn initialize_state<T, F, I>(state: &ShellState, task: F, install: I)
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    I: FnOnce(&ShellState, T),
{
    match run_blocking(task).await {
        Ok(value) => install(state, value),
        Err(error) => state.install_core_failure(error),
    }
}

/// Start one core command and relay its event stream over `on_event` until core closes it.
#[tauri::command]
async fn execute(
    state: tauri::State<'_, ShellState>,
    command: CommandDto,
    on_event: Channel<EventWireDto>,
) -> Result<Uuid, IpcErrorDto> {
    // Consume credential bytes before touching any other state, so the IPC allocation is guarded by
    // core's write-only Secret for the rest of the command body.
    let command = command
        .into_core()
        .map_err(|_| IpcErrorDto::shell("shell.command.invalid"))?;
    let class = RunClass::for_command(&command);
    // The first store snapshot is the bootstrap boundary. No mutating flow starts before it has read
    // a single pre-flow view of every startup record.
    let core = state.ready_core_after(state.initial_snapshot()).await?;
    let run_id = Uuid::new_v4();
    let lease = state
        .runs
        .start(run_id, class)
        .map_err(run_admission_error)?;
    let cancel = lease.cancellation();
    tauri::async_runtime::spawn(async move {
        supervisor::drive(core.as_ref(), command, cancel, &on_event).await;
        drop(lease);
    });
    Ok(run_id)
}

fn run_admission_error(error: RunAdmissionError) -> IpcErrorDto {
    match error {
        RunAdmissionError::Duplicate => IpcErrorDto::shell("shell.run.duplicate"),
        RunAdmissionError::Busy => IpcErrorDto::shell("shell.run.busy"),
        RunAdmissionError::Unavailable => IpcErrorDto::shell("shell.state.unavailable"),
    }
}

/// Ask a running core command to stop at its cancellation boundary.
#[tauri::command]
async fn cancel(state: tauri::State<'_, ShellState>, run_id: Uuid) -> Result<bool, IpcErrorDto> {
    state
        .runs
        .cancel(run_id)
        .map_err(|_| IpcErrorDto::shell("shell.state.unavailable"))
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
            let state = app.state::<ShellState>();
            let passphrase = Arc::new(passphrase::WebviewPassphrase::new(
                Arc::clone(&state.passphrases),
                Arc::new(TauriPromptEmitter {
                    handle: handle.clone(),
                }),
                std::thread::current().id(),
            ));
            tauri::async_runtime::spawn(async move {
                let state = handle.state::<ShellState>();
                initialize_state(
                    &state,
                    move || {
                        let config = CoreConfig::try_from_env()
                            .map_err(|error| IpcErrorDto::core(&error))?;
                        Core::with_passphrase(config, passphrase)
                            .map_err(|error| IpcErrorDto::core(&error))
                    },
                    ShellState::install_core_result,
                )
                .await;
            });
            Ok(())
        })
        .invoke_handler(ipc_surface!(tauri_handler))
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
    use std::collections::BTreeSet;

    use serde::Deserialize;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Deserialize)]
    struct ParityManifest {
        commands: Vec<ParityRow>,
    }

    #[derive(Deserialize)]
    struct ParityRow {
        ipc: String,
        #[serde(default)]
        cli: Vec<Vec<String>>,
        #[serde(default)]
        operations: Vec<ParityOperation>,
        shell_local: Option<String>,
        equivalence: String,
    }

    #[derive(Deserialize)]
    struct ParityOperation {
        shell: String,
        cli: Vec<Vec<String>>,
        equivalence: String,
    }

    #[test]
    fn every_registered_ipc_command_has_one_exact_parity_row() -> TestResult {
        let manifest: ParityManifest = serde_json::from_str(include_str!("../../ipc-parity.json"))?;
        let registered: BTreeSet<&str> = IPC_HANDLER_PATHS
            .iter()
            .filter_map(|path| path.rsplit("::").next().map(str::trim))
            .collect();
        let declared: BTreeSet<&str> = manifest
            .commands
            .iter()
            .map(|row| row.ipc.as_str())
            .collect();

        assert_eq!(
            declared.len(),
            manifest.commands.len(),
            "an IPC command appears more than once in the parity table"
        );
        assert_eq!(registered, declared);
        for row in manifest.commands {
            let has_cli = !row.cli.is_empty() && row.cli.iter().all(|route| !route.is_empty());
            let has_operations = !row.operations.is_empty()
                && row.operations.iter().all(|operation| {
                    !operation.shell.trim().is_empty()
                        && !operation.equivalence.trim().is_empty()
                        && !operation.cli.is_empty()
                        && operation.cli.iter().all(|route| !route.is_empty())
                });
            let has_shell_reason = row
                .shell_local
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty());
            assert!(
                usize::from(has_cli) + usize::from(has_operations) + usize::from(has_shell_reason)
                    == 1,
                "{} must have direct CLI routes, leaf operations, or one shell-local justification, exclusively",
                row.ipc
            );
            assert!(
                !row.equivalence.trim().is_empty(),
                "{} does not state why its CLI route is equivalent",
                row.ipc
            );
            if row.ipc == "execute" {
                let operations: BTreeSet<_> = row
                    .operations
                    .iter()
                    .map(|operation| operation.shell.clone())
                    .collect();
                assert_eq!(
                    operations.len(),
                    row.operations.len(),
                    "an execute operation appears more than once in the parity table"
                );
                assert_eq!(command::operation_ids(), operations);
            } else {
                assert!(
                    row.operations.is_empty(),
                    "{} owns unexpected leaf operations",
                    row.ipc
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn startup_waits_for_core_initialization() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let config = CoreConfig::with_base(temporary.path());
        std::fs::create_dir_all(&config.store_dir)?;
        std::fs::write(config.store_dir.join("settings.json"), b"not-json")?;
        let state = Arc::new(ShellState::default());
        let observed = state.core_waiting.notified();
        let waiting = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { startup_snapshot(&state).await })
        };
        observed.await;
        assert!(!waiting.is_finished());

        state.install_core(Core::new(config));
        let result = waiting.await?;
        let Err(error) = result else {
            return Err(std::io::Error::other("corrupt startup unexpectedly succeeded").into());
        };
        let json = serde_json::to_string(&error)?;
        assert!(json.contains("err-store"));
        assert!(!json.contains("shell.core.starting"));
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_gate_blocks_core_access_until_the_snapshot_boundary() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        let state = Arc::new(ShellState::default());
        state.install_core(Ok(core));
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let gated = {
            let state = Arc::clone(&state);
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                state
                    .ready_core_after(async move {
                        entered.wait().await;
                        released
                            .await
                            .map_err(|_| IpcErrorDto::shell("shell.test.release"))?;
                        Ok(())
                    })
                    .await
            })
        };

        entered.wait().await;
        assert!(!gated.is_finished());
        assert!(release.send(()).is_ok());
        assert!(gated.await?.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn startup_reads_an_empty_store_and_core_defaults() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        let state = ShellState::default();
        state.install_core(Ok(core));

        let snapshot = startup_snapshot(&state).await.map_err(ipc_test_error)?;
        let json = serde_json::to_string(&snapshot)?;
        assert!(json.contains(r#""profiles":[]"#));
        assert!(json.contains(r#""accounts":[]"#));
        assert!(json.contains(r#""region":"global""#));
        assert!(json.contains(env!("CARGO_PKG_VERSION")));
        Ok(())
    }

    #[tokio::test]
    async fn blocking_core_reads_leave_the_async_caller_thread() -> TestResult {
        let caller = std::thread::current().id();
        let worker = run_blocking(|| std::thread::current().id())
            .await
            .map_err(ipc_test_error)?;

        assert_ne!(worker, caller);
        Ok(())
    }

    #[tokio::test]
    async fn direct_core_reads_have_a_bounded_blocking_budget() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        let state = Arc::new(ShellState::default());
        state.install_core(Ok(core));
        let mut admitted = Vec::new();
        for _ in 0..4 {
            admitted.push(
                state
                    .ready_core_for_direct_read()
                    .await
                    .map_err(ipc_test_error)?,
            );
        }
        let waiting = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.ready_core_for_direct_read().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());

        admitted.pop();
        assert!(waiting.await?.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn panicking_core_initialization_is_a_terminal_failure() -> TestResult {
        let state = Arc::new(ShellState::default());
        let waiting = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.ready_core().await })
        };

        initialize_state(
            &state,
            || std::panic::resume_unwind(Box::new("construction failed")),
            |_, ()| {},
        )
        .await;

        let Err(error) = waiting.await? else {
            return Err(std::io::Error::other("panicking initialization became ready").into());
        };
        assert_eq!(
            serde_json::to_string(&error)?,
            r#"{"code":"shell.task.failed","error":null}"#
        );
        Ok(())
    }

    #[tokio::test]
    async fn poisoned_core_slot_can_still_publish_and_read_a_terminal_state() -> TestResult {
        let state = Arc::new(ShellState::default());
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let state = Arc::clone(&state);
            move || {
                let _slot = match state.core.lock() {
                    Ok(slot) => slot,
                    Err(poisoned) => poisoned.into_inner(),
                };
                std::panic::resume_unwind(Box::new("poison core slot"));
            }
        }));
        assert!(poisoned.is_err());

        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        state.install_core(Ok(core));

        assert!(state.ready_core().await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn startup_projects_saved_records_without_replacing_core_defaults() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        let account = apogee_core::Account::new(
            "person@example.invalid",
            apogee_core::AccountKind::Steam { app_id: 39_210 },
        );
        core.save_account(&account)?;
        let mut profile =
            apogee_core::Profile::new("Main", account.id, temporary.path().join("game"));
        profile.launch.region = apogee_core::Region::Korea;
        core.save_profile(&profile)?;
        let mut settings = core.settings()?;
        settings.language = "ja".to_owned();
        settings.close_after_launch = true;
        core.save_settings(&settings)?;
        let state = ShellState::default();
        state.install_core(Ok(core));

        let snapshot = startup_snapshot(&state).await.map_err(ipc_test_error)?;
        let json = serde_json::to_string(&snapshot)?;
        assert!(json.contains("person@example.invalid"));
        assert!(json.contains(r#""name":"Main""#));
        assert!(json.contains(r#""language":"ja""#));
        assert!(json.contains(r#""closeAfterLaunch":true"#));
        assert!(json.contains(r#""region":"korea""#));
        assert!(json.contains(r#""region":"global""#));
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_startup_store_keeps_recovery_paths_and_omits_detail() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let config = CoreConfig::with_base(temporary.path());
        std::fs::create_dir_all(&config.store_dir)?;
        let settings = config.store_dir.join("settings.json");
        let store_dir = config.store_dir.clone();
        std::fs::write(&settings, br#"{"token":"planted-secret"}"#)?;
        let state = ShellState::default();
        state.install_core(Core::new(config));

        let Err(error) = startup_snapshot(&state).await else {
            return Err(std::io::Error::other("corrupt settings unexpectedly loaded").into());
        };
        let json = serde_json::to_string(&error)?;
        assert!(json.contains("err-store"));
        assert!(json.contains(r#""kind":"corrupt""#));
        assert!(json.contains(r#""display":"#));
        assert!(json.contains("settings.json"));
        assert!(!json.contains("planted-secret"));
        assert!(settings.exists());
        let has_backup = std::fs::read_dir(store_dir)?
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt"));
        assert!(has_backup);

        std::fs::remove_file(settings)?;
        assert!(startup_snapshot(&state).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn profile_corruption_after_core_construction_reaches_startup_recovery() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let config = CoreConfig::with_base(temporary.path());
        let profiles = config.store_dir.join("profiles");
        let core = Core::new(config)?;
        std::fs::create_dir_all(&profiles)?;
        let profile = profiles.join("broken.json");
        std::fs::write(&profile, br#"{"token":"planted-secret"}"#)?;
        let state = ShellState::default();
        state.install_core(Ok(core));

        let Err(error) = startup_snapshot(&state).await else {
            return Err(std::io::Error::other("corrupt profile unexpectedly loaded").into());
        };
        let json = serde_json::to_string(&error)?;
        assert!(json.contains("err-store"));
        assert!(json.contains(r#""kind":"corrupt""#));
        assert!(json.contains("broken.json"));
        assert!(!json.contains("planted-secret"));
        assert!(profile.exists());
        let has_backup = std::fs::read_dir(profiles)?
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt"));
        assert!(has_backup);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_startup_callers_share_the_pre_write_snapshot() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        let state = Arc::new(ShellState::default());
        state.install_core(Ok(core));
        let entered = Arc::new(tokio::sync::Barrier::new(3));
        let first = {
            let state = Arc::clone(&state);
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                entered.wait().await;
                startup_snapshot(&state).await
            })
        };
        let second = {
            let state = Arc::clone(&state);
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                entered.wait().await;
                startup_snapshot(&state).await
            })
        };

        entered.wait().await;
        let before = first.await?.map_err(ipc_test_error)?;
        let alongside = second.await?.map_err(ipc_test_error)?;
        assert_eq!(
            serde_json::to_string(&before)?,
            serde_json::to_string(&alongside)?
        );

        let core = state.ready_core().await.map_err(ipc_test_error)?;
        let account = apogee_core::Account::new("later", apogee_core::AccountKind::Standard);
        core.save_account(&account)?;
        let after = startup_snapshot(&state).await.map_err(ipc_test_error)?;

        assert_eq!(
            serde_json::to_string(&before)?,
            serde_json::to_string(&after)?
        );
        assert!(!serde_json::to_string(&after)?.contains("later"));
        Ok(())
    }

    fn ipc_test_error(error: IpcErrorDto) -> std::io::Error {
        let code = serde_json::to_string(&error).unwrap_or_else(|_| "IPC failure".to_owned());
        std::io::Error::other(code)
    }
}
