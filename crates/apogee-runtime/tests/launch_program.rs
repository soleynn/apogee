#![cfg(target_os = "linux")]
//! The status of the program a launch was spawned as, for a launch something redirected.
//!
//! No wine: a shell script stands in for the runner and a compiled stub stands in for the game, which
//! is enough to reproduce both shapes the real thing has. A loader that starts the game and returns
//! exits seconds into a session that then runs for hours; a container-style runner holds its layers
//! open until the game is gone. The status has to survive both, and neither may be mistaken for the
//! launch ending.

use std::collections::BTreeMap;
use std::error::Error;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::Fetcher;
use apogee_runtime::{
    LaunchPlan, ProgramStatus, Progress, RunnerKind, Runtime, RuntimeEvent, RuntimePaths,
};
use serial_test::serial;
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

/// The program the plan names. It is never run: the runner shim ignores its arguments, exactly as a
/// real loader ignores nothing and this test cares about nothing but the status.
const LOADER: &str = "/loader/Loader.exe";
/// The argument the shim answers before doing anything else, so a caller can prove it runs.
const PROBE: &str = "--shim-probe";
/// How many times a probe may come back `ETXTBSY` before giving up. A sibling thread's fork can hold
/// a descriptor open against a file this test just wrote, and the window closes on its own once that
/// child execs; the ceiling is so a script that is genuinely unrunnable fails as itself.
const PROBE_ATTEMPTS: u32 = 500;
/// How long to wait for a status that should arrive.
const STATUS_DEADLINE: Duration = Duration::from_secs(30);
/// How long to watch for a status that should not arrive at all.
const SILENCE_WINDOW: Duration = Duration::from_secs(2);

fn runtime_over(root: &Path) -> Result<Runtime, Box<dyn Error>> {
    let fetcher = Fetcher::builder().build()?;
    Ok(Runtime::new(
        fetcher,
        RuntimePaths {
            runners: root.join("runners"),
            prefixes: root.join("prefixes"),
        },
    ))
}

/// Compile a native ELF that sleeps `seconds`, named `ffxiv_dx11.exe`, in `dir`. The name is what the
/// `/proc` scan matches on, and a copied system `sleep` will not do: coreutils dispatches on argv[0],
/// so under another name it errors instead of sleeping.
fn build_sleeper(dir: &Path, seconds: u32) -> Result<PathBuf, Box<dyn Error>> {
    let src = dir.join("sleeper.c");
    std::fs::write(
        &src,
        format!("#include <unistd.h>\nint main(void) {{ sleep({seconds}); return 0; }}\n"),
    )?;
    let exe = dir.join("ffxiv_dx11.exe");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let status = std::process::Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .status()?;
    if !status.success() {
        return Err("cc failed to build the stub".into());
    }
    Ok(exe)
}

/// A custom runner directory whose `bin/wine` lays down a prefix skeleton for `wineboot` and runs
/// `body` for anything else.
fn custom_runner(dir: &Path, body: &str) -> Result<(), Box<dyn Error>> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    let wine = bin.join("wine");
    std::fs::write(
        &wine,
        format!(
            "#!/bin/sh\n\
             [ \"$1\" = {PROBE} ] && exit 0\n\
             if [ \"$1\" = wineboot ]; then\n\
             \x20 mkdir -p \"$WINEPREFIX/drive_c\" \"$WINEPREFIX/dosdevices\"\n\
             \x20 ln -sfn ../drive_c \"$WINEPREFIX/dosdevices/c:\"\n\
             \x20 ln -sfn / \"$WINEPREFIX/dosdevices/z:\"\n\
             \x20 printf 'WINE REGISTRY Version 2\\n' > \"$WINEPREFIX/system.reg\"\n\
             \x20 exit 0\n\
             fi\n\
             {body}\n"
        ),
    )?;
    std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755))?;
    wait_until_runnable(&wine)
}

/// Run the shim's probe until it starts, so no descriptor a sibling's fork inherited is still open
/// against it when the launch spawns for real. Without this the spawn fails with `ETXTBSY` and the
/// test reports its subject as broken.
fn wait_until_runnable(shim: &Path) -> Result<(), Box<dyn Error>> {
    for _ in 0..PROBE_ATTEMPTS {
        match std::process::Command::new(shim).arg(PROBE).status() {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy => std::thread::yield_now(),
            Err(e) => return Err(Box::new(e)),
        }
    }
    Err("the shim stayed busy for every probe".into())
}

/// The next launch-program status on `events`, ignoring everything else on the stream.
async fn next_status(
    events: &mut UnboundedReceiver<RuntimeEvent>,
) -> Result<(String, ProgramStatus), Box<dyn Error>> {
    loop {
        match tokio::time::timeout(STATUS_DEADLINE, events.recv()).await {
            Ok(Some(RuntimeEvent::LaunchProgramExited { program, status })) => {
                return Ok((program, status));
            }
            Ok(Some(_)) => {}
            Ok(None) => return Err("the progress stream closed with no status".into()),
            Err(_) => return Err("no launch-program status arrived".into()),
        }
    }
}

/// Whether a launch-program status turns up within `window`.
async fn status_within(events: &mut UnboundedReceiver<RuntimeEvent>, window: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(RuntimeEvent::LaunchProgramExited { .. })) => return true,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return false,
        }
    }
}

fn proc_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// A loader that starts the game and returns is the normal path, and it returns *while the session
/// runs*. Its status is the only report it makes about whether it did its job, so it has to arrive,
/// and it has to arrive without the launch being treated as over.
#[tokio::test]
#[serial]
async fn a_loader_that_returns_early_reports_its_status_while_the_game_runs()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let runtime = runtime_over(root.path())?;
    let runner_dir = root.path().join("runner");
    std::fs::create_dir_all(&runner_dir)?;
    let game = build_sleeper(&runner_dir, 30)?;
    // Start the game, then fail the way a loader reports that it never got in.
    custom_runner(&runner_dir, &format!("\"{}\" &\nexit 7\n", game.display()))?;

    let (tx, mut events) = mpsc::unbounded_channel();
    let progress = Progress::new(tx);
    let prefix = runtime
        .prepare_custom(
            &runner_dir,
            RunnerKind::Custom,
            "stub",
            &root.path().join("prefix"),
            &CancellationToken::new(),
            &progress,
        )
        .await?;
    let mut plan = LaunchPlan::new(LOADER, String::new(), BTreeMap::new()).prefix(&prefix);
    plan.set_supervised("ffxiv_dx11.exe");
    let session = runtime
        .launch(plan, &CancellationToken::new(), &progress)
        .await?;

    let (program, status) = next_status(&mut events).await?;
    assert_eq!(
        program, LOADER,
        "the status names the program that was spawned"
    );
    assert_eq!(
        status,
        ProgramStatus::Code(7),
        "the raw status, uninterpreted"
    );
    assert!(
        proc_exists(session.game_pid()),
        "the loader's exit is not the launch ending: the game is still running"
    );
    session.kill().await?;
    Ok(())
}

/// A container-style runner holds its layers open for the whole session and reports only once the game
/// is gone. Reaping it must not make the game's exit wait on it, and the status still has to be
/// delivered when it eventually lands.
#[tokio::test]
#[serial]
async fn a_runner_that_outlives_the_game_still_reports_its_status() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let runtime = runtime_over(root.path())?;
    let runner_dir = root.path().join("runner");
    std::fs::create_dir_all(&runner_dir)?;
    let game = build_sleeper(&runner_dir, 2)?;
    // Start the game and stay up until it is gone, as umu's layers do.
    custom_runner(
        &runner_dir,
        &format!("\"{}\" &\nwait\nexit 0\n", game.display()),
    )?;

    let (tx, mut events) = mpsc::unbounded_channel();
    let progress = Progress::new(tx);
    let prefix = runtime
        .prepare_custom(
            &runner_dir,
            RunnerKind::Custom,
            "stub",
            &root.path().join("prefix"),
            &CancellationToken::new(),
            &progress,
        )
        .await?;
    let mut plan = LaunchPlan::new(LOADER, String::new(), BTreeMap::new()).prefix(&prefix);
    plan.set_supervised("ffxiv_dx11.exe");
    let session = runtime
        .launch(plan, &CancellationToken::new(), &progress)
        .await?;
    let pid = session.game_pid();

    // The game's own exit resolves on the game, never on the wrapper still holding the session open.
    tokio::time::timeout(STATUS_DEADLINE, session.wait()).await??;
    assert!(!proc_exists(pid), "the game is gone");
    let (_, status) = next_status(&mut events).await?;
    assert_eq!(status, ProgramStatus::Code(0));
    Ok(())
}

/// Nothing redirected this launch, so the process that was spawned is the runner's own loader and its
/// status reports the handoff rather than a companion. Raising it would put a line in front of the user
/// on every ordinary launch, saying nothing.
#[tokio::test]
#[serial]
async fn an_ordinary_launch_reports_no_status_for_the_runner() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let runtime = runtime_over(root.path())?;
    let runner_dir = root.path().join("runner");
    std::fs::create_dir_all(&runner_dir)?;
    let game = build_sleeper(&runner_dir, 1)?;
    custom_runner(&runner_dir, "\"$@\"\n")?;

    let (tx, mut events) = mpsc::unbounded_channel();
    let progress = Progress::new(tx);
    let prefix = runtime
        .prepare_custom(
            &runner_dir,
            RunnerKind::Custom,
            "stub",
            &root.path().join("prefix"),
            &CancellationToken::new(),
            &progress,
        )
        .await?;
    // No supervised name: the program the plan launches is the game itself.
    let plan = LaunchPlan::new(
        game.to_string_lossy().into_owned(),
        String::new(),
        BTreeMap::new(),
    )
    .prefix(&prefix);
    let session = runtime
        .launch(plan, &CancellationToken::new(), &progress)
        .await?;

    tokio::time::timeout(STATUS_DEADLINE, session.wait()).await??;
    assert!(
        !status_within(&mut events, SILENCE_WINDOW).await,
        "an ordinary launch raises no launch-program status"
    );
    Ok(())
}
