#![cfg(target_os = "windows")]
//! The Windows launch arm against a real process.
//!
//! There is no runner to stand in for and no process table to search, so the stub the launch spawns is
//! this test binary re-entered as the ignored `stub_game` below: it reports the environment and working
//! directory it was actually given, then stays up to be waited on and killed. That keeps the whole
//! thing self-contained, which matters more here than usual, because the only machines that run it are
//! a hosted Windows runner and a headless guest.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::Fetcher;
use apogee_runtime::{LaunchPlan, Progress, Runtime, RuntimePaths};
use tokio_util::sync::CancellationToken;

/// The name of the ignored test this binary re-enters as the game.
const STUB: &str = "stub_game";
/// Where the stub writes what it saw.
const OUT: &str = "APOGEE_STUB_OUT";
/// How long the stub stays up once it has reported. Zero is a game that exits on its own.
const HOLD: &str = "APOGEE_STUB_HOLD_SECS";
/// The line the stub reports its working directory on. Not an environment variable, so it cannot
/// collide with one.
const CWD: &str = "<cwd>";
/// The line the stub reports its last argument on, which is the argument string the game parses itself.
const LAST_ARG: &str = "<last-arg>";
/// A stand-in for the game's opaque argument string, in the shape the real one takes.
const GAME_ARGS: &str = "//**sqex0003redacted**//";
/// How long a report that should arrive is waited for.
const REPORT_DEADLINE: Duration = Duration::from_secs(30);
/// How long an exit that should arrive is waited for.
const EXIT_DEADLINE: Duration = Duration::from_secs(30);

/// Not a test: the process a launch spawns. Reports its environment and working directory, then holds
/// the process open for as long as it was told to.
///
/// Ignored, so an ordinary run lists it and never runs it; the launches below re-enter this binary with
/// the filter that selects it. Returns at once if it was started by anything else, so running the
/// ignored tests by hand costs nothing.
#[test]
#[ignore = "re-entered as the game by the launches in this file"]
fn stub_game() {
    let Ok(out) = std::env::var(OUT) else {
        return;
    };
    let mut report = String::new();
    for (key, value) in std::env::vars() {
        report.push_str(&format!("{key}={value}\n"));
    }
    if let Ok(dir) = std::env::current_dir() {
        report.push_str(&format!("{CWD}={}\n", dir.display()));
    }
    if let Some(last) = std::env::args().next_back() {
        report.push_str(&format!("{LAST_ARG}={last}\n"));
    }
    // Written beside the report and renamed onto it, so a reader polling for the file cannot pick up
    // half of one.
    let partial = format!("{out}.partial");
    if std::fs::write(&partial, report).is_ok() {
        let _ = std::fs::rename(&partial, &out);
    }
    let hold = std::env::var(HOLD)
        .ok()
        .and_then(|secs| secs.parse().ok())
        .unwrap_or(0);
    std::thread::sleep(Duration::from_secs(hold));
}

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

/// A plan that launches this binary as the game: it writes its report to `out` and then stays up for
/// `hold` seconds.
fn stub_plan(out: &Path, hold: u64) -> Result<LaunchPlan, Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let mut env = BTreeMap::new();
    env.insert(OUT.to_owned(), out.display().to_string());
    env.insert(HOLD.to_owned(), hold.to_string());
    // The argument string sits last, where the game's own does. The harness reads it as one more name
    // filter, which selects nothing and leaves the stub the only test that runs.
    let mut plan = LaunchPlan::new(exe.to_string_lossy().into_owned(), GAME_ARGS, env);
    // The harness's own selection flags, which is what makes the spawned binary run the stub and
    // nothing else.
    plan.set_inserted_args(vec![
        "--ignored".to_owned(),
        "--exact".to_owned(),
        STUB.to_owned(),
    ]);
    Ok(plan)
}

/// The stub's report, once it has written one.
async fn report_from(path: &Path) -> Result<String, Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + REPORT_DEADLINE;
    loop {
        if let Ok(report) = std::fs::read_to_string(path) {
            return Ok(report);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("the spawned game wrote no report".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// What the spawned process reported for `key`.
fn reported(report: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    report
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::to_owned)
}

/// Whether a process with `pid` is still in the process table, asked of the system rather than of the
/// session that is under test.
fn still_running(pid: i32) -> Result<bool, Box<dyn Error>> {
    let listed = std::process::Command::new("tasklist")
        .args(["/NH", "/FI", &format!("PID eq {pid}")])
        .output()?;
    // The filter matches at most one row, and the "no tasks" notice carries no digits, so the pid
    // appearing at all is the process being there.
    Ok(String::from_utf8_lossy(&listed.stdout).contains(&pid.to_string()))
}

/// The one thing this arm adds to the environment has to arrive, both layers of it, and the prefix
/// variables that place a program in a wine prefix must not: there is no prefix here to place it in.
///
/// The prefix variables are compared against this process's own rather than against nothing, because
/// the child inherits the environment: what is being asserted is that the launch added none of them.
#[tokio::test]
async fn the_game_is_given_the_compatibility_layers_and_no_prefix() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let out = root.path().join("seen.txt");
    let runtime = runtime_over(root.path())?;
    let plan = stub_plan(&out, 600)?.in_directory(root.path());

    let session = runtime
        .launch(plan, &CancellationToken::new(), &Progress::none())
        .await?;
    let report = report_from(&out).await?;

    // Compared case-insensitively because the value does not arrive verbatim: Windows re-spells each
    // layer it applied the way its own database names it, so `HighDPIAware` reaches the game as
    // `HighDpiAware` (measured on Windows 11 25H2). That re-spelling is the compatibility engine
    // having read the variable, which is more than the string having been inherited past it.
    assert_eq!(
        reported(&report, "__COMPAT_LAYER")
            .map(|layers| layers.to_ascii_lowercase())
            .as_deref(),
        Some("runasinvoker highdpiaware"),
        "both compatibility layers reached the game"
    );
    for variable in ["WINEPREFIX", "GAMEID", "PROTONPATH"] {
        assert_eq!(
            reported(&report, variable),
            std::env::var(variable).ok(),
            "{variable} was added by the launch"
        );
    }
    // Canonicalized on both sides: a temporary directory reaches a child through the path the system
    // hands out, which is not always spelled the way it was created.
    let ran_in = reported(&report, CWD).ok_or("the game reported no working directory")?;
    assert_eq!(
        std::fs::canonicalize(PathBuf::from(ran_in))?,
        std::fs::canonicalize(root.path())?,
        "the game ran from the directory the plan named"
    );
    // One token, unquoted and unsplit. The characters the real string is built from need no escaping,
    // so what the game is handed is the same command line the reference launcher composes by hand.
    assert_eq!(
        reported(&report, LAST_ARG).as_deref(),
        Some(GAME_ARGS),
        "the argument string reached the game verbatim"
    );
    assert!(session.game_pid() > 0, "the session tracks a real process");

    session.kill().await?;
    Ok(())
}

/// The session's stop is the child handle's, and it resolves once the process is gone rather than once
/// the request was made: a caller that stops a game and then rewrites its files has to be able to
/// believe the first half.
#[tokio::test]
async fn killing_the_session_stops_the_game() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let out = root.path().join("seen.txt");
    let runtime = runtime_over(root.path())?;

    let session = runtime
        .launch(
            stub_plan(&out, 600)?,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await?;
    let pid = session.game_pid();
    // Waited for, so the process is known to be up before it is stopped.
    report_from(&out).await?;
    assert!(still_running(pid)?, "the game is running");

    session.kill().await?;
    assert!(
        !still_running(pid)?,
        "kill resolved before the process was gone"
    );
    // Stopping a game that has already been stopped is the same answer, not an error.
    session.kill().await?;
    Ok(())
}

/// A game that ends on its own ends the session, with no stop and nothing to scan for.
#[tokio::test]
async fn a_game_that_exits_ends_the_session() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let out = root.path().join("seen.txt");
    let runtime = runtime_over(root.path())?;

    let session = runtime
        .launch(
            stub_plan(&out, 0)?,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await?;
    tokio::time::timeout(EXIT_DEADLINE, session.wait()).await??;
    assert!(
        !still_running(session.game_pid())?,
        "the session resolved while the game was still running"
    );
    Ok(())
}
