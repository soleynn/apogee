//! The companion lifecycle over real processes: what starts, what stops, and what is never touched.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_addons::external::{
    AddonEvents, ExternalAddon, GameContext, Outcome, RunIn, Trigger, start,
};
use apogee_runtime::{Runtime, RuntimePaths};
use tokio_util::sync::CancellationToken;

type Fallible = Box<dyn std::error::Error>;

/// A runtime with throwaway directories. Nothing here downloads or touches a prefix.
fn runtime(dir: &Path) -> Result<Runtime, Fallible> {
    let fetcher = apogee_fetch::Fetcher::builder().build()?;
    Ok(Runtime::new(
        fetcher,
        RuntimePaths {
            runners: dir.join("runners"),
            prefixes: dir.join("prefixes"),
        },
    ))
}

/// A script that touches `marker` every 50ms until it is stopped.
fn ticker(dir: &Path, name: &str, marker: &Path) -> Result<PathBuf, Fallible> {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nwhile :; do : > {}; sleep 0.05; done\n",
            marker.display()
        ),
    )?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

/// A script that writes `marker` once and exits.
fn one_shot(dir: &Path, name: &str, marker: &Path) -> Result<PathBuf, Fallible> {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!("#!/bin/sh\n: > {}\nexit 0\n", marker.display()),
    )?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn with_game(program: &Path, keep: bool) -> Result<ExternalAddon, Fallible> {
    Ok(ExternalAddon::new(
        program,
        vec![],
        RunIn::Host,
        Trigger::WithGame {
            keep_after_close: keep,
        },
    )?)
}

/// Whether the marker keeps being refreshed, which is how a still-running ticker is detected.
fn still_running(marker: &Path) -> bool {
    let _ = std::fs::remove_file(marker);
    std::thread::sleep(Duration::from_millis(250));
    marker.exists()
}

/// The core of it: a tool starts with the game and is stopped when the game exits.
#[tokio::test]
async fn a_companion_starts_with_the_game_and_stops_with_it() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let tool = ticker(dir.path(), "act.sh", &marker)?;
    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;

    let session = start(
        &runtime,
        &[with_game(&tool, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;
    assert!(matches!(
        session.report().outcomes[0].outcome,
        Outcome::Started { .. }
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(marker.exists(), "the companion did not run");

    let report = session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    assert!(!report.any_failed(), "{report:?}");
    assert!(!still_running(&marker), "the companion outlived the game");
    Ok(())
}

/// The stop reaches what a launcher script backgrounded, rather than orphaning it. This is the shape
/// that leaks when only the direct child is signalled.
#[tokio::test]
async fn stopping_reaches_a_process_the_tool_backgrounded() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let tool = dir.path().join("shim.sh");
    std::fs::write(
        &tool,
        format!(
            "#!/bin/sh\n(while :; do : > {}; sleep 0.05; done) &\nexit 0\n",
            marker.display()
        ),
    )?;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755))?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(
        &runtime,
        &[with_game(&tool, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(marker.exists(), "the backgrounded process did not run");
    session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    assert!(
        !still_running(&marker),
        "the backgrounded process was orphaned"
    );
    Ok(())
}

/// A tool asked to stay is not touched, and one asked to stop beside it still is. This is the pair
/// that proves the stop is targeted rather than a sweep.
#[tokio::test]
async fn a_companion_asked_to_stay_is_left_running_while_its_sibling_stops() -> Result<(), Fallible>
{
    let dir = tempfile::tempdir()?;
    let keep_marker = dir.path().join("keep");
    let stop_marker = dir.path().join("stop");
    let keeper = ticker(dir.path(), "keep.sh", &keep_marker)?;
    let stopper = ticker(dir.path(), "stop.sh", &stop_marker)?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(
        &runtime,
        &[with_game(&keeper, true)?, with_game(&stopper, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let kept_pid = match session.report().outcomes[0].outcome {
        Outcome::Started { pid } => pid,
        ref other => panic!("expected a start, got {other:?}"),
    };
    session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;

    assert!(!still_running(&stop_marker), "the sibling was not stopped");
    assert!(still_running(&keep_marker), "the kept tool was stopped");

    // Clean up the one deliberately left behind.
    if let Some(pid) = rustix::process::Pid::from_raw(kept_pid) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    Ok(())
}

/// An after-game tool runs exactly once, after the game, and is waited on.
#[tokio::test]
async fn an_after_game_tool_runs_once_after_the_game() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("ran");
    let tool = one_shot(dir.path(), "sync.sh", &marker)?;
    let addon = ExternalAddon::new(&tool, vec![], RunIn::Host, Trigger::OnClose)?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(&runtime, &[addon], &game, &AddonEvents::none()).await;

    // Nothing has run yet: the game is still up.
    assert!(!marker.exists(), "an after-game tool ran during the launch");
    assert!(session.report().outcomes.is_empty());

    let report = session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    assert!(marker.exists(), "the after-game tool did not run");
    assert_eq!(report.outcomes.len(), 1, "it ran once");
    assert!(matches!(
        report.outcomes[0].outcome,
        Outcome::Completed { code: Some(0) }
    ));
    Ok(())
}

/// A tool that is already running is recognized and not started a second time. Whoever started it
/// owns it, so this launch never stops it either.
#[tokio::test]
async fn an_already_running_tool_is_recognized_and_left_alone() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let tool = ticker(dir.path(), "act.sh", &marker)?;

    // Started outside the launcher, exactly like a user double-clicking it.
    let mut outside = std::process::Command::new(&tool).spawn()?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(
        &runtime,
        &[with_game(&tool, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;

    match session.report().outcomes[0].outcome {
        Outcome::AlreadyRunning { pid } => {
            assert_eq!(pid, outside.id().cast_signed(), "the wrong process matched");
        }
        ref other => panic!("expected it to be recognized, got {other:?}"),
    }

    session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    assert!(
        still_running(&marker),
        "a tool this launch did not start was stopped by it"
    );

    let _ = outside.kill();
    let _ = outside.wait();
    Ok(())
}

/// Two tools with the same file name in different directories are different tools. Matching on the
/// bare name collapses them into one.
#[tokio::test]
async fn two_tools_sharing_a_file_name_both_start() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let a_dir = dir.path().join("a");
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&a_dir)?;
    std::fs::create_dir_all(&b_dir)?;
    let a_marker = dir.path().join("a-alive");
    let b_marker = dir.path().join("b-alive");
    let a = ticker(&a_dir, "updater.sh", &a_marker)?;
    let b = ticker(&b_dir, "updater.sh", &b_marker)?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(
        &runtime,
        &[with_game(&a, false)?, with_game(&b, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;

    for outcome in &session.report().outcomes {
        assert!(
            matches!(outcome.outcome, Outcome::Started { .. }),
            "{:?} did not start: {:?}",
            outcome.program,
            outcome.outcome
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(a_marker.exists() && b_marker.exists());
    session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    Ok(())
}

/// One bad entry costs the user that entry, not the launch and not its siblings.
#[tokio::test]
async fn a_broken_entry_does_not_stop_the_others() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let good = ticker(dir.path(), "good.sh", &marker)?;
    let missing = dir.path().join("not-here.sh");

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(
        &runtime,
        &[with_game(&missing, false)?, with_game(&good, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;

    let report = session.report().clone();
    // Not just that it failed: the reason a shell prints is a `String`, so whatever built it had to
    // walk the cause chain. "failed to start /x/not-here.sh" on its own tells a user nothing they did
    // not already know, and the part that says the file is missing lives two levels down.
    let Outcome::Failed { reason } = &report.outcomes[0].outcome else {
        panic!("the missing program has to fail: {:?}", report.outcomes[0]);
    };
    assert!(
        reason.contains("not-here.sh") && reason.contains("No such file or directory"),
        "the reported reason drops the cause chain: {reason}"
    );
    assert!(matches!(
        report.outcomes[1].outcome,
        Outcome::Started { .. }
    ));
    assert!(report.any_failed());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(marker.exists(), "the working tool did not run");
    session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    Ok(())
}

/// A disabled entry is skipped and kept, so turning a tool off does not lose its configuration.
#[tokio::test]
async fn a_disabled_entry_is_skipped() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let tool = ticker(dir.path(), "act.sh", &marker)?;
    let mut addon = with_game(&tool, false)?;
    addon.set_enabled(false);

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(&runtime, &[addon], &game, &AddonEvents::none()).await;

    assert_eq!(session.report().outcomes[0].outcome, Outcome::Disabled);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!marker.exists(), "a disabled entry ran");
    session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    Ok(())
}

/// The backstop. Consuming the session makes the teardown happen at most once; nothing makes it
/// happen at all, because an error on the launch path drops the session instead. Dropping must not
/// leave companions running with nothing left that knows about them.
#[tokio::test]
async fn dropping_the_session_still_stops_what_it_started() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let tool = ticker(dir.path(), "act.sh", &marker)?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    {
        let session = start(
            &runtime,
            &[with_game(&tool, false)?],
            &game,
            &AddonEvents::none(),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(marker.exists());
        drop(session);
    }

    assert!(
        !still_running(&marker),
        "dropping the session leaked its companions"
    );
    Ok(())
}

/// Giving up on a launch stops what was started and runs nothing that expects a played session.
#[tokio::test]
async fn abandoning_a_launch_stops_tools_and_skips_the_after_game_ones() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let alive = dir.path().join("alive");
    let ran = dir.path().join("ran");
    let tool = ticker(dir.path(), "act.sh", &alive)?;
    let after = one_shot(dir.path(), "sync.sh", &ran)?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(
        &runtime,
        &[
            with_game(&tool, false)?,
            ExternalAddon::new(&after, vec![], RunIn::Host, Trigger::OnClose)?,
        ],
        &game,
        &AddonEvents::none(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    session
        .abandon(&CancellationToken::new(), &AddonEvents::none())
        .await;

    assert!(!still_running(&alive), "the companion was not stopped");
    assert!(!ran.exists(), "an after-game tool ran for a failed launch");
    Ok(())
}

/// A launcher that would otherwise detach after starting the game has to know whether anything is
/// still owed at exit.
#[tokio::test]
async fn a_session_reports_whether_it_still_has_work() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let tool = ticker(dir.path(), "act.sh", &marker)?;
    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;

    // Nothing configured: nothing owed.
    let empty = start(&runtime, &[], &game, &AddonEvents::none()).await;
    assert!(!empty.has_work());
    empty
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;

    // A tool that is explicitly left running owes nothing either.
    let keeps = start(
        &runtime,
        &[with_game(&tool, true)?],
        &game,
        &AddonEvents::none(),
    )
    .await;
    assert!(!keeps.has_work());
    let kept_pid = match keeps.report().outcomes[0].outcome {
        Outcome::Started { pid } => pid,
        ref other => panic!("expected a start, got {other:?}"),
    };
    keeps
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    if let Some(pid) = rustix::process::Pid::from_raw(kept_pid) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }

    // One that stops with the game does.
    let stops = start(
        &runtime,
        &[with_game(&tool, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;
    assert!(stops.has_work());
    stops
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;
    Ok(())
}

/// A tool running alongside the game is told where the game is, so a wrapper does not need a
/// substitution language in its argument vector to find it.
#[tokio::test]
async fn a_companion_is_told_the_game_process_id() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("seen");
    let tool = dir.path().join("report.sh");
    std::fs::write(
        &tool,
        format!(
            "#!/bin/sh\nprintf '%s' \"$APOGEE_GAME_PID\" > {}\nexit 0\n",
            out.display()
        ),
    )?;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755))?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(4242)?;
    let session = start(
        &runtime,
        &[with_game(&tool, false)?],
        &game,
        &AddonEvents::none(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    session
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;

    assert_eq!(std::fs::read_to_string(&out)?, "4242");
    Ok(())
}

/// An after-game tool is not handed the game's process id. By the time it runs that names a process
/// that has exited, and the number can already belong to something else.
#[tokio::test]
async fn an_after_game_tool_is_not_told_a_process_id_that_is_gone() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("seen");
    let tool = dir.path().join("report.sh");
    std::fs::write(
        &tool,
        format!(
            "#!/bin/sh\nprintf '[%s]' \"$APOGEE_GAME_PID\" > {}\nexit 0\n",
            out.display()
        ),
    )?;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755))?;

    let runtime = runtime(dir.path())?;
    let addon = ExternalAddon::new(&tool, vec![], RunIn::Host, Trigger::OnClose)?;
    let game = GameContext::new(4242)?;
    start(&runtime, &[addon], &game, &AddonEvents::none())
        .await
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;

    assert_eq!(std::fs::read_to_string(&out)?, "[]");
    Ok(())
}

/// A pid that means "my whole process group" or "everything this user owns" is not a game.
#[test]
fn a_game_context_refuses_a_pid_that_is_not_one() {
    assert!(GameContext::new(0).is_err());
    assert!(GameContext::new(-1).is_err());
    assert!(GameContext::new(1).is_ok());
}

/// Arguments reach the child verbatim, so a path with spaces stays one argument.
#[tokio::test]
async fn arguments_reach_the_child_unsplit() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("argv");
    let tool = dir.path().join("echo.sh");
    std::fs::write(
        &tool,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" > {}\nexit 0\n",
            out.display()
        ),
    )?;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755))?;

    let runtime = runtime(dir.path())?;
    let addon = ExternalAddon::new(
        &tool,
        vec!["one two \"three\"".into()],
        RunIn::Host,
        Trigger::OnClose,
    )?;
    let game = GameContext::new(1)?;
    start(&runtime, &[addon], &game, &AddonEvents::none())
        .await
        .game_closed(&CancellationToken::new(), &AddonEvents::none())
        .await;

    assert_eq!(std::fs::read_to_string(&out)?, "one two \"three\"\n");
    Ok(())
}

/// An after-game tool that never exits used to hold the teardown open forever: the game was gone, the
/// launcher had nothing left to do, and the only way out was to kill it. The token is what bounds that
/// wait, and the tool is stopped on the way out rather than left running with nothing that knows it is
/// there.
#[tokio::test]
async fn a_cancelled_teardown_stops_waiting_on_a_tool_that_never_exits() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("alive");
    let tool = ticker(dir.path(), "forever.sh", &marker)?;
    let addon = ExternalAddon::new(&tool, vec![], RunIn::Host, Trigger::OnClose)?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(&runtime, &[addon], &game, &AddonEvents::none()).await;

    // Fired while the wait is already running, which is the shape the flow has: the teardown is under
    // way and then the user quits.
    let cancel = CancellationToken::new();
    let firing = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            cancel.cancel();
        }
    });

    let report = tokio::time::timeout(
        Duration::from_secs(20),
        session.game_closed(&cancel, &AddonEvents::none()),
    )
    .await
    .map_err(|_| "the teardown waited on a tool that never exits")?;
    firing.await?;

    assert!(
        matches!(report.outcomes[0].outcome, Outcome::Cancelled),
        "a tool the user interrupted is not a failure: {:?}",
        report.outcomes
    );
    assert!(!still_running(&marker), "the tool was left running");
    Ok(())
}

/// A teardown that is cancelled before it reaches an after-game tool does not start it. Checking the
/// token only inside the wait would start every remaining tool and stop it a moment later, which for a
/// tool that writes something is not the same as never running it.
#[tokio::test]
async fn a_teardown_cancelled_first_never_starts_the_tools_it_has_left() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("ran");
    let tool = one_shot(dir.path(), "sync.sh", &marker)?;
    let addon = ExternalAddon::new(&tool, vec![], RunIn::Host, Trigger::OnClose)?;

    let runtime = runtime(dir.path())?;
    let game = GameContext::new(std::process::id().cast_signed())?;
    let session = start(&runtime, &[addon], &game, &AddonEvents::none()).await;

    let cancel = CancellationToken::new();
    cancel.cancel();
    let report = session.game_closed(&cancel, &AddonEvents::none()).await;

    assert!(
        matches!(report.outcomes[0].outcome, Outcome::Cancelled),
        "{:?}",
        report.outcomes
    );
    assert!(!marker.exists(), "the tool ran anyway");
    Ok(())
}
