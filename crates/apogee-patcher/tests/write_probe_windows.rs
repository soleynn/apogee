#![cfg(windows)]
//! The writability probe against a directory Windows really denies.
//!
//! The rest of the probe's behaviour is covered by unit tests that work anywhere. This one needs a
//! genuine access-control entry, so it needs Windows and it needs `icacls`, which ships with it.
//!
//! The deny entry names the account this process is running as, and a deny always beats an allow in
//! a Windows access check, so it denies an administrator token as well. That is what makes the test
//! meaningful on a hosted runner, whose agent already holds one: the answer here does not depend on
//! the integrity level, only on the access check, which is exactly what the probe reads.

use std::error::Error;
use std::path::Path;
use std::process::Command;

use apogee_patcher::probe_writable;

/// The account to write the access-control entry for, in the form `icacls` expects.
fn current_account() -> Result<String, Box<dyn Error>> {
    let user = std::env::var("USERNAME")?;
    Ok(match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() => format!("{domain}\\{user}"),
        _ => user,
    })
}

/// Run `icacls` and fail loudly with its own output, since a silently unapplied entry would leave
/// the assertion below testing nothing.
fn icacls(dir: &Path, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let out = Command::new("icacls").arg(dir).args(args).output()?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "icacls {args:?} failed with {}: {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    )
    .into())
}

/// A directory with a write-deny entry for this account answers "not writable", and answers
/// "writable" again once the entry is removed.
///
/// The pair is the test. Asserting only the deny half would pass just as well against a probe that
/// always said no.
#[test]
fn a_denied_directory_answers_not_writable_and_recovers() -> Result<(), Box<dyn Error>> {
    let base = tempfile::tempdir()?;
    let locked = base.path().join("locked");
    std::fs::create_dir(&locked)?;
    let account = current_account()?;

    assert!(
        probe_writable(&locked)?,
        "a fresh directory should be writable before anything is denied"
    );

    icacls(&locked, &["/deny", &format!("{account}:(OI)(CI)(W)")])?;
    assert!(
        !probe_writable(&locked)?,
        "a directory denying this account must read as needing elevation",
    );
    // And the same answer for a subdirectory that does not exist yet, which is the shape a fresh
    // install actually asks about: the walk finds the denied parent.
    assert!(!probe_writable(&locked.join("game").join("sqpack"))?);

    icacls(&locked, &["/remove:d", &account])?;
    assert!(
        probe_writable(&locked)?,
        "removing the deny entry must restore the answer",
    );
    Ok(())
}
