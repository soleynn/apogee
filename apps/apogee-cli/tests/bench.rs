//! `bench analyze` over MangoHud frametime logs: hermetic, no network, no wine. Spawns the built
//! binary, so it exercises arg parsing, the directory scan, and the rendered table end to end.

use std::fs;
use std::process::Command;

use tempfile::tempdir;

/// A minimal but real-shaped MangoHud frametime CSV: metadata block, data header, three frames.
/// `elapsed` is process uptime in **nanoseconds**, so it has to run ahead of the cumulative
/// frametimes; a row whose frametime exceeds it is dropped as an instrumentation artifact.
const FRAMETIME_CSV: &str = "os,cpu,gpu,ram,kernel,driver,cpuscheduler\n\
TestOS,TestCPU,TestGPU,0,0.0.0,,none\n\
fps,frametime,elapsed\n\
120,8.0,8000000\n\
60,16.0,24000000\n\
30,33.0,57000000\n";

/// Run the built CLI with storage pinned to a throwaway home so nothing touches real config.
fn run_bench(
    home: &std::path::Path,
    args: &[&std::ffi::OsStr],
) -> std::io::Result<std::process::Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apogee-cli"));
    cmd.env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .args(["bench", "analyze"])
        .args(args);
    cmd.output()
}

#[test]
fn analyze_scans_a_dir_skips_summaries_and_reports_metrics() {
    let home = tempdir().unwrap();
    let logs = tempdir().unwrap();
    fs::write(logs.path().join("run_2026.csv"), FRAMETIME_CSV).unwrap();
    // MangoHud always drops a companion summary next to the frametime log; it must be ignored.
    fs::write(
        logs.path().join("run_2026_summary.csv"),
        "some,summary,columns\n1,2,3\n",
    )
    .unwrap();

    let out = run_bench(home.path(), &[logs.path().as_os_str()]).unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();

    assert!(
        out.status.success(),
        "exit {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("run_2026.csv"),
        "missing frame row:\n{stdout}"
    );
    assert!(
        !stdout.contains("summary"),
        "summary not skipped:\n{stdout}"
    );
    // Mean frametime (8+16+33)/3 = 19 ms -> 52.63 avg FPS.
    assert!(stdout.contains("52.63"), "wrong average:\n{stdout}");
}

#[test]
fn a_malformed_log_fails_loudly() {
    let home = tempdir().unwrap();
    let dir = tempdir().unwrap();
    let bad = dir.path().join("bad.csv");
    fs::write(&bad, "this is not a mangohud log\n").unwrap();

    let out = run_bench(home.path(), &[bad.as_os_str()]).unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();

    assert!(!out.status.success(), "should fail on a malformed log");
    assert!(stdout.contains("error"), "no error reported:\n{stdout}");
}

#[test]
fn json_reports_every_log_and_keeps_a_failure_beside_the_successes() {
    let home = tempdir().unwrap();
    let logs = tempdir().unwrap();
    fs::write(logs.path().join("a_good.csv"), FRAMETIME_CSV).unwrap();
    fs::write(logs.path().join("b_bad.csv"), "not a mangohud log\n").unwrap();

    let out = run_bench(
        home.path(),
        &[logs.path().as_os_str(), std::ffi::OsStr::new("--json")],
    )
    .unwrap();
    assert!(!out.status.success(), "a bad log still fails the run");
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2);

    let report = &rows[0]["report"];
    assert_eq!(report["all_frames"]["frame_count"], 3);
    // The 33 ms frame is the slowest of three, so it is both percentiles.
    assert_eq!(report["measured"]["p99_ms"], 33.0);
    assert_eq!(report["measured"]["stalls_over_50ms"]["count"], 0);
    // No telemetry columns: the clock flag is unknown, not a pass.
    assert!(report["validity"]["clock_dipped"].is_null());
    assert!(rows[1]["error"].is_string());
    assert!(rows[1].get("report").is_none());
}
