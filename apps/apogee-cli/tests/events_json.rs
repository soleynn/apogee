//! Process-level checks for the stable event stream. These commands are offline by construction.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run(home: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .output()
}

fn json_lines(output: &Output) -> Result<Vec<Value>, serde_json::Error> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    let lines = stdout
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(!lines.is_empty());
    assert!(lines.iter().all(Value::is_object));
    assert_eq!(
        lines.last().and_then(|line| line["kind"].as_str()),
        Some("outcome")
    );
    Ok(lines)
}

#[test]
fn first_run_read_is_jsonl_from_the_core_stream() -> TestResult {
    let home = TempDir::new()?;
    let output = run(home.path(), &["--events-json", "first-run"])?;
    let lines = json_lines(&output)?;

    assert!(lines.iter().any(|line| line["kind"] == "firstRun"));
    Ok(())
}

#[test]
fn import_preview_is_jsonl_from_the_core_stream() -> TestResult {
    let home = TempDir::new()?;
    let source = TempDir::new()?;
    let game = TempDir::new()?;
    std::fs::write(
        source.path().join("accountsList.json"),
        r#"[{"UserName":"person@example.invalid","UseOtp":false,"SavePassword":false}]"#,
    )?;
    std::fs::write(
        source.path().join("launcherConfigV3.json"),
        serde_json::to_vec(&serde_json::json!({
            "GamePath": game.path(),
            "IsFt": false,
        }))?,
    )?;
    let source = source.path().to_string_lossy();
    let output = run(
        home.path(),
        &[
            "--events-json",
            "import",
            "xivlauncher",
            &source,
            "--dry-run",
        ],
    )?;
    let lines = json_lines(&output)?;

    assert!(lines.iter().any(|line| line["kind"] == "import"));
    Ok(())
}

#[test]
fn support_bundle_is_written_while_stdout_stays_jsonl() -> TestResult {
    let home = TempDir::new()?;
    let output_path = home.path().join("support.zip");
    let output_path_text = output_path.to_string_lossy();
    let output = run(
        home.path(),
        &[
            "--events-json",
            "support-bundle",
            "--output",
            &output_path_text,
        ],
    )?;
    let lines = json_lines(&output)?;

    let support = lines
        .iter()
        .find(|line| line["kind"] == "supportBundle")
        .ok_or("support-bundle event was missing")?;
    let emitted = support["bytes"]
        .as_array()
        .ok_or("support-bundle bytes were not an array")?
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect::<Option<Vec<_>>>()
        .ok_or("support-bundle byte array contained a non-byte value")?;
    assert_eq!(emitted, std::fs::read(&output_path)?);
    assert!(output_path.is_file());
    assert!(std::fs::metadata(output_path)?.len() > 0);
    Ok(())
}

#[test]
fn support_bundle_publish_failure_ends_with_a_failed_outcome() -> TestResult {
    let home = TempDir::new()?;
    let output_path = home.path().join("support.zip");
    std::fs::write(&output_path, b"existing archive")?;
    let output_path_text = output_path.to_string_lossy();
    let output = run(
        home.path(),
        &[
            "--events-json",
            "support-bundle",
            "--output",
            &output_path_text,
        ],
    )?;

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        lines.last().and_then(|line| line["outcome"].as_str()),
        Some("failed")
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["kind"] == "outcome")
            .count(),
        1
    );
    assert_eq!(std::fs::read(output_path)?, b"existing archive");
    Ok(())
}
