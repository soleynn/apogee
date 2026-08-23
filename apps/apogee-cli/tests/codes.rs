//! The CLI exposes the core's stable presentation vocabulary without opening configuration or a
//! credential store, so shells and packaging checks can compare their own tables to it.

use std::process::Command;

#[test]
fn dump_codes_is_sorted_unique_and_needs_no_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .arg("--dump-codes")
        .output()
        .expect("run apogee-cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("codes are UTF-8");
    let codes: Vec<_> = stdout.lines().collect();
    assert!(!codes.is_empty());
    assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(codes.iter().all(|code| {
        !code.is_empty()
            && code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }));
}

#[test]
fn credentialed_flows_offer_the_password_source_choice() {
    for flow in ["login", "play", "patch", "install"] {
        let output = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
            .args([flow, "--help"])
            .output()
            .expect("run apogee-cli help");
        assert!(output.status.success(), "{flow}");
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(
            help.contains("--password-source <PASSWORD_SOURCE>"),
            "{flow}: {help}"
        );
        assert!(
            help.contains("possible values: stored, prompt"),
            "{flow}: {help}"
        );
    }
}
