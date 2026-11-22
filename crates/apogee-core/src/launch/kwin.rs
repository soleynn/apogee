//! Keeping ACT's overlays above the game under KWin.
//!
//! OverlayPlugin draws each overlay in a topmost, borderless window titled with the overlay's own name,
//! which the user picks. KWin keeps a focused full-screen window above every ordinary "keep above"
//! window, so without help the overlays sink under the game the moment it is focused. A window rule
//! forcing them into KWin's overlay layer fixes that. Every window in the game's session shares one
//! class, and overlay titles are free text, so the rule matches that class and excludes the two
//! windows that must stay ordinary, the game's and ACT's main window, by title. ACT's own dialogs float
//! above the game too, which is harmless.
//!
//! A second rule gives ACT a taskbar entry of its own. A taskbar groups windows by their desktop
//! file, and with one class for the whole session ACT would otherwise sit inside the game's entry, so
//! that clicking the game's entry could bring up ACT. The rule names a desktop file of ACT's own for
//! every window in the session but the game's (overlays carry no taskbar entry, so it changes nothing
//! for them).
//!
//! Both rules are merged into the user's rules file as groups of their own, leaving every rule of
//! theirs as it was.

use std::path::Path;

/// Each rule's group, which is also its entry in `[General] rules`, and its body, for `class`.
fn rules(class: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "apogee-overlays",
            format!(
                "Description=Apogee: ACT overlays above the game\n\
                 wmclass={class}\nwmclassmatch=1\n\
                 title=^(?!FINAL FANTASY XIV$)(?!Advanced Combat Tracker).+$\ntitlematch=3\n\
                 layer=overlay\nlayerrule=2\n"
            ),
        ),
        (
            "apogee-act",
            format!(
                "Description=Apogee: ACT in a taskbar entry of its own\n\
                 wmclass={class}\nwmclassmatch=1\n\
                 title=^(?!FINAL FANTASY XIV$).+$\ntitlematch=3\n\
                 desktopfile={}\ndesktopfilerule=2\n",
                crate::launch::desktop::act_identity()
            ),
        ),
    ]
}

/// Make `kwinrulesrc` under `config_home` hold the overlay rule for `class`, and return whether it
/// changed (so the caller asks KWin to reload only then).
///
/// # Errors
/// Whatever reading or writing the rules file raised.
pub(crate) fn ensure_overlay_rule(config_home: &Path, class: &str) -> std::io::Result<bool> {
    let path = config_home.join("kwinrulesrc");
    let current = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let next = merged(&current, class);
    if next == current {
        return Ok(false);
    }
    std::fs::create_dir_all(config_home)?;
    let staged = path.with_extension("apogee-new");
    std::fs::write(&staged, &next)?;
    std::fs::rename(&staged, &path)?;
    Ok(true)
}

/// `current` with the rules in place: each group replaced or appended, and listed once in
/// `[General] rules` with `count` matching the list.
fn merged(current: &str, class: &str) -> String {
    let mut sections: Vec<(String, Vec<String>)> = vec![(String::new(), Vec::new())];
    for line in current.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            sections.push((trimmed[1..trimmed.len() - 1].to_owned(), Vec::new()));
        } else if let Some((_, lines)) = sections.last_mut() {
            lines.push(line.to_owned());
        }
    }
    let ours = rules(class);
    sections.retain(|(name, _)| !ours.iter().any(|(group, _)| name == group));
    let at = if let Some(at) = sections.iter().position(|(name, _)| name == "General") {
        at
    } else {
        sections.insert(1, ("General".to_owned(), Vec::new()));
        1
    };
    let general = &mut sections[at].1;
    let mut listed: Vec<String> = general
        .iter()
        .find_map(|line| line.trim().strip_prefix("rules="))
        .map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty() && !ours.iter().any(|(group, _)| id == group))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    listed.extend(ours.iter().map(|(group, _)| (*group).to_owned()));
    general.retain(|line| {
        let key = line.trim();
        !key.starts_with("rules=") && !key.starts_with("count=")
    });
    general.retain(|line| !line.trim().is_empty());
    general.insert(0, format!("count={}", listed.len()));
    general.insert(1, format!("rules={}", listed.join(",")));
    for (group, body) in ours {
        sections.push((group.to_owned(), body.lines().map(str::to_owned).collect()));
    }

    let mut out = String::new();
    for (name, lines) in &sections {
        let body: Vec<&String> = lines.iter().filter(|l| !l.trim().is_empty()).collect();
        if name.is_empty() {
            for line in body {
                out.push_str(line);
                out.push('\n');
            }
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push('[');
        out.push_str(name);
        out.push_str("]\n");
        for line in body {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Ask a running KWin to reload its rules. Best effort: with no KWin on the session bus the rule is
/// simply picked up the next time KWin starts.
pub(crate) fn reload() {
    let tried = [
        (
            "busctl",
            &[
                "--user",
                "call",
                "org.kde.KWin",
                "/KWin",
                "org.kde.KWin",
                "reconfigure",
            ][..],
        ),
        ("qdbus", &["org.kde.KWin", "/KWin", "reconfigure"][..]),
    ];
    for (program, args) in tried {
        if std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }
    }
    tracing::info!(
        "KWin did not take a reload request; the overlay rule applies when it next starts"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users() -> &'static str {
        "[General]\ncount=1\nrules=act-overlays-on-top\n\n[act-overlays-on-top]\n\
                         Description=mine\nwmclass=steam_app_0\nlayer=overlay\nlayerrule=2\n"
    }

    #[test]
    fn the_rule_joins_the_users_rules_and_leaves_theirs_alone() {
        let out = merged(users(), "steam_app_apogee");
        assert!(
            out.contains("count=3\nrules=act-overlays-on-top,apogee-overlays,apogee-act\n"),
            "{out}"
        );
        assert!(out.contains("[act-overlays-on-top]\nDescription=mine\nwmclass=steam_app_0\n"));
        assert!(
            out.contains("[apogee-overlays]\n")
                && out.contains("titlematch=3\n")
                && !out.contains("OverlayForm")
        );
        // A second pass changes nothing, so KWin is not asked to reload every launch.
        assert_eq!(merged(&out, "steam_app_apogee"), out);
    }

    #[test]
    fn a_stale_rule_is_replaced_not_duplicated_and_a_missing_file_is_created() {
        let old = merged(users(), "steam_app_0");
        let out = merged(&old, "steam_app_apogee");
        assert_eq!(out.matches("[apogee-overlays]").count(), 1);
        assert_eq!(out.matches("[apogee-act]").count(), 1);
        assert!(out.contains("desktopfile=apogee-act\ndesktopfilerule=2\n"));
        assert!(
            out.contains("wmclass=steam_app_apogee\n")
                && !out.contains("wmclass=steam_app_0\nwmclassmatch")
        );
        assert!(out.contains("count=3\n"));

        let fresh = merged("", "steam_app_apogee");
        assert!(
            fresh.starts_with("[General]\ncount=2\nrules=apogee-overlays,apogee-act\n"),
            "{fresh}"
        );
    }

    #[test]
    fn the_file_is_written_only_when_it_changes() {
        let home = tempfile::tempdir().unwrap();
        assert!(ensure_overlay_rule(home.path(), "steam_app_apogee").unwrap());
        assert!(!ensure_overlay_rule(home.path(), "steam_app_apogee").unwrap());
    }
}
