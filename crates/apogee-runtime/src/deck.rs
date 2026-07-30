//! What kind of machine this is, where that changes how a game should be launched.
//!
//! Three facts that are routinely conflated and are not the same question. The **board** says what
//! the hardware is, and only that answers "does this have a Steam Deck's CPU". The **OS image** says
//! whether SteamOS is installed, which is neither necessary (a Deck runs Bazzite or Arch just as
//! well) nor sufficient (SteamOS ships on machines that are not Decks). The **session** says whether
//! the launch is happening under the Steam compositor rather than a desktop, which is a property of
//! how the user is logged in and changes between reboots on one machine.
//!
//! Each is read separately and reported separately. The reads are split from the parsing the same way
//! the kernel version is ([`crate::env`]), so what a given board string means is decided by a test
//! over literals rather than by whatever machine happens to run the suite.

/// A Steam Deck, by the board name Valve ships in its firmware.
///
/// Both models are 1280x800; they differ in panel and refresh ceiling, not resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeckModel {
    /// The original LCD Deck, which the board calls `Jupiter`.
    Lcd,
    /// The OLED Deck, which the board calls `Galileo`.
    Oled,
}

/// What the host is, as far as anything here changes because of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HostIdentity {
    /// The Steam Deck this is, from the board itself. `None` on everything else.
    pub deck: Option<DeckModel>,
    /// SteamOS is the installed distribution. Independent of `deck` in both directions.
    pub steamos: bool,
    /// The session is the Steam compositor rather than a desktop.
    pub game_mode: bool,
}

impl HostIdentity {
    /// Read the host's identity. Every probe degrades to "no" rather than failing, because a machine
    /// that cannot answer is a machine with no Deck tuning to apply, not a launch to refuse. On a
    /// target with none of these paths that is every probe, which is the correct answer there.
    #[must_use]
    pub fn detect() -> Self {
        Self {
            deck: read_board_name().as_deref().and_then(parse_deck_model),
            steamos: read_os_release()
                .as_deref()
                .is_some_and(os_release_is_steamos),
            game_mode: session_is_game_mode(),
        }
    }
}

/// The board's own product name, as the firmware reports it.
fn read_board_name() -> Option<String> {
    std::fs::read_to_string("/sys/class/dmi/id/product_name").ok()
}

fn read_os_release() -> Option<String> {
    std::fs::read_to_string("/etc/os-release").ok()
}

/// Which Deck a board name identifies, if any.
///
/// Matched case-insensitively on the trimmed value: the strings come from firmware this project does
/// not control, and a board that renames itself is better read as no Deck than as the wrong one.
fn parse_deck_model(product_name: &str) -> Option<DeckModel> {
    let name = product_name.trim();
    if name.eq_ignore_ascii_case("Jupiter") {
        Some(DeckModel::Lcd)
    } else if name.eq_ignore_ascii_case("Galileo") {
        Some(DeckModel::Oled)
    } else {
        None
    }
}

/// Whether an `os-release` file describes SteamOS.
///
/// Keyed on `ID`, never on `VARIANT_ID`: the variant is an image label that says which edition was
/// installed, so reading it as hardware calls a Steam Machine a handheld.
fn os_release_is_steamos(text: &str) -> bool {
    os_release_value(text, "ID").is_some_and(|id| id.eq_ignore_ascii_case("steamos"))
}

/// One `KEY=value` from an `os-release` file, unquoted. Comments and blank lines are skipped, and a
/// repeated key keeps the first, since that is the one a shell sourcing the file would see last-wins
/// only if it re-assigned, which these files do not.
fn os_release_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((found, value)) = line.split_once('=') else {
            continue;
        };
        if found.trim() != key {
            continue;
        }
        let value = value.trim();
        let unquoted = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        return Some(unquoted.to_owned());
    }
    None
}

/// Whether the session is the Steam compositor. It names itself in the desktop variable, which is
/// what distinguishes a Deck booted into its game session from the same Deck at a desktop.
fn session_is_game_mode() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|desktop| desktop_is_game_mode(&desktop))
}

/// Whether a desktop-environment name includes the Steam compositor. The variable is a
/// colon-separated list of names from most to least specific, so it is split rather than compared.
fn desktop_is_game_mode(desktop: &str) -> bool {
    desktop
        .split(':')
        .any(|name| name.trim().eq_ignore_ascii_case("gamescope"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn board_names_identify_the_two_deck_models() {
        assert_eq!(parse_deck_model("Jupiter"), Some(DeckModel::Lcd));
        assert_eq!(parse_deck_model("Galileo"), Some(DeckModel::Oled));
        // Firmware values arrive with a trailing newline when read from the board.
        assert_eq!(parse_deck_model("Jupiter\n"), Some(DeckModel::Lcd));
        assert_eq!(parse_deck_model("galileo"), Some(DeckModel::Oled));
    }

    #[test]
    fn no_other_board_is_a_deck() {
        for name in [
            "X570 AORUS ELITE WIFI",
            "ROG Ally RC71L",
            "Galileo Pro",
            "Jupiter2",
            "",
        ] {
            assert_eq!(parse_deck_model(name), None, "{name} is not a Deck");
        }
    }

    /// The distribution and the hardware are separate answers, and the pairing that proves it is a
    /// Deck running something else: the board still says Jupiter while `ID` says otherwise.
    #[test]
    fn steamos_is_read_from_the_id_and_not_from_the_variant() {
        let steamos = "NAME=\"SteamOS\"\nID=steamos\nID_LIKE=arch\nVARIANT_ID=steamdeck\n";
        assert!(os_release_is_steamos(steamos));

        let deck_running_something_else = "NAME=\"Bazzite\"\nID=bazzite\nID_LIKE=\"fedora\"\n";
        assert!(!os_release_is_steamos(deck_running_something_else));

        // A desktop image that merely mentions the variant is not SteamOS.
        assert!(!os_release_is_steamos("ID=arch\nVARIANT_ID=steamdeck\n"));
    }

    #[test]
    fn os_release_values_survive_quoting_comments_and_spacing() {
        let text = "# a comment\n\nNAME=\"SteamOS\"\nID = steamos \nPRETTY='Steam Deck'\n";
        assert_eq!(os_release_value(text, "NAME").as_deref(), Some("SteamOS"));
        assert_eq!(os_release_value(text, "ID").as_deref(), Some("steamos"));
        assert_eq!(
            os_release_value(text, "PRETTY").as_deref(),
            Some("Steam Deck")
        );
        assert_eq!(os_release_value(text, "MISSING"), None);
        assert_eq!(os_release_value("", "ID"), None);
        assert_eq!(os_release_value("garbage with no equals", "ID"), None);
    }

    #[test]
    fn a_quoted_id_that_is_not_steamos_stays_not_steamos() {
        assert!(os_release_is_steamos("ID=\"steamos\"\n"));
        assert!(!os_release_is_steamos("ID=\"steamos-like\"\n"));
    }

    /// The desktop variable is a colon-separated list, so an exact string comparison misses a
    /// session that names the compositor alongside anything else.
    #[test]
    fn game_mode_is_found_anywhere_in_the_desktop_list() {
        assert!(desktop_is_game_mode("gamescope"));
        assert!(desktop_is_game_mode("gamescope:Steam"));
        assert!(desktop_is_game_mode("Steam:gamescope"));
        assert!(!desktop_is_game_mode("KDE"));
        assert!(!desktop_is_game_mode("gamescope-session"));
        assert!(!desktop_is_game_mode(""));
    }
}
