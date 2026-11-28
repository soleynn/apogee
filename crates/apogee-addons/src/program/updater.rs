//! Reading whether a program's own self-updater is switched off.
//!
//! The settings file is written by the program and by whoever else shares the prefix, so it is
//! hostile input read on every launch. The reader is total, bounded and fails closed: a key it cannot
//! find, a value it cannot read and a file it cannot parse all mean "not off", because the one wrong
//! answer that costs anything is calling an updater off when it is not.

use crate::manifest::{UpdaterKey, UpdaterKeyFormat};

/// The largest settings file read. Real ones are a few kilobytes.
pub(crate) const MAX_SETTINGS_BYTES: u64 = 4 * 1024 * 1024;

/// What a settings file says about one updater switch.
///
/// # Examples
///
/// ```
/// use apogee_addons::{ComponentManifest, UpdaterState};
///
/// # let json = br#"{"version":1,"programs":[{"name":"p","version":"1","tier":"first_class",
/// #   "game_versions":["1"],"runners":[{"name":"r","version":"1"}],
/// #   "steps":[{"name":"s","reason":"r","ops":[]}],
/// #   "start":{"program":"Apogee/p/p.exe","trigger":"with_game"},
/// #   "updater_keys":[{"file":"p.json","format":"json","key":"autoUpdate","off":"false"}]}]}"#;
/// let manifest = ComponentManifest::from_json_bytes(json)?;
/// let key = &manifest.programs[0].updater_keys[0];
///
/// assert_eq!(key.state_in(br#"{"autoUpdate": false}"#), UpdaterState::Off);
/// assert!(matches!(key.state_in(br#"{"autoUpdate": true}"#), UpdaterState::On { .. }));
/// assert_eq!(key.state_in(b"{}"), UpdaterState::Missing);
/// # Ok::<(), apogee_addons::ManifestError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdaterState {
    /// The key holds the value that means off.
    Off,
    /// The key holds something else.
    #[non_exhaustive]
    On {
        /// What it holds, cut to a short length so a hostile file cannot fill a log line.
        value: String,
    },
    /// The key is not there, or the file is not in the format the row names.
    Missing,
}

impl UpdaterKey {
    /// What `settings`, the bytes of this key's settings file, say about it.
    ///
    /// Every occurrence of the key must read off: a file naming it twice with one copy on is on,
    /// since which one the program reads is not this reader's to guess.
    #[must_use]
    pub fn state_in(&self, settings: &[u8]) -> UpdaterState {
        if settings.len() as u64 > MAX_SETTINGS_BYTES {
            return UpdaterState::Missing;
        }
        let values = match self.format {
            UpdaterKeyFormat::Json => json_values(settings, &self.key),
            UpdaterKeyFormat::XmlSetting => xml_values(settings, &self.key),
        };
        if values.is_empty() {
            return UpdaterState::Missing;
        }
        values
            .into_iter()
            .find(|value| !value.trim().eq_ignore_ascii_case(self.off.trim()))
            .map_or(UpdaterState::Off, |value| UpdaterState::On {
                value: value.chars().take(64).collect(),
            })
    }
}

/// The key's value as a top-level member of a JSON object, in its string form.
///
/// A leading UTF-8 byte order mark is skipped: the programs this reads write their settings with
/// one, and the JSON parser takes it for a stray character.
fn json_values(settings: &[u8], key: &str) -> Vec<String> {
    let settings = settings.strip_prefix(b"\xef\xbb\xbf").unwrap_or(settings);
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(settings)
    else {
        return Vec::new();
    };
    match map.get(key) {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Bool(b)) => vec![b.to_string()],
        Some(serde_json::Value::Number(n)) => vec![n.to_string()],
        // A null, a list or an object is not a switch position, and reads as "not off".
        Some(other) => vec![other.to_string()],
        None => Vec::new(),
    }
}

/// The `Value` of every element whose `Name` is the key.
///
/// Not an XML parser, deliberately: the settings format is one flat run of self-describing elements,
/// and a scanner that reads only attribute pairs inside tags cannot be made to recurse or expand an
/// entity. It reads each tag, from `<` to the next `>`, and the double-quoted attributes in it.
fn xml_values(settings: &[u8], key: &str) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(settings) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('>') else {
            break;
        };
        let tag = &after[..close];
        rest = &after[close + 1..];
        let attrs = attributes(tag);
        if attrs
            .iter()
            .any(|(name, value)| *name == "Name" && *value == key)
        {
            // A matching element without a value is not off.
            values.push(
                attrs
                    .iter()
                    .find(|(name, _)| *name == "Value")
                    .map_or_else(String::new, |(_, value)| (*value).to_owned()),
            );
        }
    }
    values
}

/// The `name="value"` pairs in one tag's text.
fn attributes(tag: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = tag;
    while let Some(eq) = rest.find("=\"") {
        let name = rest[..eq]
            .rsplit(|c: char| c.is_whitespace())
            .next()
            .unwrap_or_default();
        let after = &rest[eq + 2..];
        let Some(end) = after.find('"') else {
            break;
        };
        out.push((name, &after[..end]));
        rest = &after[end + 1..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ComponentManifest;

    fn key(format: &str) -> UpdaterKey {
        let json = format!(
            r#"{{"version":1,"programs":[{{"name":"p","version":"1","tier":"first_class",
              "game_versions":["1"],"runners":[{{"name":"r","version":"1"}}],
              "steps":[{{"name":"s","reason":"r","ops":[]}}],
              "start":{{"program":"Apogee/p/p.exe","trigger":"with_game"}},
              "updater_keys":[{{"file":"p.cfg","format":"{format}","key":"cbAutoCheck","off":"False"}}]}}]}}"#
        );
        let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("parses");
        manifest.programs[0].updater_keys[0].clone()
    }

    /// The settings shape the program writes reads as off, in either case of the boolean, and every
    /// way of saying anything else reads as not off.
    #[test]
    fn an_xml_setting_reads_off_only_when_every_copy_says_so() {
        let key = key("xml_setting");
        let off = br#"<Config><SettingsSerializer>
            <CheckBox Name="cbAutoCheck" Value="False" />
            <CheckBox Name="cbOther" Value="True" />
        </SettingsSerializer></Config>"#;
        assert_eq!(key.state_in(off), UpdaterState::Off);
        assert_eq!(
            key.state_in(br#"<CheckBox Value="false" Name="cbAutoCheck"/>"#),
            UpdaterState::Off
        );
        for (on, why) in [
            (&br#"<CheckBox Name="cbAutoCheck" Value="True" />"#[..], "on"),
            (br#"<CheckBox Name="cbAutoCheck" Value="False"/><CheckBox Name="cbAutoCheck" Value="True"/>"#, "a second copy on"),
            (br#"<CheckBox Name="cbAutoCheck" />"#, "no value"),
        ] {
            assert!(matches!(key.state_in(on), UpdaterState::On { .. }), "{why}");
        }
        for missing in [
            &b""[..],
            b"<CheckBox Name=\"cbAutoCheckX\" Value=\"False\"/>",
            b"<CheckBox Name=\"cbAutoCheck\" Value=\"False\"",
            b"\xff\xfe<",
        ] {
            assert_eq!(key.state_in(missing), UpdaterState::Missing);
        }
    }

    /// A JSON switch reads by its scalar form; a structure, a null or a file over the cap is not off.
    #[test]
    fn a_json_setting_fails_closed() {
        let key = key("json");
        assert_eq!(
            key.state_in(br#"{"cbAutoCheck": "False"}"#),
            UpdaterState::Off
        );
        assert_eq!(
            key.state_in(br#"{"cbAutoCheck": false}"#),
            UpdaterState::Off
        );
        for on in [
            &br#"{"cbAutoCheck": null}"#[..],
            br#"{"cbAutoCheck": [false]}"#,
            br#"{"cbAutoCheck": 0}"#,
        ] {
            assert!(matches!(key.state_in(on), UpdaterState::On { .. }));
        }
        // A byte order mark in front changes nothing, in either direction; a second one is not JSON.
        assert_eq!(
            key.state_in(b"\xef\xbb\xbf{\"cbAutoCheck\": \"False\"}"),
            UpdaterState::Off
        );
        assert!(matches!(
            key.state_in(b"\xef\xbb\xbf{\"cbAutoCheck\": true}"),
            UpdaterState::On { .. }
        ));
        assert_eq!(
            key.state_in(b"\xef\xbb\xbf\xef\xbb\xbf{\"cbAutoCheck\": false}"),
            UpdaterState::Missing
        );
        assert_eq!(key.state_in(b"[]"), UpdaterState::Missing);
        let huge = vec![b' '; usize::try_from(MAX_SETTINGS_BYTES).unwrap() + 1];
        assert_eq!(key.state_in(&huge), UpdaterState::Missing);
    }
}
