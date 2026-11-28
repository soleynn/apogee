//! What the distribution serves, and what this launcher writes down about it.
//!
//! No response type here is `#[serde(deny_unknown_fields)]`, on purpose: the distribution adds fields
//! (a changelog, a display name, an applicability flag it computes against its own idea of the current
//! game version) and a client that refused them would break on an upstream release note. What this
//! launcher reads is what it acts on, and nothing more.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A response body as UTF-8 JSON text, whatever encoding its byte-order mark names.
///
/// The distribution serves at least one document, the runtime digest map, as UTF-16LE with a BOM, and a
/// JSON parser reading those bytes as UTF-8 refuses them. A body with no BOM is taken as UTF-8 untouched;
/// a UTF-8 BOM is dropped. A UTF-16 body that is not whole code units or not valid UTF-16 is refused.
pub(crate) fn json_text(bytes: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>, BadEncoding> {
    let utf16 = |body: &[u8], unit: fn([u8; 2]) -> u16| -> Result<Vec<u8>, BadEncoding> {
        let (units, rest) = body.as_chunks::<2>();
        if !rest.is_empty() {
            return Err(BadEncoding);
        }
        let units: Vec<u16> = units.iter().map(|pair| unit(*pair)).collect();
        String::from_utf16(&units)
            .map(String::into_bytes)
            .map_err(|_| BadEncoding)
    };
    match bytes {
        [0xEF, 0xBB, 0xBF, body @ ..] => Ok(std::borrow::Cow::Borrowed(body)),
        [0xFF, 0xFE, body @ ..] => utf16(body, u16::from_le_bytes).map(std::borrow::Cow::Owned),
        [0xFE, 0xFF, body @ ..] => utf16(body, u16::from_be_bytes).map(std::borrow::Cow::Owned),
        _ => Ok(std::borrow::Cow::Borrowed(bytes)),
    }
}

/// A response whose byte-order mark names UTF-16 but whose body is not valid UTF-16.
#[derive(Debug, thiserror::Error)]
#[error("a UTF-16 response body is not valid UTF-16")]
pub(crate) struct BadEncoding;

/// A path-to-digest map, keyed by a Windows-shaped relative path with an uppercase hex value.
pub(crate) type HashManifest = BTreeMap<String, String>;

/// One release of Dalamud, as its distribution describes it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionInfo {
    /// The directory name the version is laid down under, used verbatim.
    pub(crate) assembly_version: String,
    /// The game version this build was made for. Compared for equality against the install's own, and
    /// a difference means "do not load", not "fail".
    #[serde(default)]
    pub(crate) supported_game_ver: String,
    /// A path component of the runtime tree, used verbatim.
    #[serde(default)]
    pub(crate) runtime_version: String,
    /// Whether the bundled .NET runtime has to be fetched at all.
    #[serde(default)]
    pub(crate) runtime_required: bool,
    /// The track that answered, which the injector is told about so a crash report says which it was.
    #[serde(default)]
    pub(crate) track: String,
    /// Where the release archive is, which is an absolute URL rather than anything derivable. Kept as
    /// written and parsed at the point of use, so a distribution serving something that is not a URL is
    /// this crate's typed error rather than a deserializer's.
    pub(crate) download_url: String,
}

/// The asset set, versioned as a whole and hashed per file.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssetMeta {
    /// Monotonic. A set is refreshed when this is *higher* than what is on disk, so a rollback upstream
    /// does not drag every client back with it.
    pub(crate) version: u32,
    /// The whole set in one archive. The per-asset `url` fields exist but are not what a client fetches.
    pub(crate) package_url: String,
    #[serde(default)]
    pub(crate) assets: Vec<AssetEntry>,
}

/// One asset, relative to the versioned asset directory.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssetEntry {
    pub(crate) file_name: String,
    /// Absent or empty means "this one is not checked", which the distribution does use.
    #[serde(default)]
    pub(crate) hash: Option<String>,
}

impl AssetEntry {
    /// The digest to check this asset against, if it carries one.
    pub(crate) fn digest(&self) -> Option<&str> {
        self.hash.as_deref().filter(|hash| !hash.is_empty())
    }
}

/// What a completed install left behind, written by this launcher rather than served by anybody.
///
/// It exists so the launch path can answer "what is installed, and is it for this game version?"
/// without a network round trip, which is what keeps a disabled setting from reaching the distribution
/// and a launch from waiting on it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Installed {
    /// The release on disk, which is also its directory name.
    pub assembly_version: String,
    /// The game version it was built for.
    pub supported_game_ver: String,
    /// The bundled runtime it was installed against.
    pub runtime_version: String,
    /// The distribution track it came from.
    pub track: String,
    /// The asset set on disk.
    pub asset_version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le_with_bom(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        bytes
    }

    /// The live runtime digest map arrives as UTF-16LE with a BOM and CRLF line ends.
    #[test]
    fn a_utf16le_digest_map_parses() {
        let body = utf16le_with_bom("{\r\n  \"dotnet.exe\": \"0A1B\"\r\n}");
        let text = json_text(&body).expect("decode");
        let map: HashManifest = serde_json::from_slice(&text).expect("parse");
        assert_eq!(map.get("dotnet.exe").map(String::as_str), Some("0A1B"));
    }

    #[test]
    fn a_body_with_a_byte_order_mark_is_decoded_by_it() {
        let mut be = vec![0xFE, 0xFF];
        be.extend("{}".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(&*json_text(&be).expect("decode"), b"{}");
        assert_eq!(&*json_text(b"\xEF\xBB\xBF{}").expect("decode"), b"{}");
        assert_eq!(&*json_text(b"{}").expect("decode"), b"{}");
    }

    #[test]
    fn a_broken_utf16_body_is_refused() {
        // A dangling byte, and an unpaired high surrogate.
        assert!(json_text(&[0xFF, 0xFE, b'{', 0x00, b'}']).is_err());
        assert!(json_text(&[0xFF, 0xFE, 0x00, 0xD8, b'{', 0x00]).is_err());
    }

    /// The distribution serves more than this launcher reads, and adds to it between releases. Refusing
    /// an unknown field would turn an upstream release note into a launcher that cannot install.
    #[test]
    fn a_version_response_carrying_fields_this_build_ignores_still_parses() {
        let json = r#"{
            "key": "", "track": "release", "assemblyVersion": "15.0.2.3",
            "runtimeVersion": "10.0.0", "runtimeRequired": true,
            "supportedGameVer": "2026.06.18.0000.0000",
            "isApplicableForCurrentGameVer": true,
            "changelog": { "date": "2026-07-17T14:06:34", "version": "15.0.2.3", "changes": [] },
            "downloadUrl": "https://kamori.goats.dev/File/Get/abc",
            "hidden": false, "displayName": "Stable", "description": "…"
        }"#;
        let info: VersionInfo = serde_json::from_str(json).expect("parse");
        assert_eq!(info.assembly_version, "15.0.2.3");
        assert_eq!(info.runtime_version, "10.0.0");
        assert!(info.runtime_required);
        assert_eq!(info.supported_game_ver, "2026.06.18.0000.0000");
        assert_eq!(info.track, "release");
        assert_eq!(info.download_url, "https://kamori.goats.dev/File/Get/abc");
    }

    /// An asset with no digest is one the distribution does not check, and it says so with a null rather
    /// than by omitting the field.
    #[test]
    fn an_asset_without_a_digest_is_not_checked() {
        let json = r#"{
            "version": 432,
            "packageUrl": "https://kamori.goats.dev/File/Get/pkg",
            "assets": [
              { "url": "https://kamori.goats.dev/File/Get/a", "fileName": "UIRes/bannedplugin.json",
                "hash": null },
              { "url": "https://kamori.goats.dev/File/Get/b", "fileName": "UIRes/font.otf",
                "hash": "7334F0BADA3A7D52E1C642217EB7EA21BE700421" }
            ]
        }"#;
        let meta: AssetMeta = serde_json::from_str(json).expect("parse");
        assert_eq!(meta.version, 432);
        assert_eq!(meta.assets[0].digest(), None);
        assert_eq!(
            meta.assets[1].digest(),
            Some("7334F0BADA3A7D52E1C642217EB7EA21BE700421")
        );
    }

    /// A hash manifest is a flat map with Windows-shaped keys; nothing about it is nested.
    #[test]
    fn a_hash_manifest_is_a_flat_windows_keyed_map() {
        let json = r#"{ "host\\fxr\\10.0.0\\hostfxr.dll": "A2D22CF8C1DB444C5856E7F90F6C9085" }"#;
        let map: HashManifest = serde_json::from_str(json).expect("parse");
        assert_eq!(
            map.get(r"host\fxr\10.0.0\hostfxr.dll").map(String::as_str),
            Some("A2D22CF8C1DB444C5856E7F90F6C9085")
        );
    }

    /// The record this launcher writes is its own file, so it round-trips through its own reader.
    #[test]
    fn the_installed_record_round_trips() {
        let record = Installed {
            assembly_version: "15.0.2.3".to_owned(),
            supported_game_ver: "2026.06.18.0000.0000".to_owned(),
            runtime_version: "10.0.0".to_owned(),
            track: "release".to_owned(),
            asset_version: 432,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains("\"assemblyVersion\""), "{json}");
        let back: Installed = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.assembly_version, record.assembly_version);
        assert_eq!(back.asset_version, record.asset_version);
    }
}
