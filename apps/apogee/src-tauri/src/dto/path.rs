//! Display-safe filesystem paths projected out of the native boundary.

use std::path::Path;

use serde::Serialize;
use ts_rs::TS;

/// A path's readable label plus its exact platform representation for diagnostics and copying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathDto {
    display: String,
    value: PathValueDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
#[expect(
    dead_code,
    reason = "the stable wire contract includes both platform-native encodings"
)]
enum PathValueDto {
    Utf8(String),
    Unix(Vec<u8>),
    Windows(Vec<u16>),
}

impl From<&Path> for PathDto {
    fn from(path: &Path) -> Self {
        let display = path.to_string_lossy().into_owned();
        let value = match path.to_str() {
            Some(path) => PathValueDto::Utf8(path.to_owned()),
            #[cfg(unix)]
            None => {
                use std::os::unix::ffi::OsStrExt;
                PathValueDto::Unix(path.as_os_str().as_bytes().to_vec())
            }
            #[cfg(windows)]
            None => {
                use std::os::windows::ffi::OsStrExt;
                PathValueDto::Windows(path.as_os_str().encode_wide().collect())
            }
        };
        Self { display, value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_paths_keep_their_display_and_exact_value() {
        let path = Path::new("install/game");
        let dto = PathDto::from(path);
        assert_eq!(dto.display, "install/game");
        assert_eq!(dto.value, PathValueDto::Utf8("install/game".to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_round_trip_without_using_the_display_label() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"game-\xff".to_vec()));
        let dto = PathDto::from(path.as_path());
        assert!(dto.display.contains('\u{fffd}'));
        assert_eq!(dto.value, PathValueDto::Unix(b"game-\xff".to_vec()));
    }
}
