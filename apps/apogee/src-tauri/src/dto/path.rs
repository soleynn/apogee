//! Reversible filesystem paths for the JSON boundary.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A path's readable label plus the exact platform representation needed for a round trip.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathDto {
    display: String,
    value: PathValueDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
enum PathValueDto {
    Utf8(String),
    Unix(Vec<u8>),
    Windows(Vec<u16>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnsupportedPathEncoding;

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

impl PathDto {
    pub(crate) fn into_path(self) -> Result<PathBuf, UnsupportedPathEncoding> {
        match self.value {
            PathValueDto::Utf8(path) => Ok(PathBuf::from(path)),
            #[cfg(unix)]
            PathValueDto::Unix(bytes) => {
                use std::ffi::OsString;
                use std::os::unix::ffi::OsStringExt;
                Ok(PathBuf::from(OsString::from_vec(bytes)))
            }
            #[cfg(windows)]
            PathValueDto::Windows(wide) => {
                use std::ffi::OsString;
                use std::os::windows::ffi::OsStringExt;
                Ok(PathBuf::from(OsString::from_wide(&wide)))
            }
            #[cfg(unix)]
            PathValueDto::Windows(_) => Err(UnsupportedPathEncoding),
            #[cfg(windows)]
            PathValueDto::Unix(_) => Err(UnsupportedPathEncoding),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_paths_round_trip() {
        let path = Path::new("install/game");
        assert_eq!(PathDto::from(path).into_path().ok().as_deref(), Some(path));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_round_trip_without_using_the_display_label() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(b"game-\xff".to_vec()));
        let dto = PathDto::from(path.as_path());
        assert!(dto.display.contains('\u{fffd}'));
        assert_eq!(dto.into_path().ok(), Some(path));
    }

    #[test]
    fn another_platforms_encoding_is_rejected() {
        let dto = PathDto {
            display: "untrusted".to_owned(),
            #[cfg(unix)]
            value: PathValueDto::Windows(vec![1]),
            #[cfg(windows)]
            value: PathValueDto::Unix(vec![1]),
        };
        assert_eq!(dto.into_path(), Err(UnsupportedPathEncoding));
    }
}
