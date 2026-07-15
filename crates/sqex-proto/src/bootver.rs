//! The unauthenticated boot-version check.
//!
//! A plain-HTTP GET asking whether the boot component is current. An empty or whitespace body means
//! current; otherwise the body is a boot patchlist naming the pending patches in order. This is also
//! the one endpoint CI is allowed to call live, to keep the patchlist parser honest against
//! genuinely-current SE output.

use http::{HeaderName, HeaderValue, Method};
use url::Url;

use crate::error::{ProtoError, Step, excerpt};
use crate::identity::PATCHER_USER_AGENT;
use crate::patchlist::{PatchListEntry, parse_patch_list};
use crate::time::LauncherTime;
use crate::transport::{ProtoRequest, Transport, TransportError};

/// Base of the boot-version endpoint; the boot version and `time` query are appended.
const BOOT_VERSION_BASE: &str = "http://patch-bootver.ffxiv.com/http/win32/ffxivneo_release_boot";
/// The `Host` the boot check addresses.
const BOOT_VERSION_HOST: &str = "patch-bootver.ffxiv.com";
/// The status a healthy boot check answers with.
const HTTP_OK: u16 = 200;

/// Ask whether the boot component named by `boot_version` is current.
///
/// Returns the pending boot patches in list order, or an empty vector when boot is current.
pub async fn check_boot_version(
    transport: &dyn Transport,
    boot_version: &str,
    now: &LauncherTime,
) -> Result<Vec<PatchListEntry>, ProtoError> {
    let request = build_request(boot_version, now)?;
    let response = transport.execute(request).await?;

    if response.status != HTTP_OK {
        return Err(ProtoError::InvalidResponse {
            step: Step::BootVersion,
            status: response.status,
            excerpt: excerpt(&response.body),
        });
    }

    let body = String::from_utf8_lossy(&response.body);
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    parse_patch_list(&body)
}

/// Build the boot-check request. The dynamic path and query segments are percent-encoded through the
/// URL builder, so a malformed input yields a valid-but-wrong URL rather than an injection; the error
/// arms exist only to keep the build panic-free and are unreachable for the constant base.
fn build_request(boot_version: &str, now: &LauncherTime) -> Result<ProtoRequest, TransportError> {
    let mut url = Url::parse(BOOT_VERSION_BASE)
        .map_err(|_| TransportError::new("invalid boot-version base URL"))?;
    url.path_segments_mut()
        .map_err(|()| TransportError::new("boot-version base URL cannot be a base"))?
        .push(boot_version)
        .push("");
    url.query_pairs_mut()
        .append_pair("time", &now.boot_check_timestamp());

    Ok(ProtoRequest::new(Method::GET, url)
        .header(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static(PATCHER_USER_AGENT),
        )
        .header(
            HeaderName::from_static("host"),
            HeaderValue::from_static(BOOT_VERSION_HOST),
        ))
}
