// The unauthenticated boot-version check. This is the one endpoint CI is allowed to call live, to
// keep the patchlist parser honest against genuinely-current SE output.

use http::{HeaderName, HeaderValue, Method};

use crate::error::{ProtoError, Step};
use crate::identity::PATCHER_USER_AGENT;
use crate::patchlist::{PatchListEntry, parse_patch_list};
use crate::time::LauncherTime;
use crate::transport::{ProtoRequest, Transport, TransportError, parse_base};

const BOOT_VERSION_BASE: &str = "http://patch-bootver.ffxiv.com/http/win32/ffxivneo_release_boot";
const BOOT_VERSION_HOST: &str = "patch-bootver.ffxiv.com";

pub async fn check_boot_version(
    transport: &dyn Transport,
    boot_version: &str,
    now: &LauncherTime,
) -> Result<Vec<PatchListEntry>, ProtoError> {
    let request = build_request(boot_version, now)?;
    let response = transport.execute(request).await?;

    // A current boot answers `204 No Content` with no body, which is an ordinary disposition rather
    // than a fault, so it is matched before the 200-only gate below (observed against the live
    // service; the same shape `register_session` documents for a current game).
    if response.status == 204 {
        return Ok(Vec::new());
    }

    if !response.is_ok() {
        // No secrets to scrub: the boot-version check runs before login, carrying only the installed
        // boot version.
        return Err(ProtoError::invalid_response(
            Step::BootVersion,
            &response,
            &[],
        ));
    }

    // `str::trim` follows `char::is_whitespace`, which does not classify U+FEFF, so a body carrying a
    // byte-order mark reads as non-empty and falls through to the parser: a BOM-stamped current boot
    // would report a patch that does not exist. Strip one leading mark before both the emptiness gate
    // and the parse, the way `decode_ver` does for the version files SE stamps the same way.
    let decoded = String::from_utf8_lossy(&response.body);
    let body = decoded.strip_prefix('\u{feff}').unwrap_or(&decoded);
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    parse_patch_list(body)
}

// `accept`/`accept-encoding` are declared even though the reference launcher sends neither: a reqwest
// client merges its own default `Accept: */*` and negotiated encoding into any request that omits
// them, after the point the fidelity check reads the built request back, so an undeclared default is
// invisible to it. Declaring the identical `*/*` here keeps the wire byte unchanged while bringing the
// header inside the check; see `crate::NEGOTIATED_HEADERS` for the `accept-encoding` exemption.
fn build_request(boot_version: &str, now: &LauncherTime) -> Result<ProtoRequest, TransportError> {
    let mut url = parse_base(BOOT_VERSION_BASE, "invalid boot-version base URL")?;
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
            HeaderName::from_static("accept"),
            HeaderValue::from_static("*/*"),
        )
        .header(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate"),
        )
        .header(
            HeaderName::from_static("host"),
            HeaderValue::from_static(BOOT_VERSION_HOST),
        ))
}
