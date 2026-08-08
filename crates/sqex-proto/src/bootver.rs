//! The unauthenticated boot-version check.
//!
//! A plain-HTTP GET asking whether the boot component is current. A current boot answers `204 No
//! Content`; a pending one a `200` whose body is a boot patchlist naming the patches in order. This
//! is the one endpoint CI is allowed to call live, to keep the patchlist parser honest against
//! genuinely-current SE output.

use http::{HeaderName, HeaderValue, Method};

use crate::error::{ProtoError, Step};
use crate::identity::PATCHER_USER_AGENT;
use crate::patchlist::{PatchListEntry, parse_patch_list};
use crate::time::LauncherTime;
use crate::transport::{ProtoRequest, Transport, TransportError, parse_base};

const BOOT_VERSION_BASE: &str = "http://patch-bootver.ffxiv.com/http/win32/ffxivneo_release_boot";
const BOOT_VERSION_HOST: &str = "patch-bootver.ffxiv.com";

/// Ask whether the boot component named by `boot_version` is current.
///
/// Returns the pending boot patches in list order, or an empty vector when boot is current. Current
/// is signaled two ways, both observed against the live service: a `204 No Content` with no body
/// (the same shape [`register_session`](crate::register_session) documents for a current game), or
/// a `200` whose body is empty or whitespace-only, including one stamped with a leading UTF-8 BOM
/// (stripped before both the emptiness check and the parse, matching [`decode_ver`](crate::decode_ver)'s
/// handling of the `.ver` files SE stamps the same way — a BOM is not itself whitespace, so an
/// un-stripped one would fall through to the parser and report a patch that does not exist).
///
/// # Errors
///
/// Returns [`ProtoError::Transport`] if the request could not be sent, [`ProtoError::InvalidResponse`]
/// if SE answers with a status other than `200` or `204`, or [`ProtoError::PatchListParse`] if a
/// `200` body is non-empty but not a well-formed patchlist.
///
/// # Examples
///
/// ```
/// # fn block_on<F: std::future::Future>(fut: F) -> F::Output {
/// #     let mut fut = std::pin::pin!(fut);
/// #     let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
/// #     loop {
/// #         if let std::task::Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
/// #             return val;
/// #         }
/// #     }
/// # }
/// use sqex_proto::{
///     LauncherTime, ProtoRequest, ProtoResponse, Transport, TransportError, check_boot_version,
/// };
///
/// struct CurrentBoot;
///
/// #[async_trait::async_trait]
/// impl Transport for CurrentBoot {
///     async fn execute(&self, _req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
///         Ok(ProtoResponse::new(204, Vec::new()))
///     }
/// }
///
/// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
/// let patches = block_on(check_boot_version(&CurrentBoot, "2024.01.01.0000.0000", &now)).unwrap();
/// assert!(patches.is_empty());
/// ```
pub async fn check_boot_version(
    transport: &dyn Transport,
    boot_version: &str,
    now: &LauncherTime,
) -> Result<Vec<PatchListEntry>, ProtoError> {
    let request = build_request(boot_version, now)?;
    let response = transport.execute(request).await?;

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
