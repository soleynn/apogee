//! Live boot-version check.
//!
//! Two unauthenticated GETs to Square Enix's real boot endpoint, covering both dispositions the
//! endpoint has. The first sends the base sentinel, which SE answers with the pending boot patch
//! chain, so the patchlist parser runs against live output. The second re-sends the last version that
//! chain offers: that version is by construction the current boot, so it must read as no pending
//! patches. Deriving the second version from the first keeps the check working across boot patches
//! with no maintenance, where a hardcoded version would go stale at every one.
//!
//! The second probe exists because the two dispositions are not the same shape on the wire: a current
//! boot answers `204 No Content`, which a 200-only status gate rejected as a protocol fault. Only the
//! sentinel was ever probed, so nothing caught it until a live patch run did.
//!
//! Exit codes separate the two kinds of failure so CI can gate on one and tolerate the other:
//!
//! - `0`: both probes agreed.
//! - `1`: SE answered and the answer was read wrongly. A regression, and reproducible.
//! - `2`: SE could not be reached. Infrastructure, and worth retrying.
//!
//! No account, no secrets.
//!
//! ```text
//! cargo run --manifest-path tools/boot-check/Cargo.toml
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use sqex_proto::{
    check_boot_version, LauncherTime, ProtoError, ProtoRequest, ProtoResponse, Transport,
    TransportError,
};

/// Old enough that SE answers with the pending boot patch chain, so the parser is exercised and the
/// current version can be derived from what the chain offers last.
const BOOT_SENTINEL: &str = "2012.01.01.0000.0000";

/// SE answered and the answer was read wrongly.
const EXIT_MISREAD: i32 = 1;
/// SE could not be reached.
const EXIT_UNREACHABLE: i32 = 2;

/// How many times the probe pair runs before a disagreement is called a regression.
const PAIR_ATTEMPTS: u32 = 2;

#[tokio::main]
async fn main() {
    let client = reqwest::Client::builder()
        .build()
        .expect("build http client");
    let transport = HttpTransport { client };

    // A boot patch published between the two probes leaves the derived version no longer current, so
    // a disagreement is re-derived once before it is reported: a genuine misread reproduces, a
    // rollout race does not. Unreachability is not retried here, because exit 2 already tells the
    // caller to.
    for attempt in 1..=PAIR_ATTEMPTS {
        match probe_pair(&transport).await {
            Ok(()) => return,
            Err(Failure::Unreachable(message)) => {
                eprintln!("live boot check could not reach the service: {message}");
                std::process::exit(EXIT_UNREACHABLE);
            }
            Err(Failure::Misread(message)) if attempt < PAIR_ATTEMPTS => {
                eprintln!("live boot check disagreed, re-deriving once: {message}");
            }
            Err(Failure::Misread(message)) => {
                eprintln!("live boot check misread the service: {message}");
                std::process::exit(EXIT_MISREAD);
            }
        }
    }
}

/// Why a probe pair failed, split by whether CI should read it as a regression.
enum Failure {
    /// SE could not be reached: DNS, connect, TLS, timeout, or a truncated read.
    Unreachable(String),
    /// SE answered, and the answer was either read wrongly or was not a shape the endpoint has.
    Misread(String),
}

impl From<ProtoError> for Failure {
    fn from(err: ProtoError) -> Self {
        let message = err.to_string();
        match err {
            ProtoError::Transport(_) => Self::Unreachable(message),
            _ => Self::Misread(message),
        }
    }
}

/// Probe the sentinel for the pending boot chain, then re-probe the last version it offers and
/// require that one to read as current.
///
/// Each probe stamps its own timestamp, as a real client would.
async fn probe_pair(transport: &dyn Transport) -> Result<(), Failure> {
    let pending = check_boot_version(transport, BOOT_SENTINEL, &utc_now()).await?;
    let Some(latest) = pending.last() else {
        return Err(Failure::Misread(format!(
            "the sentinel {BOOT_SENTINEL} reported no pending boot patches, so no current version could be derived from it"
        )));
    };
    println!(
        "probe 1: {} boot patch(es) pending from the sentinel, latest {}",
        pending.len(),
        latest.version_id
    );

    let current = check_boot_version(transport, &latest.version_id, &utc_now()).await?;
    if !current.is_empty() {
        return Err(Failure::Misread(format!(
            "{} is the last version the boot chain offers, yet re-probing it returned {} pending patch(es) instead of reading as current",
            latest.version_id,
            current.len()
        )));
    }
    println!(
        "probe 2: {} reads as current (no pending patches)",
        latest.version_id
    );
    Ok(())
}

/// A plain reqwest-backed [`Transport`]. The boot check reads only the status and body, so response
/// headers are not carried back.
struct HttpTransport {
    client: reqwest::Client,
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes())
            .map_err(|_| TransportError::new("unsupported method"))?;
        let mut builder = self.client.request(method, req.url.clone());
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.as_bytes().to_vec());
        }

        let response = builder
            .send()
            .await
            .map_err(|err| TransportError::new(format!("request failed: {err}")))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|err| TransportError::new(format!("reading body failed: {err}")))?
            .to_vec();
        Ok(ProtoResponse::new(status, body))
    }
}

/// The current UTC broken down into launcher-time parts, via the civil-from-days algorithm (no date
/// dependency).
fn utc_now() -> LauncherTime {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since_epoch.as_secs();
    let millis = since_epoch.as_millis() as u64;

    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let hour = (secs_of_day / 3_600) as u8;
    let minute = ((secs_of_day % 3_600) / 60) as u8;

    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year_civil = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let year = (year_civil + i64::from(month <= 2)) as u16;

    LauncherTime::from_parts(year, month, day, hour, minute, millis)
}
