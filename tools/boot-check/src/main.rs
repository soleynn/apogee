//! Live boot-version check.
//!
//! Makes one unauthenticated GET to Square Enix's real boot endpoint and confirms the patchlist
//! parser handles genuinely-current output. It sends a deliberately old boot version so SE returns
//! the pending boot patch chain, exercising the parser rather than the empty-body path. Exits 0 when
//! the response parses (a patchlist or an empty "boot is current"), non-zero otherwise, so CI can run
//! it as an amber canary that flags parser drift against live SE output. No account, no secrets.
//!
//! ```text
//! cargo run --manifest-path tools/boot-check/Cargo.toml
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use sqex_proto::{
    check_boot_version, LauncherTime, ProtoRequest, ProtoResponse, Transport, TransportError,
};

/// Old enough that SE answers with the pending boot patch chain, so the parser is exercised.
const BOOT_VERSION: &str = "2012.01.01.0000.0000";

#[tokio::main]
async fn main() {
    let client = reqwest::Client::builder()
        .build()
        .expect("build http client");
    let transport = HttpTransport { client };

    match check_boot_version(&transport, BOOT_VERSION, &utc_now()).await {
        Ok(entries) if entries.is_empty() => println!("boot is current (empty patchlist parsed)"),
        Ok(entries) => println!(
            "parsed {} boot patch(es) from live SE output",
            entries.len()
        ),
        Err(err) => {
            eprintln!("live boot check did not parse: {err}");
            std::process::exit(1);
        }
    }
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
