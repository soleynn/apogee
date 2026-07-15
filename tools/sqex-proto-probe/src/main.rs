//! A dev-only login probe.
//!
//! Drives `sqex-proto`'s OAuth flow against live Square Enix servers with a real account, recording
//! each raw request/response into `target/capture/<scenario>/` so a genuine login can be sanitized into
//! test fixtures. It runs one successful login and one deliberate wrong-password login (to capture the
//! failure page), printing each step's shape without ever printing or persisting the session id.
//!
//! Reads `SQEX_ID` and `SQEX_PASSWORD` from the process environment or a `.env` file in the working
//! directory. Never run in CI: it needs a real account and a network. Run from the repo root:
//!
//! ```text
//! cargo run --manifest-path tools/sqex-proto-probe/Cargo.toml
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::{HeaderName, HeaderValue};
use sqex_proto::{
    ComputerId, Credentials, LauncherTime, LoginKind, OauthContext, ProtoError, ProtoRequest,
    ProtoResponse, Transport, TransportError, begin_login,
};

const CAPTURE_ROOT: &str = "target/capture";

#[tokio::main]
async fn main() {
    load_dotenv();
    let sqexid = env_or_die("SQEX_ID");
    let password = env_or_die("SQEX_PASSWORD");

    let client = reqwest::Client::builder()
        .gzip(true)
        .deflate(true)
        .build()
        .expect("build http client");

    // One real login, captured as the success fixtures.
    run_login(&client, "success", &sqexid, &password).await;
    // One deliberate wrong password, captured as the failure fixture. Derived from the real one (so it
    // is not a hard-coded secret) and guaranteed to differ. A single attempt, no retries.
    let wrong_password = format!("{password}-invalid");
    run_login(&client, "wrong_password", &sqexid, &wrong_password).await;
}

async fn run_login(client: &reqwest::Client, scenario: &str, sqexid: &str, password: &str) {
    let transport = RecordingTransport::new(client.clone(), Path::new(CAPTURE_ROOT).join(scenario));

    // Fixed synthetic identity: the captures carry no real machine data.
    let computer_id = ComputerId::from_facts("APOGEE-PROBE", "apogee", "Linux", 8);
    let now = utc_now();
    let context = OauthContext {
        computer_id: &computer_id,
        language: "en-us",
        accept_language: "en-US,en;q=0.9",
        referer_template: "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
        lng: "en",
        region: 3,
    };

    println!("[{scenario}] fetching the login top page");
    let flow = match begin_login(
        &transport,
        &context,
        &now,
        LoginKind::Standard { free_trial: false },
    )
    .await
    {
        Ok(flow) => flow,
        Err(err) => {
            println!("[{scenario}] begin_login failed: {err}");
            return;
        }
    };
    println!("[{scenario}] server date: {:?}", flow.server_date());

    println!("[{scenario}] submitting credentials");
    match flow
        .submit(Credentials {
            sqexid,
            password,
            otp: None,
        })
        .await
    {
        Ok(auth) => println!(
            "[{scenario}] authenticated: {:?} region={} max_expansion={} playable={} terms_accepted={}",
            auth.session_id(),
            auth.region,
            auth.max_expansion,
            auth.playable,
            auth.terms_accepted,
        ),
        Err(ProtoError::OauthFailed { excerpt }) => {
            println!("[{scenario}] oauth rejected (expected for a wrong password): {excerpt}");
        }
        Err(err) => println!("[{scenario}] submit failed: {err}"),
    }
    println!("[{scenario}] capture written under {CAPTURE_ROOT}/{scenario}");
}

/// A [`Transport`] over reqwest that records every exchange to disk for later sanitizing.
struct RecordingTransport {
    client: reqwest::Client,
    dir: PathBuf,
    seq: AtomicUsize,
}

impl RecordingTransport {
    fn new(client: reqwest::Client, dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).expect("create capture directory");
        Self {
            client,
            dir,
            seq: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl Transport for RecordingTransport {
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let label = if req.url.path().ends_with("/top") {
            "top"
        } else {
            "login"
        };
        let stem = format!("{seq:02}-{label}");

        // The request body can contain the password, so this whole directory is gitignored and never
        // committed; only the sanitized response bodies become fixtures.
        std::fs::write(self.dir.join(format!("{stem}-request.txt")), render_request(&req))
            .expect("write request capture");

        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes())
            .map_err(|_| TransportError::new("unsupported method"))?;
        let mut builder = self.client.request(method, req.url.clone());
        for (name, value) in &req.headers {
            // reqwest manages content negotiation itself (client `.gzip`/`.deflate`); forwarding our
            // declared accept-encoding would disable its automatic decompression.
            if name.as_str() == "accept-encoding" {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }

        let response = builder
            .send()
            .await
            .map_err(|err| TransportError::new(format!("request failed: {err}")))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .map_err(|err| TransportError::new(format!("reading body failed: {err}")))?
            .to_vec();

        let mut header_dump = format!("status: {status}\n");
        for (name, value) in &headers {
            header_dump.push_str(&format!(
                "{}: {}\n",
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes())
            ));
        }
        std::fs::write(self.dir.join(format!("{stem}-response-headers.txt")), header_dump)
            .expect("write response headers");
        std::fs::write(self.dir.join(format!("{stem}-response-body.html")), &body)
            .expect("write response body");

        let mut out = ProtoResponse::new(status, body);
        if let Some(date) = headers.get(http::header::DATE) {
            if let Ok(value) = HeaderValue::from_bytes(date.as_bytes()) {
                out = out.with_header(HeaderName::from_static("date"), value);
            }
        }
        Ok(out)
    }
}

fn render_request(req: &ProtoRequest) -> String {
    let mut out = format!("{} {}\n", req.method.as_str(), req.url.as_str());
    for (name, value) in &req.headers {
        out.push_str(&format!(
            "{}: {}\n",
            name.as_str(),
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    if let Some(body) = &req.body {
        out.push('\n');
        out.push_str(&String::from_utf8_lossy(body));
    }
    out
}

/// Load `KEY=VALUE` lines from a `.env` file in the working directory into the process environment,
/// without overriding anything already set. Missing file is not an error.
fn load_dotenv() {
    let Ok(contents) = std::fs::read_to_string(".env") else {
        return;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches(['"', '\'']);
            if std::env::var_os(key).is_none() {
                std::env::set_var(key, value);
            }
        }
    }
}

fn env_or_die(key: &str) -> String {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => value,
        _ => {
            eprintln!("set {key} in the environment or a .env file in the working directory");
            std::process::exit(2);
        }
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
