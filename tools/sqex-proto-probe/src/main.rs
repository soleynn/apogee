//! A dev-only login probe.
//!
//! Drives `sqex-proto`'s OAuth flow against live Square Enix servers with a real account, recording
//! each raw request/response into `target/capture/<scenario>/` so a genuine login can be sanitized into
//! test fixtures. It runs one successful login and one deliberate wrong-password login (to capture the
//! failure page), printing each step's shape without ever printing or persisting the session id, the
//! TOTP secret, the generated code, or the issued patch unique id.
//!
//! Reads from the process environment or a `.env` file in the working directory:
//!
//! - `SQEX_ID`, `SQEX_PASSWORD` (required).
//! - `SQEX_TOTP_SECRET` (optional): a base32 setup key or an `otpauth://` URI for a 2FA account. When
//!   set, the probe generates the current 6-digit SHA-1/30 s code **at the server's `Date` time** (the
//!   clock-skew-corrected path) and submits it, capturing the success under `target/capture/otp/`.
//! - `SQEX_OTP` (optional): a manually-typed 6-digit code, used only when `SQEX_TOTP_SECRET` is unset.
//!   Codes expire in 30 s, so this is racy; the secret is preferred.
//! - `SQEX_GAME_PATH` (optional): the root of an installed game (the directory holding `boot/` and
//!   `game/`). When set, a successful login is followed by a session-registration step that reports the
//!   install's version and prints the disposition (the unique id stays redacted). An outdated install
//!   yields a pending patchlist; a corrupt one yields a repairable version-files error.
//!
//! With no OTP configured it behaves as before (plain `success` scenario), so it still works on a
//! no-2FA account. Never run in CI: it needs a real account and a network. Run from the repo root:
//!
//! ```text
//! cargo run --manifest-path tools/sqex-proto-probe/Cargo.toml
//! ```
//!
//! Sanitizing a capture into a fixture: keep the response bodies, replace the session id and `_STORED_`
//! blob with same-shape fakes, and delete the `*-request.txt` files (they carry the password and the
//! OTP code). The whole `target/capture/` tree is gitignored.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::{HeaderName, HeaderValue};
use sqex_proto::{
    begin_login, register_session, Authenticated, ClientContext, ComputerId, Credentials,
    InstallPaths, LauncherTime, LoginKind, OauthContext, ProtoError, ProtoRequest, ProtoResponse,
    Registration, Transport, TransportError, VersionReport,
};
use totp_rs::{Algorithm, Secret, TOTP};

const CAPTURE_ROOT: &str = "target/capture";

/// Where a scenario's one-time password comes from.
enum OtpPlan {
    /// No 2FA: submit an empty `otppw` (the original behavior).
    None,
    /// A code typed by the operator, submitted verbatim (no skew correction).
    Manual(String),
    /// A TOTP secret the probe generates a code from, at server time.
    Totp(Vec<u8>),
}

#[tokio::main]
async fn main() {
    load_dotenv();
    let sqexid = env_or_die("SQEX_ID");
    let password = env_or_die("SQEX_PASSWORD");
    let otp_plan = resolve_otp_plan();

    let client = reqwest::Client::builder()
        .gzip(true)
        .deflate(true)
        .build()
        .expect("build http client");

    // The success capture: `otp` when 2FA is configured (the fixture we need), else the plain
    // no-OTP login so the probe still works on a no-2FA account.
    match otp_plan {
        OtpPlan::None => run_login(&client, "success", &sqexid, &password, &OtpPlan::None).await,
        _ => run_login(&client, "otp", &sqexid, &password, &otp_plan).await,
    }

    // One deliberate wrong password, captured as the failure fixture. Derived from the real one (so it
    // is not a hard-coded secret) and guaranteed to differ. A single attempt, no retries, no OTP.
    // Off by default so a routine run does not throw a bad login at a real account; opt in with
    // SQEX_CAPTURE_WRONG_PASSWORD when the failure fixture actually needs re-recording.
    if std::env::var_os("SQEX_CAPTURE_WRONG_PASSWORD").is_some() {
        let wrong_password = format!("{password}-invalid");
        run_login(
            &client,
            "wrong_password",
            &sqexid,
            &wrong_password,
            &OtpPlan::None,
        )
        .await;
    }
}

/// The OAuth region to log in under. Defaults to 3 (the global/Europe login); override with
/// SQEX_REGION to match an account whose home region differs (e.g. 2 for North America).
fn probe_region() -> u16 {
    std::env::var("SQEX_REGION")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(3)
}

async fn run_login(
    client: &reqwest::Client,
    scenario: &str,
    sqexid: &str,
    password: &str,
    otp_plan: &OtpPlan,
) {
    let transport = RecordingTransport::new(client.clone(), Path::new(CAPTURE_ROOT).join(scenario));

    // Fixed synthetic identity: the captures carry no real machine data.
    let computer_id = ComputerId::from_facts("APOGEE-PROBE", "apogee", "Linux", 8);
    let now = utc_now();
    let context = OauthContext {
        client: ClientContext {
            computer_id: &computer_id,
            language: "en-us",
            accept_language: "en-US,en;q=0.9",
            referer_template:
                "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
        },
        lng: "en",
        region: probe_region(),
    };

    println!("[{scenario}] using oauth region {}", context.region);
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

    // Build the OTP code from the plan. For TOTP, generate at the server's `Date` time so a skewed
    // local clock cannot desync the code. The code is never printed.
    let code = match otp_plan {
        OtpPlan::None => None,
        OtpPlan::Manual(code) => {
            println!("[{scenario}] submitting an operator-supplied code (no skew correction)");
            Some(code.clone())
        }
        OtpPlan::Totp(secret) => {
            let local = utc_unix();
            let base = match flow.server_date().and_then(parse_http_date) {
                Some(server) => {
                    println!(
                        "[{scenario}] clock skew vs server: {}s (generating at server time)",
                        server as i64 - local as i64
                    );
                    server
                }
                None => {
                    println!("[{scenario}] no usable server Date; generating at local time");
                    local
                }
            };
            let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret.clone());
            let generated = totp.generate(base);
            println!(
                "[{scenario}] otp code generated (redacted, {} digits)",
                generated.len()
            );
            Some(generated)
        }
    };

    println!("[{scenario}] submitting credentials");
    match flow
        .submit(Credentials {
            sqexid,
            password,
            otp: code.as_deref(),
        })
        .await
    {
        Ok(auth) => {
            println!(
                "[{scenario}] authenticated: {:?} region={} max_expansion={} playable={} terms_accepted={}",
                auth.session_id(),
                auth.region,
                auth.max_expansion,
                auth.playable,
                auth.terms_accepted,
            );
            // A successful login can be followed by session registration when a game install is named.
            if let Some(game_path) = env_opt("SQEX_GAME_PATH") {
                run_register(&transport, scenario, &auth, &game_path).await;
            }
        }
        Err(ProtoError::OauthFailed { excerpt }) => {
            println!("[{scenario}] oauth rejected (expected for a wrong password): {excerpt}");
        }
        Err(err) => println!("[{scenario}] submit failed: {err}"),
    }
    println!("[{scenario}] capture written under {CAPTURE_ROOT}/{scenario}");
}

/// Register the session against an installed game, printing the disposition. Reads the install's
/// version files (repairable errors are printed, not fatal); the unique id is never printed raw.
async fn run_register(
    transport: &dyn Transport,
    scenario: &str,
    auth: &Authenticated,
    game_path: &str,
) {
    let paths = InstallPaths::new(game_path);
    let report = match VersionReport::from_install(&paths, auth.max_expansion) {
        Ok(report) => report,
        Err(err) => {
            println!("[{scenario}] version report unavailable (repair the install): {err}");
            return;
        }
    };
    println!(
        "[{scenario}] registering session (game_version={})",
        report.game_version()
    );
    match register_session(transport, auth, &report).await {
        Ok(Registration::Registered {
            unique_id,
            pending_patches,
        }) => println!(
            "[{scenario}] registered: unique_id={unique_id:?} pending_patches={}",
            pending_patches.len()
        ),
        Ok(Registration::NeedsBootPatch) => println!("[{scenario}] disposition: NeedsBootPatch"),
        Ok(Registration::VersionNotServiced) => {
            println!("[{scenario}] disposition: VersionNotServiced");
        }
        Err(err) => println!("[{scenario}] register failed: {err}"),
    }
}

/// Resolve the OTP source from the environment, preferring a stored secret over a typed code.
fn resolve_otp_plan() -> OtpPlan {
    if let Some(raw) = env_opt("SQEX_TOTP_SECRET") {
        let base32 = extract_base32_secret(&raw);
        match Secret::Encoded(base32).to_bytes() {
            Ok(bytes) => return OtpPlan::Totp(bytes),
            Err(err) => {
                eprintln!("SQEX_TOTP_SECRET is not a valid base32 secret: {err:?}");
                std::process::exit(2);
            }
        }
    }
    if let Some(code) = env_opt("SQEX_OTP") {
        return OtpPlan::Manual(code);
    }
    OtpPlan::None
}

/// Pull the base32 secret out of an `otpauth://` URI, or accept a raw setup key (spaces stripped,
/// upper-cased). If a URI carries no `secret=`, the whole string falls through and fails to decode.
fn extract_base32_secret(input: &str) -> String {
    let input = input.trim();
    let raw = if input.starts_with("otpauth://") {
        input
            .split(['?', '&'])
            .find_map(|kv| kv.strip_prefix("secret="))
            .unwrap_or(input)
    } else {
        input
    };
    raw.replace(' ', "").to_uppercase()
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
        } else if req.url.path().contains("ffxivneo_release_game") {
            "register"
        } else {
            "login"
        };
        let stem = format!("{seq:02}-{label}");

        // The request body can contain the password and the OTP code, so this whole directory is
        // gitignored and never committed; only the sanitized response bodies become fixtures.
        std::fs::write(
            self.dir.join(format!("{stem}-request.txt")),
            render_request(&req),
        )
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
            builder = builder.body(body.as_bytes().to_vec());
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
        std::fs::write(
            self.dir.join(format!("{stem}-response-headers.txt")),
            header_dump,
        )
        .expect("write response headers");
        std::fs::write(self.dir.join(format!("{stem}-response-body.html")), &body)
            .expect("write response body");

        let mut out = ProtoResponse::new(status, body);
        if let Some(date) = headers.get(http::header::DATE) {
            if let Ok(value) = HeaderValue::from_bytes(date.as_bytes()) {
                out = out.with_header(HeaderName::from_static("date"), value);
            }
        }
        // Session registration reads the patch unique id off this header; surface it so `register_session`
        // can see a `Registered` disposition. (`HeaderMap::get` is case-insensitive.)
        if let Some(uid) = headers.get("x-patch-unique-id") {
            if let Ok(value) = HeaderValue::from_bytes(uid.as_bytes()) {
                out = out.with_header(HeaderName::from_static("x-patch-unique-id"), value);
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
        out.push_str(&String::from_utf8_lossy(body.as_bytes()));
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
    match env_opt(key) {
        Some(value) => value,
        None => {
            eprintln!("set {key} in the environment or a .env file in the working directory");
            std::process::exit(2);
        }
    }
}

/// A non-empty environment variable, or `None`.
fn env_opt(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// Seconds since the Unix epoch, for the skew comparison.
fn utc_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse an HTTP-date (`Wed, 09 Jul 2025 12:00:00 GMT`, RFC 7231 IMF-fixdate) to Unix seconds. Returns
/// `None` on anything that does not match that fixed shape.
fn parse_http_date(s: &str) -> Option<u64> {
    let (_weekday, rest) = s.trim().split_once(", ")?;
    let mut fields = rest.split(' ');
    let day: i64 = fields.next()?.parse().ok()?;
    let month = month_num(fields.next()?)?;
    let year: i64 = fields.next()?.parse().ok()?;
    let mut time = fields.next()?.split(':');
    let hour: u64 = time.next()?.parse().ok()?;
    let minute: u64 = time.next()?.parse().ok()?;
    let second: u64 = time.next()?.parse().ok()?;
    let days = days_from_civil(year, month, day);
    Some(days as u64 * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn month_num(name: &str) -> Option<i64> {
    Some(match name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's `days_from_civil`, the inverse of the
/// `civil_from_days` in [`utc_now`]).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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
