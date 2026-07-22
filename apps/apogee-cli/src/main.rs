//! The headless launcher CLI: profile management and the login → launch flows, driving the one
//! `apogee-core` command/event surface. It holds no launcher logic: it parses arguments, collects a
//! password, issues a [`Command`], and renders the [`Event`] stream. The output format is a plain
//! line per event and is not a stable interface.

use std::error::Error;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use apogee_core::{
    Account, AccountKind, Command, Core, CoreConfig, Event, OtpSource, PatchProgress, Profile,
    Region, RunnerSelection, Secret, Uuid,
};
use clap::{Args, Parser, Subcommand};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "fixtures")]
mod fixtures;

/// A convenient boxed error for the CLI's top level.
type CliError = Box<dyn Error>;

#[derive(Parser)]
#[command(name = "apogee-cli", version, about = "Headless Linux FFXIV launcher")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage launch profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Authenticate and register a session (does not launch).
    Login(PlayArgs),
    /// Launch the game from a still-valid cached session.
    Launch(TargetArgs),
    /// Authenticate (or reuse a cached session), apply any pending patches, and launch the game.
    Play(PlayArgs),
    /// Apply any pending boot and game patches, bringing the install current (does not launch).
    Patch(PlayArgs),
    /// Install the game from nothing into the profile's (empty) game directory, then launch.
    Install(PlayArgs),
    /// Verify the install against its signed block indexes and re-fetch only what is broken.
    Repair(TargetArgs),
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Create a profile and its account.
    Add(ProfileAddArgs),
    /// List stored profiles.
    List,
    /// Remove a profile (and its account, if no other profile references it).
    Remove(TargetArgs),
}

#[derive(Args)]
struct ProfileAddArgs {
    /// A display name for the profile.
    #[arg(long)]
    name: String,
    /// The Square Enix login id for the account.
    #[arg(long)]
    user: String,
    /// The game installation directory (the parent of `boot/` and `game/`).
    #[arg(long)]
    game_path: PathBuf,
    /// The runner: `system` (host wine) or `managed:<name>@<version>`.
    #[arg(long, default_value = "system")]
    runner: String,
    /// The account uses a one-time password.
    #[arg(long)]
    otp: bool,
    /// The service region: `global`, `korea`, or `china`.
    #[arg(long, default_value = "global")]
    region: String,
}

#[derive(Args)]
struct TargetArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
}

#[derive(Args)]
struct PlayArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// One-time password code (prompted if omitted and the account uses one).
    #[arg(long)]
    otp: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, CliError> {
    let core = build_core()?;
    match cli.command {
        Commands::Profile { action } => {
            profile(&core, action)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Login(args) => {
            let (profile, password, otp) = gather(&core, &args)?;
            Ok(drive(
                &core,
                Command::Login {
                    profile,
                    password,
                    otp,
                },
            )
            .await)
        }
        Commands::Launch(args) => {
            let profile = resolve_profile(&core, &args.profile)?.id;
            Ok(drive(&core, Command::Launch { profile }).await)
        }
        Commands::Play(args) => {
            let (profile, password, otp) = gather(&core, &args)?;
            Ok(drive(
                &core,
                Command::PatchAndPlay {
                    profile,
                    password,
                    otp,
                },
            )
            .await)
        }
        Commands::Patch(args) => {
            let (profile, password, otp) = gather(&core, &args)?;
            Ok(drive(
                &core,
                Command::Patch {
                    profile,
                    password,
                    otp,
                },
            )
            .await)
        }
        Commands::Install(args) => {
            let (profile, password, otp) = gather(&core, &args)?;
            Ok(drive(
                &core,
                Command::Install {
                    profile,
                    password,
                    otp,
                },
            )
            .await)
        }
        Commands::Repair(args) => {
            let profile = resolve_profile(&core, &args.profile)?.id;
            Ok(drive(&core, Command::Repair { profile }).await)
        }
    }
}

/// Resolve the profile, prompt for the password, and select the one-time-password source: the shared
/// preamble of `login` and `play`.
fn gather(core: &Core, args: &PlayArgs) -> Result<(Uuid, Secret, OtpSource), CliError> {
    let profile = resolve_profile(core, &args.profile)?;
    let account = core.account(profile.account)?;
    let password = read_password()?;
    let otp = read_otp(args, &account)?;
    Ok((profile.id, password, otp))
}

/// Build the core against the real network transport and XDG-resolved storage. Under the `fixtures`
/// feature a scripted transport may be substituted (the launch backend stays real).
fn build_core() -> Result<Core, CliError> {
    let config = CoreConfig::from_env();
    #[cfg(feature = "fixtures")]
    if let Some(transport) = fixtures::transport() {
        return Ok(Core::with_transport(config, transport)?);
    }
    Ok(Core::new(config)?)
}

/// Run `cmd`, printing each event and wiring Ctrl-C to a targeted shutdown of the game.
async fn drive(core: &Core, cmd: Command) -> ExitCode {
    let cancel = CancellationToken::new();
    let on_signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            on_signal.cancel();
        }
    });

    let mut stream = core.execute_cancellable(cmd, cancel);
    let mut failed = false;
    while let Some(event) = stream.next().await {
        if matches!(event, Event::Error(_)) {
            failed = true;
        }
        println!("{}", render(&event));
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn profile(core: &Core, action: ProfileAction) -> Result<(), CliError> {
    match action {
        ProfileAction::Add(args) => {
            let account = Account {
                use_otp: args.otp,
                ..Account::new(args.user, AccountKind::Standard)
            };
            let mut profile = Profile::new(args.name, account.id, args.game_path);
            profile.runner = parse_runner(&args.runner)?;
            profile.launch.region = parse_region(&args.region)?;
            core.save_account(&account)?;
            core.save_profile(&profile)?;
            println!("created profile {} \"{}\"", profile.id, profile.name);
            Ok(())
        }
        ProfileAction::List => {
            let profiles = core.profiles()?;
            if profiles.is_empty() {
                println!("no profiles");
            }
            for p in profiles {
                let user = core
                    .account(p.account)
                    .map(|a| a.sqex_id)
                    .unwrap_or_else(|_| "<missing account>".to_owned());
                println!(
                    "{}  {}  user={}  game={}",
                    p.id,
                    p.name,
                    user,
                    p.game_path.display()
                );
            }
            Ok(())
        }
        ProfileAction::Remove(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            let account = profile.account;
            core.delete_profile(profile.id)?;
            // Prune the account only if no remaining profile still references it.
            if !core.profiles()?.iter().any(|p| p.account == account) {
                let _ = core.delete_account(account);
            }
            println!("removed profile {}", profile.id);
            Ok(())
        }
    }
}

/// Resolve a profile id or unique name to the profile. An id is loaded by key (one file); a name is
/// disambiguated by scanning the profile list.
fn resolve_profile(core: &Core, target: &str) -> Result<Profile, CliError> {
    if let Ok(id) = Uuid::parse_str(target) {
        return Ok(core.profile(id)?);
    }
    let mut matches: Vec<Profile> = core
        .profiles()?
        .into_iter()
        .filter(|p| p.name == target)
        .collect();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(format!("no profile named {target:?}").into()),
        _ => Err(format!("multiple profiles named {target:?}; use the id").into()),
    }
}

/// Read the account password from the terminal without echoing it (or a canned value in fixture mode).
fn read_password() -> Result<Secret, CliError> {
    #[cfg(feature = "fixtures")]
    if let Some(secret) = fixtures::password() {
        return Ok(secret);
    }
    let password = rpassword::prompt_password("Square Enix password: ")?;
    Ok(Secret::new(password.into_bytes()))
}

/// The one-time-password source: the flag, else an interactive prompt when the account uses one.
fn read_otp(args: &PlayArgs, account: &Account) -> Result<OtpSource, CliError> {
    if let Some(code) = &args.otp {
        Ok(OtpSource::Manual(code.clone()))
    } else if account.use_otp {
        Ok(OtpSource::Manual(prompt_line("One-time password: ")?))
    } else {
        Ok(OtpSource::Manual(String::new()))
    }
}

fn parse_runner(spec: &str) -> Result<RunnerSelection, CliError> {
    if spec == "system" {
        return Ok(RunnerSelection::SystemWine);
    }
    if let Some(rest) = spec.strip_prefix("managed:") {
        let (name, version) = rest
            .split_once('@')
            .ok_or("a managed runner must be `managed:<name>@<version>`")?;
        return Ok(RunnerSelection::Managed {
            name: name.to_owned(),
            version: version.to_owned(),
        });
    }
    Err(format!("unknown runner {spec:?} (expected `system` or `managed:<name>@<version>`)").into())
}

fn parse_region(region: &str) -> Result<Region, CliError> {
    match region {
        "global" => Ok(Region::Global),
        "korea" => Ok(Region::Korea),
        "china" => Ok(Region::China),
        other => Err(format!("unknown region {other:?} (expected global, korea, or china)").into()),
    }
}

/// Prompt and read one trimmed line from stdin (echoed).
fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// Render one core event as a line of terminal text. Presentation lives in the shell.
fn render(event: &Event) -> String {
    match event {
        Event::State(state) => format!("state: {state:?}"),
        Event::Progress(progress) => format!("progress: {}/{}", progress.completed, progress.total),
        Event::Patch(patch) => render_patch(patch),
        Event::Frontier(_) => "frontier data received".to_owned(),
        Event::Error(err) => format!("error: {err}"),
        _ => "unrecognized event".to_owned(),
    }
}

/// Render one patch/repair progress frame as a plain line. Byte counts and versions only: no secret
/// (the session credential never appears in a `PatchProgress`).
fn render_patch(patch: &PatchProgress) -> String {
    match patch {
        PatchProgress::Downloading {
            repo,
            index,
            bytes_done,
            total,
        } => format!(
            "patch: {repo:?} #{index} downloading {bytes_done}/{}",
            total.map_or_else(|| "?".to_owned(), |t| t.to_string())
        ),
        PatchProgress::Applying {
            repo,
            index,
            bytes_done,
            total,
        } => format!(
            "patch: {repo:?} #{index} applying {bytes_done}/{}",
            total.map_or_else(|| "?".to_owned(), |t| t.to_string())
        ),
        PatchProgress::Applied {
            repo,
            index,
            version,
        } => format!("patch: {repo:?} #{index} applied -> {version}"),
        PatchProgress::Verifying { repo, attempt } => {
            format!("repair: {repo:?} verifying (attempt {attempt})")
        }
        PatchProgress::Refetching {
            repo,
            attempt,
            bytes,
        } => format!("repair: {repo:?} refetched {bytes} bytes (attempt {attempt})"),
        PatchProgress::Quarantining { repo, count } => {
            format!("repair: {repo:?} quarantining {count} stray file(s)")
        }
        PatchProgress::Repaired { repo, version } => {
            format!("repair: {repo:?} repaired -> {version}")
        }
        _ => "patch: progress".to_owned(),
    }
}
