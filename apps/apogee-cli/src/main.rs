//! The headless launcher CLI: profile management and the login → launch flows, driving the one
//! `apogee-core` command/event surface. It holds no launcher logic: it parses arguments, collects a
//! password, issues a [`Command`], and renders the [`Event`] stream. The output format is a plain
//! line per event and is not a stable interface.

use std::error::Error;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apogee_core::{
    Account, AccountKind, AddonEvent, BenchStats, Command, Core, CoreConfig, Event, ExternalAddon,
    FrameLog, OtpSource, PatchProgress, Profile, Region, RunIn, RunnerSelection, Secret,
    SetupEvent, Trigger, Uuid,
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
    /// Frame-consistency analysis over MangoHud frametime logs.
    Bench {
        #[command(subcommand)]
        action: BenchAction,
    },
    /// Manage the tools that run alongside the game.
    Addon {
        #[command(subcommand)]
        action: AddonAction,
    },
    /// Back up, restore, and prune the game's settings.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Load Dalamud into the game, or leave it out.
    Dalamud {
        #[command(subcommand)]
        action: DalamudAction,
    },
}

#[derive(Subcommand)]
enum DalamudAction {
    /// Say whether this profile loads it.
    Status(TargetArgs),
    /// Load it into the game from the next launch on. It is installed on that launch, not now.
    Enable(TargetArgs),
    /// Stop loading it. Nothing is deleted, and nothing contacts its distribution while it is off.
    Disable(TargetArgs),
}

#[derive(Subcommand)]
enum BackupAction {
    /// Capture the game settings in a profile's prefix.
    Create(BackupCreateArgs),
    /// List a profile's backups, newest first.
    List(TargetArgs),
    /// Put a backup back. The tree it replaces is set aside, not deleted.
    #[cfg(unix)]
    Restore(BackupRestoreArgs),
    /// Delete all but the newest N backups. Only archives this launcher wrote are considered.
    Prune(BackupPruneArgs),
}

#[derive(Args)]
struct BackupCreateArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// A note carried in the archive, such as why it was taken.
    #[arg(long)]
    note: Option<String>,
}

#[cfg(unix)]
#[derive(Args)]
struct BackupRestoreArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// The archive to restore, as shown by `backup list`.
    #[arg(long)]
    archive: PathBuf,
}

#[derive(Args)]
struct BackupPruneArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// How many to keep. Keeping none is not expressible: it would delete every backup there is.
    #[arg(long, default_value = "5")]
    keep: NonZeroUsize,
}

#[derive(Subcommand)]
enum AddonAction {
    /// List a profile's tools, in the order they run.
    List(TargetArgs),
    /// Add a tool.
    Add(AddonAddArgs),
    /// Remove a tool by its position in the list.
    Remove(AddonIndexArgs),
    /// Include a tool in the next launch.
    Enable(AddonIndexArgs),
    /// Leave a tool out of the next launch without discarding it.
    Disable(AddonIndexArgs),
}

#[derive(Args)]
struct AddonAddArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// Absolute path to the program. A relative path would resolve against wherever the launcher
    /// started, so the same profile would run different code depending on how it was invoked.
    #[arg(long)]
    program: PathBuf,
    /// An argument for the program. Repeat for each; they are passed through verbatim.
    /// Hyphens are allowed, since a tool's own flags are the common case.
    #[arg(long = "arg", allow_hyphen_values = true)]
    args: Vec<String>,
    /// Where it runs: `host` (a native binary or script) or `prefix` (a Windows program).
    #[arg(long, default_value = "host")]
    run_in: String,
    /// When it runs: `with-game`, `with-game-keep-running`, or `on-close`.
    #[arg(long, default_value = "with-game")]
    trigger: String,
}

#[derive(Args)]
struct AddonIndexArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// The tool's position in the list, as shown by `addon list`.
    #[arg(long)]
    index: usize,
}

#[derive(Subcommand)]
enum BenchAction {
    /// Compute frame-consistency metrics from one or more MangoHud frametime CSV logs.
    Analyze(BenchAnalyzeArgs),
}

#[derive(Args)]
struct BenchAnalyzeArgs {
    /// MangoHud CSV files, or directories to scan (non-recursively) for `*.csv`.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
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
        Commands::Bench { action } => bench(action),
        Commands::Addon { action } => {
            addon(&core, action)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Backup { action } => {
            backup(&core, action)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Dalamud { action } => {
            dalamud(&core, action)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The Dalamud toggle, read from and written back to the profile that owns it.
///
/// Nothing is installed here. The setting is what a launch reads, and a launch is the only thing that
/// contacts the distribution, so switching it on offline stays offline.
fn dalamud(core: &Core, action: DalamudAction) -> Result<(), CliError> {
    let (args, on) = match action {
        DalamudAction::Status(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            println!(
                "dalamud is {}",
                if profile.launch.dalamud {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            return Ok(());
        }
        DalamudAction::Enable(args) => (args, true),
        DalamudAction::Disable(args) => (args, false),
    };
    let mut profile = resolve_profile(core, &args.profile)?;
    profile.launch.dalamud = on;
    core.save_profile(&profile)?;
    println!(
        "{} dalamud for {}",
        if on { "enabled" } else { "disabled" },
        profile.name
    );
    Ok(())
}

/// Frame-consistency analysis over MangoHud frametime logs. Offline: reads CSVs and prints a table;
/// the metrics themselves live in the library.
fn bench(action: BenchAction) -> Result<ExitCode, CliError> {
    match action {
        BenchAction::Analyze(args) => bench_analyze(&args.paths),
    }
}

fn bench_analyze(paths: &[PathBuf]) -> Result<ExitCode, CliError> {
    let files = collect_csv_files(paths)?;
    if files.is_empty() {
        return Err("no CSV files found in the given paths".into());
    }
    println!(
        "{:<32}  {:>6}  {:>7}  {:>7}  {:>7}  {:>8}  {:>8}  {:>7}",
        "file", "frames", "dur(s)", "avg", "1%low", "0.1%low", "ft(ms)", "ft(sd)"
    );
    let mut failed = false;
    for file in files {
        let name = file.file_name().map_or_else(
            || file.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        match analyze_one(&file) {
            Ok(s) => println!(
                "{:<32}  {:>6}  {:>7.3}  {:>7.2}  {:>7.2}  {:>8.2}  {:>8.3}  {:>7.3}",
                truncate(&name, 32),
                s.frame_count,
                s.duration_s,
                s.average_fps,
                s.low_1pct,
                s.low_0_1pct,
                s.frametime_mean_ms,
                s.frametime_stddev_ms,
            ),
            Err(err) => {
                failed = true;
                println!("{:<32}  error: {err}", truncate(&name, 32));
            }
        }
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Parse one MangoHud CSV into frame-consistency metrics.
fn analyze_one(file: &Path) -> Result<BenchStats, CliError> {
    let text = std::fs::read_to_string(file)?;
    Ok(FrameLog::from_mangohud_csv(&text)?.stats()?)
}

/// Expand the given paths: files are kept as-is, directories are scanned (non-recursively, sorted)
/// for `*.csv`.
fn collect_csv_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, CliError> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(path)?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|p| {
                    p.extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
                        // MangoHud writes a companion `<name>_summary.csv` (no frametime rows) next
                        // to each frametime log; skip it so a dir scan hits only the real logs.
                        && !p
                            .file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.ends_with("_summary.csv"))
                })
                .collect();
            found.sort();
            files.extend(found);
        } else {
            files.push(path.clone());
        }
    }
    Ok(files)
}

/// Shorten a display string to at most `max` characters, marking the cut with a trailing `..`.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        s.chars().take(max - 2).collect::<String>() + ".."
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
    let config = CoreConfig::try_from_env()?;
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

/// The game's settings: captured, listed, put back, and pruned.
fn backup(core: &Core, action: BackupAction) -> Result<(), CliError> {
    match action {
        BackupAction::Create(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            let (report, others) = core.backup_config(profile.id, args.note)?;
            println!(
                "backed up {} file(s), {} bytes -> {}",
                report.roots.iter().map(|r| r.files()).sum::<usize>(),
                report.archive_bytes,
                report.archive.display()
            );
            // Stated rather than hidden: a prefix run under more than one runner holds more than one
            // tree, and only the one the game wrote to last was captured.
            for other in others {
                println!("note: not captured, an older tree: {}", other.display());
            }
            Ok(())
        }
        BackupAction::List(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            let records = core.backups(profile.id)?;
            if records.is_empty() {
                println!("no backups");
                return Ok(());
            }
            for record in records {
                println!(
                    "{:>10}  {:>9}  {}",
                    record.created_at,
                    record.bytes,
                    record.path.display()
                );
            }
            Ok(())
        }
        #[cfg(unix)]
        BackupAction::Restore(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            let report = core.restore_config(profile.id, &args.archive)?;
            for root in &report.restored {
                println!(
                    "restored {} file(s) to {}",
                    root.files,
                    root.target.display()
                );
                if let Some(aside) = &root.displaced_to {
                    println!("  the tree that was there is at {}", aside.display());
                }
            }
            Ok(())
        }
        BackupAction::Prune(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            let report = core.prune_backups(profile.id, args.keep)?;
            println!(
                "kept {}, deleted {}, left {} file(s) alone",
                report.kept,
                report.deleted.len(),
                report.foreign
            );
            Ok(())
        }
    }
}

/// The tools that run alongside the game, read from and written back to the profile that owns them.
fn addon(core: &Core, action: AddonAction) -> Result<(), CliError> {
    match action {
        AddonAction::List(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            if profile.external.is_empty() {
                println!("no tools configured");
                return Ok(());
            }
            for (index, addon) in profile.external.iter().enumerate() {
                println!(
                    "{index}  {:<7}  {:<22}  {}{}",
                    render_run_in(addon.run_in()),
                    render_trigger(addon.trigger()),
                    addon.program().display(),
                    if addon.enabled() { "" } else { "  (disabled)" }
                );
            }
            Ok(())
        }
        AddonAction::Add(args) => {
            let mut profile = resolve_profile(core, &args.profile)?;
            let addon = ExternalAddon::new(
                args.program,
                args.args,
                parse_run_in(&args.run_in)?,
                parse_trigger(&args.trigger)?,
            )?;
            println!(
                "added tool {} at {}",
                addon.program().display(),
                profile.external.len()
            );
            profile.external.push(addon);
            core.save_profile(&profile)?;
            Ok(())
        }
        AddonAction::Remove(args) => {
            let mut profile = resolve_profile(core, &args.profile)?;
            let addon = take_addon(&mut profile.external, args.index)?;
            core.save_profile(&profile)?;
            println!("removed tool {}", addon.program().display());
            Ok(())
        }
        AddonAction::Enable(args) => set_enabled(core, &args, true),
        AddonAction::Disable(args) => set_enabled(core, &args, false),
    }
}

fn set_enabled(core: &Core, args: &AddonIndexArgs, on: bool) -> Result<(), CliError> {
    let mut profile = resolve_profile(core, &args.profile)?;
    let addon = profile
        .external
        .get_mut(args.index)
        .ok_or_else(|| out_of_range(args.index))?;
    addon.set_enabled(on);
    let program = addon.program().display().to_string();
    core.save_profile(&profile)?;
    println!("{} tool {program}", if on { "enabled" } else { "disabled" });
    Ok(())
}

fn take_addon(addons: &mut Vec<ExternalAddon>, index: usize) -> Result<ExternalAddon, CliError> {
    if index >= addons.len() {
        return Err(out_of_range(index));
    }
    Ok(addons.remove(index))
}

fn out_of_range(index: usize) -> CliError {
    format!("no tool at index {index} (see `addon list`)").into()
}

fn parse_run_in(spec: &str) -> Result<RunIn, CliError> {
    match spec {
        "host" => Ok(RunIn::Host),
        "prefix" => Ok(RunIn::Prefix),
        other => Err(format!("unknown location {other:?} (expected host or prefix)").into()),
    }
}

/// Total over the library's states, so the combination that would start a tool and immediately kill
/// it has no spelling here either, and no rule is needed in the shell to reject it.
fn parse_trigger(spec: &str) -> Result<Trigger, CliError> {
    match spec {
        "with-game" => Ok(Trigger::WithGame {
            keep_after_close: false,
        }),
        "with-game-keep-running" => Ok(Trigger::WithGame {
            keep_after_close: true,
        }),
        "on-close" => Ok(Trigger::OnClose),
        other => Err(format!(
            "unknown trigger {other:?} (expected with-game, with-game-keep-running, or on-close)"
        )
        .into()),
    }
}

fn render_run_in(run_in: RunIn) -> &'static str {
    match run_in {
        RunIn::Host => "host",
        RunIn::Prefix => "prefix",
        _ => "?",
    }
}

fn render_trigger(trigger: Trigger) -> &'static str {
    match trigger {
        Trigger::WithGame {
            keep_after_close: false,
        } => "with-game",
        Trigger::WithGame {
            keep_after_close: true,
        } => "with-game-keep-running",
        Trigger::OnClose => "on-close",
        _ => "?",
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
        Event::Addon(addon) => render_addon(addon),
        Event::Setup(setup) => render_setup(setup),
        Event::Frontier(_) => "frontier data received".to_owned(),
        Event::Error(err) => format!("error: {err}"),
        _ => "unrecognized event".to_owned(),
    }
}

/// Render one companion-tool event as a plain line.
fn render_addon(event: &AddonEvent) -> String {
    match event {
        AddonEvent::Started { program, pid } => {
            format!("addon: started {} (pid {pid})", program.display())
        }
        AddonEvent::AlreadyRunning { program, pid } => {
            format!("addon: {} already running (pid {pid})", program.display())
        }
        AddonEvent::Stopped { program, pid } => {
            format!("addon: stopped {} (pid {pid})", program.display())
        }
        AddonEvent::Finished { program, outcome } => {
            format!("addon: {} finished ({outcome:?})", program.display())
        }
        AddonEvent::Failed { program, reason } => {
            format!("addon: {} failed: {reason}", program.display())
        }
        AddonEvent::StillWaiting { program, seconds } => {
            format!("addon: still waiting on {} ({seconds}s)", program.display())
        }
        _ => "addon: event".to_owned(),
    }
}

/// Render one prefix-setup event as a plain line. A caveat is printed like everything else rather than
/// saved for a summary, because being read while the thing is being set up is its whole purpose.
fn render_setup(event: &SetupEvent) -> String {
    match event {
        SetupEvent::Downloading {
            what,
            bytes_done,
            total,
        } => format!(
            "setup: {what} downloading {bytes_done}/{}",
            total.map_or_else(|| "?".to_owned(), |t| t.to_string())
        ),
        SetupEvent::Installing { what, version } => format!("setup: installing {what} {version}"),
        SetupEvent::Installed { what } => format!("setup: installed {what}"),
        SetupEvent::AlreadyPresent { what } => format!("setup: {what} is already applied"),
        SetupEvent::Applying { verb, reason } => format!("setup: applying {verb} ({reason})"),
        SetupEvent::Applied { verb } => format!("setup: applied {verb}"),
        SetupEvent::Caveat { what, note } => format!("setup: {what} note: {note}"),
        SetupEvent::Failed { what, reason } => format!("setup: {what} failed: {reason}"),
        SetupEvent::CatalogUnavailable {
            detail,
            using_cached,
        } => {
            if *using_cached {
                format!("setup: catalog unreachable, using the last one fetched ({detail})")
            } else {
                format!("setup: no catalog available, applying none ({detail})")
            }
        }
        _ => "setup: event".to_owned(),
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
