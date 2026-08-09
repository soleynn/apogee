#![forbid(unsafe_code)]
//! The headless launcher CLI: profile management and the login → launch flows, driving the one
//! `apogee-core` command/event surface. It holds no launcher logic: it parses arguments, collects a
//! password, issues a [`Command`], and renders the [`Event`] stream. The output format is a plain
//! line per event and is not a stable interface.

use std::error::Error;
use std::io::{self, Write};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apogee_core::{
    Account, AccountKind, AddonEvent, BenchStats, Command, Consent, Core, CoreConfig, Deviation,
    EncryptedFile, Event, ExternalAddon, FileState, FlowState, ForeignCredentialStore, ForeignKey,
    ForeignSecretsFile, FrameLog, GpuSelect, HealthIssue, Hud, ImportOutcome, ImportSource,
    KdfCost, ListenerConsent, ListenerSettings, ListenerSources, Notice, OtpDelivery, OtpSource,
    Passphrase, PatchProgress, PrefixAction, PrefixReport, Profile, Region, RunIn, RunnerSelection,
    STEAM_APP_ID, STEAM_FREE_TRIAL_APP_ID, Secret, SecretBackend, SecretKind, SecretSweep,
    SecretsError, SetupEvent, SyncChoice, Trigger, Uuid,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

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
    /// Choose where an account's one-time code comes from, and tune the local listener.
    ///
    /// Its own group rather than a member of `secrets`: every verb there writes or deletes something
    /// in the credential store, and the listener stores nothing at all.
    Otp {
        #[command(subcommand)]
        action: OtpAction,
    },
    /// Read and change the launcher's own preferences.
    Settings {
        #[command(subcommand)]
        action: SettingsCommand,
    },
    /// Manage the passwords and one-time-password secrets the launcher keeps for an account.
    Secrets {
        #[command(subcommand)]
        action: SecretsCommand,
    },
    /// Work on a profile's wine prefix without launching anything.
    Prefix {
        #[command(subcommand)]
        action: PrefixCommand,
    },
    /// Start a profile from the Steam interface, on a handheld or anywhere else without a desktop.
    #[cfg(unix)]
    Steam {
        #[command(subcommand)]
        action: SteamAction,
    },
}

#[derive(Subcommand)]
enum SettingsCommand {
    /// Print the current preferences.
    Show,
    /// Change a preference. Only the ones named are touched.
    Set(SettingsSetArgs),
}

#[derive(Subcommand)]
enum SecretsCommand {
    /// Report which credential store answered and what condition it is in.
    Status,
    /// Save a profile's account password, read from the terminal.
    Save(TargetArgs),
    /// Save the secret a profile's account derives its one-time passwords from, read from stdin, and
    /// stop asking for a code. Takes an `otpauth://` link or the bare base32 secret behind it.
    ///
    /// Read from stdin like every other secret here and never taken as an argument: a shared secret
    /// in `/proc/<pid>/cmdline` is readable by every local user, and it is worse to leak than a code,
    /// which expires in half a minute.
    Totp(TargetArgs),
    /// Delete every secret stored for a profile's account.
    Forget(TargetArgs),
    /// Stop keeping a profile's account password, or start again. Turning it on deletes whatever is
    /// already stored.
    NeverStore(NeverStoreArgs),
    /// Copy a password saved by XIVLauncher into this launcher's store, leaving its copy alone.
    Import(ImportArgs),
    /// Choose where secrets are kept on this machine. Moves nothing: whatever the store being left
    /// behind holds stays there until it is deleted.
    Backend(BackendArgs),
    /// Change the passphrase the sealed file is kept under, and re-seal it under a fresh salt.
    Passphrase,
    /// Delete the sealed file and every secret in it, once the launcher has been pointed somewhere
    /// else. The answer for a forgotten passphrase.
    DestroyFile,
}

/// Where secrets go, as a user names it.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendChoice {
    /// The credential store this platform provides.
    Platform,
    /// A file sealed under a passphrase typed once per run.
    File,
    /// Nothing at all: the password is asked for every time.
    Nothing,
}

impl From<BackendChoice> for SecretBackend {
    fn from(choice: BackendChoice) -> Self {
        match choice {
            BackendChoice::Platform => Self::Platform,
            BackendChoice::File => Self::EncryptedFile,
            BackendChoice::Nothing => Self::Nothing,
        }
    }
}

#[derive(Args)]
struct BackendArgs {
    /// Which store to use from the next run onwards.
    #[arg(long = "to", value_enum)]
    to: BackendChoice,
}

#[derive(Args)]
struct NeverStoreArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// Whether to keep nothing for the account.
    #[arg(long)]
    on: bool,
}

#[derive(Args)]
struct ImportArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// The account name the other launcher filed the password under. Defaults to this account's
    /// Square Enix id, lowercased, which is what that launcher stores. Pass it explicitly if the
    /// account was created on a machine whose language folds letters differently.
    #[arg(long)]
    name: Option<String>,
    /// Read from the plaintext password file that launcher writes when it is configured to keep one,
    /// instead of from the platform credential store.
    #[arg(long)]
    file: Option<PathBuf>,
}

#[derive(Args)]
struct SettingsSetArgs {
    /// Keep downloaded patches after they apply. Costs disk, and lets a later repair rebuild broken
    /// ranges from them instead of downloading again.
    #[arg(long)]
    keep_patches: Option<bool>,
    /// Capture the game's settings before applying patches.
    #[arg(long)]
    backup_before_patch: Option<bool>,
    /// How many captures to keep per profile.
    #[arg(long)]
    backups_kept: Option<u32>,
    /// Stop supervising once the game is up.
    #[arg(long)]
    close_after_launch: Option<bool>,
}

/// The graphics and synchronization knobs a profile launches with.
#[derive(Args)]
struct ProfileEnvArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// Synchronization: `auto`, `ntsync`, `fsync`, `esync`, or `none`. `auto` resolves against the
    /// host and the selected runner.
    #[arg(long)]
    sync: Option<String>,
    /// Overlay: `none`, `mangohud`, or `dxvk:<spec>` (e.g. `dxvk:fps,frametimes`).
    #[arg(long)]
    hud: Option<String>,
    /// GPU: `default`, `nvidia`, `mesa`, or `vulkan:<vendor>:<device>`.
    #[arg(long)]
    gpu: Option<String>,
    /// Ask the system for its game performance profile.
    #[arg(long)]
    gamemode: Option<bool>,
}

#[derive(Subcommand)]
enum PrefixCommand {
    /// Create it if it is not there and bring it up to what a launch would.
    Create(TargetArgs),
    /// Report what has drifted. Changes nothing.
    Health(TargetArgs),
    /// Fix what can be fixed in place, and report what is left.
    Fix(TargetArgs),
    /// Delete it and build it again. Everything installed into it is lost, including the game's own
    /// settings, so it asks first unless told not to.
    Recreate(PrefixRecreateArgs),
}

#[derive(Args)]
struct PrefixRecreateArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
    /// Skip the confirmation. For scripts, which have no one to ask.
    #[arg(long)]
    yes: bool,
}

#[cfg(unix)]
#[derive(Subcommand)]
enum SteamAction {
    /// Say what this machine is and whether Steam has been told about any profile.
    Status,
    /// Offer a profile in Steam's compatibility-tool list. Steam has to be restarted to see it.
    Register(TargetArgs),
    /// Withdraw the offer. Nothing else in the Steam installation is touched.
    Unregister,
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
enum OtpAction {
    /// Say where this profile's account gets its one-time code, and where the listener would sit.
    Status(TargetArgs),
    /// Take the code from a companion app pushing it to this machine, and stop asking for one.
    ///
    /// Opens a port on this machine's network while a login waits, so it asks first.
    Listen(TargetArgs),
    /// Go back to typing the code. Deletes nothing and closes nothing that is not already closed.
    Ask(TargetArgs),
    /// Change where the listener sits and who may reach it. Only the settings named are touched.
    Listener(ListenerArgs),
}

#[derive(Args)]
struct ListenerArgs {
    /// The interface to take. `0.0.0.0` is every interface this machine answers on.
    #[arg(long)]
    bind: Option<IpAddr>,
    /// The port to take. The companion apps dial 4646.
    #[arg(long)]
    port: Option<u16>,
    /// Admit only this address. Repeat for more than one; replaces whatever was pinned before.
    #[arg(long = "allow")]
    allow: Vec<IpAddr>,
    /// Admit anything that can reach the bound interface, clearing any pinned addresses.
    #[arg(long)]
    any: bool,
    /// How many seconds a login waits for a code before giving up.
    #[arg(long)]
    wait: Option<u64>,
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
    /// Show or change how a profile's launches are tuned.
    Env(ProfileEnvArgs),
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
    /// How the account is licensed: `standard`, `free-trial`, `steam`, `steam-free-trial`, or
    /// `steam:<app-id>` for an app id none of those name.
    #[arg(long, default_value = "standard")]
    licence: String,
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

/// The arguments of a flow that authenticates. Deliberately only the profile: the password and the
/// one-time code are read from the terminal or stdin, never taken as an argument.
#[derive(Args)]
struct PlayArgs {
    /// Profile id or unique name.
    #[arg(long)]
    profile: String,
}

/// Stop this process being written to disk if it dies.
///
/// The sealed secret file derives its key once and holds it for the run, so a dump taken while the
/// store is open carries the key, and the key plus the file beside it is every password in the store
/// with no passphrase and no derivation work. A dump attached to a bug report or caught in a backup
/// travels the same way a stolen file does.
///
/// Both calls are needed and neither is redundant. `PR_SET_DUMPABLE` is what actually stops it: when
/// `core_pattern` is a pipe the kernel hands the handler an unlimited size, so `RLIMIT_CORE` alone
/// would not. The limit covers a plain-file `core_pattern`, and unlike the dumpable flag it survives
/// an `execve`, so it reaches the game and the runner this process starts too.
///
/// What it costs: crash diagnostics. A segfault anywhere in the launcher, or in what it spawns,
/// leaves an exit status and nothing to open. What it does not cover: swap and hibernation, which
/// write the same pages by a route no process-level flag reaches.
#[cfg(target_os = "linux")]
fn keep_this_process_off_disk() {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

    if let Err(err) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        eprintln!("warning: this process can still be dumped to disk: {err}");
    }
    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if let Err(err) = setrlimit(Resource::Core, none) {
        eprintln!("warning: core dumps of this process are still allowed: {err}");
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    keep_this_process_off_disk();
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, CliError> {
    // Reading what the machine is, and withdrawing a registration, are answerable without the store.
    // They have to be: the environment a game session hands a program is minimal, and these are the
    // two commands worth running when a launch from that session has gone wrong.
    #[cfg(unix)]
    if let Commands::Steam { action } = &cli.command
        && !matches!(action, SteamAction::Register(_))
    {
        return steam_without_store(action);
    }

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
        Commands::Otp { action } => {
            otp(&core, action)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Secrets { action } => {
            secrets(&core, action)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Settings { action } => {
            settings(&core, action)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Prefix { action } => prefix(&core, action).await,
        #[cfg(unix)]
        Commands::Steam { action } => steam_register(&core, action),
    }
}

/// What a sweep of an account's secrets left in the store, when it left something. `None` is a clean
/// sweep, which each caller words for itself.
///
/// The two lines say different things on purpose. One reports a sweep that reached nothing, where
/// there may or may not be a secret somewhere the launcher could not see; the other reports a store
/// that answered and deleted nothing, where there certainly is one and only the platform's own
/// keyring tool can remove it. Printing the first line for the second case tells a user their
/// password is probably gone when it is definitely not.
fn secrets_left_behind(sweep: SecretSweep) -> Option<&'static str> {
    match sweep {
        SecretSweep::Swept => None,
        SecretSweep::Unanswered => {
            Some("no secret store answered, so anything it holds for that account is still there")
        }
        SecretSweep::LeftBehind => Some(concat!(
            "the credential store holds more than one item matching that account, so it deleted ",
            "none of them and the secret is still in it; remove it with the system keyring tool",
        )),
        // The set is `#[non_exhaustive]`, and a condition this build cannot name must not be
        // rendered as the clean sweep it is not.
        _ => Some("the sweep did not finish, so the account's secrets may still be stored"),
    }
}

/// The secrets the launcher keeps, and where they come from.
///
/// There is no verb that prints one. A saved secret is read inside the login flow and nowhere else,
/// so no amount of driving this binary gets a password, or the secret a one-time password is derived
/// from, back out of the store.
fn secrets(core: &Core, action: SecretsCommand) -> Result<(), CliError> {
    match action {
        SecretsCommand::Status => {
            let report = core.secrets_report();
            println!("backend  {:?}", report.backend);
            println!("state    {:?}", report.state);
            if core.settings()?.secret_backend == SecretBackend::EncryptedFile {
                let store = sealed_store(core);
                println!("file     {}", store.path().display());
                println!("at path  {:?}", store.inspect());
            }
            match &report.sandbox {
                Some(sandbox) => println!("sandbox  {sandbox:?}"),
                None => println!("sandbox  none"),
            }
            println!("usable   {}", report.is_usable());
            Ok(())
        }
        SecretsCommand::Save(args) => {
            let account = resolve_profile(core, &args.profile)?.account;
            core.store_secret(account, SecretKind::Password, read_password()?)?;
            println!("saved the password for account {account}");
            Ok(())
        }
        SecretsCommand::Totp(args) => {
            let account = resolve_profile(core, &args.profile)?.account;
            let offered = read_line_erased("otpauth link or secret: ")?;
            let text = std::str::from_utf8(offered.expose())
                .map_err(|_| "what was typed is not valid text")?;
            let deviations = core.import_totp_secret(account, text)?;
            println!("saved the one-time-password secret for account {account}");
            println!("account {account} will generate its own codes from now on");
            // Stored exactly as it was given, so the answer is a warning rather than a refusal: the
            // secret may well be right for somewhere else, and rewriting it to what the login server
            // takes would produce wrong codes with nothing said.
            for deviation in &deviations {
                println!("warning: {}", render_deviation(deviation));
            }
            Ok(())
        }
        SecretsCommand::Forget(args) => {
            let account = resolve_profile(core, &args.profile)?.account;
            match secrets_left_behind(core.forget_secrets(account)?) {
                None => println!("forgot every secret stored for account {account}"),
                Some(left) => println!("{left}"),
            }
            Ok(())
        }
        SecretsCommand::NeverStore(args) => {
            let id = resolve_profile(core, &args.profile)?.account;
            // Sweep before recording the choice. A user who asks the launcher to stop keeping a
            // password means the one it already has, and a run that saved the flag and then failed
            // to sweep would report success over a password still in the store.
            if args.on
                && let Some(left) = secrets_left_behind(core.forget_secrets(id)?)
            {
                println!("{left}");
            }
            // Read after the sweep. A sweep rewrites the record itself (an account deriving its own
            // codes goes back to being asked for one), so a copy taken beforehand would put that
            // back when this saves.
            let mut account = core.account(id)?;
            account.never_store = args.on;
            core.save_account(&account)?;
            if args.on {
                println!("account {id} will be asked for its password every time");
            } else {
                println!("account {id} will keep its password again");
            }
            Ok(())
        }
        SecretsCommand::Backend(args) => {
            secrets_backend(core, args.to)?;
            Ok(())
        }
        SecretsCommand::Passphrase => {
            let store = sealed_store(core);
            if !matches!(store.inspect(), FileState::Sealed { .. }) {
                println!(
                    "there is no sealed secret file at {}",
                    store.path().display()
                );
                return Ok(());
            }
            let current = read_passphrase("Current secret file passphrase: ")?;
            let new = read_new_passphrase()?;
            store.change_passphrase(&current, &new)?;
            println!("re-sealed the secret file under the new passphrase");
            Ok(())
        }
        SecretsCommand::DestroyFile => {
            let store = sealed_store(core);
            if core.settings()?.secret_backend == SecretBackend::EncryptedFile {
                println!(
                    "the launcher is still set to use the secret file; run `secrets backend --to platform` \
                     or `--to nothing` first"
                );
                return Ok(());
            }
            println!(
                "this deletes {} and every password and one-time-password secret in it. \
                 Nothing recovers them.",
                store.path().display()
            );
            if !confirmed("destroy")? {
                println!("left alone");
                return Ok(());
            }
            if store.remove(Consent::granted())? {
                println!("deleted the secret file");
            } else {
                println!("there was no secret file to delete");
            }
            Ok(())
        }
        SecretsCommand::Import(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            let account = core.account(profile.account)?;
            let name = args.name.unwrap_or_else(|| account.sqex_id.to_lowercase());
            let key = ForeignKey::from_stored_name(name);
            let source: Box<dyn ImportSource> = match args.file {
                Some(path) => Box::new(ForeignSecretsFile::at(path)),
                None => Box::new(ForeignCredentialStore::new()),
            };
            match core.import_password(account.id, source.as_ref(), &key)? {
                ImportOutcome::Imported => {
                    println!("imported the password for {}", key.name());
                }
                ImportOutcome::Nothing => {
                    println!("no saved password found for {}", key.name());
                }
                // Not "nothing found": nothing was looked at. Saying otherwise would tell a user
                // their other launcher has no password saved, and send them off to retype one they
                // may already have. The other source is named because it is the one that works here.
                ImportOutcome::Unsupported => {
                    println!(
                        "cannot read the credential store on this platform, so nothing was checked \
                         for {}; pass --file with the other launcher's exported password file to \
                         import from that instead",
                        key.name()
                    );
                }
                // `ImportOutcome` is `#[non_exhaustive]`, and every arm but the first stored
                // nothing, so a condition added later is reported as one.
                _ => println!("nothing was imported for {}", key.name()),
            }
            Ok(())
        }
    }
}

/// A handle over the sealed secret file, whichever backend is currently selected.
///
/// Its own handle rather than the one the core is holding, because these verbs act on the file
/// itself: creating it, re-sealing it, deleting it. None of that is reachable through the storage
/// seam, which is what stops anything else in the launcher doing it by accident.
fn sealed_store(core: &Core) -> EncryptedFile {
    EncryptedFile::open(core.secrets_path(), std::sync::Arc::new(TerminalPassphrase))
}

/// Switch where secrets are kept from the next run onwards.
///
/// Switching to the sealed file is the one direction that needs anything of the user, because it is
/// the only one that creates something: a typed confirmation and a new passphrase, in that order.
/// Nothing is moved in either direction, and the reason is said out loud rather than left to be
/// discovered: this shell cannot read a password out of the store it is leaving, by design.
fn secrets_backend(core: &Core, choice: BackendChoice) -> Result<(), CliError> {
    let mut settings = core.settings()?;
    let chosen = SecretBackend::from(choice);

    if chosen == SecretBackend::EncryptedFile {
        let store = sealed_store(core);
        match store.inspect() {
            FileState::Sealed { work } => {
                println!(
                    "using the secret file already at {} ({} KiB over {} passes)",
                    store.path().display(),
                    work.memory_kib(),
                    work.passes()
                );
            }
            FileState::Absent => {
                println!("a secret file is weaker than a platform credential store, not stronger:");
                println!("  it protects a copy of the file taken off this machine, no more");
                println!("  anything running as you can read the file and watch you type");
                println!("  a forgotten passphrase means the saved passwords are gone");
                println!("  the passphrase is asked for once per run of the launcher");
                if !confirmed("encrypt")? {
                    println!("left alone");
                    return Ok(());
                }
                let passphrase = read_new_passphrase()?;
                store.create(Consent::granted(), &passphrase, KdfCost::CURRENT)?;
                println!("created {}", store.path().display());
            }
            FileState::Unreadable => {
                return Err(
                    format!("something at {} cannot be read", store.path().display()).into(),
                );
            }
            // Anything else at the path, including a condition a later build reports, is refused
            // rather than created over: the one thing that must never happen here is overwriting a
            // store whose passphrase this run does not have.
            _ => {
                return Err(format!(
                    "something at {} is not a secret file this build can open",
                    store.path().display()
                )
                .into());
            }
        }
    }

    settings.secret_backend = chosen;
    core.save_settings(&settings)?;
    match chosen {
        SecretBackend::Platform => println!("secrets will go to the platform credential store"),
        SecretBackend::EncryptedFile => println!("secrets will go to the sealed file"),
        SecretBackend::Nothing => {
            println!("no secret will be kept, and a password is asked every time")
        }
        _ => println!("secret backend changed"),
    }
    println!("takes effect on the next run; nothing already saved was moved or deleted");
    Ok(())
}

/// The launcher's own preferences, read and written whole.
fn settings(core: &Core, action: SettingsCommand) -> Result<(), CliError> {
    match action {
        SettingsCommand::Show => {
            let s = core.settings()?;
            println!("language            {}", s.language);
            println!("secret_backend      {:?}", s.secret_backend);
            println!("close_after_launch  {}", s.close_after_launch);
            println!("keep_patches        {}", s.keep_patches);
            println!("backups_kept        {}", s.backups_kept);
            println!("backup_before_patch {}", s.backup_before_patch);
            // Where a user looks for machine-wide state, and where the listener sits is exactly that.
            // Nothing here says whether it is in use: that is per account, and `otp status` says it.
            print_listener_settings(&s.otp_listener);
            Ok(())
        }
        SettingsCommand::Set(args) => {
            let mut s = core.settings()?;
            if let Some(v) = args.keep_patches {
                s.keep_patches = v;
            }
            if let Some(v) = args.backup_before_patch {
                s.backup_before_patch = v;
            }
            if let Some(v) = args.backups_kept {
                s.backups_kept = v;
            }
            if let Some(v) = args.close_after_launch {
                s.close_after_launch = v;
            }
            core.save_settings(&s)?;
            println!("saved");
            Ok(())
        }
    }
}

/// Show or change how a profile's launches are tuned. With no knob named it prints what is set;
/// anything left unset resolves against the host and the runner at launch time rather than here.
fn profile_env(core: &Core, args: ProfileEnvArgs) -> Result<(), CliError> {
    let mut profile = resolve_profile(core, &args.profile)?;
    let changing =
        args.sync.is_some() || args.hud.is_some() || args.gpu.is_some() || args.gamemode.is_some();

    if let Some(spec) = &args.sync {
        profile.launch.sync = parse_sync(spec)?;
    }
    if let Some(spec) = &args.hud {
        profile.launch.hud = parse_hud(spec)?;
    }
    if let Some(spec) = &args.gpu {
        profile.launch.gpu = parse_gpu(spec)?;
    }
    if let Some(v) = args.gamemode {
        profile.launch.gamemode = v;
    }
    if changing {
        core.save_profile(&profile)?;
    }

    println!("sync      {}", render_sync(profile.launch.sync));
    println!("hud       {}", render_hud(&profile.launch.hud));
    println!("gpu       {}", render_gpu(&profile.launch.gpu));
    println!("gamemode  {}", profile.launch.gamemode);
    Ok(())
}

fn parse_sync(spec: &str) -> Result<SyncChoice, CliError> {
    Ok(match spec {
        "auto" => SyncChoice::Auto,
        "ntsync" => SyncChoice::Ntsync,
        "fsync" => SyncChoice::Fsync,
        "esync" => SyncChoice::Esync,
        "none" => SyncChoice::None,
        other => return Err(format!("unknown sync {other:?}").into()),
    })
}

fn render_sync(sync: SyncChoice) -> &'static str {
    match sync {
        SyncChoice::Auto => "auto",
        SyncChoice::Ntsync => "ntsync",
        SyncChoice::Fsync => "fsync",
        SyncChoice::Esync => "esync",
        SyncChoice::None => "none",
    }
}

fn parse_hud(spec: &str) -> Result<Hud, CliError> {
    Ok(match spec {
        "none" => Hud::None,
        "mangohud" => Hud::Mango,
        other => match other.strip_prefix("dxvk:") {
            Some(inner) if !inner.is_empty() => Hud::Dxvk(inner.to_owned()),
            _ => return Err(format!("unknown hud {other:?}").into()),
        },
    })
}

fn render_hud(hud: &Hud) -> String {
    match hud {
        Hud::None => "none".to_owned(),
        Hud::Mango => "mangohud".to_owned(),
        Hud::Dxvk(spec) => format!("dxvk:{spec}"),
    }
}

fn parse_gpu(spec: &str) -> Result<GpuSelect, CliError> {
    Ok(match spec {
        "default" => GpuSelect::Default,
        "nvidia" => GpuSelect::NvidiaPrime,
        "mesa" => GpuSelect::MesaPrime,
        other => match other.strip_prefix("vulkan:") {
            Some(inner) if !inner.is_empty() => GpuSelect::VulkanDevice(inner.to_owned()),
            _ => return Err(format!("unknown gpu {other:?}").into()),
        },
    })
}

fn render_gpu(gpu: &GpuSelect) -> String {
    match gpu {
        GpuSelect::Default => "default".to_owned(),
        GpuSelect::NvidiaPrime => "nvidia".to_owned(),
        GpuSelect::MesaPrime => "mesa".to_owned(),
        GpuSelect::VulkanDevice(sel) => format!("vulkan:{sel}"),
    }
}

/// Working on a profile's prefix. The destructive one confirms first: it discards everything
/// installed into the prefix, including the settings the game keeps there.
async fn prefix(core: &Core, action: PrefixCommand) -> Result<ExitCode, CliError> {
    let (target, act) = match &action {
        PrefixCommand::Create(args) => (&args.profile, PrefixAction::Create),
        PrefixCommand::Health(args) => (&args.profile, PrefixAction::Check),
        PrefixCommand::Fix(args) => (&args.profile, PrefixAction::Fix),
        PrefixCommand::Recreate(args) => (&args.profile, PrefixAction::Recreate),
    };
    let profile = resolve_profile(core, target)?.id;

    if let PrefixCommand::Recreate(args) = &action
        && !args.yes
    {
        println!("this deletes the prefix and everything installed into it, including the game's");
        println!("own settings. `backup create` captures those first.");
        let expected = resolve_profile(core, target)?.name;
        let answer = prompt_line("type the profile name to confirm: ")?;
        // An empty answer never confirms, whatever the profile is called. Without this a profile
        // created with an empty name would be destroyed by a closed stdin, which is what a script or
        // a cron job hands this.
        if answer.trim().is_empty() || answer.trim() != expected {
            println!("not recreating");
            return Ok(ExitCode::SUCCESS);
        }
    }

    Ok(drive(
        core,
        Command::Prefix {
            profile,
            action: act,
        },
    )
    .await)
}

/// One line per problem found, or a line saying there were none.
///
/// The setup a prefix is missing counts as a problem alongside the structural ones, and a catalog
/// that could not be read is its own line rather than an absence: "nothing wrong" has to mean the
/// check looked at both halves and found nothing.
fn render_health(report: &PrefixReport) -> String {
    if report.nothing_wrong() {
        return "prefix: nothing wrong".to_owned();
    }
    let missing = report.missing_setup.as_deref().unwrap_or_default();
    let mut lines: Vec<String> = report
        .health
        .issues
        .iter()
        .map(render_health_issue)
        .collect();
    lines.extend(
        missing
            .iter()
            .map(|name| format!("missing setup {name} (fix applies it)")),
    );
    if report.missing_setup.is_none() {
        lines.push("the component catalog could not be read, so what setup this prefix is missing is unknown".to_owned());
    }
    let mut out = format!("prefix: {} problem(s)", lines.len());
    for line in lines {
        out.push_str("\n  ");
        out.push_str(&line);
    }
    out
}

/// One line per parameter of an imported secret the login server will not accept a code from. The
/// core decides what counts and names both halves of every comparison; this only writes the
/// sentence, so what counts as accepted is never spelled out twice.
fn render_deviation(deviation: &Deviation) -> String {
    match deviation {
        Deviation::Algorithm { offered, accepted } => format!(
            "this secret is hashed with {}, and the login server only takes {}",
            offered.label(),
            accepted.label()
        ),
        Deviation::Digits { offered, accepted } => format!(
            "this secret makes {offered}-digit codes, and the login server only takes {accepted}"
        ),
        Deviation::Period { offered, accepted } => format!(
            "this secret's codes change every {offered} seconds, and the login server expects {accepted}"
        ),
        // `Deviation` is `#[non_exhaustive]`: a parameter named later is still a parameter that will
        // not be accepted, and saying so is better than printing nothing at all.
        _ => "this secret has a setting the login server does not take".to_owned(),
    }
}

fn render_health_issue(issue: &HealthIssue) -> String {
    match issue {
        HealthIssue::MissingSkeleton { path } => {
            format!("missing prefix file {} (fix rebuilds it)", path.display())
        }
        HealthIssue::DriveMapping {
            letter,
            expected,
            found,
        } => match found {
            Some(found) => format!(
                "drive {letter}: points at {} instead of {} (fix rewrites it)",
                found.display(),
                expected.display()
            ),
            None => format!(
                "drive {letter}: is missing, should be {} (fix rewrites it)",
                expected.display()
            ),
        },
        HealthIssue::RunnerMismatch { recorded, expected } => format!(
            "built with {} {} but the profile now selects {} {}: only `prefix recreate` resolves this",
            recorded.name, recorded.version, expected.name, expected.version
        ),
        HealthIssue::MissingDxvkDll { dll, .. } => {
            format!("{dll} is recorded as installed but is not there (fix reinstalls it)")
        }
        _ => "an unrecognized problem".to_owned(),
    }
}

/// The Steam commands that answer without opening the store: what this machine is, and withdrawing a
/// registration.
#[cfg(unix)]
fn steam_without_store(action: &SteamAction) -> Result<ExitCode, CliError> {
    let installs = apogee_core::steam_installs();
    match action {
        SteamAction::Status => {
            let identity = apogee_core::HostIdentity::detect();
            println!(
                "machine: {}{}{}",
                describe_machine(identity.deck),
                if identity.steamos { ", SteamOS" } else { "" },
                if identity.game_mode {
                    ", in the Steam session"
                } else {
                    ""
                },
            );
            if installs.is_empty() {
                println!("steam: no installation found");
                return Ok(ExitCode::SUCCESS);
            }
            for install in &installs {
                let state = match apogee_core::installed_compat_tool(&install.path) {
                    Some(dir) => format!("registered at {}", dir.display()),
                    None if install.confined => {
                        "not registered, and cannot be: this client is confined".to_owned()
                    }
                    None => "not registered".to_owned(),
                };
                println!("steam: {} -> {state}", install.path.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        SteamAction::Unregister => {
            let install = first_steam_install(&installs)?;
            if apogee_core::remove_compat_tool(&install.path)? {
                println!("unregistered from {}", install.path.display());
            } else {
                println!("nothing registered at {}", install.path.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        // Naming the profile to register needs the store, so it is dispatched with the rest.
        SteamAction::Register(_) => Ok(ExitCode::SUCCESS),
    }
}

/// The machine, in the words a user would use for it rather than the name of a variant.
///
/// The model a future handheld reports is a model this build has no name for, and saying so beats
/// printing an identifier out of the library or claiming it is one of the two that existed here.
#[cfg(unix)]
fn describe_machine(deck: Option<apogee_core::DeckModel>) -> &'static str {
    match deck {
        None => "not a Steam Deck",
        Some(apogee_core::DeckModel::Lcd) => "Steam Deck (LCD)",
        Some(apogee_core::DeckModel::Oled) => "Steam Deck (OLED)",
        Some(_) => "Steam Deck (unrecognized model)",
    }
}

/// Offering a profile in Steam's list, so it can be started from an interface with no desktop behind
/// it.
///
/// The registration runs `launch`, which starts from a session already established: on a handheld
/// there is nowhere to type a password, so signing in stays a thing done once from a desktop and the
/// Steam entry only starts what is already logged in.
#[cfg(unix)]
fn steam_register(core: &Core, action: SteamAction) -> Result<ExitCode, CliError> {
    let SteamAction::Register(args) = action else {
        // The other two were answered before the store was opened.
        return steam_without_store(&action);
    };
    let profile = resolve_profile(core, &args.profile)?;
    let installs = apogee_core::steam_installs();
    let install = first_steam_install(&installs)?;
    if install.confined {
        return Err(format!(
            "the steam at {} runs confined, so it would not find this launcher where the \
             registration points; install steam without a sandbox to register a profile with it",
            install.path.display()
        )
        .into());
    }
    // The path this process was started from, so the registration keeps working after the shell that
    // ran it is gone. Moving the binary means registering again.
    let binary = std::env::current_exe()?;
    let tool = apogee_core::CompatTool::new(
        binary,
        vec![
            "launch".to_owned(),
            "--profile".to_owned(),
            profile.id.to_string(),
        ],
    )
    .display_name(format!("Apogee ({})", profile.name));
    let written = tool.install(&install.path)?;
    println!("registered {} at {}", profile.name, written.dir.display());
    println!("runs: {}", written.command);
    println!("restart steam for it to appear in the compatibility tool list");
    Ok(ExitCode::SUCCESS)
}

/// The Steam installation to act on: the first one found, since the search is ordered by how
/// conventional a location is and a second one is the same client packaged differently.
#[cfg(unix)]
fn first_steam_install(
    installs: &[apogee_core::SteamInstall],
) -> Result<&apogee_core::SteamInstall, CliError> {
    installs
        .first()
        .ok_or_else(|| "no steam installation found; run steam once first".into())
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

/// Where an account's one-time code comes from, and where the listener that can receive one sits.
fn otp(core: &Core, action: OtpAction) -> Result<(), CliError> {
    match action {
        OtpAction::Status(args) => otp_status(core, &args.profile),
        OtpAction::Listen(args) => otp_listen(core, &args.profile),
        OtpAction::Ask(args) => {
            let profile = resolve_profile(core, &args.profile)?;
            core.ask_for_pushed_codes_no_longer(profile.account)?;
            println!("{} will be asked for a code again", profile.name);
            Ok(())
        }
        OtpAction::Listener(args) => otp_listener(core, args),
    }
}

/// Print where this account's code comes from and how the listener is configured.
fn otp_status(core: &Core, target: &str) -> Result<(), CliError> {
    let profile = resolve_profile(core, target)?;
    let account = core.account(profile.account)?;
    let where_from = match (account.use_otp, account.otp_delivery) {
        (false, _) => "not used by this account",
        (true, OtpDelivery::Generate) => "generated here from a stored secret",
        (true, OtpDelivery::Listen) => "pushed to this machine by a companion app",
        (true, _) => "typed in",
    };
    println!("one-time code: {where_from}");
    print_listener_settings(&core.settings()?.otp_listener);
    Ok(())
}

/// Print the machine's listener settings, in the shape `settings show` uses.
fn print_listener_settings(listener: &ListenerSettings) {
    println!("  listener bind: {}", listener.bind);
    println!("  listener port: {}", listener.port);
    println!("  listener wait: {} seconds", listener.wait_seconds);
    match &listener.sources {
        ListenerSources::Only { addresses } if !addresses.is_empty() => {
            let pinned: Vec<String> = addresses.iter().map(ToString::to_string).collect();
            println!("  listener admits: {}", pinned.join(", "));
        }
        // An empty pin admits nobody, which is the one configuration that refuses to bind rather than
        // opening a port no one can reach. Only a hand-edited file produces it, and saying so is
        // better than printing an empty list that reads like "everything".
        ListenerSources::Only { .. } => {
            println!("  listener admits: nothing, so no port will be opened");
        }
        _ => println!("  listener admits: anything that can reach the bound interface"),
    }
}

/// Point an account at the listener, after saying plainly what that opens.
///
/// The one-time acknowledgment. It is a typed word rather than a yes/no because the thing being
/// agreed to is visible to other people on the network and cannot be taken back by closing a dialog.
fn otp_listen(core: &Core, target: &str) -> Result<(), CliError> {
    let profile = resolve_profile(core, target)?;
    let account = core.account(profile.account)?;
    let listener = core.settings()?.otp_listener;

    if account.otp_delivery == OtpDelivery::Listen {
        println!("{} already takes its code from the listener", profile.name);
        print_listener_settings(&listener);
        return Ok(());
    }

    // The user's own configuration, before the question rather than only after it: the accuracy of
    // this screen is the entire point of the gate, and half of what follows depends on whether a pin
    // is already set.
    println!("this is what is being turned on:");
    print_listener_settings(&listener);
    println!(
        "while a login is waiting, this machine opens port {} and takes a code from whoever sends \
         one first:",
        listener.port
    );
    if listener.bind.is_unspecified() {
        println!("  it listens on every interface, which can include a VPN, a container bridge,");
        println!("  and the internet itself if this machine has a public address");
    } else {
        println!("  it listens on {}", listener.bind);
    }
    let pinned = matches!(
        &listener.sources,
        ListenerSources::Only { addresses } if !addresses.is_empty()
    );
    if pinned {
        println!("  only the addresses listed above can submit a code; every other source is");
        println!("  closed on before it is read");
    } else {
        println!("  any device that can route a packet here can submit a code");
        println!("  so can a web page you visit, from the browser on this machine");
    }
    println!("  a wrong code submitted first fails the login, and you start over");
    println!("  the code travels in plain text, which is what the phone apps speak");
    if !pinned {
        println!("pin your phone with `apogee-cli otp listener --allow <address>` to narrow that,");
        println!("which also bounds what the listener has to keep track of");
    }
    if !confirmed("listen")? {
        println!("left alone");
        return Ok(());
    }
    core.use_pushed_codes(profile.account, ListenerConsent::granted())?;
    println!("{} will take its code from the listener", profile.name);
    Ok(())
}

/// Change where the listener sits and who may reach it. Only the settings named are touched.
///
/// Cannot turn anything on. Pointing an account at the listener is a separate verb, because that is
/// the one that opens a port and so the one that has to ask.
fn otp_listener(core: &Core, args: ListenerArgs) -> Result<(), CliError> {
    if args.any && !args.allow.is_empty() {
        return Err("--any and --allow say opposite things; pick one".into());
    }
    let mut listener = core.settings()?.otp_listener;
    if let Some(bind) = args.bind {
        listener.bind = bind;
    }
    if let Some(port) = args.port {
        listener.port = port;
    }
    if let Some(wait) = args.wait {
        listener.wait_seconds = wait;
    }
    if args.any {
        listener.sources = ListenerSources::Any;
    } else if !args.allow.is_empty() {
        // Refused here as well as in the library, because this is the one place a sentence can be
        // attached to the refusal. A link-local address means nothing without the interface it is on,
        // the comparison downstream cannot carry that, and so a pin on one would be satisfied by the
        // same address arriving over some other interface.
        if let Some(bad) = args.allow.iter().find(|addr| is_link_local(**addr)) {
            return Err(format!(
                "{bad} is a link-local address, which does not name a device on its own: the same \
                 address on another interface would match it. Pin the address your phone gets from \
                 the router instead."
            )
            .into());
        }
        listener.sources = ListenerSources::Only {
            addresses: args.allow,
        };
    }
    core.set_listener_settings(listener.clone())?;
    print_listener_settings(&listener);
    // Accepted and then said out loud, rather than refused. Each is a real thing to want (a test, or
    // a deliberately closed window) and neither can hurt anything, but both produce a listener that
    // no phone will ever reach, and silently writing one is how that becomes a mystery.
    if listener.port == 0 {
        println!("warning: port 0 takes whichever port is free at the time, so the companion app");
        println!("         will not find it. Set a fixed port for a listener you mean to use.");
    }
    if listener.wait_seconds == 0 {
        println!("warning: a wait of 0 seconds opens the port and gives up before anything can");
        println!("         connect.");
    }
    Ok(())
}

/// Whether this is an IPv6 link-local unicast address.
fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
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
    let otp = read_otp(&account)?;
    Ok((profile.id, password, otp))
}

/// Build the core against the real network transport and XDG-resolved storage. Under the `fixtures`
/// feature a scripted transport may be substituted (the launch backend stays real).
fn build_core() -> Result<Core, CliError> {
    let config = CoreConfig::try_from_env()?;
    let passphrase = std::sync::Arc::new(TerminalPassphrase);
    #[cfg(feature = "fixtures")]
    if let Some(transport) = fixtures::transport() {
        return Ok(Core::with_transport_and_passphrase(
            config, transport, passphrase,
        )?);
    }
    Ok(Core::with_passphrase(config, passphrase)?)
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
                ..Account::new(args.user, parse_licence(&args.licence)?)
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
            let removal = core.remove_profile(profile.id)?;
            println!("removed profile {}", profile.id);
            if let Some(account) = removal.account_removed {
                println!("removed account {account}");
            }
            // `Some` exactly when an account went, so this says nothing about a profile whose
            // account another profile still signs in as.
            if let Some(sweep) = removal.secret_sweep {
                match secrets_left_behind(sweep) {
                    None => println!("deleted every secret stored for it"),
                    Some(left) => println!("{left}"),
                }
            }
            Ok(())
        }
        ProfileAction::Env(args) => profile_env(core, args),
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

/// The sealed secret file's passphrase, read from the terminal at the moment the store needs it.
///
/// The library never prompts, so this is the half only a front end can supply. It reads on every
/// call and keeps nothing: the store caches the key it derived, and a second copy of the passphrase
/// living out here would be one the store's own erasure could not reach.
struct TerminalPassphrase;

impl Passphrase for TerminalPassphrase {
    fn unlock(&self) -> Result<Secret, SecretsError> {
        #[cfg(feature = "fixtures")]
        if let Some(secret) = fixtures::passphrase() {
            return Ok(secret);
        }
        // A prompt that cannot be answered is an unlock that was not completed, which is what the
        // condition below means. Rendering the terminal error would put the failure in a variant a
        // caller reads as a broken store rather than as a missing answer.
        rpassword::prompt_password("Secret file passphrase: ")
            .map(|text| Secret::new(text.into_bytes()))
            .map_err(|_| SecretsError::Locked)
    }

    fn can_prompt(&self) -> bool {
        #[cfg(feature = "fixtures")]
        if fixtures::passphrase().is_some() {
            return true;
        }
        // A run with no terminal cannot be asked, and a store that claimed otherwise would report
        // itself usable and then fail every write.
        std::io::IsTerminal::is_terminal(&io::stdin())
    }
}

/// Read a passphrase once, for a call that is about to check it against something.
fn read_passphrase(prompt: &str) -> Result<Secret, CliError> {
    #[cfg(feature = "fixtures")]
    if let Some(secret) = fixtures::passphrase() {
        return Ok(secret);
    }
    Ok(into_secret(typed(prompt)?))
}

/// Read one line with the echo off, into a buffer that is erased when it drops.
///
/// `rpassword` erases its own working buffers but hands back an ordinary `String`, and every caller
/// here holds that answer for at least as long as it takes to check it against something.
///
/// The failure worth naming is the only one that happens in practice: there is no terminal to ask on,
/// because the launcher was run from a script or a service. The library's own error for that is an
/// operating-system code with no bearing on what to do about it.
fn typed(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|err| -> CliError {
            if std::io::IsTerminal::is_terminal(&io::stdin()) {
                Box::new(err)
            } else {
                "there is no terminal to type a passphrase on".into()
            }
        })
}

/// Move an erased text buffer into a [`Secret`], leaving nothing behind.
///
/// `String::into_bytes` hands over the heap allocation rather than copying it, so the bytes are only
/// ever in one place; taking the `String` out of its wrapper leaves an empty one to drop.
fn into_secret(mut text: Zeroizing<String>) -> Secret {
    Secret::from_string(std::mem::take(&mut *text))
}

/// Read a passphrase that is about to seal a file, so it is asked for twice and compared.
///
/// Nothing can check a new passphrase later: a typo here is a store that opens for nobody, including
/// the person who made it.
fn read_new_passphrase() -> Result<Secret, CliError> {
    #[cfg(feature = "fixtures")]
    if let Some(secret) = fixtures::passphrase() {
        return Ok(secret);
    }
    let first = typed("New secret file passphrase: ")?;
    if first.is_empty() {
        return Err("a secret file needs a passphrase".into());
    }
    let again = typed("Again: ")?;
    if first != again {
        return Err("the two passphrases were not the same".into());
    }
    Ok(into_secret(first))
}

/// Require the user to type `word` before something destructive or irreversible happens.
///
/// A typed word rather than a yes-or-no, because both of the things this guards are answered wrongly
/// by a reflex: one destroys stored passwords and the other creates a store whose passphrase, once
/// forgotten, takes them with it.
fn confirmed(word: &str) -> Result<bool, CliError> {
    Ok(prompt_line(&format!("Type `{word}` to continue: "))? == word)
}

/// The one-time-password source: whatever the account is set to, which is a code read off stdin, a
/// secret the core derives one from, or nothing at all.
///
/// There is no flag for a typed code, and there must not be one. `/proc/<pid>/cmdline` is
/// world-readable with no `hidepid`, so an argument holding a live code is readable by every local
/// user for as long as the run lasts; stdin is readable by nobody. A script that has to supply one
/// pipes it in, the same line-per-answer shape as every other prompt here.
///
/// The account's own setting decides, not a look in the secret store: those are write-only, so
/// whether one holds a secret is not a question this side may ask.
fn read_otp(account: &Account) -> Result<OtpSource, CliError> {
    match (account.use_otp, account.otp_delivery) {
        (false, _) => Ok(OtpSource::Manual(Secret::new(Vec::new()))),
        (true, OtpDelivery::Generate) => Ok(OtpSource::Totp),
        // Above the catch-all, and it has to stay there: without an explicit arm an account set to
        // receive pushed codes would be prompted for a typed one, which is the opposite of the
        // feature. This is the only login shape where no code passes through this process at all.
        (true, OtpDelivery::Listen) => Ok(OtpSource::Listener),
        (true, _) => Ok(OtpSource::Manual(read_line_erased("One-time password: ")?)),
    }
}

/// Read one line of stdin into a buffer that is erased when it drops, trimming in place.
///
/// Trimming in place rather than with `trim().to_owned()`: the second `String` that would make is
/// the copy nothing erases, which is the whole point of reading into an erased buffer at all.
fn read_line_erased(prompt: &str) -> Result<Secret, CliError> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = Zeroizing::new(String::new());
    io::stdin().read_line(&mut line)?;
    let end = line.trim_end().len();
    line.truncate(end);
    let start = line.len() - line.trim_start().len();
    line.drain(..start);
    Ok(into_secret(line))
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

fn parse_licence(licence: &str) -> Result<AccountKind, CliError> {
    match licence {
        "standard" => Ok(AccountKind::Standard),
        "free-trial" => Ok(AccountKind::FreeTrial),
        "steam" => Ok(AccountKind::Steam {
            app_id: STEAM_APP_ID,
        }),
        "steam-free-trial" => Ok(AccountKind::Steam {
            app_id: STEAM_FREE_TRIAL_APP_ID,
        }),
        other => match other.strip_prefix("steam:").map(str::parse::<u32>) {
            Some(Ok(app_id)) => Ok(AccountKind::Steam { app_id }),
            _ => Err(format!(
                "unknown licence {other:?} (expected standard, free-trial, steam, \
                 steam-free-trial, or steam:<app-id>)"
            )
            .into()),
        },
    }
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
        Event::State(state) => render_state(state),
        Event::Progress(progress) => format!("progress: {}/{}", progress.completed, progress.total),
        Event::Patch(patch) => render_patch(patch),
        Event::Addon(addon) => render_addon(addon),
        Event::Setup(setup) => render_setup(setup),
        Event::Frontier(_) => "frontier data received".to_owned(),
        Event::Prefix(report) => render_health(report),
        Event::Notice(notice) => render_notice(notice),
        Event::Error(err) => format!("error: {err}"),
        _ => "unrecognized event".to_owned(),
    }
}

/// Render where the flow stands.
///
/// Two arms and a fallback, rather than a table: every other disposition is a word a user reads and
/// acts on without help, and the debug rendering has been that word all along. These two are not. One
/// is an instruction (a port is open, go and tap your phone) and the other names an address the user
/// has to recognize, and neither reads as either in debug soup.
fn render_state(state: &FlowState) -> String {
    match state {
        FlowState::WaitingForPushedCode { port, seconds } => format!(
            "state: waiting up to {seconds} seconds for a one-time code pushed to this machine on \
             port {port}"
        ),
        // The address, never the digits. Worth printing because the first well-formed code wins
        // whoever sent it: an address that is not the user's phone is the only sign of that.
        FlowState::PushedCodeReceived { from } => {
            format!("state: a one-time code arrived from {from}")
        }
        other => format!("state: {other:?}"),
    }
}

/// Render an advisory the run raised in passing.
fn render_notice(notice: &Notice) -> String {
    match notice {
        // Said from the host's point of view, which is the one the user can do something about: the
        // server being ahead is this machine being slow. `unsigned_abs` because the offset is a
        // measurement and an absurd one saturates at `i64::MIN`, which has no negation.
        Notice::ClockSkew { seconds } => format!(
            "warning: this machine's clock is {} seconds {} the login server's; the code sent was \
             generated against the server's time, but everything else here has the wrong time",
            seconds.unsigned_abs(),
            if *seconds > 0 { "behind" } else { "ahead of" },
        ),
        // Deliberate rather than left to the catch-all: a flood is the one thing the listener can see
        // that the user cannot, and "an unrecognized advisory" would throw it away. The login was not
        // affected, which is why this is a warning and not a failure.
        Notice::OtpListenerFlood { from, refused } => format!(
            "warning: {from} spent the one-time-code listener's attempt budget while this login \
             waited; {refused} connections were turned away and the login was unaffected"
        ),
        _ => "warning: an unrecognized advisory".to_owned(),
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
            format!("addon: {} finished, {outcome}", program.display())
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
        SetupEvent::Reapplying { verb, because } => {
            format!("setup: {verb} was applied before but {because}")
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reader that takes a typed answer hands back a buffer that erases itself.
    ///
    /// A tripwire, not a proof: it stops the return type quietly going back to `String`, which is the
    /// shape this got wrong once already, but nothing here can see a caller that copies the answer
    /// out again. What measures that is an allocator shim over the built binary, which needs
    /// `unsafe` and so cannot live in this workspace.
    const _: fn() = || {
        fn erased_text(_: fn(&str) -> Result<Zeroizing<String>, CliError>) {}
        fn erased_secret(_: fn(&str) -> Result<Secret, CliError>) {}
        erased_text(typed);
        erased_secret(read_line_erased);
    };

    fn report(missing: Option<&[&str]>) -> PrefixReport {
        PrefixReport {
            health: apogee_core::PrefixHealth::default(),
            missing_setup: missing
                .map(|names| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()),
        }
    }

    /// "Nothing wrong" is the one sentence that has to be earned. A prefix the runtime finds intact is
    /// half the answer: setup it is missing is a problem, a catalog nobody could read is a question,
    /// and neither of those is a clean bill.
    #[test]
    fn nothing_wrong_is_said_only_when_both_halves_answered_and_both_were_clean() {
        assert_eq!(render_health(&report(Some(&[]))), "prefix: nothing wrong");

        let missing = render_health(&report(Some(&["no-desktop-integration"])));
        assert!(missing.starts_with("prefix: 1 problem(s)"), "{missing}");
        assert!(missing.contains("no-desktop-integration"), "{missing}");

        let unknown = render_health(&report(None));
        assert!(unknown.starts_with("prefix: 1 problem(s)"), "{unknown}");
        assert!(unknown.contains("could not be read"), "{unknown}");
    }
}
