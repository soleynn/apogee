//! Headless command-line surface over the launcher core.
//!
//! Today it is a thin driver: it constructs a core and exercises the model and the store through the
//! core's synchronous profile methods. It writes only to a scratch directory, so a run is harmless.

use apogee_core::{
    Account, AccountKind, Command, Core, CoreConfig, Event, FlowState, FrontierQuery, Profile,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::temp_dir().join("apogee-cli-scratch");
    let core = Core::new(CoreConfig::with_base(base))?;

    let account = Account::new("player@example.invalid", AccountKind::Standard);
    let profile = Profile::new("Test", account.id, "/games/ffxiv".into());
    let id = profile.id;

    core.save_profile(&profile)?;
    println!("stored {} profile(s)", core.profiles()?.len());

    core.delete_profile(id)?;

    // Deleting the same profile again has nothing to remove: the typed error surfaces here.
    if let Err(err) = core.delete_profile(id) {
        println!("{err}");
    }

    // The async command surface a shell drives: it issues a Command and renders the Events the core
    // yields. The login-to-play flow arms land in a later change, so this exercises the shape of the
    // surface (which type-checks the whole Command/Event API from the app) without driving a stub.
    let command = Command::Frontier(FrontierQuery::Gate);
    println!("prepared {command:?}");
    println!("{}", render(&Event::State(FlowState::Running)));

    Ok(())
}

/// Render one core event as a line of terminal text. Presentation lives in the shell: the core emits
/// typed events and the shell turns each into words.
fn render(event: &Event) -> String {
    match event {
        Event::State(state) => format!("state: {state:?}"),
        Event::Progress(progress) => format!("progress: {}/{}", progress.completed, progress.total),
        Event::Frontier(_) => "frontier data received".to_string(),
        Event::Error(err) => format!("error: {err}"),
        _ => "unrecognized event".to_string(),
    }
}
