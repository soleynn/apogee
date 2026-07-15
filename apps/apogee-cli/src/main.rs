//! Headless command-line surface over the launcher core.
//!
//! Today it is a thin driver: it constructs a core, issues profile commands, and consumes the event
//! stream, exercising the model, the store, and the command/event surface end to end. It writes
//! only to a scratch directory, so a run is harmless.

use apogee_core::{Account, AccountKind, Command, Core, CoreConfig, Event, Profile};
use tokio_stream::{Stream, StreamExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::temp_dir().join("apogee-cli-scratch");
    let core = Core::new(CoreConfig::with_base(base))?;

    let account = Account::new("player@example.invalid", AccountKind::Standard);
    let profile = Profile::new("Test", account.id, "/games/ffxiv".into());
    let id = profile.id;

    drain(core.execute(Command::SaveProfile(Box::new(profile)))).await;
    println!("stored {} profile(s)", core.profiles()?.len());

    drain(core.execute(Command::DeleteProfile(id))).await;

    // Deleting the same profile again has nothing to remove: the stream carries a typed error.
    let mut events = core.execute(Command::DeleteProfile(id));
    while let Some(event) = events.next().await {
        if let Event::Error(err) = event {
            println!("{err}");
        }
    }

    Ok(())
}

/// Consume a command's event stream to completion, discarding its events.
async fn drain(mut stream: impl Stream<Item = Event> + Unpin) {
    while stream.next().await.is_some() {}
}
