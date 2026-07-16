//! Headless command-line surface over the launcher core.
//!
//! Today it is a thin driver: it constructs a core and exercises the model and the store through the
//! core's synchronous profile methods. It writes only to a scratch directory, so a run is harmless.

use apogee_core::{Account, AccountKind, Core, CoreConfig, Profile};

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

    Ok(())
}
