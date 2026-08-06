//! Reading another launcher's stored password off a real Secret Service.
//!
//! Needs a session bus with a provider on it, which the dedicated CI job supplies. The unit tests
//! freeze the key strings; only a real provider proves that an item filed under them is found, that
//! reading it leaves it there, and that the startup item the other launcher writes is not mistaken
//! for a password.
//!
//! What no case here proves is that the strings are the right ones. Every one of them seeds the bus
//! from the copies below, so they all pass for any value: what is under test is the search, not the
//! contract. The copies are deliberate, since seeding through the crate's own constants would make
//! even that vacuous, and each is annotated with where the real value comes from.
//!
//! Run single-threaded: the cases share one collection.

use std::collections::HashMap;

use apogee_secrets::{ForeignCredentialStore, ForeignKey, Import, ImportSource};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;

/// What the other launcher's native build files a password under: a fixed marker in `service`, the
/// lowercased account name in `username`.
///
/// `SERVICE`, goatcorp/XIVLauncher.Core@0b4ec78,
/// `src/XIVLauncher.Core/Accounts/Secrets/Providers/KeychainSecretProvider.cs:10`.
const FOREIGN_SERVICE: &str = "SEID";

/// The permanent item it writes at every startup, only so the keyring unlocks. Not a password, and
/// not an account.
///
/// `DUMMY_SVC` and `DUMMY_NAME`, same file, `:27-28`.
const DUMMY_SERVICE: &str = "XIVLauncher Safe Storage Control";
const DUMMY_NAME: &str = "XIVLauncher";

// The helpers below propagate rather than unwrap: the lint that permits a panic in a test covers
// `#[test]` bodies only, and a free function here is not one.

fn service() -> Result<SecretService<'static>, secret_service::Error> {
    SecretService::connect(EncryptionType::Dh)
}

/// File `secret` the way the other launcher would, under `svc`/`name`.
fn seed(
    service: &SecretService<'_>,
    svc: &str,
    name: &str,
    secret: &[u8],
) -> Result<(), secret_service::Error> {
    let collection = service.get_default_collection()?;
    let attributes = HashMap::from([("service", svc), ("username", name)]);
    collection.create_item(
        "imported-from-another-launcher",
        attributes,
        secret,
        true,
        "text/plain",
    )?;
    Ok(())
}

fn seeded_still_there(
    service: &SecretService<'_>,
    svc: &str,
    name: &str,
) -> Result<bool, secret_service::Error> {
    let attributes = HashMap::from([("service", svc), ("username", name)]);
    Ok(!service.search_items(attributes)?.unlocked.is_empty())
}

/// A fresh name per case, so a leftover item from an earlier run cannot make a case pass.
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// The whole point of the import: a password the other launcher saved is found under the keys this
/// crate builds from the account name.
#[test]
fn a_password_another_launcher_saved_is_found() {
    let service = service().expect("connect to the bus");
    let name = unique_name("imported");
    seed(&service, FOREIGN_SERVICE, &name, b"their-password").expect("seed the item");

    let Import::Password(found) = ForeignCredentialStore::new()
        .password(&ForeignKey::from_stored_name(&name))
        .expect("read the other launcher's store")
    else {
        panic!("the seeded password was not found");
    };

    assert_eq!(found.expose(), b"their-password");
}

/// The entry belongs to a program this one does not own. A user who tries this launcher and goes
/// back has to find their old one still able to log in.
#[test]
fn reading_leaves_the_other_launcher_s_copy_alone() {
    let service = service().expect("connect to the bus");
    let name = unique_name("untouched");
    seed(&service, FOREIGN_SERVICE, &name, b"their-password").expect("seed the item");

    let read = ForeignCredentialStore::new()
        .password(&ForeignKey::from_stored_name(&name))
        .expect("read the other launcher's store");
    assert!(
        matches!(read, Import::Password(_)),
        "the seeded password was not found"
    );

    assert!(
        seeded_still_there(&service, FOREIGN_SERVICE, &name).expect("search the bus"),
        "the import removed the other launcher's entry"
    );
}

/// That launcher writes a fixed item at every startup, purely to make the keyring unlock. It is
/// filed under a different service, so pairing the service with the account name keeps it out
/// without this crate needing to know it exists. If the search ever loosened to the name alone, an
/// account called `XIVLauncher` would import a French proverb as its password.
#[test]
fn the_startup_item_is_not_mistaken_for_a_password() {
    let service = service().expect("connect to the bus");
    seed(
        &service,
        DUMMY_SERVICE,
        DUMMY_NAME,
        b"Honi soit qui mal y pense",
    )
    .expect("seed the startup item");

    let found = ForeignCredentialStore::new()
        .password(&ForeignKey::from_stored_name(DUMMY_NAME))
        .expect("read the other launcher's store");

    assert!(
        matches!(found, Import::Nothing),
        "the startup item was read as a password"
    );
}

/// A user who never saved a password there gets an answer, not a failure. Reported as an error it
/// would look like the import was broken.
#[test]
fn an_account_with_nothing_saved_reads_as_nothing() {
    let found = ForeignCredentialStore::new()
        .password(&ForeignKey::from_stored_name(unique_name("absent")))
        .expect("read the other launcher's store");

    // `Nothing` and not `Unsupported`: this platform has a reader, and it looked.
    assert!(matches!(found, Import::Nothing));
}
