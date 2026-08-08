//! Reading a password another launcher saved, so a user switching over types it once.
//!
//! Everything here reads. Nothing writes to, or deletes from, the other program's storage: those
//! entries belong to software this launcher does not own, and a user who tries it and goes back
//! must find their setup intact. The import writes to *our* keys through the ordinary
//! [`SecretStore`](crate::SecretStore), and the source is left exactly as it was found.
//!
//! The key strings below are the whole interoperability contract, and getting one wrong fails the
//! same way as there being nothing to import: silently, with an empty answer. So they are built by
//! pure functions that need no store to test, and frozen by unit tests that run on every platform,
//! including the ones where the store they name does not exist.
//!
//! Freezing a string catches an edit to it and says nothing about whether it was ever right, and no
//! test here can: a case that seeds the store itself passes for any value it uses. So each string
//! carries a citation to the line of the other launcher's source that produces it. That source is
//! read as a specification and never copied; the launcher half of it is GPL-3.0.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::{Secret, SecretsError};

/// The prefix the other launcher writes its credentials under today.
///
/// `CREDS_PREFIX_NEW`, goatcorp/FFXIVQuickLauncher@40ed6e9,
/// `src/XIVLauncher/Accounts/XivAccount.cs:11`. The separator and the lowercased account name are
/// the interpolation at `:49`.
const TARGET_PREFIX: &str = "XIVLAUNCHER";

/// The prefix it used before, which its own reader still probes first and migrates away from. An
/// install that has not been opened since the change still has its password only under this one.
///
/// `CREDS_PREFIX_OLD`, same file, `:10`, read first at `:25`.
const LEGACY_TARGET_PREFIX: &str = "FINAL FANTASY XIV";

// The three Secret Service strings below, traced to the source that produces each. The other
// launcher's native build calls `Keyring.GetPassword(PACKAGE, SERVICE, accountName)`
// (goatcorp/XIVLauncher.Core@0b4ec78,
// `src/XIVLauncher.Core/Accounts/Secrets/Providers/KeychainSecretProvider.cs:51`). That reaches
// libsecret through goaaats/KeySharp (`KeySharp/Keyring.cs:47`, which fixes the argument order) and
// its vendored native half, hrantzsch/keychain@c856836. `src/keychain_linux.cpp` is what turns the
// three arguments into a bus item: `makeSchema` (`:41-49`) makes the package the schema name, and
// `getPassword` (`:108-121`) files the other two under the attribute names declared at `:33-34`,
// `service` and `username`.

/// The value its native build files passwords under on the Secret Service. Not the account name:
/// it is a fixed marker, the same for every account.
///
/// `SERVICE`, `KeychainSecretProvider.cs:10`, passed to every verb at `:51`, `:65` and `:71`.
const SECRET_SERVICE_SERVICE: &str = "SEID";

/// The schema its native build declares on the Secret Service.
///
/// `PACKAGE`, `KeychainSecretProvider.cs:9`, which reaches the bus as the schema name rather than as
/// anything the launcher passes per call.
///
/// Deliberately *not* part of the search below. Whether it reaches the bus as an attribute depends
/// on the binding it goes through rather than on the launcher, and a query that named it would
/// return nothing on an install that stores the item without it. The two attributes that are
/// searched are enough to identify one account's password.
pub const FOREIGN_SCHEMA: &str = "dev.goats.xivlauncher";

/// The keys another launcher stores one account's password under.
///
/// Built from the account name exactly as that launcher recorded it. Pure: no I/O, so every string
/// it produces is testable on any host, which matters because most of them name a store that only
/// one platform has and that platform has no job in this repository's checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKey {
    name: String,
}

impl ForeignKey {
    /// Take the account name as the other launcher recorded it.
    ///
    /// The name is used verbatim. That launcher lowercases it once, when the account is created,
    /// under whatever locale the machine had; lowercasing it again here would be wrong on any locale
    /// where a letter does not fold the way ASCII does, and would build a key that matches nothing.
    /// The name to pass is the one read out of its account list, not one the user typed.
    #[must_use]
    pub fn from_stored_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// The account name this key addresses.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The Credential Manager target it writes today.
    #[must_use]
    pub fn credential_target(&self) -> String {
        format!("{TARGET_PREFIX}-{}", self.name)
    }

    /// The Credential Manager target it wrote before, and still reads first.
    #[must_use]
    pub fn legacy_credential_target(&self) -> String {
        format!("{LEGACY_TARGET_PREFIX}-{}", self.name)
    }

    /// The Secret Service attributes its native build files this account's password under.
    ///
    /// The two names are `keychain_linux.cpp:33-34`, not anything the launcher chooses.
    ///
    /// Both are needed. The service half is a fixed marker rather than anything about the account,
    /// so on its own it matches every account that launcher has saved, plus the permanent dummy item
    /// it writes at startup to make the keyring unlock (`KeychainSecretProvider.cs:27-32`). Pairing
    /// it with the name is what selects one account, and what keeps that dummy out of the result
    /// without needing to know it exists.
    #[must_use]
    pub fn secret_service_attributes(&self) -> [(&'static str, &str); 2] {
        [
            ("service", SECRET_SERVICE_SERVICE),
            ("username", self.name.as_str()),
        ]
    }
}

/// What a source had for one account.
///
/// Three answers rather than two. "There is no reader for this source on this target" is not the
/// same fact as "this source was read and holds nothing", and a caller that cannot tell them apart
/// tells the user their other launcher saved no password when nothing ever looked. The two need
/// different things done about them, so they are different values.
///
/// Derives nothing, for the reason [`Secret`] derives nothing: a `Debug` on the wrapper prints the
/// password inside it the moment anything above formats the value it arrived in.
#[non_exhaustive]
pub enum Import {
    /// A password this source holds for the account.
    Password(Secret),
    /// The source was read and holds nothing under that key.
    Nothing,
    /// This source cannot be read on this target, so nothing was looked at. Not a failure: the
    /// account is fine, the store is fine, and another source may still hold the password.
    Unsupported,
}

/// A place another launcher put a password.
///
/// Read-only by design, not by omission: see the module header.
pub trait ImportSource {
    /// What this source holds for `key`.
    ///
    /// # Errors
    /// As [`SecretStore::get`](crate::SecretStore::get): the source is a store like any other and
    /// can be locked, absent, or refuse. A source with no reader on this target is
    /// [`Import::Unsupported`] rather than an error, because nothing failed.
    fn password(&self, key: &ForeignKey) -> Result<Import, SecretsError>;
}

/// The platform credential store, read at another launcher's keys instead of at ours.
#[derive(Debug, Default)]
pub struct ForeignCredentialStore;

impl ForeignCredentialStore {
    /// Construct the reader for the platform credential store.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
impl ImportSource for ForeignCredentialStore {
    fn password(&self, key: &ForeignKey) -> Result<Import, SecretsError> {
        use secret_service::EncryptionType;
        use secret_service::blocking::SecretService;

        let classify = |err: &secret_service::Error, step: &'static str| {
            crate::keyring_store::classify_secret_service(err, step)
        };

        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|err| classify(&err, "reach the other launcher's store"))?;
        let attributes: HashMap<&str, &str> = key.secret_service_attributes().into_iter().collect();
        let found = service
            .search_items(attributes)
            .map_err(|err| classify(&err, "search the other launcher's store"))?;

        match found.unlocked.as_slice() {
            [] => {
                // Locked items are reported as locked rather than as an absence. Reading one raises
                // the unlock prompt and then blocks on it, so the caller is told to unlock and come
                // back instead of being told there is nothing to import.
                if found.locked.is_empty() {
                    Ok(Import::Nothing)
                } else {
                    Err(SecretsError::Locked)
                }
            }
            [item] => {
                let bytes = item
                    .get_secret()
                    .map_err(|err| classify(&err, "read the other launcher's stored password"))?;
                Ok(non_empty(bytes))
            }
            // Two items under one account name is not a password this can pick between, and picking
            // the first would import whichever the store happened to list first.
            _ => Err(SecretsError::Ambiguous),
        }
    }
}

#[cfg(target_os = "windows")]
impl ImportSource for ForeignCredentialStore {
    /// Probes the legacy target first and the current one second, the same order and for the same
    /// reason the other launcher's own reader does: an install that has not been opened since it
    /// changed prefixes still has the password only under the old one, and the new one may exist as
    /// an empty shell. Neither an empty target nor an unreadable one ends the search: see
    /// [`first_readable`].
    ///
    /// The target is passed through verbatim as the credential's lookup key, which is what this
    /// store keys on. That is the one place in this crate that addresses a credential by target
    /// rather than by service and user: the ban on doing so exists because the argument means three
    /// different things across the three platform stores, and choosing it for *our* keys would take
    /// a path only one platform could ever run. Here the target is not ours to choose. It is fixed
    /// by the program being read, on the one platform that program stores it, and using anything
    /// else finds nothing.
    fn password(&self, key: &ForeignKey) -> Result<Import, SecretsError> {
        let name = key.name();
        first_readable(
            [key.legacy_credential_target(), key.credential_target()]
                .into_iter()
                .map(|target| read_credential(&target, name)),
        )
    }
}

/// The first password any of `reads` held, in the order they are given.
///
/// Split out from the store call so the choice is testable on a host that has no credential store,
/// which is every host this repository's checks run on. `reads` is walked lazily and abandoned on
/// the first hit, so a password found under one target is the only one this process ever holds.
///
/// A target that fails is not a target that ends the search. Each one is a name in a namespace any
/// program on the machine can write, and the two are written by different versions of the other
/// launcher, so a blob under one that is not a password says nothing about the other. The failure is
/// kept rather than dropped and reported only if no target answered, which keeps the diagnosis for
/// the case where there is nothing else to report. The last one wins: the current target is the one
/// that launcher writes today, so its condition is the live one.
#[cfg(any(target_os = "windows", test))]
fn first_readable(
    reads: impl IntoIterator<Item = Result<Import, SecretsError>>,
) -> Result<Import, SecretsError> {
    let mut failure = None;
    let mut looked = false;
    for read in reads {
        match read {
            Ok(Import::Password(secret)) => return Ok(Import::Password(secret)),
            Ok(Import::Nothing) => looked = true,
            // This platform's reader never answers it, and it is the only caller. Kept separate
            // anyway: folding it into `Nothing` would undo the distinction the type exists to draw,
            // which is between a source that held no password and one that was never able to look.
            Ok(Import::Unsupported) => {}
            Err(err) => failure = Some(err),
        }
    }
    match (failure, looked) {
        (Some(err), _) => Err(err),
        (None, true) => Ok(Import::Nothing),
        (None, false) => Ok(Import::Unsupported),
    }
}

/// Fold a failure to read one target into the taxonomy.
///
/// `NoStorageAccess` is named here the way the store and the probe name it, because it means the
/// same thing on the one platform that reaches this code: `ERROR_NO_SUCH_LOGON_SESSION`, which a
/// service, a scheduled run or a network logon produces, and which says there is no credential store
/// session at all rather than that this one credential could not be read. Reported as a backend
/// failure it would send a caller looking for a fault in the other launcher's storage.
#[cfg(any(target_os = "windows", test))]
fn classify_credential_read(err: &keyring::Error) -> SecretsError {
    match err {
        keyring::Error::NoStorageAccess(_) => SecretsError::NoBackend,
        _ => SecretsError::Backend {
            step: "read the other launcher's credential",
        },
    }
}

/// Read one credential by target, decoding the blob this platform's stores hold text in.
///
/// `get_secret` rather than `get_password` for the reason the rest of the crate uses it: the string
/// reader is the one call whose error carries the raw bytes back out. The decode is done here
/// instead, so a blob that is not text becomes a condition rather than an error holding a password.
#[cfg(target_os = "windows")]
fn read_credential(target: &str, name: &str) -> Result<Import, SecretsError> {
    use keyring::Entry;

    // Service and user are recorded on the credential but are not what this store looks it up by,
    // so they only have to be present. The target above is the whole key.
    let entry =
        Entry::new_with_target(target, crate::keyring_store::SERVICE, name).map_err(|_| {
            SecretsError::Backend {
                step: "address the other launcher's credential",
            }
        })?;
    match entry.get_secret() {
        // The blob is the password in another encoding, and the library hands it over as the only
        // surviving copy: it erases its own buffer before freeing it. Erased here on both the
        // success and the failure path, rather than dropped intact.
        Ok(mut blob) => {
            let decoded = decode_utf16le(&blob);
            blob.zeroize();
            Ok(non_empty(decoded?))
        }
        Err(keyring::Error::NoEntry) => Ok(Import::Nothing),
        Err(err) => Err(classify_credential_read(&err)),
    }
}

/// On Apple targets there is no reader: where that launcher files a password in the Keychain has
/// not been established here, and guessing at a key would report "nothing saved" for an account that
/// has one. The impl exists so the type is usable on every target this crate builds for, and the
/// plaintext-file source still works. Establishing the Keychain layout is what would replace it.
///
/// [`Import::Unsupported`] and not [`Import::Nothing`]: the two read identically to a caller that
/// only has an absence to report, and it would say the other launcher saved no password for an
/// account whose password nothing ever went looking for.
#[cfg(any(target_os = "macos", target_os = "ios"))]
impl ImportSource for ForeignCredentialStore {
    fn password(&self, _key: &ForeignKey) -> Result<Import, SecretsError> {
        Ok(Import::Unsupported)
    }
}

/// Decode the little-endian UTF-16 a Windows credential blob holds text in.
///
/// The intermediate code units are erased rather than left on the heap: they are the password, in
/// another encoding, and nothing else in this function would clear them.
#[cfg(target_os = "windows")]
fn decode_utf16le(blob: &[u8]) -> Result<Vec<u8>, SecretsError> {
    if !blob.len().is_multiple_of(2) {
        return Err(SecretsError::Backend {
            step: "decode the other launcher's credential",
        });
    }
    let mut units: Vec<u16> = blob
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let decoded = String::from_utf16(&units);
    units.zeroize();
    let mut text = decoded.map_err(|_| SecretsError::Backend {
        step: "decode the other launcher's credential",
    })?;
    let bytes = text.as_bytes().to_vec();
    text.zeroize();
    Ok(bytes)
}

/// A plaintext file another launcher writes its passwords into when it is configured to.
///
/// It exists because that configuration is real and a user running it has no keyring to read
/// instead. Nothing about reading it endorses it: the file is plaintext on disk, and importing from
/// it moves the password into a store that at least encrypts it.
///
/// The file is opened for each lookup rather than held. It contains every account's password, and
/// keeping the parsed copy alive for the lifetime of the importer would leave all of them in memory
/// for longer than the one that was asked for.
#[derive(Debug, Clone)]
pub struct ForeignSecretsFile {
    path: PathBuf,
}

impl ForeignSecretsFile {
    /// Read passwords from the file at `path`. A file that is not there is not an error: the lookup
    /// answers [`Import::Nothing`], the same as a store that holds nothing.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this reads.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ImportSource for ForeignSecretsFile {
    fn password(&self, key: &ForeignKey) -> Result<Import, SecretsError> {
        let mut body = match std::fs::read(&self.path) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Import::Nothing),
            Err(err) => return Err(SecretsError::Io(err)),
        };
        // Held rather than returned from inside the decode, so the buffer is erased on the failure
        // path as well as the success one. It is every account's password.
        let found = exported_password(&body, key.name());
        body.zeroize();
        found
    }
}

/// Pick one account's password out of the table another launcher exported, given its bytes.
///
/// Split from the read so the decode is reachable from a buffer alone. It is the one parser in this
/// crate handed a file of cleartext rather than sealed bytes, and it is handed it from a path this
/// launcher does not own, so what it has to survive is whatever anything on the machine left there.
///
/// Bytes and not text. The encoding is part of what is being decoded rather than something the read
/// may assume: a file that is not UTF-8 is a table this cannot read, which is more use to report
/// than the I/O failure that decoding during the read produced, which says the read itself broke.
///
/// One entry that is not a password does not end the search, for the reason a target that will not
/// read does not end it in `first_readable` above. Every other line belongs to an account this was
/// not asked about, written by some version of that launcher under a name that says nothing about
/// the one that was asked for, so the values are taken as whatever JSON holds them as and only the
/// asked-for one has to be a string. A number, a list or an object is passed over the way an entry
/// that is not there is.
fn exported_password(body: &[u8], wanted: &str) -> Result<Import, SecretsError> {
    // The parse error is dropped rather than carried. It quotes the input it choked on, and the
    // input here is a file of passwords.
    let mut entries: HashMap<String, serde_json::Value> =
        serde_json::from_slice(body).map_err(|_| SecretsError::Backend {
            step: "read the exported password file",
        })?;
    let found = entries.remove(wanted);
    // Every other account's password was parsed out of the file too, and dropping the map would
    // leave all of them on the heap.
    //
    // Accepted gap: no test observes that the buffer was erased before it was freed. Seeing that
    // needs a dealloc-scanning `#[global_allocator]`, which takes `unsafe`, and this crate keeps
    // its one `unsafe` module for the Windows permission arm.
    for (_, value) in entries {
        if let serde_json::Value::String(mut password) = value {
            password.zeroize();
        }
    }
    let Some(serde_json::Value::String(mut password)) = found else {
        return Ok(Import::Nothing);
    };
    let bytes = password.as_bytes().to_vec();
    password.zeroize();
    Ok(non_empty(bytes))
}

/// Reach the exported-file decoder from the crate root, for the fuzz workspace and nothing else.
///
/// Answers a property rather than only declining to abort: a password this returns was decoded out
/// of the bytes it was handed, so one longer than them is the decoder amplifying what it read. A
/// refusal and an absence are clean answers and pass.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_exported_password(body: &[u8], wanted: &str) -> bool {
    match exported_password(body, wanted) {
        Ok(Import::Password(found)) => found.expose().len() <= body.len(),
        Ok(Import::Nothing | Import::Unsupported) | Err(_) => true,
    }
}

/// Treat a blank stored password as nothing stored.
///
/// The other launcher deletes the entry instead of writing a blank one, so a blank is never a
/// password a user chose. Importing it would replace a prompt the user can answer with a saved
/// value that fails every login.
fn non_empty(bytes: Vec<u8>) -> Import {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Import::Nothing;
    }
    Import::Password(Secret::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These strings are the interoperability contract, and the platform that holds most of them has
    /// no job here, so they are frozen against a fixed name rather than left to whatever the
    /// constants happen to say. A change to either prefix, its separator, or its spacing finds
    /// nothing and reports it as nothing to import.
    ///
    /// What this cannot do is establish that the literals below are the right ones. Nothing in a
    /// test can: the live case seeds the store with the same strings it then searches for, so it
    /// passes for any value. The citations on the constants are where that comes from.
    #[test]
    fn credential_targets_are_frozen() {
        let key = ForeignKey::from_stored_name("someaccount");
        assert_eq!(key.credential_target(), "XIVLAUNCHER-someaccount");
        assert_eq!(
            key.legacy_credential_target(),
            "FINAL FANTASY XIV-someaccount"
        );
        assert_eq!(
            key.secret_service_attributes(),
            [("service", "SEID"), ("username", "someaccount")]
        );
    }

    /// The name goes in exactly as it came out of the other launcher's account list. It was already
    /// lowercased there, under the machine's own locale; folding it again here would rewrite it on a
    /// locale where a letter does not fold to the ASCII letter, and build a key matching nothing.
    #[test]
    fn a_stored_name_is_never_folded_again() {
        for name in ["MiXeD", "\u{131}rssi", "\u{130}stanbul", "acc\u{e9}nt"] {
            let key = ForeignKey::from_stored_name(name);
            assert_eq!(key.name(), name);
            assert_eq!(key.credential_target(), format!("XIVLAUNCHER-{name}"));
            assert_eq!(key.secret_service_attributes()[1].1, name);
        }
    }

    /// The one answer this helper never gives is `Unsupported`: a source that got as far as reading
    /// bytes has a reader, whatever the bytes turned out to be.
    #[test]
    fn a_blank_stored_password_is_read_as_nothing_stored() {
        for blank in [Vec::new(), b"   ".to_vec(), b"\t\r\n".to_vec()] {
            assert!(matches!(non_empty(blank), Import::Nothing));
        }
        let Import::Password(found) = non_empty(b" pw ".to_vec()) else {
            panic!("a password with spaces in it is a password");
        };
        assert_eq!(found.expose(), b" pw ");
    }

    /// The target sweep, driven with the store's answers built directly. The store it reads has one
    /// platform and that platform has no job here, so the decision is exercised on every host and the
    /// call it wraps on one.
    mod credential_targets {
        use super::*;

        /// What a target that held something hands back, as the decoded text it becomes.
        fn saved(text: &str) -> Result<Import, SecretsError> {
            Ok(Import::Password(Secret::new(text.as_bytes().to_vec())))
        }

        fn nothing() -> Result<Import, SecretsError> {
            Ok(Import::Nothing)
        }

        /// A source that could not be read at all, which is a different answer from an empty one.
        fn unsupported() -> Result<Import, SecretsError> {
            Ok(Import::Unsupported)
        }

        /// What an undecodable blob under a target comes back as.
        fn undecodable() -> Result<Import, SecretsError> {
            Err(SecretsError::Backend {
                step: "decode the other launcher's credential",
            })
        }

        /// The legacy target is a name any program on the machine can claim, and something else
        /// having left junk under it is not a reason to never look at the target the other launcher
        /// writes today. A user whose password is under the current one gets it.
        #[test]
        fn a_target_that_does_not_read_does_not_end_the_search() {
            let Ok(Import::Password(found)) =
                first_readable([undecodable(), saved("their-password")])
            else {
                panic!("the second target is still read");
            };
            assert_eq!(found.expose(), b"their-password");
        }

        /// The targets hold two different accounts' worth of plaintext between them. Reading past a
        /// hit would pull a password this was not asked for into the process for no purpose.
        #[test]
        fn nothing_is_read_after_a_hit() {
            let mut probed = Vec::new();
            let Ok(Import::Password(found)) =
                first_readable(["legacy", "current"].into_iter().map(|target| {
                    probed.push(target);
                    saved(target)
                }))
            else {
                panic!("the password under the first target");
            };

            assert_eq!(found.expose(), b"legacy");
            assert_eq!(probed, ["legacy"]);
        }

        /// A user who never saved a password there has both targets empty, and that is an answer
        /// rather than a failure.
        #[test]
        fn nothing_under_either_target_is_nothing_to_import() {
            assert!(matches!(
                first_readable([nothing(), nothing()]),
                Ok(Import::Nothing)
            ));
        }

        /// A target that was looked at outranks one that could not be: "nothing saved" is a fact
        /// about the other launcher's store, and "could not look" is a fact about this build, so the
        /// first is the more useful answer whenever anything actually managed to read.
        #[test]
        fn a_source_that_could_not_look_does_not_outrank_one_that_did() {
            assert!(matches!(
                first_readable([unsupported(), nothing()]),
                Ok(Import::Nothing)
            ));
            assert!(matches!(
                first_readable([unsupported(), unsupported()]),
                Ok(Import::Unsupported)
            ));
        }

        /// Held back, not dropped. With no password to return there is nothing else to say, and
        /// answering "nothing saved" would hide a store that is failing. `expect_err` cannot be used
        /// to get at it: that needs `Debug` on the success type, and the type inside it has none.
        #[test]
        fn a_failure_is_reported_when_no_target_answered() {
            let Err(err) = first_readable([undecodable(), nothing()]) else {
                panic!("a failure with no password behind it is dropped");
            };
            assert!(matches!(err, SecretsError::Backend { .. }), "{err:?}");
        }

        /// The one condition that is not about this credential at all. It is what a service, a
        /// scheduled run or a network logon gets, and the store and the probe both name it, so the
        /// import naming it something else would be the only place that disagrees.
        #[test]
        fn no_credential_store_session_is_not_a_credential_that_failed() {
            let err = keyring::Error::NoStorageAccess(Box::new(std::io::Error::other(
                "ERROR_NO_SUCH_LOGON_SESSION",
            )));
            assert!(matches!(
                classify_credential_read(&err),
                SecretsError::NoBackend
            ));
        }

        #[test]
        fn any_other_store_failure_is_a_backend_failure() {
            let err = keyring::Error::PlatformFailure(Box::new(std::io::Error::other("broken")));
            assert!(matches!(
                classify_credential_read(&err),
                SecretsError::Backend { .. }
            ));
        }
    }

    mod secrets_file {
        use super::*;

        fn write(body: &str) -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("secrets.json");
            std::fs::write(&path, body).expect("write the file");
            (dir, path)
        }

        #[test]
        fn a_named_account_is_found_and_the_others_are_not_returned() {
            let (_dir, path) = write(r#"{"alice":"pw-alice","bob":"pw-bob"}"#);
            let source = ForeignSecretsFile::at(&path);
            let Import::Password(found) = source
                .password(&ForeignKey::from_stored_name("alice"))
                .expect("read")
            else {
                panic!("alice is in the file");
            };
            assert_eq!(found.expose(), b"pw-alice");
            assert!(matches!(
                source
                    .password(&ForeignKey::from_stored_name("carol"))
                    .expect("read"),
                Import::Nothing
            ));
        }

        /// A user who has never turned that mode on has no file, and that is the ordinary case
        /// rather than a failure: the importer moves on to the next source. `Nothing` and not
        /// `Unsupported`, because this source is readable everywhere and the file simply is not
        /// there, which is a fact about the machine rather than about the target.
        #[test]
        fn a_file_that_is_not_there_holds_nothing() {
            let dir = tempfile::tempdir().expect("temp dir");
            let source = ForeignSecretsFile::at(dir.path().join("absent.json"));
            assert!(matches!(
                source
                    .password(&ForeignKey::from_stored_name("alice"))
                    .expect("read"),
                Import::Nothing
            ));
        }

        /// The parse failure must not reach the caller carrying what it was parsing. `expect_err`
        /// cannot be used to get at it: that would need `Debug` on the success type, and the whole
        /// point of the type inside it is that it has none.
        #[test]
        fn a_malformed_file_fails_without_quoting_itself() {
            let (_dir, path) = write(r#"{"alice": "hunter2""#);
            let Err(err) =
                ForeignSecretsFile::at(&path).password(&ForeignKey::from_stored_name("alice"))
            else {
                panic!("a truncated file is not readable");
            };
            let rendered = format!("{err} {err:?}");
            assert!(!rendered.contains("hunter2"), "{rendered}");
        }

        /// The file holds every account that launcher knows about, and the entries for the others
        /// were written by whatever version of it happened to be installed when each was saved. One
        /// of them being something this cannot read is not a reason to tell a user their own
        /// password is not in a file that has it, which is the same call the target sweep makes.
        #[test]
        fn an_entry_this_cannot_read_does_not_hide_the_one_asked_for() {
            let (_dir, path) =
                write(r#"{"bob":{"saved":"pw-bob"},"alice":"pw-alice","carol":42,"dave":null}"#);
            let Import::Password(found) = ForeignSecretsFile::at(&path)
                .password(&ForeignKey::from_stored_name("alice"))
                .expect("read")
            else {
                panic!("alice is in the file and is a password");
            };
            assert_eq!(found.expose(), b"pw-alice");
        }

        /// The other half of that call: what is passed over for another account is passed over for
        /// this one too. An entry that is not a string is not a password, and reporting it as one
        /// would hand the login something that is not what the user saved.
        #[test]
        fn an_entry_that_is_not_a_string_is_nothing_stored() {
            let (_dir, path) = write(r#"{"alice":{"saved":"pw-alice"}}"#);
            assert!(matches!(
                ForeignSecretsFile::at(&path)
                    .password(&ForeignKey::from_stored_name("alice"))
                    .expect("read"),
                Import::Nothing
            ));
        }

        /// The file is bytes on a path this launcher does not own, so its encoding is part of what
        /// is being decoded. A file that is not text is a table that cannot be read, not a read that
        /// failed, and the two send a caller looking in different places. Well-formed apart from the
        /// encoding, so it is the encoding this pins and not the shape.
        #[test]
        fn a_file_that_is_not_text_is_a_table_that_cannot_be_read() {
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("secrets.json");
            let mut body = br#"{"alice":""#.to_vec();
            body.extend_from_slice(&[0xff, 0x22, 0x7d]);
            std::fs::write(&path, body).expect("write the file");
            let Err(err) =
                ForeignSecretsFile::at(&path).password(&ForeignKey::from_stored_name("alice"))
            else {
                panic!("bytes that are not text are not a table");
            };
            assert!(matches!(err, SecretsError::Backend { .. }), "{err:?}");
        }

        /// What the fuzz target asserts, pinned here so it runs on every push rather than only under
        /// the fuzzer: the decode never returns more password than it was given bytes. Escapes are
        /// the direction that could go wrong, since each one shrinks by a different amount.
        #[test]
        fn a_decoded_password_is_never_longer_than_the_bytes_it_came_from() {
            for body in [
                r#"{"alice":"pw"}"#,
                r#"{"alice":"\u0041\u0042"}"#,
                r#"{"alice":"😀"}"#,
            ] {
                let (_dir, path) = write(body);
                let Import::Password(found) = ForeignSecretsFile::at(&path)
                    .password(&ForeignKey::from_stored_name("alice"))
                    .expect("read")
                else {
                    panic!("alice is in the file");
                };
                assert!(found.expose().len() <= body.len(), "{body}");
            }
        }

        #[test]
        fn a_name_stored_with_other_characters_round_trips() {
            let (_dir, path) = write(r#"{"ırssi":"pw-é"}"#);
            let Import::Password(found) = ForeignSecretsFile::at(&path)
                .password(&ForeignKey::from_stored_name("\u{131}rssi"))
                .expect("read")
            else {
                panic!("the account is in the file");
            };
            assert_eq!(found.expose(), "pw-\u{e9}".as_bytes());
        }
    }

    #[cfg(target_os = "windows")]
    mod windows_blob {
        use super::*;

        /// The blob a Windows credential holds text in is little-endian UTF-16 with no terminator.
        /// Decoded as UTF-8 it would become mojibake, and the login it was imported for would fail
        /// with an error from Square Enix that says nothing about an import.
        #[test]
        fn text_is_decoded_from_little_endian_code_units() {
            let blob: Vec<u8> = "pw-\u{e9}\u{1f600}"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let decoded = decode_utf16le(&blob).expect("decode");
            assert_eq!(decoded, "pw-\u{e9}\u{1f600}".as_bytes());
        }

        #[test]
        fn a_blob_that_is_not_text_is_a_condition_rather_than_an_error_holding_it() {
            // An odd length cannot be code units at all, and an unpaired surrogate is not text.
            for blob in [vec![0x41], vec![0x00, 0xD8]] {
                let err = decode_utf16le(&blob).expect_err("not decodable");
                assert!(matches!(err, SecretsError::Backend { .. }));
            }
            // Annotated: serde_json is a dependency of this crate, and its `PartialEq<Value>` impls
            // leave a bare `Vec::new()` here with more than one candidate element type.
            assert_eq!(
                decode_utf16le(&[]).expect("an empty blob decodes"),
                Vec::<u8>::new()
            );
        }
    }

    /// The Apple target has no reader, and it has to say so rather than report an absence. This is
    /// the only reader in the crate whose whole body is that answer, so it is the one place a later
    /// change could quietly turn "nobody looked" back into "there was nothing". Compiled by the
    /// Apple cross-check job and run by nothing here.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn the_apple_credential_store_reports_that_it_cannot_look() {
        let found = ForeignCredentialStore::new()
            .password(&ForeignKey::from_stored_name("someaccount"))
            .expect("a source with no reader is not a failure");
        assert!(matches!(found, Import::Unsupported));
    }
}
