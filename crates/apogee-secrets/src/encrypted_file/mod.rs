//! The fallback store: every account secret in one file, sealed under a passphrase.

mod disk;
mod frame;
mod items;
mod kdf;
mod passphrase;
mod seal;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use uuid::Uuid;
use zeroize::Zeroizing;

use frame::{CHECK_AAD_LEN, HEADER_LEN, Header, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN, corrupt};
use items::Table;

pub use kdf::KdfCost;
pub use passphrase::{Passphrase, Unprompted};

use crate::{Backend, BackendReport, BackendState, Secret, SecretKind, SecretStore, SecretsError};

/// Proof that a front end asked the user for the encrypted fallback and got an answer.
///
/// Holds nothing, and is neither `Clone`, `Copy`, `Default`, nor deserializable, with a private
/// field, so it cannot be conjured by a struct literal or produced by parsing a config file. It is
/// consumed by the call it authorizes, so one grant authorizes one action.
///
/// It does not prove what the user was shown; nothing inside a library can. What it does is confine
/// the ability to say "the user asked for this" to the layer that can actually ask, and its single
/// constructor is greppable so that confinement is checkable. The guarantee that carries the weight
/// is structural and sits beside it: there is no path from a [`SecretStore`] trait object to
/// [`EncryptedFile::create`] or [`EncryptedFile::remove`], so nothing the launcher does on its own
/// can bring a store into being or destroy one.
#[derive(Debug)]
pub struct Consent(());

impl Consent {
    /// Grant consent for one action.
    #[must_use]
    pub fn granted() -> Self {
        Self(())
    }
}

/// What is at an [`EncryptedFile`]'s path, answered without a passphrase.
///
/// The file-shaped detail lives here rather than in [`BackendState`], which is the vocabulary every
/// backend routes on and is deliberately small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileState {
    /// Nothing is there. Only [`EncryptedFile::create`] changes that.
    Absent,
    /// A store this build can open with the right passphrase, and the work opening it will cost.
    Sealed {
        /// What the file was sealed under, which is what a later unlock will pay rather than
        /// whatever this build would choose today.
        work: KdfCost,
    },
    /// The path could not be examined at all: a permission on it or on a directory above it. Says
    /// nothing about what is there, because nothing was read.
    Unreadable,
    /// Something is there and it is not a store this build opens. Anything that is not a regular
    /// file, a symlink at the path among them, and any regular file with the wrong magic, a version
    /// or an algorithm this build does not know, a length that cannot be right, or a work factor
    /// outside the band this build accepts.
    Foreign,
}

/// The key this handle derived, and what it was derived from.
///
/// The salt and the cost travel with it so a file that has been re-sealed since, which draws a fresh
/// salt, is recognised as needing a fresh derivation rather than reported as a wrong passphrase.
struct CachedKey {
    salt: [u8; SALT_LEN],
    cost: KdfCost,
    key: Zeroizing<[u8; KEY_LEN]>,
}

/// The derived key, and a lock-free answer to whether there is one.
///
/// Two views of one fact, kept in step by the guard rather than by every caller remembering to. The
/// flag exists because a read of "is this handle open" must not queue: a write holds the mutex from
/// before the file is read until after it is re-sealed, and the passphrase prompt and the Argon2
/// derivation are both inside that window, so anything that reached for the same lock waited out a
/// modal dialog first.
struct KeyCache {
    slot: Mutex<Option<CachedKey>>,
    present: AtomicBool,
}

impl KeyCache {
    fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            present: AtomicBool::new(false),
        }
    }

    /// Take the cache, taking a poisoned lock's contents back rather than turning another test's
    /// panic into a second one. Panicking is denied in this workspace, and a poisoned cache is not a
    /// condition this store models: the worst it holds is a key that will be re-derived.
    fn lock(&self) -> KeyGuard<'_> {
        KeyGuard {
            slot: self.slot.lock().unwrap_or_else(PoisonError::into_inner),
            present: &self.present,
        }
    }

    /// Whether a key is held, without taking the lock.
    ///
    /// `Relaxed` because this is a report about a moment that has already passed by the time a
    /// caller reads it: the file can be deleted, and the key dropped, between the load and the next
    /// statement. What it must not do is block, and what it must not be is a second source of truth
    /// that drifts, which is what the guard below is for.
    fn present(&self) -> bool {
        self.present.load(Ordering::Relaxed)
    }
}

/// A held key cache, which publishes whether the slot is occupied as it is released.
///
/// The two can therefore disagree only while the lock is held, which is exactly the window in which
/// a reader taking the lock would have been blocked anyway.
struct KeyGuard<'a> {
    slot: MutexGuard<'a, Option<CachedKey>>,
    present: &'a AtomicBool,
}

impl Drop for KeyGuard<'_> {
    fn drop(&mut self) {
        self.present.store(self.slot.is_some(), Ordering::Relaxed);
    }
}

impl std::ops::Deref for KeyGuard<'_> {
    type Target = Option<CachedKey>;

    fn deref(&self) -> &Self::Target {
        &self.slot
    }
}

impl std::ops::DerefMut for KeyGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.slot
    }
}

/// What to do when the store is not there.
#[derive(Clone, Copy)]
enum Missing {
    /// A write has nothing to write into.
    Refuse,
    /// A delete against a store that does not exist has already achieved what it was asked to.
    Ignore,
}

/// Opt-in fallback backend: every account secret in one file, sealed under a passphrase.
///
/// XChaCha20-Poly1305 over the whole record table, keyed by an Argon2id derivation of a passphrase
/// the user types once per launcher session. One sealed blob rather than a file per secret, so a
/// directory listing says neither which accounts have secrets nor which kinds are stored, and so
/// emptying an account is a single atomic rewrite.
///
/// The handle keeps the derived key and nothing else. No decrypted value is held between calls, so at
/// most one call's worth of plaintext is alive at a time, and the passphrase is dropped inside the
/// call that used it.
///
/// **This is weaker than a platform credential store, not stronger.** It defends a copy of the file
/// taken off the machine, up to the strength of the passphrase, and it defends nothing at all against
/// code already running as this user, which can read the file, read this process's memory, and watch
/// the passphrase being typed. It exists for sessions that have no credential store to talk to.
///
/// Two limits are worth stating rather than leaving to be discovered. A whole-file rollback is not
/// detected: anyone who can write the file can put an older copy back and resurrect a deleted secret,
/// and catching that needs a monotonic anchor elsewhere on the machine that the same attacker could
/// not also roll back. And the file's path, mode, and modification time are outside the seal, so the
/// fact that a store exists and the fact that it was written are both visible.
pub struct EncryptedFile {
    path: PathBuf,
    passphrase: Arc<dyn Passphrase>,
    key: KeyCache,
}

impl EncryptedFile {
    /// The file name this backend expects under the launcher's own directory. On-disk contract.
    pub const FILE_NAME: &'static str = "secrets.apsf";

    /// A handle over `path`, which asks `passphrase` the first time a call needs to unlock.
    ///
    /// Does no I/O and derives nothing, so constructing one costs nothing and prompts nobody. It
    /// cannot bring a store into existence: a write against a path with no store at it is
    /// [`SecretsError::NoCollection`], never a new file under a passphrase nobody confirmed.
    #[must_use]
    pub fn open(path: impl Into<PathBuf>, passphrase: Arc<dyn Passphrase>) -> Self {
        Self {
            path: path.into(),
            passphrase,
            key: KeyCache::new(),
        }
    }

    /// Where the file is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create an empty store at this handle's path and leave the handle open on it.
    ///
    /// Refuses if anything is already at the path. The secrets in an existing file cannot be got back
    /// once it is overwritten, and the passphrase that opens it is not knowable from here, so this is
    /// never the call that replaces one. An empty passphrase is refused before the path is touched: a
    /// store that opens with nothing typed is not a store.
    ///
    /// # Errors
    /// [`SecretsError::Io`] carrying [`std::io::ErrorKind::AlreadyExists`] if something is at the
    /// path, [`SecretsError::Locked`] for an empty passphrase, [`SecretsError::Backend`] if the
    /// system random source or the derivation failed, and [`SecretsError::Io`] or
    /// [`SecretsError::Denied`] for the filesystem.
    pub fn create(
        &self,
        consent: Consent,
        passphrase: &Secret,
        cost: KdfCost,
    ) -> Result<(), SecretsError> {
        let Consent(()) = consent;
        if passphrase.is_empty() {
            return Err(SecretsError::Locked);
        }
        let mut cached = self.cache();
        disk::private_dir(&self.path)?;
        let _lock = disk::Lock::take(&self.path)?;
        disk::sweep_temps(&self.path);
        if std::fs::symlink_metadata(&self.path).is_ok() {
            return Err(SecretsError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "a secret store is already there",
            )));
        }

        let salt: [u8; SALT_LEN] = seal::draw()?;
        let key = kdf::derive(passphrase.expose(), &salt, cost)?;
        self.publish(&Table::new(), &salt, cost, &key)?;
        *cached = Some(CachedKey { salt, cost, key });
        Ok(())
    }

    /// Re-seal the store under `new`, with a fresh salt and this build's current work factor.
    ///
    /// `current` is required because the store has to be opened before it can be re-sealed, and
    /// because a change that did not prove the old passphrase would let anyone at an unlocked session
    /// lock the owner out of their own secrets. Drawing a fresh salt is what makes this a re-key
    /// rather than a re-wrap: any precomputation an attacker had started against the old salt is
    /// spent. It is also the only way an existing store's work factor is raised, because it is the
    /// only moment a passphrase is on hand to derive from again.
    ///
    /// # Errors
    /// [`SecretsError::WrongPassphrase`] if `current` does not open the store,
    /// [`SecretsError::Locked`] if either passphrase is empty, [`SecretsError::NoCollection`] if
    /// there is no store, [`SecretsError::Corrupt`] if it is damaged, and the filesystem's own.
    pub fn change_passphrase(&self, current: &Secret, new: &Secret) -> Result<(), SecretsError> {
        if current.is_empty() || new.is_empty() {
            return Err(SecretsError::Locked);
        }
        let mut cached = self.cache();
        disk::private_dir(&self.path)?;
        let _lock = disk::Lock::take(&self.path)?;
        disk::sweep_temps(&self.path);

        let Some(bytes) = disk::read(&self.path)? else {
            return Err(SecretsError::NoCollection);
        };
        disk::narrow_file(&self.path);
        let header = Header::parse(&bytes)?;
        let old = kdf::derive(current.expose(), &header.salt, header.cost)?;
        let table = unseal(&bytes, &header, &old)?;

        let salt: [u8; SALT_LEN] = seal::draw()?;
        let cost = KdfCost::CURRENT;
        let key = kdf::derive(new.expose(), &salt, cost)?;
        self.publish(&table, &salt, cost, &key)?;
        *cached = Some(CachedKey { salt, cost, key });
        Ok(())
    }

    /// What is at the path. Reads the file's own header and nothing else: never derives, never asks
    /// for a passphrase, and never follows a symlink at the store path.
    #[must_use]
    pub fn inspect(&self) -> FileState {
        match disk::read(&self.path) {
            Ok(None) => FileState::Absent,
            Ok(Some(bytes)) => match Header::parse(&bytes) {
                Ok(header) => FileState::Sealed { work: header.cost },
                Err(_) => FileState::Foreign,
            },
            Err(SecretsError::Corrupt { .. }) => FileState::Foreign,
            Err(_) => FileState::Unreadable,
        }
    }

    /// Whether this handle has already derived its key, so the next call will not ask for anything.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.key.present()
    }

    /// Forget the derived key and erase it. The next call that needs one asks again.
    pub fn seal(&self) {
        *self.cache() = None;
    }

    /// Delete the store and everything in it, and seal this handle. Answers whether there was one.
    ///
    /// The bytes are unlinked rather than overwritten first, deliberately: on a copy-on-write or
    /// log-structured filesystem, and on any solid-state drive, writing over a file does not reach the
    /// blocks that held what was there. What protects a deleted store is that its contents were never
    /// plaintext to begin with.
    ///
    /// # Errors
    /// [`SecretsError::Io`] or [`SecretsError::Denied`] if the file is there and will not go, and
    /// [`SecretsError::Backend`] if the lock that serialises this against another process's write
    /// could not be taken.
    pub fn remove(&self, consent: Consent) -> Result<bool, SecretsError> {
        let Consent(()) = consent;
        let mut cached = self.cache();
        let parent_exists = self
            .path
            .parent()
            .is_none_or(|p| p.as_os_str().is_empty() || p.exists());
        let existed = if parent_exists {
            let _lock = disk::Lock::take(&self.path)?;
            disk::sweep_temps(&self.path);
            disk::remove(&self.path)?
        } else {
            false
        };
        *cached = None;
        Ok(existed)
    }

    /// Take the key cache, taking a poisoned lock's contents back rather than turning another test's
    /// panic into a second one. Panicking is denied in this workspace, and a poisoned cache is not a
    /// condition this store models: the worst it holds is a key that will be re-derived.
    fn cache(&self) -> KeyGuard<'_> {
        self.key.lock()
    }

    /// The key for `header`, from the cache when it was derived from the same salt and cost, and
    /// otherwise by asking for the passphrase and deriving.
    ///
    /// Matching on the salt is what makes a store another process re-sealed reprompt rather than
    /// report a wrong passphrase: a re-seal always draws a new salt, so a mismatch is a definite
    /// stale key rather than a possible typo.
    fn key_for(
        &self,
        cached: &mut Option<CachedKey>,
        header: &Header,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
        if let Some(current) = cached.as_ref()
            && current.salt == header.salt
            && current.cost == header.cost
        {
            return Ok(current.key.clone());
        }
        *cached = None;
        let passphrase = self.passphrase.unlock()?;
        if passphrase.is_empty() {
            return Err(SecretsError::Locked);
        }
        let key = kdf::derive(passphrase.expose(), &header.salt, header.cost)?;
        drop(passphrase);
        *cached = Some(CachedKey {
            salt: header.salt,
            cost: header.cost,
            key: key.clone(),
        });
        Ok(key)
    }

    /// Open the file's table, unlocking first if this handle is sealed.
    ///
    /// A key that turned out not to open the file is never left in the cache, however it was reached,
    /// so the next call asks again instead of failing the same way forever.
    fn read_table(
        &self,
        cached: &mut Option<CachedKey>,
        bytes: &[u8],
    ) -> Result<Table, SecretsError> {
        let header = Header::parse(bytes)?;
        let key = self.key_for(cached, &header)?;
        match unseal(bytes, &header, &key) {
            Ok(table) => Ok(table),
            Err(err) => {
                if matches!(err, SecretsError::WrongPassphrase) {
                    *cached = None;
                }
                Err(err)
            }
        }
    }

    /// Seal `table` and put it in place of whatever is at the path.
    fn publish(
        &self,
        table: &Table,
        salt: &[u8; SALT_LEN],
        cost: KdfCost,
        key: &[u8; KEY_LEN],
    ) -> Result<(), SecretsError> {
        let check_nonce: [u8; NONCE_LEN] = seal::draw()?;
        let body_nonce: [u8; NONCE_LEN] = seal::draw()?;
        let mut header = Header {
            cost,
            salt: *salt,
            check_nonce,
            check_tag: [0u8; TAG_LEN],
            body_nonce,
        };
        header.check_tag =
            seal::seal_check(key, &check_nonce, &header.to_bytes()[..CHECK_AAD_LEN])?;
        let head = header.to_bytes();

        let mut body = items::encode(table)?;
        let tag = seal::seal_body(key, &body_nonce, &header.body_aad(), &mut body)?;

        let mut file = Vec::with_capacity(head.len() + body.len() + TAG_LEN);
        file.extend_from_slice(&head);
        file.extend_from_slice(&body);
        file.extend_from_slice(&tag);
        disk::publish(&self.path, &file)
    }

    /// Run one read-modify-write against the store, under the process lock and the file lock.
    ///
    /// `change` answers whether it changed anything. Nothing is written when it did not, so a delete
    /// of a secret that was not there leaves the file byte for byte as it found it rather than
    /// re-sealing it under a new nonce and looking, to anything watching, like a write.
    fn modify(
        &self,
        missing: Missing,
        change: impl FnOnce(&mut Table) -> bool,
    ) -> Result<(), SecretsError> {
        let mut cached = self.cache();
        disk::private_dir(&self.path)?;
        let _lock = disk::Lock::take(&self.path)?;
        disk::sweep_temps(&self.path);

        let Some(bytes) = disk::read(&self.path)? else {
            return match missing {
                Missing::Refuse => Err(SecretsError::NoCollection),
                Missing::Ignore => Ok(()),
            };
        };
        disk::narrow_file(&self.path);

        let mut table = self.read_table(&mut cached, &bytes)?;
        if !change(&mut table) {
            return Ok(());
        }
        let Some(current) = cached.as_ref() else {
            // Unreachable: `read_table` leaves a key in the cache on every path that returns a table.
            // Reported rather than unwrapped, because this crate takes no panics.
            return Err(SecretsError::Backend {
                step: "seal the secret store",
            });
        };
        self.publish(&table, &current.salt, current.cost, &current.key)
    }
}

/// Open both envelopes and decode what they were holding.
fn unseal(bytes: &[u8], header: &Header, key: &[u8; KEY_LEN]) -> Result<Table, SecretsError> {
    let head = bytes.get(..HEADER_LEN).ok_or(corrupt("file length"))?;
    let split = bytes
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(corrupt("file length"))?;
    let cipher = bytes.get(HEADER_LEN..split).ok_or(corrupt("file length"))?;
    let tag: [u8; TAG_LEN] = bytes
        .get(split..)
        .and_then(|t| t.try_into().ok())
        .ok_or(corrupt("file length"))?;
    let body_aad = header.body_aad();

    if let Err(wrong_key) = seal::open_check(
        key,
        &header.check_nonce,
        &head[..CHECK_AAD_LEN],
        &header.check_tag,
    ) {
        // The check envelope refused, which on its own means only that this key does not open it: a
        // wrong passphrase and an edited check nonce or tag produce the same failure, and no tag can
        // tell a wrong key from a wrong nonce. The body is the tiebreak, because it is not bound to
        // either of those fields. If it opens, the key is the file's own and the damage is confined
        // to the check envelope; if it does not, the key really is wrong.
        let mut probe = Zeroizing::new(cipher.to_vec());
        return Err(
            match seal::open_body(key, &header.body_nonce, &body_aad, &mut probe, &tag) {
                Ok(()) => corrupt("check envelope"),
                Err(_) => wrong_key,
            },
        );
    }

    let mut body = Zeroizing::new(cipher.to_vec());
    seal::open_body(key, &header.body_nonce, &body_aad, &mut body, &tag)?;
    items::decode(&body)
}

impl SecretStore for EncryptedFile {
    /// Takes no file lock. A write publishes by rename, so a reader that opened the old file goes on
    /// seeing a whole consistent version of it, and a read never waits behind one.
    fn get(&self, account: Uuid, kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        let mut cached = self.cache();
        let Some(bytes) = disk::read(&self.path)? else {
            return Ok(None);
        };
        let table = self.read_table(&mut cached, &bytes)?;
        Ok(table
            .get(&items::key_for(account, kind))
            .map(|value| Secret::new(value.to_vec())))
    }

    fn set(&self, account: Uuid, kind: SecretKind, value: Secret) -> Result<(), SecretsError> {
        let key = items::key_for(account, kind);
        let bytes = Zeroizing::new(value.expose().to_vec());
        drop(value);
        self.modify(Missing::Refuse, move |table| {
            table.insert(key, bytes);
            true
        })
    }

    fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError> {
        let key = items::key_for(account, kind);
        self.modify(Missing::Ignore, move |table| table.remove(&key).is_some())
    }

    /// Answers from the path every time, and consults the cached key only to separate a store this
    /// handle has already unlocked from one it has not.
    ///
    /// Answering from the key alone was worse than useless: whether a key is cached says nothing
    /// about what is at the path, so a handle whose file had been deleted or overwritten behind it
    /// went on reporting `Ready` with `is_usable()` true. That state is reachable inside one process,
    /// because the CLI's own destroy-file verb opens a second handle over the path the long-lived one
    /// is holding. Reading the path is still a report about a moment that has passed, which no probe
    /// can avoid, but it is a report about the right thing.
    fn probe(&self) -> BackendReport {
        let state = match self.inspect() {
            FileState::Sealed { .. } if self.is_open() => BackendState::Ready,
            // Usable once the passphrase arrives, and unusable when nothing can supply one:
            // offering to save into a store that will refuse the write helps nobody.
            FileState::Sealed { .. } if self.passphrase.can_prompt() => BackendState::Locked,
            FileState::Sealed { .. } => BackendState::Unreachable,
            // A store nobody has created is reachable and has nothing to store into, which is
            // what this state says. It is also the only answer that keeps `is_usable` false, and
            // a secret must not be routed at a store the user has not asked for.
            FileState::Absent => BackendState::NoDefaultCollection,
            FileState::Unreadable | FileState::Foreign => BackendState::Unreachable,
        };
        BackendReport {
            backend: Backend::EncryptedFile,
            state,
            sandbox: None,
        }
    }

    /// One rewrite rather than the default's one per kind.
    ///
    /// The default body deletes each kind in turn, which here is two full read-modify-write cycles
    /// and a window in which a crash leaves the account half swept. This takes every record filed
    /// under the account in a single atomic write, **whatever its kind tag**, including tags a later
    /// build wrote and this one has no name for. That is strictly more thorough than the default:
    /// the sweep is what a user asks for when they want an account gone, and leaving behind the one
    /// record this build did not recognise is exactly the residue it exists to prevent.
    fn forget_account(&self, account: Uuid) -> Result<(), SecretsError> {
        let id = *account.as_bytes();
        self.modify(Missing::Ignore, move |table| {
            let before = table.len();
            table.retain(|(stored, _), _| *stored != id);
            table.len() != before
        })
    }
}

/// Written out rather than derived: `Zeroizing` forwards `Debug` to what it holds, so a derive here
/// would print the sealing key.
impl std::fmt::Debug for EncryptedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFile")
            .field("path", &self.path)
            .field("open", &self.is_open())
            .finish()
    }
}

/// Reach the header parser from the crate root, for the fuzz workspace and nothing else.
///
/// The parser itself lives in a module private to this one, so an entry point has to be re-exported
/// rather than named directly. The feature is what keeps it out of a shipping build.
#[cfg(feature = "fuzzing")]
pub(crate) fn parse_frame(bytes: &[u8]) {
    let _ = Header::parse(bytes);
}

/// As [`parse_frame`], for the record table.
#[cfg(feature = "fuzzing")]
pub(crate) fn parse_records(bytes: &[u8]) {
    let _ = items::decode(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);
    const OTHER: Uuid = Uuid::from_u128(2);

    /// The handle is held behind a trait object inside the composition root and moved across task
    /// boundaries with it, so it has to stay `Send + Sync + 'static`. Nothing else pins that: a cache
    /// changed to a non-`Sync` cell would otherwise be caught at the first consumer rather than here.
    const _: fn() = || {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<EncryptedFile>();
    };

    /// The sweep's headline claim, which no public API can set up: a record filed under a tag this
    /// build has no name for still goes when the account it belongs to is emptied. Leaving it behind
    /// would be a secret surviving in a store the user asked to be emptied, and every other test can
    /// only write the two kinds this build knows.
    ///
    /// Written straight through the sealing path rather than through `set`, which is the only way to
    /// put a tag there that no `SecretKind` maps to.
    #[test]
    fn an_account_sweep_takes_a_kind_this_build_does_not_know() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(EncryptedFile::FILE_NAME);
        let store = EncryptedFile::open(&path, Arc::new(Unprompted));
        store
            .create(
                Consent::granted(),
                &Secret::new(b"pp".to_vec()),
                KdfCost::floor(),
            )
            .expect("create");

        let unknown = 200;
        assert!(!SecretKind::ALL.iter().any(|k| items::tag_of(*k) == unknown));
        let mut table = Table::new();
        table.insert(
            (*ACCOUNT.as_bytes(), items::tag_of(SecretKind::Password)),
            Zeroizing::new(b"hunter2".to_vec()),
        );
        table.insert(
            (*ACCOUNT.as_bytes(), unknown),
            Zeroizing::new(b"from a later build".to_vec()),
        );
        table.insert(
            (*OTHER.as_bytes(), unknown),
            Zeroizing::new(b"another account's".to_vec()),
        );
        let held = store
            .cache()
            .as_ref()
            .map(|c| (c.salt, c.cost, c.key.clone()));
        let (salt, cost, key) = held.expect("creating leaves the handle open");
        store.publish(&table, &salt, cost, &key).expect("seal");

        store.forget_account(ACCOUNT).expect("sweep");

        let bytes = disk::read(&path).expect("read").expect("present");
        let header = Header::parse(&bytes).expect("parse");
        let left = unseal(&bytes, &header, &key).expect("open");
        assert_eq!(left.len(), 1);
        assert!(left.contains_key(&(*OTHER.as_bytes(), unknown)));
    }

    /// The body is bound to the key material and its own nonce, and to nothing else in the header.
    ///
    /// Every other test reaches the body through `unseal`, so the writer and the reader agree by
    /// construction and the suite observes the agreement rather than the binding: moving both to the
    /// same wrong region is green across the whole suite. The associated data here is rebuilt
    /// positionally from the bytes that were written, so what is asserted is what `publish`
    /// committed to rather than what the reader happens to agree with.
    ///
    /// Both halves of the classification rest on this shape. Widening it back over the check
    /// envelope makes damage there indistinguishable from a wrong passphrase; narrowing it further
    /// unbinds the body's own nonce.
    #[test]
    fn the_body_is_sealed_under_the_key_material_and_its_own_nonce() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(EncryptedFile::FILE_NAME);
        let store = EncryptedFile::open(&path, Arc::new(Unprompted));
        store
            .create(
                Consent::granted(),
                &Secret::new(b"pp".to_vec()),
                KdfCost::floor(),
            )
            .expect("create");
        store
            .set(
                ACCOUNT,
                SecretKind::Password,
                Secret::new(b"hunter2".to_vec()),
            )
            .expect("write");

        let key = store
            .cache()
            .as_ref()
            .map(|c| c.key.clone())
            .expect("writing leaves the handle open");
        let bytes = disk::read(&path).expect("read").expect("present");
        let header = Header::parse(&bytes).expect("parse");
        let split = bytes.len() - TAG_LEN;
        let head = header.to_bytes();
        let tag: [u8; TAG_LEN] = bytes[split..].try_into().expect("tag");
        assert_eq!(head[..], bytes[..HEADER_LEN], "the header round-trips");

        // Assembled by offset out of the file itself: the key material, then the last field of the
        // header, which is the body's nonce. Nothing from this module decides what goes in.
        let mut rebuilt = Vec::new();
        rebuilt.extend_from_slice(&bytes[..CHECK_AAD_LEN]);
        rebuilt.extend_from_slice(&bytes[HEADER_LEN - NONCE_LEN..HEADER_LEN]);

        let mut body = bytes[HEADER_LEN..split].to_vec();
        seal::open_body(&key, &header.body_nonce, &rebuilt, &mut body, &tag)
            .expect("the body opens under the key material and its own nonce");

        // Not the whole header. That is the shape this replaced, and under it the check envelope's
        // own bytes are covered twice over and damage to them reads as a mistyped passphrase.
        let mut body = bytes[HEADER_LEN..split].to_vec();
        assert!(
            seal::open_body(&key, &header.body_nonce, &head, &mut body, &tag).is_err(),
            "the body is still bound to the whole header"
        );

        // The property the damage-versus-typo classification rests on, in both directions. An edit
        // inside the check envelope leaves the body openable, so a correct key is still provable;
        // an edit to the key material or to the body's nonce does not.
        let mut edited = header;
        edited.check_tag[0] ^= 1;
        edited.check_nonce[0] ^= 1;
        let mut body = bytes[HEADER_LEN..split].to_vec();
        seal::open_body(
            &key,
            &header.body_nonce,
            &edited.body_aad(),
            &mut body,
            &tag,
        )
        .expect("an edited check envelope must leave the body openable");

        let mut salted = header;
        salted.salt[0] ^= 1;
        let mut renonced = header;
        renonced.body_nonce[0] ^= 1;
        for (what, moved) in [("the salt", salted), ("the body nonce", renonced)] {
            let mut body = bytes[HEADER_LEN..split].to_vec();
            assert!(
                seal::open_body(&key, &header.body_nonce, &moved.body_aad(), &mut body, &tag)
                    .is_err(),
                "the body opened with {what} edited out from under it"
            );
        }
    }

    /// The guard on the hand-written `Debug`. A derive would print the sealing key, and the whole
    /// point of the type it is held in is that it never reaches a log.
    #[test]
    fn a_store_never_prints_its_key() {
        let store = EncryptedFile::open("/nonexistent/store.apsf", Arc::new(Unprompted));
        let key = [0xAB_u8; KEY_LEN];
        *store.cache() = Some(CachedKey {
            salt: [0xCD; SALT_LEN],
            cost: KdfCost::floor(),
            key: Zeroizing::new(key),
        });
        let rendered = format!("{store:?}");
        assert!(rendered.contains("open: true"), "{rendered}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
    }

    /// A store with no way to ask must fail every call rather than take the process down with it, and
    /// must not look usable. The sweep is included because it is the one path a caller reaches while
    /// tidying up rather than while storing anything.
    #[test]
    fn a_store_with_no_way_to_ask_refuses_every_call_instead_of_panicking() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(EncryptedFile::FILE_NAME);
        let store = EncryptedFile::open(&path, Arc::new(Unprompted));

        assert_eq!(store.inspect(), FileState::Absent);
        assert!(!store.probe().is_usable());
        assert!(
            store
                .get(Uuid::nil(), SecretKind::Password)
                .expect("read")
                .is_none()
        );
        assert!(matches!(
            store.set(
                Uuid::nil(),
                SecretKind::Password,
                Secret::new(b"pw".to_vec())
            ),
            Err(SecretsError::NoCollection)
        ));
        store
            .delete(Uuid::nil(), SecretKind::Password)
            .expect("delete");
        store.forget_account(Uuid::nil()).expect("sweep");
        assert!(!store.remove(Consent::granted()).expect("remove"));
    }

    /// An absent store answers with the one state that keeps `is_usable` false. Reported as locked it
    /// would have a front end offer to save a password into a file nobody has made.
    #[test]
    fn an_absent_store_is_reported_as_having_nothing_to_store_into() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = EncryptedFile::open(dir.path().join("nope.apsf"), Arc::new(Unprompted));
        let report = store.probe();
        assert_eq!(report.backend, Backend::EncryptedFile);
        assert_eq!(report.state, BackendState::NoDefaultCollection);
        assert!(!report.is_usable());
        assert!(report.sandbox.is_none());
    }
}
