//! Getting the sealed bytes onto and off the disk without losing them.
//!
//! Three concerns live here, all of them about the file rather than about what is in it: publishing a
//! new version so that a crash leaves either the old one or the new one and never a torn one, keeping
//! two launcher processes from writing over each other, and keeping the file and its directory
//! readable by nobody else.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;
use zeroize::Zeroizing;

use super::frame::{check_size_on_disk, corrupt};
use crate::SecretsError;

/// Suffix of the sidecar the exclusive lock is taken on.
const LOCK_SUFFIX: &str = "lock";

/// Suffix every in-flight write carries until it is renamed into place.
const TEMP_SUFFIX: &str = "tmp";

/// How many times a lock will re-take a sidecar that was replaced under it before giving up.
const LOCK_ATTEMPTS: u32 = 8;

/// Read the sealed file, or answer `None` if there is nothing at the path.
///
/// The size is checked against the cap from the directory entry, before any of the file is read, so a
/// hostile file cannot make this allocate for it.
pub(crate) fn read(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, SecretsError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(map_io(err)),
    };
    if !meta.is_file() {
        // A symlink or a directory at the store path. The write path replaces whatever is there by
        // rename and never follows it, so this is what stops a *read* being redirected. It is a check
        // and not a guarantee: without a platform crate there is no way to open a path and refuse a
        // symlink in the same syscall, so a swap between here and the open is not covered. Stated
        // rather than implied.
        return Err(corrupt("store path"));
    }
    check_size_on_disk(meta.len())?;

    let mut file = File::open(path).map_err(map_io)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(meta.len() as usize + 1));
    file.read_to_end(&mut bytes).map_err(map_io)?;
    // Re-checked against what was actually read: the size the directory entry reported is a fact
    // about the moment before the open, and the file may have grown since.
    check_size_on_disk(bytes.len() as u64)?;
    Ok(Some(bytes))
}

/// Replace the file at `path` with `bytes`, atomically.
///
/// The sequence is write-elsewhere, flush, rename, and it is what makes a crash leave either the
/// whole old store or the whole new one. An orphaned temp left by a crash holds ciphertext, not
/// plaintext.
pub(crate) fn publish(path: &Path, bytes: &[u8]) -> Result<(), SecretsError> {
    let temp = sibling(path, &format!("{}.{TEMP_SUFFIX}", Uuid::new_v4()));

    let mut options = OpenOptions::new();
    options.write(true);
    // Exclusive creation, so a symlink planted at the temp name is refused rather than followed, and
    // so a name a concurrent writer is already using is never taken.
    options.create_new(true);
    private_file(&mut options);
    let mut file = options.open(&temp).map_err(map_io)?;

    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(map_io);
    drop(file);
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(map_io(err));
    }

    // Best effort, never an error. The rename is already atomic, so this only decides whether the
    // directory entry survives a power cut, and not every filesystem lets a directory be flushed.
    if let Some(parent) = path.parent() {
        let _ = File::open(parent).and_then(|dir| dir.sync_all());
    }
    Ok(())
}

/// Remove temp files a crashed write left behind.
///
/// Only ever called with the exclusive lock held, which is the one moment at which any temp beside
/// the store is provably not another live writer's in-flight file.
pub(crate) fn sweep_temps(path: &Path) {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(found) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if found.starts_with(&format!("{name}.")) && found.ends_with(&format!(".{TEMP_SUFFIX}")) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Delete the store. Answers whether there was one.
pub(crate) fn remove(path: &Path) -> Result<bool, SecretsError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(map_io(err)),
    }
}

/// The exclusive lock held across a whole read-modify-write.
///
/// Taken on a sidecar rather than on the store itself, because the store is replaced by rename: a
/// lock on the file that was there protects an inode nothing will write to again. The kernel releases
/// it when this drops, including when the process dies, so there is no stale-lock heuristic and
/// nothing to clean up.
pub(crate) struct Lock {
    _file: File,
}

impl Lock {
    /// Take the lock, waiting for whoever holds it.
    ///
    /// Blocking rather than trying and failing: the alternative is a caller that has to decide how
    /// long to retry for, and the holder is another process doing a write that takes milliseconds.
    pub(crate) fn take(path: &Path) -> Result<Self, SecretsError> {
        let sidecar = sibling(path, LOCK_SUFFIX);
        let failed = || SecretsError::Backend {
            step: "take the secret store lock",
        };
        // Bounded rather than endless. Each turn means the sidecar was replaced between this open
        // and this lock, which two launchers can genuinely lose once; a process losing it over and
        // over is racing something doing it deliberately, and waiting forever is the worse answer.
        for _ in 0..LOCK_ATTEMPTS {
            let file = open_sidecar(&sidecar)?;
            // The sidecar is never deleted. Removing it would race the next process to acquire,
            // which would then lock a file nobody else can see and serialise against nothing.
            file.lock().map_err(|_| failed())?;
            if still_at(&sidecar, &file) {
                return Ok(Self { _file: file });
            }
            // Somebody unlinked the sidecar while this waited, so the lock now held is on an inode
            // no other process will open: it excludes nobody. Two writers each holding one of these
            // both returned `Ok` and one account's secret went missing. Take the one that is there.
        }
        Err(failed())
    }
}

/// Open the lock sidecar, refusing anything at that name that is not a regular file.
///
/// This was the one path in this file opened with no guard on what it found. The temp file uses
/// `create_new` precisely so a planted symlink is refused, and the store itself is refused when it
/// is not a regular file, but the sidecar took whatever was there. A FIFO left at the name parked
/// every write inside `open(2)` indefinitely while holding the process-wide key lock, so the store
/// could not even be deleted to recover; a symlink moved the lock to a file the other writer would
/// never open, leaving the mutual exclusion protecting nothing.
///
/// Creating it exclusively first is what makes the common case safe without a check at all. The
/// fallback check is not a guarantee, for the same reason it is not one on the read path: without a
/// platform crate there is no way to open a path and refuse a symlink in one syscall, so a swap
/// between the check and the open is uncovered. Stated rather than implied.
fn open_sidecar(sidecar: &Path) -> Result<File, SecretsError> {
    let mut fresh = OpenOptions::new();
    fresh.write(true).create_new(true);
    private_file(&mut fresh);
    match fresh.open(sidecar) {
        Ok(file) => return Ok(file),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
        Err(err) => return Err(map_io(err)),
    }

    let meta = std::fs::symlink_metadata(sidecar).map_err(map_io)?;
    if !meta.is_file() {
        return Err(corrupt("store lock"));
    }
    let mut existing = OpenOptions::new();
    existing.write(true).truncate(false);
    private_file(&mut existing);
    existing.open(sidecar).map_err(map_io)
}

/// Whether `file` is still what the name resolves to.
///
/// The flock is on an inode, not on a name, so a sidecar that was unlinked while this process waited
/// leaves it holding a lock that excludes nobody.
#[cfg(unix)]
fn still_at(sidecar: &Path, file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;

    let (Ok(held), Ok(named)) = (file.metadata(), std::fs::symlink_metadata(sidecar)) else {
        return false;
    };
    held.dev() == named.dev() && held.ino() == named.ino()
}

/// Windows keeps the handle and the name together: an open file cannot be unlinked out from under
/// its holder, so the race this answers is a unix one.
#[cfg(not(unix))]
fn still_at(_sidecar: &Path, _file: &File) -> bool {
    true
}

/// A path beside `path` with one more dotted suffix.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Fold a filesystem failure into the taxonomy.
///
/// Permission is its own answer because it is the one a user fixes somewhere other than in this
/// launcher. The error is carried in the `Io` variant unchanged for the rest, which is safe here in a
/// way it is not for the credential stores: a filesystem error names a path, and the path is not a
/// secret.
fn map_io(err: std::io::Error) -> SecretsError {
    if err.kind() == ErrorKind::PermissionDenied {
        return SecretsError::Denied;
    }
    SecretsError::Io(err)
}

/// Make sure the directory the store lives in exists and is owner-only.
///
/// Narrows a directory an earlier build or a restore left wider, rather than only setting the mode on
/// one it creates: a store that has been readable since it was made would otherwise stay that way
/// forever, and nothing would ever say so.
#[cfg(unix)]
pub(crate) fn private_dir(path: &Path) -> Result<(), SecretsError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
    {
        Ok(()) => {}
        Err(err) => return Err(map_io(err)),
    }

    // `recursive` leaves an existing directory's mode alone, which is the case this repairs. Both
    // ways, deliberately: clearing the group and other bits is what keeps the store private, and
    // restoring the owner's own bits is what keeps it reachable. A repair that could only clear
    // them left a directory that had lost its owner write or search bit answering `Denied` on every
    // call forever, with no way back from inside the launcher, and this is the directory the
    // settings and the account records live in too. An exotic umask at first create reaches it, and
    // so does a restore tool.
    //
    // On the handle rather than on the path: the mode that gets set then belongs to the directory
    // that was just examined, instead of to whatever the name resolves to a moment later. Opening
    // still follows a symlink at the name, which is a smaller gap than the one it closes and is the
    // same one the read path documents.
    let Ok(dir) = File::open(parent) else {
        return Ok(());
    };
    let Ok(meta) = dir.metadata() else {
        return Ok(());
    };
    let mode = meta.permissions().mode();
    if mode & 0o777 != 0o700 {
        // setuid, setgid and sticky are carried over rather than cleared: none of them is this
        // function's business, and dropping one a user set would be a change nobody asked for.
        let _ = dir.set_permissions(PermissionsExt::from_mode((mode & 0o7000) | 0o700));
    }
    Ok(())
}

/// Narrow the store itself if something widened it.
///
/// The contents are sealed either way, so a wider file is not a reason to refuse the operation and
/// strand a user whose backup tool restored it with a group bit. It is a reason to put it back.
#[cfg(unix)]
pub(crate) fn narrow_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            let _ = std::fs::set_permissions(path, PermissionsExt::from_mode(mode & 0o700));
        }
    }
}

#[cfg(unix)]
fn private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    // On the open rather than as a later chmod, so the file is never briefly readable by anyone else.
    options.mode(0o600);
}

/// Make sure the directory the store lives in exists and that nothing but its owner can reach it.
///
/// Windows has no mode bits. What decides access is the directory's DACL, and a directory created
/// under a wide parent inherits that parent's inheritable entries verbatim: under a drive root that
/// is `BUILTIN\Users:(I)(RX)` and `NT AUTHORITY\Authenticated Users:(I)(M)`, which lets every local
/// account copy the sealed file and grind the passphrase offline, and lets any authenticated account
/// overwrite it, turning a whole-file rollback into something another user can do. So the directory
/// gets a *protected* DACL, protected being the flag that stops inheritance, holding one entry: full
/// control for the directory's own owner, inheritable by everything created inside it. The owner
/// rather than whoever is running, because that is what a mode names on the other arm.
///
/// Re-applied on every call rather than only to a directory this creates, for the reason the unix
/// arm repairs a mode both ways: a store made by an earlier build, or restored by a tool that
/// dropped the entries, would otherwise stay readable for the rest of its life with nothing to say
/// so. It is a no-op when the entry is already the one wanted, so a healthy store is never written.
#[cfg(windows)]
pub(crate) fn private_dir(path: &Path) -> Result<(), SecretsError> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    std::fs::create_dir_all(parent).map_err(map_io)?;
    if is_root(parent) {
        return Ok(());
    }
    win_acl::own_only(parent, win_acl::Inherit::Yes)
}

/// Whether `dir` is a volume root, which this arm creates under and never re-permissions.
///
/// Narrowing `C:\` is damage rather than repair, and it is not a directory this crate would have
/// created: it is whatever the caller's path happened to sit on. So a drive root keeps what it had,
/// and the store's own directory below it is the one that gets an owner-only list. Nothing a shipped
/// launcher composes puts a store at a root; the only paths that do are a caller's own choosing.
#[cfg(windows)]
fn is_root(dir: &Path) -> bool {
    dir.parent().is_none()
}

/// Narrow the store itself if something widened it, and take the read-only attribute back off.
///
/// Two repairs, because Windows has two ways to leave the store unwritable. The attribute is the one
/// that bricks it: `publish` replaces the file by rename, and a rename over a file carrying
/// `FILE_ATTRIBUTE_READONLY` fails with access denied every time, so a restore, read-only media or
/// one `attrib +R` leaves every write answering `Denied` for good while reads go on working. The
/// entry list is the other: a file restored with explicit entries of its own carries them into a
/// directory whose inheritance never gets to override them.
///
/// Best effort, like the unix arm. The contents are sealed either way, so a file that will not
/// narrow is not a reason to refuse the operation and strand the user.
#[cfg(windows)]
pub(crate) fn narrow_file(path: &Path) {
    clear_readonly(path);
    let _ = win_acl::own_only(path, win_acl::Inherit::No);
}

/// Nothing to set on the open, and nothing that needs to be.
///
/// The standard library cannot hand a `SECURITY_ATTRIBUTES` to `CreateFile`, so there is no mode to
/// put on the open the way the unix arm does. It is not the mechanism here anyway: a file created in
/// a directory whose DACL is protected and owner-only inherits that one entry and nothing else, and
/// `private_dir` runs ahead of every path that creates one. What this arm used to assert, that the
/// launcher's own directory is already restricted to the user, is now something the crate does
/// rather than something it takes on faith about a path its caller chose.
#[cfg(windows)]
fn private_file(_options: &mut OpenOptions) {}

/// Take `FILE_ATTRIBUTE_READONLY` back off, so a rename over the file can land.
///
/// The rename is the only case that needs it. An unlink does not, because the standard library
/// clears the attribute itself before removing a file on this platform, which is measured rather
/// than assumed: `a_read_only_store_deletes_without_help` is what holds that.
///
/// Refuses anything at the name that is not a regular file, for the reason the read path does: the
/// permission set here follows a symlink, and the store path is the caller's.
///
/// The lint below is the unix hazard: clearing the flag there sets every write bit, world included.
/// This arm is Windows-only, where the flag is one attribute and clearing it grants nobody anything.
#[cfg(windows)]
#[allow(
    clippy::permissions_set_readonly_false,
    reason = "one attribute on Windows; the world-writable outcome is the unix arm's, and this is \
              not compiled there"
)]
fn clear_readonly(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_file() {
        return;
    }
    let mut perms = meta.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// The Win32 behind the Windows arm above.
///
/// The one place in this workspace that leaves safe Rust, and the reason this crate is
/// `deny(unsafe_code)` where every other crate root is `forbid`: the standard library exposes no
/// security-descriptor API, and on Windows the security descriptor is the whole of what a mode is on
/// unix. `scripts/audit.sh` fails on an `unsafe` block anywhere else.
///
/// Every call is `advapi32` through Microsoft's own bindings, there is no pointer arithmetic, and
/// the two blocks the conversions allocate are freed by [`LocalBlock`] rather than by hand.
#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "the security descriptor has no safe-Rust equivalent"
)]
mod win_acl {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree, WIN32_ERROR};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OBJECT_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    use windows_sys::core::PWSTR;

    use super::map_io;
    use crate::SecretsError;

    /// Whether the entry also has to reach what is created inside the object.
    pub(super) enum Inherit {
        /// A directory: object- and container-inherit, so every file and directory made in it starts
        /// with the same one entry.
        Yes,
        /// A file: nothing is created inside it, so the entry carries no inheritance flags.
        No,
    }

    /// Give `path` a protected access list naming nobody but `path`'s own owner.
    ///
    /// Protected is what makes this a narrowing rather than an addition: it drops the parent's
    /// inherited entries, so the one written here is the whole list. Reads the current list first
    /// and returns without writing when it already matches, which is the common case on every call
    /// after the first.
    pub(super) fn own_only(path: &Path, inherit: Inherit) -> Result<(), SecretsError> {
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

        let current = read(
            &name,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        )?;
        let owner = sddl(&current, OWNER_SECURITY_INFORMATION)?;
        let Some(sid) = owner.strip_prefix("O:") else {
            return Err(unreadable());
        };
        // `FA` is full control. `OI` and `CI` are the two inheritance flags, which is what `icacls`
        // prints as `(OI)(CI)(F)`.
        let flags = match inherit {
            Inherit::Yes => "OICI",
            Inherit::No => "",
        };
        let wanted = format!("(A;{flags};FA;;;{sid})");
        let rendered = sddl(&current, DACL_SECURITY_INFORMATION)?;
        let (control, entries) = split_dacl(&rendered);
        if control.contains('P') && entries == wanted {
            return Ok(());
        }
        drop(current);

        write(&name, &parse(&format!("D:P{wanted}"))?)
    }

    /// A rendered access list split into its control flags and its entries.
    ///
    /// The flags are the descriptor's own state, `P` for protected and `AI` for auto-inherited, and
    /// Windows sets `AI` itself on the way in. Folding them into the comparison above would make the
    /// already-narrow check never match and rewrite the list on every call for the rest of the
    /// store's life.
    fn split_dacl(rendered: &str) -> (&str, &str) {
        let body = rendered.strip_prefix("D:").unwrap_or(rendered);
        match body.find('(') {
            Some(at) => body.split_at(at),
            None => (body, ""),
        }
    }

    /// A block one of these calls allocated with `LocalAlloc`, released once when it goes out of
    /// scope. The pointers read out of a descriptor point *into* it, so the block has to outlive
    /// them, which is what makes this worth a type rather than a call at each exit.
    struct LocalBlock(*mut c_void);

    impl Drop for LocalBlock {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a call documented to return `LocalAlloc`ed memory,
                // this is the only owner of it, and `Drop` runs once.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// The named object's security descriptor, holding whatever `what` asked for.
    fn read(name: &[u16], what: OBJECT_SECURITY_INFORMATION) -> Result<LocalBlock, SecretsError> {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `name` is a NUL-terminated UTF-16 path that outlives the call, `descriptor` is a
        // live out-pointer, and the four out-parameters not asked for are optional and passed null.
        // On success the descriptor is `LocalAlloc`ed and becomes `LocalBlock`'s to free.
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                what,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(LocalBlock(descriptor))
        } else {
            Err(win32(status))
        }
    }

    /// One component of `descriptor` in SDDL, the text form `icacls` and PowerShell also speak.
    ///
    /// Asked for one component at a time so the answer needs no parsing: `O:` alone is the owner and
    /// `D:` alone is the access list, where a descriptor rendered whole would have to be split.
    fn sddl(
        descriptor: &LocalBlock,
        what: OBJECT_SECURITY_INFORMATION,
    ) -> Result<String, SecretsError> {
        let mut text: PWSTR = ptr::null_mut();
        let mut units = 0u32;
        // SAFETY: the descriptor is alive for the call, and both out-pointers are live locals. On
        // success `text` is a `LocalAlloc`ed UTF-16 string of `units` characters.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                what,
                &raw mut text,
                &raw mut units,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        let text = LocalBlock(text.cast());
        let len = units as usize;
        // SAFETY: the call reported `units` characters at `text`, which is alive here and is not
        // written through anywhere.
        let rendered = unsafe { std::slice::from_raw_parts(text.0.cast::<u16>(), len) };
        // The length is documented without the terminator. Trimmed rather than trusted either way,
        // because a NUL riding along would sit inside every string `own_only` compares.
        let rendered = rendered.strip_suffix(&[0]).unwrap_or(rendered);
        String::from_utf16(rendered).map_err(|_| unreadable())
    }

    /// An SDDL access list back into a descriptor.
    fn parse(text: &str) -> Result<LocalBlock, SecretsError> {
        let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `text` is a NUL-terminated UTF-16 buffer that outlives the call, the revision is
        // the only one this API defines, `descriptor` is a live out-pointer, and the size
        // out-parameter is optional and passed null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(LocalBlock(descriptor))
    }

    /// Put `descriptor`'s access list onto the named object, protected against inheritance.
    fn write(name: &[u16], descriptor: &LocalBlock) -> Result<(), SecretsError> {
        let mut acl: *mut ACL = ptr::null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        // SAFETY: the descriptor is the one `parse` built and is alive here, and the three
        // out-pointers are live locals. `acl` comes back pointing into the descriptor.
        let ok = unsafe {
            GetSecurityDescriptorDacl(
                descriptor.0,
                &raw mut present,
                &raw mut acl,
                &raw mut defaulted,
            )
        };
        if ok == 0 || present == 0 {
            return Err(unreadable());
        }

        // SAFETY: `name` is a NUL-terminated UTF-16 path, `acl` points into `descriptor`, which
        // outlives the call, and the owner, group and audit parameters are null because only the
        // access list is being set. The call copies what it is handed and keeps no pointer.
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null(),
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(win32(status))
        }
    }

    /// A Win32 status through the same taxonomy the filesystem errors take, so access denied on the
    /// access list reads as `Denied` exactly as access denied on an open does.
    fn win32(status: WIN32_ERROR) -> SecretsError {
        map_io(std::io::Error::from_raw_os_error(status as i32))
    }

    /// The thread's last error, for the calls that report failure with a bool.
    fn last_error() -> SecretsError {
        map_io(std::io::Error::last_os_error())
    }

    /// A descriptor that came back well-formed enough to succeed and not well-formed enough to use.
    fn unreadable() -> SecretsError {
        SecretsError::Backend {
            step: "read the secret store's access list",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        #[allow(clippy::expect_used)]
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn a_published_file_reads_back_and_an_absent_one_is_nothing() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        assert!(read(&path).expect("absent").is_none());

        let bytes = vec![7u8; super::super::frame::MIN_FILE];
        publish(&path, &bytes).expect("publish");
        assert_eq!(*read(&path).expect("read").expect("present"), bytes);
    }

    /// The publish has to leave nothing behind, or a crashed write's leftovers would accumulate in a
    /// directory the user never looks at.
    #[test]
    fn a_publish_leaves_no_temp_file() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        publish(&path, &vec![0u8; super::super::frame::MIN_FILE]).expect("publish");
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .expect("list")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty());
    }

    /// A temp left by a crashed write is another process's business until the lock is held, and then
    /// it is nobody's. The sweep must take those and leave the store and the sidecar alone.
    #[test]
    fn the_sweep_takes_only_this_store_s_leftovers() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        publish(&path, &vec![0u8; super::super::frame::MIN_FILE]).expect("publish");
        let lock = Lock::take(&path).expect("lock");
        for name in [
            "store.apsf.abc.tmp",
            "store.apsf.def.tmp",
            "other.apsf.abc.tmp",
            "store.apsf.keepme",
        ] {
            std::fs::write(dir.path().join(name), b"x").expect("write");
        }
        sweep_temps(&path);
        drop(lock);

        assert!(path.exists());
        assert!(dir.path().join("store.apsf.lock").exists());
        assert!(dir.path().join("other.apsf.abc.tmp").exists());
        assert!(dir.path().join("store.apsf.keepme").exists());
        assert!(!dir.path().join("store.apsf.abc.tmp").exists());
        assert!(!dir.path().join("store.apsf.def.tmp").exists());
    }

    /// The narrowing of an existing wide *directory*, which is the one permissions path the store's
    /// own tests cannot reach: they always create their directory rather than finding one. A store
    /// made before this was owner-only, or restored by a tool that widened it, has to be put back
    /// rather than left leaking quietly for the rest of its life.
    #[cfg(unix)]
    #[test]
    fn a_directory_and_a_file_left_wider_are_narrowed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).expect("mkdir");
        std::fs::set_permissions(&nested, PermissionsExt::from_mode(0o755)).expect("chmod");
        let path = nested.join("store.apsf");
        std::fs::write(&path, b"x").expect("write");
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).expect("chmod");

        private_dir(&path).expect("directory");
        narrow_file(&path);

        assert_eq!(
            std::fs::metadata(&nested)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
    }

    /// One SDDL component of what `path` carries, read back through the platform's own tool rather
    /// than through the bindings under test: a permission this crate both writes and reads proves
    /// only that it agrees with itself, and the access list is the whole claim here.
    ///
    /// `GetSecurityDescriptorSddlForm` rather than `.Sddl`, because it answers one component at a
    /// time and so needs no splitting, and because SDDL is the one rendering `icacls` does not
    /// localize.
    #[cfg(windows)]
    #[allow(clippy::expect_used)]
    fn sddl(path: &Path, part: &str) -> String {
        let script = format!(
            "(Get-Acl -LiteralPath '{}').GetSecurityDescriptorSddlForm('{part}')",
            path.display()
        );
        let out = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .expect("run powershell");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// The one entry the arm under test should have left, spelled the way the platform renders it.
    ///
    /// `AI` is the auto-inherited flag, which Windows sets itself on the way in and which the code
    /// under test therefore does not compare on; it is pinned here because this is where what the
    /// platform actually does belongs.
    #[cfg(windows)]
    fn only_owner(path: &Path, inherit: &str) -> String {
        let owner = sddl(path, "Owner");
        let sid = owner.strip_prefix("O:").unwrap_or(&owner);
        format!("D:PAI(A;{inherit};FA;;;{sid})")
    }

    /// Hand a path an entry it should not keep, through `icacls` for the reason `sddl` reads through
    /// PowerShell. `*S-1-1-0` is Everyone by SID, so the seeding does not depend on the machine's
    /// language either.
    #[cfg(windows)]
    #[allow(clippy::expect_used)]
    fn grant_everyone(path: &Path, spec: &str) {
        let out = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(["/grant", &format!("*S-1-1-0:{spec}")])
            .output()
            .expect("run icacls");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// Set or clear `FILE_ATTRIBUTE_READONLY`, which is what a restore, read-only media or one
    /// `attrib +R` leaves behind.
    #[cfg(windows)]
    #[allow(clippy::expect_used)]
    fn set_readonly(path: &Path, on: bool) {
        let mut perms = std::fs::metadata(path).expect("stat").permissions();
        perms.set_readonly(on);
        std::fs::set_permissions(path, perms).expect("attribute");
    }

    /// Windows has no mode bits, so the directory's access list is the entire mechanism, and a
    /// directory created under a wide parent inherits that parent's entries verbatim. That is what a
    /// store under a drive root gets: `BUILTIN\Users:(I)(RX)` and `Authenticated Users:(I)(M)`, so
    /// every local account could copy the sealed file and grind the passphrase offline. The store's
    /// own tests cannot reach this, because they create their directory under a temp root that is
    /// already user-only.
    #[cfg(windows)]
    #[test]
    fn a_directory_under_a_wide_parent_is_narrowed() {
        let dir = temp_dir();
        let wide = dir.path().join("wide");
        std::fs::create_dir(&wide).expect("mkdir");
        grant_everyone(&wide, "(OI)(CI)F");
        let nested = wide.join("nested");
        let path = nested.join("store.apsf");

        private_dir(&path).expect("directory");

        assert_eq!(sddl(&nested, "Access"), only_owner(&nested, "OICI"));
    }

    /// The entry has to reach what is created in the directory, or the file the launcher actually
    /// writes its secrets into would be the one thing left wide.
    #[cfg(windows)]
    #[test]
    fn the_store_inherits_the_directory_s_one_entry() {
        let dir = temp_dir();
        let wide = dir.path().join("wide");
        std::fs::create_dir(&wide).expect("mkdir");
        grant_everyone(&wide, "(OI)(CI)F");
        let path = wide.join("nested").join("store.apsf");

        private_dir(&path).expect("directory");
        publish(&path, &vec![5u8; super::super::frame::MIN_FILE]).expect("publish");

        let owner = sddl(&path, "Owner");
        let sid = owner.strip_prefix("O:").unwrap_or(&owner);
        // `ID` marks the entry inherited, which is the point: nothing set it on the file. The file
        // itself is not protected, only auto-inherited, because protection is the directory's.
        assert_eq!(sddl(&path, "Access"), format!("D:AI(A;ID;FA;;;{sid})"));
    }

    /// A store restored with explicit entries of its own carries them into a directory whose
    /// inheritance never gets to override them, so the file is narrowed as well as the directory.
    #[cfg(windows)]
    #[test]
    fn a_store_file_left_wider_is_narrowed() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        publish(&path, &vec![6u8; super::super::frame::MIN_FILE]).expect("publish");
        grant_everyone(&path, "F");
        assert!(
            sddl(&path, "Access").contains(";WD)"),
            "the seeding did not widen the store"
        );

        narrow_file(&path);

        assert_eq!(sddl(&path, "Access"), only_owner(&path, ""));
    }

    /// `publish` replaces the store by rename, and a rename over a file carrying the read-only
    /// attribute fails with access denied every time, so a restore, read-only media or one
    /// `attrib +R` left every write answering `Denied` for good while reads went on working.
    #[cfg(windows)]
    #[test]
    fn a_read_only_store_can_be_written_again() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        let bytes = vec![7u8; super::super::frame::MIN_FILE];
        publish(&path, &bytes).expect("publish");
        set_readonly(&path, true);

        narrow_file(&path);

        publish(&path, &bytes).expect("publish over a store that was read-only");
    }

    /// The delete side of the same condition, which needs nothing from this crate: the standard
    /// library clears the attribute itself before removing a file here. Pinned rather than assumed,
    /// because the repair above would otherwise look like it owed this one too.
    #[cfg(windows)]
    #[test]
    fn a_read_only_store_deletes_without_help() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        publish(&path, &vec![8u8; super::super::frame::MIN_FILE]).expect("publish");
        set_readonly(&path, true);

        assert!(remove(&path).expect("remove a read-only store"));
    }

    /// Applying it twice is applying it once: the second call finds the entry it wants already
    /// there and writes nothing, which is what every call after the first does on a healthy store.
    #[cfg(windows)]
    #[test]
    fn narrowing_a_directory_twice_lands_on_the_same_list() {
        let dir = temp_dir();
        let path = dir.path().join("nested").join("store.apsf");

        private_dir(&path).expect("directory");
        let once = sddl(path.parent().expect("parent"), "Access");
        private_dir(&path).expect("directory again");

        assert_eq!(sddl(path.parent().expect("parent"), "Access"), once);
    }

    /// The guard that keeps this off a volume root, pinned on the decision rather than on a `C:\`
    /// this must never actually write to. Re-permissioning a drive root is damage and not repair,
    /// and nothing ships a store at one.
    #[cfg(windows)]
    #[test]
    fn a_volume_root_is_not_a_directory_this_narrows() {
        for root in [r"C:\", r"\\server\share", r"\\?\C:\"] {
            assert!(is_root(Path::new(root)), "{root} should be left alone");
        }
        for inside in [r"C:\apogee", r"C:\apogee\secrets", "relative"] {
            assert!(!is_root(Path::new(inside)), "{inside} should be narrowed");
        }
    }
}
