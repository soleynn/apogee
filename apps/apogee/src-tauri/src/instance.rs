//! Linux single-instance ownership and activation forwarding.
//!
//! The desktop owns a file lock rather than a session-bus name. A later process sends one bounded
//! datagram to the owner and exits, while a renderer re-exec carries the already-held descriptor
//! forward so there is no ownership gap.

use std::ffi::OsString;
use std::process::ExitCode;

use thiserror::Error;

#[cfg(target_os = "linux")]
const INHERITED_FD_ENV: &str = "APOGEE_INSTANCE_FD";

pub(crate) enum InstancePreflight {
    Continue(InstanceGuard),
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Exit(ExitCode),
}

pub(crate) struct InstanceGuard {
    #[cfg(target_os = "linux")]
    inner: Option<linux::LinuxGuard>,
}

impl InstanceGuard {
    pub(crate) fn reexec_environment(&self) -> Option<(&'static str, OsString)> {
        #[cfg(target_os = "linux")]
        {
            self.inner.as_ref().map(|guard| {
                (
                    INHERITED_FD_ENV,
                    OsString::from(guard.inherited_fd().to_string()),
                )
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub(crate) fn start(&self, app: tauri::AppHandle) -> Result<(), InstanceError> {
        #[cfg(target_os = "linux")]
        if let Some(guard) = &self.inner {
            return guard.start(app);
        }

        #[cfg(not(target_os = "linux"))]
        let _ = app;

        Ok(())
    }

    fn disabled() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            inner: None,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum InstanceError {
    #[cfg(target_os = "linux")]
    #[error("XDG_RUNTIME_DIR is unavailable")]
    RuntimeDirectoryUnavailable,
    #[cfg(target_os = "linux")]
    #[error("the inherited instance descriptor is invalid")]
    InvalidInheritedDescriptor,
    #[cfg(target_os = "linux")]
    #[error("the instance socket path is occupied by something other than a socket: {path}")]
    UnexpectedSocketEntry { path: std::path::PathBuf },
    #[cfg(target_os = "linux")]
    #[error("could not {operation} {path}")]
    Io {
        operation: &'static str,
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("could not encode the instance activation message")]
    Encode(#[source] serde_json::Error),
    #[cfg(target_os = "linux")]
    #[error("the running instance did not accept the activation message")]
    ActivationUnavailable(#[source] std::io::Error),
}

pub(crate) fn preflight() -> Result<InstancePreflight, InstanceError> {
    if std::env::args_os().any(|argument| argument == "--render-report") {
        return Ok(InstancePreflight::Continue(InstanceGuard::disabled()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::preflight()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(InstancePreflight::Continue(InstanceGuard::disabled()))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File};
    use std::io;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use gtk::prelude::GtkWindowExt;
    use rustix::fs::{FlockOperation, Mode, OFlags};
    use rustix::io::FdFlags;
    use serde::{Deserialize, Serialize};
    use tauri::{Emitter, Manager, UserAttentionType};

    use super::{INHERITED_FD_ENV, InstanceError, InstanceGuard, InstancePreflight};

    const LOCK_NAME: &str = "apogee.lock";
    const SOCKET_NAME: &str = "apogee.sock";
    const ATTENTION_EVENT: &str = "instance-attention-requested";
    const MAX_DATAGRAM_BYTES: usize = 4_096;
    const MAX_TOKEN_BYTES: usize = 1_024;
    const FORWARD_ATTEMPTS: usize = 50;
    const FORWARD_RETRY_DELAY: Duration = Duration::from_millis(20);
    const LISTENER_POLL: Duration = Duration::from_millis(100);

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ActivationPayload {
        activation_token: Option<String>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
    }

    impl FileIdentity {
        fn read(path: &Path) -> io::Result<Self> {
            let metadata = fs::metadata(path)?;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
    }

    #[derive(Clone, Debug)]
    struct InstancePaths {
        lock: PathBuf,
        socket: PathBuf,
    }

    impl InstancePaths {
        fn from_runtime_dir(runtime_dir: PathBuf) -> Self {
            Self {
                lock: runtime_dir.join(LOCK_NAME),
                socket: runtime_dir.join(SOCKET_NAME),
            }
        }
    }

    pub(super) struct LinuxGuard {
        // The first process owns this value. A re-exec child instead keeps the inherited raw
        // descriptor open for the remainder of the process; reconstructing ownership would require
        // unsafe code and is unnecessary.
        _lock_file: Option<File>,
        inherited_fd: RawFd,
        socket: UnixDatagram,
        socket_path: PathBuf,
        socket_identity: FileIdentity,
        running: Arc<AtomicBool>,
        started: AtomicBool,
        listener: Mutex<Option<JoinHandle<()>>>,
    }

    impl LinuxGuard {
        pub(super) fn inherited_fd(&self) -> RawFd {
            self.inherited_fd
        }

        pub(super) fn start(&self, app: tauri::AppHandle) -> Result<(), InstanceError> {
            if self
                .started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Ok(());
            }

            let listener = match self.socket.try_clone() {
                Ok(listener) => listener,
                Err(source) => {
                    self.started.store(false, Ordering::Release);
                    return Err(io_error(
                        "clone the instance socket",
                        &self.socket_path,
                        source,
                    ));
                }
            };
            if let Err(source) = listener.set_read_timeout(Some(LISTENER_POLL)) {
                self.started.store(false, Ordering::Release);
                return Err(io_error(
                    "set the instance socket timeout",
                    &self.socket_path,
                    source,
                ));
            }

            self.running.store(true, Ordering::Release);
            let running = Arc::clone(&self.running);
            let handle = match thread::Builder::new()
                .name("instance-activation".to_owned())
                .spawn(move || listen(listener, running, app))
            {
                Ok(handle) => handle,
                Err(source) => {
                    self.running.store(false, Ordering::Release);
                    self.started.store(false, Ordering::Release);
                    return Err(io_error(
                        "start the instance listener",
                        &self.socket_path,
                        source,
                    ));
                }
            };

            let mut slot = match self.listener.lock() {
                Ok(slot) => slot,
                Err(poisoned) => poisoned.into_inner(),
            };
            *slot = Some(handle);
            Ok(())
        }
    }

    impl Drop for LinuxGuard {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Release);
            let listener = match self.listener.get_mut() {
                Ok(listener) => listener,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(handle) = listener.take() {
                let _ = handle.join();
            }

            if FileIdentity::read(&self.socket_path).ok() == Some(self.socket_identity) {
                let _ = fs::remove_file(&self.socket_path);
            }
        }
    }

    pub(super) fn preflight() -> Result<InstancePreflight, InstanceError> {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|directory| !directory.is_empty())
            .map(PathBuf::from)
            .ok_or(InstanceError::RuntimeDirectoryUnavailable)?;
        let paths = InstancePaths::from_runtime_dir(runtime_dir);
        let inherited = std::env::var_os(INHERITED_FD_ENV);
        preflight_at(&paths, inherited, activation_from_environment())
    }

    fn preflight_at(
        paths: &InstancePaths,
        inherited: Option<std::ffi::OsString>,
        activation: ActivationPayload,
    ) -> Result<InstancePreflight, InstanceError> {
        if let Some(raw_fd) = inherited {
            let inherited_fd = parse_inherited_fd(&raw_fd)?;
            validate_inherited_fd(&paths.lock, inherited_fd)?;
            let guard = bind_owner(paths, None, inherited_fd)?;
            return Ok(InstancePreflight::Continue(InstanceGuard {
                inner: Some(guard),
            }));
        }

        let owned_fd = rustix::fs::open(
            &paths.lock,
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| {
            io_error(
                "open the instance lock",
                &paths.lock,
                io::Error::from(source),
            )
        })?;
        let lock_file = File::from(owned_fd);
        match rustix::fs::flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                rustix::io::fcntl_setfd(&lock_file, FdFlags::empty()).map_err(|source| {
                    io_error(
                        "make the instance lock inheritable",
                        &paths.lock,
                        io::Error::from(source),
                    )
                })?;
                let inherited_fd = lock_file.as_raw_fd();
                let guard = bind_owner(paths, Some(lock_file), inherited_fd)?;
                Ok(InstancePreflight::Continue(InstanceGuard {
                    inner: Some(guard),
                }))
            }
            Err(source)
                if source == rustix::io::Errno::AGAIN
                    || source == rustix::io::Errno::WOULDBLOCK =>
            {
                forward_with_retry(
                    &paths.socket,
                    &encode_activation(&activation)?,
                    FORWARD_ATTEMPTS,
                    FORWARD_RETRY_DELAY,
                )?;
                Ok(InstancePreflight::Exit(ExitCode::SUCCESS))
            }
            Err(source) => Err(io_error(
                "lock the instance file",
                &paths.lock,
                io::Error::from(source),
            )),
        }
    }

    fn bind_owner(
        paths: &InstancePaths,
        lock_file: Option<File>,
        inherited_fd: RawFd,
    ) -> Result<LinuxGuard, InstanceError> {
        remove_stale_socket(&paths.socket)?;
        let socket = UnixDatagram::bind(&paths.socket)
            .map_err(|source| io_error("bind the instance socket", &paths.socket, source))?;
        if let Err(source) = fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&paths.socket);
            return Err(io_error(
                "protect the instance socket",
                &paths.socket,
                source,
            ));
        }
        let socket_identity = FileIdentity::read(&paths.socket)
            .map_err(|source| io_error("inspect the instance socket", &paths.socket, source))?;

        Ok(LinuxGuard {
            _lock_file: lock_file,
            inherited_fd,
            socket,
            socket_path: paths.socket.clone(),
            socket_identity,
            running: Arc::new(AtomicBool::new(false)),
            started: AtomicBool::new(false),
            listener: Mutex::new(None),
        })
    }

    fn remove_stale_socket(path: &Path) -> Result<(), InstanceError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)
                .map_err(|source| io_error("remove the stale instance socket", path, source)),
            Ok(_) => Err(InstanceError::UnexpectedSocketEntry {
                path: path.to_path_buf(),
            }),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error("inspect the instance socket", path, source)),
        }
    }

    fn parse_inherited_fd(raw_fd: &std::ffi::OsStr) -> Result<RawFd, InstanceError> {
        raw_fd
            .to_str()
            .and_then(|fd| fd.parse::<RawFd>().ok())
            .filter(|fd| *fd >= 0)
            .ok_or(InstanceError::InvalidInheritedDescriptor)
    }

    fn validate_inherited_fd(lock_path: &Path, inherited_fd: RawFd) -> Result<(), InstanceError> {
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{inherited_fd}"));
        let descriptor = FileIdentity::read(&descriptor_path)
            .map_err(|_| InstanceError::InvalidInheritedDescriptor)?;
        let lock =
            FileIdentity::read(lock_path).map_err(|_| InstanceError::InvalidInheritedDescriptor)?;
        if descriptor != lock {
            return Err(InstanceError::InvalidInheritedDescriptor);
        }
        Ok(())
    }

    fn activation_from_environment() -> ActivationPayload {
        let xdg = std::env::var_os("XDG_ACTIVATION_TOKEN");
        let desktop = std::env::var_os("DESKTOP_STARTUP_ID");
        activation_from_values(xdg, desktop)
    }

    fn activation_from_values(
        xdg: Option<std::ffi::OsString>,
        desktop: Option<std::ffi::OsString>,
    ) -> ActivationPayload {
        let activation_token = [xdg, desktop]
            .into_iter()
            .flatten()
            .filter_map(|value| value.into_string().ok())
            .find(|value| valid_token(value));
        ActivationPayload { activation_token }
    }

    fn valid_token(token: &str) -> bool {
        !token.is_empty() && token.len() <= MAX_TOKEN_BYTES && !token.contains('\0')
    }

    fn encode_activation(payload: &ActivationPayload) -> Result<Vec<u8>, InstanceError> {
        let encoded = serde_json::to_vec(payload).map_err(InstanceError::Encode)?;
        if encoded.len() <= MAX_DATAGRAM_BYTES {
            return Ok(encoded);
        }

        serde_json::to_vec(&ActivationPayload {
            activation_token: None,
        })
        .map_err(InstanceError::Encode)
    }

    fn decode_activation(bytes: &[u8]) -> Option<ActivationPayload> {
        if bytes.len() > MAX_DATAGRAM_BYTES {
            return None;
        }
        serde_json::from_slice::<ActivationPayload>(bytes)
            .ok()
            .filter(|payload| payload.activation_token.as_deref().is_none_or(valid_token))
    }

    fn forward_with_retry(
        socket_path: &Path,
        payload: &[u8],
        attempts: usize,
        retry_delay: Duration,
    ) -> Result<(), InstanceError> {
        let sender = UnixDatagram::unbound().map_err(InstanceError::ActivationUnavailable)?;
        let mut last_error = None;
        for attempt in 0..attempts {
            match sender.send_to(payload, socket_path) {
                Ok(sent) if sent == payload.len() => return Ok(()),
                Ok(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the activation datagram was incomplete",
                    ));
                }
                Err(source) => last_error = Some(source),
            }
            if attempt + 1 < attempts {
                thread::sleep(retry_delay);
            }
        }
        Err(InstanceError::ActivationUnavailable(
            last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no forwarding attempts")
            }),
        ))
    }

    fn listen(socket: UnixDatagram, running: Arc<AtomicBool>, app: tauri::AppHandle) {
        let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];
        while running.load(Ordering::Acquire) {
            match socket.recv(&mut buffer) {
                Ok(received) => {
                    let Some(payload) = decode_activation(&buffer[..received]) else {
                        continue;
                    };
                    let app = app.clone();
                    if let Err(error) = app.clone().run_on_main_thread(move || {
                        present(&app, payload.activation_token.as_deref());
                    }) {
                        tracing::warn!(%error, "could not schedule instance activation");
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => {
                    tracing::warn!(%error, "instance activation listener stopped");
                    break;
                }
            }
        }
    }

    fn present(app: &tauri::AppHandle, activation_token: Option<&str>) {
        let Some(window) = app.get_webview_window("main") else {
            tracing::warn!("instance activation arrived before the main window existed");
            return;
        };

        if let Some(token) = activation_token {
            match window.gtk_window() {
                Ok(native) => {
                    native.set_startup_id(token);
                    native.present();
                }
                Err(error) => {
                    tracing::warn!(%error, "could not present the main window with its activation token");
                }
            }
            return;
        }

        if let Err(error) = window.request_user_attention(Some(UserAttentionType::Critical)) {
            tracing::warn!(%error, "could not request attention for the main window");
        }
        if let Err(error) = window.emit(ATTENTION_EVENT, ()) {
            tracing::warn!(%error, "could not publish the instance attention request");
        }
    }

    fn io_error(operation: &'static str, path: &Path, source: io::Error) -> InstanceError {
        InstanceError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::error::Error;
        use std::ffi::OsString;

        use tempfile::TempDir;

        use super::*;

        type TestResult = Result<(), Box<dyn Error>>;

        #[test]
        fn xdg_activation_token_takes_precedence() {
            let payload = activation_from_values(
                Some(OsString::from("xdg-token")),
                Some(OsString::from("desktop-token")),
            );
            assert_eq!(payload.activation_token.as_deref(), Some("xdg-token"));
        }

        #[test]
        fn desktop_startup_id_is_the_fallback() {
            let payload = activation_from_values(None, Some(OsString::from("desktop-token")));
            assert_eq!(payload.activation_token.as_deref(), Some("desktop-token"));
        }

        #[test]
        fn invalid_tokens_become_an_attention_only_message() -> TestResult {
            let payload =
                activation_from_values(Some(OsString::from("x".repeat(MAX_TOKEN_BYTES + 1))), None);
            assert_eq!(payload.activation_token, None);
            let encoded = encode_activation(&payload)?;
            assert!(encoded.len() <= MAX_DATAGRAM_BYTES);
            assert_eq!(decode_activation(&encoded), Some(payload));
            Ok(())
        }

        #[test]
        fn decoder_rejects_oversized_or_unexpected_input() {
            assert_eq!(decode_activation(&vec![b'x'; MAX_DATAGRAM_BYTES + 1]), None);
            assert_eq!(
                decode_activation(br#"{"activationToken":null,"path":"/tmp"}"#),
                None
            );
            assert_eq!(decode_activation(b"not-json"), None);
        }

        #[test]
        fn owner_holds_the_lock_and_later_launch_forwards_exact_payload() -> TestResult {
            let temporary = TempDir::new()?;
            let paths = InstancePaths::from_runtime_dir(temporary.path().to_path_buf());
            let first = preflight_at(
                &paths,
                None,
                ActivationPayload {
                    activation_token: None,
                },
            )?;
            let InstancePreflight::Continue(first) = first else {
                return Err(io::Error::other("the first launch did not own the instance").into());
            };

            let expected = ActivationPayload {
                activation_token: Some("activation-token".to_owned()),
            };
            let second = preflight_at(&paths, None, expected.clone())?;
            assert!(matches!(second, InstancePreflight::Exit(code) if code == ExitCode::SUCCESS));

            let guard = first
                .inner
                .as_ref()
                .ok_or_else(|| io::Error::other("the Linux guard is absent"))?;
            guard
                .socket
                .set_read_timeout(Some(Duration::from_secs(1)))?;
            let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];
            let received = guard.socket.recv(&mut buffer)?;
            assert_eq!(decode_activation(&buffer[..received]), Some(expected));
            assert!(paths.socket.exists());
            Ok(())
        }

        #[test]
        fn forwarding_retries_while_a_reexec_rebinds_the_socket() -> TestResult {
            let temporary = TempDir::new()?;
            let socket_path = temporary.path().join(SOCKET_NAME);
            let payload = br#"{"activationToken":"token"}"#.to_vec();
            let receiver_path = socket_path.clone();
            let receiver = thread::spawn(move || -> io::Result<Vec<u8>> {
                thread::sleep(Duration::from_millis(40));
                let socket = UnixDatagram::bind(receiver_path)?;
                socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];
                let received = socket.recv(&mut buffer)?;
                Ok(buffer[..received].to_vec())
            });

            forward_with_retry(
                &socket_path,
                &payload,
                FORWARD_ATTEMPTS,
                FORWARD_RETRY_DELAY,
            )?;
            let received = receiver
                .join()
                .map_err(|_| io::Error::other("the delayed receiver stopped unexpectedly"))??;
            assert_eq!(received, payload);
            Ok(())
        }

        #[test]
        fn inherited_descriptor_must_identify_the_lock_file() -> TestResult {
            let temporary = TempDir::new()?;
            let paths = InstancePaths::from_runtime_dir(temporary.path().to_path_buf());
            let first = preflight_at(
                &paths,
                None,
                ActivationPayload {
                    activation_token: None,
                },
            )?;
            let InstancePreflight::Continue(first) = first else {
                return Err(io::Error::other("the first launch did not own the instance").into());
            };
            let guard = first
                .inner
                .as_ref()
                .ok_or_else(|| io::Error::other("the Linux guard is absent"))?;
            assert!(validate_inherited_fd(&paths.lock, guard.inherited_fd()).is_ok());

            let other = temporary.path().join("other");
            fs::write(&other, b"other")?;
            assert!(validate_inherited_fd(&other, guard.inherited_fd()).is_err());
            Ok(())
        }

        #[test]
        fn stale_socket_is_removed_only_after_lock_ownership() -> TestResult {
            let temporary = TempDir::new()?;
            let paths = InstancePaths::from_runtime_dir(temporary.path().to_path_buf());
            let stale = UnixDatagram::bind(&paths.socket)?;
            drop(stale);

            let first = preflight_at(
                &paths,
                None,
                ActivationPayload {
                    activation_token: None,
                },
            )?;
            let InstancePreflight::Continue(first) = first else {
                return Err(io::Error::other("the first launch did not own the instance").into());
            };
            assert!(paths.socket.exists());

            let second = preflight_at(
                &paths,
                None,
                ActivationPayload {
                    activation_token: None,
                },
            )?;
            assert!(matches!(second, InstancePreflight::Exit(_)));
            assert!(paths.socket.exists());
            drop(first);
            assert!(!paths.socket.exists());
            Ok(())
        }

        #[test]
        fn a_regular_file_never_gets_deleted_as_a_stale_socket() -> TestResult {
            let temporary = TempDir::new()?;
            let paths = InstancePaths::from_runtime_dir(temporary.path().to_path_buf());
            fs::write(&paths.socket, b"keep")?;
            let result = preflight_at(
                &paths,
                None,
                ActivationPayload {
                    activation_token: None,
                },
            );
            assert!(matches!(
                result,
                Err(InstanceError::UnexpectedSocketEntry { .. })
            ));
            assert_eq!(fs::read(&paths.socket)?, b"keep");
            Ok(())
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_is_a_no_op() {
        let guard = InstanceGuard::disabled();
        assert!(guard.reexec_environment().is_none());
    }
}
