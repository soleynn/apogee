//! Deciding whether the apply needs another process, and driving it when it does.
//!
//! On Linux the answer is always no: game directories live under the user's home. On Windows an
//! install under a system-owned directory is not writable by the user who launched, and the write
//! has to happen somewhere else. What that costs is the verified-before-apply proof, which is a
//! value in this process and cannot travel, so the worker re-derives it (the patch store is
//! writable by the same unprivileged user, and the gap between this process checking a file and a
//! privileged process writing it is exactly where a swap would land).

use std::path::{Path, PathBuf};

use apogee_elevate::{Error as ElevateError, VersionWrite, Worker, WorkerErrorKind};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{PatchError, PatchProgress, PatcherConfig, Repo, store};

/// When the apply runs somewhere other than this process.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Elevation {
    /// Probe the install tree and ask the platform to raise privileges only if it is not writable.
    ///
    /// The probe is a real write into the tree, not a permission calculation: the answer depends on
    /// access-control entries, ownership and the token this process holds, and only the filesystem
    /// knows all three.
    #[default]
    Auto,
    /// Never raise privileges. An unwritable tree fails with the permission error it produced,
    /// which is what a caller that would rather report than prompt wants.
    Never,
    /// Always run the apply in a worker started from `binary`, with this process's own privileges.
    ///
    /// For a caller that has already arranged them, or that ships the worker somewhere other than
    /// beside the launcher.
    Worker {
        /// The worker binary to run.
        binary: PathBuf,
    },
}

/// What one apply is for: the tree, which patch of which repo, and the version it advances to.
///
/// Grouped rather than passed loose because the two executors need exactly the same four values and
/// three of them are easy to transpose at a call site.
pub(crate) struct ApplySlot<'a> {
    /// The install root the repo subtree hangs beneath.
    pub game_root: &'a Path,
    /// Which repository is being installed.
    pub repo: Repo,
    /// The patch's position in the ordered set.
    pub index: u32,
    /// The bare version to write once it applies cleanly.
    pub advance: Option<&'a str>,
}

/// Where the apply for one run happens.
pub(crate) enum Executor {
    /// In this process, as it always does where the tree is writable.
    InProcess,
    /// In a worker. `None` once a fault has consumed it, so its exit status could be read.
    Elevated(Option<Box<Worker>>),
}

impl Executor {
    /// Choose an executor for `apply_root` and, when it is a worker, start it and bind it.
    ///
    /// # Errors
    /// [`PatchError::Worker`] with [`WorkerErrorKind::Spawn`] if a worker is needed and cannot be
    /// started, or [`PatchError::Io`] if the writability probe itself fails for a reason other than
    /// permission.
    pub(crate) async fn open(
        config: &PatcherConfig,
        apply_root: &Path,
    ) -> Result<Self, PatchError> {
        match &config.elevation {
            Elevation::Never => Ok(Self::InProcess),
            Elevation::Worker { binary } => {
                Self::start(apogee_elevate::spawn::direct(binary).await, apply_root).await
            }
            Elevation::Auto => Self::automatic(apply_root).await,
        }
    }

    /// The probe-then-maybe-elevate path.
    #[cfg(windows)]
    async fn automatic(apply_root: &Path) -> Result<Self, PatchError> {
        if probe_writable(apply_root)? {
            return Ok(Self::InProcess);
        }
        let binary = beside_the_launcher()?;
        tracing::info!(
            root = %apply_root.display(),
            worker = %binary.display(),
            "the install tree is not writable; asking for elevation",
        );
        Self::start(apogee_elevate::spawn::elevated(&binary).await, apply_root).await
    }

    /// Off Windows there is nothing to elevate to: the platform has no consent flow this launcher
    /// participates in, and the game directories it installs into are the user's own.
    #[cfg(not(windows))]
    async fn automatic(_apply_root: &Path) -> Result<Self, PatchError> {
        Ok(Self::InProcess)
    }

    /// Bind a freshly started worker to the tree it may write.
    async fn start(
        started: Result<Worker, ElevateError>,
        apply_root: &Path,
    ) -> Result<Self, PatchError> {
        let mut worker = started.map_err(worker_error)?;
        // Absolute because the worker refuses a relative root: an elevated process does not inherit
        // this one's working directory, so a relative path there means something else entirely.
        let root = absolute(apply_root)?;
        worker.session().bind(&root).await.map_err(worker_error)?;
        Ok(Self::Elevated(Some(Box::new(worker))))
    }

    /// Apply one admitted patch, advancing the repo's version file if it lands cleanly.
    pub(crate) async fn apply(
        &mut self,
        admitted: &crate::install::Admitted,
        slot: ApplySlot<'_>,
        progress: &mpsc::UnboundedSender<PatchProgress>,
        cancel: &CancellationToken,
    ) -> Result<(), PatchError> {
        let ApplySlot {
            game_root,
            repo,
            index,
            advance,
        } = slot;
        match self {
            Self::InProcess => {
                crate::install::apply_in_process(
                    admitted, game_root, repo, index, progress, cancel,
                )
                .await?;
                if let Some(version) = advance {
                    store::write_ver(game_root, repo, version)?;
                }
                Ok(())
            }
            Self::Elevated(worker) => {
                let advance = advance.map(|contents| VersionWrite {
                    path: store::ver_rel(repo),
                    contents: contents.to_owned(),
                });
                let patch = absolute(admitted.path())?;
                let admission = admitted.admission().clone();
                let relay = |frame| relay_progress(frame, repo, index, progress);
                let session = Self::live(worker)?;
                let outcome = session
                    .session()
                    .apply(&patch, admission, advance, cancel, relay)
                    .await;
                Self::settle(worker, outcome).await
            }
        }
    }

    /// Copy the repo's version file to its backup, after the whole set applies.
    pub(crate) async fn backup_ver(
        &mut self,
        game_root: &Path,
        repo: Repo,
    ) -> Result<(), PatchError> {
        match self {
            Self::InProcess => store::backup_ver(game_root, repo),
            Self::Elevated(worker) => {
                // The same "nothing to back up" guard the in-process writer keeps. Without it the
                // two arms disagree: a version file that vanished under the run makes this one fail
                // an install whose bytes are all on disk, where the other returns cleanly.
                if !store::ver_path(game_root, repo).exists() {
                    return Ok(());
                }
                let (ver, bck) = (store::ver_rel(repo), store::bck_rel(repo));
                let outcome = Self::live(worker)?.session().copy_within(&ver, &bck).await;
                Self::settle(worker, outcome).await
            }
        }
    }

    /// Close the worker down at the end of a clean run.
    pub(crate) async fn finish(self) {
        if let Self::Elevated(Some(worker)) = self
            && let Some(complaint) = worker.finish().await
        {
            tracing::warn!(detail = %complaint, "the elevated worker did not exit cleanly");
        }
    }

    /// The still-live worker, or the failure that already consumed it.
    fn live(worker: &mut Option<Box<Worker>>) -> Result<&mut Worker, PatchError> {
        worker.as_deref_mut().ok_or_else(|| PatchError::Worker {
            kind: WorkerErrorKind::Protocol,
            failed_file: None,
            detail: "the elevated worker is already gone".to_owned(),
        })
    }

    /// Turn a worker result into the patcher taxonomy, taking the process's exit status along on the
    /// one failure that leaves nothing else behind.
    async fn settle(
        worker: &mut Option<Box<Worker>>,
        outcome: Result<(), ElevateError>,
    ) -> Result<(), PatchError> {
        let Err(err) = outcome else {
            return Ok(());
        };
        // A worker that stopped answering has said all it is going to say over the stream; its exit
        // status is the only detail left, and reading it means consuming the handle.
        if matches!(err, ElevateError::Gone | ElevateError::Frame(_))
            && let Some(worker) = worker.take()
            && let Some(complaint) = worker.finish().await
        {
            return Err(PatchError::Worker {
                kind: WorkerErrorKind::Protocol,
                failed_file: None,
                detail: format!("{err}: {complaint}"),
            });
        }
        Err(worker_error(err))
    }
}

/// Relay one worker progress frame onto the aggregate stream.
///
/// Only the apply phase has a home there. Re-verification is a second full pass over the patch and
/// can take a while on a large one, but the frame that would carry it has no counterpart on the
/// unprivileged path, which runs the same scan for a boot patch and reports nothing either; giving
/// it one belongs with that, not here.
fn relay_progress(
    frame: apogee_elevate::WorkerProgress,
    repo: Repo,
    index: u32,
    progress: &mpsc::UnboundedSender<PatchProgress>,
) {
    match frame {
        apogee_elevate::WorkerProgress::Applying { bytes_done } => {
            let _ = progress.send(PatchProgress::Applying {
                repo,
                index,
                bytes_done,
            });
        }
        apogee_elevate::WorkerProgress::Verifying { bytes_done } => {
            tracing::debug!(bytes_done, "the worker is re-verifying a patch");
        }
    }
}

/// Map a worker failure into the patcher taxonomy.
///
/// Every arm but cancellation lands on [`PatchError::Worker`], which is the point of the variant:
/// a privileged process that dies is a value the caller renders, not something that ends this one.
pub(crate) fn worker_error(err: ElevateError) -> PatchError {
    let worker = |kind, detail: String| PatchError::Worker {
        kind,
        failed_file: None,
        detail,
    };
    match err {
        ElevateError::Cancelled => PatchError::Cancelled,
        ElevateError::Worker {
            kind: WorkerErrorKind::Cancelled,
            ..
        } => PatchError::Cancelled,
        ElevateError::Worker {
            kind,
            failed_file,
            detail,
        } => PatchError::Worker {
            kind,
            failed_file,
            detail,
        },
        ElevateError::Spawn { ref detail, .. } => worker(WorkerErrorKind::Spawn, detail.clone()),
        // The conversation broke rather than the apply: the worker died, spoke out of turn, or the
        // stream failed. One class, because a caller acts the same way on all three.
        ElevateError::Gone | ElevateError::Frame(_) | ElevateError::Protocol { .. } => {
            worker(WorkerErrorKind::Protocol, err.to_string())
        }
    }
}

/// The worker installed beside this executable.
#[cfg(windows)]
fn beside_the_launcher() -> Result<PathBuf, PatchError> {
    /// The name the worker is installed under.
    const WORKER_BINARY: &str = "apogee-elevated.exe";

    let spawn_failed = |detail: String| PatchError::Worker {
        kind: WorkerErrorKind::Spawn,
        failed_file: None,
        detail,
    };
    let me = std::env::current_exe()
        .map_err(|e| spawn_failed(format!("cannot locate this executable: {e}")))?;
    let dir = me
        .parent()
        .ok_or_else(|| spawn_failed(format!("{} has no directory", me.display())))?;
    Ok(dir.join(WORKER_BINARY))
}

/// Make `path` absolute against the working directory, since the worker refuses a relative one.
fn absolute(path: &Path) -> Result<PathBuf, PatchError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::path::absolute(path).map_err(|source| PatchError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Whether this process can create a file in `dir`, or in the nearest ancestor that exists.
///
/// This is what [`Elevation::Auto`] consults, exposed because a front end wants the same answer
/// before it starts: "this install needs administrator rights" is worth saying while the user is
/// still choosing, not after a download. It is a real write, not a permission calculation, because
/// the answer depends on access-control entries, ownership and the token this process holds, and
/// only the filesystem knows all three. Nothing is left behind either way.
///
/// The ancestor walk is what makes a fresh install answerable: the target directory usually does not
/// exist yet, and whether it can be created is a property of its parent.
///
/// # Errors
/// [`PatchError::Io`] if the probe fails for any reason other than permission, which is a real fault
/// rather than an answer.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # fn demo(game_root: &Path) -> Result<bool, apogee_patcher::PatchError> {
/// // True when installing here will ask the user for administrator rights first.
/// let will_prompt = !apogee_patcher::probe_writable(&game_root.join("game"))?;
/// # Ok(will_prompt)
/// # }
/// ```
pub fn probe_writable(dir: &Path) -> Result<bool, PatchError> {
    let existing = dir
        .ancestors()
        .find(|candidate| candidate.exists())
        .unwrap_or(dir);
    // Which probe depends on what the install is about to do there. Inside a directory that already
    // exists it writes files, so a file is what gets tried. Above one that does not, it creates the
    // directory, and those are separate rights on Windows: the default access list on a drive root
    // lets a standard user create folders but not files, so a file probe there answers "elevation
    // required" for an install that would have succeeded unprivileged, and the tree then ends up
    // owned by administrators with every later unprivileged write to it failing.
    let outcome = if existing == dir {
        probe_file(existing)
    } else {
        probe_dir(existing)
    };
    match outcome {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
        Err(source) => Err(PatchError::Io {
            path: existing.to_path_buf(),
            source,
        }),
    }
}

/// A name nothing else will collide with, distinctive enough to recognise if a crash ever strands
/// one.
fn probe_name() -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(".apogee-write-probe-{}-{stamp:x}", std::process::id())
}

/// Create, write and remove one file in `dir`.
///
/// A create alone would answer for a directory that admits new entries but not their contents, and
/// nothing here is left behind on either outcome.
fn probe_file(dir: &Path) -> std::io::Result<()> {
    use std::io::Write;

    let path = dir.join(probe_name());
    let mut file = std::fs::File::create_new(&path)?;
    let written = file.write_all(b"apogee").and_then(|()| file.flush());
    drop(file);
    let removed = std::fs::remove_file(&path);
    written.and(removed)
}

/// Create and remove one subdirectory of `dir`.
fn probe_dir(dir: &Path) -> std::io::Result<()> {
    let path = dir.join(probe_name());
    std::fs::create_dir(&path)?;
    std::fs::remove_dir(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ordinary directory is writable, and the answer for a directory that does not exist yet
    /// comes from the nearest ancestor that does.
    #[test]
    fn the_probe_answers_for_a_directory_and_for_one_not_created_yet() {
        let dir = tempfile::tempdir().unwrap();
        assert!(probe_writable(dir.path()).unwrap());
        assert!(probe_writable(&dir.path().join("game").join("sqpack")).unwrap());
        // Nothing is left behind either way.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// A directory the process cannot write answers false rather than raising, which is the whole
    /// signal the elevation decision reads.
    #[cfg(unix)]
    #[test]
    fn a_directory_this_process_cannot_write_answers_false() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        // Running as root defeats the mode bits entirely, and a container build often does. Asked of
        // a file this test just made rather than of a process API, so it needs no extra dependency.
        let mine = dir.path().join("owner");
        std::fs::write(&mine, b"x").unwrap();
        if std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&mine).unwrap()) == 0 {
            return;
        }
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(!probe_writable(&locked).unwrap());
        assert!(!probe_writable(&locked.join("game")).unwrap());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(probe_writable(&locked).unwrap());
    }

    /// A worker failure keeps its kind and its file, and a cancellation is not dressed up as one.
    ///
    /// This is the mapping the anti-crash behaviour rests on: whatever the privileged side did, the
    /// caller gets a value.
    #[test]
    fn every_worker_failure_maps_to_a_value_the_caller_can_render() {
        let gone = worker_error(ElevateError::Gone);
        assert!(
            matches!(
                gone,
                PatchError::Worker {
                    kind: WorkerErrorKind::Protocol,
                    ..
                }
            ),
            "got {gone:?}"
        );

        let refused = worker_error(ElevateError::Worker {
            kind: WorkerErrorKind::Verify,
            failed_file: Some(PathBuf::from("/store/p0.patch")),
            detail: "block 2 does not match its digest".to_owned(),
        });
        let PatchError::Worker {
            kind: WorkerErrorKind::Verify,
            failed_file: Some(file),
            detail,
        } = &refused
        else {
            panic!("a re-verification failure must keep its kind and file, got {refused:?}");
        };
        assert_eq!(file, Path::new("/store/p0.patch"));
        assert!(detail.contains("block 2"), "{detail}");

        let spawn = worker_error(ElevateError::Spawn {
            detail: "the user declined".to_owned(),
            source: None,
        });
        assert!(
            matches!(
                spawn,
                PatchError::Worker {
                    kind: WorkerErrorKind::Spawn,
                    ..
                }
            ),
            "got {spawn:?}"
        );

        // Cancellation is the one arm that must not arrive as a worker fault: a run the user stopped
        // is re-runnable, and a caller that renders it as a crash would say the opposite.
        assert!(matches!(
            worker_error(ElevateError::Cancelled),
            PatchError::Cancelled
        ));
        assert!(matches!(
            worker_error(ElevateError::Worker {
                kind: WorkerErrorKind::Cancelled,
                failed_file: None,
                detail: String::new(),
            }),
            PatchError::Cancelled
        ));
    }
}
