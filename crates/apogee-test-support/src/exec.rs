//! Writing a fake executable that a test then runs, without the run failing "Text file busy".
//!
//! Tests in one binary run on parallel threads, and on Unix a spawn is a fork followed by an exec.
//! A file this process holds open for writing is inherited by every child another thread forks in
//! that moment, and stays open in the child until the child execs. Exec'ing the file during that
//! window fails with `ETXTBSY`, even after this process has closed its own descriptor. Close-on-exec
//! does not help, because the descriptor only closes at the child's exec. Writing under a temporary
//! name and renaming does not help either: the descriptor belongs to the inode, not the name.
//!
//! So the inode that will be exec'd is never opened for writing in this process. The contents go to
//! a staging file that is never run, and a short-lived `cp` creates the executable from it. The only
//! write descriptor to the executable then lives in that child, which has exited by the time this
//! returns.

use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Create (or replace) `path` with `contents` and mode `0o755`, in a way a concurrent spawn on
/// another test thread cannot leave busy. The parent directory must exist.
pub fn write_executable(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let mut staged = tempfile::NamedTempFile::new()?;
    staged.write_all(contents.as_ref())?;
    staged.flush()?;
    let status = Command::new("cp")
        .arg("--")
        .arg(staged.path())
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "cp onto {} exited with {status}",
            path.display()
        )));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Many threads each write a fresh script and run it straight away, so each write races the
    /// other threads' spawns, which is the interleaving that produced `ETXTBSY`.
    #[test]
    fn scripts_written_while_other_threads_spawn_always_run() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for t in 0..8 {
                let dir = dir.path();
                scope.spawn(move || {
                    for i in 0..50 {
                        let path = dir.join(format!("fake-{t}-{i}"));
                        write_executable(&path, "#!/bin/sh\nexit 0\n").unwrap();
                        let status = Command::new(&path).status().unwrap();
                        assert!(status.success());
                    }
                });
            }
        });
    }

    #[test]
    fn replacing_an_existing_script_takes_the_new_contents_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake");
        std::fs::write(&path, "old").unwrap();
        write_executable(&path, "#!/bin/sh\nexit 3\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "#!/bin/sh\nexit 3\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(Command::new(&path).status().unwrap().code(), Some(3));
    }
}
