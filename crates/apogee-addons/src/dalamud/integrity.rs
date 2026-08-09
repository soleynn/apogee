//! Checking a downloaded tree against the hash manifest that describes it.
//!
//! Dalamud's bytes carry no `sha256` pin of Apogee's own, because their version is upstream's to choose
//! and a pin has to describe bytes somebody keeps serving. What stands in for one is the digest map the
//! distribution publishes: the tree's own `hashes.json`, shipped inside the release archive, and a
//! per-asset digest in the asset metadata.
//!
//! Two of the distribution's rules are copied deliberately rather than improved on. The check walks the
//! *manifest*, never the directory, so a file the map does not list is not a failure: the distribution
//! ships files it does not track, and refusing them would make every update look corrupt. And one
//! mismatch fails the whole tree, because there is no per-file repair to fall back to: the answer is
//! always to lay the version down again.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::wire::HashManifest;

/// Which digest a manifest's values are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Digest {
    /// The Dalamud and runtime trees.
    Md5,
    /// The assets, each carrying its own.
    Sha1,
}

/// How much of a file is read at a time. Assets and runtime libraries reach tens of megabytes, and the
/// whole point of streaming them is that a check never costs the size of the largest file in RAM.
const CHUNK: usize = 64 * 1024;

/// The digest of `path` as uppercase hex, streamed rather than read whole.
pub(crate) fn hash_file(path: &Path, digest: Digest) -> io::Result<String> {
    use md5::Digest as _;

    let mut file = File::open(path)?;
    let mut buf = vec![0u8; CHUNK];
    match digest {
        Digest::Md5 => {
            let mut hasher = md5::Md5::new();
            feed(&mut file, &mut buf, |chunk| hasher.update(chunk))?;
            Ok(hex_upper(&hasher.finalize()))
        }
        Digest::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            feed(&mut file, &mut buf, |chunk| hasher.update(chunk))?;
            Ok(hex_upper(&hasher.finalize()))
        }
    }
}

fn feed(file: &mut File, buf: &mut [u8], mut sink: impl FnMut(&[u8])) -> io::Result<()> {
    loop {
        let read = file.read(buf)?;
        if read == 0 {
            return Ok(());
        }
        sink(&buf[..read]);
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        // Writing into a String cannot fail, and there is nothing sensible to do if it somehow did.
        let _ = write!(out, "{byte:02X}");
    }
    out
}

/// Resolve one manifest key against `root`.
///
/// The keys are Windows-shaped, because the tree they describe is. A backslash is an ordinary character
/// on Linux, so without folding it the whole key would arrive as a single filename that exists nowhere
/// and every file would read as missing.
pub(crate) fn resolve(root: &Path, key: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for part in key.split(['\\', '/']).filter(|part| !part.is_empty()) {
        path.push(part);
    }
    path
}

/// Why a tree is not the tree its digest map describes.
///
/// Both arms name the file, because "it does not match its own hashes" is the part a reader already
/// knows by the time they are reading an error: what they need is which file, and what about it.
#[derive(Debug)]
pub(crate) enum TreeFault {
    /// A file the map names could not be read. Absent, truncated, a directory where a file was
    /// promised: the reason it cannot be read is the same reason not to trust the tree, and the io
    /// error is what says which of those it was.
    Unreadable { file: PathBuf, source: io::Error },
    /// A file the map names is there and carries other bytes.
    Mismatch {
        file: PathBuf,
        expected: String,
        found: String,
    },
}

/// The first file `manifest` names that is not the file it describes, or `None` when every one is.
///
/// One fault rather than all of them, for the reason the module header gives: there is no per-file
/// repair to fall back to, so the first file that proves the tree wrong is the whole of the answer.
pub(crate) fn first_fault(
    root: &Path,
    manifest: &HashManifest,
    digest: Digest,
) -> Option<TreeFault> {
    manifest.iter().find_map(|(key, expected)| {
        let file = resolve(root, key);
        match hash_file(&file, digest) {
            Ok(found) if found == *expected => None,
            Ok(found) => Some(TreeFault::Mismatch {
                file,
                expected: expected.clone(),
                found,
            }),
            Err(source) => Some(TreeFault::Unreadable { file, source }),
        }
    })
}

/// The files a Dalamud version directory is unusable without.
///
/// Checked before the digests so a half-extracted tree is reported as incomplete rather than as a long
/// list of individual mismatches, and so a tree missing the injector never reaches the launch path.
pub(crate) const REQUIRED: &[&str] = &["Dalamud.Injector.exe", "Dalamud.dll", "ImGuiScene.dll"];

/// The first of those files that is not there, or `None` when every one is.
///
/// Opened rather than tested for existence, so the fault carries what the filesystem actually said: a
/// name held by a directory and a name held by nothing are different problems, and the reader of an
/// install failure wants the one that happened.
pub(crate) fn missing_required(root: &Path) -> Option<TreeFault> {
    REQUIRED.iter().find_map(|name| {
        let file = root.join(name);
        File::open(&file)
            .err()
            .map(|source| TreeFault::Unreadable { file, source })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("Hooks/1.0");
        std::fs::create_dir_all(root.join("sub")).expect("mkdir");
        std::fs::write(root.join("sub/thing.dll"), b"payload").expect("write");
        (tmp, root)
    }

    /// The digest of the payload, uppercase, so the fixtures do not depend on a hashing helper the
    /// tests are not exercising.
    fn payload_md5(root: &Path) -> String {
        hash_file(&root.join("sub/thing.dll"), Digest::Md5).expect("hash")
    }

    fn manifest(key: &str, value: &str) -> HashManifest {
        let mut map = HashManifest::new();
        map.insert(key.to_owned(), value.to_owned());
        map
    }

    /// The distribution writes its keys with backslashes. Dropping the fold makes every key resolve to
    /// one filename that exists nowhere, so a perfectly good tree reads as entirely corrupt.
    #[test]
    fn a_key_written_with_windows_separators_resolves_the_same_file() {
        let (_tmp, root) = tree();
        let digest = payload_md5(&root);
        assert!(first_fault(&root, &manifest(r"sub\thing.dll", &digest), Digest::Md5).is_none());
        assert!(first_fault(&root, &manifest("sub/thing.dll", &digest), Digest::Md5).is_none());
    }

    /// There is no per-file repair, so one bad file means the version comes down again.
    #[test]
    fn one_wrong_digest_fails_the_whole_tree() {
        let (_tmp, root) = tree();
        let mut map = manifest(r"sub\thing.dll", &payload_md5(&root));
        map.insert("sub\\missing.dll".to_owned(), "0".repeat(32));
        // And it says which file, with what the read of it said: the caller turns this into the
        // failure a user reads, and "the tree does not match" names nothing to look at.
        let fault = first_fault(&root, &map, Digest::Md5).expect("the missing file is a fault");
        assert!(
            matches!(&fault, TreeFault::Unreadable { file, .. } if file.ends_with("missing.dll")),
            "{fault:?}"
        );
    }

    /// A digest is compared as written, and the distribution writes uppercase. Folding case here would
    /// hide a client that is decoding the hex wrongly.
    #[test]
    fn a_digest_is_compared_exactly_as_the_distribution_wrote_it() {
        let (_tmp, root) = tree();
        let upper = payload_md5(&root);
        assert_eq!(
            upper,
            upper.to_uppercase(),
            "digests are produced uppercase"
        );
        let lower = upper.to_lowercase();
        let fault = first_fault(&root, &manifest(r"sub\thing.dll", &lower), Digest::Md5)
            .expect("a lowercase digest does not match");
        assert!(
            matches!(&fault, TreeFault::Mismatch { expected, found, .. }
                if *expected == lower && *found == upper),
            "the fault carries both digests: {fault:?}"
        );
    }

    /// The distribution ships files its own map does not list. Walking the directory instead of the
    /// manifest would report every one of them as an intrusion and never accept a healthy tree.
    #[test]
    fn a_file_the_manifest_does_not_list_is_not_a_failure() {
        let (_tmp, root) = tree();
        std::fs::write(root.join("unlisted.txt"), b"extra").expect("write");
        assert!(
            first_fault(
                &root,
                &manifest(r"sub\thing.dll", &payload_md5(&root)),
                Digest::Md5
            )
            .is_none()
        );
    }

    /// A tree without the injector cannot launch anything, so it is caught as incomplete rather than
    /// reaching the launch path and failing there.
    #[test]
    fn a_version_directory_missing_the_injector_is_not_usable() {
        let (_tmp, root) = tree();
        assert!(missing_required(&root).is_some());
        for name in REQUIRED {
            std::fs::write(root.join(name), b"MZ").expect("write");
        }
        assert!(missing_required(&root).is_none());
    }

    /// Both digests are the ones the distribution uses, and they are not interchangeable.
    #[test]
    fn the_two_digests_are_the_documented_ones() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("empty");
        std::fs::write(&file, b"").expect("write");
        assert_eq!(
            hash_file(&file, Digest::Md5).expect("md5"),
            "D41D8CD98F00B204E9800998ECF8427E"
        );
        assert_eq!(
            hash_file(&file, Digest::Sha1).expect("sha1"),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
    }
}
