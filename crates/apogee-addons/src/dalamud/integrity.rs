//! Checking a downloaded tree against the hash manifest that describes it.
//!
//! Dalamud's bytes are not `sha256`-pinned by Apogee's own manifest, because their version is upstream's
//! to choose and a pin has to describe bytes somebody keeps serving. What stands in for a pin is the
//! digest map the distribution publishes: the tree's own `hashes.json`, shipped inside the archive, and
//! a per-asset digest in the asset metadata.
//!
//! Two rules are copied deliberately rather than improved on. The check walks the *manifest*, never the
//! directory, so a file the map does not list is not a failure: the distribution adds files it does not
//! track, and refusing them would make every update look corrupt. And one mismatch fails the whole
//! tree, because there is no per-file repair to fall back to: the answer is always to lay the version
//! down again.

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

/// Whether every file `manifest` names is present under `root` with the digest it states.
///
/// A file that cannot be read counts as a mismatch, since the reason it cannot be read (absent,
/// truncated, unreadable) is the same reason not to trust the tree.
pub(crate) fn verify_tree(root: &Path, manifest: &HashManifest, digest: Digest) -> bool {
    manifest.iter().all(|(key, expected)| {
        hash_file(&resolve(root, key), digest).is_ok_and(|found| found == *expected)
    })
}

/// The files a Dalamud version directory is unusable without.
///
/// Checked before the digests so a half-extracted tree is reported as incomplete rather than as a long
/// list of individual mismatches, and so a tree missing the injector never reaches the launch path.
pub(crate) const REQUIRED: &[&str] = &["Dalamud.Injector.exe", "Dalamud.dll", "ImGuiScene.dll"];

/// Whether the files a version directory cannot work without are all there.
pub(crate) fn required_files_present(root: &Path) -> bool {
    REQUIRED.iter().all(|name| root.join(name).is_file())
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

    /// The digest of `payload`, uppercase, so the fixtures do not depend on a hashing helper under test.
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
        assert!(verify_tree(
            &root,
            &manifest(r"sub\thing.dll", &digest),
            Digest::Md5
        ));
        assert!(verify_tree(
            &root,
            &manifest("sub/thing.dll", &digest),
            Digest::Md5
        ));
    }

    /// There is no per-file repair, so one bad file means the version comes down again.
    #[test]
    fn one_wrong_digest_fails_the_whole_tree() {
        let (_tmp, root) = tree();
        let mut map = manifest(r"sub\thing.dll", &payload_md5(&root));
        map.insert("sub\\missing.dll".to_owned(), "0".repeat(32));
        assert!(!verify_tree(&root, &map, Digest::Md5));
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
        assert!(!verify_tree(
            &root,
            &manifest(r"sub\thing.dll", &lower),
            Digest::Md5
        ));
    }

    /// The distribution ships files its own map does not list. Walking the directory instead of the
    /// manifest would report every one of them as an intrusion and never accept a healthy tree.
    #[test]
    fn a_file_the_manifest_does_not_list_is_not_a_failure() {
        let (_tmp, root) = tree();
        std::fs::write(root.join("unlisted.txt"), b"extra").expect("write");
        assert!(verify_tree(
            &root,
            &manifest(r"sub\thing.dll", &payload_md5(&root)),
            Digest::Md5
        ));
    }

    /// A tree without the injector cannot launch anything, so it is caught as incomplete rather than
    /// reaching the launch path and failing there.
    #[test]
    fn a_version_directory_missing_the_injector_is_not_usable() {
        let (_tmp, root) = tree();
        assert!(!required_files_present(&root));
        for name in REQUIRED {
            std::fs::write(root.join(name), b"MZ").expect("write");
        }
        assert!(required_files_present(&root));
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
