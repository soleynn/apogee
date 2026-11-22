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

use apogee_fetch::{DigestPin, HexPins};
use url::Url;

use super::wire::HashManifest;
use crate::backup::confine::{RejectReason, relative_parts};

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

/// Resolve one manifest key against `root`, or say why the key may not be resolved at all.
///
/// The keys are Windows-shaped, because the tree they describe is. A backslash is an ordinary character
/// on Linux, so without folding it the whole key would arrive as a single filename that exists nowhere
/// and every file would read as missing.
///
/// A key is the distribution's claim about where a file is, and the distribution is not trusted to
/// keep it below `root`: a key that is rooted, climbs out with `..`, carries a drive letter, or names
/// something the prefix would reinterpret is refused under the same rules a restored archive entry
/// is. Refused rather than skipped, because a map that names a file outside its own tree is not a map
/// of that tree.
pub(crate) fn resolve(root: &Path, key: &str) -> Result<PathBuf, RejectReason> {
    let mut path = root.to_path_buf();
    path.extend(relative_parts(key)?);
    Ok(path)
}

/// The sha256 a content-addressed URL names, when it names one: a last path segment that is exactly
/// 64 hex digits, as the distribution's file host serves every download it hands out.
///
/// A URL shaped any other way names nothing, and the download is checked by what the distribution
/// publishes beside it instead.
pub(crate) fn content_address(url: &Url) -> Option<[u8; 32]> {
    let last = url.path_segments()?.next_back()?;
    match DigestPin::from_hex(HexPins {
        blake3: None,
        sha256: Some(last),
    })? {
        DigestPin::Sha256(digest) => Some(digest),
        _ => None,
    }
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
    /// A key the map names is not a place below the tree at all.
    Unsafe { key: String, reason: RejectReason },
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
        let file = match resolve(root, key) {
            Ok(file) => file,
            Err(reason) => {
                return Some(TreeFault::Unsafe {
                    key: key.clone(),
                    reason,
                });
            }
        };
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
pub const REQUIRED: &[&str] = &["Dalamud.Injector.exe", "Dalamud.dll", "ImGuiScene.dll"];

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

    /// A key is a claim about where a file is below the tree, and one that would put it anywhere else
    /// is refused before the filesystem is asked about it, in either separator and in every spelling
    /// a Windows reader would honour.
    #[test]
    fn a_key_that_leaves_the_tree_is_refused() {
        let root = Path::new("/srv/dalamud/Hooks/1.0");
        for (key, reason) in [
            ("..", RejectReason::Traversal),
            (r"..\..\..\.bashrc", RejectReason::Traversal),
            ("sub/../../escape.dll", RejectReason::Traversal),
            ("/etc/passwd", RejectReason::Absolute),
            (r"\Windows\System32\x.dll", RejectReason::Absolute),
            (r"C:\Windows\x.dll", RejectReason::DriveLetter),
            ("C:", RejectReason::DriveLetter),
            ("sub/thing.dll:stream", RejectReason::WindowsHostile),
            ("sub/CON.dll", RejectReason::WindowsHostile),
            ("sub/thing.dll.", RejectReason::WindowsHostile),
            ("sub/\0thing.dll", RejectReason::WindowsHostile),
            ("", RejectReason::Empty),
            (r".\\", RejectReason::Empty),
        ] {
            assert_eq!(resolve(root, key), Err(reason), "{key:?}");
        }
        assert_eq!(
            resolve(root, r".\sub\\thing.dll"),
            Ok(root.join("sub/thing.dll")),
            "a current-directory step and a doubled separator name nothing outside"
        );
    }

    /// A refused key fails the tree as an unsafe key rather than reading as a missing file: nothing
    /// was opened, so there is no filesystem answer to report.
    #[test]
    fn a_map_naming_a_file_outside_its_tree_fails_it_without_opening_anything() {
        let (tmp, root) = tree();
        // A real file at the place the key points, with the digest the map claims for it: following
        // the key would find it and call the tree intact.
        std::fs::write(tmp.path().join("outside.dll"), b"payload").expect("write");
        let digest = payload_md5(&root);
        let mut map = manifest(r"sub\thing.dll", &digest);
        map.insert(r"..\..\outside.dll".to_owned(), digest);
        let fault = first_fault(&root, &map, Digest::Md5).expect("the escaping key is a fault");
        assert!(
            matches!(&fault, TreeFault::Unsafe { key, reason: RejectReason::Traversal }
                if key == r"..\..\outside.dll"),
            "{fault:?}"
        );
    }

    /// The distribution's file host addresses every download by the sha256 of its bytes, in the last
    /// path segment. Only that exact shape names a digest; anything near it names nothing, so a URL
    /// that merely looks hashed is never held to a digest it does not carry.
    #[test]
    fn only_a_last_segment_of_exactly_64_hex_digits_is_a_content_address() {
        let hex = "3f0d8b64d2ed7c868b57541c81f5308692eb69bb856517fa3d14955fd056e815";
        let url = |raw: &str| Url::parse(raw).expect("url");
        let digest = content_address(&url(&format!("https://kamori.goats.dev/File/Get/{hex}")))
            .expect("a content address");
        assert_eq!(digest[0], 0x3f);
        assert_eq!(digest[31], 0x15);
        assert_eq!(
            content_address(&url(&format!(
                "https://h.example/File/Get/{}",
                hex.to_uppercase()
            ))),
            Some(digest),
            "case does not change the digest"
        );
        assert_eq!(
            content_address(&url(&format!("https://h.example/File/Get/{hex}?x=1"))),
            Some(digest),
            "a query is not part of the path"
        );
        for raw in [
            format!("https://h.example/File/Get/{hex}/"),
            format!("https://h.example/{hex}/latest.zip"),
            format!("https://h.example/File/Get/{}", &hex[..63]),
            format!("https://h.example/File/Get/{hex}0"),
            format!("https://h.example/File/Get/{}g", &hex[..63]),
            format!("https://h.example/File/Get/{hex}.zip"),
            "https://h.example/Dalamud/Release/Runtime/DotNet/10.0.14".to_owned(),
            "https://h.example".to_owned(),
        ] {
            assert_eq!(content_address(&url(&raw)), None, "{raw}");
        }
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
