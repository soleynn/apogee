//! The game-running guard, from both entry points.
//!
//! What is being tested is not that a refusal happens but *when*: before the patch store is created,
//! before an origin is contacted, and before a byte of the install changes. The reference launcher
//! learns the game is running from a sharing violation part way through an apply, which is a report
//! that arrives after some of the work is done and names a file rather than a cause. A guard that
//! refused just as late would be the same behavior with a better error type.
//!
//! So every test here asserts the install tree and the patch store are exactly as they were, and that
//! the origin was never asked for anything. The probe itself is a fake: what a running game looks
//! like on a machine belongs to `apogee-runtime`, and this crate's contract is only that it asks and
//! obeys.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apogee_fetch::{DigestPin, Fetcher};
use apogee_patcher::{
    GameProbe, IndexSource, InstallRequest, PatchError, Patcher, PatcherConfig, PreflightError,
    RepairRepo, RepairRequest, Repo, SePatch,
};
use apogee_test_support::chaos::ChaosServer;
use apogee_zipatch::fixtures;
use sqex_proto::PatchListEntry;
use url::Url;

/// The version every request in here claims to be working toward. Nothing reaches the code that
/// reads it.
const VERSION: &str = "2024.01.02.0000.0000";

/// Every path under `root`, directories included, each file with its content digest.
///
/// Directories are recorded because they are what an early return leaves behind: the pipelines create
/// the repo subtree and the recycler batch before they write anything into either, so a comparison
/// over files alone would call a half-prepared tree untouched.
fn snapshot(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .display()
                .to_string();
            if path.is_dir() {
                out.push(format!("d {rel}"));
                walk(&path, base, out);
            } else {
                let digest = std::fs::read(&path).map(|b| blake3::hash(&b).to_hex().to_string());
                out.push(format!("f {rel} {}", digest.unwrap_or_default()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// An install root with a repo subtree and a file in it, so "untouched" is a claim about contents and
/// not just about an empty directory.
fn populated_install() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let repo = root.path().join("game");
    std::fs::create_dir_all(&repo)?;
    std::fs::write(repo.join("ffxivgame.ver"), VERSION)?;
    std::fs::write(
        repo.join("ffxivboot.exe"),
        b"the bytes a running client holds",
    )?;
    Ok(root)
}

/// A probe that reports the game running, and the install roots it was asked about.
fn running_probe() -> (GameProbe, Arc<Mutex<Vec<PathBuf>>>) {
    let asked: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&asked);
    let probe = GameProbe::new(move |game_root| {
        if let Ok(mut asked) = recorder.lock() {
            asked.push(game_root.to_path_buf());
        }
        true
    });
    (probe, asked)
}

fn patcher(store: &Path, probe: GameProbe, ignore_space: bool) -> Result<Patcher, Box<dyn Error>> {
    let fetcher = Fetcher::builder()
        .stall_timeout(Duration::from_secs(5))
        .build()?;
    Ok(Patcher::new(
        fetcher,
        PatcherConfig {
            patch_store: store.to_path_buf(),
            keep_patches: true,
            ignore_space,
            ..PatcherConfig::new(probe)
        },
    ))
}

fn boot_request(game_root: &Path, url: Url, length: u64) -> InstallRequest {
    InstallRequest {
        repo: Repo::Boot,
        game_root: game_root.to_path_buf(),
        patches: vec![PatchListEntry {
            length,
            version_id: VERSION.to_owned(),
            url: url.to_string(),
            hashes: None,
        }],
        headers: SePatch::boot(),
    }
}

fn repair_request(game_root: &Path, index_url: Url) -> RepairRequest {
    RepairRequest {
        game_root: game_root.to_path_buf(),
        repos: vec![RepairRepo {
            repo: Repo::Game,
            target_version: VERSION.to_owned(),
            // Pinned rather than a local file, so a guard that did not fire would have to go to the
            // origin for the index before it could do anything else. That request is the tell.
            index: IndexSource::Pinned {
                url: index_url,
                pin: DigestPin::Sha256([0u8; 32]),
            },
            patch_sources: Vec::new(),
            source_base_url: None,
            headers: SePatch::new("test-session"),
        }],
    }
}

fn expect_game_running(err: &PatchError) {
    assert!(
        matches!(err, PatchError::Preflight(PreflightError::GameRunning)),
        "want the typed game-running refusal, got {err:?}",
    );
}

/// An install into an install someone is playing is refused before it makes anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_install_refuses_before_it_creates_the_patch_store() -> Result<(), Box<dyn Error>> {
    let game_root = populated_install()?;
    let before = snapshot(game_root.path());
    // A path, not a directory: the pipeline creates the store itself, so its absence afterward is
    // proof the refusal came before the first thing an install does.
    let scratch = tempfile::tempdir()?;
    let store = scratch.path().join("patches");

    let server = ChaosServer::serving(fixtures::chain().remove(0))
        .start()
        .await?;
    let (probe, asked) = running_probe();
    let err = patcher(&store, probe, false)?
        .install(boot_request(game_root.path(), server.url("p0.patch"), 1024))
        .await
        .expect_err("an install into a running game must be refused");

    expect_game_running(&err);
    assert!(
        !store.exists(),
        "the patch store was created before the guard refused the install",
    );
    assert_eq!(
        snapshot(game_root.path()),
        before,
        "a refused install changed the install tree",
    );
    assert_eq!(
        server.stats().requests(),
        0,
        "a refused install still submitted a download",
    );
    // And it asked about the install the request named, not some ambient one.
    assert_eq!(
        asked.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
        &[game_root.path().to_path_buf()],
    );
    Ok(())
}

/// A repair of an install someone is playing is refused on the same terms.
///
/// Worth its own test because repair does not share the install path: it has its own entry point, its
/// own first side effect (the fetched index under the store), and it is the operation a user reaches
/// for while the game is open, having just seen something wrong in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_refuses_before_it_fetches_an_index() -> Result<(), Box<dyn Error>> {
    let game_root = populated_install()?;
    let before = snapshot(game_root.path());
    let scratch = tempfile::tempdir()?;
    let store = scratch.path().join("patches");

    let server = ChaosServer::serving(b"not a real index".to_vec())
        .start()
        .await?;
    let (probe, asked) = running_probe();
    let err = patcher(&store, probe, false)?
        .repair(repair_request(game_root.path(), server.url("game.apzi")))
        .await
        .expect_err("a repair of a running game must be refused");

    expect_game_running(&err);
    assert!(
        !store.exists(),
        "the patch store was created before the guard refused the repair",
    );
    assert_eq!(
        snapshot(game_root.path()),
        before,
        "a refused repair changed the install tree",
    );
    assert_eq!(
        server.stats().requests(),
        0,
        "a refused repair still fetched the block index",
    );
    assert_eq!(
        asked.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
        &[game_root.path().to_path_buf()],
    );
    Ok(())
}

/// The space escape hatch does not open this door.
///
/// `ignore_space` is a caller saying it knows the free-space arithmetic is wrong about its disk. The
/// two checks share a module and a phase, which is exactly why this is worth pinning: nothing about
/// that claim extends to whether a process is running, and a guard folded in behind the same flag
/// would be off for every caller that ever set it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignoring_the_space_estimate_does_not_lift_the_guard() -> Result<(), Box<dyn Error>> {
    let game_root = populated_install()?;
    let before = snapshot(game_root.path());
    let scratch = tempfile::tempdir()?;
    let store = scratch.path().join("patches");

    let server = ChaosServer::serving(fixtures::chain().remove(0))
        .start()
        .await?;
    let (probe, _) = running_probe();
    let err = patcher(&store, probe, true)?
        .install(boot_request(game_root.path(), server.url("p0.patch"), 1024))
        .await
        .expect_err("ignore_space must not turn off the game-running guard");

    expect_game_running(&err);
    assert!(!store.exists(), "the patch store was created anyway");
    assert_eq!(snapshot(game_root.path()), before);
    assert_eq!(server.stats().requests(), 0);
    Ok(())
}

/// A game running somewhere else does not stop this install.
///
/// The negative control the other tests need to mean anything: a guard that refused every time would
/// pass all of them. The probe here answers about one install root only and the request names a
/// different one, so the install runs the whole way through, downloading and applying while a client
/// is live in another install on the same machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_game_running_in_another_install_does_not_refuse_this_one() -> Result<(), Box<dyn Error>>
{
    let game_root = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let running = elsewhere.path().to_path_buf();
    let scratch = tempfile::tempdir()?;
    let store = scratch.path().join("patches");

    let patch = fixtures::chain().remove(0);
    let server = ChaosServer::serving(patch.clone()).start().await?;
    let probe = GameProbe::new(move |game_root| game_root == running);
    let installed = patcher(&store, probe, false)?
        .install(boot_request(
            game_root.path(),
            server.url("p0.patch"),
            patch.len() as u64,
        ))
        .await?;

    assert_eq!(installed.repo, Repo::Boot);
    assert!(
        game_root.path().join("boot").exists(),
        "the install reported success without applying anything",
    );
    Ok(())
}
