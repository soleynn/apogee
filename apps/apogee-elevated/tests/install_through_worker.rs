//! The install pipeline pointed at the worker, end to end.
//!
//! The seam this covers is the one the protocol tests cannot: that `Patcher::install` routes its
//! apply, its version advance and its backup through the boundary and comes out with the same tree
//! it produces in process. The worker runs with this process's own privileges here, which is exactly
//! what the configuration says it does; the only thing a raised-privilege run adds is which process
//! holds the handle, and that is the part no hosted runner can honestly exercise.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::Fetcher;
use apogee_patcher::{
    Elevation, GameProbe, InstallRequest, Installed, PatchError, Patcher, PatcherConfig, Repo,
    SePatch, WorkerErrorKind,
};
use apogee_test_support::chaos::ChaosServer;
use apogee_test_support::tree_manifest;
use apogee_zipatch::fixtures;
use sqex_proto::{BlockHashes, PatchListEntry};
use url::Url;

mod support;

use support::{BLOCK_SIZE, block_sha1_hex};

/// The worker binary this package builds, which is what the launcher would ship beside itself.
fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apogee-elevated"))
}

fn game_entry(url: Url, bytes: &[u8], version_id: &str) -> PatchListEntry {
    PatchListEntry {
        length: bytes.len() as u64,
        version_id: version_id.to_owned(),
        url: url.to_string(),
        hashes: Some(BlockHashes {
            hash_type: "sha1".to_owned(),
            block_size: BLOCK_SIZE as u64,
            hashes: block_sha1_hex(bytes),
        }),
    }
}

fn boot_entry(url: Url, bytes: &[u8], version_id: &str) -> PatchListEntry {
    PatchListEntry {
        length: bytes.len() as u64,
        version_id: version_id.to_owned(),
        url: url.to_string(),
        hashes: None,
    }
}

/// A patcher whose applies run wherever `elevation` says.
fn patcher(store: &Path, elevation: Elevation) -> Result<Patcher, Box<dyn Error>> {
    let fetcher = Fetcher::builder()
        .stall_timeout(Duration::from_secs(5))
        .build()?;
    Ok(Patcher::new(
        fetcher,
        PatcherConfig {
            patch_store: store.to_path_buf(),
            elevation,
            ..PatcherConfig::new(GameProbe::never_running())
        },
    ))
}

fn request(repo: Repo, game_root: &Path, patches: Vec<PatchListEntry>) -> InstallRequest {
    InstallRequest {
        repo,
        game_root: game_root.to_path_buf(),
        patches,
        headers: if matches!(repo, Repo::Boot) {
            SePatch::boot()
        } else {
            SePatch::new("test-session")
        },
    }
}

/// Excuse the patcher-written version files when diffing two trees that were both written by it.
fn is_ver_or_bck(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ver" | "bck")
    )
}

/// The same game chain installed in process and through a worker produces the same tree, the same
/// version file and the same backup.
///
/// Byte-for-byte rather than "both look plausible": the whole point of moving the apply into another
/// process is that nothing else about it changes, and a differential is the only assertion that
/// actually says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_install_through_a_worker_matches_one_in_process() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let versions = ["D2024.01.01.0000.0000", "D2024.01.02.0000.0000"];

    let mut roots = Vec::new();
    for elevation in [Elevation::Never, Elevation::Worker { binary: worker() }] {
        let s0 = ChaosServer::serving(chain[0].clone()).start().await?;
        let s1 = ChaosServer::serving(chain[1].clone()).start().await?;
        let patches = vec![
            game_entry(s0.url("p0.patch"), &chain[0], versions[0]),
            game_entry(s1.url("p1.patch"), &chain[1], versions[1]),
        ];

        let store = tempfile::tempdir()?;
        let game_root = tempfile::tempdir()?;
        let patcher = patcher(store.path(), elevation)?;
        let installed = patcher
            .install(request(Repo::Game, game_root.path(), patches))
            .await?;
        assert_eq!(
            installed,
            Installed {
                repo: Repo::Game,
                new_version: "2024.01.02.0000.0000".to_owned(),
            }
        );
        roots.push(game_root);
    }

    let (in_process, elevated) = (roots[0].path().join("game"), roots[1].path().join("game"));
    let baseline = tree_manifest::author(&in_process)?;
    tree_manifest::assert_tree_matches(
        &elevated,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    for name in ["ffxivgame.ver", "ffxivgame.bck"] {
        assert_eq!(
            std::fs::read_to_string(elevated.join(name))?,
            "2024.01.02.0000.0000",
            "{name} did not advance through the worker",
        );
    }
    Ok(())
}

/// A boot chain goes through the worker too, and lands in the boot subtree with its own version
/// file. Boot is the repo with no patchlist digests, so this is the chunk-CRC admission crossing the
/// boundary: the parent scans to admit it, and the worker scans again to write it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_boot_chain_installs_through_a_worker() -> Result<(), Box<dyn Error>> {
    let patch = fixtures::patch_a();
    let server = ChaosServer::serving(patch.clone()).start().await?;
    let patches = vec![boot_entry(
        server.url("boot.patch"),
        &patch,
        "D2024.01.01.0000.0000",
    )];

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let patcher = patcher(store.path(), Elevation::Worker { binary: worker() })?;
    let installed = patcher
        .install(request(Repo::Boot, game_root.path(), patches))
        .await?;
    assert_eq!(installed.new_version, "2024.01.01.0000.0000");

    let boot = game_root.path().join("boot");
    assert!(boot.join(fixtures::DAT0_PATH).exists());
    assert_eq!(
        std::fs::read_to_string(boot.join("ffxivboot.ver"))?,
        "2024.01.01.0000.0000"
    );
    assert_eq!(
        std::fs::read_to_string(boot.join("ffxivboot.bck"))?,
        "2024.01.01.0000.0000"
    );
    Ok(())
}

/// A worker that cannot be started is a typed spawn failure, before a byte is downloaded.
///
/// Ordering matters as much as the type here: the executor is opened before the transfers, so a
/// launcher that cannot reach its worker says so at the start of an install rather than after
/// carrying a hundred gigabytes to a tree it then cannot write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_cannot_be_started_fails_before_the_first_download()
-> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let missing = store.path().join("no-such-worker");

    // The server is never contacted: the install must give up before it asks for a byte.
    let patches = vec![game_entry(
        Url::parse("http://127.0.0.1:1/p0.patch")?,
        &chain[0],
        "D2024.01.01.0000.0000",
    )];
    let patcher = patcher(store.path(), Elevation::Worker { binary: missing })?;
    let err = patcher
        .install(request(Repo::Game, game_root.path(), patches))
        .await
        .expect_err("an unreachable worker must fail the install");

    let PatchError::Worker {
        kind: WorkerErrorKind::Spawn,
        detail,
        ..
    } = &err
    else {
        panic!("expected a typed spawn failure, got {err:?}");
    };
    assert!(
        detail.contains("no-such-worker"),
        "the failure should name the binary it could not start: {detail}"
    );
    assert!(
        !game_root.path().join("game").exists(),
        "nothing should have been written"
    );
    Ok(())
}
