//! The install pipeline end to end: a patchlist drives fetch-then-apply over the chaos server and
//! the resulting tree matches a direct apply of the same chain. Apply holds list order even when a
//! later patch downloads first; a cancel-and-rerun converges; a corrupt patch is rejected at acquire
//! before any byte reaches disk.
//!
//! Patches come from `apogee_zipatch::fixtures` (one owner of the format, no Square Enix bytes) and
//! each is served by its own chaos server with synthetic per-block SHA1 standing in for a game
//! patchlist's hashes.

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use apogee_fetch::{FetchError, Fetcher};
use apogee_patcher::{
    InstallRequest, Installed, PatchError, PatchProgress, Patcher, PatcherConfig, Repo, SePatch,
};
use apogee_test_support::chaos::ChaosServer;
use apogee_test_support::tree_manifest;
use apogee_zipatch::fixtures;
use sha1::{Digest, Sha1};
use sqex_proto::{BlockHashes, PatchListEntry};
use tokio_stream::StreamExt;
use url::Url;

/// The per-block hash width the synthetic patchlist advertises (small, so a patch spans many blocks).
const BLOCK_SIZE: usize = 64;

/// Per-block lowercase-hex SHA1 over `bytes`, the game-patchlist hash shape.
fn block_sha1_hex(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(BLOCK_SIZE)
        .map(|block| {
            Sha1::digest(block)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .collect()
}

/// A game patchlist entry pointing at `url`, hashed over `bytes`, targeting `version_id`.
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

/// A single-repo game install request into `game_root`.
fn request(game_root: &Path, patches: Vec<PatchListEntry>) -> InstallRequest {
    InstallRequest {
        repo: Repo::Game,
        game_root: game_root.to_path_buf(),
        patches,
        headers: SePatch::new("test-session"),
    }
}

/// A boot patchlist entry pointing at `url`, targeting `version_id`. Boot patchlists carry no
/// per-block hashes (`hashes: None`): fetch length-checks the bytes and the patcher's chunk-CRC scan
/// admits them.
fn boot_entry(url: Url, bytes: &[u8], version_id: &str) -> PatchListEntry {
    PatchListEntry {
        length: bytes.len() as u64,
        version_id: version_id.to_owned(),
        url: url.to_string(),
        hashes: None,
    }
}

/// A single-repo boot install request into `game_root` (patch-client user-agent only, no session
/// credential, as boot patching runs before login).
fn boot_request(game_root: &Path, patches: Vec<PatchListEntry>) -> InstallRequest {
    InstallRequest {
        repo: Repo::Boot,
        game_root: game_root.to_path_buf(),
        patches,
        headers: SePatch::boot(),
    }
}

/// Excuse the patcher-written `.ver`/`.bck` when diffing against a hash-only baseline apply.
fn is_ver_or_bck(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ver" | "bck")
    )
}

/// A short per-chunk throttle: enough of a server-side floor to invert download order and to keep a
/// transfer in flight for a cancel, but small enough that the tests stay well under a second.
const THROTTLE: Duration = Duration::from_millis(12);

/// Build a `Patcher` over a fresh fetcher and the given store, keeping patches per `keep_patches`.
///
/// The stall timeout is shortened below the 15 s default: these transfers are tiny (throttles are
/// milliseconds), so a multi-second gap can only be a real hang, and CI should fail fast on it. The
/// margin over the throttle floor is still ~400x, so a busy runner cannot trip it falsely.
fn patcher(store: &Path, keep_patches: bool) -> Result<Patcher, Box<dyn Error>> {
    let fetcher = Fetcher::builder()
        .stall_timeout(Duration::from_secs(5))
        .build()?;
    Ok(Patcher::new(
        fetcher,
        PatcherConfig {
            patch_store: store.to_path_buf(),
            keep_patches,
            ignore_space: false,
        },
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_applies_a_tree_identical_to_a_direct_apply() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let versions = ["D2024.01.01.0000.0000", "D2024.01.02.0000.0000"];

    // Baseline: the same chain applied directly by zipatch, no orchestration.
    let scratch = tempfile::tempdir()?;
    fixtures::apply_chain(scratch.path(), &chain)?;
    let baseline = tree_manifest::author(scratch.path())?;

    let s0 = ChaosServer::serving(chain[0].clone()).start().await?;
    let s1 = ChaosServer::serving(chain[1].clone()).start().await?;
    let patches = vec![
        game_entry(s0.url("p0.patch"), &chain[0], versions[0]),
        game_entry(s1.url("p1.patch"), &chain[1], versions[1]),
    ];

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let patcher = patcher(store.path(), false)?;

    let installed = patcher.install(request(game_root.path(), patches)).await?;
    assert_eq!(
        installed,
        Installed {
            repo: Repo::Game,
            new_version: "2024.01.02.0000.0000".to_owned(),
        }
    );

    // The applied game subtree matches the direct apply (ignoring the patcher-written .ver/.bck).
    let game_dir = game_root.path().join("game");
    tree_manifest::assert_tree_matches(
        &game_dir,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );

    // .ver / .bck advanced to the last patch, bare and newline-free.
    assert_eq!(
        std::fs::read_to_string(game_dir.join("ffxivgame.ver"))?,
        "2024.01.02.0000.0000"
    );
    assert_eq!(
        std::fs::read_to_string(game_dir.join("ffxivgame.bck"))?,
        "2024.01.02.0000.0000"
    );

    // keep_patches = false: the store's patch files were removed after a clean apply.
    assert!(!store.path().join("p0.patch").exists());
    assert!(!store.path().join("p1.patch").exists());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_stays_in_list_order_under_out_of_order_downloads() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let versions = ["D2024.01.01.0000.0000", "D2024.01.02.0000.0000"];
    let scratch = tempfile::tempdir()?;
    fixtures::apply_chain(scratch.path(), &chain)?;
    let baseline = tree_manifest::author(scratch.path())?;

    // Throttle the earlier patch so the later one downloads first; apply must still be 0 then 1. The
    // throttle is a server-side floor, so the ordering holds regardless of how loaded the runner is.
    let s0 = ChaosServer::serving(chain[0].clone())
        .throttle(THROTTLE)
        .chunk(64)
        .start()
        .await?;
    let s1 = ChaosServer::serving(chain[1].clone()).start().await?;
    let patches = vec![
        game_entry(s0.url("p0.patch"), &chain[0], versions[0]),
        game_entry(s1.url("p1.patch"), &chain[1], versions[1]),
    ];

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let patcher = patcher(store.path(), true)?;

    let mut job = patcher.install(request(game_root.path(), patches));
    let mut stream = job.progress();
    let collector = tokio::spawn(async move {
        let mut events = Vec::new();
        while let Some(ev) = stream.next().await {
            events.push(ev);
        }
        events
    });
    let installed = job.await?;
    let events = collector.await?;

    assert_eq!(installed.new_version, "2024.01.02.0000.0000");

    // Applied strictly in list order.
    let applied_order: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            PatchProgress::Applied { index, .. } => Some(*index),
            _ => None,
        })
        .collect();
    assert_eq!(applied_order, vec![0, 1], "apply must follow list order");

    // The later patch finished downloading before the earlier one applied.
    let last_dl_1 = events
        .iter()
        .rposition(|e| matches!(e, PatchProgress::Downloading { index: 1, .. }));
    let first_applied_0 = events
        .iter()
        .position(|e| matches!(e, PatchProgress::Applied { index: 0, .. }));
    assert!(
        matches!((last_dl_1, first_applied_0), (Some(d), Some(a)) if d < a),
        "patch 1 should finish downloading before patch 0 applies (dl1={last_dl_1:?}, applied0={first_applied_0:?})",
    );

    let game_dir = game_root.path().join("game");
    tree_manifest::assert_tree_matches(
        &game_dir,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_then_rerun_converges() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let versions = ["D2024.01.01.0000.0000", "D2024.01.02.0000.0000"];
    let scratch = tempfile::tempdir()?;
    fixtures::apply_chain(scratch.path(), &chain)?;
    let baseline = tree_manifest::author(scratch.path())?;

    // Throttle every download (a server-side floor) so the cancel reliably lands mid-transfer.
    let s0 = ChaosServer::serving(chain[0].clone())
        .throttle(THROTTLE)
        .chunk(64)
        .start()
        .await?;
    let s1 = ChaosServer::serving(chain[1].clone())
        .throttle(THROTTLE)
        .chunk(64)
        .start()
        .await?;
    let patches = vec![
        game_entry(s0.url("p0.patch"), &chain[0], versions[0]),
        game_entry(s1.url("p1.patch"), &chain[1], versions[1]),
    ];

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let patcher = patcher(store.path(), true)?;

    // Run 1: cancel as soon as a download is in flight.
    let mut job = patcher.install(request(game_root.path(), patches.clone()));
    let mut stream = job.progress();
    let first = stream.next().await;
    assert!(
        matches!(first, Some(PatchProgress::Downloading { .. })),
        "expected a download to start, got {first:?}",
    );
    job.cancel();
    let drain = tokio::spawn(async move { while stream.next().await.is_some() {} });
    let result = job.await;
    drain.await?;
    assert!(
        matches!(result, Err(PatchError::Cancelled)),
        "cancel should surface as Cancelled, got {result:?}",
    );

    // Run 2: same request, no cancel; resumes the partial download and converges.
    let installed = patcher.install(request(game_root.path(), patches)).await?;
    assert_eq!(installed.new_version, "2024.01.02.0000.0000");

    let game_dir = game_root.path().join("game");
    tree_manifest::assert_tree_matches(
        &game_dir,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    assert_eq!(
        std::fs::read_to_string(game_dir.join("ffxivgame.ver"))?,
        "2024.01.02.0000.0000"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_corrupt_patch_is_rejected_before_apply() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let versions = ["D2024.01.01.0000.0000", "D2024.01.02.0000.0000"];

    // Corrupt every served byte of patch 0 so its per-block SHA1 never matches. Refusing ranges
    // routes fetch through the single-connection path, which verifies blocks from disk and fails at
    // once (no ranged re-fetch budget to burn), so the rejection is prompt.
    let len0 = chain[0].len() as u64;
    let s0 = ChaosServer::serving(chain[0].clone())
        .accept_ranges(false)
        .corrupt_range(0..len0)
        .start()
        .await?;
    let s1 = ChaosServer::serving(chain[1].clone()).start().await?;
    let patches = vec![
        game_entry(s0.url("p0.patch"), &chain[0], versions[0]),
        game_entry(s1.url("p1.patch"), &chain[1], versions[1]),
    ];

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let patcher = patcher(store.path(), true)?;

    let result = patcher.install(request(game_root.path(), patches)).await;
    assert!(
        matches!(
            result,
            Err(PatchError::Acquire(FetchError::BlockVerifyFailed { .. }))
        ),
        "a corrupt patch must be rejected at acquire, got {result:?}",
    );

    // Verification failed, so no bytes reached disk: the game subtree was never created.
    assert!(
        !game_root.path().join("game").exists(),
        "no bytes should reach disk when verification fails",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_install_admits_via_chunk_crc_and_applies_from_nothing() -> Result<(), Box<dyn Error>>
{
    let chain = fixtures::chain();
    // Boot versions carry no list-prefix letter; the bare form is written verbatim.
    let versions = ["2024.03.27.0000.0000", "2024.03.28.0000.0000"];

    // Baseline: the same chain applied directly by zipatch, no orchestration.
    let scratch = tempfile::tempdir()?;
    fixtures::apply_chain(scratch.path(), &chain)?;
    let baseline = tree_manifest::author(scratch.path())?;

    // Boot patches are served over plain HTTP with no per-block hashes: fetch delivers length-checked
    // bytes under the external-verification marker and the patcher's chunk-CRC scan admits them.
    let s0 = ChaosServer::serving(chain[0].clone()).start().await?;
    let s1 = ChaosServer::serving(chain[1].clone()).start().await?;
    let patches = vec![
        boot_entry(s0.url("p0.patch"), &chain[0], versions[0]),
        boot_entry(s1.url("p1.patch"), &chain[1], versions[1]),
    ];

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?; // empty: install from nothing.
    let patcher = patcher(store.path(), false)?;

    let installed = patcher
        .install(boot_request(game_root.path(), patches))
        .await?;
    assert_eq!(
        installed,
        Installed {
            repo: Repo::Boot,
            new_version: "2024.03.28.0000.0000".to_owned(),
        }
    );

    // The applied boot subtree matches the direct apply (ignoring the patcher-written .ver/.bck).
    let boot_dir = game_root.path().join("boot");
    tree_manifest::assert_tree_matches(
        &boot_dir,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );

    // .ver / .bck advanced to the last patch, bare and newline-free.
    assert_eq!(
        std::fs::read_to_string(boot_dir.join("ffxivboot.ver"))?,
        "2024.03.28.0000.0000"
    );
    assert_eq!(
        std::fs::read_to_string(boot_dir.join("ffxivboot.bck"))?,
        "2024.03.28.0000.0000"
    );

    // The boot header contract: every request carried the patch-client user-agent and none carried a
    // session credential (boot patching precedes login). Proves `SePatch::boot()` leaks no unique-id.
    let uas = s0.stats().user_agents();
    assert!(!uas.is_empty(), "the boot patch was requested");
    assert!(
        uas.iter()
            .all(|ua| ua.as_deref() == Some("FFXIV PATCH CLIENT")),
        "boot downloads must carry the patch-client user-agent, got {uas:?}",
    );
    assert!(
        s0.stats().patch_unique_ids().iter().all(Option::is_none),
        "boot downloads must not carry a session unique-id, got {:?}",
        s0.stats().patch_unique_ids(),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_corrupt_boot_patch_is_rejected_by_the_crc_gate() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let versions = ["2024.03.27.0000.0000", "2024.03.28.0000.0000"];

    // Flip one byte deep in patch 0's body. Its length is unchanged, so fetch's length check passes
    // and the bytes are admitted for scanning, but a chunk CRC no longer matches, so the patcher's
    // admission scan rejects it. Boot carries no per-block hashes for fetch to catch this itself.
    let len0 = chain[0].len() as u64;
    let mid = len0 / 2;
    let s0 = ChaosServer::serving(chain[0].clone())
        .corrupt_range(mid..mid + 1)
        .start()
        .await?;
    let s1 = ChaosServer::serving(chain[1].clone()).start().await?;
    let patches = vec![
        boot_entry(s0.url("p0.patch"), &chain[0], versions[0]),
        boot_entry(s1.url("p1.patch"), &chain[1], versions[1]),
    ];

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let patcher = patcher(store.path(), true)?;

    let result = patcher
        .install(boot_request(game_root.path(), patches))
        .await;
    assert!(
        matches!(result, Err(PatchError::BootAdmission { index: 0, .. })),
        "a corrupt boot patch must be rejected by the chunk-crc gate, got {result:?}",
    );

    // Rejected at admission, before apply: no boot subtree was ever created.
    assert!(
        !game_root.path().join("boot").exists(),
        "no bytes should be applied when boot admission fails",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_entry_fails_before_any_download_and_leaks_no_task()
-> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    // Entry 0 is well-formed (its host is never contacted); entry 1 carries a bad SHA1 digest, so
    // its request cannot be built. The whole install must fail before any download is spawned.
    let good = game_entry(
        Url::parse("http://127.0.0.1:9/p0.patch")?,
        &chain[0],
        "D2024.01.01.0000.0000",
    );
    let mut bad = game_entry(
        Url::parse("http://127.0.0.1:9/p1.patch")?,
        &chain[1],
        "D2024.01.02.0000.0000",
    );
    if let Some(h) = bad.hashes.as_mut() {
        h.hashes[0] = "not-a-valid-40-char-hex-sha1-digest-here".to_owned();
    }

    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    let patcher = patcher(store.path(), true)?;

    let mut job = patcher.install(request(game_root.path(), vec![good, bad]));
    let mut stream = job.progress();
    let result = job.await;

    // The progress stream closes promptly: no spawned download outlived the early error holding it
    // open (the regression this guards). A leaked task would hang this drain.
    while stream.next().await.is_some() {}

    assert!(
        matches!(result, Err(PatchError::Patchlist { index: 1, .. })),
        "a malformed entry must fail as Patchlist, got {result:?}",
    );
    assert!(
        !game_root.path().join("game").exists(),
        "nothing should be applied when the patchlist is rejected",
    );
    Ok(())
}
