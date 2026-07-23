//! The repair pipeline end to end: verify an installed tree against its block index, re-fetch only
//! the broken byte ranges, reconstruct zero/empty regions locally, and quarantine strays without
//! deleting them. Damage is healed byte-identically; byte-accounting proves only broken ranges were
//! pulled; a wrong-version index is rejected loud; a `sha256`-pinned index authenticates over HTTP.
//!
//! Patches and the index come from `apogee_zipatch::fixtures`/`build_index` (one format owner, no
//! Square Enix bytes); each patch is served by its own chaos server.

use std::error::Error;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use apogee_fetch::Fetcher;
use apogee_patcher::{
    IndexSource, PatchError, Patcher, PatcherConfig, RepairPatchSource, RepairRepo, RepairRequest,
    Repo, SePatch,
};
use apogee_test_support::chaos::{ChaosServer, sha256_of};
use apogee_test_support::tree_manifest;
use apogee_zipatch::{Platform, build_index, fixtures};

/// The version the test index and every repair target agree on.
const VERSION: &str = "2024.01.02.0000.0000";

/// The `.apzi` bytes of a versioned index over `chain`, its sources named `p{i}.patch` to match the
/// served paths.
fn apzi_bytes(chain: &[Vec<u8>], version: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let inputs: Vec<(String, Cursor<Vec<u8>>)> = chain
        .iter()
        .enumerate()
        .map(|(i, p)| (format!("p{i}.patch"), Cursor::new(p.clone())))
        .collect();
    let index = build_index(inputs, Platform::Win32, version)?;
    let mut buf = Vec::new();
    index.write_apzi(&mut buf)?;
    Ok(buf)
}

/// Write a versioned index over `chain` to `path` as `.apzi`.
fn write_index_file(chain: &[Vec<u8>], version: &str, path: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, apzi_bytes(chain, version)?)?;
    Ok(())
}

/// Serve each patch of `chain` from its own chaos server; `servers[i]` backs `p{i}.patch`.
async fn serve(chain: &[Vec<u8>]) -> Result<Vec<ChaosServer>, Box<dyn Error>> {
    let mut servers = Vec::new();
    for patch in chain {
        servers.push(ChaosServer::serving(patch.clone()).start().await?);
    }
    Ok(servers)
}

/// The per-patch repair sources: `p{i}.patch` at `servers[i]`, with `local[i]` a cached copy when set.
fn patch_sources(servers: &[ChaosServer], local: &[Option<PathBuf>]) -> Vec<RepairPatchSource> {
    servers
        .iter()
        .enumerate()
        .map(|(i, s)| RepairPatchSource {
            name: format!("p{i}.patch"),
            url: s.url(&format!("p{i}.patch")),
            local: local.get(i).cloned().flatten(),
        })
        .collect()
}

/// Overwrite one byte at `off` of a file with a value it is not (forcing a broken part).
fn corrupt_byte(path: &Path, off: usize) -> std::io::Result<()> {
    let mut data = std::fs::read(path)?;
    data[off] ^= 0xFF;
    std::fs::write(path, data)
}

/// Excuse the patcher-written `.ver`/`.bck` when diffing against a hash-only baseline apply.
fn is_ver_or_bck(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ver" | "bck")
    )
}

/// A patcher over a fresh fetcher and `store`.
fn patcher(store: &Path) -> Result<Patcher, Box<dyn Error>> {
    let fetcher = Fetcher::builder().build()?;
    Ok(Patcher::new(
        fetcher,
        PatcherConfig {
            patch_store: store.to_path_buf(),
            ..PatcherConfig::default()
        },
    ))
}

/// Apply the chain into `game_root/game` (the game repo subtree) and return the baseline manifest of a
/// separate clean apply for comparison.
fn install_game(
    chain: &[Vec<u8>],
    game_root: &Path,
) -> Result<tree_manifest::TreeManifest, Box<dyn Error>> {
    let repo = game_root.join("game");
    std::fs::create_dir_all(&repo)?;
    fixtures::apply_chain(&repo, chain)?;
    let scratch = tempfile::tempdir()?;
    fixtures::apply_chain(scratch.path(), chain)?;
    Ok(tree_manifest::author(scratch.path())?)
}

/// A single-repo game repair request.
fn request(game_root: &Path, index: IndexSource, sources: Vec<RepairPatchSource>) -> RepairRequest {
    RepairRequest {
        game_root: game_root.to_path_buf(),
        repos: vec![RepairRepo {
            repo: Repo::Game,
            target_version: VERSION.to_owned(),
            index,
            patch_sources: sources,
            source_base_url: None,
            headers: SePatch::new("test-session"),
        }],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_over_http_heals_and_pulls_only_broken_ranges() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // Break one part in each patch: the exe's leading stored block (patch 0) and the dat's [256,384)
    // add (patch 1). Each heals from a single broken source range, so the byte count stays far below
    // either whole patch.
    corrupt_byte(&repo.join("ffxivboot.exe"), 0)?;
    corrupt_byte(&repo.join(fixtures::DAT0_PATH), 256)?;

    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &[]); // no local: force HTTP
    let outcome = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await?;

    // Healed byte-identically.
    tree_manifest::assert_tree_matches(
        &repo,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );

    // Byte-accounting: some bytes were pulled, but far fewer than the whole chain, and each server
    // served strictly less than its patch (only the broken ranges left its side).
    let total_patch: u64 = chain.iter().map(|p| p.len() as u64).sum();
    assert!(outcome.bytes_refetched > 0, "a broken tree must pull bytes");
    assert!(
        outcome.bytes_refetched < total_patch,
        "pulled {} of {total_patch} whole-chain bytes",
        outcome.bytes_refetched,
    );
    let served: u64 = servers.iter().map(|s| s.stats().bytes_served()).sum();
    assert_eq!(
        outcome.bytes_refetched, served,
        "outcome must account served bytes"
    );
    for (i, patch) in chain.iter().enumerate() {
        assert!(
            servers[i].stats().bytes_served() < patch.len() as u64,
            "server {i} served a whole patch, not a broken range",
        );
    }

    // The repaired repo advanced its `.ver`/`.bck` to the target.
    assert_eq!(
        std::fs::read_to_string(repo.join("ffxivgame.ver"))?,
        VERSION
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("ffxivgame.bck"))?,
        VERSION
    );
    assert_eq!(outcome.repos.len(), 1);
    assert_eq!(outcome.repos[0].version, VERSION);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_derives_source_urls_from_the_base_url_with_no_explicit_sources()
-> Result<(), Box<dyn Error>> {
    // A single-patch chain, so one base URL covers every source the index references (the chaos server
    // serves its blob at any path, so the derived name `p0.patch` resolves against the server root).
    let chain = vec![fixtures::patch_a()];
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    corrupt_byte(&repo.join(fixtures::DAT0_PATH), 0)?;

    let servers = serve(&chain).await?;
    let base = servers[0].base_url().clone();

    // No explicit `patch_sources`: the source URL must be derived from the base alone (the index-only,
    // cache-independent heal path).
    let req = RepairRequest {
        game_root: game_root.path().to_path_buf(),
        repos: vec![RepairRepo {
            repo: Repo::Game,
            target_version: VERSION.to_owned(),
            index: IndexSource::LocalFile(index_path),
            patch_sources: Vec::new(),
            source_base_url: Some(base),
            headers: SePatch::new("s"),
        }],
    };
    let outcome = patcher(store.path())?.repair(req).await?;

    // Healed byte-identically over HTTP, pulling only the broken range from the derived URL.
    tree_manifest::assert_tree_matches(
        &repo,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    assert!(
        outcome.bytes_refetched > 0,
        "the broken range must be pulled over HTTP"
    );
    assert!(
        outcome.bytes_refetched < chain[0].len() as u64,
        "pulled the whole patch, not a broken range"
    );
    assert_eq!(outcome.bytes_refetched, servers[0].stats().bytes_served());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_without_a_source_or_a_base_url_is_index_unavailable() -> Result<(), Box<dyn Error>>
{
    let chain = vec![fixtures::patch_a()];
    let game_root = tempfile::tempdir()?;
    install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;
    corrupt_byte(&repo.join(fixtures::DAT0_PATH), 0)?;

    // Neither an explicit source nor a base URL: the index references a patch the repair cannot form.
    let req = RepairRequest {
        game_root: game_root.path().to_path_buf(),
        repos: vec![RepairRepo {
            repo: Repo::Game,
            target_version: VERSION.to_owned(),
            index: IndexSource::LocalFile(index_path),
            patch_sources: Vec::new(),
            source_base_url: None,
            headers: SePatch::new("s"),
        }],
    };
    match patcher(store.path())?.repair(req).await {
        Err(PatchError::IndexUnavailable { .. }) => Ok(()),
        other => panic!("expected IndexUnavailable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_trusts_local_patches_first_and_fetches_nothing() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // Cache the whole chain locally, so the first (trusted) attempt heals with no network at all.
    let local: Vec<Option<PathBuf>> = chain
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let path = store.path().join(format!("p{i}.patch"));
            std::fs::write(&path, p).unwrap();
            Some(path)
        })
        .collect();

    corrupt_byte(&repo.join("ffxivboot.exe"), 0)?;
    corrupt_byte(&repo.join(fixtures::DAT0_PATH), 256)?;

    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &local);
    let outcome = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await?;

    tree_manifest::assert_tree_matches(
        &repo,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    assert_eq!(
        outcome.bytes_refetched, 0,
        "local patches must satisfy the repair"
    );
    for (i, server) in servers.iter().enumerate() {
        assert_eq!(
            server.stats().requests(),
            0,
            "server {i} was contacted despite a complete local cache",
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_local_falls_back_to_http_on_the_next_attempt() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // Cache the whole chain locally, but poison patch 0's copy: same length (so range reads stay
    // in-bounds), wrong bytes (so any part sourced from it fails its CRC on the trusted first attempt).
    let local: Vec<Option<PathBuf>> = chain
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let path = store.path().join(format!("p{i}.patch"));
            let bytes = if i == 0 {
                vec![0xEE; p.len()]
            } else {
                p.clone()
            };
            std::fs::write(&path, bytes).unwrap();
            Some(path)
        })
        .collect();

    // The damaged part (the exe's leading stored block) is sourced from patch 0: the first attempt
    // reads the poisoned local copy, its CRC rejects it, and the second attempt heals it over HTTP.
    corrupt_byte(&repo.join("ffxivboot.exe"), 0)?;

    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &local);
    let outcome = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await?;

    // The retry healed it: byte-identical, and the bytes came over HTTP (the poisoned local did not
    // silently corrupt the tree, and the CRC gate did not accept its bytes).
    tree_manifest::assert_tree_matches(
        &repo,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    assert!(
        outcome.bytes_refetched > 0,
        "the poisoned local attempt must fall back to an HTTP re-fetch",
    );
    assert!(
        servers[0].stats().requests() >= 1,
        "patch 0's server should have served the range the local copy could not",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_quarantines_strays_without_deleting() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // A file the index cannot explain, sitting inside a directory the index populates
    // (`sqpack/ffxiv/`): repair must relocate it, never delete it.
    std::fs::write(repo.join("sqpack/ffxiv/leftover.dat"), b"do not delete me")?;

    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &[]);
    let outcome = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await?;

    // The stray left the tree but survives under the recycler with its bytes intact.
    assert!(
        !repo.join("sqpack/ffxiv/leftover.dat").exists(),
        "the stray was left in place"
    );
    assert_eq!(outcome.quarantined.len(), 1, "one stray quarantined");
    let recycled = game_root.path().join(&outcome.quarantined[0]);
    assert_eq!(
        std::fs::read(&recycled)?,
        b"do not delete me",
        "bytes preserved"
    );

    // With the stray gone the repo is index-clean and matches the baseline.
    tree_manifest::assert_tree_matches(
        &repo,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_spares_a_sibling_repos_subtree() -> Result<(), Box<dyn Error>> {
    // The game and its expansions share one on-disk `game/` tree: the game index populates
    // `sqpack/ffxiv/…` while expansion data lives beside it under `sqpack/ex{n}/…`. A game repair must
    // NOT quarantine an expansion file it has no index for, or it would tear a real install apart.
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // A sibling expansion's file, in a directory the game index does not populate.
    std::fs::create_dir_all(repo.join("sqpack/ex1"))?;
    let sibling = repo.join("sqpack/ex1/2b0000.win32.dat0");
    std::fs::write(&sibling, b"expansion data, not the game repo's business")?;

    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &[]);
    let outcome = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await?;

    assert!(
        outcome.quarantined.is_empty(),
        "a sibling repo's file must not be quarantined, got {:?}",
        outcome.quarantined,
    );
    assert!(
        sibling.exists(),
        "the expansion file must stay in place after a game repair",
    );
    assert_eq!(
        std::fs::read(&sibling)?,
        b"expansion data, not the game repo's business",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_version_index_is_rejected_by_the_cross_check() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    install_game(&chain, game_root.path())?;

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    // The index describes an older version than the repair means to heal to.
    write_index_file(&chain, "2023.05.05.0000.0000", &index_path)?;

    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &[]);
    let result = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await;

    assert!(
        matches!(
            result,
            Err(PatchError::VersionCrossCheck {
                repo: Repo::Game,
                ..
            })
        ),
        "a wrong-version index must be rejected, got {result:?}",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_index_authenticates_over_http() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    // Serve the .apzi from its own server under its sha256 pin, so the patch servers' byte-accounting
    // stays clean.
    let apzi = apzi_bytes(&chain, VERSION)?;
    let pin = sha256_of(&apzi);
    let index_server = ChaosServer::serving(apzi).start().await?;

    corrupt_byte(&repo.join("ffxivboot.exe"), 0)?;

    let store = tempfile::tempdir()?;
    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &[]);
    let outcome = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::Pinned {
                url: index_server.url("game.apzi"),
                sha256: pin,
            },
            sources,
        ))
        .await?;

    tree_manifest::assert_tree_matches(
        &repo,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    assert!(outcome.bytes_refetched > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_index_with_a_bad_pin_is_rejected() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    install_game(&chain, game_root.path())?;

    let apzi = apzi_bytes(&chain, VERSION)?;
    let index_server = ChaosServer::serving(apzi).start().await?;

    let store = tempfile::tempdir()?;
    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &[]);
    let result = patcher(store.path())?
        .repair(request(
            game_root.path(),
            // A pin the served bytes do not hash to: the fetch must reject it, surfaced as the index
            // being unavailable rather than a silent trust.
            IndexSource::Pinned {
                url: index_server.url("game.apzi"),
                sha256: [0u8; 32],
            },
            sources,
        ))
        .await;

    assert!(
        matches!(
            result,
            Err(PatchError::IndexUnavailable {
                repo: Repo::Game,
                ..
            })
        ),
        "a bad index pin must be rejected, got {result:?}",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_recreates_and_resizes_and_reports_counts() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // Three kinds of damage at once: a deleted file (must be recreated), a truncated file (must be
    // resized and its lost tail refetched), and a flipped byte (a broken part). All heal over HTTP.
    std::fs::remove_file(repo.join("data.bin"))?;
    let exe = repo.join("ffxivboot.exe");
    let exe_len = std::fs::metadata(&exe)?.len();
    let f = std::fs::OpenOptions::new().write(true).open(&exe)?;
    f.set_len(exe_len - 100)?; // truncate into the compressed tail part
    drop(f);
    corrupt_byte(&repo.join(fixtures::DAT0_PATH), 256)?;

    let servers = serve(&chain).await?;
    let sources = patch_sources(&servers, &[]);
    let outcome = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await?;

    tree_manifest::assert_tree_matches(
        &repo,
        &baseline,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    let r = &outcome.repos[0];
    assert_eq!(r.recreated, 1, "data.bin was recreated");
    assert_eq!(r.resized, 1, "ffxivboot.exe was resized");
    assert!(r.repaired_parts >= 1, "broken parts were rewritten");
    assert!(outcome.bytes_refetched > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_index_referencing_an_unprovided_source_is_index_unavailable()
-> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain(); // two source patches: p0, p1
    let game_root = tempfile::tempdir()?;
    install_game(&chain, game_root.path())?;

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // Provide only p0, though the index references p0 and p1: repair cannot proceed missing a source.
    let servers = serve(&chain).await?;
    let sources = vec![RepairPatchSource {
        name: "p0.patch".to_owned(),
        url: servers[0].url("p0.patch"),
        local: None,
    }];
    let result = patcher(store.path())?
        .repair(request(
            game_root.path(),
            IndexSource::LocalFile(index_path),
            sources,
        ))
        .await;

    assert!(
        matches!(
            result,
            Err(PatchError::IndexUnavailable {
                repo: Repo::Game,
                ..
            })
        ),
        "a missing source patch must be IndexUnavailable, got {result:?}",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_repo_request_repairs_each_and_shares_the_recycler_batch()
-> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;

    // Stand up two repos in one install root: apply the same chain into boot/ and game/, each with its
    // own index. (The fixture chain stands in for both repos' content; only the layout matters here.)
    for sub in ["boot", "game"] {
        let dir = game_root.path().join(sub);
        std::fs::create_dir_all(&dir)?;
        fixtures::apply_chain(&dir, &chain)?;
    }
    let store = tempfile::tempdir()?;
    let index_path = store.path().join("shared.apzi");
    write_index_file(&chain, VERSION, &index_path)?;

    // Damage a part and plant a stray in each repo's tree.
    for sub in ["boot", "game"] {
        let dir = game_root.path().join(sub);
        corrupt_byte(&dir.join("ffxivboot.exe"), 0)?;
        std::fs::write(dir.join("sqpack/ffxiv/leftover.dat"), b"stray")?;
    }

    let boot_servers = serve(&chain).await?;
    let game_servers = serve(&chain).await?;
    let req = RepairRequest {
        game_root: game_root.path().to_path_buf(),
        repos: vec![
            RepairRepo {
                repo: Repo::Boot,
                target_version: VERSION.to_owned(),
                index: IndexSource::LocalFile(index_path.clone()),
                patch_sources: patch_sources(&boot_servers, &[]),
                source_base_url: None,
                headers: SePatch::boot(),
            },
            RepairRepo {
                repo: Repo::Game,
                target_version: VERSION.to_owned(),
                index: IndexSource::LocalFile(index_path),
                patch_sources: patch_sources(&game_servers, &[]),
                source_base_url: None,
                headers: SePatch::new("s"),
            },
        ],
    };
    let outcome = patcher(store.path())?.repair(req).await?;

    // Both repos healed, both `.ver`s advanced, both strays quarantined into ONE batch directory.
    assert_eq!(outcome.repos.len(), 2);
    assert!(outcome.repos.iter().all(|r| r.version == VERSION));
    assert_eq!(
        std::fs::read_to_string(game_root.path().join("boot/ffxivboot.ver"))?,
        VERSION
    );
    assert_eq!(
        std::fs::read_to_string(game_root.path().join("game/ffxivgame.ver"))?,
        VERSION
    );
    assert_eq!(outcome.quarantined.len(), 2, "one stray per repo");
    // Both quarantined paths sit under the same `apogee_repair_recycler/{batch}/` directory.
    let batches: std::collections::HashSet<_> = outcome
        .quarantined
        .iter()
        .filter_map(|p| p.iter().nth(1).map(|b| b.to_owned()))
        .collect();
    assert_eq!(
        batches.len(),
        1,
        "all repos share one recycler batch, got {batches:?}"
    );
    Ok(())
}

/// The repair property, orchestration level: from a healthy install, damaging random bytes and
/// healing converges to the byte-identical tree every time. Runs off local patch sources so the loop
/// is fast (the byte-accounted HTTP path is covered above); `apogee-zipatch` carries the pure
/// 1000×-with-fetch-accounting property beneath this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_heals_random_damage_repeatedly() -> Result<(), Box<dyn Error>> {
    const ITERATIONS: u64 = 1000;

    let chain = fixtures::chain();
    let game_root = tempfile::tempdir()?;
    let baseline = install_game(&chain, game_root.path())?;
    let repo = game_root.path().join("game");

    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, VERSION, &index_path)?;
    let local: Vec<Option<PathBuf>> = chain
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let path = store.path().join(format!("p{i}.patch"));
            std::fs::write(&path, p).unwrap();
            Some(path)
        })
        .collect();

    let patcher = patcher(store.path())?;
    // Every regular file under the repo, the damage targets (skip the patcher's own .ver/.bck).
    let files = repo_files(&repo);
    assert!(!files.is_empty());

    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for iter in 0..ITERATIONS {
        // Damage 1..=4 random bytes across random files.
        let n = 1 + (fixtures::splitmix64(&mut state) % 4);
        for _ in 0..n {
            let f = &files[(fixtures::splitmix64(&mut state) % files.len() as u64) as usize];
            let len = std::fs::metadata(f)?.len();
            if len == 0 {
                continue;
            }
            let off = (fixtures::splitmix64(&mut state) % len) as usize;
            corrupt_byte(f, off)?;
        }

        let sources = patch_sources_local(&chain, &local)?;
        let outcome = patcher
            .repair(request(
                game_root.path(),
                IndexSource::LocalFile(index_path.clone()),
                sources,
            ))
            .await
            .map_err(|e| format!("iteration {iter}: {e:?}"))?;
        assert!(outcome.repos[0].quarantined.is_empty());

        let now = tree_manifest::author(&repo)?;
        let now_files: Vec<_> = now
            .files
            .iter()
            .filter(|f| !is_ver_or_bck(Path::new(&f.path)))
            .collect();
        let want_files: Vec<_> = baseline.files.iter().collect();
        assert_eq!(
            now_files.len(),
            want_files.len(),
            "iteration {iter}: file count drifted",
        );
        for (a, b) in now_files.iter().zip(&want_files) {
            assert_eq!(a.path, b.path, "iteration {iter}: path drift");
            assert_eq!(
                a.sha256, b.sha256,
                "iteration {iter}: {:?} not healed",
                a.path
            );
        }
    }
    Ok(())
}

/// Local-only patch sources with no server (the property loop needs no network).
fn patch_sources_local(
    chain: &[Vec<u8>],
    local: &[Option<PathBuf>],
) -> Result<Vec<RepairPatchSource>, Box<dyn Error>> {
    let mut out = Vec::with_capacity(chain.len());
    for i in 0..chain.len() {
        out.push(RepairPatchSource {
            name: format!("p{i}.patch"),
            // An unreachable placeholder URL: with a complete local cache it is never dialed.
            url: url::Url::parse(&format!("http://127.0.0.1:9/p{i}.patch"))?,
            local: local.get(i).cloned().flatten(),
        });
    }
    Ok(out)
}

/// Every regular file beneath `root`, excluding the patcher's `.ver`/`.bck` markers.
fn repo_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() && !is_ver_or_bck(&path) {
                out.push(path);
            }
        }
    }
    out
}
