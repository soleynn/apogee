//! The repair pipeline pointed at the worker, end to end.
//!
//! The seam this covers is the one the protocol tests cannot: that `Patcher::repair` routes its
//! heal, its stray quarantine, its version advance and its backup through the boundary, and comes
//! out with the tree it produces in process. The worker runs with this process's own privileges
//! here, which is exactly what the configuration says it does; the only thing a raised-privilege run
//! adds is which process holds the handle, and that is the part no hosted runner can honestly
//! exercise.

use std::error::Error;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use apogee_fetch::Fetcher;
use apogee_patcher::{
    Elevation, GameProbe, IndexSource, PatchError, Patcher, PatcherConfig, RepairPatchSource,
    RepairRepo, RepairRequest, Repo, SePatch, WorkerErrorKind,
};
use apogee_test_support::chaos::ChaosServer;
use apogee_test_support::tree_manifest;
use apogee_zipatch::{Platform, build_index, fixtures};

/// The version the test index and every repair target agree on.
const VERSION: &str = "2024.01.02.0000.0000";

/// The worker binary this package builds, which is what the launcher would ship beside itself.
fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apogee-elevated"))
}

/// A patcher whose repairs write wherever `elevation` says.
fn patcher(store: &Path, elevation: Elevation) -> Result<Patcher, Box<dyn Error>> {
    let fetcher = Fetcher::builder().build()?;
    Ok(Patcher::new(
        fetcher,
        PatcherConfig {
            patch_store: store.to_path_buf(),
            elevation,
            ..PatcherConfig::new(GameProbe::never_running())
        },
    ))
}

/// Write a versioned index over `chain` to `path` as `.apzi`, its sources named to match the served
/// paths.
fn write_index_file(chain: &[Vec<u8>], path: &Path) -> Result<(), Box<dyn Error>> {
    let inputs: Vec<(String, Cursor<Vec<u8>>)> = chain
        .iter()
        .enumerate()
        .map(|(i, p)| (format!("p{i}.patch"), Cursor::new(p.clone())))
        .collect();
    let index = build_index(inputs, Platform::Win32, VERSION)?;
    let mut buf = Vec::new();
    index.write_apzi(&mut buf)?;
    std::fs::write(path, buf)?;
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

/// The per-patch repair sources, HTTP only, so every healed byte crosses the wire and then the
/// boundary.
fn patch_sources(servers: &[ChaosServer]) -> Vec<RepairPatchSource> {
    servers
        .iter()
        .enumerate()
        .map(|(i, s)| RepairPatchSource {
            name: format!("p{i}.patch"),
            url: s.url(&format!("p{i}.patch")),
            local: None,
        })
        .collect()
}

/// A single-repo game repair request.
fn request(game_root: &Path, index: PathBuf, sources: Vec<RepairPatchSource>) -> RepairRequest {
    RepairRequest {
        game_root: game_root.to_path_buf(),
        repos: vec![RepairRepo {
            repo: Repo::Game,
            target_version: VERSION.to_owned(),
            index: IndexSource::LocalFile(index),
            patch_sources: sources,
            source_base_url: None,
            headers: SePatch::new("test-session"),
        }],
    }
}

/// Apply the chain into `game_root/game`, then break it four ways and leave one stray behind.
///
/// The four kinds of damage are the four writes a repair can make: a flipped byte in a stored part,
/// a missing file, a corrupted empty block, and an over-long file. A repair that lost any of them on
/// the way across the boundary comes out different from one that did not.
fn install_and_damage(chain: &[Vec<u8>], game_root: &Path) -> Result<(), Box<dyn Error>> {
    let repo = game_root.join("game");
    std::fs::create_dir_all(&repo)?;
    fixtures::apply_chain(&repo, chain)?;

    let mut exe = std::fs::read(repo.join("ffxivboot.exe"))?;
    exe[0] ^= 0xFF;
    std::fs::write(repo.join("ffxivboot.exe"), exe)?;

    std::fs::remove_file(repo.join("data.bin"))?;

    let dat = repo.join(fixtures::DAT0_PATH);
    let mut bytes = std::fs::read(&dat)?;
    bytes[1024..1032].fill(0xFF);
    bytes.extend_from_slice(&[0xEEu8; 512]);
    std::fs::write(&dat, bytes)?;

    std::fs::write(repo.join("sqpack/ffxiv/leftover.dat"), b"do not delete me")?;
    Ok(())
}

/// Excuse the patcher-written version files when diffing two trees that were both written by it.
fn is_ver_or_bck(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ver" | "bck")
    )
}

/// The same damage healed in process and through a worker produces the same tree, the same version
/// file, the same backup, and the same quarantined stray.
///
/// Byte-for-byte rather than "both look plausible": the whole point of moving the writes into
/// another process is that nothing else about the repair changes, and a differential is the only
/// assertion that actually says so. It also pins the two halves the boundary carries separately, the
/// heal inside the repo subtree and the stray move out of it into the recycler beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_through_a_worker_matches_one_in_process() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();

    // What a clean apply of the same chain leaves, for both runs to be measured against.
    let pristine = tempfile::tempdir()?;
    fixtures::apply_chain(pristine.path(), &chain)?;
    let baseline = tree_manifest::author(pristine.path())?;

    let mut roots = Vec::new();
    for elevation in [Elevation::Never, Elevation::Worker { binary: worker() }] {
        let store = tempfile::tempdir()?;
        let game_root = tempfile::tempdir()?;
        install_and_damage(&chain, game_root.path())?;

        let index_path = store.path().join("game.apzi");
        write_index_file(&chain, &index_path)?;
        let servers = serve(&chain).await?;
        let outcome = patcher(store.path(), elevation)?
            .repair(request(
                game_root.path(),
                index_path,
                patch_sources(&servers),
            ))
            .await?;

        assert_eq!(outcome.repos.len(), 1);
        assert_eq!(outcome.repos[0].version, VERSION);
        assert_eq!(
            outcome.repos[0].recreated, 1,
            "the missing file was rebuilt"
        );
        assert_eq!(outcome.repos[0].resized, 1, "the over-long file was cut");
        assert!(outcome.bytes_refetched > 0, "a broken tree must pull bytes");

        // The stray left the tree and its bytes survive under the recycler, which sits beside the
        // repo subtree rather than inside it.
        let repo = game_root.path().join("game");
        assert!(
            !repo.join("sqpack/ffxiv/leftover.dat").exists(),
            "the stray was left in place"
        );
        assert_eq!(outcome.quarantined.len(), 1);
        assert_eq!(
            std::fs::read(game_root.path().join(&outcome.quarantined[0]))?,
            b"do not delete me",
            "a quarantined stray must keep its bytes",
        );

        tree_manifest::assert_tree_matches(
            &repo,
            &baseline,
            Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
        );
        for name in ["ffxivgame.ver", "ffxivgame.bck"] {
            assert_eq!(
                std::fs::read_to_string(repo.join(name))?,
                VERSION,
                "{name} did not advance",
            );
        }
        roots.push(game_root);
    }

    // And the two runs agree with each other, not merely with the index.
    let elevated = tree_manifest::author(&roots[1].path().join("game"))?;
    tree_manifest::assert_tree_matches(
        &roots[0].path().join("game"),
        &elevated,
        Some(&is_ver_or_bck as &dyn Fn(&Path) -> bool),
    );
    Ok(())
}

/// A healthy repo repairs through a worker without staging a byte, and leaves nothing behind in the
/// patch store.
///
/// The staging file is this process's, in a directory the unprivileged user owns, and a run that
/// never needed one must not create it; a run that did must not leave it. Both halves matter because
/// the file holds bytes destined for a privileged write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_leaves_no_staging_behind() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let store = tempfile::tempdir()?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, &index_path)?;

    for damage in [false, true] {
        let game_root = tempfile::tempdir()?;
        let repo = game_root.path().join("game");
        std::fs::create_dir_all(&repo)?;
        fixtures::apply_chain(&repo, &chain)?;
        if damage {
            let mut exe = std::fs::read(repo.join("ffxivboot.exe"))?;
            exe[0] ^= 0xFF;
            std::fs::write(repo.join("ffxivboot.exe"), exe)?;
        }

        let servers = serve(&chain).await?;
        patcher(store.path(), Elevation::Worker { binary: worker() })?
            .repair(request(
                game_root.path(),
                index_path.clone(),
                patch_sources(&servers),
            ))
            .await?;

        assert!(
            !store.path().join("repair").exists(),
            "a staging file survived a repair (damaged: {damage})",
        );
    }
    Ok(())
}

/// An elevated repair really does stage its bytes rather than write them itself: with nowhere to
/// stage them, it fails naming the staging file.
///
/// This is the one assertion here that can tell the two arms apart. Every other test in this file
/// passes just as well if the worker is started and then quietly bypassed, because this process can
/// write the tree too: on the only platform a hosted runner has, an elevated write and an
/// unprivileged one produce the same bytes. Denying the staging directory is what makes the
/// difference observable, since a repair writing in process would never look for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_elevated_repair_stages_its_bytes_rather_than_writing_them_itself()
-> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let chain = fixtures::chain();
    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    install_and_damage(&chain, game_root.path())?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, &index_path)?;

    // Running as root defeats the mode bits entirely, and a container build often does. Asked of a
    // file this test just made rather than of a process API, so it needs no extra dependency.
    let owner = std::fs::metadata(&index_path)?;
    if std::os::unix::fs::MetadataExt::uid(&owner) == 0 {
        return Ok(());
    }

    let servers = serve(&chain).await?;
    let denied = store.path().join("denied");
    std::fs::create_dir(&denied)?;
    std::fs::copy(&index_path, denied.join("game.apzi"))?;
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o500))?;

    let outcome = patcher(&denied, Elevation::Worker { binary: worker() })?
        .repair(request(
            game_root.path(),
            denied.join("game.apzi"),
            patch_sources(&servers),
        ))
        .await;
    // Restore the mode before asserting, so a failure does not leave the tempdir undeletable.
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700))?;

    let err = outcome.expect_err("a repair that cannot stage its bytes must not report success");
    let PatchError::Io { path, .. } = &err else {
        panic!("expected the failure to name the staging file, got {err:?}");
    };
    assert!(
        path.starts_with(&denied),
        "the failure should name the staging file under the patch store: {path:?}",
    );
    Ok(())
}

/// A worker that cannot be started fails the repair as a typed value, before anything is verified.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_cannot_be_started_fails_the_repair() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let store = tempfile::tempdir()?;
    let game_root = tempfile::tempdir()?;
    install_and_damage(&chain, game_root.path())?;
    let index_path = store.path().join("game.apzi");
    write_index_file(&chain, &index_path)?;

    let missing = store.path().join("no-such-worker");
    let err = patcher(store.path(), Elevation::Worker { binary: missing })?
        .repair(request(game_root.path(), index_path, Vec::new()))
        .await
        .expect_err("an unreachable worker must fail the repair");

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
    // Nothing was touched: the stray is still where it was, unquarantined.
    assert!(
        game_root
            .path()
            .join("game/sqpack/ffxiv/leftover.dat")
            .exists(),
        "a repair that could not start still moved a file",
    );
    Ok(())
}
