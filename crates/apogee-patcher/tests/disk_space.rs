//! The patcher's disk-space story end to end, both halves and the seam between them.
//!
//! The halves are distinct and neither covers for the other, which is what these tests are for. The
//! preflight is an estimate taken before any byte moves, it can be wrong in either direction, and
//! [`PatcherConfig::ignore_space`] turns it off outright; the observation is `apogee-fetch`'s eager
//! preallocation, which sees the refusal itself. The case the estimate exists to catch and
//! structurally cannot see is the disk filling mid-install, so an observation that folds into
//! "acquire failed" leaves a caller matching on the space arms seeing only the guess.
//!
//! Both halves are covered per pool, because the two pools are not symmetric. The patch store is
//! where fetch writes, so a bad estimate there is caught by the observation; the game root is where
//! nothing but the apply writes, so its estimate is the only guard standing in front of it and is
//! pinned on its own. On the observation side, the install's patch downloads and the repair's index
//! download are separate fetches with separately written routing, and each has a plausible generic
//! arm (`Acquire`, `IndexUnavailable`) to be swallowed by.
//!
//! The mechanism is the one `apogee-fetch`'s own `tests/disk_full.rs` uses, for the same safety
//! reason: the pool under test sits on a memory-backed filesystem whose size is known, so a request
//! past it is answered with `ENOSPC` without reserving a block. A disk-backed volume would instead
//! allocate its way toward the request and take the host's free space with it. That is also why the
//! apply side has no test here: `apogee-zipatch`'s sink declares no length to be refused up front,
//! it writes its way to the end of the volume, so injecting one would mean genuinely filling a
//! filesystem this process does not own.

#![cfg(target_os = "linux")]

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use apogee_fetch::{DigestPin, Fetcher};
use apogee_patcher::{
    GameProbe, IndexSource, InstallRequest, PatchError, Patcher, PatcherConfig, PreflightError,
    RepairRepo, RepairRequest, Repo, SePatch, SpacePool,
};
use apogee_test_support::capacity::{MemoryBackedDir, memory_backed_dir};
use apogee_test_support::chaos::ChaosServer;
use apogee_zipatch::fixtures;
use sqex_proto::PatchListEntry;
use url::Url;

/// The slack the one `bytes=0-0` range-capability probe is worth in a byte count. The probe drops
/// the body unread, so whether its single byte is counted depends on the server's body task being
/// scheduled before the connection goes away.
const PROBE: u64 = 1;

/// A boot patchlist entry pointing at `url` and *claiming* `length`.
///
/// Boot is the repo that can carry a claimed length at all. A game entry's length has to agree with
/// its per-block SHA1 list (the spec builder rejects a layout where they disagree), so declaring one
/// past a filesystem's capacity would mean handing over a hash list with billions of entries in it.
/// A boot patchlist carries no hashes: the declared length is the whole fetch-side contract, which
/// is exactly the knob this needs.
fn boot_entry(url: Url, length: u64) -> PatchListEntry {
    PatchListEntry {
        length,
        version_id: "2024.03.27.0000.0000".to_owned(),
        url: url.to_string(),
        hashes: None,
    }
}

fn boot_request(game_root: &Path, patches: Vec<PatchListEntry>) -> InstallRequest {
    InstallRequest {
        repo: Repo::Boot,
        game_root: game_root.to_path_buf(),
        patches,
        headers: SePatch::boot(),
    }
}

/// A patcher whose patch store is `store`, with the preflight on or off.
fn patcher(store: &Path, ignore_space: bool) -> Result<Patcher, Box<dyn Error>> {
    let fetcher = Fetcher::builder()
        .stall_timeout(Duration::from_secs(5))
        .build()?;
    Ok(Patcher::new(
        fetcher,
        PatcherConfig {
            patch_store: store.to_path_buf(),
            keep_patches: true,
            ignore_space,
            ..PatcherConfig::new(GameProbe::never_running())
        },
    ))
}

/// A single-repo game repair whose block index is pulled from `url` under `pin`.
///
/// The index fetch is the first thing a repair does after the game-running guard, before the tree is
/// read at all, so the game root needs nothing in it for this to reach the download.
fn index_repair(game_root: &Path, url: Url, pin: DigestPin) -> RepairRequest {
    RepairRequest {
        game_root: game_root.to_path_buf(),
        repos: vec![RepairRepo {
            repo: Repo::Game,
            target_version: "2024.01.02.0000.0000".to_owned(),
            index: IndexSource::Pinned { url, pin },
            patch_sources: Vec::new(),
            source_base_url: None,
            headers: SePatch::new("test-session"),
        }],
    }
}

/// A memory-backed patch store, a normal game root, and an origin serving one real boot patch under
/// a declared length that store's filesystem can never hold.
async fn oversized_boot_install() -> Result<
    (
        MemoryBackedDir,
        tempfile::TempDir,
        ChaosServer,
        PatchListEntry,
    ),
    Box<dyn Error>,
> {
    let store = memory_backed_dir("apogee-patcher-disk-full-")?;
    let game_root = tempfile::tempdir()?;
    let patch = fixtures::chain().remove(0);
    let server = ChaosServer::serving(patch).start().await?;
    let entry = boot_entry(server.url("p0.patch"), store.beyond_capacity());
    Ok((store, game_root, server, entry))
}

/// With the preflight skipped, the disk filling during the transfer is still typed as a space
/// failure: the backstop the preflight's own contract names.
///
/// `ignore_space` is what makes this the backstop and not the estimate running again. It is also the
/// realistic shape: the escape hatch exists for a caller that knows better than the heuristic, and
/// the guarantee is that using it costs the *prediction*, not the *detection*.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disk_that_fills_mid_install_is_typed_as_a_space_failure() -> Result<(), Box<dyn Error>> {
    let (store, game_root, server, entry) = oversized_boot_install().await?;
    let patcher = patcher(store.path(), true)?;

    let err = patcher
        .install(boot_request(game_root.path(), vec![entry]))
        .await
        .expect_err("a length past the filesystem capacity must not install");

    let PatchError::OutOfSpace { path, source } = &err else {
        panic!("a full disk must not arrive as a generic acquire failure, got {err:?}");
    };
    // The path is the actionable half: it says which volume to make room on, which the patch store
    // and the game root being different filesystems is precisely why a caller cannot infer.
    assert!(
        path.starts_with(store.path()),
        "want the refused path under the patch store {:?}, got {path:?}",
        store.path(),
    );
    // And the kind survives the routing, so a caller that does want to look still can, and so the
    // arm cannot be reached by anything other than a genuine `ENOSPC`.
    assert_eq!(
        source.kind(),
        std::io::ErrorKind::StorageFull,
        "want disk-full and not some other i/o fault, got {source:?}",
    );

    // Eager, not after the fact: the origin was asked for the capability probe and nothing else, so
    // the failure landed before a payload byte was requested rather than after gigabytes of it. The
    // same claim `apogee-fetch`'s disk_full test makes, restated here because it is the patcher's
    // scheduler that decides when a transfer starts.
    let stats = server.stats();
    assert_eq!(
        stats.requests(),
        1,
        "only the capability probe should have been sent; ranges served: {:?}",
        stats.served_ranges(),
    );
    assert!(
        stats.bytes_served() <= PROBE,
        "origin served {} bytes before the reservation failed",
        stats.bytes_served(),
    );

    // Nothing was applied: the boot subtree was never created and `.ver` never advanced.
    assert!(
        !game_root.path().join("boot").exists(),
        "a failed acquire applied bytes to the game root",
    );
    Ok(())
}

/// The same install with the preflight on stops at the estimate instead, under its own arm.
///
/// The pair is the point. One run reports a pool with a needed/free pair and nothing has been
/// attempted; the other reports a path and the filesystem has already refused it. Collapsing them
/// into one variant would make "did anything happen?" unanswerable from the error, and leaving the
/// second one untyped would make the first the only space failure a caller can match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_preflight_estimate_stops_the_same_install_under_its_own_arm()
-> Result<(), Box<dyn Error>> {
    let (store, game_root, server, entry) = oversized_boot_install().await?;
    let patcher = patcher(store.path(), false)?;

    let err = patcher
        .install(boot_request(game_root.path(), vec![entry]))
        .await
        .expect_err("a length past the filesystem capacity must not install");

    assert!(
        matches!(
            err,
            PatchError::Preflight(PreflightError::NotEnoughSpace {
                pool: SpacePool::PatchStore,
                ..
            })
        ),
        "want the preflight estimate, got {err:?}",
    );
    // A prediction is made without contacting anybody.
    assert_eq!(
        server.stats().requests(),
        0,
        "the preflight refused an install after talking to the origin",
    );
    Ok(())
}

/// Two pools on one filesystem are one requirement, and the estimate has to add them up.
///
/// The install here fits either pool's need twice over and does not fit both at once, which is what
/// a patch store under the game root (or both under one home directory) makes ordinary. Guarding
/// each pool against its own reading of the same mount passes it: the reading is the same 100% of
/// free space both times, and each half asks for well under that. With `keep_patches` on the two
/// needs are equal, so the gap is a clean factor of two.
///
/// The sizes come from a live reading rather than a fraction of the mount's capacity, because
/// `/dev/shm` is shared with whatever else is running and a fixed fraction is a guess about how busy
/// the host is. Both inequalities are asserted before the install, so a host where the arithmetic
/// degenerates fails loudly here instead of passing for the wrong reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pools_sharing_a_filesystem_are_guarded_against_their_combined_need()
-> Result<(), Box<dyn Error>> {
    let scratch = memory_backed_dir("apogee-patcher-shared-fs-")?;
    let store_dir = scratch.path().join("patches");
    let game_dir = scratch.path().join("game-root");
    std::fs::create_dir_all(&store_dir)?;
    std::fs::create_dir_all(&game_dir)?;

    // 60% of free space each: either alone fits, the two together cannot.
    let free = scratch.available()?;
    let per_pool = free / 10 * 6;
    assert!(
        per_pool < free,
        "each pool must fit on its own or this proves nothing (need {per_pool}, free {free})",
    );
    assert!(
        per_pool * 2 > free,
        "the two together must not fit (need {}, free {free})",
        per_pool * 2,
    );

    // `keep_patches` makes both needs the whole patch total, so one entry sizes both pools.
    let patcher = patcher(&store_dir, false)?;
    let entry = boot_entry(Url::parse("http://127.0.0.1:9/p0.patch")?, per_pool);

    let err = patcher
        .install(boot_request(&game_dir, vec![entry]))
        .await
        .expect_err("an install needing twice the free space must be refused");

    let PatchError::Preflight(PreflightError::NotEnoughSpace {
        pool,
        needed,
        free: got,
    }) = &err
    else {
        panic!("want the preflight estimate, got {err:?}");
    };
    assert_eq!(
        *pool,
        SpacePool::SharedFilesystem,
        "one volume must not be reported as one of the two pools that share it",
    );
    assert_eq!(*needed, per_pool * 2, "the two needs were not summed");
    assert!(
        *needed > *got,
        "the reported pair does not describe a shortfall (need {needed}, have {got})",
    );
    Ok(())
}

/// How long the index origin sits on its first chunk. Far longer than the stall timeout paired with
/// it, so a regression that streams the body fails fast instead of hanging.
const WILLING_BUT_SLOW: Duration = Duration::from_secs(30);

/// A repair whose block index cannot be reserved reports a full disk, not an unreachable index.
///
/// The index is a download like any other and lands in the same patch store the patches do, so the
/// store filling is a failure this fetch can produce. `IndexUnavailable` is the arm beside it, and it
/// is the wrong answer in the most expensive way: it says the catalog or the network is at fault and
/// sends the user checking both, while the actual repair is one deleted file away from working.
///
/// The whole difference is one hand-written arm at the fetch's error boundary. Nothing else in the
/// repair suite distinguishes the two, so without this the arm can be deleted and every test still
/// passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_index_that_cannot_be_reserved_is_typed_as_a_space_failure()
-> Result<(), Box<dyn Error>> {
    let store = memory_backed_dir("apogee-patcher-index-disk-full-")?;
    let game_root = tempfile::tempdir()?;
    // No declared length travels with an index download, so the reservation is taken from the
    // response's own `Content-Length`: announcing one past the store's filesystem is what refuses it.
    let server = ChaosServer::builder(7, store.beyond_capacity())
        .throttle(WILLING_BUT_SLOW)
        .start()
        .await?;

    // The pin is one the served bytes could never hash to, and the run must not get far enough to
    // care: the reservation is refused before a payload byte arrives, so nothing is ever hashed.
    // Were that to regress, the failure would land on `IndexUnavailable`, which is the arm this
    // asserts against, so the wrong pin cannot make the test pass for the wrong reason.
    let request = index_repair(
        game_root.path(),
        server.url("game.apzi"),
        DigestPin::Sha256([0u8; 32]),
    );
    let err = patcher(store.path(), false)?
        .repair(request)
        .await
        .expect_err("an index past the filesystem capacity must not be acquired");

    let PatchError::OutOfSpace { path, source } = &err else {
        panic!("a full disk must not arrive as an unavailable index, got {err:?}");
    };
    // The path is the actionable half, and here it is more actionable than on the install path: the
    // index cache is a directory the user can clear on its own.
    let indexes = store.path().join("indexes");
    assert!(
        path.starts_with(&indexes),
        "want the refused path under {indexes:?}, got {path:?}",
    );
    assert_eq!(
        source.kind(),
        std::io::ErrorKind::StorageFull,
        "want disk-full and not some other i/o fault, got {source:?}",
    );

    // Eager, not after the fact. The origin has answered, announced its length and generated its
    // first chunk, so only the throttle keeps that chunk off the wire: a byte count of zero is the
    // client refusing before the payload rather than a server with nothing to give.
    assert_eq!(
        server.stats().bytes_served(),
        0,
        "the origin served a payload byte before the reservation failed",
    );
    Ok(())
}

/// The per-patch length below, small enough that the store's rolling window of six of them is 48 MiB
/// on any host, so the store's own estimate cannot be what refuses the install.
const WINDOWED_PATCH: u64 = 8 * 1024 * 1024;

/// The game root is predicted against its own filesystem, and it is the pool with nothing behind it.
///
/// The two pools look alike in the error type and are not alike underneath. A patch store the
/// estimate misjudges is caught by fetch's reservation, which is where every downloaded byte lands;
/// the game root is written only by the apply, which declares no length any filesystem can refuse up
/// front, so nothing observes it filling until a write partway through a patch fails. That makes this
/// estimate the only thing standing in front of the pool, and it has to be taken against the game
/// root's filesystem rather than the store's, which is the transposition this pins.
///
/// The sizes make the store unable to be the answer: many small patches, so the applied total is
/// twice what the game root holds while the store's rolling window stays at six times one patch.
/// Both inequalities are asserted before the install, so a host where the arithmetic degenerates
/// fails loudly here instead of passing for the wrong reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_game_root_pool_is_predicted_against_its_own_filesystem() -> Result<(), Box<dyn Error>>
{
    let game_root = memory_backed_dir("apogee-patcher-game-root-full-")?;
    let store = tempfile::tempdir()?;

    let free = game_root.available()?;
    let count = free / WINDOWED_PATCH * 2 + 2;
    let total = WINDOWED_PATCH * count;
    let window = WINDOWED_PATCH * 6;
    assert!(
        total > free,
        "the applied result must not fit in the game root (need {total}, free {free})",
    );
    // The same reading the preflight will take of the store, so a host too full to make the store
    // the passing pool says so here rather than reporting the wrong pool below.
    let vfs = rustix::fs::statvfs(store.path())?;
    let store_free = vfs.f_bavail.saturating_mul(vfs.f_frsize);
    assert!(
        window < store_free,
        "the store must have room for its window or this proves nothing \
         (need {window}, free {store_free})",
    );

    // Unreachable on purpose: a prediction is made without contacting anybody, and the request never
    // reaches the point of building a download.
    let url = Url::parse("http://127.0.0.1:9/p0.patch")?;
    let patches = (0..count)
        .map(|_| boot_entry(url.clone(), WINDOWED_PATCH))
        .collect();

    let err = patcher(store.path(), false)?
        .install(boot_request(game_root.path(), patches))
        .await
        .expect_err("an install past what the game root holds must be refused");

    let PatchError::Preflight(PreflightError::NotEnoughSpace {
        pool,
        needed,
        free: got,
    }) = &err
    else {
        panic!("want the preflight estimate, got {err:?}");
    };
    assert_eq!(
        *pool,
        SpacePool::GameRoot,
        "the short pool is the game root, not the store the downloads fit in",
    );
    assert_eq!(*needed, total, "the applied result was not summed whole");
    assert!(
        *needed > *got,
        "the reported pair does not describe a shortfall (need {needed}, have {got})",
    );
    Ok(())
}
