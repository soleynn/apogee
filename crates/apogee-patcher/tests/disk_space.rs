//! The patcher's disk-space story end to end, both halves and the seam between them.
//!
//! The halves are distinct and neither covers for the other, which is what these tests are for. The
//! preflight is an estimate taken before any byte moves, it can be wrong in either direction, and
//! [`PatcherConfig::ignore_space`] turns it off outright; the backstop is `apogee-fetch`'s eager
//! preallocation, which observes the refusal itself. The case the estimate exists to catch and
//! structurally cannot see is the disk filling mid-install, so a backstop that folds into
//! "acquire failed" leaves a caller matching on the space arms seeing only the guess. The third test
//! covers the estimate's own blind spot: two pools that turn out to be one filesystem.
//!
//! The mechanism is the one `apogee-fetch`'s own `tests/disk_full.rs` uses, for the same safety
//! reason: the pools sit on a memory-backed filesystem whose size is known and small, so a request
//! past it is answered with `ENOSPC` without reserving a block. A disk-backed volume would instead
//! allocate its way toward the request and take the host's free space with it.

#![cfg(target_os = "linux")]

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use apogee_fetch::Fetcher;
use apogee_patcher::{
    GameProbe, InstallRequest, PatchError, Patcher, PatcherConfig, PreflightError, Repo, SePatch,
    SpacePool,
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
