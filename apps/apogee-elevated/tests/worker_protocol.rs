//! The worker driven as a real process over the protocol.
//!
//! Everything the privileged side promises is asserted here against the shipping binary rather than
//! an in-process stand-in: it re-proves the bytes it is handed, it refuses a path that would leave
//! the tree it was bound to, it advances a version file only after a clean apply, and it can be
//! killed part way through without taking the process driving it with it.
//!
//! The transport is the worker's standard streams, which is the one thing here that is not what
//! Windows uses (there the same worker connects back over a named pipe, because the call that raises
//! privileges cannot redirect a handle). Every other byte of this is the shipping path, so the same
//! file runs on both platforms and the transport is the only part a Windows runner adds.

mod support;

use std::error::Error;
use std::path::Path;

use apogee_elevate::{Error as ElevateError, VersionWrite, WorkerErrorKind};
use apogee_zipatch::fixtures;
use tokio_util::sync::CancellationToken;

use support::{BLOCK_SIZE, block_sha1, chunk_crc, place, start, wide_expected, wide_patch};

/// The version file the fixtures advance, relative to the bound tree.
const VER: &str = "ffxivgame.ver";

/// A run long enough that a kill landing on the first progress frame is nowhere near the end: sixty
/// four megabytes of writes out of a patch file measured in kilobytes.
const WIDE_CHUNKS: usize = 64;
const WIDE_CHUNK_LEN: usize = 1 << 20;

fn version(contents: &str) -> Option<VersionWrite> {
    Some(VersionWrite {
        path: VER.to_owned(),
        contents: contents.to_owned(),
    })
}

/// The whole happy path: a two-patch chain applies through the worker to the same tree a direct
/// apply produces, the version file advances once per patch, and the backup is taken at the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_worker_applies_a_chain_and_advances_the_version() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();

    // The baseline: the same chain applied in this process, with no worker involved.
    let baseline = tempfile::tempdir()?;
    fixtures::apply_chain(baseline.path(), &chain)?;

    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;

    for (i, patch) in chain.iter().enumerate() {
        let path = place(store.path(), &format!("p{i}.patch"), patch)?;
        harness
            .session
            .apply(
                &path,
                block_sha1(patch),
                version(&format!("2024.01.0{}.0000.0000", i + 1)),
                &CancellationToken::new(),
                |_| {},
            )
            .await?;
    }
    harness.session.copy_within(VER, "ffxivgame.bck").await?;

    assert_eq!(
        std::fs::read(root.path().join(fixtures::DAT0_PATH))?,
        std::fs::read(baseline.path().join(fixtures::DAT0_PATH))?,
        "the privileged apply produced different bytes from the in-process one",
    );
    assert!(
        !root.path().join("old.txt").exists(),
        "a delete was skipped"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join(VER))?,
        "2024.01.02.0000.0000"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("ffxivgame.bck"))?,
        "2024.01.02.0000.0000"
    );
    Ok(())
}

/// A patch swapped on disk after the parent verified it is refused, and nothing is written.
///
/// This is the reason the worker verifies at all. The proof the parent took is a value in the
/// parent, and the store it took it over is writable by the same unprivileged user, so the only
/// thing standing between a swap and a privileged write is the privileged side checking again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_swapped_after_the_parent_verified_it_is_refused() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;

    // The digests describe the first patch; the bytes on disk are the second, which is a perfectly
    // valid patch that this admission does not describe.
    let admission = block_sha1(&chain[0]);
    let path = place(store.path(), "swapped.patch", &chain[1])?;

    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;
    let err = harness
        .session
        .apply(
            &path,
            admission,
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("a patch that does not match its digests must not be applied");

    let ElevateError::Worker {
        kind: WorkerErrorKind::Verify,
        failed_file: Some(named),
        ..
    } = &err
    else {
        panic!("expected a typed verification refusal naming the patch, got {err:?}");
    };
    assert_eq!(named, &path);

    // Nothing was written: not the tree, and not the version file.
    assert!(
        !root.path().join(fixtures::DAT0_PATH).exists(),
        "a refused patch still reached the sink"
    );
    assert!(!root.path().join(VER).exists());

    // And the session survives a refusal: the same worker applies the patch the digests do describe.
    let good = place(store.path(), "good.patch", &chain[0])?;
    harness
        .session
        .apply(
            &good,
            block_sha1(&chain[0]),
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await?;
    assert_eq!(
        std::fs::read_to_string(root.path().join(VER))?,
        "2024.01.01.0000.0000"
    );
    Ok(())
}

/// A patch shorter or longer than the digests describe is refused as well, not silently truncated
/// to the digests it does have.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_that_is_not_the_length_its_digests_describe_is_refused()
-> Result<(), Box<dyn Error>> {
    let patch = fixtures::patch_a();
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;

    let mut long = patch.clone();
    long.extend_from_slice(&[0u8; BLOCK_SIZE]);
    let mut short = patch.clone();
    short.truncate(patch.len() - BLOCK_SIZE);

    for (name, bytes) in [("long.patch", &long), ("short.patch", &short)] {
        let path = place(store.path(), name, bytes)?;
        let err = harness
            .session
            .apply(
                &path,
                block_sha1(&patch),
                None,
                &CancellationToken::new(),
                |_| {},
            )
            .await
            .expect_err("a length the digests do not cover must not be applied");
        assert!(
            matches!(
                err,
                ElevateError::Worker {
                    kind: WorkerErrorKind::Verify,
                    ..
                }
            ),
            "{name}: got {err:?}"
        );
    }
    Ok(())
}

/// A boot patch is admitted by its chunk CRC, and one whose bytes were flipped is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_boot_patch_is_admitted_by_its_chunk_crc() -> Result<(), Box<dyn Error>> {
    let patch = fixtures::patch_a();
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;

    // Flip a byte deep in the payload: the length is intact, so only the chunk CRC catches it.
    let mut corrupt = patch.clone();
    let victim = corrupt.len() / 2;
    corrupt[victim] ^= 0xff;
    let bad = place(store.path(), "corrupt.patch", &corrupt)?;
    let err = harness
        .session
        .apply(
            &bad,
            chunk_crc(&patch),
            None,
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("a boot patch failing its chunk crc must not be applied");
    assert!(
        matches!(
            err,
            ElevateError::Worker {
                kind: WorkerErrorKind::Verify,
                ..
            }
        ),
        "got {err:?}"
    );
    assert!(!root.path().join(fixtures::DAT0_PATH).exists());

    let good = place(store.path(), "boot.patch", &patch)?;
    harness
        .session
        .apply(
            &good,
            chunk_crc(&patch),
            None,
            &CancellationToken::new(),
            |_| {},
        )
        .await?;
    assert!(root.path().join(fixtures::DAT0_PATH).exists());
    Ok(())
}

/// A boot patch swapped for a different, perfectly well-formed patch is refused.
///
/// This is the case the chunk CRC cannot cover and the reason the boot admission carries a digest at
/// all. The substitute here is a real patch with correct CRCs throughout, which is exactly what an
/// attacker who can write to the patch store would produce: a checksum they recompute is not a check
/// on them. Only the digest the launcher took over the bytes it actually admitted separates the two.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_boot_patch_swapped_for_another_valid_patch_is_refused() -> Result<(), Box<dyn Error>> {
    let admitted = fixtures::patch_a();
    let substitute = fixtures::patch_b();
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;

    // Prove the substitute is not merely malformed: its own chunk CRCs are correct, so the scan
    // alone would wave it through.
    let path = place(store.path(), "swapped.patch", &substitute)?;
    harness
        .session
        .apply(
            &path,
            chunk_crc(&substitute),
            None,
            &CancellationToken::new(),
            |_| {},
        )
        .await?;

    let path = place(store.path(), "swapped2.patch", &substitute)?;
    let err = harness
        .session
        .apply(
            &path,
            chunk_crc(&admitted),
            None,
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("a patch that is not the one the launcher admitted must not be applied");
    let ElevateError::Worker {
        kind: WorkerErrorKind::Verify,
        detail,
        ..
    } = &err
    else {
        panic!("expected a typed verification refusal, got {err:?}");
    };
    assert!(detail.contains("admitted"), "{detail}");
    Ok(())
}

/// Every path the parent names is confined: a version file that would climb out of the bound tree,
/// and a backup copy that would land outside it, are both refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_that_would_leave_the_bound_tree_is_refused() -> Result<(), Box<dyn Error>> {
    let patch = fixtures::patch_a();
    let store = tempfile::tempdir()?;
    let base = tempfile::tempdir()?;
    let root = base.path().join("game");
    std::fs::create_dir_all(&root)?;
    let path = place(store.path(), "p.patch", &patch)?;

    let mut harness = start().await?;
    harness.session.bind(&root).await?;
    let err = harness
        .session
        .apply(
            &path,
            block_sha1(&patch),
            Some(VersionWrite {
                path: "../escaped.ver".to_owned(),
                contents: "2024.01.01.0000.0000".to_owned(),
            }),
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("a version path climbing out of the tree must be refused");
    assert!(
        matches!(
            err,
            ElevateError::Worker {
                kind: WorkerErrorKind::Protocol,
                ..
            }
        ),
        "got {err:?}"
    );
    // Refused before the apply, not after it: a patch is not half-applied and then complained about.
    assert!(!base.path().join("escaped.ver").exists());
    assert!(!root.join(fixtures::DAT0_PATH).exists());

    let escape = harness
        .session
        .copy_within(VER, "../escaped.bck")
        .await
        .expect_err("a backup landing outside the tree must be refused");
    assert!(
        matches!(
            escape,
            ElevateError::Worker {
                kind: WorkerErrorKind::Protocol,
                ..
            }
        ),
        "got {escape:?}"
    );
    Ok(())
}

/// The session refuses to work before it is bound, and refuses a root it cannot resolve on its own.
///
/// The absolute-root rule is not pedantry: a process started through the elevation verb does not
/// inherit the launcher's working directory, so a relative root there names a different place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbound_or_relative_root_is_refused() -> Result<(), Box<dyn Error>> {
    let patch = fixtures::patch_a();
    let store = tempfile::tempdir()?;
    let path = place(store.path(), "p.patch", &patch)?;

    let mut harness = start().await?;
    let unbound = harness
        .session
        .apply(
            &path,
            block_sha1(&patch),
            None,
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("an unbound session must not apply anything");
    assert!(
        matches!(
            unbound,
            ElevateError::Worker {
                kind: WorkerErrorKind::Protocol,
                ..
            }
        ),
        "got {unbound:?}"
    );

    let relative = harness
        .session
        .bind(Path::new("game"))
        .await
        .expect_err("a relative apply root must be refused");
    assert!(
        matches!(
            relative,
            ElevateError::Worker {
                kind: WorkerErrorKind::Protocol,
                ..
            }
        ),
        "got {relative:?}"
    );
    Ok(())
}

/// Killing the worker part way through an apply is a typed failure, and the process driving it
/// carries on.
///
/// The four claims, in order: the caller gets a value rather than a signal, this process is still
/// running to make the assertion, the version file did not advance past the patch that was torn, and
/// a re-run over a fresh worker converges on the tree the patch describes. The kill is a real
/// `SIGKILL`-class termination of the shipping binary from outside, not a fault hook compiled into
/// it: the worker has no code path that ends itself, which is the property under test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killing_the_worker_mid_apply_is_a_typed_failure_the_parent_survives()
-> Result<(), Box<dyn Error>> {
    let patch = wide_patch("big.bin", WIDE_CHUNKS, WIDE_CHUNK_LEN);
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let path = place(store.path(), "wide.patch", &patch)?;

    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;

    // The first progress frame means the apply is under way and, with sixty four runs to write, that
    // it is roughly one sixty-fourth of the way through it.
    let mut child = harness.child;
    let mut killed = false;
    let err = harness
        .session
        .apply(
            &path,
            block_sha1(&patch),
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |frame| {
                if !killed && matches!(frame, apogee_elevate::WorkerProgress::Applying { .. }) {
                    killed = true;
                    let _ = child.start_kill();
                }
            },
        )
        .await
        .expect_err("a worker killed mid-apply must not report success");

    assert!(killed, "the apply finished before it could be interrupted");
    assert!(
        matches!(err, ElevateError::Gone),
        "a dead worker must arrive as a typed value, got {err:?}"
    );
    // This assertion running at all is the anti-crash claim: the caller was not taken down with it.
    assert!(
        !root.path().join(VER).exists(),
        "the version advanced over a torn apply"
    );

    // Re-run against a fresh worker: the writes are positioned, so the partial tree converges.
    let mut second = start().await?;
    second.session.bind(root.path()).await?;
    second
        .session
        .apply(
            &path,
            block_sha1(&patch),
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await?;
    assert_eq!(
        std::fs::read(root.path().join("big.bin"))?,
        wide_expected(WIDE_CHUNKS, WIDE_CHUNK_LEN),
        "the re-run did not converge on the tree the patch describes",
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join(VER))?,
        "2024.01.01.0000.0000"
    );
    Ok(())
}

/// A cancel mid-apply stops the privileged writes, leaves the version alone, and leaves the worker
/// usable.
///
/// Cancelling by dropping the stream would leave an elevated process still writing into the tree,
/// which is why there is a message for it at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_mid_apply_stops_the_worker_and_leaves_it_usable() -> Result<(), Box<dyn Error>> {
    let wide = wide_patch("big.bin", WIDE_CHUNKS, WIDE_CHUNK_LEN);
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let path = place(store.path(), "wide.patch", &wide)?;

    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;

    let cancel = CancellationToken::new();
    let err = harness
        .session
        .apply(
            &path,
            block_sha1(&wide),
            version("2024.01.01.0000.0000"),
            &cancel,
            |frame| {
                if matches!(frame, apogee_elevate::WorkerProgress::Applying { .. }) {
                    cancel.cancel();
                }
            },
        )
        .await
        .expect_err("a cancelled apply must not report success");
    assert!(matches!(err, ElevateError::Cancelled), "got {err:?}");
    assert!(
        !root.path().join(VER).exists(),
        "the version advanced over a cancelled apply"
    );

    // The worker is still there, and a cancel does not carry over to the next request.
    let small = fixtures::patch_a();
    let second = place(store.path(), "small.patch", &small)?;
    harness
        .session
        .apply(
            &second,
            block_sha1(&small),
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await?;
    assert_eq!(
        std::fs::read_to_string(root.path().join(VER))?,
        "2024.01.01.0000.0000"
    );
    Ok(())
}
