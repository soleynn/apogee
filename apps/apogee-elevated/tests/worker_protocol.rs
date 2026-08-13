//! The worker driven as a real process over the protocol.
//!
//! Everything the privileged side promises is asserted here against the shipping binary rather than
//! an in-process stand-in: it re-proves the bytes it is handed, whether they arrive as a patch to
//! apply or as a repair's staged spans; it refuses a path that would leave the tree it was bound to;
//! it advances a version file only after clean work; and it can be killed part way through either
//! without taking the process driving it with it.
//!
//! The transport is the worker's standard streams, which is the one thing here that is not what
//! Windows uses (there the same worker connects back over a named pipe, because the call that raises
//! privileges cannot redirect a handle). Every other byte of this is the shipping path, so the same
//! file runs on both platforms and the transport is the only part a Windows runner adds.

mod support;

use std::error::Error;
use std::path::Path;

use apogee_elevate::{Error as ElevateError, StagedOp, StagedWrite, VersionWrite, WorkerErrorKind};
use apogee_zipatch::fixtures;
use tokio_util::sync::CancellationToken;

use support::{
    BLOCK_SIZE, block_sha1, chunk_crc, filler, place, stage, start, wide_expected, wide_patch,
};

/// The version file the fixtures advance, relative to the bound tree.
const VER: &str = "ffxivgame.ver";

/// A run long enough that a kill landing on the first progress frame is nowhere near the end: sixty
/// four megabytes of writes out of a patch file measured in kilobytes.
const WIDE_CHUNKS: usize = 64;
const WIDE_CHUNK_LEN: usize = 1 << 20;

/// The same idea for a repair, at a third the size. A repair reports every eight megabytes written,
/// so the kill lands with two thirds of the batch outstanding; that is hundreds of milliseconds of
/// writing against a kill delivered in well under one, and the whole fixture is staged on disk twice
/// (once by the test, once read back by the worker) so its size is what the test costs.
const REPAIR_SPANS: usize = 24;
const REPAIR_SPAN_LEN: usize = 1 << 20;

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

/// The repair happy path: a batch of staged writes rebuilds one file, resizes another and rewrites a
/// span of a third, and only then does the version file advance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_of_staged_writes_heals_a_tree_and_advances_the_version()
-> Result<(), Box<dyn Error>> {
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("long.bin"), vec![0xAAu8; 64])?;
    std::fs::write(root.path().join("broken.bin"), vec![0xAAu8; 32])?;

    let staging = store.path().join("staged.bin");
    let mut writes = vec![
        StagedWrite {
            path: "sub/fresh.bin".to_owned(),
            op: StagedOp::Create { len: 24 },
        },
        StagedWrite {
            path: "long.bin".to_owned(),
            op: StagedOp::Resize { len: 16 },
        },
        StagedWrite {
            path: "broken.bin".to_owned(),
            op: StagedOp::Zeros { off: 16, len: 16 },
        },
    ];
    writes.extend(stage(
        &staging,
        &[
            ("sub/fresh.bin", 0, vec![0x11u8; 8]),
            ("broken.bin", 0, vec![0x22u8; 8]),
        ],
    )?);

    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;
    harness
        .session
        .repair(
            Some(&staging),
            writes,
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await?;

    // A created file is sized and holds the staged bytes over a zeroed remainder.
    let fresh = std::fs::read(root.path().join("sub/fresh.bin"))?;
    assert_eq!(fresh.len(), 24);
    assert_eq!(&fresh[..8], &[0x11u8; 8]);
    assert_eq!(&fresh[8..], &[0u8; 16]);
    assert_eq!(std::fs::metadata(root.path().join("long.bin"))?.len(), 16);
    let broken = std::fs::read(root.path().join("broken.bin"))?;
    assert_eq!(&broken[..8], &[0x22u8; 8]);
    assert_eq!(&broken[8..16], &[0xAAu8; 8]);
    assert_eq!(
        &broken[16..],
        &[0u8; 16],
        "the zero run was not overwritten"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join(VER))?,
        "2024.01.01.0000.0000"
    );
    Ok(())
}

/// A staging file rewritten after the parent measured it is refused, and nothing from that batch is
/// written.
///
/// This is why a staged write carries a digest at all. The parent proved these bytes against the
/// block index, but that proof is a value in the parent and the staging file it took it over lives
/// in a store the unprivileged user can write. The substitute here is not corruption: it is
/// well-formed bytes of exactly the right length, which is what someone who can write that file
/// would put there. Only the digest separates the two.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_bytes_rewritten_after_the_parent_measured_them_are_refused()
-> Result<(), Box<dyn Error>> {
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let target = root.path().join("data.bin");
    std::fs::write(&target, vec![0xAAu8; 32])?;

    let staging = store.path().join("staged.bin");
    let writes = stage(&staging, &[("data.bin", 0, vec![0x11u8; 16])])?;
    // Same length, same shape, different bytes: the file the worker will read is not the file the
    // parent hashed.
    std::fs::write(&staging, vec![0x99u8; 16])?;

    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;
    let err = harness
        .session
        .repair(
            Some(&staging),
            writes.clone(),
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("staged bytes that do not match their digest must not be written");

    let ElevateError::Worker {
        kind: WorkerErrorKind::Verify,
        failed_file: Some(named),
        ..
    } = &err
    else {
        panic!("expected a typed verification refusal naming the staging file, got {err:?}");
    };
    assert_eq!(named, &staging);
    assert_eq!(
        std::fs::read(&target)?,
        vec![0xAAu8; 32],
        "a refused batch still reached the tree",
    );
    assert!(
        !root.path().join(VER).exists(),
        "the version advanced over a refused batch"
    );

    // The session survives the refusal: restoring the bytes the digests describe writes them.
    stage(&staging, &[("data.bin", 0, vec![0x11u8; 16])])?;
    harness
        .session
        .repair(
            Some(&staging),
            writes,
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await?;
    assert_eq!(&std::fs::read(&target)?[..16], &[0x11u8; 16]);
    Ok(())
}

/// A staged write is refused when its path would leave the bound tree, when its span runs past the
/// staging file, and when no staging file was named at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_staged_write_the_session_forbids_is_refused() -> Result<(), Box<dyn Error>> {
    let store = tempfile::tempdir()?;
    let base = tempfile::tempdir()?;
    let root = base.path().join("game");
    std::fs::create_dir_all(&root)?;
    let staging = store.path().join("staged.bin");
    let good = stage(&staging, &[("data.bin", 0, vec![0x11u8; 16])])?;

    let mut harness = start().await?;
    harness.session.bind(&root).await?;

    let escaping = stage(&staging, &[("../escaped.bin", 0, vec![0x11u8; 16])])?;
    let err = harness
        .session
        .repair(
            Some(&staging),
            escaping,
            None,
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("a staged write climbing out of the tree must be refused");
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
    assert!(!base.path().join("escaped.bin").exists());

    // A span the staging file cannot satisfy is a refusal, not a short write.
    std::fs::write(&staging, vec![0x11u8; 4])?;
    let err = harness
        .session
        .repair(
            Some(&staging),
            good.clone(),
            None,
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("a span past the end of the staging file must be refused");
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

    // And bytes with nowhere to have come from are a protocol fault rather than a panic.
    let err = harness
        .session
        .repair(None, good, None, &CancellationToken::new(), |_| {})
        .await
        .expect_err("a byte-carrying write with no staging file must be refused");
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
    Ok(())
}

/// A stray moves into the recycler and is never deleted, and a move that would leave the tree at
/// either end is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stray_moves_within_the_tree_and_never_out_of_it() -> Result<(), Box<dyn Error>> {
    let base = tempfile::tempdir()?;
    let root = base.path().join("install");
    std::fs::create_dir_all(root.join("game/mods"))?;
    std::fs::write(root.join("game/mods/extra.dat"), b"user data")?;

    let mut harness = start().await?;
    harness.session.bind(&root).await?;
    harness
        .session
        .move_within(
            "game/mods/extra.dat",
            "apogee_repair_recycler/20240101_000000/game/mods/extra.dat",
        )
        .await?;

    assert!(!root.join("game/mods/extra.dat").exists());
    assert_eq!(
        std::fs::read(root.join("apogee_repair_recycler/20240101_000000/game/mods/extra.dat"))?,
        b"user data",
        "the bytes must survive the move",
    );

    std::fs::write(root.join("game/mods/other.dat"), b"more")?;
    for (from, to) in [
        ("game/mods/other.dat", "../escaped.dat"),
        ("../outside.dat", "game/mods/landed.dat"),
    ] {
        let err = harness
            .session
            .move_within(from, to)
            .await
            .expect_err("a move leaving the tree must be refused");
        assert!(
            matches!(
                err,
                ElevateError::Worker {
                    kind: WorkerErrorKind::Protocol,
                    ..
                }
            ),
            "{from} -> {to}: got {err:?}"
        );
    }
    assert!(!base.path().join("escaped.dat").exists());
    assert_eq!(std::fs::read(root.join("game/mods/other.dat"))?, b"more");
    Ok(())
}

/// Killing the worker part way through a repair is a typed failure, the parent carries on, the
/// version does not advance, and a re-run over a fresh worker converges.
///
/// The mirror of the mid-apply kill, and the claims are the same four. What differs is what a torn
/// repair leaves: a batch is many small positioned writes rather than one long stream, so some have
/// landed and some have not, and the re-run has to be indifferent to which.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killing_the_worker_mid_repair_is_a_typed_failure_a_re_run_converges()
-> Result<(), Box<dyn Error>> {
    let store = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let target = root.path().join("big.bin");
    let healed = wide_expected(REPAIR_SPANS, REPAIR_SPAN_LEN);
    std::fs::write(&target, vec![0xAAu8; healed.len()])?;

    // One span per run, so the kill on the first progress frame lands with most of them unwritten.
    let spans: Vec<(&str, u64, Vec<u8>)> = (0..REPAIR_SPANS)
        .map(|chunk| {
            let off = (chunk * REPAIR_SPAN_LEN) as u64;
            ("big.bin", off, vec![filler(chunk); REPAIR_SPAN_LEN])
        })
        .collect();
    let staging = store.path().join("staged.bin");
    let writes = stage(&staging, &spans)?;

    let mut harness = start().await?;
    harness.session.bind(root.path()).await?;
    let mut child = harness.child;
    let mut killed = false;
    let err = harness
        .session
        .repair(
            Some(&staging),
            writes.clone(),
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
        .expect_err("a worker killed mid-repair must not report success");

    assert!(killed, "the repair finished before it could be interrupted");
    assert!(
        matches!(err, ElevateError::Gone),
        "a dead worker must arrive as a typed value, got {err:?}"
    );
    // This assertion running at all is the anti-crash claim.
    assert!(
        !root.path().join(VER).exists(),
        "the version advanced over a torn repair"
    );
    assert_ne!(
        std::fs::read(&target)?,
        healed,
        "the repair was not actually interrupted"
    );

    let mut second = start().await?;
    second.session.bind(root.path()).await?;
    second
        .session
        .repair(
            Some(&staging),
            writes,
            version("2024.01.01.0000.0000"),
            &CancellationToken::new(),
            |_| {},
        )
        .await?;
    assert_eq!(
        std::fs::read(&target)?,
        healed,
        "the re-run did not converge on the healed file",
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
