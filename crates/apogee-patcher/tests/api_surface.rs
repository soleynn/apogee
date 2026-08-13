//! Pins the crate's public API surface: every public item, the exact signature of every public
//! method, the auto-traits consumers rely on, and the three shapes of the error taxonomy that are
//! load-bearing rather than incidental.
//!
//! Signatures are pinned by coercing each method to a function pointer of its written-out type, so a
//! changed parameter, return type, or receiver fails this compile rather than surfacing as a consumer
//! break after the fact. Additive change (a new method, a new variant on a `#[non_exhaustive]` enum, a
//! new field on a sealed variant) passes untouched, which is the point: only the commitments break.
//!
//! Async methods and generic ones do not coerce to `fn` pointers, so each is pinned by a monomorphic
//! wrapper whose own signature restates the method's; a drifted method fails to typecheck inside the
//! wrapper.

use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use apogee_patcher::{
    Elevation, GameProbe, IndexCatalog, IndexCatalogError, IndexEntry, IndexSource, InstallRequest,
    Installed, Job, PartRef, PatchError, PatchProgress, Patcher, PatcherConfig, PreflightError,
    RepairOutcome, RepairPatchSource, RepairRepo, RepairRequest, RepairedRepo, Repo, SePatch,
    SpacePool, mods, probe_writable,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

/// Every non-async public signature, as function-pointer coercions. Never called; compiling is the
/// assertion.
#[allow(dead_code)]
fn signatures() {
    // Patcher
    let _: fn(apogee_fetch::Fetcher, PatcherConfig) -> Patcher = Patcher::new;
    let _: fn(&Patcher, InstallRequest) -> Job<Installed> = Patcher::install;
    let _: fn(&Patcher, RepairRequest) -> Job<RepairOutcome> = Patcher::repair;

    // PatcherConfig. The probe is an argument rather than a default, so that opting out of the
    // game-running guard is something the compiler makes a caller write down.
    let _: fn(GameProbe) -> PatcherConfig = PatcherConfig::new;

    // Repo
    let _: fn(&str) -> Option<Repo> = Repo::from_label;

    // GameProbe. `new` takes an `impl Fn`, which cannot coerce to a fn pointer, so it is pinned by a
    // monomorphic wrapper like the async methods below.
    fn probe(check: fn(&Path) -> bool) -> GameProbe {
        GameProbe::new(check)
    }
    let _: fn(fn(&Path) -> bool) -> GameProbe = probe;
    let _: fn() -> GameProbe = GameProbe::never_running;
    let _: fn(&GameProbe, &Path) -> bool = GameProbe::is_running;

    // SePatch. Two constructors and no accessor: the credential goes in, and only a request header
    // gets it back out.
    fn se_patch(unique_id: String) -> SePatch {
        SePatch::new(unique_id)
    }
    let _: fn(String) -> SePatch = se_patch;
    let _: fn() -> SePatch = SePatch::boot;

    // Elevation, and the writability question it answers with.
    let _: fn() -> Elevation = Elevation::default;
    let _: fn(&Path) -> Result<bool, PatchError> = probe_writable;

    // IndexCatalog / IndexEntry. `verify_default` is the only way in that takes a signature: the key
    // is compiled in, and the parse that accepts a caller-supplied key is private.
    let _: fn(&[u8]) -> Result<IndexCatalog, IndexCatalogError> = IndexCatalog::from_json_bytes;
    let _: fn(&[u8], &[u8]) -> Result<IndexCatalog, IndexCatalogError> =
        IndexCatalog::verify_default;
    // The resolved row borrows the catalog and not the version string, so a caller can look one up
    // with a temporary and keep the answer.
    let _: for<'c, 'v> fn(&'c IndexCatalog, Repo, &'v str) -> Option<&'c IndexEntry> =
        IndexCatalog::resolve;
    let _: fn(&IndexEntry) -> IndexSource = IndexEntry::source;

    // Job. Generic over the operation's result, so each method is pinned at both instantiations the
    // crate hands out.
    let _: fn(&mut Job<Installed>) -> UnboundedReceiver<PatchProgress> = Job::progress;
    let _: fn(&mut Job<RepairOutcome>) -> UnboundedReceiver<PatchProgress> = Job::progress;
    let _: fn(&Job<Installed>) = Job::cancel;
    let _: fn(&Job<Installed>) -> CancellationToken = Job::cancel_token;

    // mods
    let _: DescribeContainers = mods::describe_containers;
}

/// The lowering from a block index and its verification into a pristine map, as a named type so the
/// coercion above stays readable.
type DescribeContainers = fn(
    &apogee_zipatch::Index,
    &apogee_zipatch::VerifyReport,
    &str,
    &[apogee_sqpack::Repo],
    &mut apogee_sqpack::mods::MapBuilder,
) -> Result<(), mods::MapError>;

/// The async methods, pinned by monomorphic wrappers: a drifted signature fails to typecheck here.
#[allow(dead_code)]
mod async_signatures {
    use super::*;

    async fn wait_install(job: Job<Installed>) -> Result<Installed, PatchError> {
        job.wait().await
    }

    async fn wait_repair(job: Job<RepairOutcome>) -> Result<RepairOutcome, PatchError> {
        job.wait().await
    }

    /// A `Job` is awaitable directly, without reaching for `wait`.
    async fn into_future(job: Job<Installed>) -> Result<Installed, PatchError> {
        job.await
    }

    /// And the future it becomes is boxed and `Send`, so a caller can hold one across a spawned
    /// task. Pinned as the associated type rather than as a bound on a value, since naming it is
    /// what commits to the `Send`.
    #[allow(dead_code)]
    fn awaited_job_is_a_send_future() {
        type InstallFuture = Pin<Box<dyn Future<Output = Result<Installed, PatchError>> + Send>>;
        let _: fn(Job<Installed>) -> InstallFuture = <Job<Installed> as IntoFuture>::into_future;
    }
}

/// The public fields consumers construct these types from, named once so a rename or a retype breaks
/// here. Never called; compiling is the assertion.
#[allow(dead_code)]
fn public_fields() {
    let PatcherConfig {
        patch_store: _patch_store,
        keep_patches: _keep_patches,
        ignore_space: _ignore_space,
        repair_reattempts: _repair_reattempts,
        elevation: _elevation,
        game_probe: _game_probe,
    } = PatcherConfig::new(GameProbe::never_running());

    fn install_request(r: InstallRequest) {
        let InstallRequest {
            repo: _repo,
            game_root: _game_root,
            patches: _patches,
            headers: _headers,
        } = r;
    }

    fn installed(i: Installed) {
        let Installed {
            repo: _repo,
            new_version: _new_version,
        } = i;
    }

    fn repair_request(r: RepairRequest) {
        let RepairRequest {
            game_root: _game_root,
            repos: _repos,
        } = r;
    }

    fn repair_repo(r: RepairRepo) {
        let RepairRepo {
            repo: _repo,
            target_version: _target_version,
            index: _index,
            patch_sources: _patch_sources,
            source_base_url: _source_base_url,
            headers: _headers,
        } = r;
    }

    fn repair_patch_source(s: RepairPatchSource) {
        let RepairPatchSource {
            name: _name,
            url: _url,
            local: _local,
        } = s;
    }

    fn repaired_repo(r: RepairedRepo) {
        let RepairedRepo {
            repo: _repo,
            version: _version,
            repaired_parts: _repaired_parts,
            recreated: _recreated,
            resized: _resized,
            bytes_refetched: _bytes_refetched,
            quarantined: _quarantined,
        } = r;
    }

    fn repair_outcome(o: RepairOutcome) {
        let RepairOutcome {
            repos: _repos,
            bytes_refetched: _bytes_refetched,
            quarantined: _quarantined,
        } = o;
    }

    fn index_entry(e: IndexEntry) {
        let IndexEntry {
            repo: _repo,
            version: _version,
            url: _url,
            pin: _pin,
            source_base: _source_base,
        } = e;
    }

    fn index_catalog(c: IndexCatalog) {
        let IndexCatalog {
            version: _version,
            indexes: _indexes,
        } = c;
    }

    fn part_ref(p: PartRef) {
        let PartRef {
            path: _path,
            offset: _offset,
        } = p;
    }
}

/// The two enums a consumer is expected to match exhaustively, matched exhaustively.
///
/// This is the whole reason neither carries `#[non_exhaustive]`: a new phase or a new repo has to
/// break every renderer and every path mapping rather than slip past a `_` arm that prints the word
/// "progress" or answers `None`. Adding a variant fails this compile, which is the reminder to go
/// look at the places that actually show it to someone.
#[allow(dead_code)]
fn exhaustively_matchable(progress: &PatchProgress, repo: Repo) {
    match repo {
        Repo::Boot | Repo::Game | Repo::Expansion(_) => {}
    }
    match progress {
        PatchProgress::Downloading { .. }
        | PatchProgress::Applying { .. }
        | PatchProgress::Applied { .. }
        | PatchProgress::Verifying { .. }
        | PatchProgress::Refetching { .. }
        | PatchProgress::Quarantining { .. }
        | PatchProgress::Repaired { .. } => {}
    }
}

/// The types this crate re-exports so a consumer can name what its own public types carry, without
/// taking a dependency on the crate that defines them.
///
/// `PatchError::Worker` carries a `WorkerErrorKind` and `PatchProgress::Downloading` carries a
/// `Recoveries`; a caller that matches on either must be able to write the type down. Naming both
/// through `apogee_patcher` here is what keeps the paths from being quietly dropped.
#[allow(dead_code)]
fn re_exports_stay_nameable(
    kind: apogee_patcher::WorkerErrorKind,
    tally: apogee_patcher::Recoveries,
) {
    let _: apogee_patcher::WorkerErrorKind = kind;
    let _: apogee_patcher::Recoveries = tally;
}

/// The auto-traits and standard traits consumers rely on; losing one is a breaking change no
/// signature pin sees.
#[test]
fn public_types_keep_their_trait_obligations() {
    fn send_sync<T: Send + Sync>() {}
    fn debuggable<T: std::fmt::Debug>() {}
    fn cloneable<T: Clone>() {}
    fn copyable<T: Copy>() {}
    fn defaulted<T: Default>() {}
    fn eq<T: PartialEq + Eq>() {}
    fn error<T: std::error::Error>() {}

    send_sync::<Patcher>();
    send_sync::<PatcherConfig>();
    send_sync::<GameProbe>();
    send_sync::<Job<Installed>>();
    send_sync::<Job<RepairOutcome>>();
    send_sync::<PatchError>();
    send_sync::<PreflightError>();
    send_sync::<IndexCatalogError>();
    send_sync::<mods::MapError>();
    send_sync::<InstallRequest>();
    send_sync::<RepairRequest>();
    send_sync::<PatchProgress>();

    debuggable::<Repo>();
    debuggable::<PartRef>();
    debuggable::<SpacePool>();
    debuggable::<Patcher>();
    debuggable::<PatcherConfig>();
    debuggable::<GameProbe>();
    debuggable::<Elevation>();
    debuggable::<PatchProgress>();
    debuggable::<SePatch>();
    debuggable::<InstallRequest>();
    debuggable::<Installed>();
    debuggable::<IndexSource>();
    debuggable::<RepairPatchSource>();
    debuggable::<RepairRepo>();
    debuggable::<RepairRequest>();
    debuggable::<RepairedRepo>();
    debuggable::<RepairOutcome>();
    debuggable::<IndexCatalog>();
    debuggable::<IndexEntry>();
    debuggable::<PatchError>();
    debuggable::<PreflightError>();
    debuggable::<IndexCatalogError>();
    debuggable::<mods::MapError>();

    cloneable::<Repo>();
    cloneable::<PartRef>();
    cloneable::<SpacePool>();
    cloneable::<Patcher>();
    cloneable::<PatcherConfig>();
    cloneable::<GameProbe>();
    cloneable::<Elevation>();
    cloneable::<PatchProgress>();
    cloneable::<SePatch>();
    cloneable::<InstallRequest>();
    cloneable::<Installed>();
    cloneable::<IndexSource>();
    cloneable::<RepairPatchSource>();
    cloneable::<RepairRepo>();
    cloneable::<RepairRequest>();
    cloneable::<RepairedRepo>();
    cloneable::<RepairOutcome>();
    cloneable::<IndexCatalog>();
    cloneable::<IndexEntry>();

    copyable::<Repo>();
    copyable::<SpacePool>();

    // The repair outcome defaults so a caller can accumulate into one; elevation defaults to the
    // probe-and-decide arm, which is what `PatcherConfig::new` installs.
    defaulted::<RepairOutcome>();
    defaulted::<Elevation>();

    // Compared in consumer assertions, so equality is part of the contract rather than a convenience.
    eq::<Repo>();
    eq::<PartRef>();
    eq::<SpacePool>();
    eq::<Elevation>();
    eq::<PatchProgress>();
    eq::<Installed>();
    eq::<RepairedRepo>();
    eq::<RepairOutcome>();
    eq::<IndexEntry>();

    error::<PatchError>();
    error::<PreflightError>();
    error::<IndexCatalogError>();
    error::<mods::MapError>();
}

/// `PatchError` stays under clippy's `result_large_err` threshold.
///
/// The lint fires at 128 bytes and this type is one `FetchError` plus a repo and an index, which is
/// most of the way there. Crossing it does not fail here, it fails in every crate that returns a
/// `Result<_, PatchError>`, as a lint about a function nobody changed. A field added to the widest
/// variant is the way it happens, so the ceiling is asserted where the type is, with the number that
/// explains it.
#[test]
fn the_error_type_stays_under_the_large_err_threshold() {
    const CLIPPY_LARGE_ERR_THRESHOLD: usize = 128;
    let size = std::mem::size_of::<PatchError>();
    assert!(
        size <= CLIPPY_LARGE_ERR_THRESHOLD,
        "PatchError is {size} bytes against a {CLIPPY_LARGE_ERR_THRESHOLD}-byte lint threshold; \
         box the payload that grew rather than widening the variant",
    );
}

/// A fetch failure does not convert into a [`PatchError`], and the two error types that should still
/// do.
///
/// `PatchError::Acquire` names the repo and the patch index a download failed on, which an unwritten
/// `?` cannot supply. If `From<FetchError>` ever existed, every `?` over a fetch call would mint an
/// `Acquire` naming neither, and the arms routed by hand ahead of it, `OutOfSpace` and `Cancelled`,
/// would be flattened into "acquire failed" at whichever call site forgot. `install::acquire_err`
/// and `repair::index_acquire_err` test that routing on values; this tests that the shortcut around
/// them cannot be added in the first place.
///
/// Both directions are asserted, because a check that only ever answers "no conversion" would pass
/// just as well if the detection were broken.
#[test]
fn a_fetch_failure_cannot_be_flattened_in_by_a_bare_question_mark() {
    // Autoref specialization: the `ViaFrom` impl is on `&Probe<T>` so it is found first, and drops
    // out of consideration when its `From` bound does not hold, leaving the `NoFrom` impl on
    // `Probe<T>` one deref down. That is the whole trick, and it is the only way to ask about the
    // absence of an impl on stable.
    struct Probe<T>(PhantomData<T>);

    trait ViaFrom {
        fn converts(&self) -> bool {
            true
        }
    }
    impl<T> ViaFrom for &Probe<T> where PatchError: From<T> {}

    trait NoFrom {
        fn converts(&self) -> bool {
            false
        }
    }
    impl<T> NoFrom for Probe<T> {}

    // The double reference is the mechanism, not a slip: at one `&` the receiver matches `NoFrom`
    // directly and the `ViaFrom` impl is never reached, so every probe would answer "no conversion"
    // and this test would pass against anything. Taking clippy's suggestion here silently disarms it.
    #[allow(clippy::needless_borrow)]
    {
        assert!(
            !(&&Probe::<apogee_fetch::FetchError>(PhantomData)).converts(),
            "a `?` over a fetch call must not be able to mint an Acquire with no repo and no index",
        );
        assert!(
            (&&Probe::<PreflightError>(PhantomData)).converts(),
            "preflight still converts, so the detection above is not simply always saying no",
        );
        assert!(
            (&&Probe::<apogee_zipatch::Error>(PhantomData)).converts(),
            "and so does an apply failure",
        );
    }
}

/// Every [`PatchError`] variant is constructible from outside the crate and renders something a
/// person can act on.
///
/// The list is exhaustive by construction: `PatchError` is `#[non_exhaustive]`, so this cannot be a
/// `match`, but every variant named here has to be buildable with public types alone. A variant that
/// gains a private field, or a type a consumer cannot name, stops compiling here.
#[test]
fn every_error_variant_is_constructible_and_says_something() {
    let variants: Vec<PatchError> = vec![
        PatchError::Preflight(PreflightError::GameRunning),
        PatchError::Preflight(PreflightError::NotEnoughSpace {
            pool: SpacePool::SharedFilesystem,
            needed: 90_000,
            free: 12,
        }),
        PatchError::Patchlist {
            index: 4,
            detail: "no url".to_owned(),
        },
        PatchError::OutOfSpace {
            path: PathBuf::from("/store/p4.patch"),
            source: std::io::ErrorKind::StorageFull.into(),
        },
        PatchError::Acquire {
            repo: Repo::Game,
            index: 7,
            source: apogee_fetch::FetchError::Cancelled,
        },
        PatchError::Verify {
            repo: Repo::Expansion(2),
            broken: 1,
            first: PartRef {
                path: PathBuf::from("sqpack/ex2/0a0000.win32.dat0"),
                offset: 4096,
            },
        },
        PatchError::Apply(apogee_zipatch::Error::BadMagic),
        PatchError::BootAdmission {
            index: 0,
            source: apogee_zipatch::Error::BadMagic,
        },
        PatchError::Io {
            path: PathBuf::from("/install/game/ffxivgame.ver"),
            source: std::io::ErrorKind::PermissionDenied.into(),
        },
        PatchError::Worker {
            kind: apogee_patcher::WorkerErrorKind::Verify,
            failed_file: Some(PathBuf::from("/store/p0.patch")),
            detail: "block 2 does not match its digest".to_owned(),
        },
        PatchError::IndexUnavailable {
            repo: Repo::Boot,
            source: Box::new(std::io::Error::from(std::io::ErrorKind::NotFound)),
        },
        PatchError::VersionCrossCheck {
            repo: Repo::Game,
            index_version: "2024.01.02.0000.0000".to_owned(),
            wanted: "2024.03.28.0000.0000".to_owned(),
        },
        PatchError::Cancelled,
    ];

    for variant in &variants {
        let rendered = variant.to_string();
        assert!(
            !rendered.trim().is_empty(),
            "every variant renders: {variant:?}",
        );
    }
}
