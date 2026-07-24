#![cfg(target_os = "linux")]
//! Hermetic DXVK install through the public `Runtime` API: synthetic DXVK/nvapi tarballs are served
//! over the chaos server, installed into a fake-wineboot prefix, and the DLL placement + `prefix.json`
//! record + missing-DLL health detection are asserted. No real wine or real DXVK.

use std::error::Error;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{
    ArchiveFormat, DxvkEntry, HealthIssue, NvapiRef, Prefix, Progress, RunnerKind, Runtime,
    RuntimePaths,
};
use apogee_test_support::chaos::{ChaosServer, sha256_of};
use tokio_util::sync::CancellationToken;

/// A `wine` stand-in that lays the prefix skeleton on `wineboot`, so `prepare_custom` initializes a
/// prefix with no real wine.
const FAKE_WINE: &str = "#!/bin/sh
if [ \"$1\" = wineboot ]; then
  mkdir -p \"$WINEPREFIX/drive_c/windows\" \"$WINEPREFIX/dosdevices\"
  ln -sfn ../drive_c \"$WINEPREFIX/dosdevices/c:\"
  ln -sfn / \"$WINEPREFIX/dosdevices/z:\"
  printf 'WINE REGISTRY Version 2\\n' > \"$WINEPREFIX/system.reg\"
fi
exit 0
";

/// A gzip'd tar with the given `dll` names under `top/x64/` and `top/x32/`, each carrying its own name
/// as bytes so 64- and 32-bit copies are distinguishable.
fn dll_targz(top: &str, dlls: &[&str]) -> std::io::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for arch in ["x64", "x32"] {
        for dll in dlls {
            let body = format!("{arch}/{dll}");
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            builder.append_data(&mut header, format!("{top}/{arch}/{dll}"), body.as_bytes())?;
        }
    }
    let tar = builder.into_inner()?;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar)?;
    encoder.finish()
}

fn runtime_over(root: &Path) -> Result<Runtime, Box<dyn Error>> {
    Ok(Runtime::new(
        Fetcher::builder().build()?,
        RuntimePaths {
            runners: root.join("runners"),
            prefixes: root.join("prefixes"),
        },
    ))
}

async fn prepared(runtime: &Runtime, root: &Path) -> Result<Prefix, Box<dyn Error>> {
    let runner_dir = root.join("runner");
    let bin = runner_dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    std::fs::write(bin.join("wine"), FAKE_WINE)?;
    std::fs::set_permissions(bin.join("wine"), std::fs::Permissions::from_mode(0o755))?;
    Ok(runtime
        .prepare_custom(
            &runner_dir,
            RunnerKind::Wine,
            "wine",
            &root.join("prefix"),
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await?)
}

const DXVK_DLLS: &[&str] = &["d3d9.dll", "d3d10core.dll", "d3d11.dll", "dxgi.dll"];

#[tokio::test]
async fn install_dxvk_places_dlls_and_records_the_prefix() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    let prefix = prepared(&runtime, root.path()).await.expect("prepare");

    let tar = dll_targz("dxvk-2.4.1", DXVK_DLLS).expect("tar");
    let server = ChaosServer::serving(tar.clone())
        .start()
        .await
        .expect("server");
    let dxvk = DxvkEntry {
        version: "2.4.1".to_owned(),
        url: server.url("dxvk.tar.gz"),
        sha256: sha256_of(&tar),
        format: ArchiveFormat::TarGz,
        nvapi: None,
    };

    runtime
        .install_dxvk(
            &dxvk,
            &prefix,
            false,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("install dxvk");

    let system32 = prefix.path().join("drive_c/windows/system32");
    let syswow64 = prefix.path().join("drive_c/windows/syswow64");
    for dll in DXVK_DLLS {
        assert!(system32.join(dll).is_file(), "{dll} in system32");
        assert!(syswow64.join(dll).is_file(), "{dll} in syswow64");
    }
    // The 64- and 32-bit copies came from their own arch directories.
    assert_eq!(
        std::fs::read_to_string(system32.join("d3d11.dll")).unwrap(),
        "x64/d3d11.dll"
    );
    assert_eq!(
        std::fs::read_to_string(syswow64.join("d3d11.dll")).unwrap(),
        "x32/d3d11.dll"
    );

    let meta = prefix.metadata().expect("load").expect("prefix.json");
    let recorded = meta.dxvk.expect("dxvk recorded");
    assert_eq!(recorded.version, "2.4.1");
    assert!(!recorded.nvapi);
    assert!(
        runtime
            .check_prefix(&prefix)
            .await
            .expect("check")
            .is_healthy()
    );
}

#[tokio::test]
async fn install_dxvk_with_nvapi_adds_the_nvapi_dll() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    let prefix = prepared(&runtime, root.path()).await.expect("prepare");

    let dxvk_tar = dll_targz("dxvk-2.4.1", DXVK_DLLS).expect("tar");
    let nvapi_tar = dll_targz("dxvk-nvapi-v0.8.0", &["nvapi64.dll"]).expect("nvapi tar");
    let dxvk_server = ChaosServer::serving(dxvk_tar.clone())
        .start()
        .await
        .expect("dxvk server");
    let nvapi_server = ChaosServer::serving(nvapi_tar.clone())
        .start()
        .await
        .expect("nvapi server");

    let dxvk = DxvkEntry {
        version: "2.4.1".to_owned(),
        url: dxvk_server.url("dxvk.tar.gz"),
        sha256: sha256_of(&dxvk_tar),
        format: ArchiveFormat::TarGz,
        nvapi: Some(NvapiRef {
            url: nvapi_server.url("nvapi.tar.gz"),
            sha256: sha256_of(&nvapi_tar),
            format: ArchiveFormat::TarGz,
        }),
    };

    runtime
        .install_dxvk(
            &dxvk,
            &prefix,
            true,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("install dxvk+nvapi");

    let system32 = prefix.path().join("drive_c/windows/system32");
    assert!(
        system32.join("nvapi64.dll").is_file(),
        "nvapi64 in system32"
    );
    let meta = prefix.metadata().expect("load").expect("prefix.json");
    assert!(meta.dxvk.expect("dxvk").nvapi, "nvapi recorded");
}

#[tokio::test]
async fn health_check_flags_a_missing_dxvk_dll() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    let prefix = prepared(&runtime, root.path()).await.expect("prepare");

    let tar = dll_targz("dxvk-2.4.1", DXVK_DLLS).expect("tar");
    let server = ChaosServer::serving(tar.clone())
        .start()
        .await
        .expect("server");
    let dxvk = DxvkEntry {
        version: "2.4.1".to_owned(),
        url: server.url("dxvk.tar.gz"),
        sha256: sha256_of(&tar),
        format: ArchiveFormat::TarGz,
        nvapi: None,
    };
    runtime
        .install_dxvk(
            &dxvk,
            &prefix,
            false,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("install dxvk");

    // Delete a DLL the record says is installed.
    std::fs::remove_file(prefix.path().join("drive_c/windows/system32/dxgi.dll")).expect("rm dxgi");

    let health = runtime.check_prefix(&prefix).await.expect("check");
    assert!(
        health
            .issues
            .iter()
            .any(|i| matches!(i, HealthIssue::MissingDxvkDll { dll, .. } if dll == "dxgi.dll")),
        "missing dxgi.dll detected"
    );
}
