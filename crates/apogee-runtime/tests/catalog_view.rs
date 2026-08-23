//! Read-only catalog views over signed rows and the runtime's existing installation records.

use std::error::Error;

use apogee_fetch::Fetcher;
use apogee_runtime::{Catalog, Runtime, RuntimePaths};

const PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn catalog() -> Result<Catalog, Box<dyn Error>> {
    Ok(Catalog::from_json_bytes(
        format!(
            r#"{{
              "version": 1,
              "runners": [
                {{ "name": "GE-Proton", "version": "11-2", "kind": "proton_umu",
                   "url": "https://example.invalid/ge.tar.gz", "sha256": "{PIN}",
                   "size": 532485412, "recommended": true,
                   "archive": {{ "format": "tar.gz" }} }},
                {{ "name": "wine-xiv", "version": "10.8", "kind": "wine",
                   "url": "https://example.invalid/wine.tar.xz", "sha256": "{PIN}",
                   "size": 66368636, "recommended": false,
                   "archive": {{ "format": "tar.xz" }} }}
              ],
              "dxvk": [
                {{ "version": "3.0.2", "url": "https://example.invalid/dxvk.tar.gz",
                   "sha256": "{PIN}", "size": 17999049, "recommended": true }}
              ]
            }}"#
        )
        .as_bytes(),
    )?)
}

fn runtime(root: &std::path::Path) -> Result<Runtime, Box<dyn Error>> {
    Ok(Runtime::new(
        Fetcher::builder().build()?,
        RuntimePaths {
            runners: root.join("runners"),
            prefixes: root.join("prefixes"),
        },
    ))
}

#[test]
fn runner_view_combines_available_rows_with_exact_install_markers() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let marker_dir = root.path().join("runners/.installed");
    std::fs::create_dir_all(&marker_dir)?;
    // The empty marker is the historical format. Exact matching against a current row remains safe.
    std::fs::write(marker_dir.join("GE-Proton-11-2"), b"")?;
    // Structured contents preserve both halves of a withdrawn identity even when both contain '-'.
    std::fs::write(
        marker_dir.join("old-runner-1-2"),
        br#"{"name":"old-runner","version":"1-2"}"#,
    )?;

    let rows = runtime(root.path())?.runner_catalog_view(&catalog()?)?;
    assert_eq!(rows.len(), 3);
    assert_eq!(
        (&rows[0].name, &rows[0].version, rows[0].installed),
        (&"GE-Proton".to_owned(), &"11-2".to_owned(), true)
    );
    assert!(rows[0].available);
    assert_eq!(rows[0].size, Some(532485412));
    assert!(rows[0].recommended);
    assert!(!rows[1].installed);
    assert_eq!(
        (&rows[2].name, &rows[2].version),
        (&"old-runner".to_owned(), &"1-2".to_owned())
    );
    assert!(rows[2].installed);
    assert!(!rows[2].available);
    assert_eq!(rows[2].size, None);
    assert!(!rows[2].recommended);
    Ok(())
}

#[test]
fn dxvk_view_reads_prefix_metadata_without_preparing_it() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let prefix = root.path().join("prefix");
    std::fs::create_dir_all(&prefix)?;
    let write_record = |version: &str| {
        std::fs::write(
            prefix.join("prefix.json"),
            format!(
                r#"{{
                  "runner": {{ "name": "GE-Proton", "version": "11-2" }},
                  "dxvk": {{ "version": "{version}", "nvapi": false }}
                }}"#
            ),
        )
    };

    write_record("3.0.2")?;
    let current = runtime(root.path())?.dxvk_catalog_view(&catalog()?, Some(&prefix))?;
    assert_eq!(current.len(), 1);
    assert!(current[0].installed);
    assert!(current[0].available);

    write_record("2.4.1")?;

    let rows = runtime(root.path())?.dxvk_catalog_view(&catalog()?, Some(&prefix))?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].version, "3.0.2");
    assert!(!rows[0].installed);
    assert!(rows[0].available);
    assert_eq!(rows[0].size, Some(17999049));
    assert!(rows[0].recommended);
    assert_eq!(rows[1].version, "2.4.1");
    assert!(rows[1].installed);
    assert!(!rows[1].available);
    assert_eq!(rows[1].size, None);
    Ok(())
}
