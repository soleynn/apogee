#![no_main]

use std::sync::OnceLock;

use apogee_addons::{ComponentManifest, manifest::UpdaterKey};
use libfuzzer_sys::fuzz_target;

/// One updater key of each settings format, so the reader that runs over a co-tenant-writable
/// settings file before every program start is driven by the same bytes as the parser.
fn keys() -> &'static [UpdaterKey] {
    static KEYS: OnceLock<Vec<UpdaterKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let row = |format: &str| {
            format!(
                r#"{{"name":"p-{format}","version":"1","tier":"first_class",
                  "game_versions":["1"],"runners":[{{"name":"r","version":"1"}}],
                  "steps":[{{"name":"s-{format}","reason":"r","ops":[]}}],
                  "start":{{"program":"Apogee/p/p.exe","trigger":"with_game"}},
                  "updater_keys":[{{"file":"p.cfg","format":"{format}","key":"k","off":"False"}}]}}"#
            )
        };
        let json = format!(
            r#"{{"version":1,"programs":[{},{}]}}"#,
            row("json"),
            row("xml_setting")
        );
        ComponentManifest::from_json_bytes(json.as_bytes())
            .map(|m| {
                m.programs
                    .iter()
                    .flat_map(|p| p.updater_keys.iter().cloned())
                    .collect()
            })
            .unwrap_or_default()
    })
}

// The component manifest parser runs over a downloaded manifest before its signature is trusted for the
// shape, so it must never panic or over-allocate on any byte sequence: it only ever returns a manifest
// or a typed parse error. It also validates the destinations, registry edits, program rows, environment
// and `{appdata}` paths its rows describe, so this covers those too, and a program row it cannot read
// must cost that row rather than the manifest.
fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = apogee_addons::ComponentManifest::from_json_bytes(data) {
        for program in &manifest.programs {
            for key in &program.updater_keys {
                let _ = key.state_in(data);
            }
        }
    }
    for key in keys() {
        let _ = key.state_in(data);
    }
});
