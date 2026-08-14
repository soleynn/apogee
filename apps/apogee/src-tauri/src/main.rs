#![forbid(unsafe_code)]
// Keeps a console window from opening beside the window on Windows. Only in a release build, so a
// debug run still has somewhere to print.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! The desktop shell: one window, the frontend it loads, and the commands that frontend invokes.
//!
//! It holds no launcher rules. What it does is issue commands to `apogee-core` and render the events
//! that come back, and the types it puts on the wire are declared here rather than borrowed from the
//! domain model, so the JSON the frontend binds to is this crate's to change.
//!
//! Today that is one command, which answers what the frontend needs before it renders anything.

use std::process::ExitCode;

use apogee_core::Region;
use serde::Serialize;

/// The first thing the frontend asks for.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Startup {
    /// This binary's version, as its manifest declares it.
    version: &'static str,
    /// The service region a profile connects to when nothing has chosen one.
    default_region: &'static str,
}

#[tauri::command]
fn startup() -> Startup {
    Startup {
        version: env!("CARGO_PKG_VERSION"),
        default_region: region_label(Region::default()),
    }
}

/// The wildcard arm is required rather than defensive: `Region` is `#[non_exhaustive]`, so a variant
/// added to the domain model has to reach a frontend built before it existed.
fn region_label(region: Region) -> &'static str {
    match region {
        Region::Global => "global",
        Region::Korea => "korea",
        Region::China => "china",
        _ => "unknown",
    }
}

fn main() -> ExitCode {
    // The context macro builds the window's context on a thread of its own, for the larger stack,
    // and ends the process itself if that thread panics. Nothing here can reach around that, so the
    // one lint the table denies is carved out over the one statement that expands the macro. It is
    // an `expect` rather than an `allow` so that the day the macro stops doing it, this line is
    // reported as no longer needed instead of sitting here unread.
    #[expect(
        clippy::exit,
        reason = "the context macro's own failure path ends the process"
    )]
    let context = tauri::generate_context!();

    match tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![startup])
        .run(context)
    {
        Ok(()) => ExitCode::SUCCESS,
        // A return code rather than a panic: the builder fails on a window that cannot be created,
        // which is the condition the render fallback reads to try the next way of drawing one.
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_region_has_a_label() {
        assert_eq!(region_label(Region::Global), "global");
        assert_eq!(region_label(Region::Korea), "korea");
        assert_eq!(region_label(Region::China), "china");
    }

    #[test]
    fn the_default_region_reaches_the_frontend_named() {
        let startup = startup();
        assert_eq!(startup.default_region, "global");
        assert_eq!(startup.version, env!("CARGO_PKG_VERSION"));
    }
}
