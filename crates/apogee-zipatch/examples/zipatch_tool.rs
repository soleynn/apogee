//! `zipatch-tool`: the patch-day inspection binary. Reads a ZiPatch file and dumps every chunk with
//! its file offset, exactly as the parser sees it, stopping at `EOF_`. The dump lines carry offsets,
//! command tags, and ids — never SE bytes — so pasting one into a bug report is clean.
//!
//! ```text
//! cargo run -p apogee-zipatch --example zipatch_tool -- dump <file.patch>
//! ```
//!
//! Formatting lives in the library ([`apogee_zipatch::Chunk`]'s `Display`); this example is only the
//! I/O shell, which is why it can print while the library never does.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apogee_zipatch::PatchReader;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (Some(cmd), Some(path), None) if cmd == "dump" => match dump(&PathBuf::from(path)) {
            Ok(count) => {
                println!("{count} chunk(s)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: zipatch_tool dump <file.patch>");
            ExitCode::FAILURE
        }
    }
}

fn dump(path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let mut reader = PatchReader::open(std::io::BufReader::new(file))?;
    let mut count = 0usize;
    loop {
        let offset = reader.position();
        let Some(chunk) = reader.next_chunk()? else {
            break;
        };
        println!("{offset:#010x}  {chunk}");
        count += 1;
    }
    Ok(count)
}
