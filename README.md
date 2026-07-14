# Apogee

A from-scratch, Linux-first launcher for FINAL FANTASY XIV. Apogee reimplements the Square Enix
launcher protocol, ZiPatch patching, and Wine/Proton runner management as a workspace of standalone
Rust crates behind a headless CLI and a thin desktop shell.

## Status

Early development. The workspace is scaffolded and every crate compiles; feature work is in progress.

## Build

```sh
cargo build --workspace
```

Requires a recent stable Rust toolchain, pinned in `rust-toolchain.toml`.

## License

GNU General Public License v3.0 or later (GPL-3.0-or-later). See the `LICENSE` file. Any distributed
fork must remain open source under the same terms.

Apogee is an independent, clean-room project. It is not affiliated with or endorsed by Square Enix.
