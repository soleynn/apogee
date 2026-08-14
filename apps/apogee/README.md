# apogee (desktop shell)

The launcher's window: a Rust binary under `src-tauri/` that owns the window and the commands the
page invokes, and a Svelte frontend under `src/` that renders them. It holds no launcher rules. What
it will do is issue commands to `apogee-core` and render the events that come back; today it issues
one, `startup`, and prints the answer.

## Layout

| Path | What it is |
| --- | --- |
| `src-tauri/` | The Rust crate. Workspace root, `apogee` binary, its own `Cargo.lock`. |
| `src-tauri/build.rs` | Two lines, pinned byte-for-byte by `scripts/audit.sh`. |
| `src-tauri/tauri.conf.json` | Window, identifier, and where the frontend bundle is read from. |
| `src-tauri/capabilities/` | What the window may reach. |
| `src/` | The frontend: Svelte 5, TypeScript, plain Vite, no component library. |
| `index.html` | The Vite entry point. |

## Its own workspace

`src-tauri` is a Cargo workspace root rather than a member of the one at the repository root, and
carries a copy of that workspace's lint denies. Three things force it:

- `scripts/audit.sh` fails the build on a build script anywhere under `crates apps tools fuzz`, and
  this crate cannot compile without one. The audit carries a single exemption for
  `src-tauri/build.rs`, asserted against the file's exact contents, so it cannot quietly grow.
- The root workspace is cross-compiled for the MinGW ABI, where the window framework does not build.
- Every job that compiles the root workspace would otherwise need WebKitGTK's development headers to
  compile a crate none of them use.

The root `members` list names its apps one at a time rather than globbing `apps/*`, so nothing here
is picked up by it. `cargo deny` runs against this workspace's own policy, in `src-tauri/deny.toml`.

## Building

Needs Node and, for anything that compiles Rust, the webview development packages:

```
sudo apt-get install libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev
```

Then, from this directory:

```
npm ci
npm run check                       # svelte-check
npm run test                        # vitest
npm run build                       # writes dist/
cargo test  --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

`npm run build` has to come first. The macro that builds the window's context embeds `dist/`, so a
Rust build with no bundle on disk fails outright rather than producing a window with nothing in it.

To run it: `npm run tauri dev` (starts Vite on port 1420, then the window against it).

## Not yet done

- The icons under `src-tauri/icons/` are placeholders.
- `tauri.conf.json` sets no content security policy and the capability file grants the built-in
  default set. Narrowing both is separate work.
- Nothing here is packaged, localized, or driven by a test that opens a real window.
