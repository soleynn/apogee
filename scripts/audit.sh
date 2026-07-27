#!/usr/bin/env bash
# Mechanical architecture and source-hygiene checks. Run locally with `bash scripts/audit.sh`.
# clippy already forbids unwrap/expect/panic!/exit/dbg workspace-wide, so those are not re-checked.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
report() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$2" | sed 's/^/  /' >&2; status=1; }

# 1. Byte-order conversions live only in each crate's `bytes` module (the one endianness home).
#    ZiPatch is the mixed-endian format, so this gate matters most there.
for c in sqex-crypto apogee-sqpack apogee-zipatch; do
  hits=$(grep -rnE '(from|to)_(le|be)_bytes' "crates/$c/src" --include='*.rs' \
    | grep -v '/bytes\.rs:' || true)
  [ -z "$hits" ] || report "byte-order conversion outside $c/src/bytes.rs" "$hits"
done

# 2. No ambient global state in the library crates.
libs() { grep -rnE "$1" crates/*/src --include='*.rs' | grep -v '/apogee-test-support/' || true; }
hits=$(libs '\bstatic[[:space:]]+mut\b'); [ -z "$hits" ] || report "mutable static in a library" "$hits"
hits=$(libs 'lazy_static!|once_cell|LazyLock|OnceLock|LazyCell|OnceCell'); [ -z "$hits" ] || report "lazy global singleton" "$hits"
hits=$(grep -rnE '^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?static[[:space:]]+[A-Za-z_]' \
  crates/apogee-core/src --include='*.rs' || true)
[ -z "$hits" ] || report "ambient static in apogee-core" "$hits"

# 3. No hard process exits in the library crates (belt-and-suspenders with clippy).
hits=$(libs 'process::(exit|abort)[[:space:]]*\('); [ -z "$hits" ] || report "process exit/abort" "$hits"

# 4. Dependency-edge invariants (declared normal deps only; dev/build deps excluded).
meta=$(cargo metadata --no-deps --format-version 1)
deps_of() { jq -r --arg p "$1" \
  '.packages[]|select(.name==$p)|.dependencies[]|select(.kind==null)|.name' <<<"$meta"; }

for c in sqex-crypto sqex-proto apogee-zipatch apogee-sqpack; do
  bad=$(deps_of "$c" | grep -xE 'tokio|reqwest' || true)
  [ -z "$bad" ] || report "$c directly depends on tokio/reqwest" "$bad"
done

nonpub='apogee-core|apogee-patcher|apogee-runtime|apogee-addons|apogee-otp|apogee-secrets|apogee-elevated|apogee-cli|apogee-test-support'
for c in sqex-crypto sqex-proto apogee-sqpack apogee-zipatch apogee-fetch; do
  bad=$(deps_of "$c" | grep -xE "$nonpub" || true)
  [ -z "$bad" ] || report "$c depends on a non-publishable crate" "$bad"
done

bad=$(deps_of sqex-proto | grep -xiE 'regex|regex-.*|scraper|html5ever|select|kuchiki|tl|lol_html' || true)
[ -z "$bad" ] || report "sqex-proto pulled in a regex/HTML-parser dependency" "$bad"

# 5. No presentation below the shell: the composition root carries no user-facing string constants
#    (it emits typed codes, and the shell localizes them), and no library writes to the terminal.
hits=$(grep -rnE '^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?(const|static)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:[^=]*\bstr\b' \
  crates/apogee-core/src --include='*.rs' || true)
[ -z "$hits" ] || report "string constant in apogee-core (presentation belongs to the shell)" "$hits"
hits=$(libs '\b(print|println|eprint|eprintln)!|\b(write|writeln)![[:space:]]*\([^)]*std(out|err)')
[ -z "$hits" ] || report "terminal output in a library crate" "$hits"

# 6. Dalamud is fetched and spawned, never linked. It is an external artifact this launcher downloads,
#    verifies against the digests its own distribution publishes, and hands to a runner as a program to
#    run. Nothing here links it, loads it, or ships a byte of it, and the endpoint it comes from is a row
#    in the signed catalog rather than a value in this binary. Each of those is one edit away from being
#    untrue and none of them would fail a test, so they are checked here.

# Source only, never build output: `tools/*/target` and `fuzz/target` hold generated code, and a
# dependency that emits an `extern "C"` line into OUT_DIR would otherwise fail this on build state.
src_grep() { grep -rn --exclude-dir=target "$@" crates apps tools fuzz; }

# 6a. No package named for Dalamud or FFXIV-domain code, in a resolved graph or in a manifest. Both,
#     because neither alone covers the repo: a lockfile carries transitive pulls (which bind a crate
#     just as thoroughly as a declared one) but only two of the five workspaces here keep a tracked
#     one, and a manifest is tracked everywhere but names only direct dependencies. deny.toml names the
#     two crates this project was actually tempted by; this is the pattern sweep behind it.
locks=$(find . -name Cargo.lock -not -path '*/target/*' -not -path './References/*' | sort)
manifests=$(find . -name Cargo.toml -not -path '*/target/*' -not -path './References/*' | sort)
bad=$(
  {
    [ -z "$locks" ] || grep -hE '^name = ' $locks | sed 's/^name = "//; s/"$//'
    # The leading key of every line, comments stripped first: a dependency is `name = …`, and a comment
    # naming Dalamud is exactly what this crate's manifest legitimately carries.
    [ -z "$manifests" ] || sed 's/#.*//' $manifests | grep -oE '^[A-Za-z0-9_-]+'
  } | grep -iE '^(dalamud|goatcorp|xivlauncher|xivquicklauncher|ffxiv)' | sort -u || true
)
[ -z "$bad" ] || report "an FFXIV-domain package is declared or resolved somewhere in this repo" "$bad"

# 6b. No foreign-function linkage and no build script anywhere: both are ways to bind a native artifact
#     into this binary, and neither has ever been needed.
hits=$(src_grep -E '#\[link|extern[[:space:]]+"C"|^[[:space:]]*links[[:space:]]*=' \
  --include='*.rs' --include='Cargo.toml' || true)
[ -z "$hits" ] || report "foreign-function linkage" "$hits"
hits=$(find crates apps tools fuzz -name build.rs -not -path '*/target/*' || true)
[ -z "$hits" ] || report "a build script can link or generate against a foreign artifact" "$hits"

# 6c. No dynamic loading: the other way to reach a native artifact without declaring a dependency.
hits=$(src_grep -E '\b(libloading|dlopen|dlsym|LoadLibraryW?|GetProcAddress)\b' \
  --include='*.rs' --include='Cargo.toml' || true)
[ -z "$hits" ] || report "dynamic library loading" "$hits"

# 6d. Nothing vendored or embedded from Dalamud or from the reference launcher (which is GPL-3.0 and is
#     read as a spec, never copied).
hits=$(src_grep -iE 'include_(bytes|str)!\([^)]*(dalamud|goatcorp|xivquicklauncher|References/)' \
  --include='*.rs' || true)
[ -z "$hits" ] || report "a Dalamud or reference-launcher artifact is embedded in the build" "$hits"

# 6e. The distribution endpoint stays catalog data. Prose may name goatcorp and should; a value may not,
#     because a compiled-in endpoint is one that cannot be corrected by an edit and a re-sign. So the
#     scan drops comment lines, `tests.rs` siblings, and inline `#[cfg(test)] mod … { … }` blocks: a
#     fixture has to be able to name the host it stands in for.
#
#     The test blocks are skipped by tracking brace depth, not by cutting the file at its first
#     `#[cfg(test)]`. That attribute also sits on a `mod x;` declaration near the top of a file and on
#     single methods mid-`impl`, so cutting there hid most of several files, including this crate's own
#     root. Anything the scanner does not recognize stays scanned, which is the direction that fails
#     loudly rather than quietly.
scan_source() {
  awk '
    /^#\[cfg\(test\)\]$/ { pending = 1; next }
    pending && /^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?mod[[:space:]]+[A-Za-z_]+[[:space:]]*\{/ {
      skip = 1; depth = 0; pending = 0
    }
    pending { pending = 0 }
    skip {
      depth += gsub(/\{/, "{") - gsub(/\}/, "}")
      if (depth <= 0) skip = 0
      next
    }
    { print FILENAME ":" FNR ":" $0 }
  ' "$1"
}
hits=$(find crates apps -path '*/src/*' -name '*.rs' -not -name 'tests.rs' -not -path '*/target/*' \
  | sort \
  | while read -r f; do scan_source "$f"; done \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
  | grep -E 'goats\.dev|kamori' || true)
[ -z "$hits" ] || report "a distribution endpoint is compiled in rather than read from the catalog" "$hits"

# 6f. The installable-component surface stays removed. It was deleted with the catalog that fed it, and
#     the check that said so was run by hand once; a reintroduced profile field or command group would
#     redden nothing today. What may remain is the signed file's own type name and the migration that
#     strips the retired profile key.
#
#     Matched per identifier rather than per line, because the two names sit together in one `use` today
#     and dropping the whole line would hide a reintroduced type behind rustfmt's wrapping.
hits=$(grep -rnoE '\bComponent[A-Za-z0-9_]*' crates/apogee-core/src apps/apogee-cli/src \
  --include='*.rs' | grep -v ':ComponentManifest$' || true)
[ -z "$hits" ] || report "an installable-component type is back in the launcher" "$hits"
hits=$(grep -rnE '(\.|\bpub )components\b|\bcomponents:' \
  crates/apogee-core/src apps/apogee-cli/src --include='*.rs' || true)
[ -z "$hits" ] || report "a component set is back on the launcher's own model" "$hits"

# Informational: remaining stub markers (never fails).
printf 'stub markers (todo!/unimplemented!): %s\n' \
  "$(grep -roE 'todo!|unimplemented!' crates/*/src --include='*.rs' | wc -l | tr -d ' ')"

exit $status
