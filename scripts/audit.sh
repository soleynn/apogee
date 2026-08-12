#!/usr/bin/env bash
# Mechanical architecture and source-hygiene checks. Run locally with `bash scripts/audit.sh`.
# clippy already forbids unwrap/expect/panic!/exit/dbg workspace-wide, so those are not re-checked.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
report() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$2" | sed 's/^/  /' >&2; status=1; }

# 1. Byte-order conversions live only in each crate's one endianness home: the `bytes` module for
#    the wire-format crates (ZiPatch is the mixed-endian format, so this gate matters most there),
#    and `journal.rs` for apogee-fetch, whose only byte layout is the frozen `.apdl` sidecar.
for pair in sqex-crypto:bytes apogee-sqpack:bytes apogee-zipatch:bytes apogee-fetch:journal; do
  c=${pair%%:*} home=${pair##*:}
  hits=$(grep -rnE '(from|to)_(le|be)_bytes' "crates/$c/src" --include='*.rs' \
    | grep -v "/${home}\.rs:" || true)
  [ -z "$hits" ] || report "byte-order conversion outside $c/src/${home}.rs" "$hits"
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

# 4b. The signed catalogs are still the bytes they were signed as, and the checkout cannot rewrite
#    them. Both are embedded with `include_bytes!` and verified against a compiled-in key, so a
#    carriage return anywhere in one means the signature cannot verify in the binary that carries it.
#    Two ways that happens: a checkout that converts line endings (which is the default on Windows,
#    and is what `.gitattributes` now turns off), or a re-sign written out by an editor that added
#    them. The first is a build nobody can verify on that platform; the second reaches every
#    platform. Checked on the bytes rather than on the setting, because the setting is only half of
#    it.
grep -q '^\* -text$' .gitattributes 2>/dev/null \
  || report "the checkout may rewrite line endings in byte-exact artifacts" \
     ".gitattributes does not disable text conversion, so a Windows checkout corrupts the signed catalogs"
for m in site/indexes/manifest.json site/components/manifest.json; do
  [ -f "$m" ] || continue
  ! grep -qU $'\r' "$m" || report "a signed manifest carries carriage returns" \
    "$m cannot verify against the compiled-in key with these bytes"
done

# 4a. Network never crosses the privilege boundary. The elevated worker applies local files the
#    unprivileged launcher already fetched; it has no transfer of its own, and the shortest honest
#    statement of that is a dependency graph with nothing in it that can open a socket to a host.
#    Asserted off the resolver rather than the manifest, because the manifest of the one crate says
#    nothing about what its dependencies drag in, and because this crate's own tests dev-depend on
#    the launcher side: those edges put an HTTP client one `-e normal` away, so the resolved normal
#    graph is the only thing that distinguishes "cannot reach it" from "does not name it".
reachable=$(cargo tree -p apogee-elevated -e normal --prefix none -f '{p}' | awk '{print $1}' | sort -u)
bad=$(grep -xiE 'reqwest|hyper|hyper-util|h2|http|http-body|http-body-util|url|rustls|tokio-rustls|native-tls|openssl|apogee-fetch|apogee-patcher|apogee-core' <<<"$reachable" || true)
[ -z "$bad" ] || report "the privileged worker can reach the network" "$bad"

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

# 7. The fallback secret store's cryptography has one home. Key derivation, sealing, and the system
#    random source live in the module that documents what each of them is for and what none of them
#    buys; a second path to a key grown elsewhere in the crate would be one nobody reviewed against
#    that. The other backends do no cryptography of their own: the platform stores encrypt their own
#    items, which is the whole reason they are preferred.
hits=$(grep -rnE 'XChaCha20Poly1305|Argon2|getrandom::' crates/apogee-secrets/src --include='*.rs'   | grep -v '/encrypted_file/' || true)
[ -z "$hits" ] || report "cryptography outside the fallback store's module" "$hits"

# 8. Only a front end may say the user asked for the encrypted fallback. The token that authorizes
#    creating or destroying that store has one constructor, and a library minting its own would be
#    creating a store on the user's behalf, which is the silent fallback the design refuses. The crate
#    that defines the token is exempt, because its own tests construct one; `apps/` is where the
#    layers that can actually ask a user live, so it is not scanned.
hits=$(grep -rn 'Consent::granted' crates/*/src --include='*.rs'   | grep -v '^crates/apogee-secrets/src/' | grep -v 'ListenerConsent::granted' || true)
[ -z "$hits" ] || report "a library mints its own fallback-store consent" "$hits"

# 8b. The same rule for the other thing only a user may ask for: opening a port on their network while
#    a login waits for a code. Pointing an account at the local listener takes a token with one
#    constructor, and a library minting its own would be opening that port on the user's behalf, which
#    is the silent default this design refuses just as firmly as a silent fallback store. Gate 8's grep
#    is name-specific and would never have seen this token.
#
#    Scanned through `scan_source` (6e) rather than with a plain grep, so an inline `#[cfg(test)]`
#    module is skipped by brace depth: a test that exercises the verb has to construct the token, and
#    the alternative is a rule that dictates which file a crate's tests live in. `tests.rs` siblings are
#    dropped for the same reason. The crate that defines the token is exempt, and `apps/` is not
#    scanned at all, because that is where the layers that can actually ask a user live.
hits=$(find crates -path '*/src/*' -name '*.rs' -not -name 'tests.rs' -not -path '*/target/*' \
  -not -path 'crates/apogee-otp/src/*' \
  | sort \
  | while read -r f; do scan_source "$f"; done \
  | grep 'ListenerConsent::granted' || true)
[ -z "$hits" ] || report "a library opens a network port on the user's behalf" "$hits"

# 9. The Keychain store attaches no backend without its `keychain` feature: without it the crate
#    compiles to a shell that supports no operation. Dropping the feature from the Apple dependency
#    line is a build whose secrets go nowhere and whose probe still answers. The Linux side of that
#    trap is caught by a job with a real provider on a real bus; the Apple side has no hardware
#    anywhere in this repository's checks, so it is caught here, off the resolved graph.
#
#    The second half is the resolver split. Both platform classifications reach the error the store
#    boxed by downcasting to a type both crates have to have got from the same package. A split hands
#    them two, and the downcast then fails silently: every locked store goes back to being reported
#    as broken, with nothing anywhere saying so. It is not a compile error and no test that builds
#    green would notice, which is why it is asserted off the graph on both platforms.
#
#    `zbus` needs no assertion of its own. The Secret Service error nests it, so the Linux match arms
#    name `zbus::Error` inside `secret_service::Error`, and two majors there is a type mismatch the
#    compiler rejects rather than a downcast that quietly stops matching.
same_package_under() {
  # $1: the metadata blob, $2: the dependency's lib name, $3..: the packages that must agree on it.
  # Prints one `package: resolved` line per input and fails if they disagree or any resolved nothing.
  local meta="$1" dep="$2" pkg first= current= detail= agreed=0
  shift 2
  for pkg in "$@"; do
    current=$(jq -r --arg p "$pkg" --arg d "$dep" \
      '(.packages[]|select(.name==$p)|.id) as $id
       | .resolve.nodes[]|select(.id==$id)|.deps[]
       | select(.name==$d)|.pkg' <<<"$meta")
    detail+="$pkg: ${current:-none}"$'\n'
    [ -n "$first" ] || first="$current"
    { [ -n "$current" ] && [ "$current" = "$first" ]; } || agreed=1
  done
  [ "$agreed" = 0 ] || { printf '%s' "$detail"; return 1; }
  return 0
}

for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios; do
  apple=$(cargo metadata --format-version 1 --filter-platform "$target")
  store_id=$(jq -r '.packages[]|select(.name=="apple-native-keyring-store")|.id' <<<"$apple")
  store=$(jq -c --arg id "$store_id" '.resolve.nodes[]|select(.id==$id)' <<<"$apple")
  # The feature and the edge it gates are both asserted: the feature is what the manifest line says,
  # and the dependency is what the resolver did with it under this target's cfg.
  jq -e '.features|index("keychain")' <<<"$store" >/dev/null \
    || report "the Keychain store attaches no backend on $target" \
      "the keychain feature is not selected for this target"
  jq -e '.deps[]|select(.name=="security_framework")' <<<"$store" >/dev/null \
    || report "the Keychain store has no backend on $target" \
      "security-framework is not among its resolved dependencies"

  # iOS is exempt: nothing here builds for it, so the framework crate is taken on macOS alone and
  # that target reads no status at all.
  if [ "$target" != aarch64-apple-ios ]; then
    detail=$(same_package_under "$apple" security_framework apogee-secrets apple-native-keyring-store) \
      || report "apogee-secrets and the Keychain store read different security-framework packages on $target" \
        "$detail"
  fi
done

# The same split on Linux, where the classification this crate does most of reads the Secret Service
# error out of what the store boxed. A live job does catch this one, by asserting a locked collection
# still classifies as locked; it is asserted here as well because that job is not a required check,
# and because the graph says which package resolved without needing a bus to say it.
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  linux=$(cargo metadata --format-version 1 --filter-platform "$target")
  jq -e '.packages[]|select(.name=="zbus-secret-service-keyring-store")' <<<"$linux" >/dev/null \
    || report "no Secret Service store resolves on $target" \
      "zbus-secret-service-keyring-store is not in the resolved graph"
  detail=$(same_package_under "$linux" secret_service apogee-secrets zbus-secret-service-keyring-store) \
    || report "apogee-secrets and the Secret Service store read different secret-service packages on $target" \
      "$detail"
done

# 9a. The same trap one layer up, in this repository's own code. `apogee-secrets/mock` compiles an
#    in-process map that answers every call, and it exists for other crates' tests. Two dev-dependency
#    edges turn it on, and a dev edge is invisible to a release; but Cargo unifies features across
#    everything one invocation builds, so any `--workspace --all-targets` run resolves a single
#    apogee-secrets lib carrying `mock` and links the shipping binary against it. That is what every
#    required test job already builds, which means the only thing keeping the fake store out of a
#    release is that no *normal* edge selects the feature. Nothing else says so, and a dependency line
#    is one edit away from saying otherwise, so it is asserted here off the resolver.
#
#    `cargo tree -p` resolves as if building that package alone, which is the shipping selection; the
#    dev edges elsewhere in the workspace do not fold in and cannot produce a false positive. `-e
#    normal` drops the dev edges the package declares itself for the same reason. Features are printed
#    ahead of `{p}` because they are a comma-separated list with no spaces, so reading them from the
#    first field survives a checkout path that has one.
selection=$(cargo tree -p apogee-cli -e normal --prefix none -f '{f} {p}' \
  | awk '$2 == "apogee-secrets" { print $1 }' | sort -u)
if tr ',' '\n' <<<"$selection" | grep -qx mock; then
  report "the shipping launcher links the in-memory test secret store" \
    "$(printf '%s\n%s\n%s' \
      'a normal dependency edge selects apogee-secrets/mock, so a release keeps every' \
      'secret in a process-lifetime map and still reports a healthy store.' \
      "apogee-cli resolves apogee-secrets with: $selection")"
fi

# 9b. The shipping launcher can still read this machine's certificate authorities. `reqwest`'s
#    `rustls-tls` alone resolves to `rustls-tls-webpki-roots`, a Mozilla set compiled into the binary,
#    and under it the platform's store is never opened. `apogee-core/src/trust.rs` narrows the login
#    client to four embedded roots and offers `APOGEE_TLS_SYSTEM_ROOTS` as the one way out; that hatch
#    is for the user behind a TLS-intercepting proxy, whose root is installed on their machine and
#    nowhere else, so on a webpki-only build it restored a list that could not contain it and left
#    them exactly where they started. A unit test covers this, but only on a machine whose store the
#    test can write to, so the resolved feature is asserted here too. Read off `cargo tree` for the
#    same reason gate 9a is: the manifest names a workspace dependency, and what any one package
#    resolves is a different question from what the line says.
selection=$(cargo tree -p apogee-cli -e normal --prefix none -f '{f} {p}' \
  | awk '$2 == "reqwest" { print $1 }' | sort -u)
if ! tr ',' '\n' <<<"$selection" | grep -qx rustls-tls-native-roots; then
  report "the launcher cannot read this machine's certificate authorities" \
    "$(printf '%s\n%s\n%s' \
      'reqwest resolves without rustls-tls-native-roots, so APOGEE_TLS_SYSTEM_ROOTS restores a' \
      'root set compiled into the binary and a user behind an intercepting proxy has no way in.' \
      "apogee-cli resolves reqwest with: $selection")"
fi

# 9c. The download engine's test seams stay out of the shipping selection. `apogee-fetch/testing`
#    compiles a builder knob that adds trusted roots beside the system store, and `fuzzing` exports
#    the journal decoder; both exist for other crates' tests and for the fuzz workspace, and both are
#    declared outside the crate's version commitment on that basis. As with gate 9a, dev edges turn
#    them on all over the workspace and Cargo unifies features across a `--workspace --all-targets`
#    build, so the only thing keeping them out of a release is that no normal edge selects either.
#    Asserted off the resolver, which is the shipping selection.
selection=$(cargo tree -p apogee-cli -e normal --prefix none -f '{f} {p}' \
  | awk '$2 == "apogee-fetch" { print $1 }' | sort -u)
if tr ',' '\n' <<<"$selection" | grep -qxE 'testing|fuzzing'; then
  report "the shipping launcher compiles apogee-fetch's test seams" \
    "$(printf '%s\n%s\n%s' \
      'a normal dependency edge selects apogee-fetch/testing or /fuzzing, so a release build' \
      'carries the extra-root knob or the fuzz-only journal decoder.' \
      "apogee-cli resolves apogee-fetch with: $selection")"
fi

# 10. Unsafe code has exactly one home. The workspace lint is `deny` rather than `forbid` so that the
#    Windows arm of the fallback secret store can set an owner-only access list through advapi32,
#    which the standard library has no API for. `deny` is overridable where `forbid` was not, and the
#    relaxation reaches every test target in the workspace besides, so the shape it bought is checked
#    here rather than left to the lint. Crate roots still carry their own attribute, which is the
#    line the `unsafe_code` filter drops; a comment that merely says the word is dropped separately.
unsafe_home='crates/apogee-secrets/src/encrypted_file/disk.rs'
# Every target `[lints] workspace = true` reaches, not just `src`. An integration test, an example or
# a bench is exactly where an `unsafe` block would be waved through as scaffolding, so scanning only
# the sources left the half of the relaxation this check was written to cover unguarded. A pattern
# matching no directory is dropped instead of passed on: bash leaves it unexpanded and `grep` would
# take the literal glob for a path and fail on it.
scan=()
for d in crates/*/src apps/*/src crates/*/tests apps/*/tests \
         crates/*/examples apps/*/examples crates/*/benches apps/*/benches; do
  if [ -d "$d" ]; then scan+=("$d"); fi
done
hits=$(grep -rnE '\bunsafe\b' "${scan[@]}" --include='*.rs' \
  | grep -v "^$unsafe_home:" | grep -v 'unsafe_code' \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*)' || true)
[ -z "$hits" ] || report "unsafe outside the secret store's Windows permission arm" "$hits"
grep -qE '^mod win_acl \{$' "$unsafe_home" \
  || report "the one module allowed to hold unsafe is gone; the workspace lint can go back to forbid" \
     "$unsafe_home"

# Informational: remaining stub markers (never fails).
printf 'stub markers (todo!/unimplemented!): %s\n' \
  "$(grep -roE 'todo!|unimplemented!' crates/*/src --include='*.rs' | wc -l | tr -d ' ')"

exit $status
