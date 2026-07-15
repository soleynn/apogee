#!/usr/bin/env bash
# Mechanical architecture and source-hygiene checks. Run locally with `bash scripts/audit.sh`.
# clippy already forbids unwrap/expect/panic!/exit/dbg workspace-wide, so those are not re-checked.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
report() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$2" | sed 's/^/  /' >&2; status=1; }

# 1. Byte-order conversions live only in sqex-crypto's `bytes` module.
hits=$(grep -rnE '(from|to)_(le|be)_bytes' crates/sqex-crypto/src --include='*.rs' \
  | grep -v '/bytes\.rs:' || true)
[ -z "$hits" ] || report "byte-order conversion outside sqex-crypto/src/bytes.rs" "$hits"

# 2. No ambient global state in the library crates.
libs() { grep -rnE "$1" crates/*/src --include='*.rs' | grep -v '/apogee-test-support/' || true; }
hits=$(libs '\bstatic[[:space:]]+mut\b'); [ -z "$hits" ] || report "mutable static in a library" "$hits"
hits=$(libs 'lazy_static!|once_cell');   [ -z "$hits" ] || report "lazy global singleton" "$hits"
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

# Informational: remaining stub markers (never fails).
printf 'stub markers (todo!/unimplemented!): %s\n' \
  "$(grep -roE 'todo!|unimplemented!' crates/*/src --include='*.rs' | wc -l | tr -d ' ')"

exit $status
