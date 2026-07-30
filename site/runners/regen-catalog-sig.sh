#!/usr/bin/env bash
# Re-sign site/runners/manifest.json with the offline runner-catalog seed, producing manifest.json.sig.
# The seed is never committed; point RUNNER_CATALOG_SEED at it, or keep it at the default staging path.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
seed="${RUNNER_CATALOG_SEED:-$root/.catalog-signing/staging.seed}"
cargo run --quiet --manifest-path "$root/tools/catalog-sign/Cargo.toml" -- \
  sign "$seed" "$here/manifest.json" "$here/manifest.json.sig"
echo "signed $here/manifest.json"
