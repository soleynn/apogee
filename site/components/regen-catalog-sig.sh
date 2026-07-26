#!/usr/bin/env bash
# Re-sign site/components/manifest.json with the offline component-catalog seed, producing
# manifest.json.sig. The seed is never committed; point COMPONENT_CATALOG_SEED at it, or keep it at the
# default staging path.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
seed="${COMPONENT_CATALOG_SEED:-$root/.catalog-signing/component-staging.seed}"
cargo run --quiet --manifest-path "$root/tools/catalog-sign/Cargo.toml" -- \
  sign "$seed" "$here/manifest.json" "$here/manifest.json.sig"
echo "signed $here/manifest.json"
