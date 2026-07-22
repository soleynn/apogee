# Index catalog

`manifest.json` pins the block indexes (`.apzi`) that repair verifies an install against, one row per
repo and version. It is authenticated end to end:

- Each `.apzi` is **derived** from the repo's patch chain, so anyone can rebuild it from the same patch
  files. Its `sha256` pin authenticates the bytes.
- The manifest carrying the pins is **Ed25519-signed** (`manifest.json.sig`, detached, 64 bytes) and
  verified against a key compiled into the client (`apogee_patcher::INDEX_CATALOG_PUBLIC_KEY`) before
  any pin is trusted.

The sample entry here is signed with a **staging** key for development; the production key ceremony is
separate. Artifacts are served from `artifacts/` beside this manifest.

## Schema

```json
{
  "version": 1,
  "indexes": [
    { "repo": "game", "version": "<YYYY.MM.DD.PPPP.RRRR>",
      "url": "https://<host>/indexes/artifacts/<repo>-<version>.apzi",
      "sha256": "<64 hex>" }
  ]
}
```

`repo` is `boot`, `game`, or `ex{n}` (an expansion). `version` is the version the chain brings the repo
to (repair cross-checks it against the index's own recorded version).

## Patch-day runbook

1. **Build** the index from the version's patch chain (reproducible, no network):
   ```
   cargo run -p apogee-zipatch --example zipatch_tool -- \
     index artifacts/<repo>-<version>.apzi <version> <patch>...
   ```
2. **Pin**: `sha256sum artifacts/<repo>-<version>.apzi`, and add or update the row in `manifest.json`
   (repo, version, hosted url, that sha256).
3. **Sign** the exact manifest bytes with the offline seed:
   ```
   ./regen-catalog-sig.sh          # wraps tools/catalog-sign
   ```
4. **Publish** `manifest.json`, `manifest.json.sig`, and the new `artifacts/*.apzi`.
