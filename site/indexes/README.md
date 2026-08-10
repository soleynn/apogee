# Index catalog

`manifest.json` pins the block indexes (`.apzi`) that repair verifies an install against, one row per
repo and version. It is authenticated end to end:

- Each `.apzi` is **derived** from the repo's patch chain, so anyone can rebuild it from the same patch
  files. Its digest pin authenticates the bytes.
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
      "blake3": "<64 hex>",
      "sha256": "<64 hex>" }
  ]
}
```

`repo` is `boot`, `game`, or `ex{n}` (an expansion). `version` is the version the chain brings the repo
to (repair cross-checks it against the index's own recorded version).

A row may pin under `blake3`, under `sha256`, or under both, and a client that reads both prefers
`blake3`. Publish both: the older key keeps a client released before BLAKE3 reading this file, and the
newer one is what current clients verify against. They must describe the same bytes, which is why both
come from one read of the file (below) rather than from two separate commands.

## Patch-day runbook

1. **Build** the index from the version's patch chain (reproducible, no network):
   ```
   cargo run -p apogee-zipatch --example zipatch_tool -- \
     index artifacts/<repo>-<version>.apzi <version> <patch>...
   ```
2. **Pin**: hash the artifact once and paste both lines into the row in `manifest.json` (repo,
   version, hosted url, pins):
   ```
   cargo run --manifest-path ../../tools/catalog-sign/Cargo.toml -- \
     pin artifacts/<repo>-<version>.apzi
   ```
3. **Sign** the exact manifest bytes with the offline seed:
   ```
   ./regen-catalog-sig.sh          # wraps tools/catalog-sign
   ```
4. **Publish** `manifest.json`, `manifest.json.sig`, and the new `artifacts/*.apzi`.
