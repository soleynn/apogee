# Index catalog

`manifest.json` pins the block indexes (`.apzi`) that repair verifies an install against, one row per
repo and version. It is authenticated end to end:

- Each `.apzi` is **derived** from the repo's patch chain, so anyone can rebuild it from the same patch
  files. Its digest pin authenticates the bytes.
- The manifest carrying the pins is **Ed25519-signed** (`manifest.json.sig`, detached, 64 bytes) and
  verified against a key compiled into the client (`apogee_patcher::INDEX_CATALOG_PUBLIC_KEY`) before
  any pin is trusted.

The rows here are signed with a **staging** key for development; the production key ceremony is
separate.

**Artifacts are release assets, not committed files.** Only `manifest.json` and its signature live in
git. A full set of indexes is around 94 MB against a 24 MiB repo history, every patch day adds
another set, and git history keeps all of it forever, so the bytes go to a GitHub release
(`indexes-<game version>`) and the rows point at its download URLs. Nothing is lost by this: the
indexes are derived data, and the signature plus the pin authenticate them wherever they are served
from, so the host is untrusted by design.

Boot's artifact is the one exception, kept at `crates/apogee-patcher/tests/fixtures/` (47 KB) so the
catalog test can check a row's pin against real bytes offline. Re-author boot and that fixture must be
replaced too, or the test fails.

## Schema

```json
{
  "version": 1,
  "indexes": [
    { "repo": "game", "version": "<YYYY.MM.DD.PPPP.RRRR>",
      "url": "https://github.com/<owner>/<repo>/releases/download/indexes-<version>/<repo>-<version>.apzi",
      "blake3": "<64 hex>",
      "sha256": "<64 hex>",
      "source_base": "http://patch-dl.ffxiv.com/<repo path>/<path id>/" }
  ]
}
```

`repo` is `boot`, `game`, or `ex{n}` (an expansion). `version` is the version the chain brings the repo
to (repair cross-checks it against the index's own recorded version).

`source_base` is where the source patches this index references are served, so a repair forms each one
as `{source_base}/{name}` and heals a repo whose patch cache is gone. Take it from the patchlist
entries for that repo, path and all: Square Enix serves each repo under an opaque id
(`game/ex1/6b936f08/`), only boot's and the base game's are stable enough for the client to compile in,
and a repair fetches no patchlist to read the rest from.

It is optional. A row without one leaves the client on those two compiled-in bases, so an expansion
without one heals only from a populated cache. It must otherwise be an absolute `http` or `https` URL
**ending in `/`**, or the manifest is refused: without the slash the join drops the last path segment,
which is the id, and every source resolves to a well-formed URL that 404s.

A row may pin under `blake3`, under `sha256`, or under both, and a client that reads both prefers
`blake3`. Publish both: the older key keeps a client released before BLAKE3 reading this file, and the
newer one is what current clients verify against. They must describe the same bytes, which is why both
come from one read of the file (below) rather than from two separate commands.

## Patch-day runbook

1. **Build** the index from the version's patch chain (reproducible, no network). `<build>` is any
   scratch directory outside the repo, since these files are never committed:
   ```
   cargo run -p apogee-zipatch --example zipatch_tool -- \
     index <build>/<repo>-<version>.apzi <version> <patch>...
   ```
   The patches go in **patchlist order**, which is not the order their names sort in: a chain mixes
   `H` hist patches with `D` deltas, and a hist series suffixes its versions (`…0000a` … `…0000ah`),
   so sorting filenames puts the newest delta first. Take the order from an install's
   `patch: <repo> #<n> applied -> <version>` lines, which the cache does not preserve. One entry per
   hist series reports the bare series version there while its file carries the series' last suffix,
   so that one is named by elimination rather than by matching.
2. **Check** it against an install already at that version, before pinning bytes nothing has read:
   ```
   cargo run -p apogee-zipatch --example zipatch_tool -- verify <install>/boot <build>/boot-<v>.apzi
   cargo run -p apogee-zipatch --example zipatch_tool -- verify <install>/game <build>/ex1-<v>.apzi
   ```
   The root is the repo's subtree, not the install root: boot's target paths are relative to `boot/`,
   and the game's and every expansion's to `game/`. Pointed at the install root instead, every target
   reads as missing.
3. **Upload** the artifacts first, so the URLs the manifest is about to carry already resolve:
   ```
   gh release create indexes-<version> --latest=false \
     --title "Repair block indexes (game <version>)" <build>/*.apzi
   ```
4. **Pin**: hash each artifact once and paste both lines into its row in `manifest.json` (repo,
   version, the release download url, pins, and the `source_base`, which is the repo's directory in
   the patch cache with the host put back: the cache mirrors the URL path, id and all):
   ```
   cargo run --manifest-path ../../tools/catalog-sign/Cargo.toml -- \
     pin <build>/<repo>-<version>.apzi
   ```
5. **Sign** the exact manifest bytes with the offline seed:
   ```
   ./regen-catalog-sig.sh          # wraps tools/catalog-sign
   ```
6. **Publish** `manifest.json` and `manifest.json.sig` (a push to `main` deploys them), and replace
   `crates/apogee-patcher/tests/fixtures/boot-*.apzi` if boot was re-authored.
7. **Prove it end to end** before calling it done, against an empty data root so nothing is cached:
   ```
   apogee-cli repair --profile <p>
   ```
   A row whose bytes were never uploaded fails on `http 404`, and one pinned over the wrong bytes
   fails on the digest, both after the manifest signature has already passed.
