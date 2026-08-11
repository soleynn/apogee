# Corpus manifest

`manifest.json` pins the boot-patch corpus by URL + SHA256. Each entry:

```json
{ "url": "http://.../D2013.06.18.0000.0000.patch", "sha256": "<64 hex>", "name": "boot-2013.06.18.0000.0000" }
```

The bytes are never committed. `corpus::fetch_cached` downloads each entry into the gitignored
`.corpus-cache/` (keyed by digest) and verifies it against the pin before a test reads it, reusing
`apogee-fetch`'s verified downloader so the pin covers the on-wire bytes.

## Why the chain stops at the base patch

Square Enix serves two boot versions at a time and no more: the base every install starts from, and
the newest one. A boot patch is retired the moment a newer one supersedes it, and its URL then
answers `404` for good, which no retry or pin correction undoes. Measured 2026-08-10: the base
`2013.06.18.0000.0000` has been served since 2013 and is still the first row of the live patchlist,
while the newest slot turned over 21 times between 2022-04-22 and 2026-07-28, a median of about two
months.

So the corpus pins the base and nothing else. Pinning whichever patch is current alongside it buys
one more patch of coverage at the price of a gate that goes red every few months for a reason that is
not a regression, each time needing the oracle tree re-recorded by hand on a machine that can run the
reference applier.

What the base alone still proves: our applier reproduces the reference applier's tree byte-for-byte
over genuine Square Enix output (v2 framing, chunk CRCs, deflate blocks, a file written by several
commands), and an index built over those bytes verifies clean and reconstructs the same tree. What
leaves with the second patch is real-byte coverage of deleting a file, overwriting one already on
disk, and a `HIST`-typed header, each of which is a hand-built apply test in `apogee-zipatch`. The
current chain is still applied for real by the live check a maintainer runs against a real install
when Square Enix ships a patch.

## Recording a pin

Boot patches are served over plain HTTP and carry no upstream per-file hash, so the SHA256 is a
trust-on-first-download digest recorded once:

```
curl -s <url> -o patch.bin && sha256sum patch.bin
```

Enumerate the chain by reporting the base boot version to the unauthenticated boot-patchlist endpoint
(the surface `tools/boot-check` uses): the first row it returns is the entry pinned here. Which
patches are in the chain decides the tree they produce, so an edit to `manifest.json` also means
re-recording `fixtures/oracle/boot.tree.json` from the reference applier, run out of process, in the
same change.
