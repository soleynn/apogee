# Corpus manifest

`manifest.json` pins the boot-patch corpus by URL + SHA256. Each entry:

```json
{ "url": "http://.../D2017.01.10.0000.0001.patch", "sha256": "<64 hex>", "name": "boot-2017.01.10" }
```

The bytes are never committed. `corpus::fetch_cached` downloads each entry into the gitignored
`.corpus-cache/` (keyed by digest) and verifies it against the pin before a test reads it, reusing
`apogee-fetch`'s verified downloader so the pin covers the on-wire bytes.

## Recording a pin

Boot patches are served over plain HTTP and carry no upstream per-file hash, so the SHA256 is a
trust-on-first-download digest recorded once:

```
curl -s <url> -o patch.bin && sha256sum patch.bin
```

Enumerate the chain by reporting the base boot version to the unauthenticated boot-patchlist
endpoint (the surface `tools/boot-check` uses), then record one row per returned patch.
