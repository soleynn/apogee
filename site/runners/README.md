# Runner catalog

`manifest.json` pins the runners a launch installs: the Wine and Proton builds, the umu launcher they
run under, and the DXVK build a prepared prefix gets. It is authenticated the same way the component
and index catalogs are, with its own key:

- Each artifact is **digest-pinned**, so the bytes are authenticated whoever serves them.
- The manifest carrying the pins is **Ed25519-signed** (`manifest.json.sig`, detached, 64 bytes) and
  verified against the keys compiled into the client (`apogee_runtime::CATALOG_PUBLIC_KEYS`) before any
  pin is trusted.

Its own keys rather than the component catalog's: the two are published by different steps on different
cadences, and one compromised signer should not authenticate both.

Signed with a **staging** key for development; the production key ceremony is separate.

A runner bump is an edit here and a re-sign, never a release. `artifacts/` holds the umu-launcher
tarball this site serves itself; every other row points at an upstream release asset.

## Schema

```jsonc
{
  "version": 1,
  "runners": [
    { "name": "…", "version": "…", "kind": "proton_umu" | "wine" | "custom",
      "url": "https://…", "blake3": "<64 hex>", "sha256": "<64 hex>",
      "archive": { "format": "tar.gz" | "tar.xz" | "tar.zst" | "zip",
                   "strip_prefix": "<the archive's own top directory>" },
      // Whether this build uses ntsync, which is a property of the build and not of the kernel.
      "ntsync": true | false }
  ],
  "tools": [
    // A supporting tool installed like a runner; `umu-launcher` is the only one.
    { "name": "…", "version": "…", "url": "https://…",
      "blake3": "<64 hex>", "sha256": "<64 hex>",
      "archive": { "format": "tar.gz", "strip_prefix": "…" } }
  ],
  "dxvk": [
    { "version": "…", "url": "https://…", "blake3": "<64 hex>", "sha256": "<64 hex>",
      "format": "tar.gz",
      // The dxvk-nvapi companion, all-or-nothing: both its URL and a pin, or neither.
      "nvapi_url": "https://…", "nvapi_blake3": "<64 hex>", "nvapi_sha256": "<64 hex>",
      "nvapi_format": "tar.gz" }
  ]
}
```

A runner is resolved by `name` and `version` together, so two versions of one build are two rows. The
**first** `dxvk` row is what a launch installs when nothing names a particular one, which keeps that
choice a matter of ordering this file rather than of changing a caller.

`strip_prefix` is the archive's own top directory, which is not always the file name: `wine-xiv`'s
tarball is built per distribution and its directory says only the build flavour.

`ntsync` omitted reads as **no**, and stating it is what keeps a launch on fsync. ntsync is selected by
setting no synchronization variable at all, so a build wrongly assumed to use it runs with neither
esync nor fsync and still reports success.

A row may pin under `blake3`, under `sha256`, or under both, and a client that reads both prefers
`blake3`. Publish both, so a client released before BLAKE3 keeps reading this file. `format` defaults to
`tar.gz`, and an unrecognized value is refused rather than guessed at.

## Adding or updating a row

1. **Pin** the artifact: download it and hash it once, which prints both lines to paste in:
   ```
   cargo run --manifest-path ../../tools/catalog-sign/Cargo.toml -- pin <downloaded-artifact>
   ```
   Point `url` at the versioned upstream asset, never at a redirecting "latest" endpoint, since the pin
   has to describe the bytes that URL will keep serving.
2. **Edit** `manifest.json`.
3. **Sign** the exact manifest bytes with the offline seed:
   ```
   ./regen-catalog-sig.sh          # wraps tools/catalog-sign
   ```
   Any reformatting after signing invalidates the signature, and a test in `apogee-runtime` embeds both
   files and will fail if they disagree.
4. **Publish** `manifest.json` and `manifest.json.sig`.

## Rotating the signing key

`CATALOG_PUBLIC_KEYS` is a list, current key first, and the list is what makes a rotation possible
without an outage. With a single key one of the two sides has to move first and the other is broken
until it catches up: re-sign first and every client in the field rejects the catalog until it updates,
ship the new key first and every updated client rejects the catalog until the re-sign. Neither is
acceptable for a file every launch reads.

Three releases, in this order, and no step may be skipped or reordered:

1. **Add** the new public key to `CATALOG_PUBLIC_KEYS` **after** the current one, and release. The
   catalog is still signed by the old key, and nothing about client behaviour changes. Generate the new
   seed with `catalog-sign keygen`, which prints the array body to paste; keep the seed offline beside
   the old one.
2. **Promote and re-sign**, once that release has had time to reach the field. Move the new key to the
   front of the list, re-sign `manifest.json` with the new seed, and publish both. Clients from step 1
   accept it because it is still in their list; older clients accept it because... they do not: this is
   the step that requires step 1 to have shipped, and how long to wait between the two is the only real
   decision in this procedure.
3. **Drop** the retired key from the list, and release. Rotation complete.

Two guardrails. `the_hosted_manifest_is_signed_by_the_key_in_use_today` fails if the hosted file is
still signed by anything but the first key in the list, so a rotation stuck between steps 2 and 3 is
loud rather than silent, which is precisely the failure the overlap window would otherwise hide until
step 3 broke everyone at once. And an entry that is not a valid key fails as
`CatalogError::TrustedKeyUnusable` naming its position, rather than as a signature that did not verify,
so a mistyped paste points at the binary instead of at this file.

A retired key is dropped rather than kept, because the window exists to finish a rotation and not to
keep an old signer trusted. If the old key is being rotated out because it was *compromised*, there is
no window: go straight to step 2 with a release that carries only the new key, and accept that older
clients cannot install a runner until they update. That is the correct trade, since the alternative is
continuing to trust a signer somebody else also holds.
