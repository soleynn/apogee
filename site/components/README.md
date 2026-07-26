# Component catalog

`manifest.json` describes every companion tool and prefix-setup verb the launcher can install, one row
each. It is authenticated the same way the runner and index catalogs are, with its own key:

- Each artifact is **sha256-pinned**, so the bytes are authenticated whoever serves them.
- The manifest carrying the pins is **Ed25519-signed** (`manifest.json.sig`, detached, 64 bytes) and
  verified against a key compiled into the client (`apogee_addons::COMPONENT_PUBLIC_KEY`) before any pin
  is trusted.

Its own key rather than the runner catalog's: the two are published by different steps on different
cadences, and one compromised signer should not authenticate both.

Signed with a **staging** key for development; the production key ceremony is separate.

## Schema

```jsonc
{
  "version": 1,
  "injectables": [
    // A companion whose bytes come from its own versioned, integrity-checked distribution. A pointer,
    // never a pin, and reached only when the component is enabled.
    { "name": "…", "kind": "dalamud", "distribution": "https://…",
      "tier": "best_effort", "note": "<what the tier costs>", "caveats": ["…"] }
  ],
  "tools": [
    { "name": "…", "version": "…",
      "kind": "prefix_tool" | "external_native",
      "url": "https://…", "sha256": "<64 hex>",
      "archive": { "format": "zip" | "tar.gz" | "tar.xz" | "tar.zst", "strip_prefix": "…" },
      "into": "<relative destination>",
      "verbs": ["<verb this needs applied first>"],
      "caveats": ["<surfaced at install time>"],
      "register": { "program": "<relative to the install dir>", "args": ["…"],
                    "trigger": "with_game" | "with_game_keep_running" | "on_close" },
      "attach": "game_pid" }
  ],
  "verbs": [
    { "name": "…", "reason": "<why it exists>",
      "ops": [
        { "registry": { "key": "HKCU\\…", "name": "…",
                        "type": "string" | "expand_string" | "dword" | "disabled",
                        "value": "…" } },
        { "files": { "url": "https://…", "sha256": "<64 hex>",
                     "archive": { "format": "zip" }, "into": "<relative to C:>" } }
      ] }
  ]
}
```

`kind` decides both where a tool's files go and how it runs: `prefix_tool` installs under the prefix's
`C:` and runs through the prefix's runner, `external_native` installs under the host component directory
and runs directly. `into` is relative to whichever of those roots applies, and is refused if it is
absolute, climbs out, or carries a drive letter.

A name must be unique across all three lists, because it is what a profile stores and what the prefix's
`prefix.json` records. A verb named by a tool must exist.

`register` is optional: a component can be worth installing without being worth starting. `attach` marks
a companion whose loader takes the resolved game process id; it is carried for the phase that drives
those and is not read yet.

## Why the destinations are data

Several `into` values are informed guesses about where a Windows program looks for its own plugins. That
is exactly why they are rows rather than constants: correcting one is an edit here plus a re-sign, not a
release.

## Why the verb list is short

Verbs are described entirely by these ops, and there is deliberately no op that runs an arbitrary
installer. The first thing that wanted one was Microsoft's .NET Framework, for ACT: satisfying it means
running an opaque vendor installer, removing Wine's Mono, changing the reported Windows version, and
then losing all of it when Proton next upgrades the prefix. A verb that did some of that and reported
success would be worse than no verb, so the requirement is stated as a caveat on the row that needs it
and the user reaches for `winetricks` or `protontricks` themselves. Apogee is not a winetricks.

That leaves the ops that are idempotent by construction: a registry write, which is overwritten rather
than added, and a pinned file placement, which is overwritten too. Anything a verb does has to be safe
to do twice, because the only thing standing between a re-apply and a re-run is the prefix's own record.

## Adding or updating a row

1. **Pin**: download the artifact and `sha256sum` it. Point `url` at the versioned upstream asset, never
   at a redirecting "latest" endpoint: the pin has to describe the bytes that URL will keep serving.
2. **Edit** `manifest.json`.
3. **Sign** the exact manifest bytes with the offline seed:
   ```
   ./regen-catalog-sig.sh          # wraps tools/catalog-sign
   ```
   Any reformatting after signing invalidates the signature, and a test in `apogee-addons` embeds both
   files and will fail if they disagree.
4. **Publish** `manifest.json` and `manifest.json.sig`.
