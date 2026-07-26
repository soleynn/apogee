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
      // Paths under C: that must exist once this verb has been applied. Required for a verb with a
      // `run` op; optional otherwise, since a verb whose whole effect is a registry value has nothing
      // on disk to look for.
      "verify": ["<relative to C:>"],
      "ops": [
        { "registry": { "key": "HKCU\\…", "name": "…",
                        "type": "string" | "expand_string" | "dword" | "disabled",
                        "value": "…" } },
        // Omit `name` to remove the key and its subtree; a subtree removal must name a key at least
        // three components below its root.
        { "registry_delete": { "key": "HKLM\\…", "name": "…" } },
        { "files": { "url": "https://…", "sha256": "<64 hex>",
                     "archive": { "format": "zip" }, "into": "<relative to C:>" } },
        { "run": { "url": "https://…", "sha256": "<64 hex>", "file_name": "setup.exe",
                   "args": ["/q"], "env": [["WINEDLLOVERRIDES", "fusion=b"]],
                   "timeout_secs": 1800 } }
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

## Why a verb states what it produces

`verify` is the field that makes a verb's effect checkable instead of merely recorded, and it does three
jobs at once:

- A verb whose ops "succeeded" without producing these paths is a **failure**, so a half-finished install
  is not remembered as done and the next `ensure` tries again.
- A verb the prefix records but whose paths have since **gone** is applied again. That is not theoretical:
  Proton removes a `Microsoft.NET` directory it judges broken on a prefix upgrade, so without this the
  record would say .NET is installed while it is not, forever.
- It is the same evidence a health view would want.

It is optional, and empty is the honest answer for a verb whose whole effect is a registry value — there
is no file to look for, and the prefix's record is the only evidence there is. A verb with a `run` op may
**not** be empty, and is refused at parse time if it is.

## Why the op list is four, and why `run` is the shape it is

Three of the ops are idempotent by construction: a registry write overwrites rather than adds, a removal
treats "it was not there" as success, and a file placement overwrites. That is the selection criterion,
not a coincidence — anything a verb does has to be safe to do twice, because the only thing between a
re-apply and a re-run is the prefix's own record.

`run` is the exception and is deliberately narrow. It runs a **pinned download and nothing else**: it
cannot invoke something already in the prefix, there is no shell, and its verb must carry a `verify`. An
opaque installer's exit status is not evidence — several vendor installers exit non-zero having worked and
several exit zero having done nothing — so the status is reported and the `verify` is what decides.

The one row that uses it is `dotnet48`, for ACT. It is the least certain thing in this catalog: six ops,
one of which is a 120 MB Microsoft installer, and the sequence has **not yet been observed to complete on a
real runner**. Its `verify` is what makes that a reported failure with a retry rather than a silent one,
and the ACT row still names `winetricks`/`protontricks` as the fallback. Apogee is not a winetricks: the op
set stays at four, and a component needing something these cannot express states it as a caveat instead.

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
