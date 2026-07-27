# Component catalog

`manifest.json` describes what the launcher sets up: the prefix-setup verbs it applies on its own, and
the companions it loads into the game. It is authenticated the same way the runner and index catalogs
are, with its own key:

- Each artifact the launcher itself fetches is **sha256-pinned**, so the bytes are authenticated whoever
  serves them.
- The manifest carrying the pins is **Ed25519-signed** (`manifest.json.sig`, detached, 64 bytes) and
  verified against the keys compiled into the client (`apogee_addons::COMPONENT_PUBLIC_KEYS`) before any
  pin or pointer is trusted.

Its own keys rather than the runner catalog's: the two are published by different steps on different
cadences, and one compromised signer should not authenticate both.

Signed with a **staging** key for development; the production key ceremony is separate.

## What it carries now

One injectable, Dalamud, and one verb, `no-desktop-integration`.

Neither is a menu. The verb is prefix hygiene the launch path applies to any prefix that is missing it,
so the list here *is* the setup rather than a set of things to pick from. Dalamud is reached from a
launch setting on a profile; this row is the data behind that setting, which is where its distribution
endpoint and its support tier live. A user who leaves the setting off contacts nothing.

There used to be a third list, `tools`, curating Windows desktop applications into a prefix. It is gone,
along with the combat-data companions that were its only rows (ACT, OverlayPlugin, Triggevent, and the
`dotnet48` verb they named). Validating them is what removed them. The verb worked: Microsoft's pinned
.NET Framework 4.8 installer exits 0 in about 72 seconds and lands 760 files, reproduced on five
throwaway prefixes across stock wine 10.0 and wine-xiv-staging 10.8. It was the wrong dependency. .NET
Framework cannot host managed code under any wine available, because wine's `mscoree.dll` only ever
loads Wine Mono and Microsoft's installer never ships an `mscoree.dll` of its own (it is an OS component
from Windows 7 on). ACT does run on wine-mono 9.4.0, which self-reports as ".NET v4.8.1+", but only
behind a stack of workarounds no row here could express: a patched `Advanced Combat Tracker.exe.config`,
`MONO_PATH` pointed at a plugin's own libs directory, ACT's update check turned off, a parser plugin that
ships nowhere but ACT's own first-run wizard, and a 220 MB Chromium bundle OverlayPlugin fetches at
runtime, unpinned, and re-fetches whenever it is missing.

The structural argument behind removing the list rather than fixing the rows: Dalamud already is the
addon manager. IINACT, NoClippy and everything else worth having installs through its plugin repository,
in-process and patch-aware, with no wine specifics to get wrong. A second catalog curating Windows
desktop applications into a prefix competes with that instead of adding to it. Anything outside it is
`addon add`'s job, pointed at the user's own install.

Whether this file should remain a signed hosted manifest at all, rather than the verb becoming a
compiled-in constant, is still open. What keeps it here for now is the injectable row: it carries a live
third-party endpoint and a support tier, and correcting either should be an edit and a re-sign rather
than a release.

## Schema

```jsonc
{
  "version": 1,
  "injectables": [
    // A companion whose bytes come from its own versioned, integrity-checked distribution. A pointer,
    // never a pin, and reached only once a launch has asked for it.
    { "name": "…", "kind": "dalamud", "distribution": "https://…",
      "tier": "first_class" | "best_effort", "note": "<what the tier costs>",
      "caveats": ["…"] }
  ],
  "verbs": [
    { "name": "…", "reason": "<why it exists, shown when it runs>",
      // Paths under C: that must exist once this verb has been applied. Optional: a verb whose whole
      // effect is a registry value has nothing on disk to look for.
      "verify": ["<relative to C:>"],
      "ops": [
        { "registry": { "key": "HKCU\\…", "name": "…",
                        "type": "string" | "expand_string" | "dword" | "disabled",
                        "value": "…" } },
        // Omit `name` to remove the key and its subtree; a subtree removal must name a key at least
        // three components below its root.
        { "registry_delete": { "key": "HKLM\\…", "name": "…" } },
        { "files": { "url": "https://…", "sha256": "<64 hex>",
                     "archive": { "format": "zip" | "tar.gz" | "tar.xz" | "tar.zst",
                                  "strip_prefix": "…" },
                     "into": "<relative to C:>" } }
      ] }
  ]
}
```

A name must be unique across both lists, because it is what the prefix's `prefix.json` records. An
`into` is relative to the prefix's `C:` drive, and is refused if it is absolute, climbs out, or carries a
drive letter.

`tier` is what the launcher says out loud before it installs anything, and `best_effort` is refused
without a `note`: a tier that says "not first class" without saying what that costs is worse than no
tier at all.

## Why a verb states what it produces

`verify` is the field that makes a verb's effect checkable instead of merely recorded, and it does three
jobs at once:

- A verb whose ops "succeeded" without producing these paths is a **failure**, so a half-finished apply
  is not remembered as done and the next launch tries again.
- A verb the prefix records but whose paths have since **gone** is applied again. That is not
  theoretical: Proton removes directories it judges broken on a prefix upgrade, so without this a record
  would outlive the files, forever.
- It is the same evidence a health view would want.

It is optional, and empty is the honest answer for a verb whose whole effect is a registry value: there
is no file to look for, and the prefix's record is the only evidence there is.

What it does not do is decide that what arrived works, and the withdrawn `dotnet48` is the lesson. Both
of its paths were genuinely present on prefixes where nothing managed could load, so a file-existence
check reported success for an install that was useless. File existence is a weak predicate. Treat a
`verify` as the floor of a verb's evidence, and put anything that exercises the capability in a
functional check rather than here.

## Why the op list is three

All three are idempotent by construction: a registry write overwrites rather than adds, a removal treats
"it was not there" as success, and a file placement overwrites. That is the selection criterion, not a
coincidence: anything a verb does has to be safe to do twice, because the only thing between a re-apply
and a re-run is the prefix's own record.

There used to be a fourth, `run`, which executed a pinned download inside the prefix. It was the escape
hatch for a vendor runtime whose install is an opaque executable, and `dotnet48` was its only consumer.
With that verb withdrawn it had none, and an op nothing exercises is an op nothing tests in the field.
Apogee is not a winetricks: the op set stays at three, and a prefix needing something these three cannot
express is a case for `winetricks` or `protontricks` against that prefix, stated as a caveat rather than
automated here.

## Adding or updating a row

1. **Pin** a verb's artifact: download it and `sha256sum` it. Point `url` at the versioned upstream
   asset, never at a redirecting "latest" endpoint, since the pin has to describe the bytes that URL
   will keep serving. An injectable has no pin: its `distribution` is a pointer, and the digests that
   distribution publishes are what authenticate its bytes.
2. **Edit** `manifest.json`.
3. **Sign** the exact manifest bytes with the offline seed:
   ```
   ./regen-catalog-sig.sh          # wraps tools/catalog-sign
   ```
   Any reformatting after signing invalidates the signature, and a test in `apogee-addons` embeds both
   files and will fail if they disagree.
4. **Publish** `manifest.json` and `manifest.json.sig`.

## Rotating the signing key

`COMPONENT_PUBLIC_KEYS` is a list, current key first, and the list is what makes a rotation possible
without an outage. With a single key one of the two sides has to move first and the other is broken
until it catches up: re-sign first and every client in the field rejects the catalog until it updates,
ship the new key first and every updated client rejects the catalog until the re-sign. Neither is
acceptable for a file every launch reads.

Three releases, in this order, and no step may be skipped or reordered:

1. **Add** the new public key to `COMPONENT_PUBLIC_KEYS` **after** the current one, and release. The
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
`ManifestError::TrustedKeyUnusable` naming its position, rather than as a signature that did not
verify, so a mistyped paste points at the binary instead of at this file.

A retired key is dropped rather than kept, because the window exists to finish a rotation and not to
keep an old signer trusted. If the old key is being rotated out because it was *compromised*, there is
no window: go straight to step 2 with a release that carries only the new key, and accept that older
clients stop applying prefix setup until they update. That is the correct trade, since the alternative
is continuing to trust a signer somebody else also holds.
