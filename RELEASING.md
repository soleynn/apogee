# Releasing

Releases are cut from `main` by pushing a `v*` tag; `.github/workflows/release.yml` does the rest. It
builds the release notes from the commit history with git-cliff, and for a stable tag it also builds
and attaches the CLI archives. `CHANGELOG.md` is generated from the same history by the same
`cliff.toml`, is never edited by hand, and is regenerated only when a stable release is prepared.

## Stable release (`vX.Y.Z`)

1. Open a release pull request titled `chore(release): bump apogee-cli to X.Y.Z` that:
   - bumps `version` in `apps/apogee-cli/Cargo.toml` (and the matching `Cargo.lock` entry);
   - regenerates the changelog with the new version as its newest section:

     ```sh
     git cliff --tag vX.Y.Z -o CHANGELOG.md
     ```

   If other pull requests merge into `main` before this one, rebase and rerun the command so the
   section is complete.
2. Squash-merge it, then tag the merge commit on `main` and push the tag:

   ```sh
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

## Pre-release checkpoint (`vX.Y.Z-pre.N`)

Tag a commit on `main` and push the tag. No release pull request and no changelog change: a `-pre.N`
tag is published as a GitHub pre-release with notes only, never cuts its own changelog section, and
its commits roll forward into the next stable release.
