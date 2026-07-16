# Changelog

All notable changes to this project are documented here. Entries are grouped by crate, and each line
is tagged with its change type. Versioning aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### apogee-fetch
- Carve the download types into modules and reject unverified plain http _(added)_
- Stream, verify, and resume single-connection downloads _(added)_
- Pin resume waste, streaming memory, and the verified-file seal _(testing)_
- Re-verify existing files, harden failure paths, buffer writes _(fixed)_
- Cover resume-off, short part, 416, last-modified, and skip edges _(testing)_
- Cover unverified downloads over TLS _(testing)_

### apogee-test-support
- Add a scriptable streaming test http server _(added)_

### workspace
- Roll -pre checkpoint tags into the next release's changelog _(ci)_
- Scope release notes and prerelease flag to the tag kind _(ci)_
- Add streaming-download and test-server dependencies _(build)_
- Update time past RUSTSEC-2026-0009 _(build)_
- Use is_multiple_of in the base64 length check _(styling)_
## [0.1.0] - 2026-07-16

### apogee-addons
- Stub the async Injectable seam, and add async-trait to the workspace _(added)_

### apogee-cli
- Drive the command/event surface _(added)_

### apogee-core
- Domain model, versioned store, composition root, and command/event API (#8) _(added)_
- Stop publishing the internal HttpTransport _(changed)_
- Move CoreConfig paths into subsystems instead of cloning _(changed)_
- Dedup the store's Io error mapping _(changed)_
- Harden the store's atomic writes _(fixed)_
- Give store CRUD a synchronous method API _(changed)_
- Pin the store-miss to NoProfile mapping _(testing)_

### apogee-elevated
- Declare the apogee-zipatch dependency edge _(added)_

### apogee-fetch
- Stub FetchError, Validator, VerifiedFile, and the Fetcher builder _(added)_

### apogee-otp
- Stub OtpError, import/generate, and the Otp handle _(added)_

### apogee-patcher
- Stub PatchError and the elevated-worker protocol enums _(added)_

### apogee-runtime
- Stub RuntimeError and the launch-lifecycle types _(added)_

### apogee-secrets
- Stub the SecretStore seam, Secret, and Secrets handle _(added)_

### apogee-sqpack
- Stub the error taxonomy and block-codec surface _(added)_

### apogee-test-support
- Golden diff, corpus fetch, redaction, sandbox, and the oracle runner _(added)_
- Defer the HTTP corpus fetcher _(build)_
- Note the oracle runner has no wall-clock timeout _(documentation)_

### apogee-zipatch
- Stub the PatchSink and RangeSource seams _(added)_

### sqex-crypto
- Blowfish variants, MSVCRT RNG, mangled base64, and the endianness module _(added)_
- Encrypted launch-argument builder and sqex0003 wrapping (#5) _(added)_
- Zeroize key-derived cipher state _(fixed)_
- Zeroize cleartext arguments and drop the args clone _(fixed)_
- Fix block endianness on the cipher and dedup the drivers _(changed)_
- Construct ArgKey only through the TickCount seam _(changed)_

### sqex-proto
- Unauthenticated protocol surfaces (#6) _(added)_
- OAuth login flow and launchParams parsing (#7) _(added)_
- Hoist the shared dynamic_header helper into transport _(changed)_
- Centralize response-status and base-URL construction _(changed)_
- Carry the credential request body in zeroizing memory _(fixed)_
- Zeroize the OAuth session id _(fixed)_
- Surface only SE's structured message on OAuth failure _(fixed)_
- Normalize patchlist line endings in a single pass _(performance)_
- Extract a shared ClientContext for the request surfaces _(changed)_
- Model the request body as a RequestBody newtype _(changed)_
- Cover patchlist error arms and the empty session-id guard _(testing)_
- Pin an OTP-carrying login against the captured pages _(testing)_

### sqex-proto-probe
- Generate the OTP at server time to capture a 2FA login _(added)_

### tools
- Adapt the reqwest probes to the new request-body and context API _(fixed)_

### workspace
- Scaffold cargo workspace, shared config, and CI skeleton _(miscellaneous)_
- Adopt GPL-3.0-or-later license _(miscellaneous)_
- Add project README _(documentation)_
- Expand .gitignore for build artifacts and local env files _(miscellaneous)_
- Pass on zero tests and bump checkout to v5 _(ci)_
- Cache xwin SDK, tune rust-cache, add concurrency cancel _(ci)_
- Add issue and PR templates _(miscellaneous)_
- Add git-cliff changelog and release-notes workflow _(miscellaneous)_
- Add invitation-only contribution policy _(documentation)_
- Add security policy _(documentation)_
- Add Dependabot and CodeQL code scanning _(ci)_
- Auto-close pull requests from non-collaborators _(ci)_
- Add GitHub Pages landing page and deploy workflow _(ci)_
- Add zizmor and OpenSSF Scorecard security scanning _(ci)_
- Pin actions to commit SHAs and least-privilege token permissions _(ci)_
- Clickable Discord links and security-policy disclosure timeline _(documentation)_
- Set persist-credentials false on checkouts and annotate reviewed pull_request_target _(ci)_
- Add Dependabot cooldown and use gh CLI for releases _(ci)_
- Enforce architecture invariants and fuzz the base64 codec (#9) _(ci)_
- Live boot-version check and no-presentation audit (#10) _(ci)_
- Cross-compile the Windows target with MinGW instead of MSVC (#11) _(ci)_
- Drop the unused out-of-process golden runner (#12) _(testing)_
- Broaden the source-hygiene gates _(ci)_
- Select the nextest ci profile and lint the dev tools _(ci)_
- Note the forward-declared dev-dependencies _(miscellaneous)_
- Group the changelog by crate and catch it up _(miscellaneous)_
- Regenerate the changelog on every merge to main _(ci)_
- Auto-commit the regenerated changelog to each PR branch _(ci)_
- Stop the changelog workflow from looping on its own commits _(ci)_
- Regenerate the changelog on merge to main via an app token _(ci)_
- Note where cliff.toml is regenerated _(documentation)_
- Scope the changelog app token to contents:write _(ci)_
- Ignore common editor and IDE files _(miscellaneous)_

