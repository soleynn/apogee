# Changelog

All notable changes to this project are documented here. Entries are grouped by crate, and each line
is tagged with its change type. Versioning aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### apogee-addons
- Check a registry verb's effect, not only its stated paths (#164) _(fixed)_
- Refuse a second companion redirecting the same launch (#166) _(fixed)_
- Harden the companion seam before its surface freezes (#169) _(changed)_
- Rewrite the crate's rustdoc from scratch (#170) _(documentation)_
- Add the readings callers were deriving, clear pedantic, and freeze at 1.0.0 (#171) _(added)_

### apogee-cli
- Take the one-time code on stdin and stop the launcher being dumpable (#116) _(fixed)_

### apogee-core
- Keep the session id out of error text, and refuse before reading (#112) _(fixed)_
- Generate one-time codes against the login server's clock (#123) _(added)_
- Validate Square Enix TLS against the roots it issues from (#124) _(added)_
- Derive the computer-id from the install, not the host (#129) _(fixed)_
- Stop the install-id store swallowing I/O errors, memoize the ephemeral fallback (#139) _(fixed)_
- Correct the transport contract doc and add wire-level accept tests (#146) _(documentation)_
- Pin Accept-Language to XIVLauncher's actual seed-0 draw (#151) _(fixed)_
- Apply the catalog's prefix setup outside a launch (#162) _(fixed)_
- Report the setup a prefix is missing in its health check (#163) _(fixed)_
- Refuse every redirect on the client that carries a credential (#174) _(added)_

### apogee-fetch
- Stop asserting the capability probe won a race it is built to lose (#121) _(testing)_
- Back off between retries and honor a clamped Retry-After (#172) _(added)_
- Cap and vet the redirects the download client will follow (#173) _(added)_
- Hand a range no source will serve to the next one (#175) _(added)_

### apogee-otp
- Generate one-time codes from a stored shared secret (#122) _(added)_
- Receive a one-time code pushed to the local listener (#125) _(added)_
- API freeze and documentation pass, bump to 1.0.0 (#161) _(miscellaneous)_

### apogee-runtime
- Report the exit status of a redirected launch's program (#165) _(fixed)_

### apogee-secrets
- Store account secrets in the platform credential store (#99) _(added)_
- Add a probe report example for sandbox runs (#105) _(testing)_
- Keep nothing, forget everything, and import what another launcher saved (#106) _(added)_
- Seal account secrets in a passphrase-protected file (#108) _(added)_
- Pin the properties four one-line edits could ship past (#109) _(testing)_
- Make the probe answer about the thing it is reporting on (#110) _(fixed)_
- Tell damage to the check envelope apart from a mistyped passphrase (#111) _(fixed)_
- Make the in-memory double model a store that could exist (#113) _(fixed)_
- Guard the lock sidecar, and repair a store directory both ways (#114) _(fixed)_
- Refuse a secret with no bytes in it (#115) _(fixed)_
- Bound how long the sealed file's key stays in memory (#118) _(fixed)_
- Keep reading credential targets past a failure, and anchor the foreign key strings (#117) _(fixed)_
- Classify, compile and gate the Apple credential-store path (#119) _(fixed)_
- Give the Windows secret store an owner-only access list (#120) _(fixed)_
- Pin five hardening fixes that reverted green (#154) _(testing)_
- Fence the Io payload on Debug and the source chain, not just Display (#155) _(fixed)_
- Stop the store directory repair following a symlink (#156) _(fixed)_
- Match the seal and probe claims to the code (#158) _(documentation)_
- Fuzz the exported password table, and decode it from bytes (#160) _(testing)_

### ci
- Backfill changelog scope and harden the regeneration workflow (#94) _(fixed)_

### nightly
- Cache fuzz corpus per target across nightly runs (#150) _(ci)_

### sqex-crypto
- Obfuscate the authentication ticket for the login query (#95) _(added)_
- Close the defects found by the adversarial pass (#97) _(fixed)_
- Finish the 1.0 documentation and hardening pass (#98) _(documentation)_
- Record what pins the byte order and the generator (#107) _(documentation)_

### sqex-proto
- Log in with a Steam service account (#96) _(added)_
- Remove dead ComputerId::from_host and LauncherTime::now (#126) _(fixed)_
- Guard the OAuth scanners and match the launcher's account fold (#127) _(fixed)_
- BOM-stamped boot bodies and gate-status leniency (#128) _(fixed)_
- Validate input reaching the version report and frontier referer (#130) _(fixed)_
- Harden the patchlist parser (#132) _(fixed)_
- Close three error-path credential leaks (#131) _(fixed)_
- Make the transport seam's header-fidelity contract real (#133) _(fixed)_
- Correct identity.rs doc comments on computer-id derivation (#134) _(documentation)_
- Close the window-straddle gap in the error excerpt scrub (#135) _(fixed)_
- Close four residual patchlist and version-file gaps (#136) _(fixed)_
- Close the header-fidelity contract's remaining gaps (#137) _(fixed)_
- Close the remaining OAuth-top scrub gap and account-fold divergence (#138) _(fixed)_
- Close the 0.5 hardening/freeze gate's remaining items (#140) _(fixed)_
- Close the OAuth failure message's truncate-before-redact gap (#143) _(fixed)_
- Close the frontier header-fidelity gap PR #137 missed (#144) _(fixed)_
- Exclude the remaining 25 over-matching code points from account-id fold (#145) _(fixed)_
- Bound the login callback's total content length (#147) _(fixed)_
- Full rustdoc pass ahead of 1.0 (#148) _(documentation)_
- Gate gen_token behind a non-default feature (#149) _(added)_
- Bump to 1.0.0 (#152) _(miscellaneous)_

### workflows
- Require a pull request title the changelog can read (#93) _(ci)_

### workspace
- Unblock the two permanent deletion dead ends in the secrets lifecycle (#153) _(fixed)_
- Require the Secret Service job, widen the unsafe gate to examples (#157) _(ci)_
- Gate the in-memory secret store out of the shipping launcher (#159) _(ci)_
- Report whether a companion actually loaded into the game (#167) _(added)_
## [0.4.0] - 2026-07-31

### apogee-addons
- Choose config backup contents by rules that cannot silently match nothing (#69) _(added)_
- Config backup archive, restore, and retention (#70) _(added)_
- Run the user's own tools alongside the game (#71) _(added)_
- Prefix verbs, a signed component manifest, and the withdrawal of the catalog (#76) _(added)_
- Dalamud as a launch setting, and the catalog of installable programs removed (#77) _(added)_
- A frozen error taxonomy, an audited Dalamud boundary, and rotatable signing keys (#78) _(added)_
- Stop claiming one runner is the supported one (#90) _(fixed)_

### apogee-core
- Drive companion tools from the launch flow and the command line (#73) _(added)_
- Back up, restore, and prune the game's settings from the launcher (#74) _(added)_
- Keep the launcher store private, and capture settings before a patch (#75) _(added)_
- Bring boot current before registering, and read a 204 boot check as current (#83) _(fixed)_

### apogee-runtime
- Prefix lifecycle, health check, and in-process path translation (#64) _(added)_
- Environment matrix and DXVK install (#65) _(added)_
- Proton prefix init and broad stop under umu 1.4.1 (#66) _(fixed)_
- Frame-consistency metrics and a bench analyze command (#67) _(added)_
- Spawn and stop companion programs alongside the game (#68) _(added)_
- Runner sync capability, Steam Deck detection, and a Steam registration (#88) _(added)_
- Resolve the launch environment, install DXVK, and make prefix trouble answerable (#89) _(added)_

### apogee-sqpack
- Read SqPack indexes and resolve a game path to its bytes (#79) _(added)_
- Extract a file from a SqPack dat entry (#80) _(added)_
- Sweep an install's SqPack containers and report what disagrees with what they declare (#86) _(added)_
- Say which of an install's files are not the ones Square Enix shipped (#87) _(added)_

### ci
- Fix changelog and release-notes generation for stable releases _(fixed)_

### tools
- Probe a derived current boot version in the live boot check (#84) _(added)_

### workspace
- Pin the fuzz nightly to dodge a rustc ICE (#63) _(ci)_
- Stop paying for work a change cannot affect (#72) _(ci)_
- Ship the license inside the release tarball (#91) _(fixed)_
## [0.3.0] - 2026-07-23

### apogee-cli
- Add patch, install, and repair commands _(added)_

### apogee-core
- Drive patch, repair, and install flows _(added)_
- Add a keep-patches setting _(added)_
- Derive repair CDN source URLs from the repo _(added)_

### apogee-fetch
- Mark Progress non_exhaustive _(changed)_
- Record completed intervals in the resume journal _(added)_
- Eager file preallocation via fallocate _(added)_
- Shared token-bucket speed limiter _(added)_
- Per-host range capability probe and cache _(added)_
- Job scheduler, priorities, and shared limiter wiring _(added)_
- Segmented multi-connection transfer engine _(added)_
- Rustfmt line wrapping in limiter and scheduler _(styling)_
- Gate fallocate preallocation to Unix _(fixed)_
- Segmented completion + cancel terminal-state bugs _(fixed)_
- Bound the coalesced interval set, not raw journal records _(fixed)_
- Segmented length cross-check and If-Range revalidation _(fixed)_
- Scheduler cannot leak an admission slot to a cancelled waiter _(fixed)_
- Share identity/publish helpers and a lock helper _(changed)_
- Interval-set removal and full-coverage query _(added)_
- Per-request HTTP header policy _(added)_
- Mirror sources, header policy, and block-layout checks on the spec _(added)_
- Block layout and per-block hashing _(added)_
- Verify per-block SHA1 while downloading, re-fetching only dirty blocks _(added)_
- Carry the header policy on the range-capability probe _(fixed)_
- Block verification coverage and a recorded boot-patch gate _(testing)_
- Rustfmt and keep free test helpers unwrap-free _(styling)_
- Make the segmented resume test's interruption deterministic _(testing)_
- Harden the block verifier against races and hostile bodies _(fixed)_
- Review cleanups and a shared block-hash test helper _(changed)_
- Cover the block-verification gaps found by review _(testing)_
- Rustfmt and sync the lockfile _(styling)_
- Incremental multipart/byteranges parser _(added)_
- Fetch_ranges over 206, multipart, and 200 _(added)_
- HttpRangeSource implementing zipatch RangeSource _(added)_
- Corrupt-verify-repair over HTTP end to end _(testing)_
- Fetch_multipart fuzz target _(added)_
- Reject a range response that under-delivers _(fixed)_
- Cover the multi-range error and rejection paths _(testing)_
- Share one Content-Range parser _(changed)_
- External-verification marker for unhashed sources _(added)_

### apogee-patcher
- Install pipeline over fetch and zipatch _(added)_
- End-to-end install, ordering, cancel, rejection _(testing)_
- Boot chunk-CRC admission and install-from-nothing _(added)_
- Block-level repair with local-first-then-HTTP refetch _(added)_
- Signed index catalog with a compiled-in key _(added)_
- Add Job::cancel_token and IndexCatalog::verify_default _(added)_
- Derive repair source URLs from a base URL _(added)_

### apogee-sqpack
- Decode stored and compressed blocks _(added)_
- Read the common header and enumerate an install _(added)_
- Fuzz the block decoder _(testing)_
- Pin the common header against a real install _(testing)_
- Expose a standalone deflate-block decoder _(added)_
- Report standalone inflate faults at a payload-relative offset _(fixed)_

### apogee-test-support
- Record a tree manifest with author and compare _(added)_
- Serve 503 retry-after and hard stalls from the chaos server _(added)_
- Reject oversized request headers in the chaos server _(added)_
- Record per-range bytes and inject corrupted ranges _(added)_
- Serve multipart byte ranges with a hostile boundary _(added)_
- Fetch a verified corpus into a content-addressed cache _(added)_
- Add an example to author an oracle tree manifest _(added)_
- Pin the real boot-patch corpus and its oracle tree _(testing)_
- Per-segment chaos knobs and concurrency counter _(testing)_
- One-shot block corruption and request-header capture _(testing)_
- Add boot patchlist fixtures _(testing)_

### apogee-zipatch
- Read the ZiPatch container into a typed chunk stream _(added)_
- Add a patch dump tool and the corpus parse gate _(added)_
- Fuzz the chunk and command parsers _(testing)_
- Apply boot patches to a game tree _(added)_
- Fuzz the boot apply engine _(testing)_
- Confine deletes and harden the apply and parse edges _(fixed)_
- Apply the game-scale SQPK commands _(added)_
- Cover the game-scale apply engine _(testing)_
- Count the chunk-size field in the reader position _(fixed)_
- Add rayon and make flate2 a normal dependency _(build)_
- Build and verify a block index of an install _(added)_
- Add index and verify verbs to the patch tool _(added)_
- Cover block index build, verify, and reconstruct _(testing)_
- Make the .apzi decode total and bounded on hostile input _(fixed)_
- Cover empty-block splits and the refine-vanished path _(testing)_
- Drop the always-zero empty-block write offset _(changed)_
- Feature-gated synthetic patch fixtures _(added)_
- Rustfmt the fixtures module _(styling)_
- Expose the index repo version and platform _(added)_
- Confine the verify stray sweep to indexed directories _(fixed)_
- Label the generated index with its repo version _(added)_

### ci
- Stop the changelog render crashing on a non-conventional commit _(fixed)_

### fuzz
- Add the fetch_journal target for the resume journal decoder _(testing)_
- Fuzz the index-catalog manifest parser _(testing)_

### sqex-proto
- Report the base-version sentinel for a missing repository _(added)_
- Cover the install-mode sentinel report _(testing)_
- Expose decode_ver for canonical .ver decoding _(added)_

### workspace
- Extend the byte-order audit to apogee-sqpack _(build)_
- Extend the byte-order audit to apogee-zipatch _(build)_
- Repair broken ranges through a RangeSource planner (#42) _(changed)_
- Add the nightly soak workflow and corpus priming _(ci)_
## [0.2.0] - 2026-07-18

### apogee-cli
- Profile, login, launch, and play commands _(added)_
- End-to-end login and launch against scripted fixtures _(testing)_
- Resolve a profile by key and share the login/play preamble _(performance)_

### apogee-core
- Inject the network transport _(changed)_
- Host identity and an injectable clock _(added)_
- Persist accounts and the session cache _(added)_
- A launch backend seam over the runner _(added)_
- Credentials and dispositions on the command surface _(added)_
- Drive login through to a running game _(added)_
- Recover from a corrupt session cache and neutralize deferral notes _(fixed)_
- Surface the two needed response headers without cloning the map _(performance)_
- Share the entity-delete path between profiles and accounts _(changed)_
- Cover the cancel-kill, detach, and error branches of the flow _(testing)_
- Keep string constants out of the composition root _(fixed)_
- Resolve the runner catalog from its hosted url _(added)_

### apogee-fetch
- Carve the download types into modules and reject unverified plain http _(added)_
- Stream, verify, and resume single-connection downloads _(added)_
- Pin resume waste, streaming memory, and the verified-file seal _(testing)_
- Re-verify existing files, harden failure paths, buffer writes _(fixed)_
- Cover resume-off, short part, 416, last-modified, and skip edges _(testing)_
- Cover unverified downloads over TLS _(testing)_

### apogee-runtime
- Add signed runner catalog with Ed25519 verification _(added)_
- Stream-extract runner tarballs in-process _(added)_
- Install runners and umu via apogee-fetch _(added)_
- Spawn through the runner and supervise via /proc _(added)_
- Fuzz the runner manifest parser _(testing)_
- Confine extraction against symlink escapes and empty installs _(fixed)_
- Signal the game through its pidfd and match a pfx-named prefix _(fixed)_
- Distinguish an invalid launch plan from an unsupported platform _(changed)_
- Confirm termination after SIGKILL and poll for reaping in tests _(fixed)_
- Run the game from its install directory _(added)_
- Authenticate runners against the hosted catalog key _(added)_
- Track the real game process, not the wine loader _(fixed)_
- Follow the game across the runner's loader handoffs _(fixed)_

### apogee-test-support
- Add a scriptable streaming test http server _(added)_
- Game-install sandbox builder _(added)_
- Scripted login and registration exchanges _(added)_

### release
- Attach the apogee-cli linux binary on stable tags _(ci)_

### sqex-crypto
- Source the launch-arg key tick from the host monotonic clock (#28) _(added)_

### sqex-proto
- Session registration with version report _(added)_
- Strip a leading BOM from version files like the launcher _(fixed)_
- Cover UID-header, unreadable, and backup edge cases _(testing)_
- Pin the observed 204 No Content registration success _(testing)_
- Accept the integer login-status flag the frontier sends _(fixed)_
- Back the current-registration disposition with a live capture _(testing)_

### sqex-proto-probe
- Register step in the live login probe _(added)_
- Guard the wrong-password login and allow a region override _(fixed)_

### workspace
- Roll -pre checkpoint tags into the next release's changelog _(ci)_
- Scope release notes and prerelease flag to the tag kind _(ci)_
- Add streaming-download and test-server dependencies _(build)_
- Update time past RUSTSEC-2026-0009 _(build)_
- Use is_multiple_of in the base64 length check _(styling)_
- Run apogee-runtime supervision under wine and fuzz the manifest _(ci)_
- Refresh stale action pins flagged by zizmor _(ci)_
- Silence zizmor ref-version-mismatch on the rust-toolchain pin _(ci)_
- Exclude test code from CodeQL analysis _(ci)_
- Add the runner catalog signing helper _(build)_
- Lint the catalog signer and require the wine supervision job _(ci)_
- Stop tracking the dev tools' build output _(build)_
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

