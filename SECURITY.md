# Security Policy

Apogee signs into Square Enix accounts, stores secrets, downloads and applies game patches, and (on
Windows) runs a privileged helper. Those are the parts most worth scrutiny, and reports about them are
taken seriously.

## Reporting a vulnerability

Please report security issues privately, not in a public issue or pull request.

- Preferred: [open a private security advisory](https://github.com/soleynn/apogee/security/advisories/new).
  This is GitHub's private vulnerability reporting (also reachable from the **Security** tab, then
  **Report a vulnerability**), and it is visible only to the maintainer.
- Alternative: a direct message on Discord, [@soleynn.x](https://discord.com/users/1444305499456671829).

Include enough to reproduce: the affected version or commit, the steps, and the impact. A suggested fix
is welcome but not required.

## What to expect

This is a small, spare-time project, so response is best-effort. Expect an acknowledgement within about
5 business days, then a discussion of severity and a fix, and credit in the advisory once it is resolved
(unless you would rather stay anonymous). Please allow up to 90 days for a fix to ship before any public
disclosure; for an actively exploited issue we can coordinate a shorter timeline.

## Supported versions

Apogee is pre-release and has no stable versions yet. Security fixes land on the latest `main`; there
are no back-supported releases to patch. This section will list supported versions once releases begin.

## Scope

In scope: this repository's code, especially credential and secret handling, login and ticket
construction, patch download and verification, parsers of untrusted Square Enix data, and the elevated
worker.

Out of scope: Square Enix's own services and endpoints; Wine, Proton, and the game client; and issues
that require an already-compromised machine or physical access. Reports about third-party dependencies
are welcome, though upstream is usually the right place to fix them.

## TLS trust anchors

The client that carries account credentials validates Square Enix's certificates against the four roots
those endpoints issue from (DigiCert Global Root G2 and G3, GTS Root R1 and R4) rather than against
every root the machine trusts. A TLS-intercepting proxy or a root installed by malware is therefore
refused, where by default either would be accepted and could read the account password out of the login
submit.

Certificates and intermediates are deliberately not pinned. The login host reissues on a two-to-four
week cycle with a fresh key each time, so a pin on either would break logins on a day nothing shipped.

A refused certificate says so, names the setting below, and does not report the host as unreachable,
so hitting this looks like what it is rather than like a network fault. The nightly build checks the
live endpoints against the shipped roots, so a move to a new authority is caught before a release
rather than by users.

If this blocks you, `APOGEE_TLS_SYSTEM_ROOTS=1` puts that run back on the machine's own trust store:

```sh
APOGEE_TLS_SYSTEM_ROOTS=1 apogee-cli login
```

Needing it means either the network is intercepting TLS or Square Enix has moved to an authority this
build does not carry. The second is worth reporting, and is an ordinary issue rather than a private
advisory.
