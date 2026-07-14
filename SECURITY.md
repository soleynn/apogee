# Security Policy

Apogee signs into Square Enix accounts, stores secrets, downloads and applies game patches, and (on
Windows) runs a privileged helper. Those are the parts most worth scrutiny, and reports about them are
taken seriously.

## Reporting a vulnerability

Please report security issues privately, not in a public issue or pull request.

- Preferred: GitHub's private vulnerability reporting on this repository (the **Security** tab, then
  **Report a vulnerability**). This opens a private advisory only the maintainer can see.
- Alternative: a direct message on Discord (soleynn.x).

Include enough to reproduce: the affected version or commit, the steps, and the impact. A suggested fix
is welcome but not required.

## What to expect

This is a small, spare-time project, so response is best-effort rather than same-day. You can expect an
acknowledgement, a discussion of severity and a fix, and credit in the advisory once it is resolved
(unless you would rather stay anonymous). Please allow a reasonable window to ship a fix before any
public disclosure.

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
