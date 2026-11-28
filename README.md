<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/apogee-wordmark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/apogee-wordmark-light.svg">
    <img alt="Apogee" src=".github/assets/apogee-wordmark-light.svg" width="480">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/soleynn/apogee/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/soleynn/apogee?label=release&color=61afef&labelColor=21252b"></a>
  <a href="#install"><img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Steam%20Deck-3e4451?labelColor=21252b"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-GPL--3.0--or--later-3e4451?labelColor=21252b"></a>
</p>

A launcher for FINAL FANTASY XIV, built for Linux and the Steam Deck. It logs you in, keeps the
game patched, repairs broken files, and runs the game under Wine or Proton.

> [!NOTE]
> Apogee is early. The command-line launcher works today; the desktop app is still being built.

## What it does

- Logs in to your Square Enix account, with one-time passwords if you use them.
- Installs the game, applies patches, and repairs damaged game files.
- Downloads and manages Wine and Proton for you, or uses the Wine you already have.
- Starts Dalamud and your own tools, such as ACT, alongside the game.
- Adds the game to Steam, so it starts from Steam's interface on a Steam Deck.
- Keeps your password in your system's keyring.

Logging in works for the global (North America, Europe, Japan, Oceania) service only. Accounts
bought through Steam cannot log in yet.

## Install

Download the latest `apogee-cli` release for x86_64 Linux from the
[releases page](https://github.com/soleynn/apogee/releases/latest), check it, and put it on your
path:

```sh
v=v0.4.0
pkg=apogee-cli-$v-x86_64-unknown-linux-gnu
curl -LO https://github.com/soleynn/apogee/releases/download/$v/$pkg.tar.gz
curl -LO https://github.com/soleynn/apogee/releases/download/$v/$pkg.tar.gz.sha256
sha256sum -c $pkg.tar.gz.sha256
tar -xzf $pkg.tar.gz
install -Dm755 $pkg/apogee-cli ~/.local/bin/apogee-cli
```

## Getting started

```sh
# Point a profile at your game folder (the one that holds boot/ and game/).
# Add --otp if your account uses one-time passwords.
apogee-cli profile add --name main --user your-square-enix-id --game-path ~/Games/FFXIV

apogee-cli play --profile main      # log in, patch, and start the game
apogee-cli install --profile main   # or install the game into an empty folder first
apogee-cli repair --profile main    # fix broken game files
```

Run `apogee-cli --help` to see everything else.

## Help and feedback

Found a bug or have an idea? [Open an issue](https://github.com/soleynn/apogee/issues). To report
a security problem, see [SECURITY.md](SECURITY.md). Code contributions are by invitation; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Apogee is an independent project, not affiliated with or endorsed by Square Enix. FINAL FANTASY
XIV is a trademark of Square Enix.
