# Installation

Pick whichever fits your platform. All methods give you the same single,
self-contained `entra-emulator` binary (the Svelte portal is baked in — no Node
toolchain required at runtime).

### Quick pick by platform

- **macOS** (Intel / Apple Silicon) → [Homebrew](#homebrew-macos--linux)
- **Windows** → [winget](#windows-winget) — or the [release `.zip`](#pre-built-binaries-all-platforms) until the catalog PR merges
- **Linux** → [Homebrew](#homebrew-macos--linux) or [Docker](#docker)
- **CI / containers / any OS** → [Docker](#docker) or [`go install`](#go-install)

### All methods

| Method | Platforms | Best for |
|---|---|---|
| [Homebrew](#homebrew-macos--linux) | macOS, Linux | Mac/Linux dev machines |
| [winget](#windows-winget) | **Windows** | Windows dev machines |
| [Docker](#docker) | anywhere Docker runs | CI, containers, zero local install |
| [Pre-built binary](#pre-built-binaries-all-platforms) | macOS, Linux, Windows | pinned versions, air-gapped |
| [`go install`](#go-install) | any platform with Go | Go developers |
| [From source](#from-source) | any platform with Go | hacking on the emulator |

:::note[It's a dev tool]
The emulator is intentionally insecure (open admin API, seeded secrets,
self-signed TLS). Install it on a workstation or CI runner — never expose it
publicly.
:::

## Homebrew (macOS / Linux)

```sh
brew install calvinchengx/tap/entra-emulator
entra-emulator version
```

Works on macOS and Linux (Intel and Apple Silicon / arm64). Each tagged release
refreshes the cask, so `brew upgrade` picks up new versions. The cask clears the
macOS quarantine attribute for you, so the unsigned binary runs without a
Gatekeeper prompt.

## Windows (winget)

```powershell
winget install calvinchengx.entra-emulator
entra-emulator version
```

Each tagged release opens a manifest PR against `microsoft/winget-pkgs`; the
package is installable once that PR is merged (Microsoft's validation can take a
day or two). Until then — or for `scoop` / `choco`, which aren't published — use
the [release archive](#pre-built-binaries-all-platforms) or
[`go install`](#go-install).

## Docker

A ~13 MB distroless image (pure-Go, no cgo) on GHCR, with a built-in
`HEALTHCHECK`:

```sh
docker run -p 8443:8443 -v entra-emulator-data:/app/data \
  ghcr.io/calvinchengx/entra-emulator:latest
```

The image defaults to `ORIGIN_MODE=compat` and binds `0.0.0.0`. Mount a volume
at `/app/data` to persist the SQLite store, TLS cert, and signing key across
restarts. Tags: `latest` and each released `X.Y.Z`.

## Pre-built binaries (all platforms)

Every tagged release attaches cross-platform archives (linux / macOS / Windows
× amd64 / arm64) to the [GitHub Releases page](https://github.com/calvinchengx/entra-emulator/releases).
Download the one for your OS/arch and extract it.

**macOS / Linux** (`…_darwin_arm64.tar.gz`, `…_linux_amd64.tar.gz`, …):

```sh
tar -xzf entra-emulator_*_"$(uname -s | tr A-Z a-z)"_*.tar.gz
./entra-emulator version
```

**Windows** — download `entra-emulator_<version>_windows_amd64.zip` (or `arm64`),
unzip it, and run `entra-emulator.exe` from PowerShell:

```powershell
.\entra-emulator.exe version
```

:::caution[macOS Gatekeeper on manual downloads]
The binaries are unsigned. If you download the archive by hand (rather than via
Homebrew), macOS may quarantine it. Clear it with:
`xattr -dr com.apple.quarantine ./entra-emulator`.
:::

Each release also publishes `checksums.txt` — verify with
`sha256sum -c` (Linux) / `shasum -a 256 -c` (macOS) /
`Get-FileHash` (Windows PowerShell).

## `go install`

With a Go toolchain (1.25+), install straight from the module — no clone, no
Node — on any platform:

```sh
go install github.com/calvinchengx/entra-emulator/cmd/entra-emulator@latest
entra-emulator version
```

This works because the built portal is committed to the module, so the pure-Go
build is fully self-contained. Use `@vX.Y.Z` instead of `@latest` to pin a
release.

## From source

```sh
git clone https://github.com/calvinchengx/entra-emulator
cd entra-emulator
go build ./cmd/entra-emulator
./entra-emulator version
```

Rebuilding the portal UI needs [pnpm](https://pnpm.io)
(`pnpm --filter entra-emulator-portal build`), but a plain `go build` uses the
committed `portal/dist` and needs no Node.

## After installing

```sh
ORIGIN_MODE=compat entra-emulator        # everything on https://localhost:8443
```

Then head to the [Quickstart](01-quickstart.md) to acquire your first token, and
[TLS & origins](05-tls-and-origins.md) if you want the subdomain layout
(`login.` / `graph.` / `portal.`) instead of compat mode. To trust the
self-signed cert, run `entra-emulator trust` (it prints the platform command).
