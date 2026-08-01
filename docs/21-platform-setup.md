# 21 — Platform setup: Linux, macOS, Windows

Once the prerequisites are in place the workflow is **identical on all three
platforms**:

```bash
make doctor   # is this machine wired up? (run this first)
make run      # build and serve natively — no container runtime needed
make status   # is it actually serving?
```

This emulator is a single static Go binary, so **Docker is optional**. `make
run` compiles and serves at `https://localhost:8443` with nothing else
installed; `make up` runs the published image instead if you would rather have
a container. That makes the Windows story unusually simple — you do not need a
container runtime at all to get a token.

| Need | Why | Linux | macOS | Windows |
|---|---|---|---|---|
| **POSIX shell** | the `Makefile` recipes and `scripts/*.sh` are `/bin/sh` | built in | built in | Git for Windows (`sh.exe`) |
| **GNU Make** | the target wrappers | `make` package | Xcode Command Line Tools | `ezwinports.make` |
| **Go ≥ 1.25** | `make build`, `run`, `test` | package manager or go.dev | `brew install go` | `winget install GoLang.Go` |
| **Docker** *(optional)* | `make up`, `make smoke` | Docker Engine | Docker Desktop / OrbStack / Colima | Docker Desktop / Rancher Desktop |
| **Python 3** *(optional)* | `make e2e` | usually present | Xcode CLT or Homebrew | winget |

## Linux

```bash
sudo apt-get install -y make golang-go python3     # Debian/Ubuntu
```

If your distro's Go is older than 1.25, install from <https://go.dev/dl/>
instead. Only if you want `make up` / `make smoke`:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER" && newgrp docker
```

Skipping that last step produces the most common Linux first-run failure, and
its message points at a socket rather than at group membership:
`permission denied while trying to connect to the Docker daemon socket`.

## macOS

`make` and Python 3 come with the Xcode Command Line Tools:

```bash
xcode-select --install
brew install go
```

That installs GNU Make **3.81**, which is ancient but sufficient — nothing in
this `Makefile` needs 4.x. `brew install make` provides a current one as
`gmake` if you prefer.

Everything here is arm64-native, so Apple silicon needs no special handling.

## Windows

The emulator runs natively from PowerShell — no WSL shell, no second checkout.
Two winget packages, neither needing administrator rights:

```powershell
winget install Git.Git          # sh.exe + grep/awk/cut/curl — the POSIX userland
winget install ezwinports.make  # GNU Make
winget install GoLang.Go        # for make build / run / test
```

Installing Git here is *not* about version control: it is how Windows gets the
POSIX shell that every recipe runs under, plus the `grep`, `awk` and `curl` the
scripts call.

**Open a new terminal afterwards.** winget adds `make` to the user PATH, and an
already-running shell will not see it — the single most common "I installed it
and it still says `make` is not recognized".

PowerShell, cmd, and Git Bash all work, because `make` switches to `sh.exe` for
the recipe bodies regardless of which shell launched it. What does *not* work is
running the scripts through cmd or PowerShell directly
(`.\scripts\status.sh`) — go through `make`, or use `sh scripts/status.sh`.

### If you use Docker on Windows

Docker Desktop and Rancher Desktop both work, but they share the `docker
context` list, so a stale active context produces an error naming only a pipe:

```
error during connect: … open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
```

It means the `docker` CLI being invoked and the daemon actually serving belong
to different vendors. Rancher Desktop serves the `default` context:

```powershell
docker context ls          # the one marked * is active; find the reachable one
docker context use default
```

`make doctor` reports the active context by name and lists the alternatives when
it is unreachable — and treats a missing daemon as a *warning*, since `make run`
does not need one.

### Three Windows traps

Each fails somewhere other than where it originates, which is what makes them
expensive. All three are handled; this records what they were.

**`python3` is a fake.** Windows ships a Microsoft Store *alias stub* named
`python3`. It sits on PATH, so `command -v python3` succeeds and any "is Python
installed?" check passes — then running it exits 49, while a real Python at
`python` right beside it is never consulted. The Makefile and scripts therefore
detect an interpreter by **executing** each candidate (`python3`, `python`,
`py`) and taking the first that runs. Override with `PY=`.

**`/dev/null` is not a path curl understands.** Git Bash's shell understands
`/dev/null`, but `curl.exe` is a native Windows binary that does not — it fails
to open its output file and exits **23 after already printing the status
code**. Under `set -e` that aborted `scripts/docker-smoke.sh` on its first
check. The scripts now use `NUL` on Windows.

**GNU Make falls back to cmd.exe.** When Make cannot find a shell on PATH it
uses `cmd.exe`, which cannot run a single line of these recipes — so the failure
looks like a broken Makefile rather than a missing dependency. The Makefile pins
`SHELL := sh.exe` on Windows, so a missing Git for Windows fails by *naming the
shell*.

## Troubleshooting by symptom

| Symptom | Platform | Cause |
|---|---|---|
| `make` is not recognized | Windows | PATH not refreshed — open a new terminal |
| recipes fail with cmd.exe syntax errors | Windows | Git for Windows not installed, so no `sh.exe` |
| `permission denied … docker daemon socket` | Linux | not in the `docker` group; `newgrp docker` |
| `open //./pipe/dockerDesktopLinuxEngine` | Windows | wrong docker context — `docker context use default` |
| `Python was not found` | Windows | the Store alias stub; install a real Python |
| port 8443 already answering | any | another family member's compose stack already publishes entra there |
| `set: Illegal option -` running a script | Linux, macOS | the script was checked out with CRLF; see below |

### A note on line endings

`scripts/*.sh` must be **LF**. A shell script checked out with CRLF fails at the
shebang — `sh` reads the trailing `\r` as part of the interpreter path, and the
error names a file that plainly exists. Git for Windows sets
`core.autocrlf=true` in its *system* config, so this is the Windows default
rather than a misconfiguration. [`.gitattributes`](../.gitattributes) pins
`*.sh`, `*.py` and `Makefile` to `eol=lf` so the checkout is byte-identical
everywhere.

## The rest of the family

[azure-keyvault-emulator](https://github.com/calvinchengx/azure-keyvault-emulator)
and [fabric-emulator](https://github.com/calvinchengx/fabric-emulator) use the
same `make doctor` / `make up` / `make status` verbs, and both ship a
`docker-compose.yml` that publishes this emulator on `:8443` alongside them.
