# OIDF conformance harness

Runs an [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
plan against this emulator. Rationale, rungs and boundaries live in
[docs/23-oidf-conformance.md](../../docs/23-oidf-conformance.md); this file is
just how to drive it.

```bash
make conformance             # or: python3 e2e/conformance/run.py
python3 e2e/conformance/run.py --keep   # leave the stack up to poke at the UI
```

Docker is the only prerequisite. The run builds the emulator image, pulls the
pinned suite image, and tears everything down again unless you pass `--keep`, in
which case the suite's own UI is on `http://localhost:8099/`.

Currently one plan: `oidcc-config-certification-test-plan`, the Config OP
certification profile. It checks the discovery document against the
specification and needs no browser and no login.

## Files

| file | what it is |
|---|---|
| `run.py` | orchestration, plan creation, and the result policy |
| `docker-compose.yml` | the emulator, mongo, and the suite as siblings |
| `Dockerfile.suite` | the pinned suite image plus the emulator's CA |
| `config/oidcc-config-op.json` | the plan configuration handed to the suite |
| `config/expected.json` | declared non-`PASSED` outcomes, each with a reason |

`.certs/` and `results/` are generated and gitignored. `results/` holds the
per-condition log for each module, which is the part actually worth reading: the
summary line says `PASSED`, the log says which 34 conditions produced it.

## Result policy

Only `PASSED` is green. Anything else fails the run unless it is declared in
`config/expected.json` with a reason, so a new warning breaks the build instead
of accumulating quietly. `run.py` also asserts that the plan the suite returns
matches `EXPECTED_MODULES` exactly, because a plan that silently stopped
shipping a module would otherwise test less and still exit 0.

## Updating the suite version

`SUITE_VERSION` and `SUITE_IMAGE` in `run.py` are pinned together: the tag is
there to be read, the digest is what is pulled. It is the multi-arch **index**
digest, so the harness runs on amd64 and arm64 alike; pinning a per-architecture
manifest would quietly break one of them. Tags are listed at
`registry.gitlab.com/openid/conformance-suite` and need no credentials:

```bash
TOKEN=$(curl -s "https://gitlab.com/jwt/auth?service=container_registry&scope=repository:openid/conformance-suite:pull" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $TOKEN" https://registry.gitlab.com/v2/openid/conformance-suite/tags/list
```

After a bump, expect `EXPECTED_MODULES` to need review rather than assuming it
still holds. That assertion failing on an upgrade is the harness working.
