# OIDF conformance harness

Runs an [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
plan against this emulator. Rationale, rungs and boundaries live in
[docs/23-oidf-conformance.md](../../docs/23-oidf-conformance.md); this file is
just how to drive it.

```bash
make conformance                        # Config OP (the default)
make conformance PLAN=basic             # Basic OP, 35 modules
python3 e2e/conformance/run.py basic --keep   # leave the stack up to poke at the UI
```

Docker is the only prerequisite. A run builds the emulator image, pulls the
pinned suite image, and tears everything down again unless you pass `--keep`, in
which case the suite's own UI is on `https://localhost:8443/` (self-signed, so
your browser will complain).

Two plans:

| `PLAN=` | profile | modules | needs a browser |
|---|---|---|---|
| `config` | Config OP | 1 | no |
| `basic` | Basic OP | 35 | yes, the suite's own |

`config` checks the discovery document against the specification. `basic` drives
real logins; the suite embeds HtmlUnit, so the browser runs inside the suite
container and nothing extra is installed.

## Files

| file | what it is |
|---|---|
| `run.py` | orchestration, plan creation, and the result policy |
| `docker-compose.yml` | the emulator, mongo, and the suite as siblings |
| `Dockerfile.suite` | the pinned suite image plus the emulator's CA |
| `config/oidcc-config-op.json` | Config OP plan configuration |
| `config/oidcc-basic-op.json` | Basic OP plan configuration, including the browser script |
| `config/expected.json` | declared non-`PASSED` outcomes, each with a reason |

Clients are **not** in the config files. `run.py` registers three of them per
run through the emulator's admin API, because the redirect URI depends on the
plan alias and a committed client id would go stale.

`.certs/` and `results/` are generated and gitignored. `results/` holds the
per-condition log for each module, which is the part actually worth reading: the
summary line says `PASSED`, the log says which 34 conditions produced it.

## Result policy

Only `PASSED` is green. Anything else fails the run unless it is declared in
`config/expected.json` with a reason, so a new warning breaks the build instead
of accumulating quietly. A declaration for a module that has started passing is
reported as stale and also fails, so the file cannot quietly outlive the problem
it describes.

`run.py` asserts that the plan the suite returns matches the module list pinned
in `PLANS`, because a plan that silently stopped shipping a module would
otherwise test less and still exit 0. Re-pin with `--capture-modules`, which
reads the list back from the suite rather than from anyone transcribing its
source.

Some modules stop and ask a human for a screenshot. The harness fills the
placeholder so the plan can finish, and prints how many it filled; those modules
end as `REVIEW`, never `PASSED`.

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

`NGINX_IMAGE` is pinned from the same release and must move with it: the suite
refuses any request it believes arrived over plain http, so the TLS front end is
not optional.

After a bump, expect the pinned module lists to need review rather than assuming
they still hold. That assertion failing on an upgrade is the harness working.
