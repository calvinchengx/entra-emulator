# Microsoft Graph v1.0 OpenAPI

Someone else's artifact, pinned. We do not author it; the emulator is held to it
by `scripts/check_graph_conformance.py`.

| Field | Value |
|---|---|
| **Upstream** | https://github.com/microsoftgraph/msgraph-metadata, `openapi/v1.0/openapi.yaml` |
| **Pinned revision** | `b8cbef92f6959dca8150bf3edcc650863765e529` (2026-09-18) |
| **Format** | OpenAPI 3.0.4, generated from OData CSDL (`Microsoft.OpenApi.OData`) |
| **Licence** | MIT, Copyright (c) 2018 Microsoft Graph. Text in `LICENSE`. |
| **Integrity** | Machine-readable in `pin.json`: sha256 of the upstream YAML, and of the JSON rendering the gates read. |
| **Used by** | `scripts/check_graph_conformance.py`; the CI job `graph-conformance` |

## Why it is a rendering and not the file itself

Upstream is 44 MB of YAML. The gates read a deterministic JSON rendering of it,
gzip-compressed to about 2 MB, because parsing 44 MB of YAML on every CI run is
seconds of waste and the gates are stdlib-only. Key order is preserved, separators
are fixed and the gzip header carries no timestamp, so the same YAML always yields
the same bytes.

## Three checks, because they answer different questions

```bash
uv run scripts/vendor_graph_spec.py --verify      # offline: still hashes to pin.json?
uv run scripts/vendor_graph_spec.py --reproduce   # online: is it exactly what upstream says?
uv run scripts/vendor_graph_spec.py --pin <SHA>   # bump the pin, in its own commit
```

`--verify` runs on every push. `--reproduce` re-fetches the upstream YAML at the
pinned commit, checks *its* hash, re-derives the JSON and requires a byte-for-byte
match, so it is what stops the vendored copy drifting from what Microsoft actually
published. It runs weekly (`golden-drift.yml`) because it downloads 44 MB.

## Refreshing

Bump the pin deliberately, in its own commit, and read the diff of the findings it
produces: a newer spec is new claims about Graph, and the checker's `KNOWN` list
pins every disagreement this tree still has.
