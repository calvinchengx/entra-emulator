# Mutation testing — ws-fed

**Date:** 14 Aug 2026  
**Strategy:** per-feature (nWave default; no project `CLAUDE.md` override)  
**Threshold:** 80% kill rate

## Verdict: SKIPPED

nWave mutation tooling in this install is cosmic-ray (Python), PIT (Java), and Stryker (JS/TS/C#). This emulator’s production surface for WS-Fed is **Go** (`internal/identity/wsfed*.go`, metadata growth in `saml.go`, Graph projection, `HasRedirectURIOfType`). There is no Go mutation runner configured in the repo and no `.venv-mutation`.

Substituting an unsupported tool, or reporting a fake kill rate, would invalidate the gate.

## What still witnesses the cut

- In-process Go tests on `internal/identity`, `internal/server`, `internal/store`, `internal/graph`, `internal/tokens` (GREEN after every DELIVER step and after L1–L4 refactor).
- KPI-1 stranger: unmodified `Microsoft.AspNetCore.Authentication.WsFederation` via `python3 e2e/run.py wsfed`.
- Adversarial review: **approved** (zero testing-theater patterns).

Re-run mutation when a Go mutator is adopted project-wide.
