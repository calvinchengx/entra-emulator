# DESIGN peer review — ws-fed

**Reviewer:** [Atlas](e9e5f5ec-f40b-4f52-85ff-5d58d647de13) (`nw-solution-architect-reviewer`)  
**Date:** 14 Aug 2026  
**Iteration:** 1 (no iteration 2 — 0 critical / 0 high)

Morgan applied the four **low** documentation items after approval (ADR Consequences headings, ADR-003 drivers, enforcement gate, DISTILL SAML/OIDC + Graph projection AC). No architectural rework. Iteration 2 not required.

```yaml
review_id: "arch_rev_20260814_wsfed"
reviewer: "solution-architect-reviewer"
artifact: "docs/product/architecture/brief.md, docs/product/architecture/adr-001-005.md, docs/feature/ws-fed/design/wave-decisions.md"
iteration: 1

strengths:
  - "Clear constraint enumeration and locked decisions with explicit deferral (D6 on storage, D9 on SLO). DISCUSS wave fully reconciled."
  - "Quality-attribute ranking explicit and ISO 25010-mapped. Auditability ranked #1 with concrete implementation (Flow=wsfed, ClientID=wtrealm, no body log)."
  - "Technology choices justified with OSS-first preference and SAML analog rationale (ADR-001, ADR-004, ADR-005). No resume-driven complexity."
  - "Refuse-unsafe strategy clearly bounded (US-06/07/08) with no open redirect to unowned URLs; type-filtered redirect URIs prevent cross-protocol POST mix-up."
  - "Architecture enforcement strategy transparent: package-boundary discipline + existing Go tests + e2e/wsfed stranger. Scalable decision discipline, not framework-heavy."
  - "C4 L1–L3 with component boundaries and port contracts specified (observable, not Go signatures). Hexagonal dependency inversion documented."
  - "Spike integration complete: H2 (both endpoints = /{tid}/wsfed), H4 (no second login UI), S3b (SAML 2.0 in wresult) all traced to architecture sections."

issues_identified:
  architectural_bias: []

  decision_quality:
    - issue: "ADR-002 and ADR-004 omit explicit `## Consequences` section headings and instead embed negative consequences only in the prose Context/Decision paragraphs"
      severity: "low"
      location: "ADR-002 (lines 25–28), ADR-004 (lines 26–27)"
      recommendation: "Add explicit `## Consequences` with Positive/Negative bullet structure for consistency with ADR-001, ADR-003, ADR-005. Does not block approval, but standardizes format for future maintainers."

    - issue: "ADR-003 Context section does not explicitly reference the quality drivers (maintainability, habit); only Alternatives mention them. DISCUSS D3/D4 (story-map release) not cited, though KPI-4 is"
      severity: "low"
      location: "ADR-003 (lines 8–10)"
      recommendation: "Clarify: 'Quality drivers: maintainability (one login bug surface) and product constraint (KPI-4; zero new login UIs). See DISCUSS D3.'"

  completeness_gaps:
    - issue: "Component boundaries define responsibilities and dependencies, but do not explicitly label 'no new process/datastore' as a compliance gate in the architecture enforcement section"
      severity: "low"
      location: "brief.md § Architecture enforcement"
      recommendation: "Add enforcement rule as a formal gate: 'No new top-level module/process/datastore for WS-Fed'."

    - issue: "Metadata builder must grow WS-Fed RoleDescriptor without breaking SAML e2e. ADR-001 flags this constraint but does not specify a test gate or DISTILL integration point"
      severity: "low"
      location: "ADR-001, brief.md DISTILL handoff"
      recommendation: "Specify: 'DISTILL AC: existing SAML and OIDC e2e still pass when WS-Fed RoleDescriptor added to metadata document.'"

  implementation_feasibility:
    - issue: "Graph auditLogs/signIns projection requires app display-name resolution by ID URI instead of GUID for ClientID=wtrealm. ADR-004 notes 'small Graph adapter change' but does not specify implementation scope or risk"
      severity: "low"
      location: "ADR-004, brief.md"
      recommendation: "Add to DISTILL or DEVOPS handoff: Graph adapter change scope. Application-layer projection, not a new datastore."

  priority_validation:
    q1_largest_bottleneck:
      evidence: "brief.md § Constraint and priority analysis: protocol surface is missing (/wsfed 404 + SAML-only metadata). Scale is 0% of the problem."
      assessment: "YES"
    q2_simple_alternatives:
      assessment: "ADEQUATE"
    q3_constraint_prioritization:
      assessment: "CORRECT"
    q4_data_justified:
      assessment: "JUSTIFIED"

approval_status: "approved"
critical_issues_count: 0
high_issues_count: 0
```

## Revisions after review (lows only)

| Issue | Revision |
|---|---|
| ADR Consequences format | All five ADRs now use `### Positive` / `### Negative` under `## Consequences` |
| ADR-003 drivers | Context cites DISCUSS D3, KPI-4, maintainability + zero new login UIs |
| Enforcement gate | brief.md: no new module / process / datastore as a compliance gate |
| SAML e2e after metadata growth | ADR-001 + DISTILL item 8: existing `e2e/saml` and OIDC e2e still pass |
| Graph projection scope | ADR-004 + DISTILL item 5: URI lookup, interactive `wsfed`, no new Graph route |

Residual: **none medium or high**. Lows addressed in documentation; architecture unchanged.
