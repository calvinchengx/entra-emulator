# Shared artifacts registry — ws-fed sign-in

**Feature ID:** `ws-fed`  
**Journey:** Point a WS-Fed RP at the local STS  
**Date:** 14 Aug 2026

Every `${variable}` in the journey mockups has one source. Untracked copies are the usual cause of metadata/token mismatches (Audience ≠ Wtrealm, Issuer ≠ entityID, cert ≠ signature).

JTBD skipped; traces to DISCOVER job: point WsFederation at the emulator (`docs/feature/ws-fed/discover/problem-validation.md`).

## Registry

### tid

- **Source of truth:** The workforce tenant the emulator is serving (`{tid}`). Never a named cloud directory.
- **Displayed as:** `${tid}`
- **Consumers:** FederationMetadata URL; `/{tid}/wsfed`; path inside issuer if the emulator uses a tenant-scoped entityID.
- **Owner:** Directory / login origin (already exists).
- **Integration risk:** HIGH — wrong tenant segment 404s or signs with the wrong key.
- **Validation:** Metadata URL tenant segment equals wsfed URL tenant segment.

### login_origin

- **Source of truth:** Emulator login origin (the host Priya already uses for OIDC/SAML).
- **Displayed as:** `${login_origin}`
- **Consumers:** MetadataAddress; PassiveRequestorEndpoint; SecurityTokenServiceEndpoint; entityID (D14: may stay this origin).
- **Owner:** Existing login surface.
- **Integration risk:** HIGH — a second origin for WS-Fed would break “host/TLS knobs only.”
- **Validation:** WS-Fed URLs are on the same login origin as SAML FederationMetadata.

### metadata_url

- **Source of truth:** Existing path `{login_origin}/{tid}/federationmetadata/2007-06/federationmetadata.xml`
- **Displayed as:** `${metadata_url}`
- **Consumers:** ASP.NET `MetadataAddress`; journey step 2 GET.
- **Owner:** FederationMetadata (already served; WS-Fed RoleDescriptor is the growth).
- **Integration risk:** HIGH — a second metadata URL breaks the locked stranger (A4 / H2).
- **Validation:** No `/wsfed/metadata` (or other) path is required for sign-in.

### wsfed_url

- **Source of truth:** `fed:PassiveRequestorEndpoint` in FederationMetadata (also `fed:SecurityTokenServiceEndpoint`; both are `/{tid}/wsfed`).
- **Displayed as:** `${wsfed_url}`
- **Consumers:** Library `TokenEndpoint`; challenge GET/POST; advertised sign-out URL.
- **Owner:** WS-Fed RoleDescriptor + STS route.
- **Integration risk:** HIGH — H2 maps PassiveRequestorEndpoint → TokenEndpoint. Missing SecurityTokenServiceEndpoint is a documented Entra shape the stranger also reads.
- **Validation:** Both metadata endpoints equal `{login_origin}/{tid}/wsfed`. Challenge hits that URL. Sign-out is advertised here; `wsignout1.0` is not witnessed.

### wtrealm

- **Source of truth:** Application ID URI of the Tasks API app (`api://tasks-api`).
- **Displayed as:** `${wtrealm}`
- **Consumers:** `Wtrealm` option; `wtrealm` query; assertion Audience.
- **Owner:** App directory record (Application ID URI).
- **Integration risk:** HIGH — Audience must equal wtrealm (spike).
- **Validation:** Challenge `wtrealm`, app Application ID URI, and assertion Audience are the same string.

### wreply

- **Source of truth:** A **registered** reply URL for that app (`https://rp.example.test/signin-wsfed`).
- **Displayed as:** `${wreply}`
- **Consumers:** `wreply` query; browser POST target.
- **Owner:** App redirect/reply registration. DESIGN chooses how that registration is stored; DISCUSS requires it be registered, not trusted from the query string (SAML ACS analog).
- **Integration risk:** HIGH — bouncing to an unowned URL is an open redirect.
- **Validation:** POST target equals a registered reply URL. Unregistered or missing `wreply` does not redirect to the query-string value.

### wctx

- **Source of truth:** Opaque value the RP put on the challenge (`tasks-return-state-7`).
- **Displayed as:** `${wctx}`
- **Consumers:** Challenge query; POST body to the RP.
- **Owner:** Relying party (echoed by the STS).
- **Integration risk:** MEDIUM — OASIS: if passed, MUST be returned. Analog of SAML RelayState.
- **Validation:** POST `wctx` equals challenge `wctx` byte-for-byte when present; omitted when the RP omitted it.

### entity_id

- **Source of truth:** FederationMetadata `entityID`.
- **Displayed as:** `${entity_id}`
- **Consumers:** Parsed library Issuer; assertion Issuer.
- **Owner:** Metadata document. D14: emulator login origin is allowed; `sts.windows.net` is not required.
- **Integration risk:** HIGH — token validation uses metadata Issuer.
- **Validation:** Assertion Issuer equals metadata entityID.

### signing_cert

- **Source of truth:** Tenant signing certificate already published on `IDPSSODescriptor`.
- **Displayed as:** `${signing_cert}`
- **Consumers:** SAML metadata KeyDescriptor; WS-Fed RoleDescriptor KeyDescriptor; assertion signature.
- **Owner:** Existing tenant key material (do not mint a second key).
- **Integration risk:** HIGH — Learn: certs in both sections will be the same. Library verifies with metadata keys.
- **Validation:** Byte-identical cert in both metadata sections; assertion verifies with that cert.

### audience

- **Source of truth:** `${wtrealm}` (`api://tasks-api`).
- **Displayed as:** `${audience}`
- **Consumers:** Assertion Audience / AppliesTo.
- **Owner:** Same as wtrealm (single source — do not store a second audience).
- **Integration risk:** HIGH — spike: Audience must equal wtrealm.
- **Validation:** `${audience}` is not a separately configured value; it is `${wtrealm}`.

### wresult

- **Source of truth:** STS-issued RequestSecurityTokenResponse after interactive sign-in.
- **Displayed as:** `${wresult}`
- **Consumers:** Browser POST to `${wreply}`; WsFederation verification.
- **Owner:** STS. TokenType `…#SAMLV2.0`; inner assertion SAML 2.0 `Version="2.0"`.
- **Integration risk:** HIGH — A3 locked S3b. SharePoint SAML 1.1 is out of v0.8.0.
- **Validation:** Inner assertion namespace is SAML 2.0. Raw wresult is a live credential in captures — do not commit it.

### account

- **Source of truth:** Enabled user in the emulator directory (example: Alex Rivera, `alex.rivera@workforce.example.test`).
- **Displayed as:** `${account}`
- **Consumers:** Pick an account row; assertion subject.
- **Owner:** Existing directory / account picker.
- **Integration risk:** LOW — reuse existing picker; do not invent a WS-Fed user store.
- **Validation:** Same users as OIDC/SAML sign-in.

## Integration checkpoints

| Checkpoint | Steps | Failure |
|---|---|---|
| Metadata TokenEndpoint = challenge URL | 2, 3 | Stranger challenges a 404 or the wrong host |
| wtrealm = Audience | 1, 3, 5 | Middleware rejects audience |
| entityID = Issuer | 2, 5 | Middleware rejects issuer |
| signing cert shared | 2, 5 | Signature verify fails |
| wctx echo | 3, 5 | RP cannot round-trip its state |
| wreply registered | 1, 5 | Open redirect / SAML ACS class bug |
| Same login chrome | 4 | Second UI; habit force from OIDC/SAML |

## Vocabulary (ubiquitous language)

Use these terms in stories and ACs. Do not replace them with framework type names.

| Term | Meaning |
|---|---|
| FederationMetadata | The existing metadata document at `…/federationmetadata/2007-06/federationmetadata.xml` |
| RoleDescriptor | WS-Fed STS section in that document |
| PassiveRequestorEndpoint | Browser sign-in (and advertised sign-out) URL |
| SecurityTokenServiceEndpoint | Also published; stranger reads it |
| `wa=wsignin1.0` | Sign-in action (OASIS) |
| `wtrealm` | Application ID URI |
| `wreply` | Registered reply URL |
| `wctx` | Opaque RP context, echoed |
| `wresult` | RSTR wrapping the assertion |
| SAML 2.0 | Assertion version inside `wresult` for this witness |
| Same sign-in | The account picker OIDC and SAML already use |

Do not use in requirements: Go package names, signed-state type names, CI YAML filenames, redirect-URI type enums (DESIGN).
