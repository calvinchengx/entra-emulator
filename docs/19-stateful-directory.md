# Stateful directory: recycle bin, consent, roles & auth methods

The emulator persists a real directory in SQLite (`docs/06-data-model-and-seed.md`).
This page documents the **stateful directory surface** — the five areas where the
emulator moves beyond static reads into the lifecycle behavior a Microsoft Graph
client actually exercises:

1. [Soft-delete / recycle bin](#1--soft-delete--recycle-bin) — `directory/deletedItems`
2. [Consent grants](#2--consent-grants) — `oauth2PermissionGrants` + `appRoleAssignedTo`
3. [Directory roles](#3--directory-roles) — `roleManagement/directory` + the `wids` claim
4. [Authentication methods](#4--authentication-methods) — `/authentication/methods`
5. [Graph write parity](#5--graph-write-parity) — create/update/delete contracts

Every contract below is modelled on Microsoft's published behavior. Where the
emulator deliberately simplifies, it is called out as **Divergence**. Endpoints are
shown host-relative; on the compat origin (`ORIGIN_MODE=compat`) they are prefixed
with `/graph` exactly like the rest of the Graph surface (`docs/09-graph-api.md`).

All write routes require a valid Graph-audience bearer token. As documented in
`docs/09-graph-api.md`, the emulator does **not** enforce fine-grained Graph
permissions (`Directory.ReadWrite.All` etc.) — any valid Graph token authorizes any
operation. This keeps test setup frictionless; it is a deliberate divergence from
Entra's permission model.

---

## 1 — Soft-delete / recycle bin

In Entra, deleting a user, group, application, or service principal is a **soft
delete**: the object enters a suspended state, keeps its `id` and properties, and is
restorable for **30 days**, after which it is permanently (hard) deleted. Other
object types are hard-deleted immediately. (Microsoft docs:
`architecture/recover-from-deletions.md`.)

The emulator implements this for **users, groups, and applications**.

### Deleting

The normal Graph delete soft-deletes:

| Method | Path | Result |
|---|---|---|
| `DELETE` | `/v1.0/users/{id}` | `204`, user → recycle bin |
| `DELETE` | `/v1.0/groups/{id}` | `204`, group → recycle bin |
| `DELETE` | `/v1.0/applications/{id}` | `204`, application → recycle bin |

A soft-deleted object disappears from its live collection (`GET /users`, sign-in,
token issuance) immediately — a deleted user cannot authenticate — but is preserved
in the recycle bin with the relationships needed to restore it.

### The recycle bin

| Method | Path | → |
|---|---|---|
| `GET` | `/v1.0/directory/deletedItems/microsoft.graph.user` | deleted users |
| `GET` | `/v1.0/directory/deletedItems/microsoft.graph.group` | deleted groups |
| `GET` | `/v1.0/directory/deletedItems/microsoft.graph.application` | deleted applications |
| `GET` | `/v1.0/directory/deletedItems/{id}` | a single deleted object (any type) |
| `POST` | `/v1.0/directory/deletedItems/{id}/restore` | `200`, restored object |
| `DELETE` | `/v1.0/directory/deletedItems/{id}` | `204`, permanent delete |

Each deleted object carries a `deletedDateTime` (ISO-8601) alongside its normal
properties and an `@odata.type` cast:

```jsonc
// GET /v1.0/directory/deletedItems/microsoft.graph.user
{
  "@odata.context": ".../$metadata#directoryObjects/microsoft.graph.user",
  "value": [
    {
      "@odata.type": "#microsoft.graph.user",
      "id": "aaaaaaaa-0000-0000-0000-000000000001",
      "displayName": "Alice Example",
      "userPrincipalName": "alice@entraemulator.dev",
      "accountEnabled": true,
      "deletedDateTime": "2026-07-13T09:41:00Z"
    }
  ]
}
```

### Restore

`POST /directory/deletedItems/{id}/restore` returns the object to its live
collection with the same `id`, and re-attaches the relationships captured at delete
time:

- **Users** — group memberships are restored (memberships to groups that still
  exist).
- **Groups** — member links are restored (members that still exist).
- **Applications** — redirect URIs, exposed scopes, app roles, and client secrets
  (hashes) are restored, so tokens the app could mint before deletion work again.

Restore fails with `404` if the item is not in the recycle bin (never deleted, or
already purged/permanently deleted).

### Retention (30-day window)

Deleted objects are retained for **30 days**, then permanently purged. The emulator
honors this against its **controllable clock** (`docs/04-configuration.md`, clock
control): advancing the clock past 30 days after a delete removes the object from
the recycle bin, and a subsequent restore returns `404` — exactly as a real purge
would. This makes retention deterministically testable:

```bash
# delete a user, advance the emulator clock 31 days, confirm it is unrecoverable
POST /admin/api/clock  { "offsetSeconds": 2678400 }
GET  /v1.0/directory/deletedItems/microsoft.graph.user   # user no longer listed
POST /v1.0/directory/deletedItems/{id}/restore           # 404
```

**Divergences.**
- The emulator has no separate service-principal object — each app registration *is*
  its own service principal (`docs/09-graph-api.md`), so there is a single
  `application` recycle-bin entry per deleted app, not distinct
  `application` + `servicePrincipal` entries.
- Real Entra keeps multi-tenant applications
  (`signInAudience = AzureADMultipleOrgs` / `…PersonalMicrosoftAccount`) past the
  30-day window; the emulator applies the uniform 30-day purge to all apps.
- Cascade soft-deletion of child objects is not modelled (the emulator has no
  owned-object graph beyond the relationships listed under **Restore**).

---

## 2 — Consent grants

A user or admin consenting to an app produces **stored grant state** on the
resource's service principal, and that state is what shapes tokens. Entra models two
kinds (Microsoft docs: `identity/enterprise-apps/grant-consent-single-user.md`):

- **Delegated** permissions → `oauth2PermissionGrant` objects → the `scp` claim in
  **user** tokens.
- **Application** permissions → `appRoleAssignment` objects
  (`servicePrincipals/{id}/appRoleAssignedTo`) → the `roles` claim in **app-only**
  tokens.

Because an app registration is its own service principal here, `clientId` /
`resourceId` / `{id}` below are all **app (client) IDs**.

### Delegated — `oauth2PermissionGrants`

| Method | Path | → |
|---|---|---|
| `POST` | `/v1.0/oauth2PermissionGrants` | `201`, created grant |
| `GET` | `/v1.0/oauth2PermissionGrants` | grants (supports `$filter` on `clientId`, `consentType`) |
| `GET` | `/v1.0/servicePrincipals/{id}/oauth2PermissionGrants` | grants where `clientId == {id}` |
| `DELETE` | `/v1.0/oauth2PermissionGrants/{id}` | `204` |

```jsonc
// POST /v1.0/oauth2PermissionGrants
{
  "clientId":    "<client app id>",
  "consentType": "AllPrincipals",     // tenant-wide (admin consent); or "Principal" for one user
  "resourceId":  "<resource app id>",
  "principalId": null,                 // required only when consentType == "Principal"
  "scope":       "User.Read access_as_user"   // space-separated delegated scope values
}
```

### Application — `appRoleAssignedTo`

| Method | Path | → |
|---|---|---|
| `POST` | `/v1.0/servicePrincipals/{id}/appRoleAssignedTo` | `201`, assignment on resource `{id}` |
| `GET` | `/v1.0/servicePrincipals/{id}/appRoleAssignedTo` | assignments granted **on** `{id}` |
| `GET` | `/v1.0/servicePrincipals/{id}/appRoleAssignments` | assignments the SP `{id}` **holds** |
| `DELETE` | `/v1.0/servicePrincipals/{id}/appRoleAssignedTo/{assignmentId}` | `204` |

```jsonc
// POST /v1.0/servicePrincipals/<resource app id>/appRoleAssignedTo
{
  "principalId": "<client app id>",     // the app being granted (or a user id)
  "resourceId":  "<resource app id>",
  "appRoleId":   "<app role id>"        // all-zero GUID = default assignment, no specific role
}
```

### How grants shape tokens

- **App-only (client-credentials) tokens** — when one or more
  `appRoleAssignment`s exist for `(client app, resource)`, the `roles` claim is the
  set of assigned app-role **values** on the resource. This is authoritative when
  present.
- **Delegated (user) tokens** — the requested delegated scopes are intersected with
  the `oauth2PermissionGrant`s that apply to `(client, resource, user)`
  (`AllPrincipals`, or `Principal` matching the signed-in user); only consented
  scopes land in `scp`.

**Divergence.** The emulator's client-credentials flow historically auto-grants an
app its declared roles (`docs/07-token-service.md`). That fallback is preserved for
apps with **no** stored assignments, so existing tests keep passing; once you create
an explicit `appRoleAssignment`, the stored grants become authoritative for that
`(client, resource)` pair.

---

## 3 — Directory roles

Directory-role membership is what puts the **`wids`** claim — an array of role
**template GUIDs** — into a user's tokens, and `wids` is a primary authorization
signal for admin experiences. The emulator implements the modern unified-RBAC
surface Microsoft documents
(`identity/role-based-access-control/custom-security-attributes-manage.md`).

### Role definitions & assignments

| Method | Path | → |
|---|---|---|
| `GET` | `/v1.0/roleManagement/directory/roleDefinitions` | built-in role definitions |
| `GET` | `/v1.0/roleManagement/directory/roleDefinitions/{id}` | one definition |
| `GET` | `/v1.0/roleManagement/directory/roleAssignments` | assignments (`$filter` on `principalId`, `roleDefinitionId`) |
| `POST` | `/v1.0/roleManagement/directory/roleAssignments` | `201`, assign a role |
| `DELETE` | `/v1.0/roleManagement/directory/roleAssignments/{id}` | `204`, unassign |

```jsonc
// POST /v1.0/roleManagement/directory/roleAssignments
{
  "@odata.type":      "#microsoft.graph.unifiedRoleAssignment",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",  // Global Administrator
  "principalId":      "aaaaaaaa-0000-0000-0000-000000000001",
  "directoryScopeId": "/"                                       // tenant-wide
}
```

For built-in roles, `roleDefinitionId` **equals the role template GUID**. The
emulator seeds the common built-ins:

| Role | Template GUID |
|---|---|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` |
| Global Reader | `f2ef992c-3afb-46b9-b7cf-a126ee74c451` |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` |
| User Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` |
| Application Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` |
| Cloud Application Administrator | `158c047a-c907-4556-b7ef-446551a6b5f7` |

### The `wids` claim

Per Microsoft's token reference
(`identity-platform/access-token-claims-reference.md`), `wids` lists the template
GUIDs of the **tenant-wide** directory roles assigned to the signed-in user, and is
emitted when the app's `groupMembershipClaims` is set to `DirectoryRole` or `All`.
The emulator follows this exactly:

- A user with a tenant-wide (`directoryScopeId == "/"`) role assignment gets that
  role's template GUID in `wids`.
- `wids` appears only when the requesting app's `groupMembershipClaims` includes
  directory roles (configurable per app; `docs/04-configuration.md`).
- Admin-unit-scoped assignments (`directoryScopeId != "/"`) do **not** surface in
  `wids`, matching Entra.

**Divergences.** Only tenant-wide scope drives `wids`; the legacy
`directoryRoles` / `directoryRoleTemplates` collection and role activation are not
implemented (the unified `roleManagement/directory` surface is the modern
equivalent). Custom role definitions are out of scope — only the seeded built-ins
exist.

---

## 4 — Authentication methods

The emulator already stores each user's credentials — a password hash and any
registered passkeys (`docs/14-passkey-sign-in.md`). This surface exposes them as
Microsoft Graph **authentication methods**, and ties them to the `amr` claim.

| Method | Path | → |
|---|---|---|
| `GET` | `/v1.0/users/{id}/authentication/methods` | all methods on the user |
| `GET` | `/v1.0/me/authentication/methods` | the signed-in user's methods |
| `GET` | `/v1.0/users/{id}/authentication/passwordMethods` | password method(s) |
| `GET` | `/v1.0/users/{id}/authentication/fido2Methods` | registered passkeys |
| `DELETE` | `/v1.0/users/{id}/authentication/fido2Methods/{id}` | `204`, remove a passkey |

```jsonc
// GET /v1.0/users/{id}/authentication/methods
{
  "value": [
    { "@odata.type": "#microsoft.graph.passwordAuthenticationMethod",
      "id": "28c10230-6103-485e-b985-444c60001490" },   // Graph's well-known password method id
    { "@odata.type": "#microsoft.graph.fido2AuthenticationMethod",
      "id": "<credential id>", "displayName": "MacBook Touch ID",
      "aaGuid": "…", "model": "…" }
  ]
}
```

### Relationship to `amr`

The method a user actually signs in with drives the `amr` claim (v1.0 / requested as
an optional claim in v2.0): password sign-in yields `amr: ["pwd"]`, a passkey
assertion yields `amr: ["fido"]` (`docs/07-token-service.md`,
`docs/14-passkey-sign-in.md`). The methods collection here is the **directory-side**
inventory of what a user *could* use; `amr` reflects what they *did* use for a given
token.

**Divergences.** Read-and-delete only (plus the existing WebAuthn registration
ceremonies for passkeys); adding a password or other method types
(`microsoftAuthenticator`, `email`, `phone`, hardware OATH) is not implemented. The
password method uses Graph's fixed well-known id.

---

## 5 — Graph write parity

The user / group / application write surface (`POST` / `PATCH` / `DELETE`, member
`$ref` links) is documented in `docs/09-graph-api.md`. Two parity points specific to
the stateful behavior on this page:

- **`DELETE` is a soft delete.** `DELETE /users/{id}`, `/groups/{id}`, and
  `/applications/{id}` return `204` and route the object into the
  [recycle bin](#1--soft-delete--recycle-bin) rather than hard-deleting it.
  Permanent deletion is only via `DELETE /directory/deletedItems/{id}`.
- **Member links use the reference body.** `POST /groups/{id}/members/$ref` takes
  `{ "@odata.id": "https://…/v1.0/users/{userId}" }` (the absolute directory-object
  URL; UPN is also accepted) and returns `204`; adding a member that is already
  present returns `400`. Removal is
  `DELETE /groups/{id}/members/{userId}/$ref` → `204`. This matches Microsoft's
  `$ref` contract (`identity/role-based-access-control/admin-units-members-add.md`).

Create bodies accept the documented Entra properties (e.g. `accountEnabled`,
`displayName`, `userPrincipalName`, `passwordProfile.password` for users;
`displayName` for groups). Properties the emulator does not model (e.g.
`mailNickname`, `groupTypes`, `employeeHireDate`) are accepted and ignored rather
than rejected, so real Graph SDK payloads succeed unmodified.

---

## Verifying parity with the Microsoft Graph SDKs

Every capability on this page is exercised end-to-end by the real **Microsoft Graph
SDK** in `e2e/` (alongside the MSAL SDK suites in `docs/16-e2e-sdk-matrix.md`): the
SDK acquires a token from the emulator, then creates / patches / soft-deletes /
restores users, assigns a directory role and reads back `wids`, records a consent
grant and observes `scp` / `roles`, and lists a user's authentication methods —
proving the emulator's request/response shapes are what an unmodified Entra client
expects.
