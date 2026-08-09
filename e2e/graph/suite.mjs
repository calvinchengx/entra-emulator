// Real Microsoft Graph SDK e2e (@microsoft/microsoft-graph-client) against a
// running emulator — proves the stateful directory surface
// (docs/20-stateful-directory.md) speaks the wire protocol an unmodified Graph
// client expects: create/patch/soft-delete/restore users, assign a directory
// role, record consent grants, and read authentication methods.
//
// Auth token comes from @azure/msal-node (client credentials). The Graph client
// is driven with absolute emulator URLs so it targets the local /graph surface
// instead of graph.microsoft.com; because the SDK only auto-attaches the bearer
// token to graph.microsoft.com, we set the Authorization header per request.
// Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
import * as msal from '@azure/msal-node';
import { Client } from '@microsoft/microsoft-graph-client';

// Local emulator uses a self-signed cert; trust it for this process only.
// Keep TLS validation enabled and provide the emulator CA/cert instead.
if (!process.env.EMU_CERT) {
  throw new Error('EMU_CERT must be set to a PEM file path for emulator TLS trust.');
}
process.env.NODE_EXTRA_CA_CERTS = process.env.EMU_CERT;

const ORIGIN = process.env.EMU_ORIGIN;
const TENANT = process.env.EMU_TENANT;
const GRAPH = `${ORIGIN}/graph/v1.0`;
const AUTHORITY = `${ORIGIN}/${TENANT}`;
const DAEMON_ID = '00d88624-f0d7-46f6-a641-6232c2608928';
const DAEMON_SECRET = 'daemon-app-secret';
const GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';
// Graph's fixed id for the password authentication method.
const PASSWORD_METHOD_ID = '28c10230-6103-485e-b985-444c60001490';
const INITIAL_PASSWORD = 'S3cret!pass1';

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`  FAIL ${name} ${extra}`); failures++; }
}

const AUTH = { clientId: DAEMON_ID, clientSecret: DAEMON_SECRET, authority: AUTHORITY };
const knownAuthorities = [new URL(ORIGIN).host];

/** A confidential client with its own empty cache, so every call really hits
 *  the token endpoint. Reusing one instance would answer from cache and the
 *  lifetime assertions below would be reading a stale token. */
const freshClient = () =>
  new msal.ConfidentialClientApplication({ auth: { ...AUTH, knownAuthorities } });

/** exp - iat of a newly minted app-only token, in seconds. The payload is read
 *  without verifying: signature verification is a separate claim with its own
 *  witness, and what is under test here is the lifetime. */
async function freshLifetime() {
  const t = await freshClient().acquireTokenByClientCredential({
    scopes: ['https://graph.microsoft.com/.default'],
  });
  const claims = JSON.parse(
    Buffer.from(t.accessToken.split('.')[1], 'base64url').toString('utf8'));
  return claims.exp - claims.iat;
}

/** Whether these credentials sign in over ROPC. Returns false on a rejected
 *  credential rather than throwing, so the caller can assert a denial — a reset
 *  that is only ever checked positively would pass without invalidating the old
 *  password. */
async function ropcWorks(username, password) {
  try {
    const r = await freshClient().acquireTokenByUsernamePassword({
      scopes: ['https://graph.microsoft.com/User.Read'], username, password,
    });
    return !!r?.accessToken;
  } catch {
    return false;
  }
}

async function main() {
  console.log('Microsoft Graph SDK stateful-directory flows against', GRAPH);

  const tok = await freshClient().acquireTokenByClientCredential({
    scopes: ['https://graph.microsoft.com/.default'],
  });

  const client = Client.init({
    authProvider: (done) => done(null, tok.accessToken),
    defaultVersion: 'v1.0',
    // Allow-list the emulator hostname so the SDK's auth middleware attaches the
    // bearer token to our absolute URLs (it validates the bare hostname, no port).
    customHosts: new Set([new URL(ORIGIN).hostname]),
  });
  const api = (path) => client.api(path);

  // 1. Create a user through the SDK.
  const upn = `sdk-user@entraemulator.dev`;
  const created = await api(`${GRAPH}/users`).post({
    accountEnabled: true,
    displayName: 'SDK User',
    mailNickname: 'sdkuser',
    userPrincipalName: upn,
    // Not forcing a change at next sign-in: this user goes on to sign in over
    // ROPC below, to prove the password reset in 5k is real.
    passwordProfile: { forceChangePasswordNextSignIn: false, password: INITIAL_PASSWORD },
  });
  const uid = created.id;
  check('create user', !!uid && created.displayName === 'SDK User');

  // 2. Patch the user.
  await api(`${GRAPH}/users/${uid}`).update({ displayName: 'SDK User Renamed' });
  const patched = await api(`${GRAPH}/users/${uid}`).get();
  check('patch user', patched.displayName === 'SDK User Renamed');

  // 3. Assign a directory role (unified RBAC) to the user.
  const assignment = await api(`${GRAPH}/roleManagement/directory/roleAssignments`).post({
    roleDefinitionId: GLOBAL_ADMIN, principalId: uid, directoryScopeId: '/',
  });
  check('assign Global Administrator', assignment.roleDefinitionId === GLOBAL_ADMIN);
  const roleDefs = await api(`${GRAPH}/roleManagement/directory/roleDefinitions`).get();
  check('list role definitions', (roleDefs.value ?? []).some((d) => d.templateId === GLOBAL_ADMIN));

  // 4. Record consent grants on a resource service principal (the daemon app).
  const grant = await api(`${GRAPH}/oauth2PermissionGrants`).post({
    clientId: uid, consentType: 'AllPrincipals', resourceId: DAEMON_ID, scope: 'Tasks.Read',
  });
  check('create oauth2PermissionGrant', !!grant.id);
  const assignedTo = await api(`${GRAPH}/servicePrincipals/${DAEMON_ID}/appRoleAssignedTo`).post({
    principalId: uid, resourceId: DAEMON_ID, appRoleId: '00000000-0000-0000-0000-000000000000',
  });
  check('create appRoleAssignedTo', !!assignedTo.id);

  // 5. Read the user's authentication methods.
  const methods = await api(`${GRAPH}/users/${uid}/authentication/methods`).get();
  check('list authentication methods', Array.isArray(methods.value) &&
    methods.value.some((m) => m['@odata.type'] === '#microsoft.graph.passwordAuthenticationMethod'));

  // Unique per run, so a re-run against a persisted emulator does not collide.
  const stamp = uid.slice(0, 8);

  // 5b. Groups and membership through $ref — the half of the directory-writes
  // claim the SDK never exercised, so that row rested on our own client alone.
  const group = await api(`${GRAPH}/groups`).post({
    displayName: `SDK Group ${stamp}`, mailEnabled: false,
    mailNickname: `sdkgroup${stamp}`, securityEnabled: true,
  });
  const gid = group.id;
  check('create group', !!gid && group.displayName === `SDK Group ${stamp}`);

  // Membership is written as an OData reference, not an embedded object. A
  // server that accepted a plain POST body here would look fine to a hand
  // written client and fail against every real one.
  await api(`${GRAPH}/groups/${gid}/members/$ref`).post({
    '@odata.id': `${GRAPH}/directoryObjects/${uid}`,
  });
  const members = await api(`${GRAPH}/groups/${gid}/members`).get();
  check('member added by $ref', (members.value ?? []).some((m) => m.id === uid));

  const memberOf = await api(`${GRAPH}/users/${uid}/memberOf`).get();
  check('memberOf reports the group', (memberOf.value ?? []).some((g) => g.id === gid));

  await api(`${GRAPH}/groups/${gid}/members/${uid}/$ref`).delete();
  const after = await api(`${GRAPH}/groups/${gid}/members`).get();
  check('member removed by $ref', !(after.value ?? []).some((m) => m.id === uid));

  // 5c. Applications — the third noun in the same claim.
  const app = await api(`${GRAPH}/applications`).post({
    displayName: `SDK App ${stamp}`,
  });
  check('create application', !!app.id && app.displayName === `SDK App ${stamp}`);
  const appBack = await api(`${GRAPH}/applications/${app.id}`).get();
  check('read application back', appBack.id === app.id);

  // 5d. OData query options, built by the SDK rather than hand-written, which
  // is the point: $select projection, $top paging and $count all have to be
  // understood as the client emits them.
  const projected = await api(`${GRAPH}/users`).select('id,displayName').get();
  check('$select projects the requested fields',
    (projected.value ?? []).length > 0 &&
    Object.keys(projected.value[0]).every((k) => k === 'id' || k === 'displayName' ||
      k.startsWith('@')));

  // The full list first, so $count can be checked against the real total
  // rather than against its own type. `typeof === 'number'` would accept 0
  // beside five users — a count is exactly the field where asserting the shape
  // instead of the value proves nothing.
  const everyUser = await api(`${GRAPH}/users`).top(999).get();
  const topped = await api(`${GRAPH}/users`).top(1).count(true).get();
  check('$top bounds the page and $count reports the real total',
    (topped.value ?? []).length === 1 &&
    topped['@odata.count'] === (everyUser.value ?? []).length,
    `count=${topped['@odata.count']} actual=${(everyUser.value ?? []).length}`);

  // The claim names $skiptoken, so the suite has to follow the link rather
  // than stop at the first page — a nextLink nobody dereferences proves only
  // that a string was emitted.
  check('$top page carries a nextLink', typeof topped['@odata.nextLink'] === 'string');
  const page2 = await api(topped['@odata.nextLink']).get();
  check('nextLink returns a further page',
    (page2.value ?? []).length > 0 && page2.value[0].id !== topped.value[0].id);

  const filtered = await api(`${GRAPH}/users`)
    .filter(`startswith(displayName,'SDK User')`).get();
  check('$filter startswith selects the user',
    (filtered.value ?? []).some((u) => u.id === uid));

  // 5e. Custom role definitions — a tenant-defined role, then an assignment
  // against it. The built-in path above proves the assignment route; this
  // proves a role the tenant invented is a first-class target for it.
  const roleDef = await api(`${GRAPH}/roleManagement/directory/roleDefinitions`).post({
    displayName: `SDK Custom Role ${stamp}`,
    description: 'Created by the Graph SDK e2e',
    rolePermissions: ['microsoft.directory/users/basic/read'],
  });
  check('create custom role definition', !!roleDef.id && roleDef.isBuiltIn === false);
  const roleBack = await api(`${GRAPH}/roleManagement/directory/roleDefinitions/${roleDef.id}`).get();
  check('custom role carries its rolePermissions',
    (roleBack.rolePermissions ?? []).some((p) =>
      (p.allowedResourceActions ?? []).includes('microsoft.directory/users/basic/read')));

  const customAssignment = await api(`${GRAPH}/roleManagement/directory/roleAssignments`).post({
    roleDefinitionId: roleDef.id, principalId: uid, directoryScopeId: '/',
  });
  check('assign the custom role', customAssignment.roleDefinitionId === roleDef.id);

  // 5f. Administrative units — a directory container with $ref membership, the
  // same reference shape groups use.
  const au = await api(`${GRAPH}/directory/administrativeUnits`).post({
    displayName: `SDK AU ${stamp}`, description: 'Graph SDK e2e', visibility: 'Public',
  });
  check('create administrative unit', !!au.id && au.visibility === 'Public');

  await api(`${GRAPH}/directory/administrativeUnits/${au.id}`).update({
    description: 'Renamed by the SDK',
  });
  const auBack = await api(`${GRAPH}/directory/administrativeUnits/${au.id}`).get();
  check('patch administrative unit', auBack.description === 'Renamed by the SDK');

  await api(`${GRAPH}/directory/administrativeUnits/${au.id}/members/$ref`).post({
    '@odata.id': `${GRAPH}/directoryObjects/${uid}`,
  });
  const auMembers = await api(`${GRAPH}/directory/administrativeUnits/${au.id}/members`).get();
  check('AU member added by $ref', (auMembers.value ?? []).some((m) => m.id === uid));

  await api(`${GRAPH}/directory/administrativeUnits/${au.id}/members/${uid}/$ref`).delete();
  const auAfter = await api(`${GRAPH}/directory/administrativeUnits/${au.id}/members`).get();
  check('AU member removed by $ref', !(auAfter.value ?? []).some((m) => m.id === uid));

  // 5g. Custom security attributes — a set, typed definitions, then values on
  // the user. The assertion that matters is the LAST one: Graph withholds these
  // unless they are explicitly $select-ed, so a server that returned them by
  // default would leak attributes a real client never asked for.
  const setName = `Eng${stamp}`;
  const attrSet = await api(`${GRAPH}/directory/attributeSets`).post({
    id: setName, description: 'Graph SDK e2e', maxAttributesPerSet: 25,
  });
  check('create attribute set', attrSet.id === setName);

  for (const d of [
    { attributeSet: setName, name: 'Project', type: 'String' },
    { attributeSet: setName, name: 'CostCenter', type: 'Integer' },
  ]) {
    await api(`${GRAPH}/directory/customSecurityAttributeDefinitions`).post(d);
  }
  const csaDef = await api(
    `${GRAPH}/directory/customSecurityAttributeDefinitions/${setName}_Project`).get();
  check('definition id is the set_name composite',
    csaDef.attributeSet === setName && csaDef.name === 'Project' && csaDef.type === 'String');

  await api(`${GRAPH}/users/${uid}`).update({
    customSecurityAttributes: { [setName]: { Project: 'Apollo', CostCenter: 1001 } },
  });
  const withAttrs = await api(`${GRAPH}/users/${uid}`)
    .select('id,customSecurityAttributes').get();
  check('attribute values round-trip under $select',
    withAttrs.customSecurityAttributes?.[setName]?.Project === 'Apollo' &&
    withAttrs.customSecurityAttributes?.[setName]?.CostCenter === 1001);

  const withoutSelect = await api(`${GRAPH}/users/${uid}`).get();
  check('attributes are withheld without $select',
    !('customSecurityAttributes' in withoutSelect));

  // The declared type is enforced — a String where an Integer was declared is a
  // 400, not a silently coerced value.
  let typeRejected = false;
  try {
    await api(`${GRAPH}/users/${uid}`).update({
      customSecurityAttributes: { [setName]: { CostCenter: 'not-a-number' } },
    });
  } catch (e) { typeRejected = e.statusCode === 400; }
  check('a wrongly-typed attribute value is refused', typeRejected);

  // 5h. federatedIdentityCredentials on the application created above — the
  // Graph route onto workload identity federation.
  const ficBase = `${GRAPH}/applications/${app.id}/federatedIdentityCredentials`;
  const fic = await api(ficBase).post({
    name: 'sdk-github-actions',
    issuer: 'https://token.actions.githubusercontent.com',
    subject: 'repo:contoso/widgets:ref:refs/heads/main',
    audiences: ['api://AzureADTokenExchange'],
    description: 'Graph SDK e2e',
  });
  check('create federatedIdentityCredential', !!fic.id && fic.name === 'sdk-github-actions');

  await api(`${ficBase}/${fic.id}`).update({
    subject: 'repo:contoso/widgets:ref:refs/heads/release',
  });
  const ficBack = await api(`${ficBase}/${fic.id}`).get();
  check('patch federatedIdentityCredential subject',
    ficBack.subject === 'repo:contoso/widgets:ref:refs/heads/release');

  const ficList = await api(ficBase).get();
  check('list federatedIdentityCredentials', (ficList.value ?? []).some((c) => c.id === fic.id));

  await api(`${ficBase}/${fic.id}`).delete();
  let ficGone = false;
  try { await api(`${ficBase}/${fic.id}`).get(); }
  catch (e) { ficGone = e.statusCode === 404; }
  check('delete federatedIdentityCredential', ficGone);

  // 5i. Token lifetime policies. A policy that only appears in a catalogue
  // would be worthless — what is asserted here is that assigning one changes
  // the `exp` of the token msal-node actually receives, and that unassigning
  // puts it back.
  const baseline = await freshLifetime();
  // Positive control: if the configured default were already eight hours the
  // assertion below would pass without the policy doing anything.
  check('the baseline lifetime differs from the policy under test', baseline !== 8 * 3600,
    `baseline is ${baseline}`);
  const policy = await api(`${GRAPH}/policies/tokenLifetimePolicies`).post({
    displayName: `SDK Eight Hours ${stamp}`,
    // Entra carries the settings as JSON inside a string, so send exactly that.
    definition: ['{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"08:00:00"}}'],
  });
  check('create tokenLifetimePolicy', !!policy.id);

  await api(`${GRAPH}/applications/${DAEMON_ID}/tokenLifetimePolicies/$ref`).post({
    '@odata.id': `${GRAPH}/policies/tokenLifetimePolicies/${policy.id}`,
  });
  const assigned = await api(`${GRAPH}/applications/${DAEMON_ID}/tokenLifetimePolicies`).get();
  check('policy lists on the application', (assigned.value ?? []).some((p) => p.id === policy.id));
  check('assigned policy changes the minted token lifetime',
    (await freshLifetime()) === 8 * 3600, `baseline was ${baseline}`);

  // Unassign inside the same suite: later suites share this emulator, and a
  // policy left on the daemon app would silently reshape their tokens too.
  await api(`${GRAPH}/applications/${DAEMON_ID}/tokenLifetimePolicies/${policy.id}/$ref`).delete();
  check('unassigning restores the default lifetime', (await freshLifetime()) === baseline);
  await api(`${GRAPH}/policies/tokenLifetimePolicies/${policy.id}`).delete();

  // A definition that parses to nothing is refused rather than stored inert —
  // the caller would otherwise believe a lifetime had been applied.
  let inertRejected = false;
  try {
    await api(`${GRAPH}/policies/tokenLifetimePolicies`).post({
      displayName: 'Inert', definition: ['{"TokenLifetimePolicy":{"Version":1}}'],
    });
  } catch (e) { inertRejected = e.statusCode === 400; }
  check('a definition that sets nothing is refused', inertRejected);

  // 5j. B2B guest invitation. The invitation creates a real directory user with
  // the mangled external UPN, and redeeming flips the state an app branches on.
  const guestEmail = `guest-${stamp}@partner.example`;
  const invite = await api(`${GRAPH}/invitations`).post({
    invitedUserEmailAddress: guestEmail,
    inviteRedirectUrl: 'https://app.example/welcome',
    invitedUserDisplayName: 'SDK Guest',
  });
  const guestID = invite.invitedUser?.id;
  check('create invitation', !!guestID && invite.status === 'PendingAcceptance' &&
    typeof invite.inviteRedeemUrl === 'string');

  const guest = await api(`${GRAPH}/users/${guestID}`).get();
  check('guest is a real directory user with the #EXT# UPN',
    guest.userType === 'Guest' && guest.externalUserState === 'PendingAcceptance' &&
    guest.userPrincipalName.includes('#EXT#@'));

  // Redemption is a user-facing link, not a Graph call, so it is followed with
  // plain fetch; the state change is then read back through the SDK.
  const redeemed = await fetch(invite.inviteRedeemUrl, { redirect: 'manual' });
  check('redeem link redirects to the inviting app',
    redeemed.status === 302 &&
    (redeemed.headers.get('location') ?? '').startsWith('https://app.example/welcome'));
  const acceptedGuest = await api(`${GRAPH}/users/${guestID}`).get();
  check('redeeming flips externalUserState to Accepted',
    acceptedGuest.externalUserState === 'Accepted');

  // 5k. Password reset over the authentication-methods API. The reset has to be
  // REAL, so it is proved the only way that counts: msal-node signs the user in
  // with the new password, and the old one stops working.
  const pwBase = `${GRAPH}/users/${uid}/authentication/passwordMethods/${PASSWORD_METHOD_ID}`;
  check('the original password signs in', await ropcWorks(upn, INITIAL_PASSWORD));

  const rotated = 'R0tated!pass2';
  await api(`${pwBase}/resetPassword`).post({ newPassword: rotated });
  check('the new password signs in', await ropcWorks(upn, rotated));
  check('the old password no longer signs in', !(await ropcWorks(upn, INITIAL_PASSWORD)));

  // Omitting newPassword makes Entra generate one and return it.
  const generated = await api(`${pwBase}/resetPassword`).post({});
  check('a system-generated password is returned', typeof generated?.newPassword === 'string' &&
    generated.newPassword.length > 0);
  check('the generated password signs in', await ropcWorks(upn, generated.newPassword));

  // 5l. The two log surfaces, read after everything above actually happened —
  // so these assert over real traffic rather than a seeded row.
  // $top is raised deliberately: both logs are newest-first ring buffers, and
  // the rows being asserted on were written near the start of this suite.
  const signIns = await api(`${GRAPH}/auditLogs/signIns`).top(500).get();
  check('signIns records the client-credentials exchange',
    (signIns.value ?? []).some((s) => s.appId === DAEMON_ID &&
      s.clientAppUsed === 'Client Credentials' && s.status?.errorCode === 0));
  check('signIns records the ROPC sign-in and its failure',
    (signIns.value ?? []).some((s) => s.clientAppUsed === 'Resource Owner Password Credential' &&
      s.status?.errorCode === 0) &&
    (signIns.value ?? []).some((s) => s.clientAppUsed === 'Resource Owner Password Credential' &&
      s.status?.errorCode !== 0));

  const audits = await api(`${GRAPH}/auditLogs/directoryAudits`).top(500).get();
  const rows = audits.value ?? [];
  check('directoryAudits journals the user we created',
    rows.some((a) => (a.targetResources ?? []).some((t) => t.id === uid) &&
      a.category === 'UserManagement'));
  check('directoryAudits attributes the change to the calling app',
    rows.some((a) => a.initiatedBy?.app?.appId === DAEMON_ID));
  // App-only callers have no user, which is meaningful rather than missing.
  // The length guard is the point: `every` over an empty log would pass while
  // proving nothing at all.
  check('an app-only caller reports no user',
    rows.length > 0 && rows.every((a) => a.initiatedBy?.user === undefined));

  // 6. Soft-delete the user → it lands in the recycle bin.
  await api(`${GRAPH}/users/${uid}`).delete();
  let live404 = false;
  try { await api(`${GRAPH}/users/${uid}`).get(); }
  catch (e) { live404 = e.statusCode === 404; }
  check('soft-deleted user gone from live collection', live404);

  const bin = await api(`${GRAPH}/directory/deletedItems/microsoft.graph.user`).get();
  check('user listed in recycle bin', (bin.value ?? []).some((u) => u.id === uid &&
    u['@odata.type'] === '#microsoft.graph.user' && !!u.deletedDateTime));

  // 7. Restore, then confirm it is live again.
  await api(`${GRAPH}/directory/deletedItems/${uid}/restore`).post({});
  const restored = await api(`${GRAPH}/users/${uid}`).get();
  check('restored user is live', restored.userPrincipalName === upn);

  // 8. Permanently delete (re-delete then purge from the recycle bin).
  await api(`${GRAPH}/users/${uid}`).delete();
  await api(`${GRAPH}/directory/deletedItems/${uid}`).delete();
  let purged = false;
  try { await api(`${GRAPH}/directory/deletedItems/${uid}/restore`).post({}); }
  catch (e) { purged = e.statusCode === 404; }
  check('purged user cannot be restored', purged);

  console.log(failures ? `\n${failures} check(s) failed` : '\nall Graph SDK checks passed');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
