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

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`  FAIL ${name} ${extra}`); failures++; }
}

async function main() {
  console.log('Microsoft Graph SDK stateful-directory flows against', GRAPH);

  const cca = new msal.ConfidentialClientApplication({
    auth: {
      clientId: DAEMON_ID, clientSecret: DAEMON_SECRET,
      authority: AUTHORITY, knownAuthorities: [new URL(ORIGIN).host],
    },
  });
  const tok = await cca.acquireTokenByClientCredential({
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
    passwordProfile: { forceChangePasswordNextSignIn: true, password: 'S3cret!pass1' },
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

  const topped = await api(`${GRAPH}/users`).top(1).count(true).get();
  check('$top bounds the page and $count reports the total',
    (topped.value ?? []).length === 1 && typeof topped['@odata.count'] === 'number');

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
