// Real Microsoft Graph SDK e2e (@microsoft/microsoft-graph-client) against a
// running emulator — proves the stateful directory surface
// (docs/19-stateful-directory.md) speaks the wire protocol an unmodified Graph
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
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const ORIGIN = process.env.EMU_ORIGIN;
const TENANT = process.env.EMU_TENANT;
const GRAPH = `${ORIGIN}/graph/v1.0`;
const AUTHORITY = `${ORIGIN}/${TENANT}`;
const DAEMON_ID = 'cccccccc-0000-0000-0000-000000000002';
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
