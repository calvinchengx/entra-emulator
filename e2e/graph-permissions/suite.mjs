// Real Microsoft Graph SDK against the permission gate.
//
// docs/parity.md grades "Graph permission enforcement (scopes/roles gating
// operations)" 🟢, and until now its only witnesses were Go tests that FORGE
// tokens with chosen roles. That is our client on both ends: it proves the
// handler reads a claim, not that a real client is actually gated. A forged
// token cannot fail the way a real one does, because nothing upstream of the
// handler ever ran.
//
// Here every token comes from the emulator's own token endpoint via
// @azure/msal-node, and every call goes through @microsoft/microsoft-graph-client.
// The 403 has to survive MSAL minting the token and the Graph SDK parsing the
// error, which is the part a forged token skips.
//
// This suite boots its OWN emulator: GRAPH_PERMISSIONS is config-only with no
// runtime toggle, and the shared e2e emulator runs with the gate off (its
// default, matching Entra's own behaviour for an unconfigured tenant).
//
// Env: EMU_CERT is set by the runner; ORIGIN/PORT are this suite's own.
import * as msal from '@azure/msal-node';
import { Client } from '@microsoft/microsoft-graph-client';

const ORIGIN = process.env.GP_ORIGIN;
const TENANT = process.env.GP_TENANT;
if (!ORIGIN || !TENANT) throw new Error('GP_ORIGIN and GP_TENANT must be set');
if (!process.env.EMU_CERT) throw new Error('EMU_CERT must point at the emulator PEM');
process.env.NODE_EXTRA_CA_CERTS = process.env.EMU_CERT;

const GRAPH = `${ORIGIN}/graph/v1.0`;
const AUTHORITY = `${ORIGIN}/${TENANT}`;
const DAEMON_ID = '00d88624-f0d7-46f6-a641-6232c2608928';
const DAEMON_SECRET = 'daemon-app-secret';
const SPA_ID = '189c7070-78a3-4c13-aa18-20a2ca5755ca';
const ALICE = 'alice@entraemulator.dev';
const ALICE_PASSWORD = 'Password1!';
const knownAuthorities = [new URL(ORIGIN).host];

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`  FAIL ${name} ${extra}`); failures++; }
}

/** App-only token. Carries no roles: the directory has no Graph resource app
 *  with Application-type roles to grant, which is exactly the unprivileged
 *  caller the gate exists to stop. */
async function appOnlyToken() {
  const cca = new msal.ConfidentialClientApplication({
    auth: { clientId: DAEMON_ID, clientSecret: DAEMON_SECRET, authority: AUTHORITY, knownAuthorities },
  });
  const r = await cca.acquireTokenByClientCredential({
    scopes: ['https://graph.microsoft.com/.default'],
  });
  return r.accessToken;
}

/** Delegated token carrying a single read scope, via a real ROPC exchange. */
async function delegatedReadToken() {
  const pca = new msal.PublicClientApplication({
    auth: { clientId: SPA_ID, authority: AUTHORITY, knownAuthorities },
  });
  const r = await pca.acquireTokenByUsernamePassword({
    scopes: ['https://graph.microsoft.com/User.Read.All'],
    username: ALICE,
    password: ALICE_PASSWORD,
  });
  return r.accessToken;
}

const clientFor = (token) => Client.init({
  authProvider: (done) => done(null, token),
  defaultVersion: 'v1.0',
  // Allow-list the emulator hostname, or the SDK's auth middleware attaches the
  // bearer token only to graph.microsoft.com and every call here goes out
  // unauthenticated — arriving as 401 InvalidAuthenticationToken, which reads
  // like a broken gate rather than a missing header.
  customHosts: new Set([new URL(ORIGIN).hostname]),
});

/** Run a Graph call and report the status the SDK surfaced, so a denial is
 *  distinguishable from a transport failure. Returning only "it threw" would
 *  make a connection refusal indistinguishable from a 403. */
async function attempt(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (e) {
    return { ok: false, status: e.statusCode ?? e.status, code: e.code, body: e.body };
  }
}

const decode = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());

async function main() {
  // --- the unprivileged app-only caller is denied ---
  const appTok = await appOnlyToken();
  const appClaims = decode(appTok);
  check('app-only token really carries no roles',
    Array.isArray(appClaims.roles) && appClaims.roles.length === 0, JSON.stringify(appClaims.roles));

  const denied = await attempt(() => clientFor(appTok).api(`${GRAPH}/users`).get());
  check('Graph SDK is denied without a role', !denied.ok && denied.status === 403,
    `status=${denied.status}`);
  // Assert WHICH error. A 403 for any other reason would satisfy a status check
  // while proving nothing about the permission gate.
  const code = (() => { try { return JSON.parse(denied.body).error.code; } catch { return denied.code; } })();
  check('denial is Authorization_RequestDenied, as Graph returns',
    code === 'Authorization_RequestDenied', String(code));

  // --- a delegated caller holding the read scope is allowed ---
  const readTok = await delegatedReadToken();
  const readClaims = decode(readTok);
  check('delegated token carries the read scope', readClaims.scp === 'User.Read.All', String(readClaims.scp));

  const allowed = await attempt(() => clientFor(readTok).api(`${GRAPH}/users`).get());
  check('Graph SDK reads with the scope', allowed.ok && Array.isArray(allowed.value?.value),
    `status=${allowed.status}`);

  // --- and that read scope does not grant writes ---
  const write = await attempt(() => clientFor(readTok).api(`${GRAPH}/users`).post({
    userPrincipalName: `gate-probe-${Date.now()}@entraemulator.dev`,
    displayName: 'Gate Probe',
  }));
  check('a read scope does not grant writes', !write.ok && write.status === 403,
    `status=${write.status}`);

  console.log(failures === 0 ? 'PASS' : `FAIL (${failures})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
