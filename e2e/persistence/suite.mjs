// Real Microsoft Graph SDK across an emulator restart.
//
// docs/parity.md grades "Persisted directory" 🟢 — real SQLite, WAL, foreign
// keys — and its only witness is a Go test that round-trips the store in
// process. That proves the store can reload; it cannot prove a client's writes
// survive the process that accepted them, because the process never dies.
//
// This suite writes through the Graph SDK, the emulator is stopped and started
// again on the SAME database by the runner, and the same client reads its work
// back. The restart is the assertion: without it every check here would pass
// against a purely in-memory directory.
//
// Phase is passed as argv[2]: "write" before the restart, "read" after.
// Env: PERSIST_ORIGIN, PERSIST_TENANT, EMU_CERT, PERSIST_STATE.
import { readFileSync, writeFileSync } from 'node:fs';
import * as msal from '@azure/msal-node';
import { Client } from '@microsoft/microsoft-graph-client';

const PHASE = process.argv[2];
const ORIGIN = process.env.PERSIST_ORIGIN;
const TENANT = process.env.PERSIST_TENANT;
const STATE = process.env.PERSIST_STATE;
if (!ORIGIN || !TENANT || !STATE) throw new Error('PERSIST_ORIGIN, PERSIST_TENANT, PERSIST_STATE required');
if (!process.env.EMU_CERT) throw new Error('EMU_CERT must point at the emulator PEM');
process.env.NODE_EXTRA_CA_CERTS = process.env.EMU_CERT;

const GRAPH = `${ORIGIN}/graph/v1.0`;
const AUTHORITY = `${ORIGIN}/${TENANT}`;
const DAEMON_ID = '00d88624-f0d7-46f6-a641-6232c2608928';
const DAEMON_SECRET = 'daemon-app-secret';

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`  FAIL ${name} ${extra}`); failures++; }
}

async function graph() {
  const cca = new msal.ConfidentialClientApplication({
    auth: {
      clientId: DAEMON_ID, clientSecret: DAEMON_SECRET, authority: AUTHORITY,
      knownAuthorities: [new URL(ORIGIN).host],
    },
  });
  const tok = await cca.acquireTokenByClientCredential({
    scopes: ['https://graph.microsoft.com/.default'],
  });
  return Client.init({
    authProvider: (done) => done(null, tok.accessToken),
    defaultVersion: 'v1.0',
    // Without this the SDK attaches the token only to graph.microsoft.com and
    // every call arrives unauthenticated as a 401.
    customHosts: new Set([new URL(ORIGIN).hostname]),
  });
}

async function write() {
  const api = await graph();
  const stamp = Date.now();
  const upn = `persist-${stamp}@entraemulator.dev`;

  const user = await api.api(`${GRAPH}/users`).post({
    accountEnabled: true,
    displayName: 'Persisted Through Restart',
    mailNickname: `persist${stamp}`,
    userPrincipalName: upn,
    passwordProfile: { forceChangePasswordNextSignIn: false, password: 'S3cret!pass1' },
  });
  check('SDK created a user before the restart', !!user.id, JSON.stringify(user).slice(0, 120));

  const group = await api.api(`${GRAPH}/groups`).post({
    displayName: `Persisted Group ${stamp}`,
    mailEnabled: false,
    mailNickname: `pgrp${stamp}`,
    securityEnabled: true,
  });
  check('SDK created a group before the restart', !!group.id);

  // Membership is the interesting row: it is a foreign-keyed join, so it
  // exercises more of the "real SQLite, foreign keys" claim than a bare row.
  await api.api(`${GRAPH}/groups/${group.id}/members/$ref`).post({
    '@odata.id': `${GRAPH}/directoryObjects/${user.id}`,
  });
  const members = await api.api(`${GRAPH}/groups/${group.id}/members`).get();
  check('membership exists before the restart',
    (members.value || []).some((m) => m.id === user.id));

  writeFileSync(STATE, JSON.stringify({ upn, userId: user.id, groupId: group.id, stamp }));
}

async function read() {
  const { upn, userId, groupId } = JSON.parse(readFileSync(STATE, 'utf8'));
  const api = await graph();

  // Read by id, not by listing and counting: a count would pass on any user.
  const user = await api.api(`${GRAPH}/users/${userId}`).get();
  check('the user survived the restart', user.id === userId, `got ${user.id}`);
  check('and kept its identity, not just its row',
    user.userPrincipalName === upn && user.displayName === 'Persisted Through Restart',
    `${user.userPrincipalName} / ${user.displayName}`);

  const group = await api.api(`${GRAPH}/groups/${groupId}`).get();
  check('the group survived the restart', group.id === groupId);

  const members = await api.api(`${GRAPH}/groups/${groupId}/members`).get();
  check('the membership edge survived the restart',
    (members.value || []).some((m) => m.id === userId),
    JSON.stringify(members.value || []).slice(0, 140));

  // The seeded directory must still be there too: a restart that silently
  // re-seeded an empty database would satisfy every check above.
  const alice = await api.api(`${GRAPH}/users`).filter("userPrincipalName eq 'alice@entraemulator.dev'").get();
  check('the pre-existing directory is intact, not re-seeded over',
    (alice.value || []).length === 1);
}

const run = PHASE === 'write' ? write : PHASE === 'read' ? read : null;
if (!run) throw new Error(`unknown phase ${PHASE}`);
run().then(() => {
  console.log(failures === 0 ? `PASS (${PHASE})` : `FAIL (${PHASE}, ${failures})`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((e) => { console.error(e); process.exit(1); });
