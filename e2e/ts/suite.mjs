// Real-MSAL e2e suite (@azure/msal-node) against a running emulator.
// Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT (NODE_EXTRA_CA_CERTS already set).
import * as msal from '@azure/msal-node';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';

const ORIGIN = process.env.EMU_ORIGIN;
const TENANT = process.env.EMU_TENANT;
const AUTHORITY = `${ORIGIN}/${TENANT}`;
const SPA_ID = 'cccccccc-0000-0000-0000-000000000001';
const DAEMON_ID = 'cccccccc-0000-0000-0000-000000000002';
const DAEMON_SECRET = 'daemon-app-secret';
const ALICE_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const REDIRECT = 'https://localhost:3000';

const ca = readFileSync(process.env.EMU_CERT);
const agent = new https.Agent({ ca });

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`  FAIL ${name} ${extra}`); failures++; }
}
const decode = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

// Minimal HTTPS driver with a cookie jar for the interactive pages.
const jar = [];
function request(url, { method = 'GET', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method, agent,
      headers: { ...headers, cookie: jar.join('; ') },
    }, (res) => {
      (res.headers['set-cookie'] ?? []).forEach((c) => jar.push(c.split(';')[0]));
      let data = '';
      res.on('data', (d) => (data += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
const form = (o) => new URLSearchParams(o).toString();

async function main() {
  console.log('msal-node version flows against', AUTHORITY);

  // --- Client credentials ---
  const cca = new msal.ConfidentialClientApplication({
    auth: {
      clientId: DAEMON_ID, clientSecret: DAEMON_SECRET,
      authority: AUTHORITY, knownAuthorities: [new URL(ORIGIN).host],
    },
  });
  const cc = await cca.acquireTokenByClientCredential({
    scopes: [`api://${DAEMON_ID}/.default`],
  });
  const ccClaims = decode(cc.accessToken);
  check('client_credentials: token acquired', !!cc.accessToken);
  check('client_credentials: aud + roles', ccClaims.aud === `api://${DAEMON_ID}` &&
    ccClaims.roles?.includes('Tasks.Read.All'), JSON.stringify(ccClaims));
  check('client_credentials: no oid/scp', !ccClaims.oid && !ccClaims.scp);

  // --- Auth code + PKCE (public client, page driven over HTTPS) ---
  const pca = new msal.PublicClientApplication({
    auth: { clientId: SPA_ID, authority: AUTHORITY, knownAuthorities: [new URL(ORIGIN).host] },
  });
  const verifier = crypto.randomBytes(48).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const authUrl = await pca.getAuthCodeUrl({
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    redirectUri: REDIRECT, codeChallenge: challenge, codeChallengeMethod: 'S256',
    state: 'e2e-state', nonce: 'e2e-nonce',
  });
  const picker = await request(authUrl);
  check('authorize: account picker rendered', picker.status === 200 && picker.body.includes('alice@entralocal.dev'));
  const signed = picker.body.match(/name="__el_state" value="([^"]+)"/)?.[1];
  const submit = await request(`${ORIGIN}/${TENANT}/oauth2/v2.0/authorize`, {
    method: 'POST', body: form({ __el_state: signed, __el_user: ALICE_ID }),
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  check('authorize: 302 with code + state', submit.status === 302 && submit.headers.location?.includes('state=e2e-state'));
  const code = new URL(submit.headers.location).searchParams.get('code');

  const tokens = await pca.acquireTokenByCode({
    code, redirectUri: REDIRECT, codeVerifier: verifier,
    scopes: ['openid', 'profile', 'email', 'offline_access'],
  });
  check('acquireTokenByCode: id + access tokens', !!tokens.idToken && !!tokens.accessToken);
  check('account identity from client_info',
    tokens.account?.username === 'alice@entralocal.dev' &&
    tokens.account?.homeAccountId?.startsWith(ALICE_ID),
    JSON.stringify(tokens.account));
  check('id token nonce + ver', tokens.idTokenClaims?.nonce === 'e2e-nonce' && tokens.idTokenClaims?.ver === '2.0');

  // --- Silent renewal from cache (forces the refresh-token grant) ---
  const silent = await pca.acquireTokenSilent({
    account: tokens.account, scopes: ['openid', 'profile'], forceRefresh: true,
  });
  check('acquireTokenSilent(forceRefresh): new access token',
    !!silent.accessToken && silent.accessToken !== tokens.accessToken);

  // --- Device code (approval driven concurrently, never blocking the poll) ---
  const approve = async (userCode) => {
    const lookup = await request(`${ORIGIN}/${TENANT}/oauth2/v2.0/devicecode/verify`, {
      method: 'POST', body: form({ __el_step: 'lookup', user_code: userCode }),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    // Session cookie from the earlier sign-in gives the direct-SSO consent page.
    const st = lookup.body.match(/name="__el_state" value="([^"]+)"/)?.[1];
    if (!st) throw new Error('no consent state: ' + lookup.body.slice(0, 300));
    const decide = await request(`${ORIGIN}/${TENANT}/oauth2/v2.0/devicecode/verify`, {
      method: 'POST', body: form({ __el_step: 'decide', __el_state: st, __el_decision: 'approve' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    if (!decide.body.includes("You're all set")) throw new Error('approve failed: ' + decide.body.slice(0, 300));
  };
  let approvalPromise;
  const device = await pca.acquireTokenByDeviceCode({
    scopes: ['openid', 'profile', 'offline_access'],
    deviceCodeCallback: (info) => { approvalPromise = approve(info.userCode); },
  });
  await approvalPromise;
  check('device code: token for approving user',
    device.account?.username === 'alice@entralocal.dev', JSON.stringify(device.account));

  // --- Negative: wrong secret ---
  const bad = new msal.ConfidentialClientApplication({
    auth: { clientId: DAEMON_ID, clientSecret: 'wrong', authority: AUTHORITY, knownAuthorities: [new URL(ORIGIN).host] },
  });
  try {
    await bad.acquireTokenByClientCredential({ scopes: [`api://${DAEMON_ID}/.default`] });
    check('wrong secret rejected', false);
  } catch (e) {
    check('wrong secret rejected as invalid_client', `${e.errorCode ?? e.message}`.includes('invalid_client'), e.message);
  }

  if (failures) { console.error(`\n${failures} failure(s)`); process.exit(1); }
  console.log('\nTypeScript (msal-node) e2e: all checks passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
