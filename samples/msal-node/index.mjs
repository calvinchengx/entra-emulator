// Minimal MSAL Node sample: acquire an app-only (client-credentials) token
// from the emulator and call the emulated Microsoft Graph with it.
//
//   1. Start the emulator:  ORIGIN_MODE=compat ./entra-emulator
//   2. Run this sample:     NODE_EXTRA_CA_CERTS=$(../../entra-emulator cert-path) node index.mjs
//
// Every value defaults to a seeded dev constant; override via env if needed.
import * as msal from '@azure/msal-node';

const ORIGIN = process.env.EMU_ORIGIN ?? 'https://localhost:8443';
const TENANT = process.env.EMU_TENANT ?? '11111111-1111-1111-1111-111111111111';
const CLIENT_ID = process.env.EMU_CLIENT_ID ?? 'cccccccc-0000-0000-0000-000000000002';
const CLIENT_SECRET = process.env.EMU_CLIENT_SECRET ?? 'daemon-app-secret';

const authority = `${ORIGIN}/${TENANT}`;

const cca = new msal.ConfidentialClientApplication({
  auth: {
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authority,
    // The emulator is not a known Microsoft cloud — mark its host known so MSAL
    // skips instance discovery against login.microsoftonline.com.
    knownAuthorities: [new URL(ORIGIN).host],
  },
});

const decode = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));

const { accessToken } = await cca.acquireTokenByClientCredential({
  scopes: ['https://graph.microsoft.com/.default'],
});
const claims = decode(accessToken);
console.log(`✓ token acquired — aud=${claims.aud} appid=${claims.appid} exp=${claims.exp}`);

// Call the emulated Graph with the token. (NODE_EXTRA_CA_CERTS makes fetch
// trust the emulator's self-signed cert too.)
const resp = await fetch(`${ORIGIN}/graph/v1.0/users`, {
  headers: { Authorization: `Bearer ${accessToken}` },
});
const users = await resp.json();
console.log(`✓ GET /graph/v1.0/users → ${resp.status}, ${users.value?.length ?? 0} users:`);
for (const u of users.value ?? []) console.log(`    - ${u.displayName} <${u.userPrincipalName}>`);
