import { test, expect } from '@playwright/test';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

const cfg = JSON.parse(readFileSync(new URL('../.e2e-config.json', import.meta.url)));

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function jwtPayload(token) {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

// The witness: Chromium's own WebAuthn stack (CDP virtual authenticator +
// navigator.credentials) completing register → assert on the emulator origin,
// then an SSO authorize whose ID token carries amr:["fido"]. The Go suite
// drives the same endpoints with descope/virtualwebauthn; this is the browser
// path that suite cannot be.
test('Chromium registers a passkey, asserts it, and the ID token carries amr:["fido"]', async ({ page }) => {
  page.on('console', (m) => { if (m.type() === 'error') console.log('[browser]', m.text()); });
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));

  // Land on the emulator origin first. WebAuthn pins the RP to this page's
  // host, which is also how the emulator builds RPOrigins from Host.
  await page.goto('/health');
  await expect(page.locator('body')).toContainText(cfg.tenantId);

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  const asserted = await page.evaluate(async ({ tenantId, upn }) => {
    const toBuffer = (value) => {
      if (typeof value !== 'string') return value;
      const pad = '='.repeat((4 - (value.length % 4)) % 4);
      const b64 = (value + pad).replace(/-/g, '+').replace(/_/g, '/');
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    };
    const toB64url = (buf) => {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (const b of bytes) s += String.fromCharCode(b);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const credJSON = (cred) => {
      const out = {
        id: cred.id,
        rawId: toB64url(cred.rawId),
        type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults?.() || {},
        response: { clientDataJSON: toB64url(cred.response.clientDataJSON) },
      };
      if (cred.response.attestationObject) {
        out.response.attestationObject = toB64url(cred.response.attestationObject);
      }
      if (cred.response.authenticatorData) {
        out.response.authenticatorData = toB64url(cred.response.authenticatorData);
      }
      if (cred.response.signature) {
        out.response.signature = toB64url(cred.response.signature);
      }
      if (cred.response.userHandle) {
        out.response.userHandle = toB64url(cred.response.userHandle);
      }
      return out;
    };
    const post = async (path, body) => {
      const r = await fetch(path, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const text = await r.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch { /* keep text */ }
      if (!r.ok) throw new Error(`${path}: ${r.status} ${text}`);
      return json;
    };

    const base = `/${tenantId}/webauthn`;
    const creation = await post(`${base}/register/begin`, { upn });
    const created = await navigator.credentials.create({
      publicKey: {
        ...creation.publicKey,
        challenge: toBuffer(creation.publicKey.challenge),
        user: { ...creation.publicKey.user, id: toBuffer(creation.publicKey.user.id) },
        excludeCredentials: (creation.publicKey.excludeCredentials || []).map((c) => ({
          ...c, id: toBuffer(c.id),
        })),
      },
    });
    if (!created) throw new Error('navigator.credentials.create returned null');
    await post(`${base}/register/finish`, credJSON(created));

    const request = await post(`${base}/assert/begin`, { upn });
    const assertedCred = await navigator.credentials.get({
      publicKey: {
        ...request.publicKey,
        challenge: toBuffer(request.publicKey.challenge),
        allowCredentials: (request.publicKey.allowCredentials || []).map((c) => ({
          ...c, id: toBuffer(c.id),
        })),
      },
    });
    if (!assertedCred) throw new Error('navigator.credentials.get returned null');
    return post(`${base}/assert/finish`, credJSON(assertedCred));
  }, { tenantId: cfg.tenantId, upn: cfg.aliceUpn });

  expect(asserted.authenticated).toBe(true);
  expect(asserted.amr).toBe('fido');

  // The assertion set ee_session (SameSite=Lax). A top-level GET /authorize
  // therefore SSO-skips the picker. The redirect URI is on this same origin
  // so the 302 lands where Playwright can read the code from the URL.
  const { verifier, challenge } = pkce();
  const auth = new URL(`${cfg.emulator}/${cfg.tenantId}/oauth2/v2.0/authorize`);
  auth.searchParams.set('client_id', cfg.clientId);
  auth.searchParams.set('response_type', 'code');
  auth.searchParams.set('redirect_uri', cfg.redirectUri);
  auth.searchParams.set('scope', 'openid profile');
  auth.searchParams.set('state', 'pk');
  auth.searchParams.set('code_challenge', challenge);
  auth.searchParams.set('code_challenge_method', 'S256');
  await page.goto(auth.toString(), { waitUntil: 'commit' });
  await page.waitForURL((u) => u.pathname === '/passkey-redirect' && u.searchParams.has('code'));

  const code = new URL(page.url()).searchParams.get('code');
  expect(code).toBeTruthy();

  const token = await page.evaluate(async ({ tenantId, clientId, redirectUri, code, verifier }) => {
    const r = await fetch(`/${tenantId}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }),
    });
    return { status: r.status, json: await r.json() };
  }, {
    tenantId: cfg.tenantId,
    clientId: cfg.clientId,
    redirectUri: cfg.redirectUri,
    code,
    verifier,
  });

  expect(token.status).toBe(200);
  expect(token.json.id_token).toBeTruthy();
  const claims = jwtPayload(token.json.id_token);
  expect(claims.amr).toEqual(['fido']);
  expect(claims.tid).toBe(cfg.tenantId);
  expect(claims.ver).toBe('2.0');
});
