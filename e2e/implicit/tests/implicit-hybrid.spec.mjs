import { test, expect } from '@playwright/test';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

const cfg = JSON.parse(readFileSync(new URL('../.e2e-config.json', import.meta.url)));

function jwtPayload(token) {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

function fragmentParams(pageURL) {
  const hash = new URL(pageURL).hash.replace(/^#/, '');
  return new URLSearchParams(hash);
}

function authorizeURL(extra) {
  const auth = new URL(`${cfg.emulator}/${cfg.tenantId}/oauth2/v2.0/authorize`);
  auth.searchParams.set('client_id', cfg.clientId);
  auth.searchParams.set('redirect_uri', cfg.redirectUri);
  auth.searchParams.set('scope', 'openid profile');
  auth.searchParams.set('state', 's1');
  for (const [k, v] of Object.entries(extra)) auth.searchParams.set(k, v);
  return auth.toString();
}

async function pickAlice(page) {
  await page.locator('form button, form input[type=submit]').first().waitFor({ timeout: 10_000 });
  await page.locator('form button, form input[type=submit]').first().click();
}

// The witness: Chromium completing the front-channel implicit and hybrid
// redirects a real SPA would follow. msal-browser never emits these
// response_types, so this is not that harness.
test('implicit delivers a signed id_token in the fragment', async ({ page }) => {
  await page.goto(authorizeURL({ response_type: 'id_token', nonce: 'n1' }));
  await pickAlice(page);
  await page.waitForURL((u) => u.pathname === '/implicit-redirect' && u.hash.includes('id_token'));

  const landed = new URL(page.url());
  expect(landed.search, 'id_token must not arrive on the query string').toBe('');
  const vals = fragmentParams(page.url());
  expect(vals.get('code')).toBeNull();
  expect(vals.get('state')).toBe('s1');

  const claims = jwtPayload(vals.get('id_token'));
  expect(claims.nonce).toBe('n1');
  expect(claims.aud).toBe(cfg.clientId);
  expect(claims.tid).toBe(cfg.tenantId);
  expect(claims.ver).toBe('2.0');
});

test('hybrid delivers a code and an id_token, and the code exchanges', async ({ page }) => {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  await page.goto(authorizeURL({
    response_type: 'code id_token',
    nonce: 'n-hybrid',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }));
  await pickAlice(page);
  await page.waitForURL((u) => u.pathname === '/implicit-redirect' && u.hash.includes('id_token') && u.hash.includes('code='));

  const vals = fragmentParams(page.url());
  const code = vals.get('code');
  expect(code).toBeTruthy();
  expect(jwtPayload(vals.get('id_token')).nonce).toBe('n-hybrid');

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
  expect(token.json.access_token).toBeTruthy();
  expect(jwtPayload(token.json.id_token).tid).toBe(cfg.tenantId);
});

test('discovery advertises code, id_token, and code id_token', async ({ page }) => {
  await page.goto('/health');
  const doc = await page.evaluate(async (tenantId) => {
    const r = await fetch(`/${tenantId}/v2.0/.well-known/openid-configuration`);
    return r.json();
  }, cfg.tenantId);
  expect(doc.response_types_supported).toEqual(expect.arrayContaining(['code', 'id_token', 'code id_token']));
  expect(doc.response_types_supported).not.toContain('id_token token');
});

test('response_mode=query is refused when an id_token would be delivered', async ({ page }) => {
  await page.goto(authorizeURL({
    response_type: 'id_token',
    nonce: 'n1',
    response_mode: 'query',
  }), { waitUntil: 'commit' });
  await page.waitForURL((u) => u.searchParams.get('error') === 'invalid_request');
  expect(new URL(page.url()).hash).toBe('');
});
