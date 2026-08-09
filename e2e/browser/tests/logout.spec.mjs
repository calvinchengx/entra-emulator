import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

const cfg = JSON.parse(readFileSync(new URL('../.e2e-config.json', import.meta.url)));
const authority = `${cfg.emulator}/${cfg.tenantId}`;

function appURL(extra = {}) {
  const q = new URLSearchParams({ authority, clientId: cfg.clientId, ...extra });
  return `/?${q}`;
}

// Sign in through the emulator's real account picker, the way the sign-in
// witness does. Logout has nothing to prove without a session to end.
async function signIn(page) {
  await page.goto(appURL());
  await expect(page.locator('#status')).toHaveText(/ready|cached|authenticated/, { timeout: 20_000 });
  if ((await page.locator('#status').textContent()) === 'ready') {
    await page.click('#login');
    await page.waitForURL(/oauth2\/v2\.0\/authorize/, { timeout: 20_000 });
    await page.locator('form button, form input[type=submit]').first().waitFor({ timeout: 10_000 });
    await page.locator('form button, form input[type=submit]').first().click();
    await expect(page.locator('#status')).toHaveText('authenticated', { timeout: 20_000 });
  }
}

// RP-initiated logout and front-channel logout, driven by an unmodified
// @azure/msal-browser in a real browser.
//
// The front-channel half is the part only a browser can witness. The emulator
// renders one hidden iframe per signed-into relying party; a server-side test
// can assert the HTML contains that iframe, but not that anything ever fetched
// it. Here the RP endpoint is a real server that records its hits, so the
// assertion is that the browser actually made the call.
test('msal-browser logout ends the session and drives front-channel logout', async ({ page, request }) => {
  page.on('console', (m) => { if (m.type() === 'error') console.log('[browser]', m.text()); });
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));

  await request.delete('/logout-hits');
  await signIn(page);

  // Nothing should have called the RP's logout endpoint yet. Without this the
  // assertion below could be satisfied by a stray hit from signing in.
  expect(await (await request.get('/logout-hits')).json()).toHaveLength(0);

  await page.click('#logout');

  // The emulator honours the registered post_logout_redirect_uri, so the
  // browser ends up on the app's own signed-out page rather than the
  // emulator's default one.
  await page.waitForURL(/\/signed-out\.html$/, { timeout: 20_000 });
  await expect(page.locator('#signed-out')).toBeVisible();

  // The hidden iframe fired: the RP endpoint was fetched with iss and sid.
  const hits = await (await request.get('/logout-hits')).json();
  expect(hits).toHaveLength(1);
  expect(hits[0].iss).toBe(`${cfg.emulator}/${cfg.tenantId}/v2.0`);
  expect(hits[0].sid).toBeTruthy();

  // The SSO session is really gone, not just MSAL's cache. Signing in again has
  // to show the account picker; if the emulator had kept the session it would
  // redirect straight back with a code and this would time out.
  await page.goto(appURL());
  await expect(page.locator('#status')).toHaveText('ready', { timeout: 20_000 });
  await page.click('#login');
  await page.waitForURL(/oauth2\/v2\.0\/authorize/, { timeout: 20_000 });
  await expect(page.locator('form button, form input[type=submit]').first())
    .toBeVisible({ timeout: 10_000 });
});

// An unregistered post_logout_redirect_uri must NOT be honoured. Without this
// the test above would pass against a server that redirected anywhere it was
// told, which is an open redirect rather than a logout endpoint.
test('an unregistered post_logout_redirect_uri is refused', async ({ page }) => {
  await signIn(page);

  const idToken = await page.evaluate(() => window.__msal.getAllAccounts()[0]?.idToken);
  expect(idToken).toBeTruthy();

  const evil = 'http://localhost:9/stolen';
  const q = new URLSearchParams({ post_logout_redirect_uri: evil, id_token_hint: idToken });
  await page.goto(`${cfg.emulator}/${cfg.tenantId}/oauth2/v2.0/logout?${q}`);

  // The emulator renders its own signed-out page instead of redirecting.
  expect(page.url()).not.toContain('localhost:9');
});
