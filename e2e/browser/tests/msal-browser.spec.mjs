import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

const cfg = JSON.parse(readFileSync(new URL('../.e2e-config.json', import.meta.url)));
const authority = `${cfg.emulator}/${cfg.tenantId}`;

function appURL(extra = {}) {
  const q = new URLSearchParams({ authority, clientId: cfg.clientId, ...extra });
  return `/?${q}`;
}

// The witness: an unmodified @azure/msal-browser, in a real browser, completing
// the authorization-code + PKCE redirect flow against the emulator. Everything
// MSAL.js does here — instance discovery, the authorize redirect, PKCE, the
// token exchange, session caching — is exercised as it would be against cloud
// Entra. The hand-written Go tests assert the emulator's side; this asserts
// that a real browser SDK agrees.
test('msal-browser completes the redirect flow and caches the account', async ({ page }) => {
  page.on('console', (m) => { if (m.type() === 'error') console.log('[browser]', m.text()); });
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  await page.goto(appURL());
  await expect(page.locator('#status')).toHaveText('ready');

  // Sign in: MSAL redirects to the emulator's authorize endpoint.
  await page.click('#login');
  await page.waitForURL(/oauth2\/v2\.0\/authorize/, { timeout: 20_000 });

  // The emulator's account picker — a real interactive sign-in page.
  await page.locator('form button, form input[type=submit]').first().waitFor({ timeout: 10_000 });
  await page.locator('form button, form input[type=submit]').first().click();

  // MSAL handles the redirect back, exchanges the code with PKCE, and caches.
  await page.waitForURL((u) => u.port === String(new URL(cfg.app).port), { timeout: 20_000 });
  await expect(page.locator('#status')).toHaveText('authenticated', { timeout: 20_000 });

  // The account and id-token claims came from the emulator, through MSAL.
  await expect(page.locator('#account')).not.toBeEmpty();
  const claims = JSON.parse(await page.locator('#claims').textContent());
  expect(claims.tid).toBe(cfg.tenantId);
  expect(claims.aud).toBe(cfg.clientId);
  expect(claims.ver).toBe('2.0');

  // Reloading finds the cached account rather than signing in again — proof
  // MSAL accepted and stored what the emulator issued.
  await page.goto(appURL());
  await expect(page.locator('#status')).toHaveText(/authenticated|cached/, { timeout: 20_000 });
});
