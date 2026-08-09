// Boots the emulator over plain HTTP on localhost (a browser secure context,
// so crypto.subtle and therefore PKCE work without TLS), then registers the
// witness app's origin as a redirect URI on the seeded public SPA.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, openSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const EMU_PORT = Number(process.env.EMU_PORT || 18443);

// MSAL.js REFUSES a plain-http authority, even on localhost
// (authority_uri_insecure), so the emulator must serve TLS here. Its cert is
// self-signed: Node must accept it for setup calls, and the browser accepts it
// via ignoreHTTPSErrors in playwright.config.js.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const APP_PORT = Number(process.env.APP_PORT || 4400);
const REPO = new URL('../../', import.meta.url).pathname;

async function waitFor(url, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return await r.json();
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`timed out waiting for ${url}`);
}

export default async function globalSetup() {
  const dir = mkdtempSync(join(tmpdir(), 'msal-browser-e2e-'));
  // Log to a file, NOT inherit: an inherited stdout keeps the test runner's
  // pipe open forever, so `playwright test | tail` never terminates. Detach and
  // unref so the emulator never holds the runner alive either.
  const logFd = openSync(join(dir, 'emulator.log'), 'a');
  const proc = spawn('go', ['run', './cmd/entra-emulator'], {
    cwd: REPO,
    detached: true,
    env: {
      ...process.env,
      TLS_ENABLED: 'true',
      ORIGIN_MODE: 'compat',
      PORT: String(EMU_PORT),
      PUBLIC_ORIGIN: `https://localhost:${EMU_PORT}`,
      DB_PATH: join(dir, 'e2e.db'),
    },
    stdio: ['ignore', logFd, logFd],
  });
  proc.unref();
  writeFileSync(new URL('./.e2e-emulator.pid', import.meta.url), String(proc.pid));
  console.log(`emulator pid ${proc.pid}, log ${join(dir, 'emulator.log')}`);

  const health_body = await waitFor(`https://localhost:${EMU_PORT}/health`);

  // Find the seeded PUBLIC client (msal-browser is a public client) rather than
  // hardcoding a GUID the seed may change.
  const apps = await (await fetch(`https://localhost:${EMU_PORT}/admin/api/apps`)).json();
  const spa = (apps.value || []).find((a) => !a.isConfidential);
  if (!spa) throw new Error('no seeded public client to drive');

  const origin = `http://localhost:${APP_PORT}`;
  const reg = await fetch(`https://localhost:${EMU_PORT}/admin/api/apps/${spa.id}/redirectUris`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uri: `${origin}/`, type: 'spa' }),
  });
  if (!reg.ok && reg.status !== 409) {
    throw new Error(`could not register redirect URI: ${reg.status} ${await reg.text()}`);
  }

  writeFileSync(new URL('./.e2e-config.json', import.meta.url), JSON.stringify({
    emulator: `https://localhost:${EMU_PORT}`,
    app: origin,
    clientId: spa.id,
    tenantId: health_body.tenantId,
  }, null, 2));
}

