// Boots the emulator over TLS (MSAL.js refuses a plain-http authority even on
// localhost), then registers the witness app's origin as a redirect URI on the
// seeded public SPA.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, openSync, readFileSync, existsSync } from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const EMU_PORT = Number(process.env.EMU_PORT || 18443);

// The emulator's cert is self-signed. Rather than switch certificate
// validation OFF process-wide (which would also weaken every unrelated request
// this process makes), we TRUST that one certificate: the emulator writes it to
// TLS_CERT_DIR, and setup calls pass it as the CA. Validation stays on, and only
// this cert is accepted. The browser side does the equivalent via
// ignoreHTTPSErrors in playwright.config.js, scoped to the test browser.
const APP_PORT = Number(process.env.APP_PORT || 4400);
const REPO = new URL('../../', import.meta.url).pathname;

// json performs an HTTPS request that validates the emulator's certificate
// against the emulator's OWN cert as the trust anchor.
function json(url, { method = 'GET', body, ca } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(url, {
      method,
      ca,
      headers: body ? { 'Content-Type': 'application/json' } : {},
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({
        status: res.statusCode,
        json: () => (data ? JSON.parse(data) : null),
        text: () => data,
      }));
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function waitFor(url, caPath, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      // The cert only exists once the emulator has generated it.
      const ca = existsSync(caPath) ? readFileSync(caPath) : undefined;
      const r = await json(url, { ca });
      if (r.status === 200) return { body: r.json(), ca };
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
      // Pin the cert location so the CA can be read back for validation.
      TLS_CERT_DIR: join(dir, 'tls'),
    },
    stdio: ['ignore', logFd, logFd],
  });
  proc.unref();
  writeFileSync(new URL('./.e2e-emulator.pid', import.meta.url), String(proc.pid));
  console.log(`emulator pid ${proc.pid}, log ${join(dir, 'emulator.log')}`);

  const caPath = join(dir, 'tls', 'cert.pem');
  const { body: health_body, ca } = await waitFor(`https://localhost:${EMU_PORT}/health`, caPath);

  // Find the seeded PUBLIC client (msal-browser is a public client) rather than
  // hardcoding a GUID the seed may change.
  const apps = (await json(`https://localhost:${EMU_PORT}/admin/api/apps`, { ca })).json();
  const spa = (apps.value || []).find((a) => !a.isConfidential);
  if (!spa) throw new Error('no seeded public client to drive');

  const origin = `http://localhost:${APP_PORT}`;
  const reg = await json(`https://localhost:${EMU_PORT}/admin/api/apps/${spa.id}/redirectUris`, {
    method: 'POST', ca, body: { uri: `${origin}/`, type: 'spa' },
  });
  if (reg.status !== 201 && reg.status !== 409) {
    throw new Error(`could not register redirect URI: ${reg.status} ${reg.text()}`);
  }

  writeFileSync(new URL('./.e2e-config.json', import.meta.url), JSON.stringify({
    emulator: `https://localhost:${EMU_PORT}`,
    app: origin,
    clientId: spa.id,
    tenantId: health_body.tenantId,
  }, null, 2));
}

