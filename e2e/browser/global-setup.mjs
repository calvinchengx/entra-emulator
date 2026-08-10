// Boots the emulator over TLS (MSAL.js refuses a plain-http authority even on
// localhost), then registers the witness app's origin as a redirect URI on the
// seeded public SPA.
import { spawn, execFileSync } from 'node:child_process';
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

async function waitFor(url, caPath, logPath, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      // The cert only exists once the emulator has generated it.
      const ca = existsSync(caPath) ? readFileSync(caPath) : undefined;
      const r = await json(url, { ca });
      if (r.status === 200) return { body: r.json(), ca };
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  // Print the emulator's own output. Reporting only "timed out" discards the
  // one piece of evidence that says WHY, and sends the next reader to reproduce
  // locally to learn what the runner already knew.
  let tail = '(no log)';
  try { tail = readFileSync(logPath, 'utf8').split('\n').slice(-25).join('\n'); } catch {}
  throw new Error(`timed out waiting for ${url}\n--- emulator log ---\n${tail}`);
}

export default async function globalSetup() {
  const dir = mkdtempSync(join(tmpdir(), 'msal-browser-e2e-'));
  // Log to a file, NOT inherit: an inherited stdout keeps the test runner's
  // pipe open forever, so `playwright test | tail` never terminates. Detach and
  // unref so the emulator never holds the runner alive either.
  const logFd = openSync(join(dir, 'emulator.log'), 'a');

  // BUILD FIRST, then run the binary. `go run` compiles on every start, so the
  // health-check budget below was measuring compilation as well as startup —
  // and a cold runner cache plus a few new dependencies pushed it over, failing
  // a witness that had nothing wrong with it. Building separately makes the
  // wait measure only what it claims to. It also makes teardown reliable:
  // `go run` spawns the real server as a CHILD, so the recorded pid was the
  // wrapper's rather than the server's.
  const bin = join(dir, 'entra-emulator');
  execFileSync('go', ['build', '-o', bin, './cmd/entra-emulator'], {
    cwd: REPO, stdio: ['ignore', logFd, logFd],
  });

  const proc = spawn(bin, [], {
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
  const { body: health_body, ca } = await waitFor(`https://localhost:${EMU_PORT}/health`, caPath, join(dir, 'emulator.log'));

  // Find the seeded PUBLIC client (msal-browser is a public client) rather than
  // hardcoding a GUID the seed may change.
  const apps = (await json(`https://localhost:${EMU_PORT}/admin/api/apps`, { ca })).json();
  const spa = (apps.value || []).find((a) => !a.isConfidential);
  if (!spa) throw new Error('no seeded public client to drive');

  const origin = `http://localhost:${APP_PORT}`;
  // Two redirect URIs: the app itself (type `spa`, which is also what gates
  // token-endpoint CORS) and the post-logout landing page. The emulator
  // validates post_logout_redirect_uri against the app's registered URIs, so
  // an unregistered one is refused — exactly as real Entra refuses it.
  for (const uri of [`${origin}/`, `${origin}/signed-out.html`]) {
    const reg = await json(`https://localhost:${EMU_PORT}/admin/api/apps/${spa.id}/redirectUris`, {
      method: 'POST', ca, body: { uri, type: 'spa' },
    });
    if (reg.status !== 201 && reg.status !== 409) {
      throw new Error(`could not register redirect URI ${uri}: ${reg.status} ${reg.text()}`);
    }
  }

  // Make this app a front-channel logout relying party. The emulator notifies
  // only the apps a session actually signed into, so this URI is fetched by the
  // browser during logout and nowhere else.
  const fc = await json(`https://localhost:${EMU_PORT}/admin/api/apps/${spa.id}`, {
    method: 'PATCH', ca, body: { frontchannelLogoutUri: `${origin}/frontchannel-logout` },
  });
  if (fc.status !== 200 && fc.status !== 204) {
    throw new Error(`could not set frontchannelLogoutUri: ${fc.status} ${fc.text()}`);
  }

  writeFileSync(new URL('./.e2e-config.json', import.meta.url), JSON.stringify({
    emulator: `https://localhost:${EMU_PORT}`,
    app: origin,
    clientId: spa.id,
    tenantId: health_body.tenantId,
  }, null, 2));
}

