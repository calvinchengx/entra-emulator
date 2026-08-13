// Boots the emulator over TLS on localhost so Chromium treats the origin as a
// secure context and the WebAuthn RP ID is `localhost` — the same Host-derived
// RP the emulator builds per request.
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, openSync, readFileSync, existsSync } from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const EMU_PORT = Number(process.env.EMU_PORT || 18444);
const REPO = new URL('../../', import.meta.url).pathname;

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
      const ca = existsSync(caPath) ? readFileSync(caPath) : undefined;
      const r = await json(url, { ca });
      if (r.status === 200) return { body: r.json(), ca };
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  let tail = '(no log)';
  try { tail = readFileSync(logPath, 'utf8').split('\n').slice(-25).join('\n'); } catch {}
  throw new Error(`timed out waiting for ${url}\n--- emulator log ---\n${tail}`);
}

export default async function globalSetup() {
  const dir = mkdtempSync(join(tmpdir(), 'passkey-e2e-'));
  const logFd = openSync(join(dir, 'emulator.log'), 'a');
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
      TLS_CERT_DIR: join(dir, 'tls'),
    },
    stdio: ['ignore', logFd, logFd],
  });
  proc.unref();
  writeFileSync(new URL('./.e2e-emulator.pid', import.meta.url), String(proc.pid));
  console.log(`emulator pid ${proc.pid}, log ${join(dir, 'emulator.log')}`);

  const caPath = join(dir, 'tls', 'cert.pem');
  const { body: health } = await waitFor(
    `https://localhost:${EMU_PORT}/health`, caPath, join(dir, 'emulator.log'));

  const ca = readFileSync(caPath);
  const apps = (await json(`https://localhost:${EMU_PORT}/admin/api/apps`, { ca })).json();
  const spa = (apps.value || []).find((a) => !a.isConfidential);
  if (!spa) throw new Error('no seeded public client to drive SSO after passkey sign-in');

  // Stay on the emulator origin so the authorize 302 is a same-host navigation
  // we can read. The seeded https://localhost:3000 URI has nothing listening.
  const redirectUri = `https://localhost:${EMU_PORT}/passkey-redirect`;
  const reg = await json(`https://localhost:${EMU_PORT}/admin/api/apps/${spa.id}/redirectUris`, {
    method: 'POST', ca, body: { uri: redirectUri, type: 'spa' },
  });
  if (reg.status !== 201 && reg.status !== 409) {
    throw new Error(`could not register redirect URI ${redirectUri}: ${reg.status} ${reg.text()}`);
  }

  writeFileSync(new URL('./.e2e-config.json', import.meta.url), JSON.stringify({
    emulator: `https://localhost:${EMU_PORT}`,
    clientId: spa.id,
    tenantId: health.tenantId,
    redirectUri,
    aliceUpn: 'alice@entraemulator.dev',
  }, null, 2));
}
