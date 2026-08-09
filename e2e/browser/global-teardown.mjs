// Stop the emulator globalSetup started. `go run` spawns the built binary as a
// child, so kill the process GROUP (setup detached it to make that possible) —
// killing only the `go run` wrapper would leave the server holding its port.
import { readFileSync, rmSync } from 'node:fs';

export default async function globalTeardown() {
  const pidFile = new URL('./.e2e-emulator.pid', import.meta.url);
  try {
    const pid = Number(readFileSync(pidFile, 'utf8').trim());
    try { process.kill(-pid, 'SIGTERM'); } catch { process.kill(pid, 'SIGTERM'); }
    rmSync(pidFile, { force: true });
  } catch {}
}
