// Stop the emulator globalSetup started. Setup runs a pre-built binary now, so
// the recorded pid IS the server — but the group kill is kept, because it is
// correct either way and cheap, and the previous arrangement (`go run` spawning
// the server as a child) is exactly the shape where killing the recorded pid
// leaves the port held.
import { readFileSync, rmSync } from 'node:fs';

export default async function globalTeardown() {
  const pidFile = new URL('./.e2e-emulator.pid', import.meta.url);
  try {
    const pid = Number(readFileSync(pidFile, 'utf8').trim());
    try { process.kill(-pid, 'SIGTERM'); } catch { process.kill(pid, 'SIGTERM'); }
    rmSync(pidFile, { force: true });
  } catch {}
}
