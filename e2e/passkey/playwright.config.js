import { defineConfig, devices } from '@playwright/test';

const EMU_PORT = Number(process.env.EMU_PORT || 18444);

// Chromium on the emulator's own origin, so navigator.credentials pins the
// WebAuthn RP to the same Host the emulator builds per request. The msal-browser
// harness cannot do this: its SPA lives on a different origin.
export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.mjs',
  globalTeardown: './global-teardown.mjs',
  timeout: 60_000,
  reporter: 'line',
  forbidOnly: !!process.env.CI,
  workers: 1,
  use: {
    baseURL: `https://localhost:${EMU_PORT}`,
    ignoreHTTPSErrors: true,
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
