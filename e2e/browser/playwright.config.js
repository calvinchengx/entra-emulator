import { defineConfig, devices } from '@playwright/test';

// The msal-browser witness: a real browser running an unmodified
// @azure/msal-browser against the emulator. globalSetup boots the emulator and
// registers this app's origin as a redirect URI; webServer serves the SPA.
export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.mjs',
  globalTeardown: './global-teardown.mjs',
  timeout: 60_000,
  reporter: 'line',
  forbidOnly: !!process.env.CI,
  // One worker: the specs share a single emulator and a single RP server whose
  // recorded front-channel hits are global. Running them in parallel would let
  // one test's logout land in another's assertions.
  workers: 1,
  fullyParallel: false,
  // The emulator's TLS cert is self-signed, so the browser must accept it —
  // the same trust step a developer makes locally.
  use: {
    baseURL: `http://localhost:${process.env.APP_PORT || 4400}`,
    ignoreHTTPSErrors: true,
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node serve.mjs',
    port: Number(process.env.APP_PORT || 4400),
    reuseExistingServer: !process.env.CI,
  },
});
