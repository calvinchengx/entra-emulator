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
