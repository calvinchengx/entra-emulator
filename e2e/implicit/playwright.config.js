import { defineConfig, devices } from '@playwright/test';

const EMU_PORT = Number(process.env.EMU_PORT || 18445);

// Chromium completing implicit and hybrid authorize redirects. msal-browser
// cannot do this: it only emits response_type=code.
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
