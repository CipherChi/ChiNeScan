import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  outputDir: './test-results',
  globalSetup: './e2e/global-setup.ts',
  timeout: 90_000,
  expect: { timeout: 8_000 },
  use: {
    ...devices['Desktop Chrome'],
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
  projects: [
    { name: 'chromium-production', testMatch: ['dashboard.spec.ts', 'projects.spec.ts', 'github-import.spec.ts', 'system-status.spec.ts'] },
    {
      name: 'chromium-operator-recovery',
      testMatch: 'operator-recovery.spec.ts',
      use: { ...devices['Desktop Chrome'], trace: 'off', screenshot: 'off' },
    },
    { name: 'chromium-session-expiry', testMatch: 'session-expiry.spec.ts' },
  ],
});
