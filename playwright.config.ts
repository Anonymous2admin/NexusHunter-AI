import { defineConfig, devices } from '@playwright/test';
import fs from 'node:fs';

// Section 7 Sandbox Policy:
// In local environments, Chromium runs with default OS sandboxing enabled.
// Inside Linux containers/Docker/CI environments (where running as root or without user namespaces),
// Chromium requires --no-sandbox to avoid renderer initialization failures.
const isContainerOrCI = !!(
  process.env.CI ||
  process.env.CONTAINER ||
  fs.existsSync('/.dockerenv')
);

const chromiumArgs = isContainerOrCI
  ? [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
    ]
  : [];

export default defineConfig({
  testDir: './tests/browser-e2e',
  timeout: 60 * 1000,
  expect: {
    timeout: 8000,
  },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:3000',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://127.0.0.1:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 60 * 1000,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: chromiumArgs,
        },
      },
    },
  ],
});
