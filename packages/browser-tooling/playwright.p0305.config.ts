import { defineConfig } from '@playwright/test';
import { resolve } from 'node:path';

export type LiveCredential = 'P0305_ADMIN_LOGIN' | 'P0305_ADMIN_PASSWORD' | 'P0305_MANAGER_LOGIN' | 'P0305_MANAGER_PASSWORD' | 'P0305_MANAGER_ID' | 'P0305_PROOF_TOKEN';

export default defineConfig({
  testDir: './tests',
  testMatch: 'p0305-live.spec.ts',
  forbidOnly: true,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: './fixtures/p0305/live-reporter.mjs',
  outputDir: resolve(import.meta.dirname, '../../node_modules/.cache/p0305-live-browser'),
  use: { browserName: 'chromium', viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true,
    headless: true, serviceWorkers: 'block', trace: 'off', video: 'off', screenshot: 'off' },
});
