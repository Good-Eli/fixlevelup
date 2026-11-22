import { defineConfig } from '@playwright/test';
import { resolve } from 'node:path';

export type LiveCredential = 'P0404_ADMIN_ID' | 'P0404_ADMIN_LOGIN' | 'P0404_ADMIN_PASSWORD' | 'P0404_MANAGER_ID'
  | 'P0404_MANAGER_LOGIN' | 'P0404_MANAGER_PASSWORD' | 'P0404_CITY_ID' | 'P0404_OUTSIDE_CITY_ID' | 'P0404_PROOF_TOKEN';

export default defineConfig({
  testDir: './tests',
  testMatch: 'p0404-live.spec.ts',
  forbidOnly: true,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  globalTimeout: 180_000,
  reporter: './fixtures/p0404/live-reporter.mjs',
  outputDir: resolve(import.meta.dirname, '../../node_modules/.cache/p0404-live-browser'),
  use: { browserName: 'chromium', viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true,
    headless: true, serviceWorkers: 'block', trace: 'off', video: 'off', screenshot: 'off' },
});
