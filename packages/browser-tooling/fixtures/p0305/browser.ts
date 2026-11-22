import { expect, type BrowserContext, type Page } from '@playwright/test';

export const mockOrigin = 'http://127.0.0.1:4170';
export const liveOrigin = 'https://127.0.0.1:4176';
export const apiPrefix = '/api/v1';
export function allowedAsset(path: string): boolean {
  return path === '/crm/access' || path === '/favicon.ico' || path.startsWith('/_next/static/');
}

/** Dialog text is never logged; tests separately verify the semantic confirmation. */
export function decide(page: Page, accept: boolean): Promise<string> {
  return new Promise(resolve => page.once('dialog', async dialog => {
    const message = dialog.message();
    if (accept) { await dialog.accept(); } else { await dialog.dismiss(); }
    resolve(message);
  }));
}

export async function signIn(page: Page, origin: string, credentials: { login: string; password: string }) {
  await page.goto(`${origin}/crm/access`);
  await page.getByLabel('Логин', { exact: true }).fill(credentials.login);
  await page.getByLabel('Пароль', { exact: true }).fill(credentials.password);
  await page.getByRole('button', { name: 'Войти', exact: true }).press('Enter');
}

export async function noOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
}

export async function confineLive(context: BrowserContext, events: string[]) {
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin === liveOrigin && (url.pathname.startsWith(`${apiPrefix}/`) || allowedAsset(url.pathname))) {
      await route.continue();
    } else {
      events.push('unapproved live browser request');
      await route.abort();
    }
  });
}
