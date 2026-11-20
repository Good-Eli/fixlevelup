import { expect, test, type Page, type Response } from '@playwright/test';

const webOrigin = 'http://127.0.0.1:4170';
const miniappOrigin = 'http://127.0.0.1:4171';
const allowedOrigins = new Set([webOrigin, miniappOrigin]);

// Keep diagnostics free of URL paths, query strings, credentials and error text.
function requestOrigin(rawUrl: string): string {
  try {
    return new URL(rawUrl).origin;
  } catch {
    return 'invalid-origin';
  }
}

async function instrumentPage(page: Page) {
  const unexpectedOrigins: string[] = [];
  const failedRequestOrigins: string[] = [];
  const unsuccessfulResponses: { origin: string; status: number }[] = [];
  const unsuccessfulJavaScriptResponses: { origin: string; status: number }[] = [];
  let pageErrors = 0;
  let consoleErrors = 0;
  let successfulJavaScriptResponses = 0;

  page.on('pageerror', () => { pageErrors += 1; });
  page.on('console', (message) => {
    if (message.type() === 'error') {consoleErrors += 1;}
  });
  page.on('requestfailed', (request) => {
    failedRequestOrigins.push(requestOrigin(request.url()));
  });
  page.on('response', (response) => {
    const url = new URL(response.url());
    const diagnostic = { origin: url.origin, status: response.status() };
    if (response.status() >= 400) {unsuccessfulResponses.push(diagnostic);}
    // URL.pathname also recognizes Next assets served with a query string.
    if (response.request().resourceType() === 'script' && url.pathname.endsWith('.js')) {
      if (response.ok()) {successfulJavaScriptResponses += 1;}
      else {unsuccessfulJavaScriptResponses.push(diagnostic);}
    }
  });

  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (allowedOrigins.has(url.origin) || url.protocol === 'data:' || url.protocol === 'blob:') {
      await route.continue();
      return;
    }
    unexpectedOrigins.push(url.origin);
    await route.abort('blockedbyclient');
  });

  return {
    assertClean() {
      expect(unexpectedOrigins, 'Unexpected network origins').toEqual([]);
      expect(failedRequestOrigins, 'Failed request origins').toEqual([]);
      expect(unsuccessfulResponses, 'Unsuccessful HTTP responses').toEqual([]);
      expect(unsuccessfulJavaScriptResponses, 'Unsuccessful JavaScript responses').toEqual([]);
      expect(pageErrors, 'Uncaught browser errors (messages omitted)').toBe(0);
      expect(consoleErrors, 'Browser console errors (messages omitted)').toBe(0);
      expect(successfulJavaScriptResponses, 'Successful production JavaScript assets').toBeGreaterThan(0);
    },
  };
}

async function assertDocument(page: Page, title: string) {
  await expect(page).toHaveTitle(title);
  await expect(page.locator('html')).toHaveAttribute('lang', 'ru');
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute('content', /\bnoindex\b/i);
  await expect(page.locator('meta[name="viewport"]')).toHaveAttribute(
    'content', /\bwidth\s*=\s*device-width\b/i,
  );
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(title);
  await expect(page.locator('form, input, textarea, select, button, a, [role="button"], [role="link"]'))
    .toHaveCount(0);

  // String evaluation avoids adding DOM libraries to the Node tooling tsconfig.
  const hasHorizontalOverflow = await page.evaluate<boolean>(
    'Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) > document.documentElement.clientWidth',
  );
  expect(hasHorizontalOverflow, 'The technical page fits the configured desktop or mobile viewport').toBe(false);
}

function assertNavigation(response: Response | null) {
  expect(response !== null, 'A navigation document response is available').toBe(true);
  if (!response) {throw new Error('Missing navigation document response');}
  expect(response.status(), 'Production document HTTP status').toBe(200);
  expect(response.headers()['x-robots-tag']).toMatch(/\bnoindex\b/i);
  return response;
}

test('web production technical foundation', async ({ page }, testInfo) => {
  const instrumentation = await instrumentPage(page);
  const response = assertNavigation(await page.goto(`${webOrigin}/`, { waitUntil: 'networkidle' }));
  expect(response.headers()['x-powered-by'], 'Web does not expose a powered-by header').toBeUndefined();

  await assertDocument(page, 'Техническая проверка web');
  await expect(page.locator('main p')).toHaveText(
    'Сборочный стенд P01-01.3. Клиентские функции и CRM ещё не реализованы.',
  );
  const output = page.getByTestId('web-foundation');
  await expect(output).toBeVisible();
  await expect(output).toHaveText('web-foundation-ok');
  const initialOutput = await output.textContent();
  instrumentation.assertClean();

  const reloaded = assertNavigation(await page.reload({ waitUntil: 'networkidle' }));
  expect(reloaded.headers()['x-powered-by']).toBeUndefined();
  await assertDocument(page, 'Техническая проверка web');
  await expect(output).toBeVisible();
  await expect(output).toHaveText(initialOutput ?? 'web-foundation-ok');
  await page.screenshot({ path: testInfo.outputPath('web.png'), fullPage: true, animations: 'disabled' });
  instrumentation.assertClean();
});

test('Mini App production JavaScript mount', async ({ page }, testInfo) => {
  const instrumentation = await instrumentPage(page);
  const response = assertNavigation(await page.goto(`${miniappOrigin}/`, { waitUntil: 'networkidle' }));
  const shell = await response.text();
  // The navigation document is an empty shell; these nodes must be mounted by JavaScript.
  expect(/<div\b[^>]*\bid=["']root["'][^>]*>\s*<\/div>/i.test(shell), 'Mini App starts with an empty root').toBe(true);
  expect(shell.includes('miniapp-foundation-ok'), 'The output is absent from the original HTML shell').toBe(false);
  expect(shell.includes('<h1'), 'The heading is absent from the original HTML shell').toBe(false);
  expect(await page.evaluate<boolean>('document.querySelector(\'script[type="module"][src]\') !== null'),
    'The built document loads a JavaScript module').toBe(true);

  await assertDocument(page, 'Техническая проверка Mini App');
  await expect(page.locator('#root > main > h1')).toHaveText('Техническая проверка Mini App');
  await expect(page.locator('#root main p')).toHaveText(
    'Сборочный стенд P01-01.4. Telegram и рабочие функции мастера ещё не подключены.',
  );
  const output = page.locator('#root').getByTestId('miniapp-foundation');
  await expect(output).toBeVisible();
  await expect(output).toHaveText('miniapp-foundation-ok');
  const initialOutput = await output.textContent();
  instrumentation.assertClean();

  assertNavigation(await page.reload({ waitUntil: 'networkidle' }));
  await assertDocument(page, 'Техническая проверка Mini App');
  await expect(page.locator('#root > main > h1')).toHaveText('Техническая проверка Mini App');
  await expect(output).toBeVisible();
  await expect(output).toHaveText(initialOutput ?? 'miniapp-foundation-ok');
  await page.screenshot({ path: testInfo.outputPath('miniapp.png'), fullPage: true, animations: 'disabled' });
  instrumentation.assertClean();
});
