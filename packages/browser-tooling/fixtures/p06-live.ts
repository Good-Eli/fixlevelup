import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { request as http } from 'node:http';
import { createServer, request as https } from 'node:https';
import { createRequire } from 'node:module';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium, expect } from '@playwright/test';

const loopback = '127.0.0.1';
const webPort = 4175;
const registryPath = '/crm/requests';
const list = '/api/v1/requests';
const optionsPath = `${list}/filters`;
const browserEndpoint = `ws://${loopback}:4178/p06-registry`;
const web = new URL('../../../apps/web/', import.meta.url);
const next = createRequire(new URL('package.json', web)).resolve('next/dist/bin/next');

interface Fixture {
  readonly origin: string;
  readonly apiPort: number;
  readonly key: Buffer;
  readonly cert: Buffer;
  readonly sessionToken: string;
  readonly publicNumber: string;
}

export async function proveLiveRegistry(fixture: Fixture) {
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1' || process.env['FIXLEVELUP_P06_BROWSER'] !== '1'
    || fixture.origin !== 'https://crm.example.test'
    || (await readFile('/proc/net/dev', 'utf8')).trim().split('\n').slice(2).some(line => !/^\s*lo:/u.test(line))) {
    throw new Error('P06 browser proof requires the isolated loopback lab');
  }

  const child = spawn(process.execPath, [next, 'start', '--hostname', loopback, '--port', String(webPort)], {
    cwd: fileURLToPath(web), stdio: 'ignore',
    env: { PATH: process.env['PATH'], HOME: process.env['HOME'], NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1' },
  });
  const stopped = once(child, 'exit');
  let unexpected = 0;
  const ingress = createServer({ key: fixture.key, cert: fixture.cert }, (req, res) => {
    const path = new URL(req.url ?? '/', fixture.origin).pathname;
    const api = path === list || path === optionsPath;
    if (req.headers.host !== new URL(fixture.origin).host || req.method !== 'GET'
      || (!api && path !== registryPath && !path.startsWith('/_next/static/') && path !== '/favicon.ico')) {
      unexpected++;
      res.writeHead(404).end();
      return;
    }
    const target = { host: loopback, port: api ? fixture.apiPort : webPort, path: req.url, method: req.method, headers: req.headers };
    const forward = (response: import('node:http').IncomingMessage) => {
      res.writeHead(response.statusCode ?? 502, response.headers);
      response.pipe(res);
    };
    const upstream = api ? https({ ...target, ca: fixture.cert, servername: 'localhost' }, forward) : http(target, forward);
    upstream.once('error', () => { if (!res.headersSent) { res.writeHead(502); } res.end(); });
    upstream.setTimeout(10_000, () => upstream.destroy());
    res.once('close', () => upstream.destroy());
    req.pipe(upstream);
  });

  const ready = async () => {
    for (let attempt = 0; attempt < 30 && child.exitCode === null; attempt++) {
      try {
        const response = await fetch(`http://${loopback}:${String(webPort)}${registryPath}`, { signal: AbortSignal.timeout(500) });
        await response.body?.cancel();
        if (response.ok) { return; }
      } catch { /* Next is still starting. */ }
      await delay(250);
    }
    throw new Error('Production Next registry page did not start');
  };

  let browser: Awaited<ReturnType<typeof chromium.connect>> | undefined;
  try {
    await ready();
    ingress.listen(443, loopback);
    await once(ingress, 'listening');
    browser = await chromium.connect(browserEndpoint, { timeout: 10_000 });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    try {
      const page = await context.newPage();
      page.setDefaultTimeout(10_000);
      const pageUrl = `${fixture.origin}${registryPath}`;
      const heading = page.getByRole('heading', { name: 'Реестр заявок' });
      const result = page.getByRole('region', { name: 'Заявки' });
      const row = result.getByRole('row').filter({ hasText: fixture.publicNumber });
      const consoleErrors: Error[] = [];
      page.on('pageerror', error => consoleErrors.push(error));
      const byPath = (path: string) => page.waitForResponse(response => new URL(response.url()).pathname === path);

      const [anonymous] = await Promise.all([byPath(list), page.goto(pageUrl)]);
      expect(anonymous.status()).toBe(401);
      await expect(heading).toBeVisible();
      await expect(result.getByRole('alert')).toContainText('Войдите в CRM');
      await expect(row).toHaveCount(0);

      // The existing real staff login fixture has already created this session.
      await context.addCookies([{ name: '__Host-fixlevelup_session', value: fixture.sessionToken,
        url: fixture.origin, secure: true, httpOnly: true, sameSite: 'Strict' }]);
      const [listed, choices] = await Promise.all([byPath(list), byPath(optionsPath), page.reload()]);
      expect(listed.status()).toBe(200);
      expect(choices.status()).toBe(200);
      expect(listed.headers()['cache-control']).toMatch(/^no-store\b/u);
      expect(choices.headers()['cache-control']).toMatch(/^no-store\b/u);
      await expect(row).toContainText('Ремонт');
      await expect(result).not.toContainText('Synthetic intake sentinel');
      await expect(result).not.toContainText('+15550100001');

      const category = page.getByRole('combobox', { name: 'Тип техники', exact: true });
      const district = page.getByRole('combobox', { name: 'Район', exact: true });
      const source = page.getByRole('combobox', { name: 'Источник', exact: true });
      await expect(category.getByRole('option', { name: 'Synthetic category' })).toHaveCount(1);
      await expect(district.getByRole('option', { name: 'Synthetic district' })).toHaveCount(1);
      await expect(source.getByRole('option', { name: 'Synthetic REQUEST_SOURCE' })).toHaveCount(1);
      await expect(page.getByText('Фильтры по мастеру, оплате и проблемам пока недоступны.')).toBeVisible();
      const apply = page.getByRole('button', { name: 'Применить' });
      const categoryId = await category.selectOption({ label: 'Synthetic category' });
      const districtId = await district.selectOption({ label: 'Synthetic district' });
      const sourceId = await source.selectOption({ label: 'Synthetic REQUEST_SOURCE' });
      const [filtered] = await Promise.all([byPath(list), apply.click()]);
      const query = new URL(filtered.url()).searchParams;
      expect(query.get('categoryId')).toBe(categoryId[0]);
      expect(query.get('districtId')).toBe(districtId[0]);
      expect(query.get('sourceId')).toBe(sourceId[0]);
      await expect(row).toBeVisible();

      await page.getByLabel('Создана с (UTC)').fill('2099-01-01T00:00');
      const [empty] = await Promise.all([byPath(list), apply.click()]);
      expect(new URL(empty.url()).searchParams.get('from')).toBe('2099-01-01T00:00:00.000Z');
      await expect(result.getByRole('status')).toHaveText('Заявок по выбранным фильтрам нет.');
      await expect(row).toHaveCount(0);

      await page.getByRole('button', { name: 'Сбросить' }).click();
      await expect(row).toBeVisible();
      await expect(category).toHaveValue('');
      await expect(district).toHaveValue('');
      await expect(source).toHaveValue('');
      expect(consoleErrors).toHaveLength(0);
      expect(unexpected).toBe(0);
    } finally {
      await context.close();
    }
  } finally {
    await browser?.close();
    ingress.closeAllConnections();
    ingress.close();
    child.kill();
    await stopped;
  }
}
