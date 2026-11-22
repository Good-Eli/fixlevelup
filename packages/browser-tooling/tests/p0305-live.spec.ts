import { randomUUID } from 'node:crypto';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import type { LiveCredential } from '../playwright.p0305.config.js';
import { apiPrefix, confineLive, decide, liveOrigin, signIn } from '../fixtures/p0305/browser.js';

function config(name: LiveCredential): string {
  const value = process.env[name];
  if (!value) { throw new Error('Isolated live fixture unavailable'); }
  return value;
}

async function assertCookie(context: BrowserContext) {
  const cookie = (await context.cookies(liveOrigin)).find(value => value.name === '__Host-fixlevelup_session');
  // Boolean assertion so no browser cookie can be serialized by a failure.
  expect(Boolean(cookie?.secure && cookie.httpOnly && cookie.sameSite === 'Strict' && cookie.domain === '127.0.0.1' && cookie.path === '/')).toBe(true);
}

const legal = `${apiPrefix}/legal/documents`;
const publication = { title: 'Проверка синтетической версии', body: 'Не юридический документ. '.repeat(600),
  sourceRef: 'synthetic-browser-source', legalBasis: 'synthetic-browser-basis' };

async function publish(page: Page) {
  await page.getByRole('button', { name: 'Документы', exact: true }).click();
  await page.getByRole('button', { name: 'REQUEST_PROCESSING', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Загрузить список', exact: true })).toHaveCount(1);
  await page.getByLabel('Вид документа').selectOption('CONSENT_FORM');
  const creation = page.waitForResponse(r => new URL(r.url()).pathname === legal && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Создать документ', exact: true }).click();
  expect((await creation).status()).toBe(201); console.log('Live checkpoint: legal create status 201');
  await page.getByRole('button', { name: 'Загрузить список', exact: true }).click();
  await page.getByRole('button', { name: 'CONSENT_FORM', exact: true }).click(); console.log('Live checkpoint: exact legal card selected');
  await page.getByLabel('Заголовок', { exact: true }).fill(publication.title);
  await page.getByLabel('Текст документа', { exact: true }).fill(publication.body);
  await page.getByLabel('Источник', { exact: true }).fill(publication.sourceRef);
  await page.getByLabel('Правовое основание', { exact: true }).fill(publication.legalBasis);
  const response = page.waitForResponse(r => new URL(r.url()).pathname.startsWith(`${legal}/`) && r.url().endsWith('/publish') && r.request().method() === 'POST');
  const accepted = decide(page, true);
  await page.getByRole('button', { name: 'Опубликовать новую версию', exact: true }).click();
  await accepted;
  const receipt = await response;
  expect(receipt.status()).toBe(201);
  expect(receipt.headers()['cache-control']).toBe('no-store');
  const { data } = await receipt.json() as { data: { id: string; revisionId: string; version: number; revisionVersion: number } };
  expect(Object.keys(data).sort()).toEqual(['id', 'revisionId', 'revisionVersion', 'version']);
  expect(receipt.headers()['etag']).toBe(`"p03-v${String(data.version)}"`);
  const key = receipt.request().headers()['idempotency-key'];
  expect(Boolean(key && /^[a-f0-9-]{36}$/.test(key))).toBe(true);
  return { ...data, key };
}

// Registration is independent of default technical/P02/P03 UI runs. Explicit -c
// config plus the disposable runner must provision runtime credentials first.
if (process.env['P0305_LIVE'] === '1') {
  test('real HTTPS browser: administrator publishes, PostgreSQL proves actor and evidence, manager POST is forbidden', async ({ page, browser }) => {
    const unexpected: string[] = [];
    await test.step('admin login and cookie', async () => {
      await confineLive(page.context(), unexpected);
      await signIn(page, liveOrigin, { login: config('P0305_ADMIN_LOGIN'), password: config('P0305_ADMIN_PASSWORD') });
      await expect(page.getByRole('button', { name: 'Документы', exact: true })).toBeVisible();
      await assertCookie(page.context());
    });
    const receipt = await test.step('CRM legal form publication', () => publish(page));
    async function assertEvidence() {
      const response = await fetch('http://127.0.0.1:4177/proof', {
        method: 'POST', headers: { authorization: `Bearer ${config('P0305_PROOF_TOKEN')}`, 'content-type': 'application/json' },
        body: JSON.stringify({ ...receipt, ...publication }), signal: AbortSignal.timeout(5000),
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ versions: 1, receipts: 1, audits: 1, events: 1, exact: true });
    }
    await test.step('PostgreSQL publication evidence', assertEvidence);
    await test.step('manager login and direct authorization', async () => {
      const manager = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: 'block' });
      try {
      await confineLive(manager, unexpected);
      const managerPage = await manager.newPage();
      const loggedIn = managerPage.waitForResponse(r => r.url() === `${liveOrigin}${apiPrefix}/auth/login` && r.request().method() === 'POST');
      await signIn(managerPage, liveOrigin, { login: config('P0305_MANAGER_LOGIN'), password: config('P0305_MANAGER_PASSWORD') });
      expect((await loggedIn).status()).toBe(200);
      await assertCookie(manager);
      const outcome = await managerPage.evaluate(async ({ target, candidate, payload, key, version }) => {
        const me = await fetch('/api/v1/auth/me', { headers: { 'x-auth-request': '1' }, cache: 'no-store' });
        const { data } = await me.json() as { data?: { staffId: string; csrfToken: string } };
        if (me.status !== 200 || data?.staffId !== candidate || !data.csrfToken) { return { verified: false }; }
        const denied = await fetch(target, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json',
          'x-csrf-token': data.csrfToken, 'idempotency-key': key, 'if-match': `"p03-v${String(version)}"` }, body: JSON.stringify(payload) });
        return { verified: true, status: denied.status, cache: denied.headers.get('cache-control') };
      }, { target: `${legal}/${receipt.id}/publish`, candidate: config('P0305_MANAGER_ID'), payload: publication,
        key: randomUUID(), version: receipt.version });
      expect(outcome).toEqual({ verified: true, status: 403, cache: 'no-store' });
      await expect(managerPage.getByRole('button', { name: 'Документы', exact: true })).toHaveCount(0);
      } finally { await manager.close(); }
    });
    await test.step('PostgreSQL denied-write isolation', assertEvidence);
    expect(unexpected).toEqual([]);
  });
}
