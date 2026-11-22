import { randomUUID } from 'node:crypto';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import type { LiveCredential } from '../playwright.p0404.config.js';
import { apiPrefix, confineLive, decide, liveOrigin, noOverflow, signIn } from '../fixtures/p0305/browser.js';

function config(name: LiveCredential): string {
  const value = process.env[name];
  if (!value) { throw new Error('Disposable P04 browser fixture is not available'); }
  return value;
}
const click = (page: Page, name: string) => page.getByRole('button', { name, exact: true }).click();
const fill = (page: Page, name: string, value: string) => page.getByLabel(name, { exact: true }).fill(value);
const confirmed = /Операция подтверждена сервером/;
const maxMinor = '9223372036854775807';
const items = '/catalog/items';
const partCode = 'live-part';
const partTitle = 'Синтетическая запчасть QA';
const districtTitle = 'Синтетический район QA';
const areaCode = 'live-area';
const areaTitle = 'Синтетическая зона QA';
const faqCode = 'live-faq';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

type Receipt = { id: string; key: string; version: number };
type Revision = Receipt & { revisionId: string; revisionVersion: number };
type Write = (Revision & { kind: 'item'|'faq'; actor: 'admin' })
  | (Revision & { kind: 'price'; actor: 'manager'; itemId: string })
  | (Receipt & { kind: 'district'; actor: 'admin' })
  | (Receipt & { kind: 'coverage'; actor: 'admin'; areaId: string; districtId: string })
  | (Receipt & { kind: 'contact'; actor: 'admin'; revisionId: string });

async function command(page: Page, route: string, label: string, options: {
  status?: number; method?: 'POST' | 'PUT'; confirm?: boolean; revision?: boolean; family?: 'p04' | 'p03' | 'geo';
} = {}): Promise<Receipt | Revision> {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === apiPrefix + route
    && response.request().method() === (options.method ?? 'POST'), { timeout: 12_000 });
  const accepted = options.confirm ? decide(page, true) : undefined;
  const [response] = await Promise.all([pending, click(page, label), accepted]);
  expect(response.status()).toBe(options.status ?? 201);
  expect(response.headers()['cache-control']).toBe('no-store');
  const { data } = await response.json() as { data: Omit<Revision,'key'> };
  expect(Object.keys(data).sort()).toEqual(options.revision ? ['id','revisionId','revisionVersion','version'] : ['id','version']);
  const key = response.request().headers()['idempotency-key'];
  expect(Boolean(key && uuid.test(key) && uuid.test(data.id))).toBe(true);
  if (!key) { throw new Error('Missing command proof'); }
  expect(response.headers()['etag']).toBe(`"${options.family ?? 'geo'}-v${String(data.version)}"`);
  await expect(page.getByRole('status').filter({ hasText: confirmed })).toBeVisible();
  return { ...data, key };
}
function revision(receipt: Receipt | Revision): Revision {
  if (!('revisionId' in receipt) || !uuid.test(receipt.revisionId) || !Number.isSafeInteger(receipt.revisionVersion)) {
    throw new Error('Missing exact publication proof');
  }
  return receipt;
}
async function assertCookie(context: BrowserContext) {
  const cookie = (await context.cookies(liveOrigin)).find(value => value.name === '__Host-fixlevelup_session');
  expect(Boolean(cookie?.secure && cookie.httpOnly && cookie.sameSite === 'Strict' && cookie.path === '/' && cookie.domain === '127.0.0.1')).toBe(true);
}

async function part(page: Page): Promise<Revision> {
  await click(page, 'Каталог компании');
  await click(page, 'Запчасти (PART)');
  const create = page.getByRole('group', { name: 'Новая позиция · Запчасти (PART)', exact: true });
  await create.getByLabel('Код', { exact: true }).fill(partCode);
  await create.getByLabel('Единица измерения', { exact: true }).fill('piece');
  const draft = await command(page, items, 'Создать позицию', { family: 'p04' });
  await click(page, 'Запчасти (PART)'); await click(page, 'Загрузить запчасти'); await click(page, partCode);
  await expect(page.getByLabel('Длительность, мин', { exact: true })).toHaveCount(0);
  await fill(page, 'Название', partTitle);
  await page.getByLabel('Видна мастеру', { exact: true }).check();
  const result = revision(await command(page, `${items}/${draft.id}/versions`, 'Опубликовать версию', { family: 'p04', revision: true }));
  expect(result.id === draft.id && result.version === 2).toBe(true);
  return result;
}

async function geography(page: Page, city: string): Promise<Write[]> {
  const base = `/settings/service-cities/${city}`;
  async function openCity() { await click(page, 'Загрузить города'); await click(page, 'p04-primary'); }
  await click(page, 'Районы, зоны и контакты'); await openCity(); await click(page, 'Районы');
  const districtForm = page.getByRole('group', { name: 'Новый район', exact: true });
  await districtForm.getByLabel('Код', { exact: true }).fill('live-district');
  await districtForm.getByLabel('Название района', { exact: true }).fill(districtTitle);
  const district = await command(page, `${base}/administrative-districts`, 'Создать район');
  await openCity(); await click(page, 'Зоны обслуживания');
  await page.getByRole('group', { name: 'Новая зона', exact: true }).getByLabel('Код', { exact: true }).fill(areaCode);
  const area = await command(page, `${base}/service-areas`, 'Создать зону');
  await openCity(); await click(page, 'Зоны обслуживания'); await click(page, 'Загрузить зоны'); await click(page, areaCode);
  const versions = `${base}/service-areas/${area.id}/versions`;
  await fill(page, 'Название зоны', areaTitle);
  const draft = await command(page, versions, 'Создать черновик зоны');
  async function openAreaDraft() {
    await openCity(); await click(page, 'Зоны обслуживания'); await click(page, 'Загрузить зоны'); await click(page, areaCode);
    await click(page, 'История зоны'); await click(page, `${areaTitle} · версия 1`);
  }
  await openAreaDraft();
  await click(page, 'Загрузить полное покрытие'); await click(page, 'Загрузить районы для покрытия'); await click(page, districtTitle);
  await page.getByRole('group', { name: `Покрытие: ${districtTitle}`, exact: true }).getByRole('combobox').selectOption('FULL');
  await click(page, 'Применить к полному набору');
  const coverage = await command(page, `${versions}/${draft.id}/district-coverage`, 'Сохранить полное покрытие', { method: 'PUT', confirm: true, status: 200 });
  await openAreaDraft(); await click(page, 'Перечитать черновик и покрытие');
  await command(page, `${versions}/${draft.id}/publish`, 'Опубликовать зону', { confirm: true, status: 200 });
  await openCity(); await fill(page, 'Публичный контакт', '+70000000001');
  const contactRevision = await command(page, `${base}/versions`, 'Создать версию города');
  await openCity(); await click(page, 'История города'); await click(page, 'Версия города 2');
  const contact = await command(page, `${base}/versions/${contactRevision.id}/publish`, 'Опубликовать версию города', { confirm: true, status: 200 });
  expect(contact.id === city).toBe(true);
  await openCity(); await expect(page.getByText('+70000000001', { exact: true })).toBeVisible();
  return [{ ...district, kind: 'district', actor: 'admin' }, { ...coverage, kind: 'coverage', actor: 'admin', areaId: area.id, districtId: district.id },
    { ...contact, kind: 'contact', actor: 'admin', revisionId: contactRevision.id }];
}

async function faq(page: Page): Promise<Revision> {
  await click(page, 'Каталог компании'); await click(page, 'FAQ и публикации CRM');
  await page.getByRole('group', { name: 'Новый блок контента', exact: true }).getByRole('combobox').selectOption('FAQ');
  await fill(page, 'Код блока', faqCode);
  const block = await command(page, '/content/blocks', 'Создать блок', { family: 'p03' });
  await click(page, 'Загрузить список'); await click(page, `FAQ · ${faqCode}`);
  await fill(page, 'Заголовок', 'Синтетический вопрос QA');
  await fill(page, 'Текст публикации', 'Синтетический ответ для проверки внутреннего FAQ.'); await fill(page, 'Источник', 'synthetic-browser-proof');
  return revision(await command(page, `/content/blocks/${block.id}/publish`, 'Опубликовать новую версию', { confirm: true, revision: true, family: 'p03' }));
}

async function price(page: Page, cityId: string, itemId: string, validFrom: string): Promise<Revision> {
  const path = `/pricing/cities/${cityId}/items/${itemId}/price-versions`;
  const workspace = () => page.getByRole('region', { name: 'Городские цены и тарифы', exact: true });
  async function stream() {
    await click(page, 'Загрузить города');
    const picker = workspace().getByLabel('Город', { exact: true });
    await expect(picker).toBeEnabled(); await expect(picker).toHaveValue('');
    await expect(picker.locator('option')).toHaveCount(2);
    await picker.selectOption(cityId);
    await click(page, 'Фиксированные цены'); await click(page, 'Загрузить позиции города');
    await workspace().getByLabel('Позиция', { exact: true }).selectOption(itemId);
    await click(page, 'Загрузить историю версий');
  }
  await click(page, 'Городские цены и тарифы'); await stream();
  await fill(page, 'Сумма (минорные единицы)', maxMinor); await fill(page, 'Валюта', 'RUB');
  await fill(page, 'Начало действия (UTC)', validFrom); await fill(page, 'Источник', 'synthetic-price-proof');
  const made = revision(await command(page, path, 'Опубликовать цену', { confirm: true, family: 'p04', revision: true }));
  await stream();
  await workspace().getByLabel('Версия', { exact: true }).selectOption(made.revisionId);
  await expect(workspace().getByText(`${maxMinor} RUB`, { exact: false }).filter({ hasText: 'synthetic-price-proof' })).toBeVisible();
  await noOverflow(page);
  return made;
}

type Proof = { readonly writes: Record<string,{ rows: number; receipts: number; audits: number; outbox: number; exact: boolean }>;
  readonly counts: Record<string, number>; readonly deniedReceipts: number };
async function evidence(writes: readonly Write[], deniedKeys: readonly string[]) {
  const response = await fetch('http://127.0.0.1:4177/proof', { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
    headers: { authorization: `Bearer ${config('P0404_PROOF_TOKEN')}`, 'content-type': 'application/json' }, body: JSON.stringify({ writes, deniedKeys }) });
  expect(response.status).toBe(200);
  return await response.json() as Proof;
}

if (process.env['P0404_LIVE'] === '1') {
  test('production HTTPS: staff P04 and canonical P03 forms persist exact evidence; wrong scope changes nothing', async ({ page, browser }) => {
    const blocked: string[] = [];
    const cityId = config('P0404_CITY_ID');
    const outside = config('P0404_OUTSIDE_CITY_ID');
    const validFrom = new Date(Date.now() + 7_200_000).toISOString();
    page.setDefaultTimeout(10_000);
    const item = await test.step('real login and PART publication', async () => {
      await confineLive(page.context(), blocked);
      await signIn(page, liveOrigin, { login: config('P0404_ADMIN_LOGIN'), password: config('P0404_ADMIN_PASSWORD') });
      const made = await part(page); await assertCookie(page.context()); return made;
    });
    const geo = await test.step('canonical P03 district, zone, coverage and contact', () => geography(page, cityId));
    const publishedFaq = await test.step('canonical P03 FAQ publication', () => faq(page));
    const writes: Write[] = [{ ...item, kind: 'item', actor: 'admin' }, ...geo, { ...publishedFaq, kind: 'faq', actor: 'admin' }];
    const managerContext = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: 'block' });
    try {
      await confineLive(managerContext, blocked);
      const manager = await managerContext.newPage();
      await signIn(manager, liveOrigin, { login: config('P0404_MANAGER_LOGIN'), password: config('P0404_MANAGER_PASSWORD') });
      await expect(manager.getByRole('button', { name: 'Городские цены и тарифы', exact: true })).toBeVisible();
      for (const tab of ['Каталог компании','Определения тарифов','Авито: ручные записи','Города и зоны','Контент']) {
        await expect(manager.getByRole('button', { name: tab, exact: true })).toHaveCount(0);
      }
      await assertCookie(managerContext);
      const fixed = await price(manager, cityId, item.id, validFrom);
      writes.push({ ...fixed, kind: 'price', actor: 'manager', itemId: item.id });
      const deniedKeys = [randomUUID(), randomUUID()];
      const before = await evidence(writes, deniedKeys);
      expect(Object.keys(before.writes).sort()).toEqual(['contact','coverage','district','faq','item','price']);
      for (const row of Object.values(before.writes)) { expect(row).toEqual({ rows: 1, receipts: 1, audits: 1, outbox: 1, exact: true }); }
      expect(before.deniedReceipts).toBe(0);
      const refusal = await manager.evaluate(async args => {
        const me = await fetch('/api/v1/auth/me', { headers: { 'x-auth-request': '1' }, cache: 'no-store' });
        const { data } = await me.json() as { data?: { staffId: string; csrfToken: string } };
        if (me.status !== 200 || data?.staffId !== args.staffId || !data.csrfToken) { return []; }
        const pricePath = `/api/v1/pricing/cities/${args.outside}/items/${args.itemId}/price-versions`;
        const commands = [
          { path: pricePath, key: args.keys[0] ?? '', tag: '"p04-v0"', body: { amountMinor: args.amountMinor, currency: 'RUB', sourceRef: 'denied-fixture', validFrom: args.validFrom } },
          { path: '/api/v1/catalog/items', key: args.keys[1] ?? '', tag: undefined, body: { kind: 'PART', code: 'denied-company-catalog', unit: 'piece' } },
        ];
        return await Promise.all(commands.map(async command => {
          const response = await fetch(command.path, { method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
            headers: { 'x-csrf-token': data.csrfToken, 'idempotency-key': command.key, 'content-type': 'application/json',
              ...(command.tag ? { 'if-match': command.tag } : {}) }, body: JSON.stringify(command.body) });
          await response.body?.cancel();
          return { status: response.status, private: response.headers.get('cache-control') === 'no-store' };
        }));
      }, { itemId: item.id, outside, staffId: config('P0404_MANAGER_ID'), keys: deniedKeys, amountMinor: maxMinor, validFrom });
      expect(refusal).toEqual([{ status: 404, private: true }, { status: 403, private: true }]);
      expect(await evidence(writes, deniedKeys)).toEqual(before);
      expect(blocked).toEqual([]);
    } finally { await managerContext.close(); }
  });
}
