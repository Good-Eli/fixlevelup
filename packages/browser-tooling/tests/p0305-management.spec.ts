import { expect, test, type Page } from '@playwright/test';
import { P03_REFERENCE_TYPES } from '../../p03-contracts/src/policy.js';
import { P03_COMPANY_FIELDS } from '../../p03-contracts/src/wire.js';
import { decide, noOverflow } from '../fixtures/p0305/browser.js';
import { arrange, adminGrants, geoGrants, id, list, rejected, timestamp, uuid, wire, type Hit } from '../fixtures/p0305/mock.js';

// Production UI with a strict, synthetic browser intercept. These are not server authorization proofs.
test.use({ serviceWorkers: 'block', trace: 'off', screenshot: 'off', video: 'off' });
const button = (page: Page, name: string) => page.getByRole('button', { name, exact: true });
const click = (page: Page, name: string) => button(page, name).click();
const status = (page: Page, message: RegExp) => expect(page.getByRole('status').filter({ hasText: message })).toBeVisible();
const json = (hit: Hit | undefined): unknown => JSON.parse(hit?.body ?? 'null') as unknown;
function command(hit: Hit | undefined, version?: number, family = 'p03') {
  expect(hit?.key).toMatch(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  expect(hit?.tag).toBe(version === undefined ? undefined : `"${family}-v${String(version)}"`);
}
async function confirm(page: Page, name: string, yes = true) { const dialog = decide(page, yes); await click(page, name); return dialog; }
const success = /Операция подтверждена сервером/;
const retry = 'Проверить / повторить';
const company = '/settings/versions';
const names = ['Название оператора','Регистрационный идентификатор оператора','Адрес оператора','Источник юридической проверки','Источник политики безопасности','Источник политики хранения','Источник политики загрузки'];
const emptyCompany = Object.fromEntries(P03_COMPANY_FIELDS.map(k => [k, null]));

test('company empty state, exact history, seven named values and explicit versioned publish', async ({ page }) => {
  const s = await arrange(page);
  let current = 0;
  s.handlers.push((route, h) => {
    if (h.method === 'GET' && h.path === company) {
      return wire(route, { ...list(current ? [{ id: id.item, version: 2, publishedAt: timestamp }, { id: uuid(41), version: 1, publishedAt: timestamp }] : []), version: current });
    }
    if (h.method === 'GET' && /^\/settings\/versions\/[12]$/.test(h.path)) {
      const version = Number(h.path.at(-1));
      return wire(route, { id: version === 2 ? id.item : uuid(41), version, publishedAt: timestamp,
        launchMode: 'SINGLE_CITY', primaryCityId: id.city, reviewedBy: id.actor, settings: emptyCompany });
    }
    if (h.method === 'POST' && h.path === company) { return wire(route, { id: id.revision, version: 3 }, 201); }
  });
  await s.signIn(); await click(page, 'Настройки и справочники'); await click(page, 'Загрузить настройки');
  await expect(page.getByText(/Первая версия появится при активации города/)).toBeVisible();
  await expect(button(page, 'Редактировать настройки')).toHaveCount(0);
  current = 2;
  await click(page, 'Обновить список'); await click(page, 'Версия 1');
  await expect(page.getByRole('heading', { name: 'Версия 1 · история' })).toBeVisible();
  await expect(button(page, 'Редактировать настройки')).toHaveCount(0);
  await click(page, 'Версия 2'); await click(page, 'Редактировать настройки');
  await expect(page.getByText('Не задано', { exact: true })).toHaveCount(7);
  await button(page, 'Опубликовать настройки').press('Enter');
  expect(s.hitsFor('POST', company)).toHaveLength(0);
  for (const [i, name] of names.entries()) { await page.getByRole('textbox', { name, exact: true }).fill(`Synthetic ${String(i)}`); }
  expect(await confirm(page, 'Опубликовать настройки', false)).toContain('новую версию');
  expect(s.hitsFor('POST', company)).toHaveLength(0);
  await confirm(page, 'Опубликовать настройки'); await status(page, success);
  const [h] = s.hitsFor('POST', company);
  command(h, 2); expect(json(h)).toEqual(Object.fromEntries(P03_COMPANY_FIELDS.map((k,i) => [k, `Synthetic ${String(i)}`])));
  await noOverflow(page); s.done();
});

const refs = '/settings/references';
const refLabels = ['Интервалы обратного звонка','Способы оплаты','Причины отмены','Причины отказа','Источники заявки'];
const picker = '/settings/management/cities';
const city = { id: id.city, version: 3, code: 'synthetic-city', status: 'ACTIVE', currentVersionId: id.cityVersion };

test('five explicit reference types, company/archive history and callback city timezone publication', async ({ page }) => {
  const s = await arrange(page);
  const cb = `${refs}/callback_interval`;
  const pay = `${refs}/payment_method`;
  const payment = { id: uuid(22), version: 2, type: 'PAYMENT_METHOD', scope: 'COMPANY', cityId: null,
    code: 'synthetic-payment', currentVersionId: uuid(23), archivedAt: null as string | null };
  const interval = { id: id.item, version: 2, type: 'CALLBACK_INTERVAL', scope: 'CITY', cityId: city.id,
    code: 'synthetic-interval', currentVersionId: id.revision, archivedAt: null };
  const payHistory = `${pay}/${payment.id}/versions`;
  const cbHistory = `${cb}/${interval.id}/versions`;
  const summary = { id: uuid(23), entryId: payment.id, version: 1, label: 'Проверка оплаты', publishedAt: timestamp };
  s.handlers.push((route, h) => {
    if (h.method === 'GET' && h.path === picker && h.url.searchParams.get('domain') === 'callback_interval') { return wire(route, list([city])); }
    if (h.method === 'GET' && h.path === `${picker}/${id.city}/versions`) { return wire(route, { ...list([{ id: id.cityVersion, sequence: 1, timezone: 'Asia/Yekaterinburg', published: true }]), version: 3 }); }
    if (h.method === 'GET' && h.path === cb && h.url.searchParams.get('cityId') === id.city) { return wire(route, list([interval])); }
    if (h.method === 'GET' && h.path === `${cb}/${interval.id}` && h.url.searchParams.get('cityId') === id.city) { return wire(route, interval); }
    if (h.method === 'POST' && h.path === cbHistory && h.url.searchParams.get('cityId') === id.city) { return wire(route, { id: interval.id, version: 3, revisionId: id.revision, revisionVersion: 2 }, 201); }
    if (h.method === 'GET' && h.path === `${pay}/${payment.id}` && !h.url.searchParams.has('cityId')) { return wire(route, payment); }
    if (h.method === 'GET' && h.path === payHistory) { return wire(route, { ...list([summary]), version: payment.version }); }
    if (h.method === 'GET' && h.path === `${payHistory}/${summary.id}`) { return wire(route, { ...summary, type: payment.type, cityId: null, sourceRef: 'synthetic-exact-ref',
      validFrom: timestamp, validUntil: null, provenanceCityVersionId: null, interval: null }); }
    if (h.method === 'POST' && h.path === `${pay}/${payment.id}/archive`) { payment.archivedAt = timestamp; return wire(route, { id: payment.id, version: ++payment.version }); }
    if (h.method === 'GET' && h.path === pay && h.url.searchParams.get('includeArchived') === 'true' && !h.url.searchParams.has('cityId')) { return wire(route, list([payment])); }
    if (h.method === 'GET' && ['/cancel_reason','/decline_reason','/request_source'].some(x => h.path === `${refs}${x}`) && !h.url.searchParams.has('cityId')) { return wire(route, list([])); }
  });
  await s.signIn(); await click(page, 'Настройки и справочники');
  expect(Object.keys(P03_REFERENCE_TYPES)).toHaveLength(refLabels.length);
  for (const label of refLabels.slice(2)) {
    await click(page, label); await click(page, 'Загрузить список'); await expect(page.getByText('Нет доступных записей.')).toBeVisible();
  }
  await click(page, 'Способы оплаты'); await click(page, 'Загрузить список'); await click(page, payment.code);
  await confirm(page, 'Архивировать запись'); await status(page, success);
  command(s.hitsFor('POST', `${pay}/${payment.id}/archive`)[0], 2);
  await click(page, 'Способы оплаты'); await click(page, 'Загрузить список'); await click(page, payment.code);
  await expect(button(page, 'Архивировать запись')).toHaveCount(0);
  await click(page, 'История справочника'); await click(page, 'Проверка оплаты · версия 1');
  await expect(page.getByText('synthetic-exact-ref', { exact: true })).toBeVisible();
  await click(page, 'Интервалы обратного звонка'); await expect(button(page, 'Загрузить список')).toHaveCount(0);
  await click(page, 'Загрузить города'); await click(page, city.code); await click(page, 'Загрузить список'); await click(page, interval.code);
  await click(page, 'Загрузить версии города'); await click(page, '1 · Asia/Yekaterinburg');
  await page.getByLabel('Название записи', { exact: true }).fill('Тест интервала');
  await page.getByLabel('Источник', { exact: true }).fill('synthetic-callback');
  await page.getByLabel('Начало действия (ISO 8601 с зоной)', { exact: true }).fill(timestamp);
  await page.getByLabel('Начало интервала', { exact: true }).fill('60'); await page.getByLabel('Конец интервала', { exact: true }).fill('120');
  await confirm(page, 'Опубликовать новую версию'); await status(page, success);
  const [h] = s.hitsFor('POST', cbHistory);
  command(h, 2); expect(json(h)).toEqual({ label: 'Тест интервала', sourceRef: 'synthetic-callback', validFrom: timestamp, validUntil: null,
    cityVersionId: id.cityVersion, interval: { startMinute: 60, endMinute: 120 } });
  await noOverflow(page); s.done();
});

const content = '/content/blocks';
const block = { id: id.item, version: 2, code: 'synthetic-faq', kind: 'FAQ', scope: 'COMPANY', cityId: null,
  allowCompanyFallback: false, currentRevisionId: id.revision, archivedAt: null };
const contentCard = `${content}/${id.item}`;
const pub = `${contentCard}/publish`;
const summary = { id: id.revision, blockId: id.item, version: 1, title: 'Синтетическая история', publishedAt: timestamp };
const scriptText = `<script>window.p0305Executed = true</script><img src="https://example.invalid/p0305" onerror="window.p0305Executed = true">`;
function contentMock(s: Awaited<ReturnType<typeof arrange>>) {
  s.handlers.push((route,h) => {
    if (h.method !== 'GET') { return; }
    if (h.path === content && h.url.searchParams.get('scope') === 'COMPANY') { return wire(route, list([block])); }
    if (h.path === contentCard) { return wire(route, block); }
    if (h.path === `${contentCard}/revisions`) { return wire(route, { ...list([summary]), version: 2 }); }
    if (h.path === `${contentCard}/revisions/${id.revision}`) { return wire(route, { ...summary, body: scriptText, sourceRef: 'synthetic-exact-content' }); }
  });
}
async function contentEditor(page: Page) {
  await click(page, 'Контент'); await click(page, 'Загрузить список'); await click(page, 'FAQ · synthetic-faq');
  await page.getByLabel('Заголовок', { exact: true }).fill('Синтетическая публикация');
  await page.getByLabel('Текст публикации', { exact: true }).fill(scriptText);
  await page.getByLabel('Источник', { exact: true }).fill('synthetic-test');
}

test('FAQ/FACT/SEO, plain-text exact preview on demand, mutation and archive guards', async ({ page }) => {
  const s = await arrange(page); contentMock(s);
  let archived = false;
  s.handlers.unshift((route,h) => {
    if (h.method === 'POST' && h.path === `${contentCard}/archive`) { archived = true; return wire(route, { id: id.item, version: 3 }); }
    if (h.method === 'GET' && archived && h.path === contentCard) { return wire(route, { ...block, version: 3, archivedAt: timestamp }); }
  });
  await s.signIn(); await contentEditor(page);
  await expect(page.getByLabel('Тип контента').locator('option')).toHaveText(['FAQ', 'FACT', 'SEO']);
  await click(page, 'История публикаций');
  expect(s.hitsFor('GET', `${contentCard}/revisions/${id.revision}`)).toHaveLength(0);
  await expect(page.locator('pre')).toHaveCount(0);
  await click(page, 'Синтетическая история · версия 1');
  await expect(page.locator('pre')).toHaveText(scriptText);
  expect(await page.evaluate(() => Reflect.has(window,'p0305Executed'))).toBe(false);
  await expect(page.locator('pre img, pre script')).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  await noOverflow(page);
  await confirm(page, 'Архивировать блок'); await status(page, success);
  await click(page, 'Загрузить список'); await click(page, 'FAQ · synthetic-faq');
  await expect(page.getByRole('heading', { name: 'synthetic-faq · FAQ · архив' })).toBeVisible();
  await expect(button(page, 'Опубликовать новую версию')).toHaveCount(0);
  command(s.hitsFor('POST', `${contentCard}/archive`)[0], 2); s.done();
});

for (const cause of ['network', 'malformed-200', '500'] as const) {
  test(`publication ${cause}: no automatic retry, explicit identical I/body/V`, async ({ page }) => {
    const s = await arrange(page); contentMock(s);
    let calls = 0;
    s.handlers.push((route,h) => {
      if (h.method !== 'POST' || h.path !== pub) { return; }
      if (++calls === 1) {
        if (cause === 'network') { return route.abort('failed'); }
        if (cause === 'malformed-200') { return route.fulfill({ status: 200, body: '{' }); }
        return rejected(route, 500);
      }
      return wire(route, { id: id.item, version: 3, revisionId: id.revision, revisionVersion: 2 }, 201);
    });
    await s.signIn(); await contentEditor(page); await confirm(page,'Опубликовать новую версию');
    await status(page, /Результат операции не подтверждён/);
    await expect(page.getByLabel('Текст публикации')).toHaveCount(0);
    expect(s.hitsFor('POST', pub)).toHaveLength(1);
    await button(page, retry).press('Enter'); await status(page, success);
    const rows = s.hitsFor('POST', pub);
    expect(rows).toHaveLength(2);
    const [first, second] = rows;
    command(first, 2);
    expect([second?.key, second?.tag, second?.body]).toEqual([first?.key, first?.tag, first?.body]);
    s.done();
  });
}

for (const kind of ['changed-generation','refresh-failure','stale-412','revoked-403'] as const) {
  test(`publication ${kind}: clears stale editor and never sends another write`, async ({ page }) => {
    const s = await arrange(page); contentMock(s);
    s.handlers.push((route,h) => {
      if (h.method !== 'POST' || h.path !== pub) { return; }
      if (kind === 'changed-generation') { return rejected(route, 500); }
      if (kind === 'stale-412') { return rejected(route, 412); }
      if (kind === 'revoked-403') { s.access.p03Permissions = s.access.p03Permissions.filter(g => !g.code.startsWith('content.')); return rejected(route, 403); }
      s.faults.access = true;
      return wire(route, { id: id.item, version: 3, revisionId: id.revision, revisionVersion: 2 }, 201);
    });
    await s.signIn(); await contentEditor(page); await confirm(page, 'Опубликовать новую версию');
    if (kind === 'changed-generation') {
      await status(page, /Результат операции не подтверждён/);
      s.identity.authVersion++;
      await click(page, retry); await status(page, /Рабочая сессия изменилась/);
    } else if (kind === 'refresh-failure') { await status(page, /не отправляйте операцию повторно/); }
    else if (kind === 'stale-412') { await status(page, /изменилась|версия/i); }
    else { await status(page, /прав|доступ/i); await expect(button(page, 'Контент')).toHaveCount(0); }
    await expect(button(page, retry)).toHaveCount(0); await expect(page.getByLabel('Текст публикации')).toHaveCount(0);
    expect(s.hitsFor('POST', pub)).toHaveLength(1); s.done();
  });
}

const legal = '/legal/documents';
test('legal purposes and kinds, summary/exact separation, UTF-8 limit and explicit publish', async ({ page }) => {
  const s = await arrange(page);
  const doc = { id: id.item, version: 2, purpose: 'MARKETING', kind: 'OPT_IN_NOTICE', currentVersionId: id.revision };
  const document = `${legal}/${doc.id}`;
  const history = `${document}/versions`;
  const rev = { id: id.revision, documentId: doc.id, sequence: 1, title: 'История документа QA', publishedAt: timestamp, checksum: 'a'.repeat(64) };
  const exact = `${history}/${rev.id}`;
  s.handlers.push((route,h) => {
    if (h.method === 'GET' && h.path === legal && h.url.searchParams.get('purpose') === 'MARKETING') { return wire(route, list([doc])); }
    if (h.method === 'POST' && h.path === legal) { return wire(route, { id:doc.id, version:1 }, 201); }
    if (h.method === 'GET' && h.path === document) { return wire(route, doc); }
    if (h.method === 'GET' && h.path === history) { return wire(route, { ...list([rev]), version: 2 }); }
    if (h.method === 'GET' && h.path === exact) { return wire(route, { ...rev, kind: doc.kind, purpose: doc.purpose, body: 'Синтетический точный текст', reviewedBy: id.actor, legalBasis: 'synthetic-old-basis', sourceRef: 'synthetic-old-source' }); }
    if (h.method === 'POST' && h.path === `${document}/publish`) { return wire(route, { id: doc.id, version: 3, revisionId: uuid(30), revisionVersion: 2 }, 201); }
  });
  await s.signIn(); await click(page, 'Документы');
  await expect(button(page, 'REQUEST_PROCESSING')).toBeVisible(); await expect(button(page, 'ADDRESS_COVERAGE')).toHaveCount(0);
  await expect(page.getByLabel('Вид документа').locator('option')).toHaveText(['POLICY','CONSENT_FORM','OPT_IN_NOTICE']);
  await click(page, 'MARKETING');
  await expect(button(page, 'Загрузить список')).toHaveCount(1);
  await expect(button(page, 'Создать документ')).toHaveCount(1);
  await page.getByLabel('Вид документа').selectOption('OPT_IN_NOTICE'); await click(page, 'Создать документ'); await status(page,success);
  const [created] = s.hitsFor('POST',legal); command(created); expect(json(created)).toEqual({ purpose:'MARKETING', kind:'OPT_IN_NOTICE' });
  await click(page,'MARKETING'); await click(page, 'Загрузить список'); await click(page, 'OPT_IN_NOTICE');
  await click(page, 'История документа');
  expect(s.hitsFor('GET', exact)).toHaveLength(0); await expect(page.locator('pre')).toHaveCount(0);
  await click(page, 'История документа QA · версия 1');
  await expect(page.locator('pre')).toHaveText('Синтетический точный текст');
  await expect(page.getByText(rev.checksum, { exact: true })).toBeVisible();
  await page.getByLabel('Заголовок', { exact: true }).fill('Документ QA');
  await page.getByLabel('Правовое основание', { exact: true }).fill('synthetic-basis');
  await page.getByLabel('Источник', { exact: true }).fill('synthetic-source');
  const body = page.getByLabel('Текст документа', { exact: true });
  // A control character is inflated to six JSON bytes, below the form's character bound.
  // Set from the browser's native textarea setter without embedding any secret or endpoint.
  await body.evaluate(e => { (e as HTMLTextAreaElement).value = '\u0001'.repeat(176_000); });
  await confirm(page,'Опубликовать новую версию'); await status(page,/UTF-8/);
  expect(s.hitsFor('POST',`${document}/publish`)).toHaveLength(0);
  const validBody = 'Проверка UTF-8 ©. '.repeat(1700);
  await body.fill(validBody);
  await confirm(page,'Опубликовать новую версию'); await status(page,success);
  const [h] = s.hitsFor('POST',`${document}/publish`);
  command(h, 2); expect(Buffer.byteLength(h?.body ?? '', 'utf8')).toBeGreaterThan(4096);
  expect(json(h)).toEqual({ title: 'Документ QA', legalBasis: 'synthetic-basis', sourceRef: 'synthetic-source', body: validBody });
  s.done();
});

test('manager operational readiness and city-scoped content; no full read, no publish grants', async ({ page }) => {
  const s = await arrange(page, { manager: true, standard: [],
    geo: [{ code: 'geography.read', scope: 'CITY' }],
    grants: [{ code: 'settings.readiness.read', scope: 'GLOBAL' }, { code: 'settings.fullread', scope: 'GLOBAL' },
      { code: 'legal.read', scope: 'GLOBAL' }, { code: 'content.read', scope: 'CITY' }, { code: 'content.manage', scope: 'CITY' }] });
  const scoped = { ...block, scope: 'CITY', cityId: id.city };
  s.handlers.push((route,h) => {
    if (h.method !== 'GET') { return; }
    if (h.path === '/settings/readiness') { return wire(route, { ...list([{ id: id.city, name: 'Свой тестовый город', status: 'MISSING', missing: ['CITY_INACTIVE'] }]),
      sections: [{ section: 'COMPANY_SETTINGS', status: 'MISSING', missing: ['COMPANY_VERSION_MISSING'] }, { section: 'REQUEST_PROCESSING', status: 'CONFIGURED', missing: [] },
        { section: 'P04', status: 'NOT_IMPLEMENTED', missing: [] }, { section: 'PRODUCTION', status: 'NOT_ASSESSED', missing: [] }] }); }
    if (h.path === picker && h.url.searchParams.get('domain') === 'content') { return wire(route, list([city])); }
    if (h.path === content && h.url.searchParams.get('scope') === 'CITY' && h.url.searchParams.get('cityId') === id.city) { return wire(route, list([scoped])); }
    if (h.path === contentCard) { return wire(route, scoped); }
  });
  await s.signIn(); await click(page, 'Готовность'); await click(page, 'Проверить готовность');
  await expect(page.getByText('PRODUCTION: NOT_ASSESSED')).toBeVisible();
  await expect(page.getByText('Свой тестовый город: MISSING · CITY_INACTIVE')).toBeVisible();
  await expect(button(page, 'Документы')).toHaveCount(0); await expect(button(page, 'Настройки и справочники')).toHaveCount(0);
  await expect(page.getByText(/primaryCityId|operatorAddress|legalBasis|policyRef/)).toHaveCount(0);
  await click(page, 'Контент'); await expect(button(page, 'Компания')).toHaveCount(0);
  await click(page, 'Загрузить города'); await click(page, city.code); await click(page, 'Загрузить список'); await click(page, 'FAQ · synthetic-faq');
  await expect(button(page, 'Создать блок')).toBeVisible(); await expect(button(page, 'Архивировать блок')).toBeVisible(); await expect(button(page, 'Опубликовать новую версию')).toHaveCount(0);
  expect(s.hits.some(h => h.path.startsWith(legal) || h.path.startsWith(company))).toBe(false); await noOverflow(page); s.done();
});

test('P03 role editor enforces stored scope; role grants survive separately confirmed founder revoke', async ({ page }) => {
  const s = await arrange(page);
  const code = 'content.read';
  const bootstrap = '/settings/management/bootstrap';
  const revoke = `${bootstrap}/${id.actor}/${code}/revoke`;
  let granted = false; let revoked = false;
  s.handlers.push((route,h) => {
    if (h.path === `/roles/${id.adminRole}/permissions` && h.method === 'PUT') { granted = true; return wire(route, { id: id.adminRole, version: 3 }); }
    if (h.path === `/roles/${id.managerRole}/permissions` && h.method === 'PUT') { return wire(route, { id: id.managerRole, version: 3 }); }
    if (h.path === bootstrap && h.method === 'GET') { return wire(route, list(revoked ? [] : [{ assignmentId: id.bootstrap, staffId: id.actor, code, version: 1 }])); }
    if (h.path === revoke && h.method === 'POST') {
      revoked = true;
      s.access.p03Permissions = adminGrants.filter(g => g.code !== code || granted);
      return wire(route, { id: id.bootstrap, version: 2 });
    }
  });
  await s.signIn(); await click(page, 'Роли и возможности'); await click(page, 'Менеджер · MANAGER · системная');
  const grant = page.getByRole('checkbox', { name: /content\.read/ });
  await expect(grant).toBeEnabled(); await grant.check(); await expect(page.getByLabel(`Область ${code}`)).toHaveCount(0);
  await expect(page.getByRole('checkbox', { name: /legal\.manage/ })).toBeDisabled();
  const cityWarning = await confirm(page,'Сохранить возможности',false);
  expect(cityWarning).toMatch(/CITY/);
  expect(cityWarning).toMatch(/все нынешние и будущие сотрудники/i);
  expect(cityWarning).toMatch(/назначенн[^.]*город/i);
  expect(s.hitsFor('PUT',`/roles/${id.managerRole}/permissions`)).toHaveLength(0);
  await click(page, 'Мастер · TECHNICIAN · системная'); await expect(grant).toBeDisabled();
  await click(page,'Администратор · ADMIN · системная'); await grant.check();
  const scope = page.getByLabel(`Область ${code}`);
  await expect(scope.locator('option')).toHaveText(['CITY','GLOBAL']); await scope.selectOption('GLOBAL');
  await expect(page.getByText(/все нынешние и будущие сотрудники/)).toBeVisible();
  expect(await confirm(page,'Сохранить возможности')).toContain('все нынешние и будущие сотрудники');
  await status(page,/Возможности роли обновлены/);
  const roleWrites = s.hitsFor('PUT',`/roles/${id.adminRole}/permissions`);
  expect(roleWrites).toHaveLength(1); expect(roleWrites[0]?.tag).toBe('"role-v2"');
  expect(json(roleWrites[0])).toEqual({ permissions: [{ code, scope: 'GLOBAL' }] });
  await click(page,'Личные права'); await click(page,'Загрузить личные права');
  const action = `Отозвать личное право ${code}`;
  expect(await confirm(page,action,false)).toMatch(/необратимо/i);
  expect(s.hitsFor('POST',revoke)).toHaveLength(0);
  expect(await confirm(page,action)).toContain('Права ролей останутся без изменений'); await status(page,success);
  const [h] = s.hitsFor('POST',revoke); command(h,1); expect(json(h)).toEqual({});
  await click(page,'Загрузить личные права'); await expect(button(page,action)).toHaveCount(0);
  await expect(button(page,'Контент')).toBeVisible(); s.done();
});

const geo = '/settings/service-cities';
const cityPath = `${geo}/${id.city}`;
const districtPath = `${cityPath}/administrative-districts`;
const cityHistory = `${cityPath}/versions`;
const cityRevision = { id: id.cityVersion, sequence: 2, displayName: 'Тестовый локальный город', addressDisplay: null,
  timezone: 'Asia/Yekaterinburg', publicContact: 'synthetic-contact', officeHours: [[[540, 720]], [], [], [], [], [], []], publishedAt: timestamp };
const cityRow = { id: id.city, code: 'synthetic-city', version: 3, lifecycle: 'ACTIVE', currentVersionId: id.cityVersion };
function cities(s: Awaited<ReturnType<typeof arrange>>) {
  s.handlers.push((route,h) => {
    if (h.method !== 'GET') { return; }
    if (h.path === geo) { return wire(route, list([cityRow])); }
    if (h.path === cityPath) { return wire(route, { ...cityRow, currentVersion: cityRevision }); }
    if (h.path === cityHistory) { return wire(route, { ...list([cityRevision, { ...cityRevision, id: uuid(34), sequence: 1, timezone: 'Europe/Moscow' }]), version: 3 }); }
  });
}
async function openCity(page: Page) { await click(page,'Города и зоны'); await click(page,'Загрузить города'); await click(page,cityRow.code); }

test('city local version, exact history and publication action; scoped administrative and technician forms', async ({ page }) => {
  const s = await arrange(page, { geo: geoGrants,
    standard: ['roles.read','roles.permissions.manage','staff.read','staff.role.assign'] });
  cities(s);
  const technicianId = uuid(60), assignmentId = uuid(61);
  const techs = `${cityPath}/technicians`;
  const membership = `${techs}/${technicianId}/city-memberships`;
  const assignments = `${cityPath}/administrators/${id.manager}/assignments`;
  let assigned = false;
  s.handlers.push((route,h) => {
    if (h.method === 'GET' && h.path === '/staff') { return wire(route, list([{ id: id.manager, role: 'MANAGER', roleId: id.managerRole, roleName: 'Менеджер', employmentState: 'ACTIVE', displayName: 'Синтетический менеджер', version: 0 }])); }
    if (h.method === 'POST' && h.path === cityHistory) { return wire(route, { id: uuid(37), version: 4 }, 201); }
    if (h.method === 'POST' && h.path === `${cityHistory}/${uuid(34)}/publish`) { return wire(route, { id: id.city, version: 4 }); }
    if (h.method === 'GET' && h.path === techs) { return wire(route, list([{ id: technicianId, displayName: 'Тестовый мастер своего города', version: 0 }])); }
    if (h.method === 'GET' && [membership, `${techs}/${technicianId}/service-area-grants`].includes(h.path)) { return wire(route, { ...list([]), version: 0 }); }
    if (h.method === 'POST' && h.path === membership) { return wire(route, { id: uuid(65), version: 1 }, 201); }
    if (h.method === 'GET' && h.path === assignments) { return wire(route, { ...list(assigned ? [{ id: assignmentId, cityId: id.city, staffId: id.manager, revokedAt: null, grantedAt: timestamp, active: true }] : []), version: assigned ? 1 : 0 }); }
    if (h.method === 'POST' && h.path === assignments) { assigned = true; return wire(route, { id: assignmentId, version: 1 }, 201); }
    if (h.method === 'POST' && h.path === `${assignments}/${assignmentId}/revoke`) { assigned = false; return wire(route, { id: assignmentId, version: 2 }); }
  });
  await s.signIn(); await openCity(page); await click(page,'История города'); await click(page,'Версия города 1');
  await expect(page.getByText('Europe/Moscow', { exact: true })).toBeVisible();
  await expect(button(page, 'Создать черновик города')).toBeVisible();
  await expect(button(page, 'Сделать основным')).toBeVisible(); await expect(button(page, 'Деактивировать город')).toBeVisible();
  await confirm(page,'Опубликовать версию города'); await status(page,success);
  command(s.hitsFor('POST',`${cityHistory}/${uuid(34)}/publish`)[0],3,'geo');
  await click(page,'Загрузить города'); await click(page,cityRow.code);
  await page.getByLabel('Название города', { exact: true }).fill('Тестовый город 2');
  await page.getByLabel('Понедельник', { exact: true }).fill('10:30–12:00');
  await click(page,'Создать версию города'); await status(page,success);
  const [created] = s.hitsFor('POST',cityHistory); command(created,3,'geo');
  expect(json(created)).toEqual({ displayName: 'Тестовый город 2', addressDisplay: null, timezone: cityRevision.timezone,
    publicContact: cityRevision.publicContact, officeHours: [[[630,720]],[],[],[],[],[],[]] });
  await click(page,'Загрузить города'); await click(page,cityRow.code); await click(page,'Допуски мастеров');
  await click(page,'Загрузить мастеров города'); await click(page,'Тестовый мастер своего города');
  await click(page,'История допуска в город'); await click(page,'История допуска в зоны');
  await expect(page.getByText('Нет доступных записей.', { exact:true })).toHaveCount(2);
  await page.getByLabel('Начало допуска (ISO 8601 с зоной)').fill(timestamp);
  await confirm(page,'Выдать допуск в город'); await status(page,success);
  const [admitted] = s.hitsFor('POST',membership); command(admitted,0,'geo'); expect(json(admitted)).toEqual({ validFrom:timestamp, validTo:null });
  await click(page,'Загрузить города'); await click(page,cityRow.code); await click(page,'Административные назначения');
  await page.getByLabel('Сотрудник с веб-доступом').selectOption(id.manager); await click(page,'Загрузить назначения');
  await expect(page.getByText('Нет доступных записей.', { exact:true })).toBeVisible();
  await confirm(page,'Назначить административный город'); await status(page,success);
  command(s.hitsFor('POST',assignments)[0],0,'geo');
  await click(page,'Загрузить города'); await click(page,cityRow.code); await click(page,'Административные назначения');
  await page.getByLabel('Сотрудник с веб-доступом').selectOption(id.manager); await click(page,'Загрузить назначения');
  await confirm(page,'Отозвать назначение'); await status(page,success);
  command(s.hitsFor('POST',`${assignments}/${assignmentId}/revoke`)[0],1,'geo');
  await noOverflow(page); s.done();
});

test('manager city read-only, edits district and preserves full zone mapping beyond a paged picker', async ({ page }) => {
  const s = await arrange(page, { manager: true, standard: [], grants: [],
    geo: [{ code: 'geography.read', scope: 'CITY' }, { code: 'geography.manage', scope: 'CITY' }] });
  cities(s);
  const district = { id: uuid(21), cityId: id.city, version: 2, name: 'Видимый район', code: 'district-visible', archivedAt: null as string | null };
  const outside = { id: uuid(22), cityId: id.city, version: 3, name: 'Архивный район второй страницы', code: 'district-archived', archivedAt: timestamp };
  const untouched = { id: uuid(23), cityId: id.city, version: 1, name: 'Район третьей страницы', code: 'district-untouched', archivedAt: null };
  const area = { id: uuid(25), cityId: id.city, version: 4, code: 'synthetic-zone', currentVersionId: null, archivedAt: null };
  const areas = `${cityPath}/service-areas`;
  const versions = `${areas}/${area.id}/versions`;
  const draft = { id: uuid(26), areaId: area.id, cityId: id.city, version: 7, sequence: 1, name: 'Черновик зоны QA', coverageDescription: null, addressCriteria: null, publishedAt: null };
  const draftPath = `${versions}/${draft.id}`;
  const coverage = `${draftPath}/district-coverage`;
  const archived = { districtId: outside.id, relation: 'PARTIAL', description: 'Не менять архивное соответствие' };
  const hidden = { districtId: untouched.id, relation: 'FULL', description: null };
  s.handlers.push((route,h) => {
    if (h.method === 'GET' && h.path === districtPath) {
      const cursor = h.url.searchParams.get('cursor');
      return wire(route, { ...list(cursor === 'page_2' ? [outside] : cursor === 'page_3' ? [untouched] : [district], cursor === 'page_2' ? 'page_3' : cursor === 'page_3' ? null : 'page_2'), version: 3 });
    }
    if (h.method === 'GET' && h.path === `${districtPath}/${district.id}`) { return wire(route, district); }
    if (h.method === 'PATCH' && h.path === `${districtPath}/${district.id}`) { return wire(route, { id: district.id, version: 3 }); }
    if (h.method === 'GET' && h.path === areas) { return wire(route, { ...list([area]), version: 3 }); }
    if (h.method === 'GET' && h.path === `${areas}/${area.id}`) { return wire(route, area); }
    if (h.method === 'GET' && h.path === versions) { return wire(route, { ...list([draft]), version: 4 }); }
    if (h.method === 'GET' && h.path === draftPath) { return wire(route, draft); }
    if (h.method === 'GET' && h.path === coverage && !h.url.search) { return wire(route, { areaVersionId: draft.id, version: 8, items: [archived, hidden] }); }
    if (h.method === 'PUT' && h.path === coverage) { return wire(route, { id: draft.id, version: 9 }); }
  });
  await s.signIn(); await openCity(page);
  await expect(button(page,'Создать черновик города')).toHaveCount(0); await expect(button(page,'Создать версию города')).toHaveCount(0);
  await expect(button(page,'Сделать основным')).toHaveCount(0); await expect(button(page,'Административные назначения')).toHaveCount(0);
  await click(page,'Районы'); await click(page,'Загрузить районы'); await click(page,district.name);
  const editor = page.getByRole('group',{ name:'Редактирование района' });
  await editor.getByLabel('Название района').fill('Переименованный район QA');
  await editor.getByRole('button',{ name:'Сохранить район' }).click(); await status(page,success);
  const [patched] = s.hitsFor('PATCH',`${districtPath}/${district.id}`); command(patched,2,'geo'); expect(json(patched)).toEqual({ name:'Переименованный район QA' });
  await click(page,'Загрузить города'); await click(page,cityRow.code); await click(page,'Зоны обслуживания');
  await click(page,'Загрузить зоны'); await click(page,area.code); await click(page,'История зоны'); await click(page,`${draft.name} · версия 1`);
  await expect(button(page,'Опубликовать зону')).toHaveCount(0); await expect(button(page,'Сохранить черновик зоны')).toBeVisible();
  await click(page,'Загрузить полное покрытие');
  await expect(page.getByRole('heading',{ name:'Полное покрытие районов (2 / 200)' })).toBeVisible();
  await click(page,'Загрузить районы для покрытия'); await click(page,'Загрузить ещё');
  await expect(button(page,outside.name)).toBeDisabled(); await expect(button(page,untouched.name)).toHaveCount(0);
  await click(page,district.name); await page.getByLabel('Охват').selectOption('PARTIAL'); await click(page,'Применить к полному набору');
  await confirm(page,'Сохранить полное покрытие'); await status(page,success);
  const [saved] = s.hitsFor('PUT',coverage); command(saved,8,'geo');
  expect(json(saved)).toEqual({ districts: [archived, hidden, { districtId: district.id, relation:'PARTIAL', description:null }] });
  expect(s.hitsFor('GET',districtPath).some(h => h.url.searchParams.get('cursor') === 'page_3')).toBe(false);
  await noOverflow(page); s.done();
});

test('mixed-version zone editor never PATCHes stale exact draft with a newer coverage precondition', async ({ page }) => {
  const s = await arrange(page); cities(s);
  const area = { id: uuid(71), cityId: id.city, version: 1, code: 'race-zone', currentVersionId: null, archivedAt: null };
  const areas = `${cityPath}/service-areas`;
  const versions = `${areas}/${area.id}/versions`;
  const draft = { id: uuid(72), areaId: area.id, cityId: id.city, version: 1, sequence: 1, name: 'Старый черновик QA', coverageDescription: null, addressCriteria: null, publishedAt: null };
  const exact = `${versions}/${draft.id}`;
  const coverage = `${exact}/district-coverage`;
  s.handlers.push((route,h) => {
    if (h.method === 'GET' && h.path === areas) { return wire(route, { ...list([area]), version: 3 }); }
    if (h.method === 'GET' && h.path === `${areas}/${area.id}`) { return wire(route, area); }
    if (h.method === 'GET' && h.path === versions) { return wire(route, { ...list([draft]), version: 1 }); }
    if (h.method === 'GET' && h.path === exact) { return wire(route, draft); }
    if (h.method === 'GET' && h.path === coverage) { return wire(route, { areaVersionId: draft.id, version: 2, items: [] }); }
    if (h.method === 'PATCH' && h.path === exact) { return rejected(route, h.tag === '"geo-v1"' ? 412 : 400); }
  });
  await s.signIn(); await openCity(page); await click(page,'Зоны обслуживания'); await click(page,'Загрузить зоны');
  await click(page,area.code); await click(page,'История зоны'); await click(page,`${draft.name} · версия 1`);
  await click(page,'Загрузить полное покрытие');
  await expect(page.getByRole('heading',{ name:'Полное покрытие районов (0 / 200)' })).toBeVisible();
  await expect(button(page,'Опубликовать зону')).toBeDisabled();
  await click(page,'Сохранить черновик зоны'); await status(page,/Версия изменилась/);
  const [write] = s.hitsFor('PATCH',exact);
  command(write,1,'geo'); expect(json(write)).toEqual({ name:draft.name, coverageDescription:null, addressCriteria:null });
  s.done();
});

test('mixed-version city editor blocks stale local fields and lifecycle changes until detail reload', async ({ page }) => {
  const s = await arrange(page);
  let detailReads = 0;
  const latest = { ...cityRevision, id: uuid(77), sequence: 3, displayName:'Новые конкурентные поля', timezone:'Asia/Novosibirsk' };
  s.handlers.push((route,h) => {
    if (h.method === 'GET' && h.path === cityPath) {
      return wire(route, ++detailReads === 1 ? { ...cityRow, currentVersion: cityRevision }
        : { ...cityRow, version:4, currentVersionId:latest.id, currentVersion:latest });
    }
    if (h.method === 'GET' && h.path === cityHistory) { return wire(route, { ...list([latest,cityRevision]), version:4 }); }
    if (h.method === 'POST' && h.path === cityHistory) { return wire(route, { id: uuid(78), version: 5 }, 201); }
  });
  cities(s); await s.signIn(); await openCity(page);
  await expect(page.getByLabel('Название города')).toHaveValue(cityRevision.displayName);
  await click(page,'История города'); await expect(button(page,'Версия города 3')).toBeVisible();
  await expect(button(page,'Создать версию города')).toBeDisabled();
  await expect(button(page,'Сделать основным')).toBeDisabled(); await expect(button(page,'Деактивировать город')).toBeDisabled();
  expect(s.hitsFor('POST',cityHistory)).toHaveLength(0);
  await click(page,'Перечитать карточку города');
  await expect(page.getByLabel('Название города')).toHaveValue(latest.displayName);
  await expect(page.getByLabel('Часовой пояс IANA')).toHaveValue(latest.timezone);
  await click(page,'Создать версию города'); await status(page,success);
  const [write] = s.hitsFor('POST',cityHistory);
  command(write,4,'geo');
  expect(json(write)).toEqual({ displayName:latest.displayName, timezone:latest.timezone, addressDisplay:null,
    publicContact:latest.publicContact, officeHours:latest.officeHours });
  s.done();
});
