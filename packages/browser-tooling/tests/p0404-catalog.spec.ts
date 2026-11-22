import { expect, test, type Page } from '@playwright/test';
import { decide, noOverflow } from '../fixtures/p0305/browser.js';
import { id, list, timestamp, uuid, wire } from '../fixtures/p0305/mock.js';
import {
  avitoPath, brand, category, citiesPath, city, cityPath, cityReads, companyReads, directories, estimate, estimatePath, estimatesPath,
  expectCommand, fault, fixed, items, itemsPath, label, listing, mapping, mappingsPath, model, outsideCity, period, policyPath,
  pricePath, problem, profile, receipt, review, rig, rulePath, rules, rulesPath, type Fixture,
} from '../fixtures/p0404/mock.js';

// Strict synthetic browser intercepts in the existing six projects, not server authorization proofs.
test.use({ serviceWorkers: 'block', trace: 'off', screenshot: 'off', video: 'off' });
const catalog = 'Каталог компании', pricing = 'Городские цены и тарифы', definitions = 'Определения тарифов', avito = 'Авито: ручные записи';
const retry = 'Проверить / повторить';
const button = (page: Page, name: string) => page.getByRole('button', { name, exact: true });
const click = (page: Page, name: string) => button(page, name).click();
const field = (page: Page, name: string) => page.getByLabel(name, { exact: true });
const status = (page: Page, text: RegExp) => expect(page.getByRole('status').filter({ hasText: text })).toBeVisible();
const error = (page: Page, text: RegExp) => expect(page.getByRole('alert').filter({ hasText: text })).toBeVisible();
const success = (page: Page) => status(page, /Операция подтверждена сервером/);
async function confirmed(page: Page, name: string, accept = true) { const dialog = decide(page, accept); await click(page, name); return dialog; }
async function fill(page: Page, fields: Record<string, string>) {
  for (const [name, value] of Object.entries(fields)) { await field(page, name).fill(value); }
}
async function schedule(page: Page, when = period.validFrom) {
  await fill(page, { 'Начало действия (UTC)': when, Источник: period.sourceRef, Валюта: 'RUB' });
}
function exact(s: Fixture, path: string, body: unknown, version?: number, count = 1) {
  const hits = s.hitsFor('POST', path);
  expect(hits).toHaveLength(count);
  expectCommand(hits.at(-1), body, version);
}
const chooseCategory = async (page: Page) => { await click(page, 'Загрузить варианты: Категория'); await click(page, `Выбрать: ${label(category)}`); };
async function companyCard(page: Page, load: string, row: { code: string; title?: string | null }) {
  await click(page, load); await click(page, label(row));
  await expect(page.getByRole('heading', { name: label(row), exact: true })).toBeVisible();
}
async function cityPicker(page: Page, cityId = city.id) {
  await click(page, 'Загрузить города');
  await expect(field(page, 'Город')).toHaveValue('');
  await expect(page.getByText('Выберите город. Город не подставляется автоматически.')).toBeVisible();
  await expect(button(page, 'Фиксированные цены')).toHaveCount(0);
  await field(page, 'Город').selectOption(cityId);
}

// Groups 1–3: device/category-model, symptoms/mapping, brands.
test('catalogue directories, scoped metadata choices, exact history, and same-category work mapping', async ({ page }) => {
  test.setTimeout(60_000);
  const s = await rig(page); companyReads(s);
  const archive = `${directories.BRAND}/${brand.id}/archive`;
  const history = `${directories.CATEGORY}/${category.id}/versions`;
  const r = { id: category.currentVersionId, entryId: category.id, version: 1, title: category.title, publishedAt: timestamp };
  s.handlers.push((route, h) => {
    if (h.method === 'GET' && h.path === history) { return wire(route, { ...listing([r]), version: category.version }); }
    if (h.method === 'GET' && h.path === `${history}/${r.id}`) { return wire(route, { ...r, description: 'Точное описание прошлой версии' }); }
    if (h.method !== 'POST') { return; }
    if (h.path === directories.MODEL) { return receipt(route, model.id, 1); }
    if (h.path === history) { return receipt(route, category.id, 3, 2); }
    if (h.path === archive) { return receipt(route, brand.id, 3, undefined, 200); }
    if (h.path === mappingsPath) { return receipt(route, mapping.id, 1); }
    if (h.path === `${mappingsPath}/${mapping.id}/publish`) { return receipt(route, mapping.id, 3); }
  });
  await s.signIn(); await click(page, catalog); await companyCard(page, 'Загрузить категории', category);
  await click(page, 'История версий');
  expect(s.hitsFor('GET', `${history}/${r.id}`)).toHaveLength(0);
  await click(page, `Версия 1 · ${r.title}`);
  await expect(page.getByText('Точное описание прошлой версии')).toBeVisible();
  await expect(button(page, 'Опубликовать версию')).toHaveCount(0);
  await click(page, 'Загрузить текущую версию');
  await fill(page, { Название: 'Обновлённая техника', Описание: 'Обновлённое описание техники' });
  await click(page, 'Опубликовать версию'); await success(page);
  exact(s, history, { title: 'Обновлённая техника', description: 'Обновлённое описание техники' }, 2);
  await click(page, 'Модели');
  await expect(button(page, 'Создать модель')).toHaveCount(0);
  await chooseCategory(page);
  await click(page, 'Загрузить варианты: Бренд');
  await expect(button(page, 'Выбрать: qa-archived-brand')).toHaveCount(0);
  await click(page, `Выбрать: ${label(brand)}`);
  await field(page, 'Код').fill(model.code); await click(page, 'Создать модель'); await success(page);
  exact(s, directories.MODEL, { code: model.code, categoryId: category.id, brandId: brand.id });
  await click(page, 'Бренды'); await companyCard(page, 'Загрузить бренды', brand);
  expect(await confirmed(page, 'Архивировать', false)).toMatch(/истории/);
  expect(s.hitsFor('POST', archive)).toHaveLength(0);
  await confirmed(page, 'Архивировать'); await success(page); exact(s, archive, {}, 2);
  await click(page, 'Неисправности'); await companyCard(page, 'Загрузить неисправности', fault);
  await click(page, 'Связи неисправностей'); await chooseCategory(page);
  await click(page, 'Загрузить варианты: Неисправность'); await click(page, `Выбрать: ${label(fault)}`);
  await click(page, 'Загрузить варианты: Работа (WORK)'); await click(page, 'Выбрать: qa-work');
  for (const invalid of ['qa-wrong-fault', 'qa-wrong-work', 'qa-part', 'qa-material']) {
    await expect(button(page, `Выбрать: ${invalid}`)).toHaveCount(0);
  }
  await click(page, 'Создать связь'); await success(page);
  exact(s, mappingsPath, { categoryId: category.id, faultId: fault.id, itemId: items.WORK.id });
  await click(page, 'Связи неисправностей'); await click(page, 'Загрузить связи');
  await click(page, `${fault.id} → ${items.WORK.id}`); await confirmed(page, 'Опубликовать связь'); await success(page);
  exact(s, `${mappingsPath}/${mapping.id}/publish`, {}, 2);
  await noOverflow(page); s.done();
});

// Groups 4–6, 8: exact kind, units and duration, typed visibility, no price/override fields on metadata.
test('WORK/PART/MATERIAL/TRAVEL/DIAGNOSTICS publish their exact kind and permitted duration only', async ({ page }) => {
  test.setTimeout(60_000);
  const s = await rig(page); companyReads(s);
  s.handlers.push((route, h) => {
    if (h.method !== 'POST') { return; }
    for (const item of Object.values(items)) {
      if (h.path === `${itemsPath}/${item.id}/versions`) { return receipt(route, item.id, 2, 1); }
    }
  });
  await s.signIn(); await click(page, catalog);
  const cases = [
    ['Работы (WORK)', 'Загрузить работы', items.WORK, '75'], ['Запчасти (PART)', 'Загрузить запчасти', items.PART],
    ['Материалы (MATERIAL)', 'Загрузить материалы', items.MATERIAL], ['Выезд (TRAVEL)', 'Загрузить выезды', items.TRAVEL],
    ['Диагностика (DIAGNOSTICS)', 'Загрузить диагностику', items.DIAGNOSTICS, '35'],
  ] as const;
  for (const [tab, load, item, duration] of cases) {
    await click(page, tab);
    if (item.kind === 'WORK') { await expect(button(page, 'Создать позицию')).toHaveCount(0); }
    await companyCard(page, load, item);
    expect(s.hitsFor('GET', itemsPath).at(-1)?.url.searchParams.get('kind')).toBe(item.kind);
    await expect(field(page, 'Сумма (минорные единицы)')).toHaveCount(0);
    const time = field(page, 'Длительность, мин');
    const path = `${itemsPath}/${item.id}/versions`;
    const title = `Тестовая позиция ${item.kind}`;
    await field(page, 'Название').fill(title);
    if (duration) {
      await expect(time).toHaveAttribute('required', '');
      await time.fill('0'); await click(page, 'Опубликовать версию');
      expect(s.hitsFor('POST', path)).toHaveLength(0);
      await time.fill(duration);
    } else { await expect(time).toHaveCount(0); }
    await field(page, 'Видна мастеру').check();
    if (item.kind === 'MATERIAL') { await field(page, 'Публичная видимость').check(); }
    await click(page, 'Опубликовать версию'); await success(page);
    exact(s, path, { kind: item.kind, title, description: null, technicianVisible: true, publicVisible: item.kind === 'MATERIAL',
      ...(duration ? { durationMinutes: Number(duration) } : {}) }, item.version);
  }
  s.done();
});

// Groups 4, 5, 7: decimal string money, actual exact provenance, zero rationale and separate public estimates.
test('city fixed prices and estimates require scoped choices and preserve exact money and provenance', async ({ page }) => {
  test.setTimeout(60_000);
  const s = await rig(page); cityReads(s);
  const workPrice = pricePath('WORK'), partPrice = pricePath('PART');
  s.handlers.push((route, h) => {
    if (h.method === 'GET') {
      if (h.path === workPrice) { return wire(route, { ...listing([]), version: 0 }); }
      if (h.path === partPrice) { return wire(route, { ...listing([fixed]), version: 1 }); }
      if (h.path === `${partPrice}/${fixed.id}`) { return wire(route, fixed); }
      if (h.path === estimatesPath) { return wire(route, listing([estimate])); }
      if (h.path === estimatePath) { return wire(route, estimate); }
      if (h.path === `${estimatePath}/versions`) {
        const prior = { id: uuid(181), seriesId: estimate.id, cityId: city.id, cityVersionId: id.cityVersion,
          version: 2, validFrom: fixed.validFrom, validUntil: '2021-01-01T00:00:00.000Z', effectiveUntil: '2021-01-01T00:00:00.000Z',
          publishedAt: fixed.publishedAt, title: 'Исторический диапазон QA', currency: 'RUB', minMinor: '100', maxMinor: '200' };
        return wire(route, { ...listing([prior]), version: 2 });
      }
    } else if (h.method === 'POST') {
      if (h.path === workPrice) { return receipt(route, uuid(180), 1, 1); }
      if (h.path === `${partPrice}/${fixed.id}/close`) { return receipt(route, fixed.seriesId, 2, undefined, 200); }
      if (h.path === estimatesPath) { return receipt(route, estimate.id, 1); }
      if (h.path === `${estimatePath}/versions`) { return receipt(route, estimate.id, 3, 3); }
    }
  });
  await s.signIn(); await click(page, pricing); await cityPicker(page);
  await click(page, 'Готовность цен'); await click(page, 'Загрузить готовность цен');
  await expect(page.getByText('Не настроено (нет действующей версии)')).toBeVisible();
  await expect(page.getByText('Отсутствие цены не означает нулевую цену.')).toBeVisible();
  await click(page, 'Фиксированные цены'); await click(page, 'Загрузить позиции города');
  await field(page, 'Вид позиции').selectOption('WORK'); await field(page, 'Позиция').selectOption(items.WORK.id);
  await expect(button(page, 'Опубликовать цену')).toHaveCount(0);
  await click(page, 'Загрузить историю версий'); await schedule(page);
  await field(page, 'Сумма (минорные единицы)').fill('0'); await confirmed(page, 'Опубликовать цену');
  await error(page, /Заполните обязательные поля/); expect(s.hitsFor('POST', workPrice)).toHaveLength(0);
  await field(page, 'Обоснование нуля').fill('Подтверждённая бесплатная работа QA');
  await confirmed(page, 'Опубликовать цену'); await success(page);
  exact(s, workPrice, { ...period, currency: 'RUB', amountMinor: '0', zeroBasis: 'Подтверждённая бесплатная работа QA' }, 0);
  await cityPicker(page); await click(page, 'Фиксированные цены'); await click(page, 'Загрузить позиции города');
  await field(page, 'Вид позиции').selectOption('PART'); await field(page, 'Позиция').selectOption(items.PART.id);
  await expect(field(page, 'Позиция').locator('option')).toHaveText(['Выберите позицию', 'Позиция PART · qa-part · PART']);
  await click(page, 'Загрузить историю версий'); await field(page, 'Версия').selectOption(fixed.id);
  await expect(page.getByText(id.cityVersion, { exact: true })).toBeVisible();
  await expect(page.getByText(/fixture-price-review/)).toBeVisible();
  await field(page, 'Граница закрытия (UTC)').fill(period.validFrom);
  await confirmed(page, 'Закрыть цену'); await success(page);
  exact(s, `${partPrice}/${fixed.id}/close`, { at: period.validFrom }, 1);
  await cityPicker(page); await click(page, 'Оценочные диапазоны');
  await click(page, 'Загрузить категории города');
  await fill(page, { 'Код диапазона': estimate.code }); await field(page, 'Категория диапазона').selectOption(category.id);
  await click(page, 'Создать диапазон'); await success(page);
  exact(s, estimatesPath, { code: estimate.code, categoryId: category.id });
  await cityPicker(page); await click(page, 'Оценочные диапазоны'); await click(page, 'Загрузить оценочные диапазоны');
  await field(page, 'Диапазон').selectOption(estimate.id); await click(page, 'Загрузить точный диапазон');
  await click(page, 'Загрузить историю версий'); await schedule(page);
  const estimateFields = { Название: 'Оценка ремонта QA', 'Минимум (минорные единицы)': '9007199254740993',
    'Максимум (минорные единицы)': '9007199254740992', Условия: 'После осмотра', 'Предупреждение об оценке': 'Это не фиксированная цена' };
  await fill(page, estimateFields); await confirmed(page, 'Опубликовать диапазон'); await error(page, /Минимум не может/);
  expect(s.hitsFor('POST', `${estimatePath}/versions`)).toHaveLength(0);
  await field(page, 'Максимум (минорные единицы)').fill('9007199254740994');
  await confirmed(page, 'Опубликовать диапазон'); await success(page);
  exact(s, `${estimatePath}/versions`, { ...period, title: estimateFields.Название, currency: 'RUB', minMinor: '9007199254740993',
    maxMinor: '9007199254740994', conditions: estimateFields.Условия, disclaimer: estimateFields['Предупреждение об оценке'] }, 2);
  await noOverflow(page); s.done();
});

// Groups 9–11: immutable definitions, local windows, non-window express/discount and limits.
test('rule definitions and city temporal/express/discount forms are distinct; policy uses typed rows', async ({ page }) => {
  test.setTimeout(75_000);
  const s = await rig(page); cityReads(s);
  s.handlers.push((route, h) => {
    if (h.method === 'POST' && h.path === rulesPath) { return receipt(route, rules.EXPRESS.id, 1); }
    if (h.path === policyPath || Object.values(rules).some(row => h.path === `${cityPath}/rules/${row.id}/versions`)) {
      if (h.method === 'GET') { return wire(route, { ...listing([]), version: 0 }); }
      if (h.method === 'POST') { return receipt(route, uuid(190), 1, 1); }
    }
  });
  await s.signIn(); await click(page, definitions);
  for (const tab of ['Вечернее (EVENING)', 'Ночное (NIGHT)', 'Срочность (EXPRESS)', 'Надбавка (SURCHARGE)', 'Скидка (DISCOUNT)']) {
    await expect(button(page, tab)).toBeVisible();
  }
  await click(page, 'Срочность (EXPRESS)');
  await expect(field(page, 'Начало местного окна (чч:мм)')).toHaveCount(0);
  await field(page, 'Код').fill(rules.EXPRESS.code); await click(page, 'Создать определение'); await success(page);
  exact(s, rulesPath, { code: rules.EXPRESS.code, kind: 'EXPRESS' });
  await click(page, pricing);
  for (const kind of ['EVENING', 'NIGHT', 'EXPRESS', 'DISCOUNT'] as const) {
    await cityPicker(page); await click(page, 'Тарифные правила'); await click(page, 'Загрузить правила города');
    await field(page, 'Правило').selectOption(rules[kind].id);
    await click(page, 'Загрузить историю версий');
    await expect(button(page, 'Опубликовать правило')).toHaveCount(0);
    await click(page, 'Загрузить категории города'); await schedule(page);
    const temporal = kind === 'EVENING' || kind === 'NIGHT';
    const night = kind === 'NIGHT';
    const isRate = kind !== 'EXPRESS';
    const method = isRate ? 'RATE' : 'FIXED';
    const title = `Тариф QA ${kind}`;
    await fill(page, { Название: title, 'Минимум базы (минорные единицы)': '1000', 'Максимум дельты (минорные единицы)': '5000' });
    await field(page, 'Основание расчёта').selectOption('WORKS_AND_PARTS');
    await field(page, 'Метод').selectOption(method);
    await field(page, 'Категории правила').selectOption(category.id);
    if (isRate) { await field(page, 'Ставка (базисные пункты)').fill('1250'); }
    else { await field(page, 'Фиксированная дельта (минорные единицы)').fill('2500'); }
    if (temporal) {
      await fill(page, { 'Начало местного окна (чч:мм)': night ? '23:15' : '18:30', 'Конец местного окна (чч:мм)': night ? '06:45' : '21:00' });
      if (night) {
        await field(page, 'Переход через полночь').selectOption('no');
        await confirmed(page, 'Опубликовать правило'); await error(page, /пересекает ли оно полночь/);
        expect(s.hitsFor('POST', rulePath(kind))).toHaveLength(0);
      }
      await field(page, 'Переход через полночь').selectOption(night ? 'yes' : 'no');
    } else {
      await expect(field(page, 'Начало местного окна (чч:мм)')).toHaveCount(0);
      if (kind === 'EXPRESS') {
        await field(page, 'Ставка (базисные пункты)').fill('100');
        await confirmed(page, 'Опубликовать правило'); await error(page, /только для выбранного метода/);
        expect(s.hitsFor('POST', rulePath(kind))).toHaveLength(0);
        await field(page, 'Ставка (базисные пункты)').clear();
      }
    }
    await confirmed(page, 'Опубликовать правило'); await success(page);
    exact(s, rulePath(kind), { ...period, kind, title, currency: 'RUB', base: 'WORKS_AND_PARTS', method, minBase: '1000', maxBase: null,
      minDelta: null, maxDelta: '5000', categoryIds: [category.id], fixedMinor: isRate ? null : '2500', rateBps: isRate ? 1250 : null,
      ...(temporal ? { startMinute: night ? 1395 : 1110, endMinute: night ? 405 : 1260, wrapsMidnight: night } : {}) }, 0);
  }
  await cityPicker(page); await click(page, 'Ценовая политика'); await click(page, 'Загрузить историю версий');
  await click(page, 'Загрузить правила города'); await schedule(page);
  await fill(page, { 'Отображение налога': 'Налог указан отдельно', 'Максимальная ручная дельта (минорные единицы)': '9200',
    'Код единицы': 'piece', 'Шкала (0–6)': '0' });
  await field(page, 'Округление').selectOption('HALF_UP');
  await click(page, 'Добавить: Приоритеты'); await click(page, 'Добавить: Совместимости');
  await field(page, 'Правило приоритета').selectOption(rules.DISCOUNT.id); await field(page, 'Приоритет (0–1000000)').fill('42');
  await field(page, 'Первое совместимое правило').selectOption(rules.DISCOUNT.id);
  await field(page, 'Второе совместимое правило').selectOption(rules.DISCOUNT.id);
  await confirmed(page, 'Опубликовать политику'); await error(page, /пары.*одно правило дважды/);
  expect(s.hitsFor('POST', policyPath)).toHaveLength(0);
  await field(page, 'Второе совместимое правило').selectOption(rules.EXPRESS.id);
  await confirmed(page, 'Опубликовать политику'); await success(page);
  exact(s, policyPath, { ...period, currency: 'RUB', taxDisplay: 'Налог указан отдельно', roundingMode: 'HALF_UP',
    units: { piece: 0 }, maxManualDeltaMinor: '9200', priorities: [{ ruleId: rules.DISCOUNT.id, priority: 42 }],
    compatibilities: [{ leftRuleId: rules.DISCOUNT.id, rightRuleId: rules.EXPRESS.id }] }, 0);
  s.done();
});

// Groups 12–13: verify canonical P03 navigation and role restrictions, not duplicate writes.
test('CITY manager sees only authorized city, no implicit selection or write forms, and hands off to canonical P03 tabs', async ({ page }) => {
  const s = await rig(page, { manager: true, p04: [{ code: 'pricing.read', scope: 'CITY' }], standard: [],
    geo: [{ code: 'geography.read', scope: 'CITY' }], grants: [{ code: 'content.read', scope: 'CITY' }] });
  cityReads(s);
  const route = '/settings/service-cities';
  const p03City = { id: city.id, code: city.code, version: 2, lifecycle: 'ACTIVE', currentVersionId: id.cityVersion };
  s.handlers.push((r, h) => {
    if (h.method !== 'GET') { return; }
    if (h.path === route) { return wire(r, list([p03City])); }
    if (h.path === `${route}/${city.id}`) {
      return wire(r, { ...p03City, currentVersion: { id: id.cityVersion, sequence: 1, displayName: city.name, addressDisplay: null,
        timezone: 'Asia/Yekaterinburg', publicContact: 'Проверочный контакт QA', officeHours: [[], [], [], [], [], [], []], publishedAt: timestamp } });
    }
    if (h.path === '/settings/management/cities' && h.url.searchParams.get('domain') === 'content') {
      return wire(r, list([{ id: city.id, code: city.code, version: 2, status: 'ACTIVE', currentVersionId: id.cityVersion }]));
    }
    if (h.path === '/content/blocks' && h.url.searchParams.get('scope') === 'CITY' && h.url.searchParams.get('cityId') === city.id) {
      return wire(r, list([{ id: uuid(200), version: 1, code: 'qa-faq', kind: 'FAQ', scope: 'CITY', cityId: city.id,
        allowCompanyFallback: false, currentRevisionId: null, archivedAt: null }]));
    }
    if (h.path === pricePath('WORK')) { return wire(r, { ...listing([]), version: 0 }); }
  });
  await s.signIn(); await click(page, pricing);
  for (const hidden of [catalog, avito, definitions]) { await expect(button(page, hidden)).toHaveCount(0); }
  await cityPicker(page);
  await expect(field(page, 'Город').locator('option')).toHaveText(['Выберите город', `${city.name} · ${city.code}`]);
  expect(s.hitsFor('GET', citiesPath)).toHaveLength(1);
  await click(page, 'Фиксированные цены'); await click(page, 'Загрузить позиции города');
  await field(page, 'Позиция').selectOption(items.WORK.id); await click(page, 'Загрузить историю версий');
  await expect(page.getByText(/Версия набора: 0/)).toBeVisible();
  await expect(button(page, 'Опубликовать цену')).toHaveCount(0);
  await click(page, 'Районы, зоны и контакты'); await click(page, 'Загрузить города'); await click(page, city.code);
  await expect(button(page, 'Районы')).toBeVisible(); await expect(button(page, 'Зоны обслуживания')).toBeVisible();
  await expect(page.getByText('Проверочный контакт QA', { exact: true })).toBeVisible();
  await expect(button(page, 'Создать версию города')).toHaveCount(0);
  await click(page, pricing); await click(page, 'FAQ и публикации CRM');
  await expect(button(page, 'Компания')).toHaveCount(0);
  await click(page, 'Загрузить города'); await click(page, city.code); await click(page, 'Загрузить список');
  await expect(button(page, 'FAQ · qa-faq')).toBeVisible();
  await expect(button(page, 'Создать блок')).toHaveCount(0);
  expect(s.hits.some(h => h.method !== 'GET' || h.path.includes(outsideCity.id))).toBe(false);
  await noOverflow(page); s.done();
});

// Group 14: local profile/review forms, mandatory manual evidence and no external request or link.
test('Avito profile and review are manually published, validated, and displayed as plain text without external I/O', async ({ page }) => {
  test.setTimeout(60_000);
  const s = await rig(page); companyReads(s);
  const sourceUrl = 'https://www.avito.ru/profile/synthetic-qa';
  const common = { title: 'Внутренняя запись QA', sourceUrl, permissionRef: 'synthetic-manual-consent-ref' };
  const reviewRequest = { ...common, sourceDate: '2026-02-28', excerpt: 'Синтетическая выдержка QA', rating: 5 };
  const profileVersions = `${avitoPath}/${profile.id}/versions`, reviewVersions = `${avitoPath}/${review.id}/versions`;
  const profileCurrent = { id: profile.currentVersionId, version: 1, kind: 'PROFILE' as const, entryId: profile.id,
    title: profile.title, sourceUrl, permissionRef: common.permissionRef, sourceDate: null, excerpt: null, rating: null,
    profileRevisionId: null, publishedAt: timestamp };
  const reviewSummary = { id: review.currentVersionId, version: 1, kind: 'REVIEW' as const, entryId: review.id, title: review.title, publishedAt: timestamp };
  s.handlers.push((route, h) => {
    if (h.method === 'GET' && h.path === `${profileVersions}/${profileCurrent.id}`) { return wire(route, profileCurrent); }
    if (h.method === 'GET' && h.path === reviewVersions) { return wire(route, { ...listing([reviewSummary]), version: 2 }); }
    if (h.method === 'GET' && h.path === `${reviewVersions}/${reviewSummary.id}`) {
      return wire(route, { ...reviewRequest, ...reviewSummary, profileRevisionId: profileCurrent.id });
    }
    if (h.method !== 'POST') { return; }
    if (h.path === profileVersions) { return receipt(route, profile.id, 3, 2); }
    if (h.path === avitoPath) { return receipt(route, review.id, 1); }
    if (h.path === reviewVersions) { return receipt(route, review.id, 3, 2); }
  });
  await s.signIn(); await click(page, avito); await companyCard(page, 'Загрузить профили', profile);
  await click(page, 'Загрузить текущую версию');
  await expect(field(page, 'Дата источника (ГГГГ-ММ-ДД)')).toHaveCount(0);
  await fill(page, { Название: common.title, 'URL источника': 'https://example.invalid/profile/synthetic-qa', 'Основание разрешения': common.permissionRef });
  await confirmed(page, 'Опубликовать версию'); await error(page, /Проверьте формат/);
  expect(s.hitsFor('POST', profileVersions)).toHaveLength(0);
  await field(page, 'URL источника').fill(sourceUrl);
  expect(await confirmed(page, 'Опубликовать версию', false)).toMatch(/внутреннего использования/);
  expect(s.hitsFor('POST', profileVersions)).toHaveLength(0);
  await confirmed(page, 'Опубликовать версию'); await success(page); exact(s, profileVersions, common, 2);
  await click(page, 'Отзывы (REVIEW)'); await expect(button(page, 'Создать отзыв')).toHaveCount(0);
  await click(page, 'Загрузить варианты: Профиль Авито'); await click(page, `Выбрать: ${label(profile)}`);
  await expect(button(page, `Выбрать: ${review.code}`)).toHaveCount(0);
  await field(page, 'Код').fill(review.code); await click(page, 'Создать отзыв'); await success(page);
  exact(s, avitoPath, { code: review.code, kind: 'REVIEW', profileId: profile.id });
  await click(page, 'Отзывы (REVIEW)'); await companyCard(page, 'Загрузить отзывы', review);
  await click(page, 'История версий'); await click(page, `Версия 1 · ${reviewSummary.title}`);
  await expect(page.getByText(sourceUrl, { exact: true })).toBeVisible();
  await expect(page.getByText(profileCurrent.id, { exact: true })).toBeVisible();
  await expect(page.locator('a[href*="avito.ru"], iframe, img[src*="avito.ru"]')).toHaveCount(0);
  await click(page, 'Загрузить текущую версию');
  await fill(page, { Название: common.title, 'URL источника': sourceUrl, 'Основание разрешения': common.permissionRef,
    'Дата источника (ГГГГ-ММ-ДД)': '2026-02-30', Выдержка: reviewRequest.excerpt, Оценка: '5' });
  await confirmed(page, 'Опубликовать версию'); await error(page, /Проверьте формат/);
  expect(s.hitsFor('POST', reviewVersions)).toHaveLength(0);
  await field(page, 'Дата источника (ГГГГ-ММ-ДД)').fill(reviewRequest.sourceDate);
  await confirmed(page, 'Опубликовать версию'); await success(page); exact(s, reviewVersions, reviewRequest, 2);
  await noOverflow(page); s.done();
});

const lifecyclePath = `${directories.CATEGORY}/${category.id}/versions`;
const originalFields = { title: 'Черновик QA до ответа сервера', description: 'Локальные поля QA' };
const lifecycleCurrent = { id: category.currentVersionId, entryId: category.id, version: 1, title: category.title, description: null, publishedAt: timestamp };
function lifecycleReads(s: Fixture) {
  s.handlers.push((route, h) => {
    if (h.method === 'GET' && h.path === `${lifecyclePath}/${lifecycleCurrent.id}`) { return wire(route, lifecycleCurrent); }
  });
}
async function startLifecycle(page: Page, s: Fixture) {
  await s.signIn(); await click(page, catalog); await companyCard(page, 'Загрузить категории', category);
  await click(page, 'Загрузить текущую версию');
  await fill(page, { Название: originalFields.title, Описание: originalFields.description });
  await click(page, 'Опубликовать версию');
}
for (const swap of [false, true]) {
  test(`503 unknown: ${swap ? 'changed session discards pending command' : 'only explicit identical replay is sent'}`, async ({ page }) => {
    const s = await rig(page); companyReads(s); lifecycleReads(s);
    let writes = 0;
    s.handlers.push((route, h) => {
      if (h.method === 'POST' && h.path === lifecyclePath) {
        return ++writes === 1 ? problem(route, 503) : receipt(route, category.id, 3, 2, 200);
      }
    });
    await startLifecycle(page, s);
    await status(page, /Результат операции не подтверждён/);
    await expect(field(page, 'Название')).toHaveCount(0);
    exact(s, lifecyclePath, originalFields, 2);
    expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
    await expect(button(page, retry)).toBeEnabled();
    // The uncertain screen offers a human action, not another submit or background write.
    await expect(button(page, 'Опубликовать версию')).toHaveCount(0);
    expect(s.hitsFor('POST', lifecyclePath)).toHaveLength(1);
    if (swap) { s.identity.authVersion++; }
    await click(page, retry);
    if (swap) {
      await status(page, /Рабочая сессия изменилась/);
      await expect(button(page, 'Войти')).toBeEnabled();
      await expect(button(page, retry)).toHaveCount(0);
      await fill(page, { Логин: 'synthetic-ui', Пароль: 'synthetic-ui-only' }); await click(page, 'Войти');
      await click(page, catalog); await companyCard(page, 'Загрузить категории', category);
      await expect(field(page, 'Название')).toHaveCount(0);
      await click(page, 'Загрузить текущую версию');
      await expect(field(page, 'Название')).toHaveValue(lifecycleCurrent.title);
      await expect(button(page, 'Восстановить черновик')).toHaveCount(0);
      expect(s.hitsFor('POST', lifecyclePath)).toHaveLength(1);
    } else {
      await success(page); exact(s, lifecyclePath, originalFields, 2, 2);
      const [first, second] = s.hitsFor('POST', lifecyclePath);
      expect([second?.url.href, second?.tag, second?.key, second?.body]).toEqual([first?.url.href, first?.tag, first?.key, first?.body]);
      await expect(button(page, retry)).toHaveCount(0);
    }
    s.done();
  });
}

test('412 reloads the fresh card; restore is explicit and sends only a fresh command on submit', async ({ page }) => {
  const s = await rig(page);
  let version = 2;
  const currentId = uuid(210);
  s.handlers.push((route, h) => {
    if (h.method === 'GET' && h.path === `${directories.CATEGORY}/${category.id}`) {
      return wire(route, { ...category, version, currentVersionId: version === 2 ? lifecycleCurrent.id : currentId });
    }
    if (h.method === 'GET' && h.path === `${lifecyclePath}/${currentId}`) {
      return wire(route, { id: currentId, entryId: category.id, version: 2, title: 'Новые серверные поля QA', description: 'От другой команды', publishedAt: timestamp });
    }
    if (h.method === 'POST' && h.path === lifecyclePath) {
      if (version === 2) { version = 3; return problem(route, 412); }
      return receipt(route, category.id, 4, 3);
    }
  });
  companyReads(s); lifecycleReads(s);
  await startLifecycle(page, s);
  await status(page, /Версия изменилась/);
  await expect(button(page, retry)).toHaveCount(0);
  await expect(field(page, 'Название')).toHaveCount(0);
  exact(s, lifecyclePath, originalFields, 2);
  await companyCard(page, 'Загрузить категории', category);
  await expect(page.getByText('Версия карточки: 3')).toBeVisible();
  await expect(button(page, 'Восстановить черновик')).toHaveCount(0);
  await click(page, 'Загрузить текущую версию');
  await expect(field(page, 'Название')).toHaveValue('Новые серверные поля QA');
  await click(page, 'Восстановить черновик');
  await status(page, /отправки не было/);
  await expect(field(page, 'Название')).toHaveValue(originalFields.title);
  await expect(field(page, 'Описание')).toHaveValue(originalFields.description);
  expect(s.hitsFor('POST', lifecyclePath)).toHaveLength(1);
  await click(page, 'Опубликовать версию'); await success(page);
  exact(s, lifecyclePath, originalFields, 3, 2);
  const [first, second] = s.hitsFor('POST', lifecyclePath);
  expect(second?.key).not.toBe(first?.key);
  s.done();
});
