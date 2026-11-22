import { expect, test, type Page } from '@playwright/test';
import { decide } from '../fixtures/p0305/browser.js';
import { uuid, wire } from '../fixtures/p0305/mock.js';
import {
  category, city, cityPath, cityReads, companyReads, expectCommand, fixed, items, itemsPath, label, listing,
  otherCategory, period, pricePath, problem, receipt, rig, rulePath, rules,
} from '../fixtures/p0404/mock.js';

test.use({ serviceWorkers: 'block', trace: 'off', screenshot: 'off', video: 'off' });
const button = (page: Page, name: string) => page.getByRole('button', { name, exact: true });
const field = (page: Page, name: string) => page.getByLabel(name, { exact: true });
const status = (page: Page, text: RegExp) => page.getByRole('status').filter({ hasText: text });
const click = (page: Page, name: string) => button(page, name).click();
const restore = 'Восстановить черновик';
const retry = 'Проверить / повторить';
const success = /Операция подтверждена сервером/;
async function confirm(page: Page, name: string) {
  const dialog = decide(page, true);
  await click(page, name);
  await dialog;
}
async function selectCity(page: Page) {
  await click(page, 'Загрузить города');
  await field(page, 'Город').selectOption(city.id);
}

// MUST 1: the immutable create parent is part of the retained draft target.
test('denied PART create retains a draft only for the original category', async ({ page }) => {
  const s = await rig(page); companyReads(s);
  s.handlers.push((route, hit) => {
    if (hit.method === 'POST' && hit.path === itemsPath) { return problem(route, 403); }
  });
  const saved = { code: 'audit-part', unit: 'piece', kind: 'PART', categoryId: category.id };
  const categoryOption = `Выбрать: ${label(category)}`;
  await s.signIn(); await click(page, 'Каталог компании'); await click(page, 'Запчасти (PART)');
  await click(page, 'Загрузить варианты: Категория'); await click(page, categoryOption);
  await field(page, 'Код').fill(saved.code); await field(page, 'Единица измерения').fill(saved.unit);
  await click(page, 'Создать позицию');
  await expect(status(page, /прав|доступ/i)).toBeVisible();
  expect(s.hitsFor('POST', itemsPath)).toHaveLength(1);
  expectCommand(s.hitsFor('POST', itemsPath)[0], saved);
  await click(page, 'Запчасти (PART)');
  await expect(field(page, 'Код')).toHaveValue('');
  await expect(button(page, restore)).toHaveCount(0);
  await click(page, 'Загрузить варианты: Категория'); await click(page, `Выбрать: ${label(otherCategory)}`);
  await expect(field(page, 'Код')).toHaveValue(''); await expect(field(page, 'Единица измерения')).toHaveValue('');
  await expect(button(page, restore)).toHaveCount(0);
  await click(page, categoryOption);
  await expect(field(page, 'Код')).toHaveValue('');
  await click(page, restore);
  await expect(field(page, 'Код')).toHaveValue(saved.code); await expect(field(page, 'Единица измерения')).toHaveValue(saved.unit);
  await click(page, 'Снять выбор: Категория');
  await expect(field(page, 'Код')).toHaveValue(''); await expect(field(page, 'Единица измерения')).toHaveValue('');
  expect(s.hitsFor('POST', itemsPath)).toHaveLength(1);
  s.done();
});

// MUST 2: missing category labels must not silently turn a restricted rule into an unrestricted one.
test('stale rule draft refuses restore while its category is off the loaded page', async ({ page }) => {
  const s = await rig(page);
  const path = rulePath('EXPRESS');
  const categories = [category, otherCategory].map(({ id, code, title }) => ({ id, code, title }));
  let stale = false;
  s.handlers.push((route, hit) => {
    if (hit.method === 'GET' && hit.path === `${cityPath}/categories`) {
      const cursor = hit.url.searchParams.get('cursor');
      if (cursor === 'next') { return wire(route, listing(categories.slice(0, 1))); }
      if (cursor === null) { return wire(route, stale ? listing(categories.slice(1), 'next') : listing(categories)); }
    }
    if (hit.method === 'GET' && hit.path === path) {
      const existing = { id: uuid(640), seriesId: uuid(642), cityId: city.id, cityVersionId: fixed.cityVersionId,
        version: 1, validFrom: fixed.validFrom, validUntil: null, effectiveUntil: null, publishedAt: fixed.publishedAt,
        ruleId: rules.EXPRESS.id, kind: 'EXPRESS', title: 'Опубликованный тариф QA' };
      return wire(route, { ...listing(stale ? [existing] : []), version: stale ? 1 : 0 });
    }
    if (hit.method === 'POST' && hit.path === path) { stale = true; return problem(route, 412); }
  });
  cityReads(s);
  const saved = { ...period, kind: 'EXPRESS', title: 'Редакция правила QA', currency: 'RUB', base: 'WORKS',
    method: 'FIXED', minBase: null, maxBase: null, minDelta: null, maxDelta: null, categoryIds: [category.id], fixedMinor: '1200', rateBps: null };
  async function openRule() {
    await selectCity(page); await click(page, 'Тарифные правила'); await click(page, 'Загрузить правила города');
    await field(page, 'Правило').selectOption(rules.EXPRESS.id);
    await click(page, 'Загрузить категории города'); await click(page, 'Загрузить историю версий');
  }
  await s.signIn(); await click(page, 'Городские цены и тарифы'); await openRule();
  await field(page, 'Название').fill(saved.title);
  await field(page, 'Валюта').fill(saved.currency);
  await field(page, 'Начало действия (UTC)').fill(saved.validFrom);
  await field(page, 'Источник').fill(saved.sourceRef);
  await field(page, 'Основание расчёта').selectOption(saved.base);
  await field(page, 'Метод').selectOption(saved.method);
  await field(page, 'Фиксированная дельта (минорные единицы)').fill(saved.fixedMinor);
  const chosen = field(page, 'Категории правила');
  await chosen.selectOption(category.id);
  await confirm(page, 'Опубликовать правило');
  await expect(status(page, /Версия изменилась/)).toBeVisible();
  expectCommand(s.hitsFor('POST', path)[0], saved, 0);
  await openRule();
  await expect(chosen.locator('option')).toHaveText([label(otherCategory)]);
  await click(page, restore);
  await expect(page.getByRole('alert').filter({ hasText: /вариант.*недоступ|загрузите.*вариант/i })).toBeVisible();
  await expect(field(page, 'Название')).toHaveValue('');
  await expect(chosen).toHaveValues([]);
  await expect(button(page, 'Убрать черновик')).toBeVisible();
  await expect(button(page, 'Опубликовать правило')).toBeDisabled();
  expect(s.hitsFor('POST', path)).toHaveLength(1);
  await click(page, 'Загрузить ещё: Загрузить категории города');
  await click(page, restore);
  await expect(chosen).toHaveValues([category.id]);
  await expect(field(page, 'Название')).toHaveValue(saved.title);
  await chosen.selectOption([]);
  await click(page, 'Опубликовать правило');
  await expect(page.getByRole('alert').filter({ hasText: /Исходный набор вариантов изменился/ })).toBeVisible();
  expect(s.hitsFor('POST', path)).toHaveLength(1);
  await chosen.selectOption(category.id);
  await confirm(page, 'Опубликовать правило');
  await expect(status(page, /Версия изменилась/)).toBeVisible();
  expect(s.hitsFor('POST', path)).toHaveLength(2);
  expectCommand(s.hitsFor('POST', path)[1], saved, 1);
  s.done();
});

// MUST 3: a syntactically valid receipt for the wrong stream cannot acknowledge the command.
test('wrong fixed-close stream receipt stays uncertain; explicit replay keeps the exact request', async ({ page }) => {
  const s = await rig(page); cityReads(s);
  const history = pricePath('PART');
  const revision = `${history}/${fixed.id}`;
  const close = `${revision}/close`;
  let posts = 0;
  s.handlers.push((route, hit) => {
    if (hit.method === 'GET' && hit.path === history) { return wire(route, { ...listing([fixed]), version: 1 }); }
    if (hit.method === 'GET' && hit.path === revision) { return wire(route, fixed); }
    if (hit.method === 'POST' && hit.path === close) {
      return receipt(route, ++posts === 1 ? uuid(641) : fixed.seriesId, 2, undefined, 200);
    }
  });
  await s.signIn(); await click(page, 'Городские цены и тарифы'); await selectCity(page);
  await click(page, 'Фиксированные цены'); await click(page, 'Загрузить позиции города');
  await field(page, 'Позиция').selectOption(items.PART.id);
  await click(page, 'Загрузить историю версий'); await field(page, 'Версия').selectOption(fixed.id);
  await field(page, 'Граница закрытия (UTC)').fill(period.validFrom);
  await confirm(page, 'Закрыть цену');
  await expect(status(page, /Результат операции не подтверждён/)).toBeVisible();
  await expect(status(page, success)).toHaveCount(0);
  expect(s.hitsFor('POST', close)).toHaveLength(1);
  await click(page, retry);
  await expect(status(page, success)).toBeVisible();
  await expect(button(page, retry)).toHaveCount(0);
  const hits = s.hitsFor('POST', close);
  expect(hits).toHaveLength(2);
  for (const hit of hits) { expectCommand(hit, { at: period.validFrom }, 1); }
  const [first, second] = hits;
  expect([second?.url.href, second?.key, second?.tag, second?.body]).toEqual([first?.url.href, first?.key, first?.tag, first?.body]);
  s.done();
});

// MUST 4: correct aggregate ID and ETag do not prove that a NEW period was appended.
test('fixed replacement rejects a wrong sequence and then the closed revision ID on explicit replay', async ({ page }) => {
  const s = await rig(page); cityReads(s);
  const history = pricePath('PART');
  const exact = `${history}/${fixed.id}`;
  const replace = `${exact}/replace`;
  const replacement = { at: period.validFrom, validUntil: null, amountMinor: '2250', currency: 'RUB', zeroBasis: null, sourceRef: period.sourceRef };
  let posts = 0;
  s.handlers.push((route, hit) => {
    if (hit.method === 'GET' && hit.path === history) { return wire(route, { ...listing([fixed]), version: 1 }); }
    if (hit.method === 'GET' && hit.path === exact) { return wire(route, fixed); }
    if (hit.method === 'POST' && hit.path === replace) {
      posts++;
      return wire(route, { id: fixed.seriesId, version: 2, revisionVersion: posts === 1 ? 1 : 2,
        revisionId: posts === 2 ? fixed.id : uuid(644) }, posts === 1 ? 201 : 200, '"p04-v2"');
    }
  });
  await s.signIn(); await click(page, 'Городские цены и тарифы'); await selectCity(page);
  await click(page, 'Фиксированные цены'); await click(page, 'Загрузить позиции города');
  await field(page, 'Позиция').selectOption(items.PART.id);
  await click(page, 'Загрузить историю версий'); await field(page, 'Версия').selectOption(fixed.id);
  const form = page.getByRole('group', { name: 'Заменить цену', exact: true });
  await form.getByLabel('Граница замены (UTC)', { exact: true }).fill(replacement.at);
  await form.getByLabel('Сумма (минорные единицы)', { exact: true }).fill(replacement.amountMinor);
  await form.getByLabel('Валюта', { exact: true }).fill(replacement.currency);
  await form.getByLabel('Источник', { exact: true }).fill(replacement.sourceRef);
  await confirm(page, 'Заменить цену');
  await expect(status(page, /Результат операции не подтверждён/)).toBeVisible();
  await expect(status(page, success)).toHaveCount(0);
  expect(s.hitsFor('POST', replace)).toHaveLength(1);
  await click(page, retry);
  await expect(status(page, /Результат операции не подтверждён/)).toBeVisible();
  await expect(status(page, success)).toHaveCount(0);
  expect(s.hitsFor('POST', replace)).toHaveLength(2);
  await click(page, retry);
  await expect(status(page, success)).toBeVisible();
  const hits = s.hitsFor('POST', replace);
  expect(hits).toHaveLength(3);
  for (const hit of hits) { expectCommand(hit, replacement, 1); }
  const exactRequests = hits.map(hit => [hit.url.href, hit.key, hit.tag, hit.body]);
  expect(exactRequests[1]).toEqual(exactRequests[0]); expect(exactRequests[2]).toEqual(exactRequests[0]);
  s.done();
});
