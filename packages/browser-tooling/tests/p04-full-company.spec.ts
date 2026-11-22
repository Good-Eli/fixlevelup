import { expect, test, type Page } from '@playwright/test';
import { timestamp, uuid, wire } from '../fixtures/p0305/mock.js';
import { category, directories, expectCommand, label, listing, rig, tag } from '../fixtures/p0404/mock.js';

test.use({ serviceWorkers: 'block', trace: 'off', screenshot: 'off', video: 'off' });
const button = (page: Page, name: string) => page.getByRole('button', { name, exact: true });
const click = (page: Page, name: string) => button(page, name).click();
const status = (page: Page, text: RegExp) => page.getByRole('status').filter({ hasText: text });
const success = /Операция подтверждена сервером/;
const uncertain = /Результат операции не подтверждён/;
const retry = 'Проверить / повторить';
const current = { id: uuid(720), entryId: category.id, version: 2, title: 'Текущая техника QA', description: null, publishedAt: timestamp };
const entry = { ...category, version: 3, currentVersionId: current.id, title: current.title };
const detail = `${directories.CATEGORY}/${entry.id}`;
const versions = `${detail}/versions`;
const revision = `${versions}/${current.id}`;
async function openCurrent(page: Page) {
  await click(page, 'Каталог компании'); await click(page, 'Загрузить категории'); await click(page, label(entry));
  await expect(button(page, 'Опубликовать версию')).toHaveCount(0);
  await click(page, 'Загрузить текущую версию');
}

test('company publication rejects a wrong sequence and the previous revision ID, then accepts an exact replay', async ({ page }) => {
  const s = await rig(page);
  const body = { title: 'Следующая версия техники QA', description: null };
  let posts = 0;
  s.handlers.push((route, hit) => {
    if (hit.method === 'GET' && hit.path === directories.CATEGORY) { return wire(route, listing([entry])); }
    if (hit.method === 'GET' && hit.path === detail) { return wire(route, entry); }
    if (hit.method === 'GET' && hit.path === revision) { return wire(route, current); }
    if (hit.method === 'POST' && hit.path === versions) {
      posts++;
      return wire(route, { id: entry.id, version: 4, revisionVersion: posts === 1 ? 1 : 3,
        revisionId: posts === 2 ? current.id : uuid(721) }, posts === 1 ? 201 : 200, tag(4));
    }
  });
  await s.signIn(); await openCurrent(page);
  const title = page.getByLabel('Название', { exact: true });
  await expect(title).toHaveValue(current.title);
  await title.fill(body.title); await click(page, 'Опубликовать версию');
  await expect(status(page, uncertain)).toBeVisible();
  await expect(status(page, success)).toHaveCount(0);
  expect(s.hitsFor('POST', versions)).toHaveLength(1);
  await click(page, retry);
  await expect(status(page, uncertain)).toBeVisible();
  await expect(status(page, success)).toHaveCount(0);
  expect(s.hitsFor('POST', versions)).toHaveLength(2);
  await click(page, retry);
  await expect(status(page, success)).toBeVisible();
  await expect(button(page, retry)).toHaveCount(0);
  const hits = s.hitsFor('POST', versions);
  expect(hits).toHaveLength(3);
  for (const hit of hits) { expectCommand(hit, body, 3); }
  const sent = hits.map(hit => [hit.url.href, hit.key, hit.tag, hit.body]);
  expect(sent[1]).toEqual(sent[0]); expect(sent[2]).toEqual(sent[0]);
  s.done();
});

test('company publication is unavailable when the exact current sequence conflicts with the card', async ({ page }) => {
  const s = await rig(page);
  s.handlers.push((route, hit) => {
    if (hit.method === 'GET' && hit.path === directories.CATEGORY) { return wire(route, listing([entry])); }
    if (hit.method === 'GET' && hit.path === detail) { return wire(route, entry); }
    if (hit.method === 'GET' && hit.path === revision) { return wire(route, { ...current, version: 1 }); }
  });
  await s.signIn(); await openCurrent(page);
  await expect(status(page, /Карточка изменилась/)).toBeVisible();
  await expect(button(page, 'Опубликовать версию')).toHaveCount(0);
  await click(page, 'Получить актуальную карточку');
  await expect(button(page, 'Загрузить текущую версию')).toBeVisible();
  expect(s.hitsFor('GET', detail)).toHaveLength(2);
  expect(s.hitsFor('POST', versions)).toHaveLength(0);
  s.done();
});
