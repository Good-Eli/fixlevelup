import { expect, test, type Page } from '@playwright/test';

// Only the production Next bundle talks to these synthetic, in-browser responses.
// This proves the *UI projection* of the P03-02 geography matrix: which scope the role
// editor offers for a target role and exactly what payload it would send. It is NOT an
// HTTP/Nest/PostgreSQL authorization proof (those are covered by the API integration
// suites); every response here is fabricated in the browser route handler.
const origin = 'http://127.0.0.1:4170';
const actor = '22222222-2222-4222-8222-222222222222';
const csrf = 'x'.repeat(43);
const managerRole = '66666666-6666-4666-8666-666666666666';
const adminRole = '77777777-7777-4777-8777-777777777777';
const technicianRole = '88888888-8888-4888-8888-888888888888';

const geo = (code: string, description: string) => ({ code, description, module: 'geography', scope: 'CITY', scopes: ['CITY', 'GLOBAL'], protected: false });
const catalog = [
  { code: 'roles.permissions.manage', description: 'Изменение возможностей роли', module: 'roles', scope: 'GLOBAL', scopes: ['GLOBAL'], protected: true },
  { code: 'staff.read', description: 'Просмотр сотрудников', module: 'staff', scope: 'GLOBAL', scopes: ['GLOBAL'], protected: false },
  geo('geography.read', 'Чтение города, районов и зон'),
  geo('geography.manage', 'Подготовка настроек города и зон'),
  geo('geography.publish', 'Публикация версий города и покрытия'),
  geo('staff.geography.read', 'Чтение территориальных допусков мастеров'),
  geo('staff.geography.manage', 'Выдача и отзыв допусков мастеров'),
];
// The founder administrator holds the five bootstrap geography codes as individual
// GLOBAL grants; the manager role holds none of them.
const founderGeo = ['geography.read', 'geography.manage', 'geography.publish', 'staff.geography.read', 'staff.geography.manage']
  .map(code => ({ code, scope: 'GLOBAL' as const }));
const role = (id: string, code: string, name: string) => ({
  id, code, name, description: 'Синтетическая роль', type: 'SYSTEM' as const, status: 'ACTIVE' as const, version: 2,
  assignedCount: 0, activeAssignedCount: 0, updatedAt: '2026-11-21T00:00:00Z', updatedBy: null, permissions: [],
});
const manager = role(managerRole, 'MANAGER', 'Менеджер');
const administrator = role(adminRole, 'ADMIN', 'Администратор');
const master = role(technicianRole, 'TECHNICIAN', 'Мастер');
const roles = [manager, administrator, master];
const list = (items: unknown[]) => ({ items, pageInfo: { hasMore: false, nextCursor: null } });
const label = (r: { name: string; code: string }) => `${r.name} · ${r.code} · системная`;

/** Same-origin synthetic API. Unknown calls are collected and fail the test, so the page
 * cannot silently reach a real backend or the network. */
async function server(page: Page) {
  const unexpected: string[] = [];
  const writes: { path: string; tag: string; body: unknown }[] = [];
  let authenticated = false;
  await page.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    if (url.origin !== origin) { unexpected.push(url.origin); await route.abort(); return; }
    if (!url.pathname.startsWith('/api/v1/')) { await route.continue(); return; }
    const path = url.pathname.slice('/api/v1/'.length); const key = `${request.method()} ${path}`;
    const found = roles.find(r => `GET roles/${r.id}` === key);
    const grant = /^PUT roles\/([^/]+)\/permissions$/.exec(key);
    let status = 200; let data: unknown;
    if (key === 'GET auth/me') { status = authenticated ? 200 : 401; data = { staffId: actor, csrfToken: csrf }; }
    else if (key === 'POST auth/login') { authenticated = request.headers()['x-csrf-token'] === 'login'; status = authenticated ? 200 : 403; data = { staffId: actor, csrfToken: csrf }; }
    else if (key === 'GET access') { data = { staffId: actor, role: { id: actor, code: 'ADMIN', type: 'SYSTEM' }, permissions: ['roles.read', 'roles.permissions.manage', 'staff.read'], geoPermissions: founderGeo }; }
    else if (key === 'GET roles') { data = list(roles); }
    else if (found) { data = found; }
    else if (key === 'GET permissions') { data = list(catalog); }
    else if (key === 'GET staff') { data = list([]); }
    else if (grant) {
      writes.push({ path: grant[1] ?? '', tag: request.headers()['if-match'] ?? '', body: request.postDataJSON() });
      data = { id: grant[1], version: 3 };
    } else if (key === 'POST auth/logout') { authenticated = false; await route.fulfill({ status: 204 }); return; }
    else { unexpected.push(key); status = 404; }
    await route.fulfill({ status, json: { data, meta: { requestId: 'offline-test' } } });
  });
  return { unexpected, writes };
}

async function openRole(page: Page, name: string) {
  await page.getByRole('button', { name: 'Роли и возможности' }).click();
  await page.getByRole('button', { name }).click();
}

/** The label element that wraps one catalog checkbox (description + code/scope hint). */
function entry(page: Page, name: RegExp) {
  const checkbox = page.getByRole('checkbox', { name });
  return { checkbox, label: page.locator('label.permission').filter({ has: checkbox }) };
}

test('manager role editor offers CITY only, disables publish and sends the CITY grant', async ({ page }) => {
  const backend = await server(page);
  await page.goto(`${origin}/crm/access`);
  await page.getByLabel('Логин').fill('synthetic'); await page.getByLabel('Пароль').fill('fixture');
  await page.getByRole('button', { name: 'Войти' }).click();
  await openRole(page, label(manager));
  // The manager role may only store CITY geography, so the read grant shows CITY and no
  // scope selector appears (the admin-only alternative is not offered at all).
  const read = entry(page, /Чтение города, районов и зон/);
  await expect(read.checkbox).toBeEnabled();
  await expect(read.label).toContainText('geography.read · CITY');
  await expect(read.label.locator('select')).toHaveCount(0);
  // Publishing geography is never a manager operation: the checkbox cannot be selected.
  await expect(page.getByRole('checkbox', { name: /Публикация версий города и покрытия/ })).toBeDisabled();
  await expect(page.getByRole('checkbox', { name: /Подготовка настроек города и зон/ })).toBeEnabled();
  // An explicit selection produces exactly one CITY grant, nothing implied.
  await read.checkbox.check();
  page.once('dialog', async dialog => { expect(dialog.message()).toContain('Изменить права роли'); await dialog.accept(); });
  await page.getByRole('button', { name: 'Сохранить возможности' }).click();
  await expect.poll(() => backend.writes.length).toBe(1);
  expect(backend.writes[0]).toEqual({ path: managerRole, tag: '"role-v2"', body: { permissions: [{ code: 'geography.read', scope: 'CITY' }] } });
  expect(backend.unexpected).toEqual([]);
});

test('GLOBAL geography is selectable only on the SYSTEM ADMIN role, never on the master channel role', async ({ page }) => {
  const backend = await server(page);
  await page.goto(`${origin}/crm/access`);
  await page.getByLabel('Логин').fill('synthetic'); await page.getByLabel('Пароль').fill('fixture');
  await page.getByRole('button', { name: 'Войти' }).click();
  await openRole(page, label(administrator));
  const read = entry(page, /Чтение города, районов и зон/);
  await expect(read.checkbox).toBeEnabled();
  await expect(read.label).toContainText('geography.read · CITY/GLOBAL');
  await read.checkbox.check();
  // Only the administrator role exposes the scope selector, and GLOBAL is a real choice.
  const scopes = read.label.locator('select');
  await expect(scopes.locator('option')).toHaveText(['CITY', 'GLOBAL']);
  await scopes.selectOption('GLOBAL');
  page.once('dialog', async dialog => { await dialog.accept(); });
  await page.getByRole('button', { name: 'Сохранить возможности' }).click();
  await expect.poll(() => backend.writes.length).toBe(1);
  expect(backend.writes[0]).toEqual({ path: adminRole, tag: '"role-v2"', body: { permissions: [{ code: 'geography.read', scope: 'GLOBAL' }] } });
  // The technician channel role never receives geography at all.
  await openRole(page, label(master));
  for (const name of [/Чтение города, районов и зон/, /Публикация версий города и покрытия/, /Выдача и отзыв допусков мастеров/]) {
    await expect(page.getByRole('checkbox', { name })).toBeDisabled();
  }
  await expect(page.getByRole('button', { name: 'Сохранить возможности' })).toBeDisabled();
  expect(backend.writes).toHaveLength(1);
  expect(backend.unexpected).toEqual([]);
});
