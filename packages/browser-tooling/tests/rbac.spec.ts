import { expect, test, type Page } from '@playwright/test';

// Only the production Next bundle talks to these synthetic, in-browser responses.
// This verifies UI behavior, not Nest/DB enforcement (tested independently).
const origin = 'http://127.0.0.1:4170';
const actor = '22222222-2222-4222-8222-222222222222';
const target = '33333333-3333-4333-8333-333333333333';
const roleId = '44444444-4444-4444-8444-444444444444';
const csrf = 'x'.repeat(43);
const person = {id:target,roleId:target,role:'TECHNICIAN',roleName:'Мастер',displayName:'Тестовый мастер',employmentState:'ACTIVE',version:2};
const role = {id:roleId,code:'CUSTOM_TEST',name:'Тестовая роль',description:'Пример',type:'CUSTOM',status:'ACTIVE',version:3,assignedCount:1,activeAssignedCount:1,updatedAt:'2026-11-20T00:00:00Z',updatedBy:null,permissions:[]};
const permissions = ['staff.read','staff.deactivate','staff.role.assign','roles.read','roles.create','roles.archive','roles.permissions.manage'];
const catalog = [{code:'staff.read',description:'Просмотр сотрудников',module:'staff',scope:'GLOBAL',protected:false},
  {code:'roles.archive',description:'Архивирование роли',module:'roles',scope:'GLOBAL',protected:true}];
const list = (items: unknown[]) => ({items,pageInfo:{hasMore:false,nextCursor:null}});
async function server(page: Page, caps: string[], authenticated = false) {
  const calls: string[] = []; const unexpected: string[] = []; let tag = ''; let writes = 0;
  await page.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    if (url.origin !== origin) { unexpected.push(url.origin); await route.abort(); return; }
    if (!url.pathname.startsWith('/api/v1/')) { await route.continue(); return; }
    const path = url.pathname.slice('/api/v1/'.length); const key = `${request.method()} ${path}`; calls.push(key);
    let data: unknown; let status = 200;
    switch (key) {
      case 'GET auth/me': status = authenticated ? 200 : 401; data = {staffId:actor,csrfToken:csrf}; break;
      case 'POST auth/login': authenticated = request.headers()['x-csrf-token'] === 'login'; status = authenticated ? 200 : 403; data = {staffId:actor,csrfToken:csrf}; break;
      case 'GET access': data = {staffId:actor,role:{id:actor,code:'ADMIN',type:'SYSTEM'},permissions:caps}; break;
      case 'GET staff': data = list([person]); break;
      case `GET staff/${target}`: data = person; break;
      case 'GET roles': data = list([role, {...role,id:actor,type:'SYSTEM',code:'ADMIN'},
        {...role,id:'55555555-5555-4555-8555-555555555555',code:'CUSTOM_STRONG',permissions:[{code:'staff.update',scope:'GLOBAL'}]}]); break;
      case `GET roles/${roleId}`: data = role; break;
      case 'GET permissions': data = list(catalog); break;
      case `PUT roles/${roleId}/permissions`: writes++; tag = request.headers()['if-match'] ?? ''; status = request.headers()['x-csrf-token'] === csrf ? 412 : 403; break;
      case 'POST auth/logout': authenticated = false; await route.fulfill({status:204}); return;
      default: unexpected.push(key); status = 404;
    }
    await route.fulfill({status,json:{data,meta:{requestId:'offline-test'}}});
  });
  return {calls, unexpected, tag:() => tag, writes:() => writes};
}
test('closed CRM login, restricted role editor, cancel, stale mutation and logout', async ({ page }) => {
  const backend = await server(page,permissions);
  await page.goto(`${origin}/crm/access`);
  await expect(page.getByRole('heading',{name:'Вход для сотрудников'})).toBeVisible();
  expect(backend.calls).toEqual(['GET auth/me']);
  await page.getByLabel('Логин').fill('synthetic'); await page.getByLabel('Пароль').fill('fixture'); await page.getByRole('button',{name:'Войти'}).click();
  await page.getByRole('button',{name:person.displayName}).click();
  const choice = page.getByLabel('Новая роль');
  await expect(choice.locator('option')).toHaveText(['Выберите роль',`${role.name} · CUSTOM_TEST · пользовательская`,`${role.name} · ADMIN · системная`]);
  await choice.selectOption(actor);
  page.once('dialog', async dialog => { expect(dialog.message()).toContain(`${role.name} · ADMIN · системная`); await dialog.dismiss(); });
  await page.getByRole('button',{name:'Сменить роль'}).click();
  page.once('dialog', async dialog => { expect(dialog.message()).toContain('Затронут 1 сотрудник'); await dialog.dismiss(); });
  await page.getByRole('button',{name:'Деактивировать сотрудника'}).click();
  await page.getByRole('button',{name:'Роли и возможности'}).click(); await page.getByRole('button',{name:`${role.name} · CUSTOM_TEST · пользовательская`}).click();
  await expect(page.getByRole('checkbox',{name:/Архивирование роли/})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Архивировать роль'})).toBeDisabled();
  await page.getByRole('checkbox',{name:/Просмотр сотрудников/}).check();
  page.once('dialog', async dialog => { expect(dialog.message()).toContain('Назначено сотрудников: 1'); await dialog.accept(); });
  await page.getByRole('button',{name:'Сохранить возможности'}).click();
  await expect(page.getByRole('status').filter({hasText:'Версия изменилась'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Сохранить возможности'})).toHaveCount(0);
  expect(backend.tag()).toBe('"role-v3"'); expect(backend.writes()).toBe(1);
  await page.getByRole('button',{name:'Выйти'}).click(); await expect(page.getByRole('heading',{name:'Вход для сотрудников'})).toBeVisible();
  expect(backend.unexpected).toEqual([]); expect(backend.calls).not.toContain(`POST staff/${target}/deactivate`);
});
test('independent create-only access never loads staff, self or role catalogs', async ({page}) => {
  const backend = await server(page,['staff.create'],true); await page.goto(`${origin}/crm/access`);
  await expect(page.getByRole('button',{name:'Создать сотрудника'})).toBeVisible();
  await expect(page.getByText('Для текущей роли список сотрудников закрыт.')).toBeVisible();
  await page.getByRole('button',{name:'Роли и возможности'}).click(); await expect(page.getByText('Для текущей роли каталог и карточки ролей закрыты.')).toBeVisible();
  expect(backend.calls).toEqual(['GET auth/me','GET access']); expect(backend.unexpected).toEqual([]);
  await page.getByRole('button',{name:'Сотрудники',exact:true}).click();
  let writes = 0; let complete: () => void = () => { throw new Error('No request'); };
  await page.route('**/api/v1/staff', async route => {
    writes++; expect(route.request().method()).toBe('POST'); expect(route.request().headers()['x-csrf-token']).toBe(csrf);
    expect(route.request().postDataJSON()).toEqual({role:'TECHNICIAN',displayName:'Тест'});
    await new Promise<void>(resolve => { complete = resolve; });
    await route.fulfill({status:201,json:{data:{id:target,version:0},meta:{requestId:'offline-test'}}});
  });
  await page.getByLabel('Имя (необязательно)').fill('Тест'); const create = page.getByRole('button',{name:'Создать сотрудника'}); await create.click();
  await expect.poll(() => writes).toBe(1); await expect(create).toBeDisabled(); await expect(page.getByText('Профиль сотрудника создан.')).toHaveCount(0);
  complete(); await expect(page.getByText(`Профиль сотрудника создан. ID: ${target}. Версия: 0.`)).toBeVisible(); expect(writes).toBe(1);
  expect(backend.calls).toEqual(['GET auth/me','GET access','GET auth/me','GET access']);
});
for (const afterWrite of ['different actor','unavailable identity'] as const) {
  test(`confirmed creation stays private after ${afterWrite}`, async ({page}) => {
    const backend = await server(page,['staff.create'],true);
    await page.goto(`${origin}/crm/access`);
    const create = page.getByRole('button',{name:'Создать сотрудника'}); await expect(create).toBeEnabled();
    let writes = 0;
    await page.route('**/api/v1/staff', async route => {
      expect(route.request().method()).toBe('POST'); writes++;
      await route.fulfill({status:201,json:{data:{id:target,version:7}}});
    });
    await page.route('**/api/v1/auth/me', async route => {
      await route.fulfill(afterWrite === 'different actor' ? {status:200,json:{data:{staffId:roleId,csrfToken:csrf}}} : {status:503,json:{}});
    });
    await create.click(); const notice = page.getByRole('status');
    await expect(notice).toContainText('Сервер подтвердил операцию'); await expect(notice).toContainText('не отправляйте операцию повторно');
    await expect(page.getByRole('heading',{name:'Вход для сотрудников'})).toBeVisible();
    await expect(page.getByRole('main')).not.toContainText(target); await expect(page.getByRole('main')).not.toContainText('Версия: 7');
    await expect(create).toHaveCount(0); await expect(page.getByRole('button',{name:'Выйти'})).toHaveCount(0);
    expect(writes).toBe(1); expect(backend.calls).toEqual(['GET auth/me','GET access']); expect(backend.unexpected).toEqual([]);
  });
}
