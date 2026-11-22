import { expect, type Page, type Route, type Request } from '@playwright/test';
import { P03_CAPABILITIES, P03_CAPABILITY_METADATA } from '../../../p03-contracts/src/policy.js';
import type { P03Grant } from '../../../p03-contracts/src/policy.js';
import { allowedAsset, apiPrefix, mockOrigin, signIn } from './browser.js';

export const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const id = { actor: uuid(1), manager: uuid(2), adminRole: uuid(3), managerRole: uuid(4), techRole: uuid(5), city: uuid(6), cityVersion: uuid(7), item: uuid(8), revision: uuid(9), bootstrap: uuid(10) };
export const timestamp = '2026-11-21T09:00:00.000Z';
export const adminGrants: P03Grant[] = P03_CAPABILITIES.map(code => ({ code, scope: 'GLOBAL' }));
export const geoGrants = ['geography.read', 'geography.manage', 'geography.publish', 'staff.geography.read', 'staff.geography.manage'].map(code => ({ code, scope: 'GLOBAL' }));
export const roles = [['ADMIN', 'Администратор', id.adminRole], ['MANAGER', 'Менеджер', id.managerRole], ['TECHNICIAN', 'Мастер', id.techRole]].map(([code, name, roleId]) => ({ id: roleId, code, name, type: 'SYSTEM', status: 'ACTIVE', version: 2,
  assignedCount: 2, activeAssignedCount: 2, updatedAt: timestamp, updatedBy: null, description: 'Синтетическая роль', permissions: [] }));
const catalog = P03_CAPABILITIES.map(code => ({ code, ...P03_CAPABILITY_METADATA[code], scope: P03_CAPABILITY_METADATA[code].scopes[0] }));
export function list<T>(items: readonly T[], cursor: string | null = null) { return { items, pageInfo: { hasMore: cursor !== null, nextCursor: cursor } }; }
export function wire(route: Route, data: unknown, status = 200, etag?: string) {
  return route.fulfill({ status, json: { data, meta: { requestId: uuid(99) } }, headers: { 'cache-control': 'no-store', ...(etag ? { etag } : {}) } });
}
export function rejected(route: Route, status: number) {
  return route.fulfill({ status, json: { type: 'about:blank', title: 'REQUEST_REJECTED', status, code: 'REQUEST_REJECTED', requestId: uuid(99) }, headers: { 'cache-control': 'no-store' } });
}
export interface Hit { readonly method: string; readonly path: string; readonly url: URL; readonly tag: string | undefined; readonly key: string | undefined; readonly body: string | null; readonly request: Request }
export type Handler = (route: Route, hit: Hit) => Promise<void> | undefined;
export async function arrange(page: Page, options: { manager?: boolean; grants?: P03Grant[]; geo?: typeof geoGrants; standard?: string[] } = {}) {
  let signedIn = false;
  const access = { staffId: options.manager ? id.manager : id.actor, role: { id: options.manager ? id.managerRole : id.adminRole,
    code: options.manager ? 'MANAGER' : 'ADMIN', type: 'SYSTEM' }, permissions: options.standard ?? ['roles.read', 'roles.permissions.manage', 'staff.read'],
    geoPermissions: options.geo ?? geoGrants, p03Permissions: options.grants ?? adminGrants.slice() };
  const identity = { staffId: access.staffId, authVersion: 1, csrfToken: 'x'.repeat(43) };
  const faults = { me: false, access: false };
  const unknown: string[] = [];
  const hits: Hit[] = [];
  const handlers: Handler[] = [];
  await page.context().route('**/*', async route => {
    const request = route.request(), method = request.method(), url = new URL(request.url());
    if (url.origin !== mockOrigin) { unknown.push('unexpected origin'); await route.abort(); return; }
    if (!url.pathname.startsWith(`${apiPrefix}/`)) {
      if (method === 'GET' && allowedAsset(url.pathname)) { await route.continue(); return; }
      unknown.push('unexpected asset'); await route.abort(); return;
    }
    const path = url.pathname.slice(apiPrefix.length), headers = request.headers();
    // Login/password payloads and CSRF values aren't retained in request evidence.
    const hit = { method, path, url, tag: headers['if-match'], key: headers['idempotency-key'], body: /^\/auth\//.test(path) ? null : request.postData(), request };
    if (!/^\/auth\//.test(path)) { hits.push(hit); }
    if (path === '/auth/me' && method === 'GET' && headers['x-auth-request'] === '1') {
      if (signedIn && !faults.me) { await wire(route, identity); } else { await rejected(route, faults.me ? 503 : 401); } return;
    }
    if (path === '/auth/login' && method === 'POST' && headers['x-csrf-token'] === 'login') { signedIn = true; await wire(route, identity); return; }
    if (path === '/auth/logout' && signedIn && method === 'POST') { signedIn = false; await route.fulfill({ status: 204 }); return; }
    if (!signedIn) { unknown.push('unexpected anonymous API request'); await route.abort(); return; }
    for (const handler of handlers) {
      const handled = handler(route, hit); if (handled) { await handled; return; }
    }
    if (method === 'GET') {
      if (path === '/access') { if (faults.access) { await rejected(route, 503); } else { await wire(route, access); } return; }
      if (path === '/staff') { await wire(route, list([])); return; }
      if (path === '/permissions') { await wire(route, list(catalog)); return; }
      if (path === '/roles') { await wire(route, list(roles)); return; }
      const role = roles.find(r => path === `/roles/${r.id ?? ''}`);
      if (role) { await wire(route, role); return; }
    }
    unknown.push(`${method} ${path}`); await route.abort();
  });
  const hitsFor = (method: string, path: string) => hits.filter(hit => hit.method === method && hit.path === path);
  return { handlers, access, identity, faults, hitsFor, hits,
    signIn: () => signIn(page, mockOrigin, { login: 'synthetic-ui', password: 'synthetic-ui-only' }),
    done: () => { expect(unknown).toEqual([]); },
  };
}
