import { P03_CAPABILITIES, P03_CAPABILITY_METADATA, isP03Capability, type P03Grant } from '@fixlevelup/p03-contracts';

// Relative URLs only. The reverse proxy, not the client, chooses the Nest host.
type Json = Record<string, unknown>;
type Decoder<T> = (value: unknown) => T;
function object(value: unknown): Json {
  if (!value || typeof value !== 'object' || Array.isArray(value)) { throw new Error('Invalid API response'); }
  return value as Json;
}
function text(value: unknown): string {
  if (typeof value !== 'string') { throw new Error('Invalid API response'); }
  return value;
}
function count(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) { throw new Error('Invalid version/count'); }
  return value;
}
function bool(value: unknown): boolean {
  if (typeof value !== 'boolean') { throw new Error('Invalid API response'); } return value;
}
function nullable<T>(read: Decoder<T>, value: unknown): T | null { return value === null ? null : read(value); }
function array<T>(read: Decoder<T>, value: unknown): T[] {
  if (!Array.isArray(value)) { throw new Error('Invalid API list'); } return value.map(read);
}
function oneOf<const T extends string>(value: unknown, ...values: T[]): T {
  const found = values.find(x => x === value); if (!found) { throw new Error('Invalid API response'); } return found;
}
export const uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}';
function id(value: unknown): string {
  const result = text(value); if (!new RegExp(`^${uuidPattern}$`).test(result)) { throw new Error('Invalid resource ID'); } return result;
}
function roleType(v: unknown) { return oneOf(v, 'SYSTEM', 'CUSTOM'); }
function scope(v: unknown) { return oneOf(v, 'SELF', 'GLOBAL', 'CITY'); }

// P04-03 role-editor policy, not an authorization decision or an implicit grant.
const P04_SCOPES = {
  'catalog.read': ['GLOBAL'], 'catalog.manage': ['GLOBAL'],
  'pricing.rules.read': ['GLOBAL'], 'pricing.rules.manage': ['GLOBAL'],
  'pricing.read': ['CITY', 'GLOBAL'], 'pricing.manage': ['CITY', 'GLOBAL'],
  'content.externalreviews.read': ['GLOBAL'], 'content.externalreviews.manage': ['GLOBAL'],
  'content.externalreviews.publish': ['GLOBAL'],
} as const;
export type P04Capability = keyof typeof P04_SCOPES;
export type P04Scope = 'GLOBAL' | 'CITY';
export interface P04Grant { readonly code: P04Capability; readonly scope: P04Scope }
export function isP04Capability(value: unknown): value is P04Capability {
  return typeof value === 'string' && Object.hasOwn(P04_SCOPES, value);
}
export function p04Scopes(role: { type: 'SYSTEM' | 'CUSTOM'; code: string }, code: P04Capability): readonly P04Scope[] {
  const scopes: readonly P04Scope[] = P04_SCOPES[code];
  if (role.type === 'SYSTEM' && role.code === 'ADMIN') { return scopes; }
  return role.type === 'CUSTOM' || role.code === 'MANAGER' ? scopes.filter(s => s === 'CITY') : [];
}
function checkP04RoleGrants(role: { type: 'SYSTEM' | 'CUSTOM'; code: string }, grants: readonly Grant[]): void {
  const seen = new Set<P04Capability>();
  for (const g of grants) {
    if (!isP04Capability(g.code)) { continue; }
    if (g.scope === 'SELF' || !p04Scopes(role, g.code).includes(g.scope) || seen.has(g.code)) { throw new Error('Invalid P04 grant'); }
    seen.add(g.code);
  }
}
function p04Grants(role: { type: 'SYSTEM' | 'CUSTOM'; code: string }, value: unknown): readonly P04Grant[] | undefined {
  if (value === undefined) { return undefined; }
  if (!Array.isArray(value) || value.length > Object.keys(P04_SCOPES).length) { throw new Error('Invalid P04 grant list'); }
  const grants = array<P04Grant>(v => {
    const g = object(v);
    const code = g['code'];
    if (Object.keys(g).length !== 2 || !isP04Capability(code)) { throw new Error('Invalid P04 grant'); }
    return { code, scope: oneOf(g['scope'], 'GLOBAL', 'CITY') };
  }, value);
  checkP04RoleGrants(role, grants);
  return grants;
}
function grant(value: unknown) { const r = object(value); return { code: text(r['code']), scope: scope(r['scope']) }; }
function permission(value: unknown) {
  const r = object(value);
  // `scopes` is the authoritative list for a target role; legacy `scope` stays supported.
  const scopes = r['scopes'] === undefined ? [scope(r['scope'])] : array(scope, r['scopes']);
  if (!scopes.length) { throw new Error('Invalid scope list'); }
  const item = { ...grant(r), description: text(r['description']), module: text(r['module']), protected: bool(r['protected']), scopes };
  if (isP04Capability(item.code)) {
    const expected: readonly string[] = P04_SCOPES[item.code];
    if (item.protected || item.module !== item.code.split('.')[0] || item.scope !== expected[0]
      || scopes.length !== expected.length || expected.some(s => !scopes.some(actual => actual === s))) {
      throw new Error('Invalid P04 catalog permission');
    }
  }
  return item;
}
function role(value: unknown) {
  const r = object(value);
  const decoded = { id: id(r['id']), code: text(r['code']), name: text(r['name']), description: nullable(text, r['description']),
    type: roleType(r['type']), status: oneOf(r['status'], 'ACTIVE', 'ARCHIVED'), version: count(r['version']), assignedCount: nullable(count, r['assignedCount']),
    activeAssignedCount: nullable(count, r['activeAssignedCount']), updatedAt: text(r['updatedAt']), updatedBy: nullable(id, r['updatedBy']), permissions: array(grant, r['permissions']) };
  checkP04RoleGrants(decoded, decoded.permissions);
  return decoded;
}
function staff(value: unknown) {
  const r = object(value); return { id: id(r['id']), role: text(r['role']), roleId: id(r['roleId']), roleName: text(r['roleName']),
    employmentState: oneOf(r['employmentState'], 'ACTIVE', 'INACTIVE'), displayName: nullable(text, r['displayName']), version: count(r['version']) };
}
function identity(value: unknown) {
  const r = object(value); const csrf = text(r['csrfToken']);
  if (!/^[A-Za-z0-9_-]{43}$/.test(csrf)) { throw new Error('Invalid CSRF response'); }
  const authVersion = r['authVersion'] === undefined ? undefined : count(r['authVersion']);
  return { staffId: id(r['staffId']), csrf, authVersion };
}
export type Identity = ReturnType<typeof identity>;
export interface GeoGrantView { code: string; scope: 'GLOBAL' | 'CITY' }
function access(value: unknown): { staffId: string; role: { id: string; code: string; type: 'SYSTEM' | 'CUSTOM' }; permissions: string[]; geoPermissions?: GeoGrantView[]; p03Permissions?: readonly P03Grant[]; p04Permissions?: readonly P04Grant[] } {
  const r = object(value); const rawRole = object(r['role']);
  const role = { id: id(rawRole['id']), code: text(rawRole['code']), type: roleType(rawRole['type']) };
  const p04 = p04Grants(role, r['p04Permissions']);
  // Individual geography grants (code + GLOBAL/CITY) as resolved by the server session.
  // Optional so an older/absent field can never be read as an implicit grant.
  const geo = r['geoPermissions'] === undefined ? undefined
    : array(v => { const g = object(v); return { code: text(g['code']), scope: oneOf(g['scope'], 'GLOBAL', 'CITY') }; }, r['geoPermissions']);
  const raw = r['p03Permissions'];
  if (raw !== undefined && (!Array.isArray(raw) || raw.length > P03_CAPABILITIES.length)) { throw new Error('Invalid P03 grant list'); }
  const p03 = raw === undefined ? undefined : array<P03Grant>(v => {
    const g = object(v); const code = g['code']; const scope = oneOf(g['scope'], 'GLOBAL', 'CITY');
    if (!isP03Capability(code) || !P03_CAPABILITY_METADATA[code].scopes.includes(scope)) { throw new Error('Invalid P03 grant'); }
    return { code, scope };
  }, raw);
  if (p03 && new Set(p03.map(g => g.code)).size !== p03.length) { throw new Error('Duplicate P03 grant'); }
  return { staffId: id(r['staffId']), role, permissions: array(text, r['permissions']),
    ...(geo === undefined ? {} : { geoPermissions: geo }), ...(p03 === undefined ? {} : { p03Permissions: p03 }),
    ...(p04 === undefined ? {} : { p04Permissions: p04 }) };
}
function list<T>(read: Decoder<T>) { return (v: unknown) => array(read, object(v)['items']); }
function permissionCatalog(value: unknown) {
  const permissions = list(permission)(value);
  const p04 = permissions.filter(p => isP04Capability(p.code));
  if (new Set(p04.map(p => p.code)).size !== p04.length) { throw new Error('Duplicate P04 catalog permission'); }
  return permissions;
}
function receipt(value: unknown) {
  const r = object(value); return { id: id(r['id']), version: count(r['version']) };
}
export type Access = ReturnType<typeof access>;
export type Role = ReturnType<typeof role>;
export type Person = ReturnType<typeof staff>;
export type Permission = ReturnType<typeof permission>;
export type Grant = ReturnType<typeof grant>;
export class ApiError extends Error { constructor(readonly status: number) { super(`HTTP ${String(status)}`); } }
export function errorMessage(e: unknown) {
  if (e instanceof ApiError) {
    switch (e.status) {
      case 400: return 'Сервер отклонил введённые данные. Проверьте поля.';
      case 401: return 'Сессия отсутствует или истекла. Войдите снова.';
      case 403: return 'Действие запрещено. Проверьте актуальные права доступа.';
      case 404: return 'Объект недоступен или не найден.';
      case 409: return 'Конфликт состояния: операция не выполнена. Проверьте назначение, статус и защиту последнего администратора.';
      case 412: case 428: return 'Версия изменилась или не указана. Проверьте актуальные данные перед повторной отправкой.';
      case 429: return 'Слишком много запросов. Повторите позже.';
    }
  }
  return 'Нет подтверждения от сервера. Обновите данные перед повторной отправкой.';
}
export function api(signal: AbortSignal, csrf?: string) {
  async function request<T>(path: string, read: Decoder<T>, method = 'GET', body?: object, etag?: string): Promise<T> {
    const headers = new Headers({ Accept: 'application/json', 'X-Auth-Request': '1' });
    if (method !== 'GET') {
      const token = path === 'auth/login' ? 'login' : csrf;
      if (!token) { throw new Error('Missing CSRF'); }
      headers.set('Content-Type', 'application/json'); headers.set('X-CSRF-Token', token);
      if (etag) { headers.set('If-Match', etag); }
    }
    const res = await fetch(`/api/v1/${path}`, { method, headers, signal, credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error',
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (!res.ok) { throw new ApiError(res.status); }
    return read(res.status === 204 ? null : object(await res.json())['data']);
  }
  const staffPath = (target: string) => target === 'self' ? 'staff/self' : `staff/${id(target)}`;
  const rolePath = (target: string) => `roles/${id(target)}`;
  const tag = (resource: 'staff'|'role', version: number) => `"${resource}-v${String(count(version))}"`;
  return {
    me: () => request('auth/me', identity), login: (login: string, password: string) => request('auth/login', identity, 'POST', { login, password }),
    logout: () => request('auth/logout', v => { if (v !== null) { throw new Error('Unexpected logout response'); } }, 'POST', {}),
    access: () => request('access', access), roles: () => request('roles', list(role)), staff: () => request('staff', list(staff)),
    catalog: () => request('permissions', permissionCatalog), role: (target: string) => request(rolePath(target), role),
    person: (target: string) => request(staffPath(target), staff), members: (target: string) => request(`${rolePath(target)}/staff`, list(staff)),
    createRole: (name: string, description: string) => request('roles', receipt, 'POST', { name, description }),
    editRole: (target: Role, name: string, description: string) => request(rolePath(target.id), receipt, 'PATCH', { name, description }, tag('role', target.version)),
    permissions: (target: Role, permissions: Grant[]) => request(`${rolePath(target.id)}/permissions`, receipt, 'PUT', { permissions }, tag('role', target.version)),
    archive: (target: Role) => request(`${rolePath(target.id)}/archive`, receipt, 'POST', {}, tag('role', target.version)),
    createPerson: (role: 'TECHNICIAN'|'MANAGER', displayName: string) => request('staff', receipt, 'POST', { role, ...(displayName ? { displayName } : {}) }),
    rename: (target: string, version: number, displayName: string) => request(staffPath(target), receipt, 'PATCH', { displayName }, tag('staff', version)),
    assign: (target: string, version: number, roleId: string) => request(`staff/${id(target)}/role`, receipt, 'PUT', { roleId: id(roleId) }, tag('staff', version)),
    deactivate: (target: string, version: number) => request(`${staffPath(target)}/deactivate`, receipt, 'POST', {}, tag('staff', version)),
  };
}
export type Client = ReturnType<typeof api>;
