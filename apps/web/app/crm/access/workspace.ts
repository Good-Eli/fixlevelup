import type { Access, Client, Person, Permission, Role } from './api';

export function has(a: Access, code: string) { return a.permissions.includes(code); }
/** An individual geography grant as resolved by the server session (bootstrap or role). */
export function hasGeo(a: Access, code: string, scope?: 'GLOBAL' | 'CITY') {
  return (a.geoPermissions ?? []).some(g => g.code === code && (scope === undefined || g.scope === scope));
}
export function admin(a: Access) { return a.role.type === 'SYSTEM' && a.role.code === 'ADMIN'; }
export function protects(a: Access, code: string) { return admin(a) && has(a, code); }
export function canTarget(a: Access, person: Person) {
  return person.id !== a.staffId && person.employmentState === 'ACTIVE' && (admin(a) || person.role === 'TECHNICIAN');
}
/** Scopes the edited role may store for one catalog code: staff codes are fixed, while
 * geography GLOBAL and publish are restricted to the SYSTEM ADMIN role. */
export function allowedScopes(r: Role, p: Permission) {
  if (p.scopes.length === 1) { return p.scopes; }
  const targetAdmin = r.type === 'SYSTEM' && r.code === 'ADMIN';
  if ((r.type === 'SYSTEM' && r.code === 'TECHNICIAN') || (p.code === 'geography.publish' && !targetAdmin)) { return []; }
  return targetAdmin ? p.scopes : p.scopes.filter(s => s === 'CITY');
}
export function delegable(a: Access, r: Role) {
  return r.status === 'ACTIVE' && r.permissions.every(g => has(a, g.code) ||
    (g.scope === 'SELF' && ['staff.self.read','staff.self.update','staff.self.deactivate'].includes(g.code)) ||
    (g.scope !== 'SELF' && hasGeo(a, g.code, 'GLOBAL') && (g.scope === 'CITY' || (r.type === 'SYSTEM' && r.code === 'ADMIN')) &&
      (g.code !== 'geography.publish' || (r.type === 'SYSTEM' && r.code === 'ADMIN'))));
}
export function roleLabel(r: Role) { return `${r.name} · ${r.code} · ${r.type === 'SYSTEM' ? 'системная' : 'пользовательская'}`; }
/** A grant may be edited when the actor already holds it, or when it is retained from the
 * current set (retention is not delegation). Geography additionally requires the actor's
 * own GLOBAL grant and a scope the target role may legally hold; a code-only call is the
 * legacy staff form and keeps the P02 rule. */
export function canEditGrant(a: Access, r: Role, grant: Permission | string, mandatory: boolean) {
  if (!(r.status === 'ACTIVE' && protects(a, 'roles.permissions.manage') && !mandatory)) { return false; }
  const code = typeof grant === 'string' ? grant : grant.code;
  const retained = r.permissions.some(g => g.code === code);
  if (typeof grant === 'string' || grant.scopes.length === 1) { return has(a, code) || retained; }
  const retainedAtAllowedScope = r.permissions.some(g => g.code === code && allowedScopes(r, grant).includes(g.scope));
  return (hasGeo(a, code, 'GLOBAL') || retainedAtAllowedScope) && allowedScopes(r, grant).length > 0;
}
export async function load(client: Client, staffId: string) {
  const access = await client.access();
  if (access.staffId !== staffId) { throw new Error('Session changed'); }
  const [roles, catalog, people, self] = await Promise.all([
    has(access, 'roles.read') ? client.roles() : [], has(access, 'roles.read') ? client.catalog() : [],
    has(access, 'staff.read') ? client.staff() : [], has(access, 'staff.self.read') ? client.person('self') : null,
  ]);
  return { access, roles, catalog, people, self };
}
export type Snapshot = Awaited<ReturnType<typeof load>>;
export type Write = (call: (c: Client) => Promise<{id:string; version:number}>, success: string, showReceipt?: boolean) => void;
export function fields(form: HTMLFormElement, name: string) { const v = new FormData(form).get(name); return typeof v === 'string' ? v.trim() : ''; }
