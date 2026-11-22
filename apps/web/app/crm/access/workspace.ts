import { isP03Capability, P03_CAPABILITY_METADATA, type P03Scope } from '@fixlevelup/p03-contracts';
import { isP04Capability, p04Scopes, type Access, type Client, type Grant, type P04Capability, type Person, type Permission, type Role } from './api';

export function has(a: Access, code: string) { return a.permissions.includes(code); }
/** An individual geography grant as resolved by the server session (bootstrap or role). */
export function hasGeo(a: Access, code: string, scope?: 'GLOBAL' | 'CITY') {
  return (a.geoPermissions ?? []).some(g => g.code === code && (scope === undefined || g.scope === scope));
}
export function admin(a: Access) { return a.role.type === 'SYSTEM' && a.role.code === 'ADMIN'; }
function p03Scopes(r: Access['role'], code: string): readonly P03Scope[] {
  if (!isP03Capability(code) || (r.type === 'SYSTEM' && !['ADMIN', 'MANAGER'].includes(r.code))) { return []; }
  const policy = P03_CAPABILITY_METADATA[code];
  const systemAdmin = r.type === 'SYSTEM' && r.code === 'ADMIN';
  if (policy.systemAdminOnly && !systemAdmin) { return []; }
  return policy.scopes.filter(s => s !== 'GLOBAL' || !policy.globalSystemAdminOnly || systemAdmin);
}
export function hasP03(a: Access, code: string, scope?: P03Scope) {
  const allowed = p03Scopes(a.role, code);
  return (a.p03Permissions ?? []).some(g => g.code === code && allowed.includes(g.scope) && (scope === undefined || g.scope === scope));
}
export function p03ReplacementAllowed(a: Access, r: Role, grants: readonly Grant[]) {
  return grants.every(g => !isP03Capability(g.code) || (g.scope !== 'SELF' && p03Scopes(r, g.code).includes(g.scope) &&
    (hasP03(a, g.code, 'GLOBAL') || (a.role.id !== r.id && r.permissions.some(old => old.code === g.code && old.scope === g.scope)))));
}
export function protects(a: Access, code: string) { return admin(a) && has(a, code); }
export function holdsGlobalP04(a: Access, code: P04Capability) {
  if (!protects(a, 'roles.permissions.manage')) { return false; }
  const matches = (a.p04Permissions ?? []).filter(g => g.code === code);
  return matches.length === 1 && matches[0]?.scope === 'GLOBAL';
}
function validP04Grants(r: Role, grants: readonly Grant[]) {
  const seen = new Set<P04Capability>();
  return grants.every(g => {
    if (!isP04Capability(g.code)) { return true; }
    if (g.scope === 'SELF' || !p04Scopes(r, g.code).includes(g.scope) || seen.has(g.code)) { return false; }
    seen.add(g.code);
    return true;
  });
}
function mayRetainP04(a: Access, r: Role, grant: Grant) {
  return a.role.id !== r.id && has(a, 'roles.read') && r.permissions.some(g => g.code === grant.code && g.scope === grant.scope);
}
export function p04ReplacementAllowed(a: Access, r: Role, grants: readonly Grant[]) {
  const manages = protects(a, 'roles.permissions.manage');
  return r.status === 'ACTIVE' && validP04Grants(r, r.permissions) && validP04Grants(r, grants)
    && grants.every(g => !isP04Capability(g.code) || (manages && (holdsGlobalP04(a, g.code) || mayRetainP04(a, r, g))));
}
export function p04GrantChanges(original: readonly Grant[], selected: readonly Grant[]) {
  const oldScopes = new Map(original.filter(g => isP04Capability(g.code)).map(g => [g.code, g.scope]));
  const newScopes = new Map(selected.filter(g => isP04Capability(g.code)).map(g => [g.code, g.scope]));
  return [...new Set([...oldScopes.keys(), ...newScopes.keys()])].flatMap(code => {
    const from = oldScopes.get(code);
    const to = newScopes.get(code);
    return from === to ? [] : [{ code, from, to }];
  });
}
export function canTarget(a: Access, person: Person) {
  return person.id !== a.staffId && person.employmentState === 'ACTIVE' && (admin(a) || person.role === 'TECHNICIAN');
}
/** Scopes the edited role may store for one catalog code: staff codes are fixed, while
 * geography GLOBAL and publish are restricted to the SYSTEM ADMIN role. */
export function allowedScopes(r: Role, p: Permission) {
  if (isP04Capability(p.code)) { return p04Scopes(r, p.code).filter(s => p.scopes.includes(s)); }
  if (isP03Capability(p.code)) { return p03Scopes(r, p.code).filter(s => p.scopes.includes(s)); }
  if (p.scopes.length === 1) { return p.scopes; }
  const targetAdmin = r.type === 'SYSTEM' && r.code === 'ADMIN';
  if ((r.type === 'SYSTEM' && r.code === 'TECHNICIAN') || (p.code === 'geography.publish' && !targetAdmin)) { return []; }
  return targetAdmin ? p.scopes : p.scopes.filter(s => s === 'CITY');
}
export function delegable(a: Access, r: Role) {
  return r.status === 'ACTIVE' && validP04Grants(r, r.permissions) && r.permissions.every(g => {
    if (isP04Capability(g.code)) { return holdsGlobalP04(a, g.code); }
    if (isP03Capability(g.code)) { return g.scope !== 'SELF' && p03Scopes(r, g.code).includes(g.scope) && hasP03(a, g.code, 'GLOBAL'); }
    return has(a, g.code) || (g.scope === 'SELF' && ['staff.self.read','staff.self.update','staff.self.deactivate'].includes(g.code)) ||
      (g.scope !== 'SELF' && hasGeo(a, g.code, 'GLOBAL') && (g.scope === 'CITY' || (r.type === 'SYSTEM' && r.code === 'ADMIN')) &&
        (g.code !== 'geography.publish' || (r.type === 'SYSTEM' && r.code === 'ADMIN')));
  });
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
  if (isP04Capability(code)) {
    const scopes = typeof grant === 'string' ? p04Scopes(r, code) : allowedScopes(r, grant);
    return validP04Grants(r, r.permissions) && scopes.some(scope => holdsGlobalP04(a, code) || mayRetainP04(a, r, { code, scope }));
  }
  if (isP03Capability(code)) {
    const scopes = typeof grant === 'string' ? p03Scopes(r, code) : allowedScopes(r, grant);
    return scopes.length > 0 && (hasP03(a, code, 'GLOBAL') || (a.role.id !== r.id && r.permissions.some(g => g.code === code && scopes.includes(g.scope as P03Scope))));
  }
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
