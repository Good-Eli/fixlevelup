import type { Access, Client, Person, Role } from './api';

export function has(a: Access, code: string) { return a.permissions.includes(code); }
export function admin(a: Access) { return a.role.type === 'SYSTEM' && a.role.code === 'ADMIN'; }
export function protects(a: Access, code: string) { return admin(a) && has(a, code); }
export function canTarget(a: Access, person: Person) {
  return person.id !== a.staffId && person.employmentState === 'ACTIVE' && (admin(a) || person.role === 'TECHNICIAN');
}
export function delegable(a: Access, r: Role) {
  return r.status === 'ACTIVE' && r.permissions.every(g => has(a,g.code) ||
    (g.scope === 'SELF' && ['staff.self.read','staff.self.update','staff.self.deactivate'].includes(g.code)));
}
export function roleLabel(r: Role) { return `${r.name} · ${r.code} · ${r.type === 'SYSTEM' ? 'системная' : 'пользовательская'}`; }
export function canEditGrant(a: Access, r: Role, code: string, mandatory: boolean) {
  return r.status === 'ACTIVE' && protects(a, 'roles.permissions.manage') && !mandatory && (has(a, code) || r.permissions.some(p => p.code === code));
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
