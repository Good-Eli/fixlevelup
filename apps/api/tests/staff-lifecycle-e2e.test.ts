import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { check, fixturePerTest, integration, text } from './rbac-fixture.js';
import type { RbacFixture, Web } from './rbac-fixture.js';

// All subjects are local synthetic accounts. Every case has its own randomly named DB,
// and all competing operations run through HTTP on runtime PG sessions (not mock writes).
const v0 = '"staff-v0"';
const deactivate = (f: RbacFixture, actor: Web, target: string, etag?: string) =>
  f.call(actor, 'post', `/staff/${target}/deactivate`, {}, etag);
const admins = (f: RbacFixture) => f.count(`SELECT count(*)::int n FROM foundation.staff s
  JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
  JOIN foundation.roles r ON r.id=a.role_id JOIN foundation.staff_web_credentials c ON c.staff_id=s.id
  WHERE r.code='ADMIN' AND r.role_type='SYSTEM' AND s.employment_state='ACTIVE'`);
async function anotherAdmin(f: RbacFixture) {
  const m = await f.webStaff(); const r = check(await f.assign(m.id, await f.systemRole('ADMIN')), 200);
  const web = await f.login(m.id, m.login, m.password); expect(await admins(f)).toBe(2); return { web, etag: r.etag };
}

integration('staff lifecycle and historical last-ADMIN regression (real PG + HTTP)', () => {
  const fixture = fixturePerTest();
  it('applies strong If-Match, denies ordinary self mutations, keeps session history, and closes all web routes after deactivation', async () => {
    const f = fixture(); const m = await f.webStaff();
    const path = `/staff/${m.id}`;
    expect(check(await f.call(f.admin, 'get', path), 200).etag).toBe(v0);
    check(await deactivate(f, f.admin, 'not-a-uuid', v0), 400);
    check(await deactivate(f, f.admin, randomUUID(), v0), 404);
    check(await deactivate(f, f.admin, m.id), 428);
    for (const bad of ['W/"staff-v0"', 'staff-v0', '"auth-v0"', '"staff-v01"']) { check(await deactivate(f, f.admin, m.id, bad), 400); }
    check(await deactivate(f, f.admin, m.id, '"staff-v1"'), 412);
    check(await deactivate(f, m, m.id.toUpperCase(), v0), 403);
    expect(check(await f.call(f.admin, 'get', path), 200).data).toMatchObject({ employmentState: 'ACTIVE', version: 0 });
    const done = check(await deactivate(f, f.admin, m.id, v0), 200);
    expect(done.data).toMatchObject({ id: m.id, role: 'MANAGER', employmentState: 'INACTIVE', version: 1 });
    expect(done.etag).toBe('"staff-v1"'); check(await deactivate(f, f.admin, m.id, done.etag), 409);
    const row = await f.db.query('SELECT employment_state,auth_version FROM foundation.staff WHERE id=$1', [m.id]);
    expect(row.rows).toEqual([{ employment_state: 'INACTIVE', auth_version: 1 }]);
    const audit = await f.db.query("SELECT details FROM foundation.audit_logs WHERE operation='STAFF_DEACTIVATED' AND details->>'target'=$1", [m.id]);
    expect(audit.rows).toMatchObject([{ details: { by: f.admin.id, target: m.id } }]);
    const sessions = await f.db.query('SELECT auth_version,revoked_at FROM foundation.web_sessions WHERE staff_id=$1', [m.id]);
    expect(sessions.rows).toEqual([{ auth_version: 0, revoked_at: null }]);
    for (const p of ['/staff', path, '/staff/self']) { check(await f.call(m, 'get', p), 401); }
    check(await f.call(m, 'post', '/staff', { role: 'TECHNICIAN' }), 401);
    expect(await f.rejectedLogin(m)).toBe(401);
  });

  it('rejects the Telegram bearer and grace replay after deactivation, without deleting or revoking the original session', async () => {
    const f = fixture(); const tech = await f.createStaff('TECHNICIAN'); const tg = await f.tg(tech);
    expect(check(await f.call(tg, 'get', '/telegram/staff/self'), 200).data).toMatchObject({ id: tech, role: 'TECHNICIAN' });
    check(await deactivate(f, f.admin, tech, v0), 200);
    check(await f.call(tg, 'get', '/telegram/staff/self'), 401); expect(await tg.replay()).toBe(400);
    expect(await f.count("SELECT count(*)::int n FROM foundation.web_sessions WHERE staff_id=$1 AND channel='STAFF_TELEGRAM' AND revoked_at IS NULL AND auth_version=0", [tech])).toBe(1);
  });

  it.each(['deactivate-first', 'write-first'] as const)('%s: mutation order, exact count/audit, old web session history', async (order) => {
    const f = fixture(); const m = await f.webStaff();
    const snapshot = async () => [await f.count("SELECT count(*)::int n FROM foundation.staff WHERE role='TECHNICIAN'"),
      await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='STAFF_CREATED' AND details->>'by'=$1", [m.id])];
    const before = await snapshot(); const d = () => deactivate(f, f.admin, m.id, v0); const w = () => f.call(m, 'post', '/staff', { role: 'TECHNICIAN' });
    if (order === 'deactivate-first') {
      const [first, second] = await f.race(d, w); check(first, 200); check(second, 401);
    } else {
      const [first, second] = await f.race(w, d); check(first, 201); check(second, 200);
      const id = text(first.data, 'id');
      expect(await f.count(`SELECT count(*)::int n FROM foundation.audit_logs a,foundation.audit_logs b WHERE a.operation='STAFF_CREATED'
        AND a.details->>'created'=$1 AND b.operation='STAFF_DEACTIVATED' AND b.details->>'target'=$2 AND a.occurred_at<=b.occurred_at`, [id, m.id])).toBe(1);
    }
    check(await w(), 401);
    expect(await snapshot()).toEqual(before.map((n) => n + (order === 'write-first' ? 1 : 0)));
    expect(await f.count('SELECT count(*)::int n FROM foundation.web_sessions WHERE staff_id=$1 AND auth_version=0 AND revoked_at IS NULL', [m.id])).toBe(1);
    expect(await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='STAFF_DEACTIVATED' AND details->>'target'=$1", [m.id])).toBe(1);
  }, 20000);

  it('two managers trying to remove two different last admins both receive hidden-object 404', async () => {
    const f = fixture(); const second = await anotherAdmin(f); const a = await f.webStaff(); const b = await f.webStaff();
    const result = await f.race(() => deactivate(f, a, f.admin.id, v0), () => deactivate(f, b, second.web.id, second.etag), 'both-denied');
    expect(result.map((r) => r.status)).toEqual([404, 404]); expect(await admins(f)).toBe(2);
    expect(await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='STAFF_DEACTIVATED'")).toBe(0);
  }, 20000);

  it('two admins self-deactivating: exactly one success, one conflict, one reachable admin; bootstrap stays closed', async () => {
    const f = fixture(); const second = await anotherAdmin(f);
    const [a, b] = await f.race(() => deactivate(f, f.admin, 'self', v0), () => deactivate(f, second.web, 'self', second.etag));
    check(a, 200); check(b, 409); expect(await admins(f)).toBe(1);
    check(await f.call(second.web, 'get', '/staff/self'), 200); check(await f.call(f.admin, 'get', '/staff/self'), 401);
    expect(await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='STAFF_DEACTIVATED' AND details->>'target'=$1", [f.admin.id])).toBe(1);
    await expect(bootstrapFirstAdmin(f.db, { login: 'retry', password: randomUUID() })).rejects.toMatchObject({ code: 'ALREADY_INITIALIZED' });
  }, 20000);

  it('direct service writers prove the second transaction waits on the shared advisory lock, not a guard preflight', async () => {
    const f = fixture(); const second = await anotherAdmin(f);
    const [a, b] = await f.race(() => f.directSelfDeactivate(f.admin, 0), () => f.directSelfDeactivate(second.web, 1), 'writers');
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    expect(await admins(f)).toBe(1);
    expect(await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='STAFF_DEACTIVATED'")).toBe(1);
    expect(await f.count("SELECT count(*)::int n FROM foundation.staff WHERE employment_state='INACTIVE' AND role='ADMIN'")).toBe(1);
  }, 20000);

  it('a demotion and self-deactivation on different last admins share one lock and preserve one reachable admin', async () => {
    const f = fixture(); const other = await anotherAdmin(f); const manager = await f.systemRole('MANAGER');
    const [a, b] = await f.race(() => f.assign(other.web.id, manager, other.etag), () => deactivate(f, f.admin, 'self', v0));
    check(a, 200); check(b, 409); expect(await admins(f)).toBe(1);
    check(await f.call(f.admin, 'get', '/roles'), 200);
    expect(await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='STAFF_DEACTIVATED'")).toBe(0);
  }, 20000);
});
