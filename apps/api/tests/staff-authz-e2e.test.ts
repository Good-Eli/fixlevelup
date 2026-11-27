import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { check, fixturePerTest, grant, integration, items, text } from './rbac-fixture.js';

integration('staff authorization real HTTP against isolated PostgreSQL', () => {
  const fixture = fixturePerTest();

  it('denies by default; explicit role grants apply to all members without logging in again', { timeout: 30_000 }, async () => {
    const f = fixture(); const custom = text(check(await f.createRole(), 201).data, 'id');
    const a = await f.webStaff(); const b = await f.webStaff();
    for (const web of [a, b]) { check(await f.assign(web.id, custom), 200); }
    const subjects = await Promise.all([a, b].map((w) => f.login(w.id, w.login, w.password)));
    expect(await f.count('SELECT count(*)::int n FROM foundation.user_permissions')).toBe(0);
    expect(await f.count("SELECT count(*)::int n WHERE has_any_column_privilege('fixlevelup_runtime','foundation.user_permissions','SELECT,INSERT,UPDATE')")).toBe(0);
    for (const w of subjects) {
      const access = check(await f.call(w, 'get', '/access'), 200).data;
      expect(access).toMatchObject({ staffId: w.id, role: { id: custom, type: 'CUSTOM' }, permissions: [] });
      check(await f.call(w, 'get', '/staff'), 403); check(await f.call(w, 'post', '/staff', { role: 'TECHNICIAN' }), 403);
    }
    check(await f.permset(custom, ['staff.read']), 200);
    const id = await f.createStaff('TECHNICIAN');
    for (const w of subjects) {
      const list = check(await f.call(w, 'get', '/staff'), 200);
      expect(items(list).map((row) => row['id'])).toContain(id);
      expect(list.data['pageInfo']).toEqual({ nextCursor: null, hasMore: false });
      expect(check(await f.call(w, 'get', `/staff/${id}`), 200).data).toMatchObject({ id, role: 'TECHNICIAN', employmentState: 'ACTIVE' });
      check(await f.call(w, 'get', `/staff/${randomUUID()}`), 404); check(await f.call(w, 'get', '/staff/invalid'), 400);
      check(await f.call(w, 'post', '/staff', { role: 'TECHNICIAN' }), 403);
    }
    check(await f.permset(custom, []), 200);
    for (const w of subjects) { check(await f.call(w, 'get', '/staff'), 403); }
  });

  it('locks manager access to technicians and non-idempotent creates commit both staff and audit', { timeout: 30_000 }, async () => {
    const f = fixture(); const m = await f.webStaff(); const other = await f.webStaff();
    const creates: string[] = [];
    for (let i = 0; i < 2; i++) {
      const r = check(await f.call(m, 'post', '/staff', { role: 'TECHNICIAN' }), 201); expect(r.etag).toBe('"staff-v0"');
      const id = text(r.data, 'id'); expect(id).toMatch(/^[0-9a-f-]{36}$/i); creates.push(id);
      const stored = await f.db.query('SELECT role,employment_state,auth_version FROM foundation.staff WHERE id=$1', [id]);
      expect(stored.rows[0]).toMatchObject({ role: 'TECHNICIAN', employment_state: 'ACTIVE', auth_version: 0 });
      const audit = await f.db.query("SELECT details FROM foundation.audit_logs WHERE operation='STAFF_CREATED' AND details->>'created'=$1", [id]);
      expect(audit.rows).toMatchObject([{ details: { by: m.id, created: id } }]);
    }
    expect(new Set(creates).size).toBe(2);
    expect(items(check(await f.call(m, 'get', '/staff'), 200)).map((r) => r['id']).sort()).toEqual(creates.sort());
    // Neither role projection nor an attacker-supplied city, role or staffId may widen visibility.
    const hiddenCustom = await f.createStaff('TECHNICIAN'); const role = text(check(await f.createRole(), 201).data, 'id');
    check(await f.assign(hiddenCustom, role), 200);
    for (const target of [other.id, f.admin.id, hiddenCustom, randomUUID()]) {
      check(await f.call(m, 'get', `/staff/${target}`), 404);
      check(await f.call(m, 'patch', `/staff/${target}`, { displayName: 'No change' }, '"staff-v0"'), 404);
      check(await f.call(m, 'post', `/staff/${target}/deactivate`, {}, '"staff-v0"'), 404);
    }
    check(await f.call(m, 'post', '/staff', { role: 'MANAGER' }), 403);
    const id = creates[0]; if (!id) { throw new Error('Missing persisted technician'); }
    check(await f.call(m, 'put', `/staff/${id}/role`, { roleId: await f.systemRole('ADMIN') }, '"staff-v0"'), 403);
    const path = `/staff/${id}`;
    const update = check(await f.call(m, 'patch', path, { displayName: 'New name' }, '"staff-v0"'), 200); expect(update.etag).toBe('"staff-v1"');
    check(await f.call(m, 'patch', path, { role: 'ADMIN', displayName: 'Rejected' }, update.etag), 400);
    expect(check(await f.call(m, 'get', path), 200).data).toMatchObject({ displayName: 'New name', role: 'TECHNICIAN' });
    check(await f.call(m, 'post', `${path}/deactivate`, {}, update.etag), 200);
  });

  it.each(['revoke-first', 'write-first'] as const)('%s: revocation and already running POST serialize; no later insert or audit', async (order) => {
    const f = fixture(); const m = await f.webStaff(); const role = await f.systemRole('MANAGER');
    const version = check(await f.call(f.admin, 'get', `/roles/${role}`), 200).etag;
    const snapshot = async () => [await f.count('SELECT count(*)::int n FROM foundation.staff'),
      await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='STAFF_CREATED'")];
    const before = await snapshot();
    const revoke = () => f.call(f.admin, 'put', `/roles/${role}/permissions`, { permissions: [grant('staff.read')] }, version);
    const create = () => f.call(m, 'post', '/staff', { role: 'TECHNICIAN' });
    const [a, b] = order === 'revoke-first' ? await f.race(revoke, create) : await f.race(create, revoke);
    if (order === 'revoke-first') { check(a, 200); check(b, 403); }
    else { check(a, 201); check(b, 200); }
    const delta = order === 'write-first' ? 1 : 0;
    expect(await snapshot()).toEqual(before.map((n) => n + delta));
    check(await create(), 403); expect(await snapshot()).toEqual(before.map((n) => n + delta));
    check(await f.call(m, 'get', '/staff'), 200);
  }, 20000);
});
