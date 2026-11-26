import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { check, fixturePerTest, grant, integration, items, text } from './rbac-fixture.js';

integration('RBAC role management, history and channel boundaries on isolated PG', () => {
  const fixture = fixturePerTest();
  it('protects system roles/mandatory permissions, exposes only supported scopes and protects management endpoints', { timeout: 30_000 }, async () => {
    const f = fixture(); const m = await f.webStaff(); const adminRole = await f.systemRole('ADMIN');
    const permissions = items(check(await f.call(f.admin, 'get', '/permissions'), 200));
    for (const code of ['staff.self.read', 'staff.create', 'roles.archive', 'staff.role.assign']) { expect(permissions.map((p) => p['code'])).toContain(code); }
    const rid = text(check(await f.createRole(), 201).data, 'id');
    const detail = check(await f.call(f.admin, 'get', `/roles/${rid}`), 200);
    check(await f.call(m, 'get', '/roles'), 403); check(await f.call(m, 'get', '/permissions'), 403);
    check(await f.call(m, 'post', '/roles', { name: 'Not admin', description: '' }), 403);
    check(await f.call(m, 'patch', `/roles/${rid}`, { name: 'No' }, detail.etag), 403);
    check(await f.call(m, 'post', `/roles/${rid}/archive`, {}, detail.etag), 403);
    check(await f.call(f.admin, 'post', '/roles', { name: 'Unexpected', description: '', permissions: [grant('roles.create')] }), 400);
    check(await f.permset(rid, ['roles.permissions.manage']), 403);
    check(await f.permset(adminRole, ['staff.read']), 403);
    const sys = check(await f.call(f.admin, 'get', `/roles/${adminRole}`), 200);
    check(await f.call(f.admin, 'patch', `/roles/${adminRole}`, { name: 'No' }, sys.etag), 409);
    check(await f.call(f.admin, 'post', `/roles/${adminRole}/archive`, {}, sys.etag), 409);
    check(await f.call(f.admin, 'patch', `/roles/${rid}`, { name: 'Missing version' }), 428);
    check(await f.call(f.admin, 'patch', `/roles/${rid}`, { name: 'Weak version' }, `W/${detail.etag}`), 400);
    for (const body of [ { permissions: [{ code: 'staff.read', scope: 'CITY' }] },
      { permissions: [{ code: 'staff.self.read', scope: 'GLOBAL' }] }, { permissions: [grant('unknown.capability')] } ]) {
      const denied = await f.call(f.admin, 'put', `/roles/${rid}/permissions`, body, detail.etag);
      expect([400, 403]).toContain(denied.status);
    }
    expect(check(await f.call(f.admin, 'get', `/roles/${rid}`), 200).etag).toBe(detail.etag);
    const rename = check(await f.call(f.admin, 'patch', `/roles/${rid}`, { name: 'Renamed role' }, detail.etag), 200);
    expect(rename.data).toMatchObject({ name: 'Renamed role' }); expect(rename.etag).not.toBe(detail.etag);
    check(await f.call(f.admin, 'put', `/staff/${f.admin.id.toUpperCase()}/role`, { roleId: rid }, '"staff-v0"'), 403);
  });

  it('only one permission editor wins a concurrent If-Match; loser cannot partially overwrite the set', async () => {
    const f = fixture(); const second = await f.webStaff(); check(await f.assign(second.id, await f.systemRole('ADMIN')), 200);
    const editor = await f.login(second.id, second.login, second.password);
    const r = check(await f.createRole(), 201); const path = `/roles/${text(r.data, 'id')}`;
    const etag = check(await f.call(f.admin, 'get', path), 200).etag;
    const [a, b] = await f.race(() => f.call(f.admin, 'put', `${path}/permissions`, { permissions: [grant('staff.read')] }, etag),
      () => f.call(editor, 'put', `${path}/permissions`, { permissions: [grant('staff.create')] }, etag));
    check(a, 200); check(b, 412); const current = check(await f.call(editor, 'get', path), 200);
    expect(current.etag).toBe(a.etag); expect(current.etag).not.toBe(etag);
    const persisted = await f.db.query('SELECT permission_code,scope_type FROM foundation.role_permissions WHERE role_id=$1 AND enabled', [text(r.data, 'id')]);
    expect(persisted.rows).toEqual([{ permission_code: 'staff.read', scope_type: 'GLOBAL' }]);
  }, 20000);

  it.each(['archive-first', 'assign-first'] as const)('%s never leaves an active staff member assigned to an archived role', async (order) => {
    const f = fixture(); const second = await f.webStaff(); check(await f.assign(second.id, await f.systemRole('ADMIN')), 200);
    const editor = await f.login(second.id, second.login, second.password); const target = await f.createStaff('TECHNICIAN');
    const role = text(check(await f.createRole(), 201).data, 'id'); const path = `/roles/${role}`;
    const etag = check(await f.call(f.admin, 'get', path), 200).etag;
    const archive = () => f.call(editor, 'post', `${path}/archive`, {}, etag); const assign = () => f.assign(target, role);
    const [a, b] = order === 'archive-first' ? await f.race(archive, assign) : await f.race(assign, archive);
    check(a, 200); check(b, 409);
    const roleState = check(await f.call(f.admin, 'get', path), 200).data;
    expect(roleState['status']).toBe(order === 'archive-first' ? 'ARCHIVED' : 'ACTIVE');
    const active = await f.count('SELECT count(*)::int n FROM foundation.staff_role_assignments WHERE role_id=$1 AND staff_id=$2 AND revoked_at IS NULL', [role, target]);
    expect(active).toBe(order === 'archive-first' ? 0 : 1);
    expect(await f.count('SELECT count(*)::int n FROM foundation.staff_role_assignments WHERE staff_id=$1 AND revoked_at IS NULL', [target])).toBe(1);
    if (order === 'assign-first') {
      expect(items(check(await f.call(f.admin, 'get', `${path}/staff`), 200)).map((s) => s['id'])).toContain(target);
      expect(await f.count(`SELECT count(*)::int n FROM foundation.staff_role_assignments old
        JOIN foundation.staff_role_assignments cur ON cur.staff_id=old.staff_id AND cur.revoked_at IS NULL
        WHERE old.staff_id=$1 AND old.revoked_at=cur.assigned_at AND cur.role_id=$2 AND old.role_id<>$2 AND old.revoked_by=cur.assigned_by`, [target, role])).toBe(1);
    }
  }, 20000);

  it('role change invalidates CRM and Telegram independently, keeps original channel binding, and denies stale grace replay', async () => {
    const f = fixture(); const m = await f.webStaff(); const tech = await f.createStaff('TECHNICIAN'); const tg = await f.tg(tech);
    const role = text(check(await f.createRole(), 201).data, 'id'); check(await f.permset(role, ['staff.self.read']), 200);
    check(await f.call(m, 'get', '/staff/self'), 200); check(await f.call(tg, 'get', '/telegram/staff/self'), 200);
    check(await f.call({ token: m.token }, 'get', '/telegram/staff/self'), 401);
    check(await f.call({ ...m, cookie: `__Host-fixlevelup_session=${tg.token}` }, 'get', '/staff/self'), 401);
    check(await f.assign(m.id, role), 200); check(await f.assign(tech, role), 200);
    check(await f.call(m, 'get', '/staff/self'), 401); check(await f.call(tg, 'get', '/telegram/staff/self'), 401); expect(await tg.replay()).toBe(400);
    const fresh = await f.login(m.id, m.login, m.password);
    expect(check(await f.call(fresh, 'get', '/staff/self'), 200).data).toMatchObject({ id: m.id, roleId: role });
    check(await f.call(fresh, 'get', '/staff'), 403);
    expect(await f.count('SELECT count(*)::int n FROM foundation.web_sessions WHERE staff_id=ANY($1::uuid[]) AND auth_version=0', [[m.id, tech]])).toBe(2);
  });

  it('Telegram honors the same ordinary grants and technician target restrictions, without accepting CRM cookies', { timeout: 30_000 }, async () => {
    const f = fixture(); const tech = await f.createStaff('TECHNICIAN'); const tg = await f.tg(tech); const target = await f.createStaff('TECHNICIAN');
    const api = '/telegram/staff';
    for (const path of [api, '/telegram/roles', '/telegram/permissions']) { check(await f.call(tg, 'get', path), 403); }
    check(await f.call(tg, 'post', api, { role: 'TECHNICIAN' }), 403);
    check(await f.call(tg, 'patch', `${api}/${target}`, { displayName: 'No' }, '"staff-v0"'), 403);
    check(await f.call(tg, 'post', `${api}/${target}/deactivate`, {}, '"staff-v0"'), 403);
    const rid = text(check(await f.createRole(), 201).data, 'id'); check(await f.permset(rid, ['staff.read','roles.read']), 200);
    check(await f.assign(tech, rid), 200); check(await f.call(tg, 'get', api), 401);
    const fresh = await f.exchange(tg.user);
    const list = check(await f.call(fresh, 'get', api, undefined, undefined, 'https://mini.example.test'), 200);
    expect(items(list).map((s) => s['id'])).toEqual([target]);
    for (const path of [`${api}/${tech}`, `${api}/${f.admin.id}`]) { check(await f.call(fresh, 'get', path), 404); }
    check(await f.call(fresh, 'get', `${api}/self`), 403);
    for (const suffix of ['/roles', '/permissions']) {
      check(await f.call(fresh, 'get', `/telegram${suffix}`, undefined, undefined, 'https://mini.example.test'), 200);
      check(await f.call(fresh, 'get', suffix), 401); check(await f.call(f.admin, 'get', `/telegram${suffix}`), 401);
    }
    const admin = await f.systemRole('ADMIN');
    expect(items(check(await f.call(fresh, 'get', `/telegram/roles/${admin}/staff`), 200))).toEqual([]);
    const technician = await f.systemRole('TECHNICIAN');
    expect(items(check(await f.call(fresh, 'get', `/telegram/roles/${technician}/staff`), 200)).map((s) => s['id'])).toEqual([target]);
    check(await f.permset(rid, ['staff.create','staff.update','staff.deactivate']), 200);
    check(await f.call(fresh, 'get', api), 403);
    const created = check(await f.call(fresh, 'post', api, { role: 'TECHNICIAN' }), 201); const id = text(created.data, 'id');
    expect(created.data).toEqual({ id, version: 0 });
    const update = check(await f.call(fresh, 'patch', `${api}/${id}`, { displayName: 'TG write' }, created.etag), 200);
    expect(update.data).toEqual({ id, version: 1 });
    expect(check(await f.call(fresh, 'post', `${api}/${id}/deactivate`, {}, update.etag), 200).data).toEqual({ id, version: 2 });
    check(await f.call(fresh, 'post', api, { role: 'MANAGER' }), 403);
  });

  it('an audit insert failure rolls back all staff, assignment, role, permission and version effects; same session can retry', async () => {
    const f = fixture(); const role = text(check(await f.createRole(), 201).data, 'id');
    const rpath = `/roles/${role}`; const tag = check(await f.call(f.admin, 'get', rpath), 200).etag;
    const snapshot = async () => Promise.all([
      f.count('SELECT count(*)::int n FROM foundation.staff'), f.count('SELECT count(*)::int n FROM foundation.staff_role_assignments'),
      f.count('SELECT count(*)::int n FROM foundation.audit_logs'), f.count('SELECT version AS n FROM foundation.roles WHERE id=$1', [role]),
      f.count('SELECT count(*)::int n FROM foundation.role_permissions WHERE role_id=$1', [role]),
    ]);
    const before = await snapshot();
    await f.db.query(`ALTER TABLE foundation.audit_logs ADD CONSTRAINT fixture_inject_audit_failure
      CHECK (operation NOT IN ('STAFF_ROLE_ASSIGNED','ROLE_PERMISSIONS_CHANGED')) NOT VALID`);
    const create = () => f.call(f.admin, 'post', '/staff', { role: 'TECHNICIAN' });
    const set = () => f.call(f.admin, 'put', `${rpath}/permissions`, { permissions: [grant('staff.read')] }, tag);
    try {
      for (const run of [create, set]) {
        const r = check(await run(), 500); expect(r.body).toMatchObject({ status: 500, code: 'INTERNAL_ERROR' });
        expect(JSON.stringify(r.body).includes('fixture_inject')).toBe(false); expect(await snapshot()).toEqual(before);
      }
    } finally { await f.db.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT fixture_inject_audit_failure'); }
    check(await create(), 201); check(await set(), 200);
    expect(await snapshot()).toEqual(before.map((n, i) => n + (i === 2 ? 3 : 1)));
  });

  it('bounded policy lock contention returns HTTP 409 without committing; same request then succeeds', async () => {
    const f = fixture(); const locker = await f.db.connect(); const before = await f.count('SELECT count(*)::int n FROM foundation.staff');
    const run = () => f.call(f.admin, 'post', '/staff', { role: 'TECHNICIAN' });
    try {
      await locker.query('BEGIN'); await locker.query("SELECT pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0))");
      const start = Date.now(); check(await run(), 409); expect(Date.now() - start).toBeGreaterThanOrEqual(4000);
      expect(await f.count('SELECT count(*)::int n FROM foundation.staff')).toBe(before);
    } finally { try { await locker.query('ROLLBACK'); } finally { locker.release(); } }
    check(await run(), 201); expect(await f.count('SELECT count(*)::int n FROM foundation.staff')).toBe(before + 1);
  }, 15000);

  it('write-only role editor never learns whether a guessed name matched', async () => {
    const f = fixture(); const role = text(check(await f.createRole(), 201).data, 'id');
    const detail = check(await f.call(f.admin, 'get', `/roles/${role}`), 200); const priorName = text(detail.data, 'name');
    const id = await f.systemRole('ADMIN'); check(await f.permset(id, ['staff.role.assign','roles.create','roles.update','roles.archive','roles.permissions.manage']), 200);
    check(await f.call(f.admin, 'get', `/roles/${role}`), 403);
    const same = check(await f.call(f.admin, 'patch', `/roles/${role}`, { name: priorName }, detail.etag), 200);
    const other = check(await f.call(f.admin, 'patch', `/roles/${role}`, { name: 'Different' }, same.etag), 200);
    expect(same.data).toEqual({ id: role, version: Number(detail.data['version'])+1 });
    expect(other.data).toEqual({ id: role, version: Number(detail.data['version'])+2 });
    expect(await f.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='ROLE_UPDATED' AND details->>'target'=$1", [role])).toBe(2);
  });

  it('TG SELF resolves server identity; ownership and exact link survive neither mass assignment nor a rebind', async () => {
    const f = fixture(); const tech = await f.createStaff('TECHNICIAN'); const tg = await f.tg(tech);
    const path = '/telegram/staff/self';
    const self = check(await f.call(tg, 'get', path), 200); expect(self.data['id']).toBe(tech);
    check(await f.call(tg, 'patch', path, { displayName: 'Refused', staffId: f.admin.id }, self.etag), 400);
    const changed = check(await f.call(tg, 'patch', path, { displayName: 'Technician' }, self.etag), 200);
    expect(changed.data).toMatchObject({ id: tech, displayName: 'Technician' });
    expect(check(await f.call(f.admin, 'get', `/staff/${f.admin.id}`), 200).data['displayName']).not.toBe('Technician');
    await f.db.query('UPDATE foundation.staff_telegram_links SET revoked_at=clock_timestamp() WHERE id=$1', [tg.link]);
    await f.db.query('INSERT INTO foundation.staff_telegram_links (id,staff_id,telegram_user_id) VALUES ($1,$2,$3)', [randomUUID(), tech, tg.user]);
    check(await f.call(tg, 'get', path), 401); check(await f.call(tg, 'patch', path, { displayName: 'No' }, changed.etag), 401);
    expect(await tg.replay()).toBe(400);
  });
});
