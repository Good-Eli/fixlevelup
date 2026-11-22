import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { check, records, text } from './geography-fixture.js';
import { integration } from './rbac-fixture.js';
import { city, COMPANY_FIELDS, contentInput, fixtureCode, global, idOf, managementPerTest, minimal, problem } from './settings-management-fixture.js';

const CAPABILITIES = [
  'settings.fullread', 'settings.manage', 'settings.readiness.read',
  'references.callbackinterval.read', 'references.callbackinterval.manage',
  'references.paymentmethod.read', 'references.paymentmethod.manage',
  'references.cancelreason.read', 'references.cancelreason.manage',
  'references.declinereason.read', 'references.declinereason.manage',
  'references.requestsource.read', 'references.requestsource.manage',
  'content.read', 'content.manage', 'content.publish', 'legal.read', 'legal.manage',
].sort();
const BOOTSTRAP = '/settings/management/bootstrap';
const CONTENT = '/content/blocks';
const READINESS = '/settings/readiness';

integration('P03 management authority on live Nest + isolated PostgreSQL', () => {
  const fixture = managementPerTest();

  it('issues exactly 18 personal GLOBAL rights at real console bootstrap; explicit role grants survive source revocation', async () => {
    const f = fixture(); const a = f.admin;
    const role = await f.base.systemRole('ADMIN');
    const later = await f.base.webStaff();
    check(await f.base.assign(later.id, role), 200);
    const secondary = await f.base.login(later.id, later.login, later.password);
    expect(records(check(await f.read('/access'), 200).data['p03Permissions']).map(({ code, scope }) => ({ code, scope })))
      .toEqual(CAPABILITIES.map(global));
    expect(records(check(await f.read('/access', { web: secondary }), 200).data['p03Permissions'])).toEqual([]);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.role_permissions WHERE permission_code=ANY($1::text[])', [CAPABILITIES])).toBe(0);
    const sources = records(check(await f.read(BOOTSTRAP), 200).data['items']);
    const assignmentId = await f.geo.currentAssignment(a.id);
    expect(sources).toEqual(CAPABILITIES.map((code) => ({ assignmentId, staffId: a.id, code, version: 1 })));
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.geography_bootstrap_permissions WHERE assignment_id=$1', [assignmentId])).toBe(5);
    problem(await f.read(READINESS, { web: secondary }), 403);
    check(await f.addRoleGrants(role, [global('settings.readiness.read')]), 200);
    check(await f.read(READINESS, { web: secondary }), 200);
    const options = { key: randomUUID(), etag: '"p03-v1"' };
    const path = `${BOOTSTRAP}/${a.id}/settings.readiness.read/revoke`;
    const revoked = check(await f.post(path, {}, options), 200);
    minimal(revoked); expect(revoked.data).toEqual({ id: assignmentId, version: 2 });
    const retry = check(await f.post(path, {}, options), 200);
    expect([retry.data, retry.etag]).toEqual([revoked.data, revoked.etag]);
    for (const web of [a, secondary]) { check(await f.read(READINESS, { web }), 200); }
    const selfPath = `${BOOTSTRAP}/${a.id}/legal.manage/revoke`;
    const selfOptions = { key: randomUUID(), etag: '"p03-v1"' };
    check(await f.post(selfPath, {}, selfOptions), 200);
    problem(await f.post(selfPath, {}, selfOptions), 403);
    const evidence = () => Promise.all([
      f.base.count('SELECT count(*)::int n FROM foundation.p03_bootstrap_permissions WHERE revoked_at IS NOT NULL'),
      f.base.count('SELECT count(*)::int n FROM foundation.p03_command_receipts'),
      f.base.count('SELECT count(*)::int n FROM foundation.audit_logs'),
      f.base.count('SELECT count(*)::int n FROM foundation.outbox_events'),
    ]);
    const beforeMismatch = await evidence();
    const requested = `${BOOTSTRAP}/${a.id}/legal.read/revoke`;
    // First original code remains GLOBAL via its explicit role grant; second does not.
    // Both mismatches must be indistinguishable from a missing target.
    const stillHeld = await f.post(requested, {}, options);
    const removed = await f.post(requested, {}, selfOptions);
    const missing = await f.post(`${BOOTSTRAP}/${randomUUID()}/legal.read/revoke`, {}, { etag: '"p03-v1"' });
    for (const reply of [stillHeld, removed, missing]) { problem(reply, 404); expect(reply.etag).toBe(''); }
    expect(await evidence()).toEqual(beforeMismatch);
    await f.base.db.query('SELECT foundation.issue_first_p03_permissions()');
    const current = await f.base.login(a.id, a.login, a.password);
    expect(records(check(await f.read('/access', { web: current }), 200).data['p03Permissions']).map(({ code }) => code)).not.toContain('legal.manage');
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p03_bootstrap_permissions WHERE assignment_id=$1 AND revoked_by=$2 AND row_version=2', [assignmentId, a.id])).toBe(2);
  }, 30_000);

  it('permits explicit MANAGER and CUSTOM-web grants but filters each read and write to its real scope; CUSTOM-TG is masked', async () => {
    const f = fixture(); const a = f.admin;
    const visible = await f.geo.activeCity(a, 'z-visible');
    const hidden = await f.geo.publishedDraftCity(a, 'a-hidden');
    const m = await f.base.webStaff(); const managerRole = await f.base.systemRole('MANAGER');
    problem(await f.read(READINESS, { web: m }), 403);
    check(await f.assignCity(m.id, visible.id), 201);
    check(await f.addRoleGrants(managerRole, [
      global('settings.readiness.read'), city('geography.read'), city('content.manage'),
      global('references.paymentmethod.manage'),
    ]), 200);
    const payload = { scope: 'CITY', cityId: visible.id, code: 'z-visible', kind: 'FAQ', allowCompanyFallback: false };
    const paymentPath = '/settings/references/payment_method';
    problem(await f.post(CONTENT, payload, { web: m }), 403);
    problem(await f.post(paymentPath, { code: 'synthetic-payment' }, { web: m }), 403);
    check(await f.addRoleGrants(managerRole, [city('content.read'), global('references.paymentmethod.read')]), 200);
    const block = check(await f.post(CONTENT, payload, { web: m }), 201);
    const contentPath = `${CONTENT}/${idOf(block)}`;
    problem(await f.post(`${contentPath}/publish`, contentInput(), { web: m, etag: block.etag }), 403);
    const payment = check(await f.post(paymentPath, { code: 'synthetic-payment' }, { web: m }), 201);
    check(await f.read(`${paymentPath}/${idOf(payment)}`, { web: m }), 200);
    problem(await f.read('/settings/references/cancel_reason', { web: m }), 403);
    const company = check(await f.post(CONTENT, { scope: 'COMPANY', code: 'a-company', kind: 'FAQ', allowCompanyFallback: true }), 201);
    const other = check(await f.post(CONTENT, { ...payload, cityId: hidden.id, code: 'a-other' }), 201);
    problem(await f.read(`${CONTENT}/${idOf(company)}`, { web: m }), 404);
    problem(await f.read(`${CONTENT}/${idOf(other)}`, { web: m }), 404);
    problem(await f.post(`${CONTENT}/${idOf(other)}/archive`, {}, { web: m, etag: other.etag }), 404);
    problem(await f.post('/settings/versions', COMPANY_FIELDS, { web: m, etag: '"p03-v1"' }), 403);
    problem(await f.read('/settings/versions', { web: m }), 403);
    problem(await f.read('/legal/documents', { web: m }), 403);
    const safe = check(await f.read(`${READINESS}?limit=1`, { web: m }), 200);
    expect(records(safe.data['items']).map(({ id }) => id)).toEqual([visible.id]);
    expect(safe.data['pageInfo']).toEqual({ hasMore: false, nextCursor: null });
    expect(Object.keys(safe.data).sort()).toEqual(['items', 'pageInfo', 'sections']);
    for (const item of records(safe.data['sections'])) {
      expect(Object.keys(item).sort()).toEqual(['missing', 'section', 'status']);
    }
    expect(safe.data['sections']).toEqual(expect.arrayContaining([
      { section: 'PROVIDERS', status: 'NOT_ASSESSED', missing: [] },
      { section: 'P05', status: 'NOT_IMPLEMENTED', missing: [] },
    ]));
    expect(JSON.stringify(safe.body)).not.toContain(hidden.id);
    const role = text(check(await f.base.createRole(), 201).data, 'id');
    const tech = await f.base.createStaff('TECHNICIAN');
    check(await f.addRoleGrants(role, [city('content.read'), city('content.manage'), city('content.publish')]), 200);
    const customWeb = await f.base.webStaff();
    check(await f.base.assign(customWeb.id, role), 200); check(await f.base.assign(tech, role), 200);
    const web = await f.base.login(customWeb.id, customWeb.login, customWeb.password);
    const telegram = await f.base.tg(tech);
    check(await f.assignCity(web.id, visible.id), 201);
    const publishOptions = { web, etag: block.etag, key: randomUUID() };
    const published = check(await f.post(`${contentPath}/publish`, contentInput(), publishOptions), 201);
    minimal(published, true);
    problem(await f.read(contentPath, { web: telegram }), 401);
    problem(await f.read(contentPath, { web: { ...web, cookie: `__Host-fixlevelup_session=${telegram.token}` } }), 401);
    problem(await f.read(contentPath, { web: null }), 401);
    problem(await f.read(contentPath, { origin: 'https://other.example.test' }), 403);
    problem(await f.post(`${contentPath}/archive`, {}, { web, etag: published.etag, csrf: 'wrong' }), 403);
    check(await f.base.assign(web.id, managerRole, `"staff-v${String(await f.geo.staffVersion(web.id))}"`), 200);
    problem(await f.post(`${contentPath}/publish`, contentInput(), publishOptions), 401);
    await f.assertSafeEvidence();
  }, 45_000);

  it('denies unheld grant replacement, staff create/assign and later territory expansion in both orders', async () => {
    const f = fixture(); const a = f.admin;
    const x = await f.geo.activeCity(a, 'x-city');
    const y = await f.geo.publishedDraftCity(a, 'y-city');
    const role = await f.base.systemRole('ADMIN'); const mRole = await f.base.systemRole('MANAGER');
    const deputyCredentials = await f.base.webStaff();
    const scoped = await f.base.webStaff(); const cityFirst = await f.base.webStaff();
    const customRole = text(check(await f.base.createRole(), 201).data, 'id');
    check(await f.addRoleGrants(role, [global('geography.manage')]), 200);
    check(await f.base.assign(deputyCredentials.id, role), 200);
    const deputy = await f.base.login(deputyCredentials.id, deputyCredentials.login, deputyCredentials.password);
    check(await f.assignCity(cityFirst.id, x.id, deputy), 201); // city first, before any stored P03 grant
    check(await f.addRoleGrants(mRole, [city('content.read')], deputy), 403);
    check(await f.addRoleGrants(mRole, [city('content.read')]), 200);
    check(await f.addRoleGrants(customRole, [city('content.read')]), 200);
    check(await f.base.call(deputy, 'post', '/staff', { role: 'MANAGER' }), 403);
    check(await f.base.call(deputy, 'put', `/staff/${cityFirst.id}/role`, { roleId: customRole },
      `"staff-v${String(await f.geo.staffVersion(cityFirst.id))}"`), 403);
    check(await f.assignCity(scoped.id, x.id, deputy), 403); // grant first, still needs exact own GLOBAL
    check(await f.assignCity(scoped.id, x.id), 201);
    check(await f.base.call(a, 'post', '/staff', { role: 'MANAGER' }), 201);
    check(await f.addRoleGrants(role, [global('content.manage'), global('content.publish'), city('content.read')]), 200);
    check(await f.assignCity(deputy.id, x.id), 201);
    const common = { kind: 'FAQ', code: fixtureCode('intersection'), allowCompanyFallback: false };
    // GLOBAL manage/publish and CITY read do not confer a single broad permission.
    problem(await f.post(CONTENT, { ...common, scope: 'COMPANY' }, { web: deputy }), 403);
    problem(await f.post(CONTENT, { ...common, scope: 'CITY', cityId: y.id }, { web: deputy }), 404);
    check(await f.post(CONTENT, { ...common, scope: 'CITY', cityId: x.id }, { web: deputy }), 201);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.content_blocks')).toBe(1);
  }, 45_000);
});
