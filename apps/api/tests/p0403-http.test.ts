import { randomUUID } from 'node:crypto';
import { P04_ROUTES } from '@fixlevelup/p03-contracts/p04';
import type { P04Operation } from '@fixlevelup/p03-contracts/p04';
import { expect, it } from 'vitest';
import { check, geoTag, records, text, versionOf } from './geography-fixture.js';
import { id, p04Path, p04PerTest, p04Tag, page, PRIVATE_P04, receipt, revision } from './p0403-http-fixture.js';
import { integration, record } from './rbac-fixture.js';
import { city, fixtureCode, problem } from './settings-management-fixture.js';

const CATEGORIES = '/catalog/categories';
const CITIES = '/pricing/cities';
const AVITO = '/content/external-reviews';
const TIMEOUT = 30_000;

integration('P04-03 staff HTTP on isolated PostgreSQL', () => {
  const fixture = p04PerTest();

  it('registers all 80 generated operations, without default grants or public aliases', async () => {
    const f = fixture();
    const ops = Object.keys(P04_ROUTES) as P04Operation[];
    expect(ops).toHaveLength(80);
    for (const op of ops) {
      const route = P04_ROUTES[op];
      const path = p04Path(op, Object.fromEntries(route.params.map(key => [key, randomUUID()])));
      const result = route.method === 'GET' ? await f.read(path, { web: null }) : await f.post(path, {}, { web: null });
      problem(result, 401);
    }
    const role = check(await f.base.call(f.admin, 'get', '/access'), 200).data;
    expect(role['p04Permissions'] ?? []).toEqual([]);
    problem(await f.read(CATEGORIES), 403);
    problem(await f.post(CATEGORIES, { code: 'disallowed-before-issue' }), 403);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p04_bootstrap_permissions')).toBe(0);
    await f.asCatalog();
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p04_bootstrap_permissions')).toBe(9);
    expect(await f.base.count("SELECT count(*)::int n FROM foundation.role_permissions WHERE permission_code='catalog.read'")).toBe(0);
    check(await f.read(CATEGORIES), 200);
    for (const path of [CATEGORIES + '/', '/Catalog/categories', '/catalog/%63ategories', '/public/catalog', '/pricing/calculate', '/content/external-reviews/import']) {
      problem(await f.read(path), 404);
    }
    problem(await f.http('DELETE', CATEGORIES), 404);
  }, 45_000);

  it('rejects unauthenticated/security/JSON/I/V variants before effects and preserves normalized exact replay', async () => {
    const f = fixture();
    await f.asCatalog();
    const anonymous = { ...f.admin, cookie: `__Host-fixlevelup_session=${'A'.repeat(43)}` };
    problem(await f.read(CATEGORIES, { web: anonymous }), 401);
    problem(await f.read(CATEGORIES, { origin: 'https://other.example.test' }), 403);
    const bad = { code: 'p04-transport-test' };
    const before = await f.evidence();
    problem(await f.post(CATEGORIES, bad, { csrf: 'forged-token' }), 403);
    problem(await f.post(CATEGORIES, bad, { origin: 'https://other.example.test' }), 403);
    problem(await f.post(CATEGORIES, { ...bad, cityId: randomUUID() }), 400);
    problem(await f.post(CATEGORIES, bad, { key: null }), 400);
    problem(await f.post(CATEGORIES, bad, { etag: p04Tag(0) }), 400);
    problem(await f.post(CATEGORIES, bad, { headers: { 'Content-Encoding': 'gzip' } }), 415);
    problem(await f.post(`${CATEGORIES}?includeArchived=false`, bad), 400);
    problem(await f.http('POST', CATEGORIES, req => req.end('{"code":"first", "c\\u006fde":"second"}')), 400);
    const json = Buffer.from(JSON.stringify(bad));
    const atLimit = Buffer.concat([json, Buffer.alloc(16_384 - json.length, 0x20)]);
    // Cross the cap by exactly one payload byte, without queuing a terminating
    // chunk against the server's early close (a TCP reset race on Windows).
    // Require the complete 413 problem before end-of-input, not just a close.
    const tooLarge = await f.http('POST', CATEGORIES, req => {
      req.write(atLimit);
      req.write(' ');
    }, { headers: { 'Transfer-Encoding': 'chunked' } });
    problem(tooLarge, 413);
    expect(await f.evidence()).toEqual(before);
    const entity = receipt(await f.chunked('POST', CATEGORIES, atLimit), 201);
    const path = `${CATEGORIES}/${id(entity)}/versions`;
    const details = { title: '   Reviewed name   ' };
    problem(await f.post(path, details, { key: null }), 400); // I is validated before V
    problem(await f.post(path, { extra: 'shape-checked-after-I-V' }), 428);
    problem(await f.post(path, details, { etag: `W/${entity.etag}` }), 400);
    problem(await f.post(path, details, { etag: p04Tag(0) }), 400);
    problem(await f.post(path, details, { etag: p04Tag(2) }), 412);
    const key = randomUUID();
    const written = receipt(await f.post(path, details, { key, etag: entity.etag }), 201, true);
    const replay = receipt(await f.post(path, { description: null, title: 'Reviewed name' }, { key, etag: entity.etag }), 200, true);
    expect([replay.data, replay.etag]).toEqual([written.data, written.etag]);
    problem(await f.post(path, { title: 'Changed name' }, { key, etag: entity.etag }), 409);
    problem(await f.post(path, details, { etag: entity.etag }), 412);
    const stored = await f.readReceipt(key);
    expect(stored).toMatchObject([{ actor_id: f.admin.id, operation: 'categoryPublish', city_id: null,
      subject_id: id(entity), entity_id: id(entity), entity_version: 2, target_version_id: null,
      revision_id: revision(written), revision_version: 1 }]);
    expect(stored[0]?.request_sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(check(await f.read(`${path}/${revision(written)}`), 200).data).toMatchObject({ title: 'Reviewed name', description: null, entryId: id(entity) });
    problem(await f.read(`/catalog/brands/${id(entity)}/versions/${revision(written)}`), 404);
    expect(check(await f.read(`${path}?limit=1`), 200).data).not.toHaveProperty('reviewedBy');
  }, TIMEOUT);

  it('projects legacy P03 city names safely on both P04 discovery routes without changing city history', async () => {
    const f = fixture();
    await f.asCatalog();
    const { primary } = await f.cities();
    const cityPath = `/settings/service-cities/${primary.id}`;
    const versionPath = `${cityPath}/versions`;
    const cases = [
      { original: 'North\t\u200b\tCity', projected: 'North City' },
      { original: '\u200b\u2060', projected: null },
    ];
    const observed = [];
    for (const { original, projected } of cases) {
      const before = check(await f.geo.cityDetail(f.admin, primary.id), 200);
      const code = text(before.data, 'code');
      const added = check(await f.geo.write(f.admin, 'post', versionPath, {
        displayName: original, timezone: 'Europe/Moscow', publicContact: '+70000000000',
        officeHours: Array.from({ length: 7 }, () => [[540, 1080]]),
      }, { etag: geoTag(versionOf(before)) }), 201);
      const versionId = text(added.data, 'id');
      check(await f.geo.publishCityVersion(f.admin, primary.id, versionId, versionOf(added)), 200);
      observed.push({
        cities: await f.read(CITIES), readiness: await f.read('/pricing/readiness'), code, name: projected ?? code,
      });
      const current = check(await f.geo.cityDetail(f.admin, primary.id), 200);
      expect(current.data['currentVersion']).toMatchObject({ id: versionId, displayName: original });
      const history = check(await f.geo.read(f.admin, versionPath), 200);
      expect(records(history.data['items'])).toContainEqual(expect.objectContaining({ id: versionId, displayName: original }));
    }
    for (const { cities, readiness, code, name } of observed) {
      const cityLabel = { id: primary.id, code, name };
      expect(page(check(cities, 200))).toEqual([cityLabel]);
      expect(page(check(readiness, 200))).toEqual([{ ...cityLabel, fixed: 'MISSING', policy: 'MISSING' }]);
    }
  }, TIMEOUT);

  it('requires a lowercase P04 idempotency key before write and replay', async () => {
    const f = fixture();
    await f.asCatalog();
    // Force one alphabetic digit so the uppercase variant is always different.
    const key = `a${randomUUID().slice(1)}`;
    const upper = key.toUpperCase();
    const body = { code: fixtureCode('lowercase-key') };
    const before = await f.evidence();
    problem(await f.post(CATEGORIES, body, { key: upper }), 400);
    expect(await f.evidence()).toEqual(before);
    expect(await f.readReceipt(key)).toEqual([]);
    const written = receipt(await f.post(CATEGORIES, body, { key }), 201);
    const committed = await f.evidence();
    problem(await f.post(CATEGORIES, body, { key: upper }), 400);
    const replay = receipt(await f.post(CATEGORIES, body, { key }), 200);
    expect([replay.data, replay.etag]).toEqual([written.data, written.etag]);
    expect(await f.evidence()).toEqual(committed);
    expect(await f.readReceipt(key)).toHaveLength(1);
  }, TIMEOUT);

  it('uses real CITY read/manage intersection and conceals receipts after their old city is revoked', async () => {
    const f = fixture();
    await f.asCatalog();
    const staff = await f.base.webStaff();
    const managerRole = await f.base.systemRole('MANAGER');
    const { primary, other } = await f.cities();
    const category = await f.category();
    const part = await f.part(category.id);
    const primaryPrice = p04Path('fixedPublish', { cityId: primary.id, itemId: part.id });
    const otherPrice = p04Path('fixedPublish', { cityId: other.id, itemId: part.id });
    const body = { amountMinor: '9223372036854775807', currency: 'RUB', sourceRef: 'review://synthetic/max-price', validFrom: await f.dbInstant() };
    problem(await f.read(CITIES, { web: staff }), 403);
    check(await f.addRoleGrants(managerRole, [city('pricing.read')]), 200);
    expect(page(check(await f.read(CITIES, { web: staff }), 200))).toEqual([]);
    const assignment = check(await f.assignCity(staff.id, primary.id), 201);
    expect(page(check(await f.read(CITIES, { web: staff }), 200))).toEqual([expect.objectContaining({ id: primary.id })]);
    expect(Object.keys(page(check(await f.read(CITIES, { web: staff }), 200))[0] ?? {}).sort()).toEqual(['code', 'id', 'name']);
    const labels = page(check(await f.read(`${CITIES}/${primary.id}/items`, { web: staff }), 200));
    expect(labels).toEqual([expect.objectContaining({ id: part.id, title: 'Reviewed part' })]);
    expect(labels[0]).not.toHaveProperty('amountMinor');
    problem(await f.read(`${CITIES}/${other.id}/items`, { web: staff }), 404);
    problem(await f.read('/pricing/rules', { web: staff }), 403);
    problem(await f.read(CATEGORIES, { web: staff }), 403);
    problem(await f.post(primaryPrice, body, { web: staff, etag: p04Tag(0) }), 403);
    check(await f.addRoleGrants(managerRole, [city('pricing.manage')]), 200);
    const key = randomUUID();
    const command = (path: string) => f.post(path, body, { web: staff, key, etag: p04Tag(0) });
    const created = receipt(await command(primaryPrice), 201, true);
    expect(await f.readReceipt(key)).toEqual([expect.objectContaining({ actor_id: staff.id, operation: 'fixedPublish',
      subject_id: part.id, city_id: primary.id, entity_id: id(created), revision_id: revision(created) })]);
    const exact = check(await f.read(`${primaryPrice}/${revision(created)}`, { web: staff }), 200).data;
    expect(exact).toMatchObject({ cityId: primary.id, itemId: part.id, amountMinor: body.amountMinor });
    expect(exact).not.toHaveProperty('reviewedBy');
    problem(await command(otherPrice), 404);
    problem(await f.read(`${otherPrice}/${revision(created)}`), 404); // even GLOBAL caller cannot use wrong parent
    const current = check(await f.geo.cityDetail(f.admin, primary.id), 200);
    check(await f.geo.write(f.admin, 'post', `/settings/service-cities/${other.id}/activate`,
      { replaceActiveCityId: primary.id, replaceActiveCityVersion: versionOf(current) }, { etag: geoTag(other.version) }), 200);
    check(await f.assignCity(staff.id, other.id), 201);
    problem(await command(otherPrice), 409); // distinguish a collision only while both cities are authorized
    await f.base.db.query('UPDATE foundation.staff_admin_city_assignments SET revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1',
      [text(assignment.data, 'id'), f.admin.id]);
    problem(await command(primaryPrice), 404);
    const concealed = await command(otherPrice);
    problem(concealed, 404);
    expect(JSON.stringify(concealed.body)).not.toContain(revision(created));
    expect(await f.readReceipt(key)).toHaveLength(1);
    receipt(await f.post(otherPrice, body, { web: staff, etag: p04Tag(0) }), 201, true);
  }, TIMEOUT);

  it('conceals empty pricing streams for CITY-invisible positions before receipt matching', async () => {
    const f = fixture();
    await f.asCatalog();
    const manager = await f.base.webStaff();
    check(await f.addRoleGrants(await f.base.systemRole('MANAGER'), [city('pricing.read'), city('pricing.manage')]), 200);
    const { primary, other } = await f.cities();
    check(await f.assignCity(manager.id, primary.id), 201);
    const category = await f.category();
    const visible = await f.part(category.id);
    const hidden = receipt(await f.post('/catalog/items', { kind: 'PART', code: fixtureCode('draft'), unit: 'piece' }), 201);
    const remote = await f.part();
    const archivedEmpty = await f.part();
    const path = (cityId: string, itemId: string) => p04Path('fixedList', { cityId, itemId });
    const body = { amountMinor: '100', currency: 'RUB', sourceRef: 'synthetic only', validFrom: await f.dbInstant() };
    const web = { web: manager };
    const key = randomUUID();
    const fresh = { ...web, etag: p04Tag(0) };
    problem(await f.read('/catalog/items', web), 403);
    expect(check(await f.read(path(primary.id, visible.id), web), 200).data).toMatchObject({ version: 0, items: [] });
    const stored = receipt(await f.post(path(primary.id, visible.id), body, { ...fresh, key }), 201, true);
    receipt(await f.post(path(other.id, remote.id), body, { etag: p04Tag(0) }), 201, true);
    for (const item of [visible, remote, archivedEmpty]) {
      receipt(await f.post(`/catalog/items/${item.id}/archive`, {}, { etag: item.published.etag }), 200);
    }
    const before = await f.readReceipt(key);
    expect(page(check(await f.read(`${CITIES}/${primary.id}/items`, web), 200))).toEqual([]);
    for (const itemId of [id(hidden), remote.id, archivedEmpty.id, randomUUID()]) {
      problem(await f.read(path(primary.id, itemId), web), 404);
      problem(await f.read(`${path(primary.id, itemId)}?includeArchived=true`, web), 404);
      problem(await f.post(path(primary.id, itemId), body, { ...fresh, key }), 404);
      problem(await f.post(path(primary.id, itemId), body, fresh), 404);
    }
    expect(await f.readReceipt(key)).toEqual(before);
    expect(check(await f.read(`${path(primary.id, visible.id)}/${revision(stored)}`, web), 200).data)
      .toMatchObject({ cityId: primary.id, itemId: visible.id, amountMinor: '100' });
    expect(page(check(await f.read(path(primary.id, visible.id), web), 200))).toHaveLength(1);
    expect(receipt(await f.post(path(primary.id, visible.id), body, { ...fresh, key }), 200, true).data).toEqual(stored.data);
  }, TIMEOUT);

  it('applies CITY visibility to rule history and pricing references before receipt conflicts', async () => {
    const f = fixture();
    await f.asCatalog();
    const manager = await f.base.webStaff();
    check(await f.addRoleGrants(await f.base.systemRole('MANAGER'), [city('pricing.read'), city('pricing.manage')]), 200);
    const { primary, other } = await f.cities();
    check(await f.assignCity(manager.id, primary.id), 201);
    const category = await f.category();
    const unpublished = receipt(await f.post(CATEGORIES, { code: fixtureCode('hidden-reference') }), 201);
    const liveRule = receipt(await f.post('/pricing/rules', { code: fixtureCode('live-rule'), kind: 'EXPRESS' }), 201);
    const remoteRule = receipt(await f.post('/pricing/rules', { code: fixtureCode('other-city-rule'), kind: 'EXPRESS' }), 201);
    const rulePath = (cityId: string, ruleId: string) => p04Path('ruleVersionList', { cityId, ruleId });
    const ruleForm = { kind: 'EXPRESS', method: 'FIXED', fixedMinor: '10', base: 'ORDER_BASE', title: 'Synthetic express',
      currency: 'RUB', validFrom: await f.dbInstant(), sourceRef: 'synthetic-rule-source', categoryIds: [category.id] };
    const web = { web: manager };
    const fresh = { ...web, etag: p04Tag(0) };
    const keys = { rule: randomUUID(), estimate: randomUUID(), policy: randomUUID() };
    const target = rulePath(primary.id, id(liveRule));
    const rule = receipt(await f.post(target, ruleForm, { ...fresh, key: keys.rule }), 201, true);
    receipt(await f.post(rulePath(other.id, id(remoteRule)), ruleForm, { etag: p04Tag(0) }), 201, true);
    const estimates = p04Path('estimateCreate', { cityId: primary.id });
    const estimateBody = { categoryId: category.id, code: fixtureCode('estimate') };
    const estimate = receipt(await f.post(estimates, estimateBody, { ...web, key: keys.estimate }), 201);
    const policy = p04Path('policyPublish', { cityId: primary.id });
    const policyBody = { currency: 'RUB', validFrom: ruleForm.validFrom, sourceRef: 'synthetic-policy-source', taxDisplay: 'Synthetic',
      roundingMode: 'HALF_UP', units: { piece: 0 }, maxManualDeltaMinor: '0', priorities: [{ ruleId: id(liveRule), priority: 1 }], compatibilities: [] };
    const savedPolicy = receipt(await f.post(policy, policyBody, { ...fresh, key: keys.policy }), 201, true);
    receipt(await f.post(`/pricing/rules/${id(remoteRule)}/archive`, {}, { etag: remoteRule.etag }), 200);
    const remote = rulePath(primary.id, id(remoteRule));
    problem(await f.read(remote, web), 404);
    problem(await f.post(remote, ruleForm, { ...fresh, key: keys.rule }), 404);
    problem(await f.post(target, { ...ruleForm, categoryIds: [id(unpublished)] }, { ...fresh, key: keys.rule }), 404);
    problem(await f.post(estimates, { ...estimateBody, categoryId: id(unpublished) }, { ...web, key: keys.estimate }), 404);
    problem(await f.post(policy, { ...policyBody, priorities: [{ ruleId: id(remoteRule), priority: 1 }] }, { ...fresh, key: keys.policy }), 404);
    receipt(await f.post(`/pricing/rules/${id(liveRule)}/archive`, {}, { etag: liveRule.etag }), 200);
    receipt(await f.post(`${CATEGORIES}/${category.id}/archive`, {}, { etag: category.published.etag }), 200);
    expect(check(await f.read(`${target}/${revision(rule)}`, web), 200).data).toMatchObject({ categoryIds: [category.id] });
    expect(receipt(await f.post(target, ruleForm, { ...fresh, key: keys.rule }), 200, true).data).toEqual(rule.data);
    expect(receipt(await f.post(estimates, estimateBody, { ...web, key: keys.estimate }), 200).data).toEqual(estimate.data);
    expect(receipt(await f.post(policy, policyBody, { ...fresh, key: keys.policy }), 200, true).data).toEqual(savedPolicy.data);
  }, TIMEOUT);

  it('uses typed reviewed manual Avito history and city policy/rule/estimate projections without expanding the API', async () => {
    const f = fixture();
    await f.asCatalog();
    const { primary } = await f.cities();
    const label = await f.category();
    const at = await f.dbInstant();
    const basis = { currency: 'RUB', validFrom: at, sourceRef: 'synthetic-reviewed' };
    const rule = receipt(await f.post('/pricing/rules', { code: fixtureCode('express'), kind: 'EXPRESS' }), 201);
    const rulePath = p04Path('ruleVersionPublish', { cityId: primary.id, ruleId: id(rule) });
    const publishedRule = receipt(await f.post(rulePath, { ...basis, kind: 'EXPRESS', method: 'RATE', rateBps: 10000,
      title: 'Reviewed express', base: 'WORKS', categoryIds: [label.id] }, { etag: p04Tag(0) }), 201, true);
    expect(check(await f.read(`${rulePath}/${revision(publishedRule)}`), 200).data).toMatchObject({ rateBps: 10000, currency: 'RUB', categoryIds: [label.id] });
    const policyPath = p04Path('policyPublish', { cityId: primary.id });
    const policy = receipt(await f.post(policyPath, { ...basis, taxDisplay: 'Reviewed tax display', roundingMode: 'HALF_UP',
      units: { piece: 0 }, maxManualDeltaMinor: '10', priorities: [{ ruleId: id(rule), priority: 10 }], compatibilities: [] }, { etag: p04Tag(0) }), 201, true);
    expect(check(await f.read(`${policyPath}/${revision(policy)}`), 200).data).toMatchObject({ maxManualDeltaMinor: '10', units: { piece: 0 } });
    const estimates = p04Path('estimateCreate', { cityId: primary.id });
    const estimate = receipt(await f.post(estimates, { code: fixtureCode('range'), categoryId: label.id }), 201);
    const inputs = { ...basis, title: 'Reviewed range', minMinor: '0', maxMinor: '9223372036854775807', disclaimer: 'Synthetic only' };
    const rangePath = `${estimates}/${id(estimate)}/versions`;
    problem(await f.post(rangePath, { ...inputs, maxMinor: 10 }, { etag: estimate.etag }), 400);
    const range = receipt(await f.post(rangePath, inputs, { etag: estimate.etag }), 201, true);
    expect(check(await f.read(`${rangePath}/${revision(range)}`), 200).data).toMatchObject({ minMinor: '0', maxMinor: inputs.maxMinor });
    const discovery = page(check(await f.read('/pricing/readiness'), 200));
    expect(discovery).toEqual([expect.objectContaining({ id: primary.id, fixed: 'MISSING', policy: 'MISSING' })]);
    expect(Object.keys(discovery[0] ?? {}).sort()).toEqual(['code', 'fixed', 'id', 'name', 'policy']);
    const profile = receipt(await f.post(AVITO, { kind: 'PROFILE', code: fixtureCode('profile') }), 201);
    const source = { title: 'Synthetic profile', permissionRef: 'synthetic review authorization', sourceUrl: 'https://www.avito.ru/synthetic/profile' };
    const profilePath = `${AVITO}/${id(profile)}/versions`;
    problem(await f.post(profilePath, { ...source, sourceUrl: 'https://www.avito.ru:443/synthetic/profile' }, { etag: profile.etag }), 400);
    const published = receipt(await f.post(profilePath, source, { etag: profile.etag }), 201, true);
    const review = receipt(await f.post(AVITO, { kind: 'REVIEW', code: fixtureCode('review'), profileId: id(profile) }), 201);
    const reviewPath = `${AVITO}/${id(review)}/versions`;
    const reviewed = receipt(await f.post(reviewPath, { ...source, title: 'Synthetic review', sourceDate: '2026-11-22',
      excerpt: 'Reviewed synthetic excerpt', rating: 5 }, { etag: review.etag }), 201, true);
    const view = check(await f.read(`${reviewPath}/${revision(reviewed)}`), 200).data;
    expect(view).toMatchObject({ profileRevisionId: revision(published), rating: 5, title: 'Synthetic review' });
    expect(view).not.toHaveProperty('reviewedBy');
    receipt(await f.post(`${AVITO}/${id(profile)}/archive`, {}, { etag: published.etag }), 200);
    expect(check(await f.read(`${reviewPath}/${revision(reviewed)}`), 200).data).toEqual(view);
    problem(await f.post(reviewPath, { ...source, sourceDate: '2026-11-22', excerpt: 'Rejected because parent archived' }, { etag: reviewed.etag }), 409);
  }, TIMEOUT);

  it('validates the persisted Avito type before stale CAS and before any receipt conflict', async () => {
    const f = fixture();
    await f.asCatalog();
    const profile = receipt(await f.post(AVITO, { kind: 'PROFILE', code: fixtureCode('profile-kind') }), 201);
    const path = `${AVITO}/${id(profile)}/versions`;
    const source = { title: 'Synthetic source', permissionRef: 'Synthetic review proof', sourceUrl: 'https://avito.ru/synthetic/source' };
    const key = randomUUID();
    const published = receipt(await f.post(path, source, { key, etag: profile.etag }), 201, true);
    const review = receipt(await f.post(AVITO, { kind: 'REVIEW', code: fixtureCode('review-kind'), profileId: id(profile) }), 201);
    const reviewPath = `${AVITO}/${id(review)}/versions`;
    const reviewShape = { ...source, sourceDate: '2026-11-22', excerpt: 'Reviewed only for a REVIEW entry', rating: 4 };
    const reviewed = receipt(await f.post(reviewPath, reviewShape, { etag: review.etag }), 201, true);
    const before = await f.evidence();
    problem(await f.post(path, reviewShape, { etag: profile.etag }), 400);
    problem(await f.post(path, reviewShape, { key, etag: profile.etag }), 400);
    problem(await f.post(reviewPath, source, { etag: review.etag }), 400);
    problem(await f.post(path, { ...source, title: 'Valid changed profile body' }, { key, etag: profile.etag }), 409);
    expect(receipt(await f.post(path, source, { key, etag: profile.etag }), 200, true).data).toEqual(published.data);
    expect(check(await f.read(`${reviewPath}/${revision(reviewed)}`), 200).data).toMatchObject({ profileRevisionId: revision(published) });
    expect(await f.evidence()).toEqual(before);
  }, TIMEOUT);

  it('closes P04 reads and writes while the shared RBAC grant fence trigger is disabled', async () => {
    const f = fixture();
    await f.asCatalog();
    check(await f.read(CATEGORIES), 200);
    const command = () => f.post(CATEGORIES, { code: 'synthetic-rbac-fence-drift' });
    const before = await f.evidence();
    await f.base.db.query('ALTER TABLE foundation.role_permissions DISABLE TRIGGER rbac_grant_write');
    try {
      problem(await f.read(CATEGORIES), 503);
      problem(await command(), 503);
      expect(await f.evidence()).toEqual(before);
    } finally {
      await f.base.db.query('ALTER TABLE foundation.role_permissions ENABLE TRIGGER rbac_grant_write');
    }
    check(await f.read(CATEGORIES), 200);
    receipt(await command(), 201);
  }, TIMEOUT);

  it.each([
    ['audit_logs', '57014'], ['outbox_events', '57014'], ['p04_command_receipts', '57014'], ['p04_command_receipts', '23505'],
  ] as const)('rolls back domain and all evidence after an actual %s INSERT fault (%s)', async (table, sqlstate) => {
    const f = fixture();
    await f.asCatalog();
    const draft = receipt(await f.post(CATEGORIES, { code: fixtureCode('rollback') }), 201);
    const path = `${CATEGORIES}/${id(draft)}/versions`;
    const before = await f.evidence();
    // Install only after readiness probe and locked authorization, before receipt SELECT/domain write.
    await f.base.db.query(`CREATE FUNCTION foundation.p04_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION '${PRIVATE_P04}' USING ERRCODE='${sqlstate}'; END $$`);
    const hook = f.observeP04Receipt({ beforeSelect: async () => {
      await f.base.db.query(`CREATE TRIGGER p04_http_fault BEFORE INSERT ON foundation.${table}
        FOR EACH ROW EXECUTE FUNCTION foundation.p04_http_fault()`);
    } });
    const key = randomUUID();
    const command = () => f.post(path, { title: 'Reviewed rollback' }, { key, etag: draft.etag });
    try { problem(await command(), 500); expect(hook.fired()).toBe(1); }
    finally {
      hook.restore();
      await f.base.db.query(`DROP TRIGGER IF EXISTS p04_http_fault ON foundation.${table}`);
      await f.base.db.query('DROP FUNCTION foundation.p04_http_fault()');
    }
    expect(await f.evidence()).toEqual(before);
    expect(await f.readReceipt(key)).toEqual([]);
    expect(check(await f.read(`${CATEGORIES}/${id(draft)}`), 200).data).toMatchObject({ version: 1, currentVersionId: null });
    receipt(await command(), 201, true);
    expect(await f.readReceipt(key)).toHaveLength(1);
  }, TIMEOUT);

  it.each(['receipt-read', 'receipt-insert'] as const)('rechecks DB-clock session freshness after an actual %s lock wait', async step => {
    const f = fixture();
    await f.asCatalog();
    const key = randomUUID();
    const body = { code: fixtureCode('expiry') };
    const command = () => f.post(CATEGORIES, body, { key });
    if (step === 'receipt-read') { receipt(await command(), 201); }
    const before = await f.evidence();
    const locker = await f.base.db.connect();
    let pending: ReturnType<typeof command> | undefined;
    try {
      const holder = await f.backend(locker);
      await locker.query('BEGIN');
      const hook = f.observeP04Receipt({ beforeSelect: async () => {
        await locker.query(`LOCK TABLE foundation.p04_command_receipts IN ${step === 'receipt-read' ? 'ACCESS EXCLUSIVE' : 'SHARE'} MODE`);
      } });
      try {
        const expiry = await f.shortenSession(f.admin, step === 'receipt-read' ? 'idle' : 'absolute', 2400);
        pending = command(); void pending.catch(() => undefined);
        expect(await f.waitForLock(holder, 'p04_command_receipts', step === 'receipt-read' ? 'AccessShareLock' : 'RowExclusiveLock')).not.toBe(holder);
        expect(hook.fired()).toBe(1);
        await f.waitForExpiry(expiry);
        await locker.query('COMMIT');
        problem(await pending, 401);
        expect(await f.evidence()).toEqual(before);
      } finally { hook.restore(); }
    } finally { await locker.query('ROLLBACK'); locker.release(); await Promise.allSettled([pending]); }
  }, TIMEOUT);

  it('waits behind real RBAC grant removal and returns no historical receipt on the losing side', async () => {
    const f = fixture();
    await f.asCatalog();
    const manager = await f.base.webStaff();
    const roleId = await f.base.systemRole('MANAGER');
    check(await f.addRoleGrants(roleId, [city('pricing.read'), city('pricing.manage')]), 200);
    const { primary } = await f.cities();
    await f.assignCity(manager.id, primary.id);
    const cat = await f.category();
    const path = p04Path('estimateCreate', { cityId: primary.id });
    const data = { code: fixtureCode('revoke'), categoryId: cat.id };
    const key = randomUUID();
    const command = () => f.post(path, data, { key, web: manager });
    const won = receipt(await command(), 201);
    const role = check(await f.base.call(f.admin, 'get', `/roles/${roleId}`), 200);
    const remaining = records(role.data['permissions']).filter(x => x['code'] !== 'pricing.manage');
    const revoke = () => f.base.call(f.admin, 'put', `/roles/${roleId}/permissions`, { permissions: remaining }, role.etag);
    const locker = await f.base.db.connect();
    let a: ReturnType<typeof revoke> | undefined;
    let b: ReturnType<typeof command> | undefined;
    try {
      await locker.query('BEGIN');
      const blocker = await f.backend(locker);
      await locker.query('LOCK TABLE foundation.audit_logs IN EXCLUSIVE MODE');
      a = revoke(); void a.catch(() => undefined);
      const policyHolder = await f.waitForLock(blocker, 'audit_logs', 'RowExclusiveLock');
      b = command(); void b.catch(() => undefined);
      expect(await f.waitForPolicyWait(policyHolder)).not.toBe(policyHolder);
      await locker.query('COMMIT');
      check(await a, 200);
      const denied = await b;
      problem(denied, 403);
      expect(JSON.stringify(denied.body)).not.toContain(id(won));
      expect(await f.readReceipt(key)).toHaveLength(1);
    } finally { await locker.query('ROLLBACK'); locker.release(); await Promise.allSettled([a, b]); }
  }, TIMEOUT);

  it('returns 503 for hidden successful COMMIT, then only explicit authorized retry gets the exact 200 receipt', async () => {
    const f = fixture();
    await f.asCatalog();
    const key = randomUUID();
    const body = { code: fixtureCode('lost-ack') };
    const command = () => f.post(CATEGORIES, body, { key });
    const before = await f.evidence();
    const hook = f.observeP04Receipt({ loseCommitAck: true });
    try {
      problem(await command(), 503);
      expect(hook.fired()).toBe(1);
    } finally { hook.restore(); }
    const [stored] = await f.readReceipt(key);
    expect(stored).toMatchObject({ actor_id: f.admin.id, operation: 'categoryCreate', entity_version: 1 });
    const committed = await f.evidence();
    for (const field of ['entries', 'receipts', 'audits', 'outbox']) { expect(committed[field]).toBe(Number(before[field]) + 1); }
    expect(committed['revisions']).toBe(before['revisions']);
    const replay = receipt(await command(), 200);
    expect(replay.data).toEqual({ id: stored?.entity_id, version: stored?.entity_version });
    expect(await f.evidence()).toEqual(committed);
    await f.waitForExpiry(await f.shortenSession(f.admin, 'idle', 100));
    const unauthorized = await command();
    problem(unauthorized, 401);
    const unauthorizedBody = record(unauthorized.body);
    expect(unauthorizedBody).not.toHaveProperty('data');
    expect(JSON.stringify(unauthorizedBody)).not.toContain(id(replay));
    expect(await f.evidence()).toEqual(committed);
  }, TIMEOUT);
});
