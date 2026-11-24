import { createHash, randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { check, geoTag, records, text } from './geography-fixture.js';
import { integration } from './rbac-fixture.js';
import {
  city, COMPANY_FIELDS, contentInput, fixtureCode, global, idOf, legalInput, managementPerTest, minimal, p03Tag,
  PRIVATE_MARKER, problem, referencePath,
} from './settings-management-fixture.js';
import type { ManagementFixture } from './settings-management-fixture.js';

const PAYMENT = referencePath('payment_method');
const LEGAL = '/legal/documents';
const CONTENT = '/content/blocks';
const COMPANY = '/settings/versions';
const publishedRef = { label: 'Synthetic label', sourceRef: 'fixture-reference', validFrom: '2020-01-01T00:00:00.000Z', validUntil: null };
const evidenceTables = ['p03_command_receipts', 'audit_logs', 'outbox_events'] as const;
async function snapshot(f: ManagementFixture) {
  return Promise.all(['reference_entries', 'reference_entry_versions', ...evidenceTables]
    .map((table) => f.base.count(`SELECT count(*)::int AS n FROM foundation.${table}`)));
}

integration('P03 commands through real Nest authorization, domain ports and PostgreSQL', () => {
  const fixture = managementPerTest();

  it('composes real geography activation and complete company revisions: no prerequisites loop or caller-supplied primary', async () => {
    const f = fixture();
    const empty = check(await f.read(COMPANY), 200);
    expect(empty.etag).toBe(p03Tag(0));
    expect(records(empty.data['items'])).toHaveLength(0);
    const primary = await f.geo.activeCity(f.admin, 'primary-fixture');
    const first = check(await f.read(COMPANY), 200);
    expect(first.etag).toBe(p03Tag(1));
    const firstExact = check(await f.read(`${COMPANY}/1`), 200);
    expect(firstExact.data).toMatchObject({ primaryCityId: primary.id, launchMode: 'SINGLE_CITY',
      settings: Object.fromEntries(Object.keys(COMPANY_FIELDS).map((key) => [key, null])) });
    const no = { ...COMPANY_FIELDS }; Reflect.deleteProperty(no, 'retentionPolicyRef');
    for (const invalid of [no, { ...COMPANY_FIELDS, operatorName: ' ' }, { ...COMPANY_FIELDS, primaryCityId: randomUUID() },
      { ...COMPANY_FIELDS, ready: true }, { ...COMPANY_FIELDS, actor: f.admin.id }]) {
      problem(await f.post(COMPANY, invalid, { etag: first.etag }), 400);
    }
    expect(check(await f.read(COMPANY), 200).etag).toBe(first.etag);
    const result = check(await f.post(COMPANY, COMPANY_FIELDS, { etag: first.etag }), 201);
    minimal(result);
    expect(result.data['version']).toBe(2);
    const latest = check(await f.read(`${COMPANY}/2`), 200);
    const publishedAt = text(latest.data, 'publishedAt');
    expect(Number.isFinite(Date.parse(publishedAt))).toBe(true);
    expect(latest.data).toEqual({ ...result.data, publishedAt, primaryCityId: primary.id,
      launchMode: 'SINGLE_CITY', reviewedBy: f.admin.id, settings: COMPANY_FIELDS });
    expect(check(await f.read(`${COMPANY}/1`), 200).data).toEqual(firstExact.data);
    problem(await f.read(`${COMPANY}/3`), 404);
    const page = check(await f.read(`${COMPANY}?limit=1`), 200);
    expect(records(page.data['items'])).toEqual([{ ...result.data, publishedAt: latest.data['publishedAt'] }]);
    await f.assertSafeEvidence();
  });

  it('enforces all five closed reference types and immutable current/history; callback snapshot pins the exact city version', async () => {
    const f = fixture(); const a = f.admin;
    const x = await f.geo.activeCity(a, 'reference-a');
    const y = await f.geo.publishedDraftCity(a, 'reference-b');
    const callback = referencePath('callback_interval');
    problem(await f.read(callback), 400);
    problem(await f.post(callback, { code: 'interval' }), 400);
    problem(await f.read(`${PAYMENT}?cityId=${x.id}`), 400);
    problem(await f.post(referencePath('reference_entries'), { code: 'escape' }), 400);
    const types = [
      ['payment_method', 'PAYMENT_METHOD'], ['cancel_reason', 'CANCEL_REASON'],
      ['decline_reason', 'DECLINE_REASON'], ['request_source', 'REQUEST_SOURCE'],
    ] as const;
    const idByType = new Map<string, string>();
    for (const [type, expected] of types) {
      const path = referencePath(type);
      const entry = check(await f.post(path, { code: 'same-code' }), 201); minimal(entry);
      const id = idOf(entry); idByType.set(type, id);
      const revision = check(await f.post(`${path}/${id}/versions`, publishedRef, { etag: entry.etag }), 201);
      minimal(revision, true);
      const detail = check(await f.read(`${path}/${id}`), 200);
      expect(detail.data).toMatchObject({ id, type: expected, scope: 'COMPANY', cityId: null, currentVersionId: revision.data['revisionId'] });
      const exact = check(await f.read(`${path}/${id}/versions/${text(revision.data, 'revisionId')}`), 200);
      expect(exact.data).toMatchObject({ entryId: id, type: expected, cityId: null, provenanceCityVersionId: null, interval: null });
    }
    problem(await f.read(`${PAYMENT}/${String(idByType.get('cancel_reason'))}`), 404);
    const query = `?cityId=${x.id}`;
    const entry = check(await f.post(callback + query, { code: 'interval' }), 201); minimal(entry);
    const path = `${callback}/${idOf(entry)}`;
    const firstInput = { ...publishedRef, cityVersionId: x.versionId, interval: { startMinute: 60, endMinute: 120 } };
    problem(await f.post(`${path}/versions${query}`, { ...firstInput, cityVersionId: y.versionId }, { etag: entry.etag }), 404);
    problem(await f.post(`${path}/versions${query}`, { ...firstInput, interval: { startMinute: 120, endMinute: 60 } }, { etag: entry.etag }), 400);
    const first = check(await f.post(`${path}/versions${query}`, firstInput, { etag: entry.etag }), 201);
    const second = check(await f.post(`${path}/versions${query}`, { ...firstInput, label: 'New label' }, { etag: first.etag }), 201);
    minimal(second, true);
    const page = check(await f.read(`${path}/versions${query}&limit=1`), 200);
    const cursor = text(page.data['pageInfo'] as Record<string, unknown>, 'nextCursor');
    const rest = check(await f.read(`${path}/versions${query}&limit=1&cursor=${encodeURIComponent(cursor)}`), 200);
    expect(new Set([...(records(page.data['items'])), ...records(rest.data['items'])].map(({ id }) => id)))
      .toEqual(new Set([first.data['revisionId'], second.data['revisionId']]));
    problem(await f.read(`${PAYMENT}/${idByType.get('payment_method') ?? ''}/versions?cursor=${encodeURIComponent(cursor)}`), 400);
    const archived = check(await f.post(`${path}/archive${query}`, {}, { etag: second.etag }), 200); minimal(archived);
    expect(records(check(await f.read(callback + query), 200).data['items'])).toEqual([]);
    expect(records(check(await f.read(`${callback + query}&includeArchived=true`), 200).data['items']).map(({ id }) => id)).toEqual([idOf(entry)]);
    const firstExact = `${path}/versions/${text(first.data, 'revisionId')}`;
    expect(check(await f.read(firstExact + query), 200).data).toMatchObject({ label: firstInput.label,
      provenanceCityVersionId: x.versionId, interval: firstInput.interval });
    problem(await f.read(`${firstExact}?cityId=${y.id}`), 404);
    problem(await f.post(`${path}/versions${query}`, firstInput, { etag: archived.etag }), 409);
  }, 30_000);

  it('round trips all content kinds and both legal purposes; exact parent and reserved-purpose checks hold under real RC', async () => {
    const f = fixture(); const a = f.admin;
    const scope = { scope: 'COMPANY', allowCompanyFallback: true };
    const createBlock = async (kind: string) => check(await f.post(CONTENT, { ...scope, kind, code: fixtureCode('content') }), 201);
    const [faq, fact, seo] = await Promise.all([createBlock('FAQ'), createBlock('FACT'), createBlock('SEO')]);
    minimal(seo);
    const block = `${CONTENT}/${idOf(faq)}`;
    const other = `${CONTENT}/${idOf(fact)}`;
    const body = `<script>"${PRIVATE_MARKER}"</script>`;
    const p = check(await f.post(`${block}/publish`, contentInput(body), { etag: faq.etag }), 201);
    minimal(p, true);
    const revisionId = text(p.data, 'revisionId');
    problem(await f.read(`${other}/revisions/${revisionId}`), 404);
    expect(check(await f.read(`${block}/revisions/${revisionId}`, { safeBody: false }), 200).data).toMatchObject({ body });
    const summary = records(check(await f.read(`${block}/revisions?limit=200`), 200).data['items']);
    expect(summary.map((r) => Object.keys(r).sort())).toEqual([['blockId', 'id', 'publishedAt', 'title', 'version']]);
    const archived = check(await f.post(`${block}/archive`, {}, { etag: p.etag }), 200); minimal(archived);
    expect(check(await f.read(`${block}/revisions/${revisionId}`, { safeBody: false }), 200).data['body']).toBe(body);

    const request = check(await f.post(LEGAL, { purpose: 'REQUEST_PROCESSING', kind: 'CONSENT_FORM' }), 201);
    const marketing = check(await f.post(LEGAL, { purpose: 'MARKETING', kind: 'OPT_IN_NOTICE' }), 201);
    minimal(request); minimal(marketing);
    const path = `${LEGAL}/${idOf(request)}`;
    const legal = legalInput();
    for (const field of ['reviewedBy', 'actor', 'checksum', 'ready', 'publishedAt']) {
      problem(await f.post(`${path}/publish`, { ...legal, [field]: PRIVATE_MARKER }, { etag: request.etag }), 400);
    }
    const published = check(await f.post(`${path}/publish`, legal, { etag: request.etag }), 201); minimal(published, true);
    const next = check(await f.post(`${path}/publish`, legalInput('Replacement legal fixture'), { etag: published.etag }), 201);
    const exactId = text(published.data, 'revisionId');
    const exact = check(await f.read(`${path}/versions/${exactId}`, { safeBody: false }), 200);
    expect(exact.data).toMatchObject({ ...legal, reviewedBy: a.id, checksum: createHash('sha256').update(legal.body).digest('hex'),
      purpose: 'REQUEST_PROCESSING', kind: 'CONSENT_FORM', id: exactId });
    expect(check(await f.read(path), 200).data['currentVersionId']).toBe(next.data['revisionId']);
    const history = check(await f.read(`${path}/versions?limit=200`), 200);
    expect(records(history.data['items']).map((r) => Object.keys(r).sort())).toEqual(Array.from({ length: 2 },
      () => ['checksum', 'documentId', 'id', 'publishedAt', 'sequence', 'title']));
    expect(history.bytes).toBeLessThan(512 * 1024);
    problem(await f.read(`${LEGAL}/${idOf(marketing)}/versions/${exactId}`), 404);
    problem(await f.post(LEGAL, { purpose: 'ADDRESS_COVERAGE', kind: 'CONSENT_FORM' }), 400);
    const reserved = randomUUID(); const reservedVersion = randomUUID();
    await f.base.db.query("INSERT INTO foundation.legal_documents (id,purpose,kind) VALUES ($1,'ADDRESS_COVERAGE','CONSENT_FORM')", [reserved]);
    await f.base.db.query(`INSERT INTO foundation.legal_document_versions
      (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
      VALUES ($1,$2,'ADDRESS_COVERAGE','CONSENT_FORM',1,'Reserved fixture',$3,$4,'Reserved basis','Reserved source',$5)`,
    [reservedVersion, reserved, PRIVATE_MARKER, createHash('sha256').update(PRIVATE_MARKER).digest('hex'), a.id]);
    expect(records(check(await f.read(LEGAL), 200).data['items']).map(({ id }) => id).sort()).toEqual([idOf(request), idOf(marketing)].sort());
    for (const end of ['', '/versions', `/versions/${reservedVersion}`]) { problem(await f.read(`${LEGAL}/${reserved}${end}`), 404); }
    problem(await f.post(`${LEGAL}/${reserved}/publish`, legal, { etag: p03Tag(1) }), 404);
    problem(await f.read(`${LEGAL}/${idOf(request)}/consents`), 404);
    await f.assertSafeEvidence();
  }, 30_000);

  it('returns minimal same-key receipts after CAS; canonical object order works, changed body, parent and expected version conflict', async () => {
    const f = fixture();
    problem(await f.post(PAYMENT, { code: 'first' }, { key: null }), 400);
    const key = randomUUID();
    const [a, b] = await f.base.race(() => f.post(PAYMENT, { code: 'first' }, { key }),
      () => f.post(PAYMENT, { code: 'first' }, { key }), 'writers');
    expect([a.status, b.status]).toEqual([201, 200]);
    minimal(a);
    expect([b.data, b.etag]).toEqual([a.data, a.etag]);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.reference_entries')).toBe(1);
    expect(await f.base.count("SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='P03_MANAGEMENT_CHANGED'")).toBe(1);
    expect(await f.base.count("SELECT count(*)::int n FROM foundation.outbox_events WHERE event_type='P03_MANAGEMENT_CHANGED'")).toBe(1);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p03_command_receipts WHERE actor_id=$1 AND key=$2', [f.admin.id, key])).toBe(1);
    problem(await f.post(PAYMENT, { code: 'changed' }, { key }), 409);
    const cancel = referencePath('cancel_reason');
    check(await f.read(cancel), 200);
    problem(await f.post(cancel, { code: 'first' }, { key }), 409);
    expect(records(check(await f.read(cancel), 200).data['items'])).toEqual([]);
    const second = check(await f.post(PAYMENT, { code: 'second' }), 201);
    const path = `${PAYMENT}/${idOf(a)}/versions`;
    problem(await f.post(path, publishedRef), 428);
    problem(await f.post(path, publishedRef, { etag: p03Tag(2) }), 412);
    const publishKey = randomUUID();
    const options = { key: publishKey, etag: a.etag };
    const first = check(await f.post(path, publishedRef, options), 201); minimal(first, true);
    const reversed = Object.fromEntries(Object.entries(publishedRef).reverse());
    const repeat = check(await f.post(path, reversed, options), 200);
    expect([repeat.data, repeat.etag]).toEqual([first.data, first.etag]);
    problem(await f.post(path, publishedRef, { ...options, etag: first.etag }), 409);
    problem(await f.post(`${PAYMENT}/${idOf(second)}/versions`, publishedRef, options), 409);
    problem(await f.post(path, { ...publishedRef, label: 'Other' }, options), 409);
    problem(await f.post(path, publishedRef, { etag: a.etag }), 412);
    const archived = check(await f.post(`${PAYMENT}/${idOf(a)}/archive`, {}, { etag: first.etag }), 200);
    expect(check(await f.post(path, reversed, options), 200).data).toEqual(first.data);
    problem(await f.post(path, reversed, { etag: archived.etag }), 409);
    await f.assertSafeEvidence();
  }, 20_000);

  it('returns a create-key scope conflict only while the original content target remains authorized', async () => {
    const f = fixture(); const a = f.admin;
    const originalCity = await f.geo.activeCity(a, 'receipt-origin');
    const nextCity = await f.geo.publishedDraftCity(a, 'receipt-destination');
    const base = { code: 'receipt-scope', kind: 'FAQ', allowCompanyFallback: false, scope: 'CITY' };
    const original = { ...base, cityId: originalCity.id };
    const changed = { ...base, cityId: nextCity.id };
    const founderKey = randomUUID();
    const founder = check(await f.post(CONTENT, { ...original, code: 'parent-founder' }, { key: founderKey }), 201);
    check(await f.read(`${CONTENT}?scope=CITY&cityId=${nextCity.id}`), 200);
    problem(await f.post(CONTENT, { ...changed, code: 'parent-founder' }, { key: founderKey }), 409);
    expect(check(await f.read(`${CONTENT}/${idOf(founder)}`), 200).data['cityId']).toBe(originalCity.id);

    const m = await f.base.webStaff(); const role = await f.base.systemRole('MANAGER');
    check(await f.addRoleGrants(role, [city('content.read'), city('content.manage'), city('content.publish')]), 200);
    const grant = check(await f.assignCity(m.id, originalCity.id), 201);
    const key = randomUUID(); const options = { key, web: m };
    const created = check(await f.post(CONTENT, original, options), 201); minimal(created);
    const nextPath = `/settings/service-cities/${nextCity.id}`;
    check(await f.geo.write(a, 'post', `${nextPath}/activate`, {
      replaceActiveCityId: originalCity.id, replaceActiveCityVersion: originalCity.version,
    }, { etag: geoTag(nextCity.version) }), 200);
    check(await f.assignCity(m.id, nextCity.id), 201);
    // No real city is simultaneously ACTIVE. The old management assignment is still
    // live after the explicitly reviewed activation handover and both targets are readable.
    check(await f.read(`${CONTENT}/${idOf(created)}`, { web: m }), 200);
    check(await f.read(`${CONTENT}?scope=CITY&cityId=${nextCity.id}`, { web: m }), 200);
    problem(await f.post(CONTENT, changed, options), 409);
    const other = check(await f.post(CONTENT, { ...changed, code: 'receipt-update-target' }, { web: m }), 201);
    const storedPath = `${CONTENT}/${idOf(created)}`;
    const requestedPath = `${CONTENT}/${idOf(other)}`;
    const pubOptions = { web: m, key: randomUUID(), etag: created.etag };
    const published = check(await f.post(`${storedPath}/publish`, contentInput(), pubOptions), 201);
    const archiveOptions = { web: m, key: randomUUID(), etag: published.etag };
    check(await f.post(`${storedPath}/archive`, {}, archiveOptions), 200);
    const publishOther = () => f.post(`${requestedPath}/publish`, contentInput(), pubOptions);
    const archiveOther = () => f.post(`${requestedPath}/archive`, {}, archiveOptions);
    problem(await publishOther(), 409);
    problem(await archiveOther(), 409);
    const revoke = `/settings/service-cities/${originalCity.id}/administrators/${m.id}/assignments/${text(grant.data, 'id')}/revoke`;
    check(await f.geo.write(a, 'post', revoke, {}, { etag: geoTag(await f.geo.staffVersion(m.id)) }), 200);
    problem(await f.read(`${CONTENT}/${idOf(created)}`, { web: m }), 404);
    for (const result of [await f.post(CONTENT, changed, options), await publishOther(), await archiveOther()]) {
      expect([403, 404]).toContain(result.status); problem(result, result.status);
      expect(JSON.stringify(result.body)).not.toContain(idOf(created));
    }
    expect(check(await f.read(requestedPath, { web: m }), 200).data).toMatchObject({ version: 1, currentRevisionId: null, archivedAt: null });
    expect(records(check(await f.read(`${CONTENT}?scope=CITY&cityId=${nextCity.id}`, { web: m }), 200).data['items']).map(({ id }) => id))
      .toEqual([idOf(other)]);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p03_command_receipts WHERE actor_id=$1 AND key=$2', [m.id, key])).toBe(1);
    const fresh = check(await f.post(CONTENT, changed, { ...options, key: randomUUID() }), 201);
    expect(idOf(fresh)).not.toBe(idOf(created));
  }, 30_000);

  it('survives a real successful COMMIT with hidden driver acknowledgement and persists exactly one command', async () => {
    const f = fixture();
    const before = await snapshot(f);
    const key = randomUUID(); const body = { code: 'lost-ack-fixture' };
    const hook = f.loseNextCommitReply();
    try {
      const initial = check(await f.post(PAYMENT, body, { key }), 200);
      expect(hook.fired()).toBe(1);
      minimal(initial);
      const committed = await snapshot(f);
      expect(committed[0]).toBe(Number(before[0]) + 1);
      expect(committed[2]).toBe(Number(before[2]) + 1);
      const replay = check(await f.post(PAYMENT, body, { key }), 200); minimal(replay);
      const receipt = (await f.base.db.query<{ entity_id: string; entity_version: number }>(
        'SELECT entity_id,entity_version FROM foundation.p03_command_receipts WHERE key=$1', [key])).rows[0];
      expect(replay.data).toEqual({ id: receipt?.entity_id, version: receipt?.entity_version });
      expect([initial.data, initial.etag]).toEqual([replay.data, replay.etag]);
      expect(await snapshot(f)).toEqual(committed);
    } finally { hook.restore(); }
    await f.assertSafeEvidence();
  });

  it('maps a reference prelock timeout to 409 with no receipt or domain effect (P05 fence regression)', async () => {
    const f = fixture();
    const entry = check(await f.post(PAYMENT, { code: 'lock-timeout-fixture' }), 201);
    const before = await snapshot(f);
    const holder = await f.base.db.connect();
    try {
      await holder.query('BEGIN');
      // Another session holds the unified GEO/CFG writer fence: the runner's
      // PRE-CHECK prelock must time out (app pool lock_timeout is 1s) and map
      // to the P03 409 transport contract, never a 500.
      await holder.query('SELECT pg_advisory_xact_lock(734305,1)');
      const path = `${PAYMENT}/${idOf(entry)}`;
      const key = randomUUID();
      problem(await f.post(`${path}/versions`, publishedRef, { key, etag: entry.etag }), 409);
      expect(await snapshot(f)).toEqual(before);
      expect(await f.base.count('SELECT count(*)::int n FROM foundation.p03_command_receipts WHERE key=$1', [key])).toBe(0);
      await holder.query('ROLLBACK');
    } finally {
      await holder.query('ROLLBACK').catch(() => undefined);
      holder.release();
    }
    // After the fence clears the same command succeeds: 201, one receipt.
    const key2 = randomUUID();
    const fresh = check(await f.post(`${PAYMENT}/${idOf(entry)}/versions`, publishedRef, { key: key2, etag: entry.etag }), 201);
    minimal(fresh, true);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p03_command_receipts WHERE key=$1', [key2])).toBe(1);
    await f.assertSafeEvidence();
  });

  it.each(evidenceTables)('rolls back every domain and evidence write when %s INSERT actually fails', async (table) => {    const f = fixture();
    const entry = check(await f.post(PAYMENT, { code: 'fault-fixture' }), 201);
    const path = `${PAYMENT}/${idOf(entry)}`;
    const before = await snapshot(f);
    await f.base.db.query(`CREATE FUNCTION foundation.test_p03_drop_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'synthetic-p03-private-marker-не-выводить' USING ERRCODE='57014'; END $$`);
    const hook = f.beforeReceiptSelect(async () => {
      await f.base.db.query(`CREATE TRIGGER test_p03_drop_evidence BEFORE INSERT ON foundation.${table}
        FOR EACH ROW EXECUTE FUNCTION foundation.test_p03_drop_evidence()`);
    });
    const key = randomUUID();
    const command = () => f.post(`${path}/versions`, publishedRef, { key, etag: entry.etag });
    try { problem(await command(), 500); expect(hook.fired()).toBe(1); }
    finally {
      hook.restore();
      await f.base.db.query(`DROP TRIGGER IF EXISTS test_p03_drop_evidence ON foundation.${table}`);
    }
    expect(await snapshot(f)).toEqual(before);
    expect(check(await f.read(path), 200).data).toMatchObject({ version: 1, currentVersionId: null });
    minimal(check(await command(), 201), true);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p03_command_receipts WHERE key=$1', [key])).toBe(1);
    await f.assertSafeEvidence();
  });

  it.each(['receipt-read', 'receipt-insert'] as const)('rechecks fresh expiry after actual %s lock wait, rolling back the entire write', async (step) => {
    const f = fixture();
    const key = randomUUID(); const input = { code: 'expired-fixture' };
    const command = () => f.post(PAYMENT, input, { key });
    if (step === 'receipt-read') { minimal(check(await command(), 201)); }
    const before = await snapshot(f);
    const locker = await f.base.db.connect();
    let pending: ReturnType<typeof command> | undefined;
    try {
      const pid = await f.backend(locker);
      await locker.query('BEGIN');
      const hook = f.beforeReceiptSelect(async () => {
        await locker.query(`LOCK TABLE foundation.p03_command_receipts IN ${step === 'receipt-read' ? 'ACCESS EXCLUSIVE' : 'SHARE'} MODE`);
      });
      try {
        const expires = await f.shortenSession(f.admin, step === 'receipt-read' ? 'idle' : 'absolute');
        pending = command(); void pending.catch(() => undefined);
        expect(await f.waitForLock(pid, 'p03_command_receipts', step === 'receipt-read' ? 'AccessShareLock' : 'RowExclusiveLock')).not.toBe(pid);
        expect(hook.fired()).toBe(1);
        await f.waitForExpiry(expires);
        await locker.query('COMMIT');
        problem(await pending, 401);
        expect(await snapshot(f)).toEqual(before);
      } finally { hook.restore(); }
    } finally { await locker.query('ROLLBACK'); locker.release(); await Promise.allSettled([pending]); }
  }, 15_000);

  it.each(['revoke-first', 'write-first'] as const)('serializes %s under the real RBAC lock and never returns an unauthorized receipt', async (order) => {
    const f = fixture(); const m = await f.base.webStaff(); const role = await f.base.systemRole('MANAGER');
    check(await f.addRoleGrants(role, [global('references.paymentmethod.read'), global('references.paymentmethod.manage')]), 200);
    const detail = check(await f.base.call(f.admin, 'get', `/roles/${role}`), 200);
    const remaining = records(detail.data['permissions']).filter(({ code }) => code !== 'references.paymentmethod.manage');
    const revoke = () => f.http('PUT', `/roles/${role}/permissions`, (req) => req.end(JSON.stringify({ permissions: remaining })), { etag: detail.etag });
    const key = randomUUID();
    const write = () => f.post(PAYMENT, { code: 'revoke-fixture' }, { web: m, key });
    const first = order === 'revoke-first' ? revoke : write;
    const second = order === 'revoke-first' ? write : revoke;
    const locker = await f.base.db.connect();
    let a: ReturnType<typeof first> | undefined;
    let b: ReturnType<typeof second> | undefined;
    try {
      const blocker = await f.backend(locker);
      await locker.query('BEGIN');
      await locker.query('LOCK TABLE foundation.audit_logs IN EXCLUSIVE MODE');
      a = first(); void a.catch(() => undefined);
      const holder = await f.waitForLock(blocker, 'audit_logs', 'RowExclusiveLock');
      b = second(); void b.catch(() => undefined);
      expect(await f.waitForPolicyWait(holder)).not.toBe(holder);
      await locker.query('COMMIT');
      if (order === 'revoke-first') { check(await a, 200); problem(await b, 403); }
      else { minimal(check(await a, 201)); check(await b, 200); }
    } finally { await locker.query('ROLLBACK'); locker.release(); await Promise.allSettled([a, b]); }
    problem(await write(), 403);
    expect(await f.base.count('SELECT count(*)::int n FROM foundation.p03_command_receipts WHERE key=$1', [key])).toBe(order === 'write-first' ? 1 : 0);
  }, 20_000);
});
