/**
 * P05-03 channel-offer fixture tests (task-8). Defensive only: they prove the
 * test-only `RequestOffers` port refuses every non-allowable state with the
 * reviewed closed codes, that the A/B/C-tech/C-live/D stages are each
 * authoritative, that the writer/reader fence serializes the read, and that the
 * request-intake seed really resolves through the production read ports on an
 * isolated S3 database.
 *
 * Lab only (`FIXLEVELUP_SYNTHETIC_ORCHESTRATOR=1` and the disposable-DB opt-in);
 * every database is created by the fixture itself and dropped by `close()`.
 * No working/dev database is contacted, and nothing here is a P05 feature test
 * for HTTP or for a real provider.
 */
import 'reflect-metadata';
import { createHash, randomUUID } from 'node:crypto';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { P05ChannelSelection } from '@fixlevelup/p03-contracts/p05';
import { checkOfferClock, confirmOffer } from '../src/requests/intake/basis.js';
import { RequestFailure } from '../src/requests/intake/errors.js';
import { classifyPolicyPair, policyPairKey } from '../src/requests/workflow/registry.js';
import { readSingleCityContext } from '../src/settings/geography/city-context.js';
import { resolveReferenceForUse } from '../src/settings/configuration/references.js';
import { RequestOfferFixture } from './p05-offer-fixture.js';
import type { RequestOfferFixtureOptions } from './p05-offer-fixture.js';
import {
  REQUEST_POLICY_REVISION, REQUEST_WORKFLOW_VERSION, seedPolicyPackage, seedRequestFixtures,
} from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { RbacFixture } from './rbac-fixture.js';

const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1'
  && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1' ? describe : describe.skip;

/** The closed refusal code of a `RequestFailure`, or a hard failure. */
async function refusal(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof RequestFailure) { return error.code; }
    throw error;
  }
  throw new Error('Expected the fixture port to refuse');
}

integration('P05 channel-offer fixture (RequestOffers port on a real PostgreSQL primary)', () => {
  let offer: RequestOfferFixture | undefined;

  async function current(options: RequestOfferFixtureOptions = {}): Promise<RequestOfferFixture> {
    const fixture = await RequestOfferFixture.create(options);
    offer = fixture;
    return fixture;
  }

  beforeEach(async () => { await current(); }, 60_000);
  afterEach(async () => {
    const fixture = offer;
    offer = undefined;
    if (fixture !== undefined) { await fixture.close(); }
  }, 60_000);

  function fixture(): RequestOfferFixture {
    if (offer === undefined) { throw new Error('Missing offer fixture'); }
    return offer;
  }

  it('returns the exact allow basis tuple and writes nothing', async () => {
    const f = fixture();
    const before = await f.snapshot();
    const selection = f.selection();
    const basis = await f.shared((client) => confirmOffer(client, f, selection));
    expect(basis.provider).toBe(selection.provider);
    expect(basis.catalogVersionId).toBe(selection.catalogVersionId);
    expect(basis.optionVersionId).toBe(selection.optionVersionId);
    expect(basis.purpose).toBe('REQUEST_CONFIRMATION');
    expect(basis.basisId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(basis.validUntil).toBeInstanceOf(Date);
    expect(Object.keys(basis).sort()).toEqual(['basisId', 'catalogVersionId', 'optionVersionId', 'provider', 'purpose', 'validUntil']);
    expect(Object.isFrozen(basis)).toBe(true);
    expect(basis.validUntil.getTime()).toBeGreaterThan((await f.clock()).getTime());
    // A pure read: the port never provisions, repairs or substitutes anything.
    expect(await f.snapshot()).toEqual(before);
  }, 60_000);

  it('refuses a stale catalog, foreign option, provider or purpose with CHANNEL_OPTIONS_CHANGED', async () => {
    const f = fixture();
    const stale = f.selection();
    const published = await f.publishCatalogVersion();
    expect(await refusal(() => f.validateDetached(stale))).toBe('CHANNEL_OPTIONS_CHANGED');
    expect(await refusal(() => f.validateDetached(f.selection({ optionVersionId: randomUUID() }))))
      .toBe('CHANNEL_OPTIONS_CHANGED');
    expect(await refusal(() => f.validateDetached(f.selection({ provider: 'VK' }))))
      .toBe('CHANNEL_OPTIONS_CHANGED');
    // The purpose is a closed literal in the wire DTO; a forged one must not match.
    const forgedPurpose = { ...f.selection(), purpose: 'REQUEST_SERVICE_CALL' } as unknown as P05ChannelSelection;
    expect(await refusal(() => f.validateDetached(forgedPurpose))).toBe('CHANNEL_OPTIONS_CHANGED');
    // The published catalog is current and valid for the new option version.
    const fresh = f.selection({
      catalogVersionId: published.catalogVersionId, optionVersionId: published.optionVersionId,
    });
    await expect(f.validateDetached(fresh)).resolves.toMatchObject({
      catalogVersionId: published.catalogVersionId, optionVersionId: published.optionVersionId,
    });
  }, 60_000);

  it('refuses a current A-off option with CHANNEL_OFFER_DISABLED (not a readiness failure)', async () => {
    const f = fixture();
    await f.setOfferEnabled(false);
    expect(await refusal(() => f.validateDetached(f.selection()))).toBe('CHANNEL_OFFER_DISABLED');
    expect(await refusal(() => f.shared((client) => confirmOffer(client, f, f.selection()))))
      .toBe('CHANNEL_OFFER_DISABLED');
    // A newly published A-off catalog keeps the same classification.
    const off = await f.publishCatalogVersion({ offerEnabled: false });
    const selection = f.selection({ catalogVersionId: off.catalogVersionId, optionVersionId: off.optionVersionId });
    expect(await refusal(() => f.validateDetached(selection))).toBe('CHANNEL_OFFER_DISABLED');
  }, 60_000);

  it('refuses a suspended connection (B) with CHANNEL_NOT_READY and recovers when it is resumed', async () => {
    const f = fixture();
    await f.suspendConnection();
    expect(await refusal(() => f.validateDetached(f.selection()))).toBe('CHANNEL_NOT_READY');
    await f.resumeConnection();
    await expect(f.validateDetached(f.selection())).resolves.toMatchObject({ provider: 'TG' });
  }, 60_000);

  it('refuses revoked and expired credentials (B) with CHANNEL_NOT_READY', async () => {
    const revoked = await RequestOfferFixture.create();
    try {
      await revoked.revokeCredentials();
      expect(await refusal(() => revoked.validateDetached(revoked.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await revoked.close(); }
    const expired = await RequestOfferFixture.create();
    try {
      await expired.expireCredentials();
      expect(await refusal(() => expired.validateDetached(expired.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await expired.close(); }
  }, 120_000);

  it('refuses failed, expired and revoked readiness (C-tech) with CHANNEL_NOT_READY', async () => {
    const failed = await RequestOfferFixture.create();
    try {
      await failed.failReadiness('TLS');
      expect(await refusal(() => failed.validateDetached(failed.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await failed.close(); }
    const expired = await RequestOfferFixture.create();
    try {
      await expired.expireReadiness('WEBHOOK');
      expect(await refusal(() => expired.validateDetached(expired.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await expired.close(); }
    const revoked = await RequestOfferFixture.create();
    try {
      await revoked.revokeReadiness('CONFIG');
      expect(await refusal(() => revoked.validateDetached(revoked.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await revoked.close(); }
  }, 180_000);

  it('refuses revoked and expired live acceptance (C-live) with CHANNEL_NOT_READY', async () => {
    const revoked = await RequestOfferFixture.create();
    try {
      await revoked.revokeLiveAcceptance();
      expect(await refusal(() => revoked.validateDetached(revoked.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await revoked.close(); }
    const expired = await RequestOfferFixture.create();
    try {
      await expired.expireLiveAcceptance();
      expect(await refusal(() => expired.validateDetached(expired.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await expired.close(); }
  }, 120_000);

  it('refuses revoked and expired capability evidence (D) with CHANNEL_NOT_READY', async () => {
    const revoked = await RequestOfferFixture.create();
    try {
      await revoked.revokeCapability('BINDING');
      expect(await refusal(() => revoked.validateDetached(revoked.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await revoked.close(); }
    const expired = await RequestOfferFixture.create();
    try {
      await expired.expireCapability('SERVICE');
      expect(await refusal(() => expired.validateDetached(expired.selection()))).toBe('CHANNEL_NOT_READY');
    } finally { await expired.close(); }
  }, 120_000);

  it('treats database-clock expiry as a live refusal and rejects a stale basis clock', async () => {
    const f = fixture();
    const basis = await f.validateDetached(f.selection());
    await f.expireAll();
    expect(await refusal(() => f.validateDetached(f.selection()))).toBe('CHANNEL_NOT_READY');
    // `checkOfferClock` re-reads the DB clock and refuses a basis whose own
    // deadline already passed (a real clock comparison, not a cached boolean).
    const past = Object.freeze({ ...basis, validUntil: new Date((await f.clock()).getTime() - 1_000) });
    expect(await refusal(() => f.shared((client) => checkOfferClock(client, past)))).toBe('CHANNEL_NOT_READY');
  }, 60_000);

  it('refuses a missing port instead of inventing an allow basis', async () => {
    const f = fixture();
    expect(await refusal(() => f.shared((client) => confirmOffer(client, undefined, f.selection()))))
      .toBe('CHANNEL_NOT_READY');
  }, 60_000);

  it('serializes the authoritative read against the source writer fence (X vs S)', async () => {
    const f = fixture();
    const stale = f.selection();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const writer = f.exclusive(async (client) => {
      await f.publishCatalogVersion({}, client);
      await gate;
    });
    const pending = f.validateDetached(stale);
    let settled = false;
    void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      // The read must be observably WAITING on the fence, not resolved early.
      await f.waitForWaiter();
      expect(await f.blockedWaiters()).toBeGreaterThan(0);
      await new Promise((resolve) => { setTimeout(resolve, 100); });
      expect(settled).toBe(false);
      release();
      await writer;
      expect(await refusal(() => pending)).toBe('CHANNEL_OPTIONS_CHANGED');
    } finally {
      release();
      await writer.catch(() => undefined);
      await pending.catch(() => undefined);
    }
  }, 60_000);

  it('keeps the previous catalog authoritative when the writer rolls back', async () => {
    const f = fixture();
    const selection = f.selection();
    const writer = f.exclusive(async (client) => {
      await f.publishCatalogVersion({}, client);
      throw new Error('synthetic writer rollback');
    });
    await expect(writer).rejects.toThrow('synthetic writer rollback');
    await expect(f.validateDetached(selection)).resolves.toMatchObject({
      catalogVersionId: selection.catalogVersionId, optionVersionId: selection.optionVersionId,
    });
  }, 60_000);

  it('keeps distinct providers/schemas independent (TG and VK)', async () => {
    const vk = await RequestOfferFixture.create({ provider: 'VK' });
    try {
      const tg = fixture();
      expect(vk.schema).not.toBe(tg.schema);
      const tgBasis = await tg.validateDetached(tg.selection());
      const vkBasis = await vk.validateDetached(vk.selection());
      expect(tgBasis.provider).toBe('TG');
      expect(vkBasis.provider).toBe('VK');
      // A VK selection is not a TG membership and vice versa.
      expect(await refusal(() => tg.validateDetached(vk.selection()))).toBe('CHANNEL_OPTIONS_CHANGED');
      expect(await refusal(() => vk.validateDetached(tg.selection()))).toBe('CHANNEL_OPTIONS_CHANGED');
    } finally { await vk.close(); }
  }, 120_000);
});

integration('P05 request-intake seed on an isolated S3 database', () => {
  let fixture: RbacFixture | undefined;
  let seeded: RequestFixtures | undefined;
  let historical: { readonly id: string; readonly workflowVersion: string; readonly policyRevision: string;
    readonly metadataSha256: string } | undefined;

  beforeAll(async () => {
    const created = new RbacFixture({ p04: true });
    fixture = created;
    await created.start();
    seeded = await seedRequestFixtures(created, { reviewerId: created.admin.id });
    historical = await seedPolicyPackage(created);
  }, 300_000);

  afterAll(async () => {
    const created = fixture;
    fixture = undefined;
    if (created !== undefined) { await created.close(); }
  }, 120_000);

  function seededFixtures(): { readonly fixture: RbacFixture; readonly seeded: RequestFixtures } {
    if (fixture === undefined || seeded === undefined) { throw new Error('Missing seeded request fixture'); }
    return { fixture, seeded };
  }

  it('resolves the seeded city through the production single-city context read', async () => {
    const { fixture: base, seeded: facts } = seededFixtures();
    const city = await readSingleCityContext(base.db);
    expect(city).toEqual({ cityId: facts.cityId, cityVersionId: facts.cityVersionId, timezone: facts.timezone });
  }, 60_000);

  it('resolves the seeded COMPANY/CITY references with exact version provenance', async () => {
    const { fixture: base, seeded: facts } = seededFixtures();
    const source = await resolveReferenceForUse(base.db, { entryId: facts.formSourceEntryId, type: 'REQUEST_SOURCE' });
    expect(source).toMatchObject({ entryId: facts.formSourceEntryId, type: 'REQUEST_SOURCE', scope: 'COMPANY' });
    const cancel = await resolveReferenceForUse(base.db, { entryId: facts.cancelReasonEntryId, type: 'CANCEL_REASON' });
    expect(cancel).toMatchObject({ entryId: facts.cancelReasonEntryId, scope: 'COMPANY' });
    const interval = await resolveReferenceForUse(base.db, {
      entryId: facts.callbackIntervalEntryId, type: 'CALLBACK_INTERVAL', intakeCityVersionId: facts.cityVersionId,
    });
    expect(interval).toMatchObject({
      scope: 'CITY', cityId: facts.cityId, timezone: facts.timezone,
      timezoneCityVersionId: facts.cityVersionId, interval: { startMinute: 540, endMinute: 600 },
    });
  }, 60_000);

  it('publishes the seeded catalog category/fault and coverage mapping', async () => {
    const { fixture: base, seeded: facts } = seededFixtures();
    const catalog = await base.db.query<{ id: string; kind: string; current_version_id: string | null }>(
      'SELECT id,kind,current_version_id FROM foundation.catalog_directory_entries WHERE id=ANY($1::uuid[]) ORDER BY kind',
      [[facts.categoryId, facts.faultId]]);
    expect(catalog.rows.map((row) => row.kind)).toEqual(['CATEGORY', 'FAULT']);
    expect(catalog.rows.every((row) => typeof row.current_version_id === 'string')).toBe(true);
    const fault = await base.db.query<{ category_id: string | null }>(
      'SELECT category_id FROM foundation.catalog_directory_entries WHERE id=$1', [facts.faultId]);
    expect(fault.rows[0]?.category_id).toBe(facts.categoryId);
    const coverage = await base.db.query<{ n: number }>(`SELECT count(*)::int AS n
      FROM foundation.service_area_district_coverage WHERE city_id=$1 AND area_version_id=$2 AND district_id=$3`,
    [facts.cityId, facts.areaVersionId, facts.districtId]);
    expect(coverage.rows[0]?.n).toBe(1);
    const area = await base.db.query<{ current_version_id: string | null }>(
      'SELECT current_version_id FROM foundation.service_areas WHERE id=$1', [facts.areaId]);
    expect(area.rows[0]?.current_version_id).toBe(facts.areaVersionId);
  }, 60_000);

  it('publishes the current REQUEST_PROCESSING consent form and the POLICY document', async () => {
    const { fixture: base, seeded: facts } = seededFixtures();
    const documents = await base.db.query<{ id: string; kind: string; current_version_id: string | null; purpose: string }>(
      `SELECT id,kind,current_version_id,purpose FROM foundation.legal_documents
       WHERE id=ANY($1::uuid[]) ORDER BY kind`, [[facts.consentDocumentId, facts.policyDocumentId]]);
    expect(documents.rows.map((row) => ({ kind: row.kind, current: row.current_version_id, purpose: row.purpose })))
      .toEqual([
        { kind: 'CONSENT_FORM', current: facts.consentDocumentVersionId, purpose: 'REQUEST_PROCESSING' },
        { kind: 'POLICY', current: facts.policyDocumentVersionId, purpose: 'REQUEST_PROCESSING' },
      ]);
    const versions = await base.db.query<{ checksum_ok: boolean }>(`SELECT
      checksum = encode(sha256(convert_to(body,'UTF8')),'hex') AS checksum_ok
      FROM foundation.legal_document_versions WHERE id=$1`, [facts.consentDocumentVersionId]);
    expect(versions.rows[0]?.checksum_ok).toBe(true);
  }, 60_000);

  it('stores the policy digest over the exact PostgreSQL jsonb text and classifies the pair', async () => {
    const { fixture: base, seeded: facts } = seededFixtures();
    const policy = await base.db.query<{ workflow_version: string; policy_revision: string; text: string }>(
      `SELECT workflow_version,policy_revision,metadata::text AS text FROM foundation.request_policy_packages WHERE id=$1`,
      [facts.policyId]);
    const row = policy.rows[0];
    expect(row).toMatchObject({
      workflow_version: REQUEST_WORKFLOW_VERSION, policy_revision: REQUEST_POLICY_REVISION,
    });
    expect(facts.policyMetadataSha256).toBe(createHash('sha256').update(row?.text ?? '', 'utf8').digest('hex'));
    const supported = new Set([policyPairKey(REQUEST_WORKFLOW_VERSION, REQUEST_POLICY_REVISION)]);
    expect(classifyPolicyPair({ workflowVersion: REQUEST_WORKFLOW_VERSION, policyRevision: REQUEST_POLICY_REVISION },
      supported)).toBe('SUPPORTED');
    // The seeded historical package is a genuinely separate immutable row.
    if (historical === undefined) { throw new Error('Missing historical policy package'); }
    expect(classifyPolicyPair({
      workflowVersion: historical.workflowVersion, policyRevision: historical.policyRevision,
    }, supported)).toBe('UNSUPPORTED_POLICY');
    const history = await base.db.query<{ text: string }>(
      'SELECT metadata::text AS text FROM foundation.request_policy_packages WHERE id=$1', [historical.id]);
    expect(historical.metadataSha256).toBe(createHash('sha256').update(history.rows[0]?.text ?? '', 'utf8').digest('hex'));
  }, 60_000);

  it('fails closed when the port gets a client from another database (no cross-DB fallback)', async () => {
    const { fixture: base, seeded: facts } = seededFixtures();
    const offer = await RequestOfferFixture.create({ provider: 'MAX' });
    try {
      const selection = offer.selection();
      const client = await base.db.connect();
      try {
        // The reviewed contract is same-primary-transaction: a client connected
        // to another database must never be authorized from a second connection.
        expect(await refusal(() => offer.lock(client))).toBe('CHANNEL_NOT_READY');
        expect(await refusal(() => confirmOffer(client, offer, selection))).toBe('CHANNEL_NOT_READY');
        // The fixture's own connection is the only authoritative reader.
        await expect(offer.validateDetached(selection)).resolves.toMatchObject({
          provider: 'MAX',
          catalogVersionId: selection.catalogVersionId,
          optionVersionId: selection.optionVersionId,
          purpose: 'REQUEST_CONFIRMATION',
        });
      } finally { client.release(); }
      // The seeded request basis itself is untouched by those refusals.
      const city = await readSingleCityContext(base.db);
      expect(city.cityId).toBe(facts.cityId);
    } finally { await offer.close(); }
  }, 120_000);
});

integration('P05 attached offer fixture (same database as the request aggregate)', () => {
  let fixture: RbacFixture | undefined;
  let seeded: RequestFixtures | undefined;
  let offer: RequestOfferFixture | undefined;

  beforeAll(async () => {
    const created = new RbacFixture({ p04: true });
    fixture = created;
    await created.start();
    seeded = await seedRequestFixtures(created, { reviewerId: created.admin.id });
    // The T integration path: the catalog lives in a private schema of the SAME
    // database, so the port is read on the same PoolClient and transaction as
    // the request write.
    offer = await RequestOfferFixture.attach(created, { provider: 'TG' });
  }, 300_000);

  afterAll(async () => {
    const attached = offer;
    const created = fixture;
    offer = undefined;
    fixture = undefined;
    try {
      if (attached !== undefined) { await attached.close(); }
    } finally {
      if (created !== undefined) { await created.close(); }
    }
  }, 120_000);

  function attached(): { readonly fixture: RbacFixture; readonly offer: RequestOfferFixture; readonly seeded: RequestFixtures } {
    if (fixture === undefined || offer === undefined || seeded === undefined) {
      throw new Error('Missing attached offer fixture');
    }
    return { fixture, offer, seeded };
  }

  it('attaches inside the fixture database and never creates another one', async () => {
    const { fixture: base, offer: attachedOffer } = attached();
    expect(attachedOffer.database).toBe(base.database);
    const schema = await base.db.query<{ present: boolean }>(
      'SELECT to_regnamespace($1) IS NOT NULL AS present', [attachedOffer.schema]);
    expect(schema.rows[0]?.present).toBe(true);
    // The runtime role can read the fixture schema but not write it.
    const grants = await base.db.query<{ readable: boolean; writable: boolean }>(`SELECT
      has_schema_privilege('fixlevelup_runtime',$1,'USAGE') AS readable,
      has_schema_privilege('fixlevelup_runtime',$1,'CREATE') AS writable`, [attachedOffer.schema]);
    expect(grants.rows[0]).toEqual({ readable: true, writable: false });
    // The private schema is outside `foundation`, so the reviewed physical
    // profile catalog cannot see it as a request-surface relation.
    const foundation = await base.db.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='foundation' AND c.relname IN ('pointer','catalog_versions','catalog_entries',
         'options','connections','credentials','readiness_checks','live_acceptances','capability_evidence')`);
    expect(foundation.rows[0]?.n).toBe(0);
  }, 60_000);

  it('reads the authoritative basis on the caller client and same transaction', async () => {
    const { fixture: base, offer: attachedOffer } = attached();
    const selection = attachedOffer.selection();
    const client = await base.db.connect();
    try {
      await client.query('BEGIN');
      // Inside the caller's own transaction: the port takes the SHARED fence and
      // reads the catalog there, so an uncommitted writer move is visible and a
      // stale selection is refused without leaving the transaction.
      await expect(confirmOffer(client, attachedOffer, selection)).resolves.toMatchObject({
        catalogVersionId: selection.catalogVersionId, optionVersionId: selection.optionVersionId,
      });
      const published = await attachedOffer.publishCatalogVersion({}, client);
      expect(await refusal(() => confirmOffer(client, attachedOffer, selection))).toBe('CHANNEL_OPTIONS_CHANGED');
      const fresh = attachedOffer.selection({
        catalogVersionId: published.catalogVersionId, optionVersionId: published.optionVersionId,
      });
      await expect(confirmOffer(client, attachedOffer, fresh)).resolves.toMatchObject({
        catalogVersionId: published.catalogVersionId,
      });
      await client.query('ROLLBACK');
    } finally { client.release(); }
    // The rollback restored the previous catalog: the original selection is valid.
    await expect(attachedOffer.validateDetached(selection)).resolves.toMatchObject({
      catalogVersionId: selection.catalogVersionId,
    });
  }, 60_000);

  it('takes the shared reader fence reentrantly (lock + validateNewOffer on one client)', async () => {
    const { fixture: base, offer: attachedOffer } = attached();
    const selection = attachedOffer.selection();
    const client = await base.db.connect();
    try {
      await client.query('BEGIN');
      // Both the composition's early `lock()` and the port's own read take the
      // SHARED side of (705025,1) on the same backend: reentrant, no conversion,
      // no self-deadlock, and the exclusive side stays free for a real writer.
      await attachedOffer.lock(client);
      await attachedOffer.lock(client);
      const basis = await attachedOffer.validateNewOffer(client, selection);
      expect(basis).toMatchObject({
        catalogVersionId: selection.catalogVersionId, optionVersionId: selection.optionVersionId,
      });
      const held = await client.query<{ shared: boolean; exclusive: boolean }>(`SELECT
        EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND classid=705025::int::oid AND objid=1::oid
          AND objsubid=2 AND mode='ShareLock' AND granted AND pid=pg_backend_pid()) AS shared,
        EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND classid=705025::int::oid AND objid=1::oid
          AND objsubid=2 AND mode='ExclusiveLock' AND pid=pg_backend_pid()) AS exclusive`);
      expect(held.rows[0]).toEqual({ shared: true, exclusive: false });
      await client.query('COMMIT');
    } finally { client.release(); }
  }, 60_000);

  it('leaves the schema and the parent database intact when the attached fixture closes', async () => {
    const { fixture: base, offer: attachedOffer } = attached();
    const schema = attachedOffer.schema;
    await attachedOffer.close();
    // No DROP SCHEMA while the parent database is active: the parent still sees
    // its own schema, and its own teardown remains the only owner of the DB.
    const present = await base.db.query<{ present: boolean }>('SELECT to_regnamespace($1) IS NOT NULL AS present', [schema]);
    expect(present.rows[0]?.present).toBe(true);
    // A closed fixture refuses further reads instead of returning a stale basis.
    await expect(attachedOffer.validateDetached(attachedOffer.selection())).rejects.toThrow('Offer fixture is closed');
    // Re-attaching on the same database is possible (the parent is still alive);
    // a second provider/schema lives side by side with the first.
    offer = await RequestOfferFixture.attach(base, { provider: 'VK', schema: 'p05_offer_fixture_vk' });
    await expect(offer.validateDetached(offer.selection())).resolves.toMatchObject({ provider: 'VK' });
  }, 60_000);
});
