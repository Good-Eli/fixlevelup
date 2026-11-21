/**
 * Typed reference catalogue against a real isolated PostgreSQL instance.
 *
 * Proves the parts unit tests cannot: scope/type CHECKs, the same-city composite FK,
 * the CAS on the entry token, the immutable revision history, archive behaviour,
 * and the consumption-time timezone rule (the interval's local window follows the
 * trusted intake city version, never the stored creation provenance, and the
 * resolution names the exact city-version row that supplied the zone).
 */
import { afterAll, beforeAll, expect, it } from 'vitest';
import {
  archiveReferenceEntry, createReferenceEntry, listReferenceEntries, publishReferenceVersion,
  readReferenceSnapshot, resolveReferenceForUse,
} from '../src/settings/configuration/index.js';
import { ConfigurationError } from '../src/settings/configuration/configuration-errors.js';
import {
  addSyntheticCityVersion, configurationIntegration, createConfigurationFixture, createSyntheticCity,
  installFailingAuditTrigger, removeFailingAuditTrigger,
} from './configuration-fixture.js';
import type { ConfigurationFixture, SyntheticCity } from './configuration-fixture.js';

const codeOf = async (promise: Promise<unknown>): Promise<string> => {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ConfigurationError) {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected a typed refusal');
};

const from = '2026-01-01T00:00:00Z';
const until = '2027-01-01T00:00:00Z';

configurationIntegration('reference catalogue against isolated PostgreSQL', () => {
  let fixture: ConfigurationFixture;
  let city: SyntheticCity;
  let otherCity: SyntheticCity;

  beforeAll(async () => {
    fixture = await createConfigurationFixture();
    city = await createSyntheticCity(fixture, { timezone: 'Europe/Moscow' });
    otherCity = await createSyntheticCity(fixture, { timezone: 'Asia/Tokyo' });
  }, 60_000);

  afterAll(async () => { await fixture.close(); });

  const createCityInterval = (target: SyntheticCity, code: string) =>
    fixture.inTransaction((client) => createReferenceEntry(client, fixture.reviewer, {
      type: 'CALLBACK_INTERVAL', cityId: target.id, code,
    }));

  const publishInterval = (
    entryId: string, expectedVersion: number, provenanceCityVersionId: string,
    overrides: Record<string, unknown> = {},
  ) => fixture.inTransaction((client) => publishReferenceVersion(client, fixture.reviewer, {
    type: 'CALLBACK_INTERVAL', entryId, expectedVersion, label: 'Callback 09:00-18:00',
    sourceRef: 'review://synthetic/callback/1', validFrom: from, validUntil: until,
    cityVersionId: provenanceCityVersionId, interval: { startMinute: 540, endMinute: 1080 },
    ...overrides,
  }));

  it('creates a city interval, publishes an immutable version and moves the pointer', async () => {
    const entry = await createCityInterval(city, 'day-window');
    expect(entry.version).toBe(1);

    const receipt = await publishInterval(entry.id, 1, city.versionId);
    expect(receipt).toMatchObject({ entryId: entry.id, version: 1, entryVersion: 2 });

    const snapshot = await fixture.inTransaction((client) => readReferenceSnapshot(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id,
    }));
    expect(snapshot.entry).toMatchObject({
      id: entry.id, type: 'CALLBACK_INTERVAL', scope: 'CITY', cityId: city.id, version: 2,
      currentVersionId: receipt.id, archivedAt: null,
    });
    expect(snapshot.version).toMatchObject({
      label: 'Callback 09:00-18:00', sourceRef: 'review://synthetic/callback/1',
      provenanceCityVersionId: city.versionId, interval: { startMinute: 540, endMinute: 1080 },
    });
    // The projection carries no staff identity.
    expect(JSON.stringify(snapshot)).not.toContain(fixture.reviewer);

    const listed = await fixture.inTransaction((client) => listReferenceEntries(client, {
      type: 'CALLBACK_INTERVAL', cityId: city.id,
    }));
    expect(listed.items.map((item) => item.code)).toContain('day-window');

    // Audit + outbox rows were written in the same transaction.
    const audit = await fixture.migrator.query(
      `SELECT 1 FROM foundation.audit_logs WHERE operation IN ('reference.entry.create','reference.version.publish')`);
    expect(audit.rows.length).toBeGreaterThanOrEqual(2);
    const outbox = await fixture.migrator.query(
      `SELECT payload FROM foundation.outbox_events WHERE event_type='reference.version.publish' ORDER BY created_at DESC LIMIT 1`);
    // The payload carries identifiers only, never the reviewed label or source text.
    expect(JSON.stringify(outbox.rows[0])).not.toContain('Callback 09:00-18:00');
  }, 60_000);

  it('refuses a stale entry token, a wrong type and a foreign-city provenance version', async () => {
    const entry = await createCityInterval(city, 'stale-window');
    await publishInterval(entry.id, 1, city.versionId);
    // The token advanced to 2: a publisher that still holds 1 is stale.
    expect(await codeOf(publishInterval(entry.id, 1, city.versionId))).toBe('STALE_VERSION');
    // A version can never change the type of its entry.
    expect(await codeOf(fixture.inTransaction((client) => publishReferenceVersion(client, fixture.reviewer, {
      type: 'PAYMENT_METHOD', entryId: entry.id, expectedVersion: 2, label: 'Card',
      sourceRef: 'review://synthetic/pay/1', validFrom: from, cityVersionId: null, interval: null,
    })))).toBe('CONFLICT');
    // Another city's version is not creation provenance for this entry.
    expect(await codeOf(publishInterval(entry.id, 2, otherCity.versionId))).toBe('NOT_FOUND');
    // A callback interval without a window is refused before SQL.
    expect(await codeOf(fixture.inTransaction((client) => publishReferenceVersion(client, fixture.reviewer, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, expectedVersion: 2, label: 'No window',
      sourceRef: 'review://synthetic/callback/2', validFrom: from, cityVersionId: city.versionId, interval: null,
    })))).toBe('INVALID_INPUT');
    // The interval bounds are re-checked at the port boundary.
    expect(await codeOf(fixture.inTransaction((client) => publishReferenceVersion(client, fixture.reviewer, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, expectedVersion: 2, label: 'Bad window',
      sourceRef: 'review://synthetic/callback/3', validFrom: from, cityVersionId: city.versionId,
      interval: { startMinute: 600, endMinute: 600 },
    })))).toBe('INVALID_INPUT');
  }, 60_000);

  it('keeps the historical snapshot after archive and refuses new use', async () => {
    const entry = await createCityInterval(city, 'archive-window');
    const published = await publishInterval(entry.id, 1, city.versionId);
    const archived = await fixture.inTransaction((client) => archiveReferenceEntry(client, fixture.reviewer, {
      entryId: entry.id, expectedVersion: 2,
    }));
    expect(archived.version).toBe(3);

    // The old revision is unchanged and still readable with its reviewed label.
    const historical = await fixture.inTransaction((client) => readReferenceSnapshot(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, version: published.version,
    }));
    expect(historical.version.id).toBe(published.id);
    expect(historical.version.label).toBe('Callback 09:00-18:00');
    // Archiving keeps the historical revision and its creation provenance as reviewed.
    expect(historical.version.provenanceCityVersionId).toBe(city.versionId);
    expect(historical.entry.archivedAt).not.toBeNull();

    // No new version and no new use for an archived entry.
    expect(await codeOf(publishInterval(entry.id, 3, city.versionId))).toBe('ARCHIVED');
    expect(await codeOf(fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, intakeCityVersionId: city.versionId, at: from,
    })))).toBe('ARCHIVED');
    // Archive is one-way: re-archiving an archived entry is refused for both the
    // current and a stale token, so no caller can rewrite the archived timestamp.
    for (const expectedVersion of [2, 3]) {
      expect(await codeOf(fixture.inTransaction((client) => archiveReferenceEntry(client, fixture.reviewer, {
        entryId: entry.id, expectedVersion,
      })))).toBe('ARCHIVED');
    }
    // Archived entries are excluded from the default list.
    const listed = await fixture.inTransaction((client) => listReferenceEntries(client, {
      type: 'CALLBACK_INTERVAL', cityId: city.id,
    }));
    expect(listed.items.map((item) => item.id)).not.toContain(entry.id);
    const withArchived = await fixture.inTransaction((client) => listReferenceEntries(client, {
      type: 'CALLBACK_INTERVAL', cityId: city.id, includeArchived: true,
    }));
    expect(withArchived.items.map((item) => item.id)).toContain(entry.id);
  }, 60_000);

  it('resolves the local timezone from the trusted intake city version, not creation provenance', async () => {
    const entry = await createCityInterval(city, 'timezone-window');
    // Version 1 reviewed with Europe/Moscow as provenance.
    const published = await publishInterval(entry.id, 1, city.versionId);

    // The same city later publishes version 2 with a different zone (a reviewed change).
    const secondVersionId = await addSyntheticCityVersion(fixture, city, { timezone: 'Asia/Tokyo', version: 2 });

    // A request that consumed version 1 keeps the Moscow window and names exactly the
    // city-version row that supplied it, which is not the reference revision id.
    const first = await fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, intakeCityVersionId: city.versionId, at: from,
    }));
    expect(first.timezone).toBe('Europe/Moscow');
    expect(first.timezoneCityVersionId).toBe(city.versionId);
    // Two distinct identities: the immutable reference revision and its timezone source.
    expect(first.versionId).toBe(published.id);
    expect(first.version).toBe(1);
    expect(first.timezoneCityVersionId).not.toBe(first.versionId);
    expect(first).toMatchObject({ interval: { startMinute: 540, endMinute: 1080 }, scope: 'CITY', cityId: city.id });
    // The named source is a real row of the entry's city, and its stored zone is the
    // one returned: the id is the queried row id, not an echo of the request field.
    const firstSource = await fixture.migrator.query<{ id: string; timezone: string }>(
      'SELECT id,timezone FROM foundation.service_city_versions WHERE id=$1', [first.timezoneCityVersionId]);
    expect(firstSource.rows).toEqual([{ id: city.versionId, timezone: 'Europe/Moscow' }]);

    // A later request consuming version 2 resolves Tokyo, and the source id follows the
    // consuming version while the reference revision id stays the same.
    const second = await fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, intakeCityVersionId: secondVersionId, at: from,
    }));
    expect(second.timezone).toBe('Asia/Tokyo');
    expect(second.timezoneCityVersionId).toBe(secondVersionId);
    expect(second.versionId).toBe(published.id);
    // The second resolution also keeps the two identities distinct: the reference
    // revision it resolves is never the city-version row that supplied the zone.
    expect(second.timezoneCityVersionId).not.toBe(second.versionId);
    expect(second.timezoneCityVersionId).not.toBe(first.timezoneCityVersionId);
    const secondSource = await fixture.migrator.query<{ id: string; timezone: string }>(
      'SELECT id,timezone FROM foundation.service_city_versions WHERE id=$1', [second.timezoneCityVersionId]);
    expect(secondSource.rows).toEqual([{ id: secondVersionId, timezone: 'Asia/Tokyo' }]);
    // The stored revision still records its own creation provenance unchanged.
    const snapshot = await fixture.inTransaction((client) => readReferenceSnapshot(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id,
    }));
    expect(snapshot.version.id).toBe(published.id);
    expect(snapshot.version.provenanceCityVersionId).toBe(city.versionId);
    expect(snapshot.version.label).toBe('Callback 09:00-18:00');

    // A foreign city's version is refused, never silently replaced.
    expect(await codeOf(fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, intakeCityVersionId: otherCity.versionId, at: from,
    })))).toBe('NOT_FOUND');
    // A city interval without a trusted intake version cannot be resolved at all.
    expect(await codeOf(fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id,
    })))).toBe('INVALID_INPUT');
  }, 60_000);

  it('evaluates effectiveness at the requested instant without an implicit fallback', async () => {
    const entry = await createCityInterval(city, 'effectivity-window');
    await publishInterval(entry.id, 1, city.versionId, {
      validFrom: '2026-06-01T00:00:00Z', validUntil: '2026-07-01T00:00:00Z',
    });
    // Before the period: not effective.
    expect(await codeOf(fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, intakeCityVersionId: city.versionId,
      at: '2026-05-01T00:00:00Z',
    })))).toBe('CONFLICT');
    // Inside the period: effective, with the database-visible instant echoed.
    const inside = await fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, intakeCityVersionId: city.versionId,
      at: '2026-06-15T00:00:00Z',
    }));
    expect(inside.effectiveAt).toBe('2026-06-15T00:00:00.000Z');
    // At/after valid_until: not effective (the window is half-open).
    expect(await codeOf(fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'CALLBACK_INTERVAL', entryId: entry.id, intakeCityVersionId: city.versionId,
      at: '2026-07-01T00:00:00Z',
    })))).toBe('CONFLICT');
  }, 60_000);

  it('publishes a company-scoped type with no city, window or timezone', async () => {
    const entry = await fixture.inTransaction((client) => createReferenceEntry(client, fixture.reviewer, {
      type: 'PAYMENT_METHOD', code: 'card-online',
    }));
    const published = await fixture.inTransaction((client) => publishReferenceVersion(client, fixture.reviewer, {
      type: 'PAYMENT_METHOD', entryId: entry.id, expectedVersion: 1, label: 'Card online',
      sourceRef: 'review://synthetic/pay/1', validFrom: from, validUntil: until,
    }));
    expect(published.version).toBe(1);
    const resolved = await fixture.inTransaction((client) => resolveReferenceForUse(client, {
      type: 'PAYMENT_METHOD', entryId: entry.id, at: from,
    }));
    expect(resolved).toMatchObject({
      scope: 'COMPANY', cityId: null, timezone: null, timezoneCityVersionId: null, interval: null,
    });
    // The DTO always carries the timezone source field; a company type has no source.
    expect(resolved.timezoneCityVersionId).toBeNull();
    expect(Object.keys(resolved)).toContain('timezoneCityVersionId');
    // A company type must not accept a city version or a window.
    expect(await codeOf(fixture.inTransaction((client) => publishReferenceVersion(client, fixture.reviewer, {
      type: 'PAYMENT_METHOD', entryId: entry.id, expectedVersion: 2, label: 'Card',
      sourceRef: 'review://synthetic/pay/2', validFrom: from, cityVersionId: city.versionId, interval: null,
    })))).toBe('INVALID_INPUT');
    // A city id on a company entry is refused at the boundary.
    expect(await codeOf(fixture.inTransaction((client) => createReferenceEntry(client, fixture.reviewer, {
      type: 'PAYMENT_METHOD', cityId: city.id, code: 'cash',
    })))).toBe('INVALID_INPUT');
    // A duplicate company code is a conflict from the partial unique index.
    expect(await codeOf(fixture.inTransaction((client) => createReferenceEntry(client, fixture.reviewer, {
      type: 'PAYMENT_METHOD', code: 'card-online',
    })))).toBe('CONFLICT');
  }, 60_000);

  it('requires an explicit caller transaction and keeps history append-only for runtime', async () => {
    const client = await fixture.runtime.connect();
    try {
      // Autocommit: no explicit transaction, so every write is refused.
      expect(await codeOf(createReferenceEntry(client, fixture.reviewer, {
        type: 'PAYMENT_METHOD', code: 'autocommit-method',
      }))).toBe('TRANSACTION_REQUIRED');
      const existing = await fixture.migrator.query<{ id: string }>(
        `SELECT id FROM foundation.reference_entry_versions LIMIT 1`);
      const versionId = existing.rows[0]?.id;
      expect(versionId).toBeDefined();
      // A published revision is immutable even for the runtime role.
      await expect(client.query('UPDATE foundation.reference_entry_versions SET label=$2 WHERE id=$1',
        [versionId, 'rewritten'])).rejects.toMatchObject({ code: '42501' });
      // ... and a reference entry cannot be deleted.
      await expect(client.query('DELETE FROM foundation.reference_entries')).rejects.toMatchObject({ code: '42501' });
    } finally {
      client.release();
    }
  }, 30_000);

  it('rolls the publish back when the audit write fails', async () => {
    const entry = await createCityInterval(city, 'rollback-window');

    // A synthetic trigger makes every audit INSERT fail. The revision INSERT and the
    // pointer CAS run first, so only a real rollback can leave no trace of them.
    await installFailingAuditTrigger(fixture);
    try {
      await expect(publishInterval(entry.id, 1, city.versionId)).rejects.toBeDefined();
    } finally {
      await removeFailingAuditTrigger(fixture);
    }

    // Nothing survived: no version row, no pointer move, no audit/outbox pair.
    const versions = await fixture.migrator.query(
      `SELECT 1 FROM foundation.reference_entry_versions WHERE entry_id=$1`, [entry.id]);
    expect(versions.rows).toHaveLength(0);
    const entryRow = await fixture.migrator.query<{ row_version: number; current_version_id: string | null }>(
      'SELECT row_version,current_version_id FROM foundation.reference_entries WHERE id=$1', [entry.id]);
    expect(entryRow.rows[0]).toEqual({ row_version: 1, current_version_id: null });
    const outbox = await fixture.migrator.query(
      `SELECT 1 FROM foundation.outbox_events WHERE event_type='reference.version.publish' AND payload->>'entryId'=$1`,
      [entry.id]);
    expect(outbox.rows).toHaveLength(0);
    // The entry itself is still usable afterwards.
    const published = await publishInterval(entry.id, 1, city.versionId);
    expect(published.version).toBe(1);
  }, 60_000);
});