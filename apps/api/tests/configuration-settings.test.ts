/**
 * Company-settings port against a real isolated PostgreSQL instance.
 *
 * Every write goes through the real `fixlevelup_runtime` role inside an explicit
 * caller transaction; synthetic baseline rows are created by the migration owner.
 * These tests prove what unit tests cannot: the runtime grants, the immutable
 * append-only revision chain, the CAS on `expectedLastVersion`, the shared company
 * advisory lock (contention and carry-forward), the caller-transaction guard, the
 * audit/outbox atomicity, and that an audit failure rolls the publish back.
 */
import { randomUUID } from 'node:crypto';
import type { Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  COMPANY_SETTINGS_LOCK_HELD_SQL, acquireCompanySettingsLock,
  listCompanySettingsHistory, publishCompanySettings, readCompanySettings, readCompanySettingsReadiness,
  readCompanySettingsVersion, requireCompleteSettings,
} from '../src/settings/configuration/index.js';
import { ConfigurationError } from '../src/settings/configuration/configuration-errors.js';
import type { CompanySettingsReadiness } from '../src/settings/configuration/company-settings.js';
import {
  configurationIntegration, createConfigurationFixture, createSyntheticCity, createSyntheticSettingsBaseline,
  installFailingAuditTrigger, removeFailingAuditTrigger, syntheticSettings,
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

/** Runtime client that is *not* inside a transaction, for the guard test. */
async function autocommit(client: Client, run: (client: Client) => Promise<unknown>): Promise<unknown> {
  return run(client);
}

configurationIntegration('company settings port against isolated PostgreSQL', () => {
  let fixture: ConfigurationFixture;
  let city: SyntheticCity;

  beforeAll(async () => {
    fixture = await createConfigurationFixture();
    city = await createSyntheticCity(fixture);
  }, 60_000);

  afterAll(async () => { await fixture.close(); }, 30_000);

  it('publishes a complete revision, keeps history immutable and preserves the primary city', async () => {
    const baseline = await createSyntheticSettingsBaseline(fixture, city);
    const latestBefore = await fixture.inTransaction((client) => readCompanySettings(client));
    expect(latestBefore).toMatchObject({ version: baseline.version, primaryCityId: city.id });
    // A revision created before 013 leaves every policy field unknown, not empty.
    expect(latestBefore?.settings.operatorName).toBeNull();
    expect(Object.values(latestBefore?.settings ?? {})).toEqual(Array(7).fill(null));

    const readinessBefore = await fixture.inTransaction((client) => readCompanySettingsReadiness(client));
    expect(readinessBefore.missingFields).toHaveLength(7);
    expect(readinessBefore.ready).toBe(false);
    expect(() => { requireCompleteSettings(readinessBefore); })
      .toThrow(expect.objectContaining({ code: 'INCOMPLETE' }));

    const receipt = await fixture.inTransaction((client) => publishCompanySettings(client, fixture.reviewer, {
      settings: syntheticSettings(), expectedLastVersion: baseline.version,
    }));
    expect(receipt).toMatchObject({
      version: baseline.version + 1,
      previousVersion: baseline.version,
      launchMode: 'SINGLE_CITY',
      primaryCityId: city.id,
    });
    expect(receipt.carriedFields).toEqual([]);

    const latest = await fixture.inTransaction((client) => readCompanySettings(client));
    expect(latest).toMatchObject({ version: baseline.version + 1, primaryCityId: city.id });
    expect(latest?.settings).toEqual(syntheticSettings());
    expect(latest?.reviewedBy).toBe(fixture.reviewer);

    // The old revision is untouched and still readable with its NULL fields.
    const historical = await fixture.inTransaction((client) => readCompanySettingsVersion(client, baseline.version));
    expect(historical.settings.operatorName).toBeNull();

    const history = await fixture.inTransaction((client) => listCompanySettingsHistory(client, 10));
    expect(history.items.map((item) => item.version)).toEqual([baseline.version + 1, baseline.version]);
    // No secret, city timezone or contact value is exposed by the company settings view.
    const serialized = JSON.stringify(history);
    expect(serialized).not.toContain('office@example.test');
    expect(serialized).not.toContain(city.timezone);

    const ready = await fixture.inTransaction((client) => readCompanySettingsReadiness(client));
    expect(ready.missingFields).toEqual([]);
    // Readiness stays false: no consent form exists yet, which is a separate gate.
    expect(ready.missingDocuments).toEqual(['REQUEST_PROCESSING']);
    expect(ready.ready).toBe(false);

    // Every publish wrote one audit row and one outbox event with the same correlation id.
    const audit = await fixture.migrator.query<{ operation: string; details: Record<string, unknown> }>(
      `SELECT operation,details FROM foundation.audit_logs WHERE operation='settings.publish'`);
    expect(audit.rows.length).toBeGreaterThanOrEqual(1);
    const details = audit.rows.at(-1)?.details;
    expect(details).toMatchObject({ entity: 'SETTINGS', version: baseline.version + 1 });
    // The audit payload carries identifiers only, never reviewed text.
    expect(JSON.stringify(details)).not.toContain('Synthetic Operator');
    const outbox = await fixture.migrator.query(
      `SELECT 1 FROM foundation.outbox_events WHERE event_type='settings.publish'`);
    expect(outbox.rows.length).toBeGreaterThanOrEqual(1);
  }, 60_000);

  it('refuses a stale expected version and a partially configured revision', async () => {
    const latest = await fixture.inTransaction((client) => readCompanySettings(client));
    expect(latest).not.toBeNull();
    const currentVersion = latest?.version ?? 0;

    // A publisher that read an older revision cannot overwrite the newer one.
    expect(await codeOf(fixture.inTransaction((client) => publishCompanySettings(client, fixture.reviewer, {
      settings: syntheticSettings(), expectedLastVersion: currentVersion - 1,
    })))).toBe('STALE_VERSION');

    // An incomplete revision is refused before any SQL runs.
    const incomplete: Record<string, string> = syntheticSettings();
    delete incomplete['retentionPolicyRef'];
    expect(await codeOf(fixture.inTransaction((client) => publishCompanySettings(client, fixture.reviewer, {
      settings: incomplete, expectedLastVersion: currentVersion,
    })))).toBe('INVALID_INPUT');
    expect(await codeOf(fixture.inTransaction((client) => publishCompanySettings(client, fixture.reviewer, {
      settings: { ...syntheticSettings(), uploadPolicyRef: '  ' }, expectedLastVersion: currentVersion,
    })))).toBe('INVALID_INPUT');

    // An arbitrary/secret key is not a settings field.
    expect(await codeOf(fixture.inTransaction((client) => publishCompanySettings(client, fixture.reviewer, {
      settings: { ...syntheticSettings(), apiKey: 'x' }, expectedLastVersion: currentVersion,
    })))).toBe('INVALID_INPUT');

    const after = await fixture.inTransaction((client) => readCompanySettings(client));
    expect(after?.version).toBe(currentVersion);
  }, 60_000);

  it('carries a policy ref forward as provenance of the earlier review', async () => {
    const latest = await fixture.inTransaction((client) => readCompanySettings(client));
    const currentVersion = latest?.version ?? 0;
    const samePolicy = syntheticSettings();
    const receipt = await fixture.inTransaction((client) => publishCompanySettings(client, fixture.secondReviewer, {
      settings: samePolicy, expectedLastVersion: currentVersion,
    }));
    expect(receipt.carriedFields).toEqual([
      'operatorName', 'operatorRegistrationId', 'operatorAddress', 'legalReviewRef',
      'securityPolicyRef', 'retentionPolicyRef', 'uploadPolicyRef',
    ]);
    // The publisher of this revision is recorded, even though the refs were reviewed earlier.
    const view = await fixture.inTransaction((client) => readCompanySettingsVersion(client, receipt.version));
    expect(view.reviewedBy).toBe(fixture.secondReviewer);
  }, 60_000);

  it('requires an explicit caller transaction for the company lock', async () => {
    const client = await fixture.runtime.connect();
    try {
      // Autocommit: the transaction-scoped lock is released immediately, so the
      // guard refuses instead of silently running without serialization.
      expect(await codeOf(autocommit(client, (target) => acquireCompanySettingsLock(target))))
        .toBe('TRANSACTION_REQUIRED');
      // The same call inside an explicit transaction succeeds.
      await client.query('BEGIN');
      await acquireCompanySettingsLock(client);
      await client.query('COMMIT');
    } finally {
      client.release();
    }
  }, 30_000);

  it('does not mistake a lock held by another session for the caller own lock', async () => {
    // The probe is restricted to `pid = pg_backend_pid()` and to the two-int
    // `objsubid = 2` form, so a session-level lock held by a different backend on the
    // same key can never satisfy it. The probe is read directly (not through
    // acquireCompanySettingsLock) because taking the lock would block on the holder.
    const holder = await fixture.runtime.connect();
    const caller = await fixture.runtime.connect();
    try {
      await holder.query('SELECT pg_advisory_lock(734305,1)');
      const probe = await caller.query<{ held: boolean }>(COMPANY_SETTINGS_LOCK_HELD_SQL, [734305, 1]);
      expect(probe.rows[0]?.held).toBe(false);
    } finally {
      await holder.query('SELECT pg_advisory_unlock(734305,1)').catch(() => undefined);
      holder.release();
      caller.release();
    }
  }, 30_000);

  it('serializes two publishers on the shared company lock and refuses the stale one', async () => {
    const latest = await fixture.inTransaction((client) => readCompanySettings(client));
    const currentVersion = latest?.version ?? 0;
    const primaryCityId = latest?.primaryCityId;

    const first = await fixture.runtime.connect();
    const second = await fixture.runtime.connect();
    const observer = await fixture.runtime.connect();
    try {
      await first.query('BEGIN');
      const firstReceipt = await publishCompanySettings(first, fixture.reviewer, {
        settings: syntheticSettings({ operatorName: 'Synthetic Operator First' }), expectedLastVersion: currentVersion,
      });
      // The second publisher starts while the first holds the company lock. It must
      // block on pg_advisory_xact_lock rather than read the pre-commit state.
      await second.query('BEGIN');
      const secondPid = (await second.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      const pending = publishCompanySettings(second, fixture.reviewer, {
        settings: syntheticSettings({ operatorName: 'Synthetic Operator Second' }), expectedLastVersion: currentVersion,
      });
      let waitEventType: string | null = null;
      for (let attempt = 0; attempt < 50 && waitEventType === null; attempt += 1) {
        const waiting = await observer.query<{ wait_event_type: string | null }>(
          'SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [secondPid]);
        waitEventType = waiting.rows[0]?.wait_event_type ?? null;
        if (waitEventType === null) { await new Promise((resolve) => setTimeout(resolve, 25)); }
      }
      expect(waitEventType).toBe('Lock');
      await first.query('COMMIT');

      // The waiting publisher now sees the committed revision and its CAS token is
      // stale: it is refused instead of overwriting what the first publisher wrote.
      await expect(pending).rejects.toMatchObject({ code: 'STALE_VERSION' });
      // A retry with the revision it just read succeeds and carries the primary city.
      const retried = await publishCompanySettings(second, fixture.reviewer, {
        settings: syntheticSettings({ operatorName: 'Synthetic Operator Second' }),
        expectedLastVersion: firstReceipt.version,
      });
      await second.query('COMMIT');
      expect(retried.version).toBe(firstReceipt.version + 1);
      expect(retried.primaryCityId).toBe(primaryCityId);

      const history = await fixture.inTransaction((client) => listCompanySettingsHistory(client, 3));
      expect(history.items[0]?.settings.operatorName).toBe('Synthetic Operator Second');
      expect(history.items[1]?.settings.operatorName).toBe('Synthetic Operator First');
      // No publisher switched the company primary city or launch mode.
      expect(history.items.every((item) => item.primaryCityId === primaryCityId && item.launchMode === 'SINGLE_CITY'))
        .toBe(true);
    } finally {
      await first.query('ROLLBACK').catch(() => undefined);
      await second.query('ROLLBACK').catch(() => undefined);
      first.release();
      second.release();
      observer.release();
    }
  }, 60_000);
  it('rolls the publish back when the audit write fails', async () => {
    const before = await fixture.inTransaction((client) => readCompanySettings(client));
    const currentVersion = before?.version ?? 0;
    const nextVersion = currentVersion + 1;

    // A synthetic trigger makes every audit INSERT fail. The publish must then abort
    // as a whole: no new revision row and no outbox event survive.
    await installFailingAuditTrigger(fixture);
    try {
      await expect(fixture.inTransaction((client) => publishCompanySettings(client, fixture.reviewer, {
        settings: syntheticSettings({ operatorName: 'Synthetic Operator Rolled Back' }),
        expectedLastVersion: currentVersion,
      }))).rejects.toBeDefined();
    } finally {
      await removeFailingAuditTrigger(fixture);
    }

    // No revision was committed by the failed publish.
    const after = await fixture.inTransaction((client) => readCompanySettings(client));
    expect(after?.version).toBe(currentVersion);
    const revision = await fixture.migrator.query(
      'SELECT 1 FROM foundation.business_settings_versions WHERE version=$1', [nextVersion]);
    expect(revision.rows).toHaveLength(0);
    const outbox = await fixture.migrator.query(
      `SELECT 1 FROM foundation.outbox_events WHERE event_type='settings.publish' AND payload->>'version'=$1`,
      [String(nextVersion)]);
    expect(outbox.rows).toHaveLength(0);
  }, 60_000);});

describe('company settings readiness purpose policy', () => {
  it('refuses an incomplete readiness report with the first missing field', () => {
    // Pure shape check: the SQL half is covered by the integration suite above.
    const readiness: CompanySettingsReadiness = {
      ready: false, latestVersion: 1, launchMode: 'SINGLE_CITY', primaryCityId: randomUUID(),
      missingFields: [], documents: [{ purpose: 'REQUEST_PROCESSING', kind: 'CONSENT_FORM', current: false }],
      missingDocuments: ['REQUEST_PROCESSING'],
    };
    expect(() => { requireCompleteSettings(readiness); })
      .toThrow(expect.objectContaining({ code: 'INCOMPLETE', field: 'REQUEST_PROCESSING' }));
  });
});
