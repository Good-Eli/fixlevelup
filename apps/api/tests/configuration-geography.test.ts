/**
 * Cross-aggregate regression: the company settings revision and the geography
 * primary pointer share `foundation.business_settings_versions`.
 *
 * These tests exercise the real geography commands (`catalogCommands`) on the same
 * isolated database, with a server-trusted context built here, to prove:
 *
 * 1. a company-lock timeout in geography surfaces as the geography transport
 *    contract (HTTP 409), not as a raw internal port error or a 500;
 * 2. a geography primary change carries the company policy provenance forward
 *    instead of publishing a revision with unknown policy fields;
 * 3. a settings publish and a geography activation cannot deadlock when they run
 *    concurrently, because both take the shared company lock before any city row
 *    (the geography commands take it at the top of `run`);
 * 4. a latest revision in the reserved `MULTI_CITY` mode is refused by geography
 *    instead of being silently converted to `SINGLE_CITY`.
 *
 * This file does not test authorization: the context below is constructed
 * directly because the guard is P03-02's own subject. It only proves the shared
 * company-aggregate SQL contract between the two modules.
 */
import { HttpException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { catalogCommands } from '../src/settings/geography/catalog-commands.js';
import type { GeoContext, GeoTarget } from '../src/settings/geography/geo-contract.js';
import {
  publishCompanySettings, readCompanySettings, readCompanySettingsVersion,
} from '../src/settings/configuration/index.js';
import {
  configurationIntegration, createConfigurationFixture, createSyntheticCity, createSyntheticSettingsBaseline,
  syntheticSettings,
} from './configuration-fixture.js';
import type { ConfigurationFixture, SyntheticCity } from './configuration-fixture.js';

const statusOf = async (promise: Promise<unknown>): Promise<number | string> => {
  try {
    await promise;
  } catch (error) {
    if (error instanceof HttpException) {
      return error.getStatus();
    }
    if (error instanceof Error && 'code' in error && typeof error.code === 'string') {
      return error.code;
    }
    throw error;
  }
  throw new Error('Expected the command to be refused');
};

configurationIntegration('settings and geography share one company aggregate', () => {
  let fixture: ConfigurationFixture;
  let primary: SyntheticCity;
  let secondary: SyntheticCity;

  beforeAll(async () => {
    fixture = await createConfigurationFixture();
    primary = await createSyntheticCity(fixture, { timezone: 'Europe/Moscow' });
    secondary = await createSyntheticCity(fixture, { timezone: 'Asia/Tokyo' });
    // The first revision (all policy fields unknown) is created by geography
    // activation in production; here it is the synthetic baseline.
    await createSyntheticSettingsBaseline(fixture, primary);
  }, 60_000);

  afterAll(async () => { await fixture.close(); }, 30_000);

  /**
   * Trusted context for one command, on the caller's own client and transaction.
   * `cityIds: null` is the GLOBAL scope a verified SYSTEM ADMIN has.
   */
  function geoContext(client: PoolClient): GeoContext {
    return {
      client,
      staffId: fixture.reviewer,
      cityIds: null,
      role: { id: '00000000-0000-4000-8000-000000000001', code: 'ADMIN', type: 'SYSTEM' },
      permissions: [],
      geoPermissions: [{ code: 'geography.publish', scope: 'GLOBAL' }],
      principal: { kind: 'staff-web', staffId: fixture.reviewer, role: 'ADMIN', authVersion: 1 },
    };
  }

  /** Runs one geography command in its own explicit caller transaction. */
  async function execute(
    name: 'cityActivate' | 'citySetPrimary',
    target: GeoTarget,
    body: unknown,
    expected: number,
  ): Promise<unknown> {
    const command = catalogCommands[name];
    const client = await fixture.runtime.connect();
    try {
      await client.query('BEGIN');
      const ctx = geoContext(client);
      await command.check(ctx, target);
      const result = await command.run(ctx, target, body, expected);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  it('surfaces a company-lock timeout as a typed HTTP conflict, not a raw port error', async () => {
    // Another transaction holds the shared company lock, so a geography command with a
    // short lock_timeout fails the lock wait (55P03). The internal port maps that to
    // ConfigurationError(CONFLICT); the geography wrapper must translate it back to the
    // geography transport contract (409) instead of letting a non-HttpException become 500.
    const holder = await fixture.runtime.connect();
    const geographer = await fixture.runtime.connect();
    try {
      await holder.query('BEGIN');
      const latest = await fixture.inTransaction((client) => readCompanySettings(client));
      const cityId = latest?.primaryCityId ?? '';
      await holder.query('SELECT pg_advisory_xact_lock(734305,1)');

      await geographer.query('BEGIN');
      await geographer.query("SET LOCAL lock_timeout='100ms'");
      const ctx = geoContext(geographer);
      const cityRow = await holder.query<{ row_version: number }>(
        'SELECT row_version FROM foundation.service_cities WHERE id=$1', [cityId]);
      const command = catalogCommands.citySetPrimary;
      const startedAt = Date.now();
      const outcome = await command.run(ctx, { cityId }, {}, cityRow.rows[0]?.row_version ?? 0)
        .then(() => 'completed', (error: unknown) => error);
      const elapsed = Date.now() - startedAt;

      // It really waited on the lock instead of failing for an unrelated reason.
      expect(elapsed).toBeGreaterThanOrEqual(90);
      // A typed 409 conflict: never a raw ConfigurationError and never a 500.
      expect(outcome).toBeInstanceOf(HttpException);
      expect((outcome as HttpException).getStatus()).toBe(409);
      expect((outcome as Error).name).not.toBe('ConfigurationError');
      await geographer.query('ROLLBACK');
    } finally {
      await holder.query('ROLLBACK').catch(() => undefined);
      holder.release();
      geographer.release();
    }
  }, 60_000);

  it('carries published policy provenance forward when geography moves the primary city', async () => {
    const baseline = await fixture.inTransaction((client) => readCompanySettings(client));
    const baseVersion = baseline?.version ?? 0;
    // Publish the complete company policy revision first.
    const published = await fixture.inTransaction((client) => publishCompanySettings(client, fixture.reviewer, {
      settings: syntheticSettings(), expectedLastVersion: baseVersion,
    }));
    expect(published.version).toBe(baseVersion + 1);

    const [targetRow, previousRow] = await Promise.all([
      fixture.migrator.query<{ row_version: number }>(
        'SELECT row_version FROM foundation.service_cities WHERE id=$1', [secondary.id]),
      fixture.migrator.query<{ row_version: number }>(
        'SELECT row_version FROM foundation.service_cities WHERE id=$1', [primary.id]),
    ]);

    // Activate the second city, explicitly naming the current primary and its token.
    const activation = await execute('cityActivate', { cityId: secondary.id }, {
      replaceActiveCityId: primary.id, replaceActiveCityVersion: previousRow.rows[0]?.row_version ?? 0,
    }, targetRow.rows[0]?.row_version ?? 0);
    expect(activation).toMatchObject({ id: secondary.id });

    const latest = await fixture.inTransaction((client) => readCompanySettings(client));
    // A new revision exists, the primary moved, and every policy value survived.
    expect(latest?.primaryCityId).toBe(secondary.id);
    expect(latest?.version).toBe(published.version + 1);
    expect(latest?.settings).toEqual(syntheticSettings());
    // The publisher of the carried revision is the geography actor, and the policy
    // refs remain provenance of the earlier review (not a fresh review).
    expect(latest?.reviewedBy).toBe(fixture.reviewer);

    // The earlier revision is still readable and unchanged.
    const previous = await fixture.inTransaction((client) => readCompanySettingsVersion(client, published.version));
    expect(previous.primaryCityId).toBe(primary.id);
    expect(previous.settings).toEqual(syntheticSettings());
  }, 60_000);

  it('does not deadlock when a settings publish and a geography activation run concurrently', async () => {
    // Both writers take pg_advisory_xact_lock(734305,1) first; the settings publisher
    // then only inserts (FK check on service_cities) while geography locks the city row.
    // The opposite order (city lock -> company lock) is what would deadlock here.
    const latest = await fixture.inTransaction((client) => readCompanySettings(client));
    const currentVersion = latest?.version ?? 0;
    const currentPrimary = latest?.primaryCityId ?? '';

    const publisher = await fixture.runtime.connect();
    const geographer = await fixture.runtime.connect();
    const observer = await fixture.runtime.connect();
    try {
      await publisher.query('BEGIN');
      const published = await publishCompanySettings(publisher, fixture.reviewer, {
        settings: syntheticSettings({ operatorName: 'Synthetic Concurrent Operator' }),
        expectedLastVersion: currentVersion,
      });
      // Geography starts while the publisher holds the company lock: it must wait for
      // the company lock, never take the city lock first.
      await geographer.query('BEGIN');
      const geographerPid = (await geographer.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      const cityRow = await observer.query<{ row_version: number }>(
        'SELECT row_version FROM foundation.service_cities WHERE id=$1', [currentPrimary]);
      const command = catalogCommands.cityActivate;
      const ctx = geoContext(geographer);
      const target: GeoTarget = { cityId: currentPrimary };
      const pending = command.run(ctx, target, {}, cityRow.rows[0]?.row_version ?? 0)
        .then(async () => { await geographer.query('COMMIT'); });

      let waitEventType: string | null = null;
      for (let attempt = 0; attempt < 60 && waitEventType === null; attempt += 1) {
        const waiting = await observer.query<{ wait_event_type: string | null }>(
          'SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [geographerPid]);
        waitEventType = waiting.rows[0]?.wait_event_type ?? null;
        if (waitEventType === null) { await new Promise((resolve) => setTimeout(resolve, 25)); }
      }
      // Blocked on the shared company lock, not on a city row or anything else.
      expect(waitEventType).toBe('Lock');
      await publisher.query('COMMIT');

      const settled = await pending.then(() => 'ok', (error: unknown) => error);
      // Either it succeeds or it is a typed conflict; a deadlock would be 40P01.
      if (settled !== 'ok' && !(settled instanceof HttpException)) {
        throw settled;
      }
      const after = await fixture.inTransaction((client) => readCompanySettings(client));
      // The publisher's revision survived and no policy value was lost.
      expect(after?.version).toBeGreaterThanOrEqual(published.version);
      expect(after?.settings).toEqual(syntheticSettings({ operatorName: 'Synthetic Concurrent Operator' }));
      // Geography carried the same primary city forward (no switch, no policy loss).
      expect(after?.primaryCityId).toBe(currentPrimary);
    } finally {
      await publisher.query('ROLLBACK').catch(() => undefined);
      await geographer.query('ROLLBACK').catch(() => undefined);
      publisher.release();
      geographer.release();
      observer.release();
    }
  }, 60_000);

  it('refuses a reserved MULTI_CITY latest revision instead of converting it', async () => {
    // Synthetic reserved-mode revision written by the migration owner, exactly as an
    // unsupported configuration would look after a manual/legacy change.
    await fixture.migrator.query(`INSERT INTO foundation.business_settings_versions
      (id,version,launch_mode,primary_city_id,reviewed_by)
      SELECT $1,COALESCE(max(version),0)+1,'MULTI_CITY',$2,$3 FROM foundation.business_settings_versions`,
    ['55555555-5555-4555-8555-555555555555', secondary.id, fixture.reviewer]);

    const cityRow = await fixture.migrator.query<{ row_version: number }>(
      'SELECT row_version FROM foundation.service_cities WHERE id=$1', [primary.id]);
    const expected = cityRow.rows[0]?.row_version ?? 0;
    // Geography must refuse: MULTI_CITY is reserved vocabulary, not an implicit mode.
    expect(await statusOf(execute('citySetPrimary', { cityId: primary.id }, {}, expected))).toBe(409);
    // The reserved revision was not replaced or converted.
    const latest = await fixture.inTransaction((client) => readCompanySettings(client));
    expect(latest?.launchMode).toBe('MULTI_CITY');
  }, 60_000);
});
