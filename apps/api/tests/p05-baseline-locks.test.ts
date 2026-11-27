/**
 * P05-01 baseline lock proof (docs/P05-PLAN.md §5.1, "Доказательства перед первой DDL").
 *
 * Runs against the real isolated 021 PostgreSQL chain. Its only purpose is to
 * capture, before any P05 DDL exists, how the current GEO/CFG writer and reader
 * paths actually interleave:
 *
 *  - a company-settings publisher (X (734305,1) -> settings INSERT) versus a
 *    fenced geography writer (X -> city row FOR UPDATE): in both commit orders
 *    they serialize on the shared company lock before any city row, so no
 *    deadlock (40P01) occurs and the publisher's INSERT only takes a KEY SHARE
 *    on the referenced city;
 *  - an UNFENCED city publish (today: city row FOR UPDATE only, no X)
 *    interleaves with a reader: the reader's later statement sees the committed
 *    pointer move. This is the documented pre-S1 gap the unified fence must
 *    close; the S1 change is then a deliberate, observed difference;
 *  - the catalog (P04) fence (77304,1) and the company fence (734305,1) are
 *    distinct keys: opposite-order acquisition from two sessions grants both
 *    immediately. The S1 unified fence must keep this property;
 *  - the runtime role can INSERT into a fenced-basis relation with no X today
 *    (the real districtCreate path), recorded as the exact pre-guard fact the
 *    S1 BEFORE STATEMENT guard flips into a rejection.
 *
 * Two backends plus an independent observer (`pg_blocking_pids`, exact advisory
 * key and lock mode, both commit orders and a rollback variant) are used.
 *
 * This file proves the CURRENT state. It is not a P05 feature test: no P05
 * relation exists yet and only 021 relations are touched.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, expect, it } from 'vitest';
import {
  createConfigurationFixture, createSyntheticCity, createSyntheticSettingsBaseline,
  syntheticSettings,
} from './configuration-fixture.js';
import type { ConfigurationFixture, SyntheticCity } from './configuration-fixture.js';
import { publishCompanySettings, readCompanySettings } from '../src/settings/configuration/index.js';

const COMPANY_KEY = { classId: 734305, objectId: 1 } as const;

const proof = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? it : it.skip;

let fixture: ConfigurationFixture;
let primary: SyntheticCity;

beforeAll(async () => {
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') { return; }
  // Baseline = schema profile S0 (exactly 021): the chain stops before the
  // first P05 migration, so the guard-less facts below are the pre-DDL truth.
  fixture = await createConfigurationFixture({ capBefore: '20261123000100_request_intake_foundation' });
  primary = await createSyntheticCity(fixture, { timezone: 'Europe/Moscow' });
  await createSyntheticSettingsBaseline(fixture, primary);
}, 120_000);

afterAll(async () => { await fixture.close(); }, 60_000);

/** Independent observer: exactly one pending advisory edge waiter->blocker. */
async function advisoryEdge(waiter: number, blocker: number): Promise<boolean> {
  const result = await fixture.runtime.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_locks w
     WHERE w.locktype='advisory' AND w.pid=$1 AND NOT w.granted
       AND w.classid=$2::int::oid AND w.objid=$3::int::oid AND w.objsubid=2
       AND $4=ANY(pg_blocking_pids(w.pid))`,
    [waiter, COMPANY_KEY.classId, COMPANY_KEY.objectId, blocker]);
  return result.rows[0]?.n === 1;
}

/** Minimal query-capable handle: a Pool or a single checked-out client. */
interface QueryClient { query: import('pg').PoolClient['query'] }

/** Waits until `pid` observably waits on a lock, via an independent observer client. */
async function waitUntilBlocked(observer: QueryClient, pid: number): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const row = await observer.query<{ wait: string | null; blocked: boolean; state: string; n: number }>(
      `SELECT wait_event_type AS wait,
         array_length(pg_blocking_pids(pid), 1) IS NOT NULL AS blocked, state,
         (SELECT count(*)::int FROM pg_locks l WHERE l.pid=pid AND NOT l.granted) AS n
       FROM pg_stat_activity WHERE pid=$1`, [pid]);
    const current = row.rows[0];
    if (current && (current.wait === 'Lock' || current.blocked || current.n > 0)) { return; }
    if (attempt === 199 && current) {
      throw new Error(`Backend never reached a lock wait (state=${current.state} wait=${String(current.wait)} blocked=${String(current.blocked)} ungranted=${String(current.n)})`);
    }
    await new Promise((resolve) => { setTimeout(resolve, 25); });
  }
  throw new Error('Backend did not reach an observable lock wait');
}

async function backendPid(client: QueryClient): Promise<number> {
  const pid = (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
  if (typeof pid !== 'number') { throw new Error('Missing backend PID'); }
  return pid;
}

const geoLockStep = 'SELECT pg_advisory_xact_lock(734305,1)' as const;

/** Baseline proof 1: both fenced writers serialize on (734305,1) before any city row. */
for (const order of ['publisher-first', 'geography-first'] as const) {
  proof(`baseline: fenced company publisher vs fenced geography writer (${order})`, { timeout: 120_000 }, async () => {
    const publisher = await fixture.runtime.connect();
    const geographer = await fixture.runtime.connect();
    const observer = await fixture.runtime.connect();
    try {
      const latest = await fixture.inTransaction((client) => readCompanySettings(client));
      const version = latest?.version ?? 0;

      await publisher.query('BEGIN');
      await geographer.query('BEGIN');
      const pubPid = await backendPid(publisher);
      const geoPid = await backendPid(geographer);

      if (order === 'publisher-first') {
        // Publisher completes its X + INSERT while still holding the X.
        const published = await publishCompanySettings(publisher, fixture.reviewer, {
          settings: syntheticSettings({ operatorName: `Baseline ${order}` }), expectedLastVersion: version,
        });
        expect(published.version).toBeGreaterThan(version);
        // Geography (real cityActivate order: X first, then city row) queues behind.
        const pendingGeo = geographer.query(geoLockStep).then(async () => geographer.query(
          'SELECT row_version FROM foundation.service_cities WHERE id=$1 FOR UPDATE', [primary.id]));
        await waitUntilBlocked(observer, geoPid);
        expect(await advisoryEdge(geoPid, pubPid)).toBe(true);
        await publisher.query('COMMIT');
        await pendingGeo; // granted after the commit; the city lock is free
        await geographer.query('COMMIT');
      } else {
        // Geography holds X and the city row FOR UPDATE.
        await geographer.query(geoLockStep);
        await geographer.query(
          'SELECT row_version FROM foundation.service_cities WHERE id=$1 FOR UPDATE', [primary.id]);
        // Publisher queues on the X; after the geographer commits, its INSERT
        // FK check takes only KEY SHARE on the city row, so no inversion.
        let published2: { version: number } | undefined;
        const pendingPublish = publishCompanySettings(publisher, fixture.reviewer, {
          settings: syntheticSettings({ operatorName: `Baseline ${order}` }), expectedLastVersion: version,
        }).then((receipt) => { published2 = receipt; });
        await waitUntilBlocked(observer, pubPid);
        expect(await advisoryEdge(pubPid, geoPid)).toBe(true);
        await geographer.query('COMMIT');
        await pendingPublish;
        expect(published2?.version).toBeGreaterThan(version);
        await publisher.query('COMMIT');
      }
      // Both orders leave exactly the winner's whole revision on top.
      const after = await fixture.inTransaction((client) => readCompanySettings(client));
      expect(after?.settings.operatorName).toBe(`Baseline ${order}`);
    } finally {
      await publisher.query('ROLLBACK').catch(() => undefined);
      await geographer.query('ROLLBACK').catch(() => undefined);
      publisher.release();
      geographer.release();
      observer.release();
    }
  });
}

proof('baseline: unfenced city publish interleaves with a fenced reader (documented gap)', { timeout: 120_000 }, async () => {
  const publisher = await fixture.runtime.connect();
  const reader = await fixture.runtime.connect();
  try {
    // A second reviewed city version to publish to.
    const versionId = randomUUID();
    await fixture.migrator.query(`INSERT INTO foundation.service_city_versions
      (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES ($1,$2,2,'Synthetic second','Europe/Moscow','office@example.test','[[],[],[],[],[],[],[]]'::jsonb,$3)`,
    [versionId, primary.id, fixture.reviewer]);
    const cityRow = await fixture.migrator.query<{ row_version: number; current_version_id: string }>(
      'SELECT row_version, current_version_id FROM foundation.service_cities WHERE id=$1', [primary.id]);
    const before = cityRow.rows[0]?.current_version_id ?? '';

    await publisher.query('BEGIN');
    await reader.query('BEGIN');

    // The real unfenced cityPublish statements: city row FOR UPDATE + pointer move.
    await publisher.query('SELECT row_version FROM foundation.service_cities WHERE id=$1 FOR UPDATE', [primary.id]);
    await publisher.query('UPDATE foundation.service_cities SET current_version_id=$2 WHERE id=$1', [primary.id, versionId]);

    // Reader: the P04 fenced catalog basis read (S (77304,1)), then the pointer.
    await reader.query('SELECT pg_advisory_xact_lock_shared(77304,1)');
    const read1 = await reader.query<{ current_version_id: string }>(
      'SELECT current_version_id FROM foundation.service_cities WHERE id=$1', [primary.id]);

    await publisher.query('COMMIT');

    // READ COMMITTED: the reader's NEXT statement sees the committed move even
    // though its transaction began earlier. No fence serializes this pair today.
    const read2 = await reader.query<{ current_version_id: string }>(
      'SELECT current_version_id FROM foundation.service_cities WHERE id=$1', [primary.id]);
    expect(read1.rows[0]?.current_version_id).toBe(before);
    expect(read2.rows[0]?.current_version_id).toBe(versionId);
    await reader.query('COMMIT');
  } finally {
    await publisher.query('ROLLBACK').catch(() => undefined);
    await reader.query('ROLLBACK').catch(() => undefined);
    publisher.release();
    reader.release();
  }
});

proof('baseline: catalog fence and company fence are independent keys (no false edge)', { timeout: 60_000 }, async () => {
  const a = await fixture.runtime.connect();
  const b = await fixture.runtime.connect();
  try {
    await a.query('BEGIN');
    await b.query('BEGIN');
    await a.query('SELECT pg_advisory_xact_lock(734305,1)');
    await b.query('SELECT pg_advisory_xact_lock_shared(77304,1)');
    // Distinct keys: A's shared 77304 grant is immediate. B's exclusive 734305
    // must wait for A's commit — issued without awaiting so A can commit (a
    // sequential await would be a self-deadlock of the test, not of PG).
    await a.query('SELECT pg_advisory_xact_lock_shared(77304,1)');
    const pendingB = b.query('SELECT pg_advisory_xact_lock(734305,1)');
    await a.query('COMMIT');
    await pendingB;
    await b.query('COMMIT');
  } finally {
    await a.query('ROLLBACK').catch(() => undefined);
    await b.query('ROLLBACK').catch(() => undefined);
    a.release();
    b.release();
  }
});

proof('baseline: rollback variant — a rolled-back fenced writer releases the edge cleanly', { timeout: 60_000 }, async () => {
  const writer = await fixture.runtime.connect();
  const waiter = await fixture.runtime.connect();
  const observer = await fixture.runtime.connect();
  try {
    await writer.query('BEGIN');
    await waiter.query('BEGIN');
    const writerPid = await backendPid(writer);
    const waiterPid = await backendPid(waiter);
    await writer.query(geoLockStep);
    const pending = waiter.query(geoLockStep);
    await waitUntilBlocked(observer, waiterPid);
    expect(await advisoryEdge(waiterPid, writerPid)).toBe(true);
    await writer.query('ROLLBACK');
    await pending; // granted immediately after the rollback
    await waiter.query('COMMIT');
  } finally {
    await writer.query('ROLLBACK').catch(() => undefined);
    await waiter.query('ROLLBACK').catch(() => undefined);
    writer.release();
    waiter.release();
    observer.release();
  }
});

proof('baseline: runtime direct DML on a fenced-basis relation succeeds today (pre-guard fact)', { timeout: 60_000 }, async () => {
  // On 021 the runtime role INSERTs into administrative_districts with no X
  // fence (the real districtCreate path). This is the pre-S1 fact the S1 guard
  // flips into a rejection; the later migration test diffs against it.
  const before = await fixture.runtime.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM foundation.administrative_districts');
  await fixture.inTransaction(async (client) => {
    await client.query(`INSERT INTO foundation.administrative_districts (id,city_id,code,name)
      VALUES ($1,$2,$3,'Baseline district')`,
    [randomUUID(), primary.id, `baseline-${randomUUID().slice(0, 8)}`]);
  });
  const after = await fixture.runtime.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM foundation.administrative_districts');
  expect(after.rows[0]?.n).toBe((before.rows[0]?.n ?? 0) + 1);
});
