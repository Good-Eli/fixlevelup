/**
 * Isolated fixture lifecycle: a provisioning failure AFTER the successful
 * `CREATE DATABASE` (the first GRANT/REVOKE, the fixture connection, any of the
 * 001…023 migration SQL, the pinned history, or the synthetic staff bootstrap)
 * must still end its own connections and drop exactly the database it created.
 *
 * The faults are injected by observing and rejecting real `pg` statements on
 * `Client.prototype.query` (the same technique the form-session transport suite
 * uses); no fixture API is widened, no production code is stubbed and no
 * migration is replaced. Every assertion is about observable lifecycle state:
 * which database names exist, which sessions remain, and which error reaches the
 * caller. The suite never touches a database it did not create, and a teardown
 * failure is proven to surface instead of being swallowed.
 *
 * Opt-in like the other isolated suites: `FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1`
 * (plus the local dev PostgreSQL at 127.0.0.1:55432, or the isolated S4 lab
 * cluster in synthetic mode, where the maintenance identity comes from the
 * attested `loadP05LabTarget().openMaintenance()` binding).
 */
import { randomBytes } from 'node:crypto';
import { Client } from 'pg';
import { afterAll, beforeAll, expect, it } from 'vitest';
import {
  configurationIntegration,
  createConfigurationFixture,
  openConfigurationMaintenanceClient,
} from './configuration-fixture.js';
import { OwnedTestDatabase, dropOwnedTestDatabase } from './owned-test-database.js';

/** Only the disposable configuration databases are ever dropped by this suite. */
const DISPOSABLE = /^fixlevelup_configuration_test_[a-f0-9]{24}$/;

/**
 * Every throwaway fixture family in the suite tree. Sibling suites run in a
 * second Vitest worker and legitimately CREATE and DROP these names while this
 * file is running, so "still present afterwards" can only be asserted for
 * databases no fixture family owns — otherwise the check races a concurrent
 * teardown and fails for a reason unrelated to this suite.
 */
const DISPOSABLE_FAMILY = /^fixlevelup_(?:configuration|legal|auth_e2e|auth_readiness|web_auth|tg_auth|bootstrap|recovery|rbac|p017a|p05)[a-z0-9_]*_test_[a-f0-9]{24}$|^fixlevelup_(?:p017a|p05)_/;

/** Snapshot of the databases this suite could never be responsible for. */
async function persistentNames(maintenance: Client): Promise<string[]> {
  return (await databaseNames(maintenance)).filter((name) => !DISPOSABLE_FAMILY.test(name));
}

interface QueryFaults {
  /** Databases named by an observed `CREATE DATABASE` statement, in order. */
  readonly created: string[];
  /** Databases named by an observed `DROP DATABASE` statement, in order. */
  readonly dropped: string[];
  /** Restores the untouched `Client.prototype.query`. */
  readonly restore: () => void;
}

/**
 * Installs one `Client.prototype.query` observer that records CREATE/DROP DATABASE
 * names and can reject a statement with an injected error. `decide` returns the
 * error to reject with, or `undefined` to let the real statement run.
 */
function installQueryFaults(decide: (sql: string, database: string | undefined) => Error | undefined): QueryFaults {
  const descriptor = Object.getOwnPropertyDescriptor(Client.prototype, 'query');
  const originalQuery: unknown = descriptor?.value;
  if (!descriptor || typeof originalQuery !== 'function') { throw new Error('Missing PG Client.prototype.query'); }
  const created: string[] = [];
  const dropped: string[] = [];
  Object.defineProperty(Client.prototype, 'query', {
    ...descriptor,
    value: function observedQuery(this: Client, ...args: unknown[]): unknown {
      const sql = args[0];
      if (typeof sql !== 'string') { return Reflect.apply(originalQuery, this, args); }
      const create = /^\s*CREATE\s+DATABASE\s+"?([^"\s]+)"?/i.exec(sql);
      if (create?.[1] !== undefined) { created.push(create[1]); }
      const drop = /^\s*DROP\s+DATABASE\s+(?:IF\s+EXISTS\s+)?"?([^"\s]+)"?/i.exec(sql);
      if (drop?.[1] !== undefined) { dropped.push(drop[1]); }
      const database = this.database;
      const failure = decide(sql, database);
      if (failure !== undefined) { return Promise.reject(failure); }
      return Reflect.apply(originalQuery, this, args);
    },
  });
  return { created, dropped, restore: () => { Object.defineProperty(Client.prototype, 'query', descriptor); } };
}

/** Sorted database names visible on the cluster. */
async function databaseNames(maintenance: Client): Promise<string[]> {
  const result = await maintenance.query<{ datname: string }>(
    'SELECT datname FROM pg_database ORDER BY datname',
  );
  return result.rows.map((row) => row.datname);
}

/** Open sessions (any role) currently attached to one database. */
async function sessionsOn(maintenance: Client, database: string): Promise<number> {
  const result = await maintenance.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1', [database],
  );
  return result.rows[0]?.n ?? 0;
}

configurationIntegration('isolated fixture database lifecycle', () => {
  let maintenance: Client;

  beforeAll(async () => {
    maintenance = await openConfigurationMaintenanceClient();
  }, 60_000);

  afterAll(async () => {
    await maintenance.end();
  });

  it('drops its own database when the first GRANT/REVOKE fails right after CREATE', async () => {
    const before = await persistentNames(maintenance);
    let injected: Error | undefined;
    const faults = installQueryFaults((sql, database) => {
      // The provisioning connection is the only one on `postgres` issuing this
      // statement; the injected failure therefore fires exactly on the fixture.
      if (database !== 'postgres' || injected !== undefined) { return undefined; }
      if (/^\s*REVOKE\s+ALL\s+ON\s+DATABASE\b/i.test(sql)) {
        injected = new Error('Injected early provisioning failure');
        return injected;
      }
      return undefined;
    });
    try {
      await expect(createConfigurationFixture()).rejects.toThrow('Injected early provisioning failure');
    } finally {
      faults.restore();
    }
    expect(injected).toBeInstanceOf(Error);
    expect(faults.created).toHaveLength(1);
    const created = faults.created[0];
    if (created === undefined || !DISPOSABLE.test(created)) { throw new Error(`Unexpected created database: ${String(created)}`); }
    // The half-built fixture is gone and no session outlived it.
    const after = await databaseNames(maintenance);
    expect(after).not.toContain(created);
    expect(await sessionsOn(maintenance, created)).toBe(0);
    // Nothing that existed before this attempt was destroyed.
    for (const name of before) { expect(after).toContain(name); }
  }, 60_000);

  it('drops its own database when a migration statement fails mid-chain', async () => {
    const before = await persistentNames(maintenance);
    let calls = 0;
    const faults = installQueryFaults((_sql, database) => {
      if (database === undefined || !DISPOSABLE.test(database)) { return undefined; }
      calls += 1;
      // Call 1 is the fixture's own `SELECT current_database()` isolation guard,
      // call 2 is the first migration batch: failing at call 3 proves the cleanup
      // also covers a chain that already applied reviewed DDL.
      if (calls === 3) { return new Error('Injected mid-chain migration failure'); }
      return undefined;
    });
    try {
      await expect(createConfigurationFixture()).rejects.toThrow('Injected mid-chain migration failure');
    } finally {
      faults.restore();
    }
    expect(faults.created).toHaveLength(1);
    const created = faults.created[0];
    if (created === undefined || !DISPOSABLE.test(created)) { throw new Error(`Unexpected created database: ${String(created)}`); }
    const after = await databaseNames(maintenance);
    expect(after).not.toContain(created);
    expect(await sessionsOn(maintenance, created)).toBe(0);
    for (const name of before) { expect(after).toContain(name); }
  }, 120_000);

  it('reports a teardown failure together with the provisioning failure instead of hiding it', async () => {
    let migrationCalls = 0;
    let dropFailed = false;
    const faults = installQueryFaults((sql, database) => {
      if (/^\s*DROP\s+DATABASE\b/i.test(sql) && !dropFailed) {
        dropFailed = true;
        return new Error('Injected teardown failure');
      }
      if (dropFailed || database === undefined || !DISPOSABLE.test(database)) { return undefined; }
      migrationCalls += 1;
      if (migrationCalls === 3) { return new Error('Injected mid-chain migration failure'); }
      return undefined;
    });
    let failure: unknown;
    try {
      await createConfigurationFixture();
    } catch (error) {
      failure = error;
    } finally {
      faults.restore();
    }
    // Both failures reach the caller: the original provisioning error is not
    // replaced by the cleanup error, and the cleanup error is not swallowed.
    expect(failure).toBeInstanceOf(AggregateError);
    const errors: unknown[] = (failure as AggregateError).errors as unknown[];
    const messages = errors.map((error) => (error instanceof Error ? error.message : 'non-error')).join(' | ');
    expect(messages).toMatch(/Injected mid-chain migration failure/);
    expect(messages).toMatch(/Injected teardown failure/);
    expect(faults.dropped.length).toBeGreaterThanOrEqual(1);
    // The drop was refused, so this attempt's database survived on purpose. This
    // suite now removes its own artifact with a real, unpatched statement.
    const created = faults.created[0];
    if (created === undefined || !DISPOSABLE.test(created)) { throw new Error(`Unexpected created database: ${String(created)}`); }
    // Owner-aware drop: in lab mode the maintenance identity is a NOINHERIT
    // member, so the helper assumes the database owner role first.
    await dropOwnedTestDatabase(maintenance, created);
    expect(await databaseNames(maintenance)).not.toContain(created);
  }, 120_000);

  it('still provisions and drops normally when no fault is injected', async () => {
    const before = await persistentNames(maintenance);
    const fixture = await createConfigurationFixture();
    const database = fixture.database;
    expect(DISPOSABLE.test(database)).toBe(true);
    expect(await databaseNames(maintenance)).toContain(database);
    await fixture.close();
    const after = await databaseNames(maintenance);
    expect(after).not.toContain(database);
    expect(await sessionsOn(maintenance, database)).toBe(0);
    for (const name of before) { expect(after).toContain(name); }
  }, 300_000);

  it('shared owned-database helper drops its own database when the REVOKE/GRANT prepare block fails', async () => {
    const before = await persistentNames(maintenance);
    const name = `fixlevelup_configuration_test_${randomBytes(12).toString('hex')}`;
    const pattern = /^fixlevelup_configuration_test_[a-f0-9]{24}$/;
    let failure: unknown;
    try {
      await OwnedTestDatabase.create({
        name,
        pattern,
        prepare: async (client) => {
          // Same first-DDL failure shape as the proven leak: CREATE succeeded,
          // the privilege block fails.
          await client.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
          throw new Error('Injected prepare failure');
        },
      });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe('Injected prepare failure');
    const after = await databaseNames(maintenance);
    expect(after).not.toContain(name);
    expect(await sessionsOn(maintenance, name)).toBe(0);
    for (const existing of before) { expect(after).toContain(existing); }
  }, 60_000);

  it('shared owned-database helper surfaces a teardown failure instead of swallowing it', async () => {
    const name = `fixlevelup_configuration_test_${randomBytes(12).toString('hex')}`;
    const pattern = /^fixlevelup_configuration_test_[a-f0-9]{24}$/;
    let failure: unknown;
    const owned = await OwnedTestDatabase.create({ name, pattern });
    try {
      // A failed resource close must not skip the drop of this run's database.
      await owned.dispose(() => Promise.reject(new Error('Injected resource close failure')));
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toMatch(/Injected resource close failure/);
    expect(await databaseNames(maintenance)).not.toContain(name);
  }, 60_000);
});
