/**
 * Test-only owned-database lifecycle (P05 preflight D6/D6b).
 *
 * One disposable PostgreSQL database per fixture run, with a single ownership
 * rule: the helper drops a database only when THIS run's `CREATE DATABASE`
 * succeeded (CREATE is the reuse guard, an existing name is a hard error) AND
 * the name still matches the caller's strict disposable pattern. The ownership
 * flag is consumed on the first dispose, so a double close never drops anything.
 *
 * Failure contract (the reason this helper exists):
 *  - a failure between the successful CREATE and the fixture's return (the first
 *    REVOKE/GRANT, a `.connect`, migration SQL, pinned history, bootstrap, app
 *    composition) must end this run's own connections and drop exactly the
 *    database this run created;
 *  - a teardown failure is never swallowed: `dispose` rethrows the single
 *    teardown error, and `failure` returns an `AggregateError` carrying BOTH the
 *    provisioning error and the teardown error.
 *
 * Maintenance connection policy: the maintenance connection only ever targets
 * the `postgres` control database and only executes CREATE/DROP/GRANT/REVOKE on
 * the disposable name. Dev mode uses the local `fixlevelup_dev` role on
 * `postgres`; synthetic (S4 lab) mode uses the attested
 * `loadP05LabTarget().openMaintenance()` binding from
 * `apps/api/tests/p05-lab-target.ts` (never duplicated here) and has NO dev
 * fallback, so a lab run either uses the attested lab identity or fails closed.
 * Because the lab orchestrator is a NOINHERIT MEMBER of the database owner, the
 * owner role is assumed explicitly (`SET ROLE fixlevelup_migrator`) before the
 * GRANT/REVOKE block and before DROP DATABASE; CREATE DATABASE itself only needs
 * CREATEDB.
 *
 * Test-only: `create` refuses to run unless the isolated-DB opt-in is set.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from 'pg';

const root = resolve(import.meta.dirname, '../../..');
const connection = { host: '127.0.0.1' as const, port: 55432 };
const SYNTHETIC_FLAG = 'FIXLEVELUP_SYNTHETIC_ORCHESTRATOR';
const DEV_ADMIN_ROLE = 'fixlevelup_dev';
/** The database OWNER in both modes: 022/023 DDL hard-requires this role name. */
const OWNER_ROLE = 'fixlevelup_migrator';
const HEX64 = /^[a-f0-9]{64}$/;
const DEV_POSTGRES_ENV = resolve(root, 'infra/dev-postgres/.env');
const TOOLING_ENV = resolve(root, 'packages/database-tooling/.env');

/** True only under the explicit lab opt-in; every other value keeps dev mode. */
export function syntheticLabMode(): boolean {
  return process.env[SYNTHETIC_FLAG] === '1';
}

function readSecret(file: string, name: string): string {
  const value = new RegExp(`^${name}=([a-f0-9]{64})$`, 'm').exec(readFileSync(file, 'utf8'))?.[1];
  if (value === undefined) { throw new Error(`Missing local test credential: ${name}`); }
  return value;
}

export interface FixtureCredentials {
  readonly migrator: string;
  readonly runtime: string;
}

/**
 * Runtime/migrator passwords for a fixture database.
 *
 * Lab mode reads ONLY the lab process env (`FIXLEVELUP_MIGRATOR_PASSWORD`,
 * `FIXLEVELUP_RUNTIME_PASSWORD`); a partially populated env fails closed instead
 * of silently falling back to the legacy dev `.env` files, so a lab run can never
 * be provisioned with dev credentials.
 */
export function fixtureCredentials(): FixtureCredentials {
  if (syntheticLabMode()) {
    const migrator = process.env['FIXLEVELUP_MIGRATOR_PASSWORD'] ?? '';
    const runtime = process.env['FIXLEVELUP_RUNTIME_PASSWORD'] ?? '';
    if (!HEX64.test(migrator) || !HEX64.test(runtime)) {
      throw new Error('Synthetic lab mode requires FIXLEVELUP_MIGRATOR_PASSWORD and FIXLEVELUP_RUNTIME_PASSWORD from the lab process env');
    }
    return { migrator, runtime };
  }
  return {
    migrator: readSecret(TOOLING_ENV, 'FIXLEVELUP_MIGRATOR_PASSWORD'),
    runtime: readSecret(TOOLING_ENV, 'FIXLEVELUP_RUNTIME_PASSWORD'),
  };
}

/** Opens one maintenance client on `postgres`; the caller always closes it. */
export type MaintenanceOpener = () => Promise<Client>;

function devMaintenance(): MaintenanceOpener {
  return async () => {
    const password = readSecret(DEV_POSTGRES_ENV, 'POSTGRES_PASSWORD');
    const client = new Client({ ...connection, database: 'postgres', user: DEV_ADMIN_ROLE, password });
    await client.connect();
    return client;
  };
}

/**
 * Maintenance opener for a fixture database.
 *
 * Lab mode uses the attested `loadP05LabTarget().openMaintenance()` (the single
 * lab binding/admission path, never duplicated here). Dev mode keeps the local
 * `fixlevelup_dev` role on `postgres`. There is no dev fallback under the
 * synthetic flag: a lab run either uses the attested lab identity or fails closed.
 */
export function maintenanceOpener(): MaintenanceOpener {
  if (!syntheticLabMode()) { return devMaintenance(); }
  return async () => {
    // Dynamic import: a dev run never loads the lab-only module graph.
    const { loadP05LabTarget } = await import('./p05-lab-target.js');
    return await loadP05LabTarget().openMaintenance();
  };
}

/**
 * The lab orchestrator is a NOINHERIT MEMBER of the database owner, so CREATE
 * DATABASE works but GRANT/REVOKE/DROP do not: those statements must run as the
 * actual owner. `SET ROLE` is only needed in lab mode; dev keeps its admin role.
 */
export async function becomeOwner(client: Client): Promise<void> {
  if (syntheticLabMode()) { await client.query(`SET ROLE ${OWNER_ROLE}`); }
}

/**
 * Drops back to the maintenance identity after a `becomeOwner` block, so a later
 * `CREATE DATABASE` still runs as the orchestrator (CREATEDB is the
 * orchestrator's privilege, not the owner's). No-op outside lab mode.
 */
export async function releaseOwner(client: Client): Promise<void> {
  if (syntheticLabMode()) { await client.query('RESET ROLE'); }
}

/** Every disposable fixture prefix the legacy suites are allowed to own. */
const FIXTURE_DATABASE = /^fixlevelup_(?:configuration|rbac|legal|auth_e2e|bootstrap|recovery|tg_auth|web_auth)_test_[a-f0-9]{24}$/;

/**
 * Drops one disposable fixture database through an existing maintenance client,
 * assuming the owner role where the mode requires it. Test-only helper for
 * suites that must clean up their own artifact outside a fixture object (e.g.
 * after an injected teardown failure). The strict disposable-name pattern is
 * re-checked here so this can never target a non-fixture database.
 */
export async function dropOwnedTestDatabase(client: Client, name: string): Promise<void> {
  if (!FIXTURE_DATABASE.test(name)) {
    throw new Error(`Refusing to drop a non-fixture database: ${name}`);
  }
  await becomeOwner(client);
  if (syntheticLabMode()) {
    const dispose = await pinFreshFileDatabase(client, name);
    await dispose(client);
  } else {
    await client.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  }
}

type MaintenanceSql = Pick<Client, 'query'>;
type FreshDatabaseDisposal = (operator: MaintenanceSql) => Promise<void>;

/** Call only after this run's successful CREATE. Ended pg pools may still
 * have a PostgreSQL backend exiting. Never signal those (or other) processes.
 * Close new connections, observe PG's real state, then use ordinary DROP.
 * Retain a busy database with an explicit failure; no FORCE fallback. */
export async function pinFreshFileDatabase(maintenance: MaintenanceSql, name: string): Promise<FreshDatabaseDisposal> {
  if (!FIXTURE_DATABASE.test(name) && !/^fixlevelup_(?:(?:file_restore|auth_readiness_test)_[a-f0-9]{24}|p019a_worker_[a-f0-9]{12})$/u.test(name)) {
    throw new Error('Unexpected fixture database');
  }
  const identity = 'SELECT oid::text AS oid FROM pg_database WHERE datname=$1 AND current_database()=\'postgres\' AND datdba=\'fixlevelup_migrator\'::regrole';
  const oid = (await maintenance.query<{ oid: string }>(identity, [name])).rows[0]?.oid;
  if (!oid || !/^[1-9][0-9]*$/u.test(oid)) { throw new Error('Missing freshly created database identity'); }
  return async (operator: MaintenanceSql): Promise<void> => {
    const verify = async () => {
      if ((await operator.query<{ oid: string }>(identity, [name])).rows[0]?.oid !== oid) {
        throw new Error('File fixture ownership changed; not dropping database');
      }
    };
    await verify();
    await operator.query(`ALTER DATABASE "${name}" ALLOW_CONNECTIONS false`);
    const deadline = performance.now() + 5_000;
    do {
      const result = await operator.query<{ ready: boolean }>(`SELECT NOT d.datallowconn AND
        NOT EXISTS (SELECT FROM pg_stat_activity WHERE datid=d.oid) AND
        NOT EXISTS (SELECT FROM pg_prepared_xacts WHERE database=d.datname) AS ready
        FROM pg_database d WHERE d.datname=$1 AND d.oid=$2::oid`, [name, oid]);
      if (result.rows[0]?.ready === true) {
        await verify();
        await operator.query(`DROP DATABASE "${name}"`);
        return;
      }
      await delay(25);
    } while (performance.now() < deadline);
    throw new Error('Owned file fixture still has a backend or prepared transaction; left closed');
  };
}

/** Rethrow one teardown error as-is, several as one AggregateError. */
function throwCollected(errors: readonly unknown[], message: string): void {
  if (errors.length === 1) { throw errors[0]; }
  if (errors.length > 1) { throw new AggregateError(errors, message); }
}

export interface OwnedTestDatabaseOptions {
  /** Exact disposable name this run intends to create. */
  readonly name: string;
  /** Strict allowlist pattern; a name outside it is refused before any CREATE. */
  readonly pattern: RegExp;
  /** Runs on the maintenance connection after CREATE (REVOKE/GRANT block). */
  readonly prepare?: (maintenance: Client) => Promise<void>;
  /** Synthetic-mode maintenance opener; defaults to the dev test role. */
  readonly openMaintenance?: MaintenanceOpener;
  /** File fixture: drop only a pinned, verified empty-of-backends DB, without FORCE. */
  readonly gracefulFileDrop?: true;
}

export class OwnedTestDatabase {
  private created: boolean;
  private closed = false;
  private gracefulDispose?: FreshDatabaseDisposal;

  private constructor(
    private readonly database: string,
    private readonly pattern: RegExp,
    private readonly openMaintenance: MaintenanceOpener,
    private readonly gracefulFileDrop: boolean,
  ) {
    this.created = false;
  }

  /**
   * Creates the disposable database and runs `prepare` on the same maintenance
   * connection. Any failure (including `prepare`) drops this run's database
   * before the error is rethrown, so a half-provisioned fixture never leaks it.
   */
  static async create(options: OwnedTestDatabaseOptions): Promise<OwnedTestDatabase> {
    if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') {
      throw new Error('Owned test database requires FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1');
    }
    if (!FIXTURE_DATABASE.test(options.name) || !options.pattern.test(options.name)) {
      throw new Error(`Refusing non-isolated test database: ${options.name}`);
    }
    const owned = new OwnedTestDatabase(options.name, options.pattern, options.openMaintenance ?? maintenanceOpener(),
      syntheticLabMode() || options.gracefulFileDrop === true);
    try {
      const maintenance = await owned.openMaintenance();
      try {
        await maintenance.query(`CREATE DATABASE "${options.name}" OWNER ${OWNER_ROLE} TEMPLATE template0`);
        owned.created = true;
        if (owned.gracefulFileDrop) { owned.gracefulDispose = await pinFreshFileDatabase(maintenance, options.name); }
        // CREATE DATABASE only needs CREATEDB, but REVOKE/GRANT on the new
        // database need the actual owner: in the lab the orchestrator is a
        // NOINHERIT MEMBER, so the owner privilege is assumed explicitly.
        await becomeOwner(maintenance);
        if (options.prepare !== undefined) { await options.prepare(maintenance); }
      } finally {
        // Closing the maintenance connection cannot leak a database: the owned
        // database is dropped by failure()/dispose() through a fresh connection.
        await maintenance.end().catch(() => undefined);
      }
      return owned;
    } catch (error) {
      throw await owned.failure(error);
    }
  }

  get name(): string {
    return this.database;
  }

  /** True while this run still owns a database that has not been dropped. */
  get owned(): boolean {
    return this.created;
  }

  /** Consumes the ownership flag; a second call returns undefined. */
  private take(): string | undefined {
    if (!this.created) { return undefined; }
    this.created = false;
    return this.pattern.test(this.database) ? this.database : undefined;
  }

  /**
   * Ends the caller's own resources first (pools, app, admission), then drops
   * exactly the database this run created. Idempotent. Never swallows: a failing
   * resource close and a failing DROP both reach the caller (AggregateError when
   * both fail).
   */
  async dispose(closeResources?: () => Promise<void>): Promise<void> {
    if (this.closed) { return; }
    this.closed = true;
    const ownedDatabase = this.take();
    const errors: unknown[] = [];
    if (closeResources !== undefined) {
      try { await closeResources(); } catch (error) { errors.push(error); }
    }
    if (ownedDatabase !== undefined) {
      try {
        const maintenance = await this.openMaintenance();
        try {
          // DROP DATABASE requires ownership: the lab orchestrator is only a
          // NOINHERIT MEMBER, so assume the owner role explicitly.
          await becomeOwner(maintenance);
          if (this.gracefulFileDrop) {
            if (!this.gracefulDispose) { throw new Error('Owned file fixture identity unconfirmed; not dropping database'); }
            await this.gracefulDispose(maintenance);
          } else {
            await maintenance.query(`DROP DATABASE IF EXISTS "${ownedDatabase}" WITH (FORCE)`);
          }
        } finally {
          try { await maintenance.end(); } catch (error) { errors.push(error); }
        }
      } catch (error) {
        errors.push(error);
      }
    }
    throwCollected(errors, 'Owned test database teardown failed');
  }

  /**
   * Provisioning failed: dispose (optionally closing the caller's own resources),
   * then return the error to throw. When cleanup also fails, both errors are
   * returned in one AggregateError instead of hiding the teardown failure.
   */
  async failure(failure: unknown, closeResources?: () => Promise<void>): Promise<Error> {
    try {
      await this.dispose(closeResources);
    } catch (teardownError) {
      return new AggregateError([failure, teardownError],
        'Test database provisioning failed and its teardown also failed');
    }
    return failure instanceof Error ? failure : new Error('Test database provisioning failed');
  }
}
