/**
 * Guarded runtime DB pool (docs/P05-PLAN.md §7, "Все потребители БД").
 *
 * Every runtime DB consumer routes its pg.Pool through `admittedPool`: a real
 * pool is created (no driver replacement), but every checkout — `connect()` or
 * a promise-style `query(...)` — first verifies the branded authorization,
 * witness, and exact physical profile on the acquired connection. A failing
 * verification on a connected backend destroys that connection and revokes the
 * admission across pools; a repaired target does not reactivate it. A unit of
 * work already checked out cannot be rolled back retroactively by this guard.
 *
 * Prisma compatibility: the guard is a Proxy over the real pg.Pool instance
 * (`instanceof pg.Pool` keeps holding), so `PrismaPg(pool, ...)` accepts it and
 * uses the guarded `connect()`/`query()` paths unchanged.
 */
import { Pool } from 'pg';
import type { PoolClient, PoolConfig, QueryConfig, QueryResult, QueryResultRow } from 'pg';
import { AdmissionError } from './admission.js';
import type { AdmissionErrorCode } from './admission.js';
import { requireAuthorizationKind } from './process-admission.js';
import type { ProcessAuthorization } from './process-admission.js';
import { matchesRuntimeTarget } from './runtime-admission.js';
import type { RuntimeAdmission } from './runtime-admission.js';
import type { ConsumerKind } from './proof.js';
import type { DatabaseConfig } from '../database/runtime-database.js';
import { verifyPhysicalProfile } from './physical-profile.js';

/** The subset of pg.Pool the application consumes (checked against usages). */
export interface PoolLike {
  readonly totalCount: number;
  readonly idleCount: number;
  readonly waitingCount: number;
  readonly expiredCount: number;
  connect(): Promise<PoolClient>;
  end(): Promise<void>;
  on(event: 'error', listener: (error: Error) => void): unknown;
  query<R extends QueryResultRow = QueryResultRow>(queryText: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
  query<R extends QueryResultRow = QueryResultRow>(config: QueryConfig<R>): Promise<QueryResult<R>>;
}

/** Typed fail-closed signal for a denied pool checkout; never carries driver details. */
export class AdmissionRequiredError extends Error {
  readonly code = 'ADMISSION_REQUIRED';
  /** The gate's typed rejection code this denial wraps, when one was produced. */
  readonly reason: AdmissionErrorCode | undefined;

  constructor(reason?: AdmissionErrorCode) {
    super(reason === undefined ? 'Database admission required' : `Database admission required (${reason})`);
    this.name = 'AdmissionRequiredError';
    this.reason = reason;
  }
}

/** A real pg.Pool whose checkouts are admitted by the gate; satisfies PoolLike. */
export type GuardedPool = Pool & { readonly whenAdmitted: () => Promise<void> };

/**
 * Creates the real pool described by `options` and returns it wrapped so that
 * every checkout verifies admission first. `whenAdmitted()` resolves after the
 * first successful verification and never rejects; resources that own periodic
 * DB work (the web-auth cleanup timer) use it to guarantee no tick can issue
 * DB work before the gate has verified a connection. All other pool members —
 * including the `error` event wiring — forward to the underlying pool.
 */
const revoked = new WeakSet<RuntimeAdmission>();
const poolAdmissions = new WeakMap<object, () => RuntimeAdmission>();

/** A structural query port alone is not a completed S2 launch. */
export function requireFormSessionPool(pool: object): 'S2' | 'S3' {
  const binding = poolAdmissions.get(pool)?.().binding;
  if (!binding || (binding.profile !== 'S2' && binding.profile !== 'S3')
    || (binding.expected.consumerKind !== 'API' && binding.expected.consumerKind !== 'TEST')) {
    throw new AdmissionRequiredError();
  }
  return binding.profile;
}

export function requireRequestEffectsPool(pool: object): void {
  if (requireFormSessionPool(pool) !== 'S3') { throw new AdmissionRequiredError(); }
}

export function requireRuntimeAuthorization(authorization: ProcessAuthorization, kind: ConsumerKind, target: DatabaseConfig): RuntimeAdmission {
  const admission = requireAuthorizationKind(authorization, kind);
  if (revoked.has(admission) || !matchesRuntimeTarget(admission, target)) { throw new AdmissionRequiredError(); }
  return admission;
}

type PoolTuning = Pick<PoolConfig, 'max' | 'connectionTimeoutMillis' | 'query_timeout' | 'statement_timeout'
  | 'idleTimeoutMillis' | 'options' | 'application_name'>;

export function admittedPool(deps: { authorization: ProcessAuthorization; kind: ConsumerKind }, target: DatabaseConfig,
  tuning: PoolTuning): GuardedPool {
  const config = Object.freeze({ host: target.host, port: target.port, database: target.database,
    user: target.user, password: target.password });
  const admission = requireRuntimeAuthorization(deps.authorization, deps.kind, config);
  const pool = new Pool({ ...tuning, ...config });
  let resolveAdmitted: (() => void) | undefined;
  const admitted = new Promise<void>((resolve) => { resolveAdmitted = resolve; });
  const whenAdmitted = (): Promise<void> => admitted;

  const guardedConnect = async (): Promise<PoolClient> => {
    if (revoked.has(admission)) { throw new AdmissionRequiredError(); }
    let client: PoolClient | undefined;
    try {
      client = await pool.connect();
      if (requireRuntimeAuthorization(deps.authorization, deps.kind, config) !== admission) {
        throw new AdmissionRequiredError();
      }
      await admission.gate.verifyConnection(client, new Date());
      if (!await verifyPhysicalProfile(client, config, admission.binding.profile)) { throw new AdmissionRequiredError(); }
      await admission.gate.verifyConnection(client, new Date());
      if (requireRuntimeAuthorization(deps.authorization, deps.kind, config) !== admission) {
        throw new AdmissionRequiredError();
      }
      const resolve = resolveAdmitted;
      if (resolve) { resolveAdmitted = undefined; resolve(); }
      return client;
    } catch (error) {
      // Disconnect the unverified connection; it must never serve business work.
      // Acquisition failures deny this attempt; evidence from a connected
      // backend revokes this authorization across all its runtime consumers.
      if (client) { revoked.add(admission); client.release(true); }
      throw error instanceof AdmissionError
        ? new AdmissionRequiredError(error.code)
        : new AdmissionRequiredError();
    }
  };

  const guardedQuery = async (
    textOrConfig: string | QueryConfig<QueryResultRow>,
    values?: readonly unknown[],
  ): Promise<QueryResult<QueryResultRow>> => {
    const client = await guardedConnect();
    try {
      if (typeof textOrConfig === 'string') {
        return await client.query<QueryResultRow>(textOrConfig, values === undefined ? undefined : [...values]);
      }
      return await client.query<QueryResultRow>(textOrConfig);
    } finally {
      client.release();
    }
  };

  const guarded = new Proxy(pool, {
    get(target, property) {
      if (property === 'whenAdmitted') { return whenAdmitted; }
      if (property === 'connect') { return guardedConnect; }
      if (property === 'query') { return guardedQuery; }
      const value: unknown = Reflect.get(target, property, target);
      if (typeof value === 'function') {
        const bound = value.bind(target) as unknown as (...args: unknown[]) => unknown;
        return bound;
      }
      return value;
    },
  });
  poolAdmissions.set(guarded, () => requireRuntimeAuthorization(deps.authorization, deps.kind, config));
  return guarded as GuardedPool;
}
