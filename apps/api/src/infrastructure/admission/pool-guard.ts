/**
 * Guarded runtime DB pool (docs/P05-PLAN.md §7, "Все потребители БД").
 *
 * Every runtime DB consumer routes its pg.Pool through `admittedPool`: a real
 * pool is created (no driver replacement), but every checkout — `connect()` or
 * a promise-style `query(...)` — first runs the admission gate's single-query
 * verification on the acquired connection. Per plan §7 the check happens for
 * каждое новое физическое соединение до любой бизнес-операции: pg creates
 * physical connections lazily at acquire time, so verify-on-acquire covers
 * every new connection. A failing verification releases the client with
 * `release(true)` (the connection is never reused) and surfaces only the typed
 * AdmissionRequiredError — driver errors and credentials never leak. A client
 * already checked out before the witness disappeared keeps working until it is
 * released (verify-on-acquire semantics); the next checkout fails closed.
 *
 * Prisma compatibility: the guard is a Proxy over the real pg.Pool instance
 * (`instanceof pg.Pool` keeps holding), so `PrismaPg(pool, ...)` accepts it and
 * uses the guarded `connect()`/`query()` paths unchanged.
 */
import { Pool } from 'pg';
import type { PoolClient, PoolConfig, QueryConfig, QueryResult, QueryResultRow } from 'pg';
import { AdmissionError } from './admission.js';
import type { AdmissionErrorCode, AdmissionGate } from './admission.js';

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
export function admittedPool(deps: { gate: AdmissionGate; now?: () => Date }, options: PoolConfig): GuardedPool {
  const now = deps.now ?? (() => new Date());
  const pool = new Pool(options);
  let resolveAdmitted: (() => void) | undefined;
  const admitted = new Promise<void>((resolve) => { resolveAdmitted = resolve; });
  const whenAdmitted = (): Promise<void> => admitted;

  const guardedConnect = async (): Promise<PoolClient> => {
    const client = await pool.connect();
    try {
      await deps.gate.verifyConnection(client, now());
      const resolve = resolveAdmitted;
      if (resolve) { resolveAdmitted = undefined; resolve(); }
      return client;
    } catch (error) {
      // Disconnect the unverified connection; it must never serve business work.
      client.release(true);
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
  return guarded as GuardedPool;
}
