/**
 * Minimal database surface for the internal P03-03 configuration ports.
 *
 * These ports are internal and transaction-scoped: a trusted caller (a later
 * P03-05/P05 command layer) passes the connected `PoolClient` it already runs
 * inside an explicit transaction. There is deliberately no NestJS provider, no
 * HTTP controller, no connection pool and no capability/auth decision here, so
 * this module can neither start a second transaction, commit the caller's work,
 * nor widen the runtime role. Every statement is bound-parameter SQL on that one
 * client.
 *
 * The type is exactly `query`, so `pg.PoolClient` satisfies it directly and the
 * ports cannot acquire a second connection. The caller-transaction requirement is
 * enforced at runtime by `assertCallerTransaction` (references/content) and
 * `acquireCompanySettingsLock` (company settings).
 */
import type { PoolClient } from 'pg';

export type ConfigurationClient = Pick<PoolClient, 'query'>;
