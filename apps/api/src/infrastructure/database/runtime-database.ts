import { Injectable } from '@nestjs/common';
import type { OnModuleDestroy } from '@nestjs/common';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../../generated/prisma/client.js';
import { ConfigurationError } from '../../runtime/config.js';
import { admittedPool } from '../admission/pool-guard.js';
import type { GuardedPool } from '../admission/pool-guard.js';
import type { ProcessAuthorization } from '../admission/process-admission.js';
import { LegacyReadinessProbes } from './legacy-readiness.js';
import { probeP05Layer } from './p05-profile-catalog.js';
import type { PoolClient } from 'pg';
import type { ConsumerKind } from '../admission/proof.js';

export interface DatabaseConfig {
  readonly host: '127.0.0.1';
  readonly port: number;
  readonly database: string;
  readonly user: 'fixlevelup_runtime';
  readonly password: string;
}

export function loadDatabaseConfig(env: NodeJS.ProcessEnv): DatabaseConfig {
  const fields: string[] = [];
  if (env['DB_HOST'] !== '127.0.0.1') { fields.push('DB_HOST'); }
  if (env['DB_PORT'] !== '55432') { fields.push('DB_PORT'); }
  if (env['DB_NAME'] !== 'fixlevelup_dev') { fields.push('DB_NAME'); }
  if (env['DB_USER'] !== 'fixlevelup_runtime') { fields.push('DB_USER'); }
  const password = env['DB_PASSWORD'] ?? '';
  if (password.length < 32 || password.length > 256 || /[\r\n\0]/.test(password)) { fields.push('DB_PASSWORD'); }
  if (fields.length) { throw new ConfigurationError(fields); }
  return Object.freeze({ host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_runtime', password });
}

export type { ReadinessRow } from './legacy-readiness.js';

@Injectable()
export class RuntimeDatabase implements OnModuleDestroy {
  private readonly pool: GuardedPool | undefined;
  private readonly client: PrismaClient | undefined;
  private readonly pending = new Map<string, Promise<boolean>>();
  private closing = false;

  constructor(private readonly config?: DatabaseConfig, private readonly authEnabled = false,
    authorization?: ProcessAuthorization, kind: ConsumerKind = 'API') {
    if (!config) { return; }
    if (!authorization) { throw new ConfigurationError(['LAUNCH_PROOF_TOKEN']); }
    this.pool = admittedPool({ authorization, kind }, config, { max: 2, connectionTimeoutMillis: 1000,
      query_timeout: 1000, statement_timeout: 1000, idleTimeoutMillis: 1000,
      options: '-c lock_timeout=1000', application_name: 'fixlevelup-api-runtime' });
    this.pool.on('error', () => { /* never log driver errors or credentials */ });
    this.client = new PrismaClient({ adapter: new PrismaPg(this.pool, {
      schema: 'foundation', disposeExternalPool: false,
      onPoolError: () => undefined, onConnectionError: () => undefined,
    }), log: [], errorFormat: 'minimal' });
  }

  private run(key: string, probe: (client: PoolClient) => Promise<boolean>): Promise<boolean> {
    const pool = this.pool;
    if (this.closing || !pool) { return Promise.resolve(false); }
    const existing = this.pending.get(key);
    if (existing) { return existing; }
    const pending = (async () => {
      const client = await pool.connect();
      try { return await probe(client) && !this.closing; }
      finally { client.release(); }
    })().catch(() => false).finally(() => { this.pending.delete(key); });
    this.pending.set(key, pending);
    return pending;
  }

  ready(): Promise<boolean> {
    const prisma = this.client;
    if (this.closing || !prisma) { return Promise.resolve(false); }
    const existing = this.pending.get('legacy');
    if (existing) { return existing; }
    // Real Prisma adapter consumer, using the guarded Pool on every query.
    // The pool verifies all legacy/P04 predicates before this round trip.
    const pending = prisma.$queryRaw<{ ready: boolean }[]>`
      SELECT current_database() = ${this.config?.database} AND current_user = 'fixlevelup_runtime' AS ready
    `
      .then((rows) => !this.closing && rows[0]?.ready === true)
      .catch(() => false).finally(() => { this.pending.delete('legacy'); });
    this.pending.set('legacy', pending);
    return pending;
  }

  settingsManagementReady(): Promise<boolean> {
    const config = this.config;
    return this.authEnabled && config ? this.run('management', (client) =>
      new LegacyReadinessProbes(client, config.database, true).settingsManagementReady()) : Promise.resolve(false);
  }

  catalogManagementReady(): Promise<boolean> {
    const config = this.config;
    return this.authEnabled && config ? this.run('catalog', (client) =>
      new LegacyReadinessProbes(client, config.database, true).catalogManagementReady()) : Promise.resolve(false);
  }

  private layer(layer: 'S1' | 'S2' | 'NO_S1' | 'NO_S2'): Promise<boolean> {
    return this.authEnabled ? this.run(layer, (client) => probeP05Layer(client, layer)) : Promise.resolve(false);
  }

  requestIntakeReady(): Promise<boolean> { return this.layer('S1'); }
  formSessionReady(): Promise<boolean> { return this.layer('S2'); }
  preIntakeProfileAbsent(): Promise<boolean> { return this.layer('NO_S1'); }
  formSessionProfileAbsent(): Promise<boolean> { return this.layer('NO_S2'); }

  async onModuleDestroy(): Promise<void> {
    this.closing = true;
    await Promise.all(this.pending.values());
    try { await this.client?.$disconnect(); }
    finally { await this.pool?.end(); }
  }
}
