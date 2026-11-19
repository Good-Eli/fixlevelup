import { Injectable } from '@nestjs/common';
import type { OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../../generated/prisma/client.js';
import { ConfigurationError } from '../../runtime/config.js';

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

export interface ReadinessRow {
  database: string;
  role: string;
  safe_role: boolean;
  safe_schema: boolean;
  columns: { table: string; column: string; type: string; not_null: boolean }[];
  constraints: { table: string; name: string; kind: string; validated: boolean; definition: string }[];
  indexes: { table: string; name: string; valid: boolean; unique: boolean; definition: string }[];
}

const expectedColumns = {
  audit_logs: { id: 'uuid', operation: 'varchar', correlation_id: 'uuid', occurred_at: 'timestamptz', details: 'jsonb' },
  outbox_events: { id: 'uuid', event_id: 'uuid', event_type: 'varchar', created_at: 'timestamptz', status: 'varchar', payload: 'jsonb', attempt_count: 'int4' },
};
const expectedConstraints = [
  ['audit_logs', 'audit_logs_pkey', 'p', 'PRIMARY KEY (id)'],
  ['audit_logs', 'audit_logs_operation_check', 'c', 'CHECK ((length((operation)::text) > 0))'],
  ['outbox_events', 'outbox_events_pkey', 'p', 'PRIMARY KEY (id)'],
  ['outbox_events', 'outbox_events_status_check', 'c', "CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'EXPANDED'::character varying, 'FAILED'::character varying])::text[])))"],
  ['outbox_events', 'outbox_events_type_check', 'c', 'CHECK ((length((event_type)::text) > 0))'],
  ['outbox_events', 'outbox_events_attempt_count_check', 'c', 'CHECK ((attempt_count >= 0))'],
];

@Injectable()
export class RuntimeDatabase implements OnModuleDestroy {
  private readonly pool: Pool | undefined;
  private readonly client: PrismaClient | undefined;
  private pending: Promise<boolean> | undefined;
  private closing = false;

  constructor(private readonly config?: DatabaseConfig) {
    if (!config) { return; }
    this.pool = new Pool({ ...config, max: 2, connectionTimeoutMillis: 1000,
      query_timeout: 1000, statement_timeout: 1000, idleTimeoutMillis: 1000,
      options: '-c lock_timeout=1000',
      application_name: 'fixlevelup-api-runtime' });
    this.pool.on('error', () => { /* never log driver errors or credentials */ });
    this.client = new PrismaClient({ adapter: new PrismaPg(this.pool, {
      schema: 'foundation', disposeExternalPool: false,
      onPoolError: () => undefined, onConnectionError: () => undefined,
    }), log: [], errorFormat: 'minimal' });
  }

  ready(): Promise<boolean> {
    if (this.closing || !this.client || !this.config) { return Promise.resolve(false); }
    // Concurrent health requests share one bounded probe, never fill a queue.
    this.pending ??= this.probe().catch(() => false).finally(() => { this.pending = undefined; });
    return this.pending;
  }

  private async probe(): Promise<boolean> {
    if (!this.client || !this.config) { return false; }
    const rows = await this.client.$queryRaw<ReadinessRow[]>`
      SELECT current_database() AS database, current_user AS role,
        (SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)
          AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid)
          FROM pg_roles r WHERE rolname=current_user) AS safe_role,
        (EXISTS(SELECT 1 FROM pg_namespace n WHERE nspname='foundation' AND nspowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user))
          AND NOT has_database_privilege(current_user,current_database(),'CREATE')
          AND NOT has_database_privilege(current_user,current_database(),'TEMP')
          AND has_schema_privilege(current_user,'foundation','USAGE')
          AND NOT has_schema_privilege(current_user,'foundation','CREATE')
          AND has_table_privilege(current_user,'foundation.audit_logs','SELECT')
          AND has_table_privilege(current_user,'foundation.audit_logs','INSERT')
          AND NOT has_table_privilege(current_user,'foundation.audit_logs','UPDATE,DELETE,TRUNCATE')
          AND NOT has_any_column_privilege(current_user,'foundation.audit_logs','UPDATE')
          AND has_table_privilege(current_user,'foundation.outbox_events','SELECT')
          AND has_table_privilege(current_user,'foundation.outbox_events','INSERT')
          AND NOT has_table_privilege(current_user,'foundation.outbox_events','DELETE,TRUNCATE')
          AND NOT has_table_privilege(current_user,'foundation._prisma_migrations','SELECT')
          AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='foundation' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))) AS safe_schema,
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,'column',a.attname,'type',t.typname,'not_null',a.attnotnull))
          FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          JOIN pg_type t ON t.oid=a.atttypid WHERE n.nspname='foundation' AND c.relname IN ('audit_logs','outbox_events')
          AND a.attnum>0 AND NOT a.attisdropped),'[]'::json) AS columns,
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,'name',k.conname,'kind',k.contype,'validated',k.convalidated,'definition',pg_get_constraintdef(k.oid)))
          FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='foundation'),'[]'::json) AS constraints,
        COALESCE((SELECT json_agg(json_build_object('table',t.relname,'name',c.relname,'valid',i.indisvalid,'unique',i.indisunique,'definition',pg_get_indexdef(i.indexrelid)))
          FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='foundation'),'[]'::json) AS indexes
    `;
      const row = rows[0];
      if (!row || this.closing || row.database !== this.config.database || row.role !== 'fixlevelup_runtime'
        || !row.safe_role || !row.safe_schema) { return false; }
      for (const [table, columns] of Object.entries(expectedColumns)) {
        for (const [column, type] of Object.entries(columns)) {
          if (!row.columns.some((entry) => entry.table === table && entry.column === column && entry.type === type && entry.not_null)) { return false; }
        }
      }
      if (!expectedConstraints.every(([table, name, kind, definition]) => row.constraints.some((entry) =>
        entry.table === table && entry.name === name && entry.kind === kind && entry.validated && entry.definition === definition))) { return false; }
      return row.indexes.some((entry) => entry.table === 'outbox_events' && entry.name === 'outbox_events_event_id_key' && entry.valid && entry.unique
        && entry.definition === 'CREATE UNIQUE INDEX outbox_events_event_id_key ON foundation.outbox_events USING btree (event_id)')
        && row.indexes.some((entry) => entry.table === 'outbox_events' && entry.name === 'outbox_events_queue_idx' && entry.valid && !entry.unique
          && entry.definition === 'CREATE INDEX outbox_events_queue_idx ON foundation.outbox_events USING btree (status, created_at)');
  }

  async onModuleDestroy(): Promise<void> {
    this.closing = true;
    await this.pending;
    try { await this.client?.$disconnect(); }
    finally { await this.pool?.end(); }
  }
}
