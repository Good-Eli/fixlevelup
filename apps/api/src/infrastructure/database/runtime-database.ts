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
  columns: { table: string; column: string; type: string; not_null: boolean; type_modifier: number }[];
  constraints: { table: string; name: string; kind: string; validated: boolean; definition: string }[];
  indexes: { table: string; name: string; valid: boolean; unique: boolean; definition: string }[];
}

const expectedColumns = {
  audit_logs: { id: 'uuid', operation: 'varchar', correlation_id: 'uuid', occurred_at: 'timestamptz', details: 'jsonb' },
  outbox_events: {
    id: 'uuid', event_id: 'uuid', event_type: 'varchar', created_at: 'timestamptz', status: 'varchar', payload: 'jsonb', attempt_count: 'int4',
    lease_owner: 'uuid', lease_generation: 'int8', lease_expires_at: 'timestamptz', next_attempt_at: 'timestamptz', last_error_code: 'varchar',
  },
};
const nullableOutboxColumns = new Set(['lease_owner', 'lease_expires_at', 'last_error_code']);
const expectedOutboxTypeModifiers: Readonly<Record<string, number>> = { lease_expires_at: 6, next_attempt_at: 6, last_error_code: 36 };
const expectedConstraints = [
  ['audit_logs', 'audit_logs_pkey', 'p', 'PRIMARY KEY (id)'],
  ['audit_logs', 'audit_logs_operation_check', 'c', 'CHECK ((length((operation)::text) > 0))'],
  ['outbox_events', 'outbox_events_pkey', 'p', 'PRIMARY KEY (id)'],
  ['outbox_events', 'outbox_events_status_check', 'c', "CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'EXPANDED'::character varying, 'FAILED'::character varying])::text[])))"],
  ['outbox_events', 'outbox_events_type_check', 'c', 'CHECK ((length((event_type)::text) > 0))'],
  ['outbox_events', 'outbox_events_attempt_count_check', 'c', 'CHECK ((attempt_count >= 0))'],
  ['outbox_events', 'outbox_events_lease_generation_check', 'c', 'CHECK ((lease_generation >= 0))'],
  ['outbox_events', 'outbox_events_lease_pair_check', 'c', 'CHECK (((lease_owner IS NULL) = (lease_expires_at IS NULL)))'],
  ['outbox_events', 'outbox_events_lease_pending_check', 'c', "CHECK (((lease_owner IS NULL) OR ((status)::text = 'PENDING'::text)))"],
  ['outbox_events', 'outbox_events_last_error_code_check', 'c', "CHECK (((last_error_code)::text = ANY ((ARRAY['HANDLER_FAILED'::character varying, 'ATTEMPTS_EXHAUSTED'::character varying])::text[])))"],
];

@Injectable()
export class RuntimeDatabase implements OnModuleDestroy {
  private readonly pool: Pool | undefined;
  private readonly client: PrismaClient | undefined;
  private pending: Promise<boolean> | undefined;
  private closing = false;

  constructor(private readonly config?: DatabaseConfig, private readonly authEnabled = false) {
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
          AND NOT has_table_privilege(current_user,'foundation.outbox_events','UPDATE,DELETE,TRUNCATE')
          AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['status','attempt_count','lease_owner','lease_generation','lease_expires_at','next_attempt_at','last_error_code']) AS worker(column_name)
            WHERE NOT has_column_privilege(current_user,'foundation.outbox_events',worker.column_name,'UPDATE'))
          AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='foundation.outbox_events'::regclass
            AND a.attnum>0 AND NOT a.attisdropped
            AND a.attname NOT IN ('status','attempt_count','lease_owner','lease_generation','lease_expires_at','next_attempt_at','last_error_code')
            AND has_column_privilege(current_user,'foundation.outbox_events',a.attname,'UPDATE'))
          AND NOT has_table_privilege(current_user,'foundation._prisma_migrations','SELECT')
          AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='foundation' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))) AS safe_schema,
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,'column',a.attname,'type',t.typname,'not_null',a.attnotnull,'type_modifier',a.atttypmod))
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
          const notNull = table !== 'outbox_events' || !nullableOutboxColumns.has(column);
          const typeModifier = table === 'outbox_events' ? expectedOutboxTypeModifiers[column] : undefined;
          if (!row.columns.some((entry) => entry.table === table && entry.column === column && entry.type === type
            && entry.not_null === notNull && (typeModifier === undefined || entry.type_modifier === typeModifier))) { return false; }
        }
      }
      if (!expectedConstraints.every(([table, name, kind, definition]) => row.constraints.some((entry) =>
        entry.table === table && entry.name === name && entry.kind === kind && entry.validated && entry.definition === definition))) { return false; }
      const foundationReady = row.indexes.some((entry) => entry.table === 'outbox_events' && entry.name === 'outbox_events_event_id_key' && entry.valid && entry.unique
        && entry.definition === 'CREATE UNIQUE INDEX outbox_events_event_id_key ON foundation.outbox_events USING btree (event_id)')
        && row.indexes.some((entry) => entry.table === 'outbox_events' && entry.name === 'outbox_events_queue_idx' && entry.valid && !entry.unique
          && entry.definition === 'CREATE INDEX outbox_events_queue_idx ON foundation.outbox_events USING btree (status, created_at)')
        && row.indexes.some((entry) => entry.table === 'outbox_events' && entry.name === 'outbox_events_due_idx' && entry.valid && !entry.unique
          && entry.definition === 'CREATE INDEX outbox_events_due_idx ON foundation.outbox_events USING btree (status, next_attempt_at, created_at, id)');
      return foundationReady && (!this.authEnabled || await this.authReady());
  }

  private async authReady(): Promise<boolean> {
    if (!this.client) { return false; }
    // Catalog checks require no additional runtime table privileges. Missing objects, grants,
    // or incompatible schemas must fail closed without exposing driver errors.
    const rows = await this.client.$queryRaw<{ ready: boolean }[]>`
      WITH expected_columns(table_name, column_name, type_name, not_null, modifier) AS (VALUES
        ('staff','id','uuid',true,-1), ('staff','role','varchar',true,20),
        ('staff','employment_state','varchar',true,20), ('staff','auth_version','int4',true,-1),
        ('staff_web_credentials','staff_id','uuid',true,-1), ('staff_web_credentials','login','varchar',true,259),
        ('staff_web_credentials','password_hash','varchar',true,259),
        ('staff_bootstrap_marker','id','int2',true,-1), ('staff_bootstrap_marker','staff_id','uuid',true,-1),
        ('web_sessions','id','uuid',true,-1), ('web_sessions','staff_id','uuid',true,-1),
        ('web_sessions','token_hash','varchar',true,68), ('web_sessions','auth_version','int4',true,-1),
        ('web_sessions','created_at','timestamptz',true,6), ('web_sessions','idle_expires_at','timestamptz',true,6),
        ('web_sessions','absolute_expires_at','timestamptz',true,6), ('web_sessions','revoked_at','timestamptz',false,6),
        ('web_auth_throttles','key_hash','varchar',true,68),
        ('web_auth_attempts','id','uuid',true,-1), ('web_auth_attempts','key_hash','varchar',true,68),
        ('web_auth_attempts','reserved_at','timestamptz',true,6), ('web_auth_attempts','expires_at','timestamptz',true,6),
        ('web_auth_attempts','failed_at','timestamptz',false,6), ('web_auth_attempts','completed_at','timestamptz',false,6),
        ('user_permissions','id','uuid',true,-1), ('user_permissions','staff_id','uuid',true,-1),
        ('user_permissions','capability','varchar',true,68), ('user_permissions','scope','varchar',true,20),
        ('user_permissions','valid_from','timestamptz',true,6), ('user_permissions','valid_until','timestamptz',false,6),
        ('user_permissions','revoked_at','timestamptz',false,6), ('user_permissions','granted_by','uuid',false,-1),
        ('user_permissions','created_at','timestamptz',true,6),
        ('staff_telegram_links','id','uuid',true,-1), ('staff_telegram_links','staff_id','uuid',true,-1),
        ('staff_telegram_links','telegram_user_id','int8',true,-1),
        ('staff_telegram_links','username','varchar',false,68), ('staff_telegram_links','linked_by','uuid',false,-1),
        ('staff_telegram_links','created_at','timestamptz',true,6), ('staff_telegram_links','revoked_at','timestamptz',false,6),
        ('web_sessions','channel','varchar',true,20), ('web_sessions','initdata_digest','varchar',false,68),
        ('web_sessions','initdata_exchanged_at','timestamptz',false,6), ('web_sessions','telegram_link_id','uuid',false,-1),
        ('staff','display_name','varchar',false,84), ('staff','profile_version','int4',true,-1),
        ('permissions','code','varchar',true,68), ('permissions','module','varchar',true,36), ('permissions','description','varchar',true,504),
        ('permissions','protected','bool',true,-1), ('permissions','active','bool',true,-1),
        ('roles','id','uuid',true,-1), ('roles','code','varchar',true,68), ('roles','name','varchar',true,84),
        ('roles','description','varchar',true,504), ('roles','role_type','varchar',true,20), ('roles','status','varchar',true,20),
        ('roles','version','int4',true,-1), ('roles','created_at','timestamptz',true,6), ('roles','updated_at','timestamptz',true,6),
        ('roles','created_by','uuid',false,-1), ('roles','updated_by','uuid',false,-1),
        ('role_permissions','role_id','uuid',true,-1), ('role_permissions','permission_code','varchar',true,68),
        ('role_permissions','scope_type','varchar',true,20), ('role_permissions','enabled','bool',true,-1),
        ('staff_role_assignments','id','uuid',true,-1), ('staff_role_assignments','staff_id','uuid',true,-1),
        ('staff_role_assignments','role_id','uuid',true,-1), ('staff_role_assignments','assigned_at','timestamptz',true,6),
        ('staff_role_assignments','assigned_by','uuid',false,-1), ('staff_role_assignments','revoked_at','timestamptz',false,6),
        ('staff_role_assignments','revoked_by','uuid',false,-1)
      ), required_privileges(table_name, column_name, privilege) AS (VALUES
        ('staff','id','SELECT'), ('staff','role','SELECT'), ('staff','employment_state','SELECT'), ('staff','auth_version','SELECT'), ('staff','auth_version','UPDATE'),
        ('staff','id','INSERT'), ('staff','role','INSERT'), ('staff','employment_state','INSERT'), ('staff','auth_version','INSERT'),
        ('staff_web_credentials','staff_id','SELECT'), ('staff_web_credentials','login','SELECT'), ('staff_web_credentials','password_hash','SELECT'), ('staff_web_credentials','password_hash','UPDATE'),
        ('web_sessions','id','SELECT'), ('web_sessions','staff_id','SELECT'), ('web_sessions','token_hash','SELECT'), ('web_sessions','auth_version','SELECT'), ('web_sessions','created_at','SELECT'), ('web_sessions','idle_expires_at','SELECT'), ('web_sessions','absolute_expires_at','SELECT'), ('web_sessions','revoked_at','SELECT'),
        ('web_sessions','id','INSERT'), ('web_sessions','staff_id','INSERT'), ('web_sessions','token_hash','INSERT'), ('web_sessions','auth_version','INSERT'), ('web_sessions','created_at','INSERT'), ('web_sessions','idle_expires_at','INSERT'), ('web_sessions','absolute_expires_at','INSERT'), ('web_sessions','revoked_at','INSERT'),
        ('web_sessions','token_hash','UPDATE'), ('web_sessions','auth_version','UPDATE'), ('web_sessions','idle_expires_at','UPDATE'), ('web_sessions','revoked_at','UPDATE'),
        ('web_auth_throttles','key_hash','SELECT'), ('web_auth_throttles','key_hash','INSERT'), ('web_auth_throttles','key_hash','UPDATE'),
        ('web_auth_attempts','id','SELECT'), ('web_auth_attempts','key_hash','SELECT'), ('web_auth_attempts','reserved_at','SELECT'), ('web_auth_attempts','expires_at','SELECT'), ('web_auth_attempts','failed_at','SELECT'), ('web_auth_attempts','completed_at','SELECT'),
        ('web_auth_attempts','id','INSERT'), ('web_auth_attempts','key_hash','INSERT'), ('web_auth_attempts','reserved_at','INSERT'), ('web_auth_attempts','expires_at','INSERT'), ('web_auth_attempts','failed_at','INSERT'), ('web_auth_attempts','completed_at','INSERT'),
        ('web_auth_attempts','expires_at','UPDATE'), ('web_auth_attempts','failed_at','UPDATE'), ('web_auth_attempts','completed_at','UPDATE'),
        ('staff','display_name','SELECT'), ('staff','profile_version','SELECT'), ('staff','display_name','INSERT'),
        ('staff','display_name','UPDATE'), ('staff','role','UPDATE'), ('staff','profile_version','UPDATE'),
        ('staff','employment_state','UPDATE'),
        ('staff_telegram_links','id','SELECT'), ('staff_telegram_links','staff_id','SELECT'),
        ('staff_telegram_links','telegram_user_id','SELECT'), ('staff_telegram_links','username','SELECT'),
        ('staff_telegram_links','linked_by','SELECT'), ('staff_telegram_links','created_at','SELECT'),
        ('staff_telegram_links','revoked_at','SELECT'),
        ('staff_telegram_links','revoked_at','UPDATE'), ('staff_telegram_links','username','UPDATE'),
        ('web_sessions','channel','SELECT'), ('web_sessions','initdata_digest','SELECT'),
        ('web_sessions','initdata_exchanged_at','SELECT'), ('web_sessions','telegram_link_id','SELECT'),
        ('web_sessions','channel','INSERT'), ('web_sessions','initdata_digest','INSERT'),
        ('web_sessions','initdata_exchanged_at','INSERT'), ('web_sessions','telegram_link_id','INSERT'),
        ('roles','id','INSERT'), ('roles','code','INSERT'), ('roles','name','INSERT'), ('roles','description','INSERT'), ('roles','created_by','INSERT'), ('roles','updated_by','INSERT'),
        ('roles','name','UPDATE'), ('roles','description','UPDATE'), ('roles','status','UPDATE'), ('roles','version','UPDATE'), ('roles','updated_at','UPDATE'), ('roles','updated_by','UPDATE'),
        ('role_permissions','role_id','INSERT'), ('role_permissions','permission_code','INSERT'), ('role_permissions','enabled','INSERT'), ('role_permissions','scope_type','INSERT'),
        ('role_permissions','enabled','UPDATE'),
        ('staff_role_assignments','id','INSERT'), ('staff_role_assignments','staff_id','INSERT'), ('staff_role_assignments','role_id','INSERT'), ('staff_role_assignments','assigned_by','INSERT'),
        ('staff_role_assignments','revoked_at','UPDATE'), ('staff_role_assignments','revoked_by','UPDATE')
        UNION ALL SELECT table_name, column_name, 'SELECT' FROM expected_columns
          WHERE table_name IN ('roles','permissions','role_permissions','staff_role_assignments')
      ), expected_constraints(table_name, name, kind) AS (VALUES
        ('staff_web_credentials','staff_web_credentials_supported_check','c'),
        ('permissions','permissions_pkey','p'), ('permissions','permissions_metadata_check','c'), ('permissions','permissions_protected_active_check','c'),
        ('roles','roles_pkey','p'), ('roles','roles_identity_check','c'), ('roles','roles_metadata_check','c'),
        ('role_permissions','role_permissions_pkey','p'), ('role_permissions','role_permissions_role_id_fkey','f'),
        ('role_permissions','role_permissions_permission_code_fkey','f'), ('role_permissions','role_permissions_scope_check','c'),
        ('staff_role_assignments','staff_role_assignments_pkey','p'), ('staff_role_assignments','staff_role_assignments_staff_id_fkey','f'),
        ('staff_role_assignments','staff_role_assignments_role_id_fkey','f'), ('staff_role_assignments','staff_role_assignments_assigned_by_fkey','f'),
        ('staff_role_assignments','staff_role_assignments_revoked_by_fkey','f'), ('staff_role_assignments','staff_role_assignments_period_check','c'),
        ('staff_role_assignments','staff_role_assignments_actor_check','c'), ('staff','staff_display_name_check','c'), ('staff','staff_profile_version_check','c'),
        ('staff','staff_pkey','p'), ('staff','staff_role_check','c'), ('staff','staff_employment_state_check','c'), ('staff','staff_auth_version_check','c'),
        ('staff_web_credentials','staff_web_credentials_pkey','p'), ('staff_web_credentials','staff_web_credentials_staff_id_fkey','f'), ('staff_web_credentials','staff_web_credentials_login_check','c'), ('staff_web_credentials','staff_web_credentials_password_hash_check','c'),
        ('staff_bootstrap_marker','staff_bootstrap_marker_pkey','p'), ('staff_bootstrap_marker','staff_bootstrap_marker_singleton_check','c'), ('staff_bootstrap_marker','staff_bootstrap_marker_staff_id_fkey','f'),
        ('web_sessions','web_sessions_pkey','p'), ('web_sessions','web_sessions_staff_id_fkey','f'), ('web_sessions','web_sessions_token_hash_check','c'), ('web_sessions','web_sessions_auth_version_check','c'), ('web_sessions','web_sessions_expiry_check','c'), ('web_sessions','web_sessions_revoked_at_check','c'),
        ('web_auth_throttles','web_auth_throttles_pkey','p'), ('web_auth_throttles','web_auth_throttles_key_hash_check','c'),
        ('web_auth_attempts','web_auth_attempts_pkey','p'), ('web_auth_attempts','web_auth_attempts_key_hash_fkey','f'), ('web_auth_attempts','web_auth_attempts_expiry_check','c'), ('web_auth_attempts','web_auth_attempts_completion_check','c'),
        ('user_permissions','user_permissions_pkey','p'), ('user_permissions','user_permissions_staff_id_fkey','f'), ('user_permissions','user_permissions_granted_by_fkey','f'),
        ('user_permissions','user_permissions_capability_check','c'), ('user_permissions','user_permissions_scope_check','c'), ('user_permissions','user_permissions_validity_check','c'), ('user_permissions','user_permissions_revoked_at_check','c'),
        ('staff_telegram_links','staff_telegram_links_pkey','p'), ('staff_telegram_links','staff_telegram_links_staff_id_fkey','f'), ('staff_telegram_links','staff_telegram_links_linked_by_fkey','f'),
        ('staff_telegram_links','staff_telegram_links_telegram_user_id_check','c'), ('staff_telegram_links','staff_telegram_links_username_check','c'), ('staff_telegram_links','staff_telegram_links_revoked_at_check','c'),
        ('web_sessions','web_sessions_channel_check','c'), ('web_sessions','web_sessions_initdata_digest_check','c'), ('web_sessions','web_sessions_channel_pair_check','c'),
        ('web_sessions','web_sessions_initdata_exchanged_at_check','c'), ('web_sessions','web_sessions_telegram_link_id_fkey','f')
      ), expected_indexes(table_name, name, unique_index, columns) AS (VALUES
        ('staff_web_credentials','staff_web_credentials_login_key',true,'login'), ('staff_bootstrap_marker','staff_bootstrap_marker_staff_id_key',true,'staff_id'),
        ('web_sessions','web_sessions_token_hash_key',true,'token_hash'), ('web_sessions','web_sessions_staff_id_idx',false,'staff_id'), ('web_sessions','web_sessions_absolute_expiry_idx',false,'absolute_expires_at'),
        ('web_auth_attempts','web_auth_attempts_key_expiry_idx',false,'key_hash, expires_at'), ('web_auth_attempts','web_auth_attempts_expiry_idx',false,'expires_at'),
        ('user_permissions','user_permissions_staff_id_idx',false,'staff_id'),
        ('staff_telegram_links','staff_telegram_links_staff_id_idx',false,'staff_id'),
        ('roles','roles_code_key',true,'code'), ('staff_role_assignments','staff_role_assignments_role_staff_idx',false,'role_id, staff_id')
      )
      SELECT
        NOT EXISTS (SELECT 1 FROM expected_columns e WHERE NOT EXISTS (
          SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_type t ON t.oid=a.atttypid
          WHERE n.nspname='foundation' AND c.relname=e.table_name AND c.relkind='r' AND a.attname=e.column_name AND a.attnum>0 AND NOT a.attisdropped
            AND t.typname=e.type_name AND a.attnotnull=e.not_null AND a.atttypmod=e.modifier))
        AND NOT EXISTS (SELECT 1 FROM required_privileges e WHERE NOT has_column_privilege(current_user, format('foundation.%I',e.table_name), e.column_name,e.privilege))
        AND NOT EXISTS (SELECT 1 FROM (SELECT DISTINCT table_name FROM expected_columns) e
          WHERE has_table_privilege(current_user,format('foundation.%I',e.table_name),'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'))
        AND NOT EXISTS (SELECT 1 FROM (SELECT DISTINCT table_name FROM expected_columns) e
          JOIN pg_namespace n ON n.nspname='foundation' JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=e.table_name
          JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
          CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
          WHERE has_column_privilege(current_user,c.oid,a.attname,p.privilege || ' WITH GRANT OPTION') OR has_column_privilege(current_user,c.oid,a.attname,p.privilege)
            AND NOT EXISTS (SELECT 1 FROM required_privileges r WHERE r.table_name=e.table_name AND r.column_name=a.attname AND r.privilege=p.privilege))
        AND NOT EXISTS (SELECT 1 FROM expected_constraints e WHERE NOT EXISTS (
          SELECT 1 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='foundation' AND c.relname=e.table_name AND k.conname=e.name AND k.contype::text=e.kind AND k.convalidated))
        AND NOT EXISTS (SELECT 1 FROM expected_indexes e WHERE NOT EXISTS (
          SELECT 1 FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
          WHERE n.nspname='foundation' AND t.relname=e.table_name AND idx.relname=e.name AND i.indisvalid AND i.indisunique=e.unique_index
            AND pg_get_indexdef(i.indexrelid)=format('CREATE %sINDEX %I ON foundation.%I USING btree (%s)', CASE WHEN e.unique_index THEN 'UNIQUE ' ELSE '' END,e.name,e.table_name,e.columns)))
        AND NOT EXISTS (SELECT FROM (VALUES
          ('staff','rbac_staff_write','rbac_lock_write'),('staff','rbac_staff_current','rbac_check_staff'),
          ('roles','rbac_role_write','rbac_lock_write'),('roles','rbac_guard_role','rbac_guard_role'),
          ('permissions','rbac_catalog_write','rbac_lock_write'),('permissions','rbac_guard_catalog','rbac_guard_catalog'),
          ('role_permissions','rbac_grant_write','rbac_lock_write'),('role_permissions','rbac_guard_grant','rbac_guard_grant'),
          ('staff_role_assignments','rbac_assignment_write','rbac_lock_write'),('staff_role_assignments','rbac_guard_assignment','rbac_guard_assignment'),
          ('staff_role_assignments','rbac_assignment_current','rbac_check_staff'),('staff_web_credentials','rbac_credential_removal','rbac_lock_write'),
          ('staff_web_credentials','rbac_credential_current','rbac_check_staff')) required(tab,trig,fn)
          WHERE NOT EXISTS (SELECT FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid=to_regclass(format('foundation.%I', required.tab)) AND t.tgname=required.trig AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal
              AND p.pronamespace='foundation'::regnamespace AND p.proname=required.fn AND NOT p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']
              AND NOT has_function_privilege(current_user,p.oid,'EXECUTE')
              AND (required.fn<>'rbac_check_staff' OR (t.tgdeferrable AND t.tginitdeferred))))
        AND (SELECT count(*) FROM pg_index i WHERE i.indexrelid=to_regclass('foundation.staff_role_assignments_current_key')
             AND i.indisunique AND i.indisvalid AND pg_get_indexdef(i.indexrelid)='CREATE UNIQUE INDEX staff_role_assignments_current_key ON foundation.staff_role_assignments USING btree (staff_id) WHERE (revoked_at IS NULL)')=1
        AND (SELECT count(*) FROM foundation.roles WHERE role_type='SYSTEM' AND status='ACTIVE' AND code IN ('ADMIN','MANAGER','TECHNICIAN'))=3
        AND NOT EXISTS (SELECT FROM unnest(ARRAY['staff.role.assign','roles.create','roles.update','roles.archive','roles.permissions.manage']) req(code)
          WHERE NOT EXISTS (SELECT FROM foundation.roles r JOIN foundation.role_permissions rp ON rp.role_id=r.id
            JOIN foundation.permissions p ON p.code=rp.permission_code AND p.code=req.code AND p.protected AND p.active
            WHERE r.role_type='SYSTEM' AND r.code='ADMIN' AND r.status='ACTIVE' AND rp.enabled AND rp.scope_type='GLOBAL'))
        AND (SELECT count(*) FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
             JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
             WHERE n.nspname='foundation' AND t.relname='staff_telegram_links' AND idx.relname='staff_telegram_links_active_key'
               AND i.indisvalid AND i.indisunique
               AND pg_get_indexdef(i.indexrelid)='CREATE UNIQUE INDEX staff_telegram_links_active_key ON foundation.staff_telegram_links USING btree (telegram_user_id) WHERE (revoked_at IS NULL)') = 1
        AND (SELECT count(*) FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
             JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
             WHERE n.nspname='foundation' AND t.relname='staff_telegram_links' AND idx.relname='staff_telegram_links_active_staff_key'
               AND i.indisvalid AND i.indisunique
               AND pg_get_indexdef(i.indexrelid)='CREATE UNIQUE INDEX staff_telegram_links_active_staff_key ON foundation.staff_telegram_links USING btree (staff_id) WHERE (revoked_at IS NULL)') = 1
        AND (SELECT count(*) FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
             JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
             WHERE n.nspname='foundation' AND t.relname='web_sessions' AND idx.relname='web_sessions_initdata_digest_idx'
               AND i.indisvalid AND NOT i.indisunique
               AND pg_get_indexdef(i.indexrelid)='CREATE INDEX web_sessions_initdata_digest_idx ON foundation.web_sessions USING btree (initdata_digest) WHERE (initdata_digest IS NOT NULL)') = 1
        AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['cleanup_web_auth_attempts','cleanup_web_auth_throttles','cleanup_web_sessions']) f(name)
          WHERE NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='foundation' AND p.proname=f.name AND p.pronargs=0 AND p.prosecdef
              AND p.proconfig @> ARRAY['search_path=pg_catalog'] AND p.proowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)
              AND has_function_privilege(current_user,p.oid,'EXECUTE')
              AND NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')))
        AS ready
    `;
    return rows[0]?.ready === true;
  }

  async onModuleDestroy(): Promise<void> {
    this.closing = true;
    await this.pending;
    try { await this.client?.$disconnect(); }
    finally { await this.pool?.end(); }
  }
}
