import type { Client, QueryResultRow } from 'pg';
import { P04_CAPABILITIES } from '../../authz/capability.js';

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

// P03-03 (013) mechanical readiness: exact physical columns, not legal readiness. A
// missing column, a widened nullability or a changed type/typmod must fail closed.
// `type`/`modifier` are the pg_type name and atttypmod; `notNull` is attnotnull.
type SettingsColumn = readonly [type: string, modifier: number, notNull: boolean];
const settingsColumns: Readonly<Record<string, Readonly<Record<string, SettingsColumn>>>> = {
  business_settings_versions: {
    id: ['uuid', -1, true], version: ['int4', -1, true], launch_mode: ['varchar', 20, true],
    primary_city_id: ['uuid', -1, true], reviewed_by: ['uuid', -1, true], published_at: ['timestamptz', 6, true],
    operator_name: ['text', -1, false], operator_registration_id: ['text', -1, false],
    operator_address: ['text', -1, false], legal_review_ref: ['text', -1, false],
    security_policy_ref: ['text', -1, false], retention_policy_ref: ['text', -1, false],
    upload_policy_ref: ['text', -1, false],
  },
  reference_entries: {
    id: ['uuid', -1, true], type: ['varchar', 36, true], scope: ['varchar', 20, true],
    city_id: ['uuid', -1, false], code: ['varchar', 68, true], row_version: ['int4', -1, true],
    current_version_id: ['uuid', -1, false], archived_at: ['timestamptz', 6, false],
  },
  reference_entry_versions: {
    id: ['uuid', -1, true], entry_id: ['uuid', -1, true], type: ['varchar', 36, true],
    city_id: ['uuid', -1, false], version: ['int4', -1, true], label: ['text', -1, true],
    valid_from: ['timestamptz', 6, true], valid_until: ['timestamptz', 6, false],
    source_ref: ['text', -1, true], reviewed_by: ['uuid', -1, true], published_at: ['timestamptz', 6, true],
    city_version_id: ['uuid', -1, false], start_minute: ['int4', -1, false], end_minute: ['int4', -1, false],
  },
  content_blocks: {
    id: ['uuid', -1, true], code: ['varchar', 68, true], kind: ['varchar', 20, true],
    scope: ['varchar', 20, true], city_id: ['uuid', -1, false], allow_company_fallback: ['bool', -1, true],
    row_version: ['int4', -1, true], current_revision_id: ['uuid', -1, false], archived_at: ['timestamptz', 6, false],
  },
  content_block_revisions: {
    id: ['uuid', -1, true], block_id: ['uuid', -1, true], version: ['int4', -1, true],
    title: ['text', -1, true], body: ['text', -1, true], source_ref: ['text', -1, true],
    reviewed_by: ['uuid', -1, true], published_at: ['timestamptz', 6, true],
  },
  legal_documents: {
    id: ['uuid', -1, true], purpose: ['varchar', 36, true], kind: ['varchar', 28, true],
    row_version: ['int4', -1, true], current_version_id: ['uuid', -1, false],
  },
  legal_document_versions: {
    id: ['uuid', -1, true], document_id: ['uuid', -1, true], purpose: ['varchar', 36, true],
    kind: ['varchar', 28, true], version: ['int4', -1, true], title: ['text', -1, true],
    body: ['text', -1, true], checksum: ['varchar', 68, true], legal_basis: ['text', -1, true],
    source_ref: ['text', -1, true], reviewed_by: ['uuid', -1, true], published_at: ['timestamptz', 6, true],
  },
  request_sessions: {
    id: ['uuid', -1, true], secret_hash: ['varchar', 68, true], intake_city_id: ['uuid', -1, true],
    intake_city_version_id: ['uuid', -1, true], created_at: ['timestamptz', 6, true],
    expires_at: ['timestamptz', 6, true], revoked_at: ['timestamptz', 6, false],
  },
  consent_records: {
    id: ['uuid', -1, true], session_id: ['uuid', -1, true], document_id: ['uuid', -1, true],
    document_version_id: ['uuid', -1, true], purpose: ['varchar', 36, true], action: ['varchar', 20, true],
    legal_basis: ['text', -1, true], source: ['varchar', 36, true], evidence_ref: ['uuid', -1, true],
    occurred_at: ['timestamptz', 6, true], supersedes_id: ['uuid', -1, false],
  },
};

// Index definitions are compared after normalizing away quotes, parentheses, whitespace
// and the redundant varchar->text casts, so a changed column order or predicate fails.
const normalizeIndex = (definition: string): string => definition
  .replace(/\s+/g, '').replace(/"/g, '').replace(/[()]/g, '').replace(/::text/g, '');
const settingsIndexes: readonly (readonly [table: string, name: string, definition: string])[] = [
  ['reference_entries', 'reference_entries_company_code_key',
    "CREATE UNIQUE INDEX reference_entries_company_code_key ON foundation.reference_entries USING btree (type, code) WHERE scope = 'COMPANY'"],
  ['reference_entries', 'reference_entries_city_code_key',
    "CREATE UNIQUE INDEX reference_entries_city_code_key ON foundation.reference_entries USING btree (city_id, type, code) WHERE scope = 'CITY'"],
  ['reference_entries', 'reference_entries_type_id_key',
    'CREATE UNIQUE INDEX reference_entries_type_id_key ON foundation.reference_entries USING btree (type, id)'],
  ['reference_entry_versions', 'reference_entry_versions_entry_version_key',
    'CREATE UNIQUE INDEX reference_entry_versions_entry_version_key ON foundation.reference_entry_versions USING btree (entry_id, version)'],
  ['reference_entry_versions', 'reference_entry_versions_entry_type_id_key',
    'CREATE UNIQUE INDEX reference_entry_versions_entry_type_id_key ON foundation.reference_entry_versions USING btree (entry_id, type, id)'],
  ['content_blocks', 'content_blocks_company_code_key',
    "CREATE UNIQUE INDEX content_blocks_company_code_key ON foundation.content_blocks USING btree (code) WHERE scope = 'COMPANY'"],
  ['content_blocks', 'content_blocks_city_code_key',
    "CREATE UNIQUE INDEX content_blocks_city_code_key ON foundation.content_blocks USING btree (city_id, code) WHERE scope = 'CITY'"],
  ['content_block_revisions', 'content_block_revisions_block_version_key',
    'CREATE UNIQUE INDEX content_block_revisions_block_version_key ON foundation.content_block_revisions USING btree (block_id, version)'],
  ['content_block_revisions', 'content_block_revisions_block_id_key',
    'CREATE UNIQUE INDEX content_block_revisions_block_id_key ON foundation.content_block_revisions USING btree (block_id, id)'],
  ['legal_documents', 'legal_documents_purpose_kind_key',
    'CREATE UNIQUE INDEX legal_documents_purpose_kind_key ON foundation.legal_documents USING btree (purpose, kind)'],
  ['legal_documents', 'legal_documents_id_purpose_kind_key',
    'CREATE UNIQUE INDEX legal_documents_id_purpose_kind_key ON foundation.legal_documents USING btree (id, purpose, kind)'],
  ['legal_document_versions', 'legal_document_versions_document_version_key',
    'CREATE UNIQUE INDEX legal_document_versions_document_version_key ON foundation.legal_document_versions USING btree (document_id, version)'],
  ['legal_document_versions', 'legal_document_versions_document_id_key',
    'CREATE UNIQUE INDEX legal_document_versions_document_id_key ON foundation.legal_document_versions USING btree (document_id, id)'],
  ['legal_document_versions', 'legal_document_versions_document_id_purpose_key',
    'CREATE UNIQUE INDEX legal_document_versions_document_id_purpose_key ON foundation.legal_document_versions USING btree (document_id, id, purpose)'],
  ['request_sessions', 'request_sessions_secret_hash_key',
    'CREATE UNIQUE INDEX request_sessions_secret_hash_key ON foundation.request_sessions USING btree (secret_hash)'],
  ['consent_records', 'consent_records_session_evidence_key',
    'CREATE UNIQUE INDEX consent_records_session_evidence_key ON foundation.consent_records USING btree (session_id, evidence_ref)'],
  ['consent_records', 'consent_records_supersedes_id_key',
    'CREATE UNIQUE INDEX consent_records_supersedes_id_key ON foundation.consent_records USING btree (supersedes_id)'],
];
// The eight 013 tables: the runtime must never hold table-level privilege, DELETE or
// TRUNCATE. Only the 013 revision/event tables are strictly append-only for the runtime.
const settingsTables = ['reference_entries', 'reference_entry_versions', 'content_blocks',
  'content_block_revisions', 'legal_documents', 'legal_document_versions', 'request_sessions', 'consent_records'];

// Named CHECK constraints of 013 with fragments that must appear in the definition, so a
// renamed-but-weakened guard (e.g. CHECK (true)) fails readiness even under the same name.
const settingsChecks: readonly (readonly [table: string, name: string, needles: readonly string[]])[] = [
  ['business_settings_versions', 'business_settings_versions_operator_name_check', ['operator_name IS NULL', 'length']],
  ['business_settings_versions', 'business_settings_versions_operator_registration_id_check', ['operator_registration_id IS NULL']],
  ['business_settings_versions', 'business_settings_versions_operator_address_check', ['operator_address IS NULL']],
  ['business_settings_versions', 'business_settings_versions_legal_review_ref_check', ['legal_review_ref IS NULL']],
  ['business_settings_versions', 'business_settings_versions_security_policy_ref_check', ['security_policy_ref IS NULL']],
  ['business_settings_versions', 'business_settings_versions_retention_policy_ref_check', ['retention_policy_ref IS NULL']],
  ['business_settings_versions', 'business_settings_versions_upload_policy_ref_check', ['upload_policy_ref IS NULL']],
  ['reference_entries', 'reference_entries_type_check', ['CALLBACK_INTERVAL', 'PAYMENT_METHOD', 'REQUEST_SOURCE']],
  ['reference_entries', 'reference_entries_scope_check', ['COMPANY', 'CITY']],
  ['reference_entries', 'reference_entries_scope_city_check', ['CALLBACK_INTERVAL', 'city_id IS NOT NULL']],
  // pg_get_constraintdef renders varchar columns with an explicit ::text cast, so needles
  // avoid the `column ~` form and match the parts that survive the cast.
  ['reference_entries', 'reference_entries_code_check', ['~', 'A-Za-z', '{0,63}']],
  ['reference_entries', 'reference_entries_row_version_check', ['row_version >= 1']],
  ['reference_entry_versions', 'reference_entry_versions_version_check', ['version >= 1']],
  ['reference_entry_versions', 'reference_entry_versions_type_check', ['CALLBACK_INTERVAL', 'REQUEST_SOURCE']],
  ['reference_entry_versions', 'reference_entry_versions_type_fields_check', ['CALLBACK_INTERVAL', 'start_minute IS NOT NULL']],
  ['reference_entry_versions', 'reference_entry_versions_interval_check', ['start_minute >= 0', 'start_minute < end_minute', 'end_minute <= 1440']],
  ['reference_entry_versions', 'reference_entry_versions_label_check', ['label ~']],
  ['reference_entry_versions', 'reference_entry_versions_source_check', ['source_ref ~']],
  ['reference_entry_versions', 'reference_entry_versions_window_check', ['valid_until IS NULL', 'valid_until > valid_from']],
  ['content_blocks', 'content_blocks_kind_check', ['FAQ', 'FACT', 'SEO']],
  ['content_blocks', 'content_blocks_scope_check', ['COMPANY', 'CITY']],
  ['content_blocks', 'content_blocks_scope_city_check', ['COMPANY', 'CITY', 'city_id IS NOT NULL']],
  ['content_blocks', 'content_blocks_code_check', ['~', 'A-Za-z', '{0,63}']],
  ['content_blocks', 'content_blocks_row_version_check', ['row_version >= 1']],
  ['content_blocks', 'content_blocks_fallback_scope_check', ["'COMPANY'", 'allow_company_fallback']],
  ['content_block_revisions', 'content_block_revisions_version_check', ['version >= 1']],
  ['content_block_revisions', 'content_block_revisions_text_check', ['title ~', 'body ~', 'source_ref ~']],
  ['legal_documents', 'legal_documents_purpose_check', ['REQUEST_PROCESSING', 'ADDRESS_COVERAGE', 'MARKETING']],
  ['legal_documents', 'legal_documents_kind_check', ['POLICY', 'CONSENT_FORM', 'OPT_IN_NOTICE']],
  ['legal_documents', 'legal_documents_row_version_check', ['row_version >= 1']],
  ['legal_document_versions', 'legal_document_versions_purpose_check', ['REQUEST_PROCESSING', 'MARKETING']],
  ['legal_document_versions', 'legal_document_versions_kind_check', ['POLICY', 'CONSENT_FORM', 'OPT_IN_NOTICE']],
  ['legal_document_versions', 'legal_document_versions_version_check', ['version >= 1']],
  // The checksum must really be the SHA-256 of the UTF-8 body, not a format-only pattern.
  ['legal_document_versions', 'legal_document_versions_checksum_check', ['sha256', 'convert_to', 'encode']],
  ['legal_document_versions', 'legal_document_versions_text_check', ['title ~', 'body ~', 'legal_basis ~', 'source_ref ~']],
  ['request_sessions', 'request_sessions_secret_hash_check', ['~', '0-9a-f', '{64}']],
  ['request_sessions', 'request_sessions_expiry_check', ['expires_at > created_at']],
  ['consent_records', 'consent_records_purpose_check', ['REQUEST_PROCESSING', 'ADDRESS_COVERAGE', 'MARKETING']],
  ['consent_records', 'consent_records_action_check', ['GIVEN', 'REVOKED']],
  ['consent_records', 'consent_records_source_check', ['FORM']],
  ['consent_records', 'consent_records_given_supersedes_check', ['GIVEN', 'REVOKED', 'supersedes_id']],
  ['consent_records', 'consent_records_legal_basis_check', ['legal_basis ~']],
];
// The composite FKs that make a pointer/target meaningful: dropping one would let a row
// name a foreign version and still look ready, so the exact definition is pinned here.
const settingsForeignKeys: readonly (readonly [table: string, name: string, needles: readonly string[]])[] = [
  ['reference_entries', 'reference_entries_city_id_fkey', ['FOREIGN KEY (city_id)', 'service_cities(id)']],
  ['reference_entries', 'reference_entries_id_type_current_version_id_fkey',
    ['FOREIGN KEY (id, type, current_version_id)', 'reference_entry_versions(entry_id, type, id)']],
  ['reference_entry_versions', 'reference_entry_versions_type_entry_id_fkey',
    ['FOREIGN KEY (type, entry_id)', 'reference_entries(type, id)']],
  ['reference_entry_versions', 'reference_entry_versions_city_id_fkey', ['FOREIGN KEY (city_id)', 'service_cities(id)']],
  ['reference_entry_versions', 'reference_entry_versions_city_id_city_version_id_fkey',
    ['FOREIGN KEY (city_id, city_version_id)', 'service_city_versions(city_id, id)']],
  ['reference_entry_versions', 'reference_entry_versions_reviewed_by_fkey', ['FOREIGN KEY (reviewed_by)', 'staff(id)']],
  ['content_blocks', 'content_blocks_city_id_fkey', ['FOREIGN KEY (city_id)', 'service_cities(id)']],
  ['content_blocks', 'content_blocks_id_current_revision_id_fkey',
    ['FOREIGN KEY (id, current_revision_id)', 'content_block_revisions(block_id, id)']],
  ['content_block_revisions', 'content_block_revisions_block_id_fkey', ['FOREIGN KEY (block_id)', 'content_blocks(id)']],
  ['content_block_revisions', 'content_block_revisions_reviewed_by_fkey', ['FOREIGN KEY (reviewed_by)', 'staff(id)']],
  ['legal_documents', 'legal_documents_id_current_version_id_fkey',
    ['FOREIGN KEY (id, current_version_id)', 'legal_document_versions(document_id, id)']],
  ['legal_document_versions', 'legal_document_versions_document_id_purpose_kind_fkey',
    ['FOREIGN KEY (document_id, purpose, kind)', 'legal_documents(id, purpose, kind)']],
  ['legal_document_versions', 'legal_document_versions_reviewed_by_fkey', ['FOREIGN KEY (reviewed_by)', 'staff(id)']],
  ['request_sessions', 'request_sessions_intake_city_id_fkey', ['FOREIGN KEY (intake_city_id)', 'service_cities(id)']],
  ['request_sessions', 'request_sessions_intake_city_id_intake_city_version_id_fkey',
    ['FOREIGN KEY (intake_city_id, intake_city_version_id)', 'service_city_versions(city_id, id)']],
  ['consent_records', 'consent_records_session_id_fkey', ['FOREIGN KEY (session_id)', 'request_sessions(id)']],
  ['consent_records', 'consent_records_document_id_document_version_id_purpose_fkey',
    ['FOREIGN KEY (document_id, document_version_id, purpose)', 'legal_document_versions(document_id, id, purpose)']],
  ['consent_records', 'consent_records_supersedes_id_fkey', ['FOREIGN KEY (supersedes_id)', 'consent_records(id)']],
];
// Every 013 trigger with its function; all functions must stay SECURITY INVOKER,
// search_path-pinned, migrator-owned and NOT executable by the runtime or PUBLIC.
const settingsTriggers: readonly (readonly [table: string, trigger: string, fn: string])[] = [
  ['reference_entries', 'reference_entries_guard', 'reference_entries_guard'],
  ['reference_entries', 'reference_entries_reject_truncate', 'settings_history_reject_truncate'],
  ['reference_entry_versions', 'reference_entry_versions_pointer_guard', 'reference_entry_versions_pointer_guard'],
  ['reference_entry_versions', 'reference_entry_versions_immutable', 'reference_entry_versions_immutable'],
  ['reference_entry_versions', 'reference_entry_versions_reject_truncate', 'settings_history_reject_truncate'],
  ['content_blocks', 'content_blocks_guard', 'content_blocks_guard'],
  ['content_blocks', 'content_blocks_reject_truncate', 'settings_history_reject_truncate'],
  ['content_block_revisions', 'content_block_revisions_pointer_guard', 'content_block_revisions_pointer_guard'],
  ['content_block_revisions', 'content_block_revisions_immutable', 'content_block_revisions_immutable'],
  ['content_block_revisions', 'content_block_revisions_reject_truncate', 'settings_history_reject_truncate'],
  ['legal_documents', 'legal_documents_guard', 'legal_documents_guard'],
  ['legal_documents', 'legal_documents_reject_truncate', 'settings_history_reject_truncate'],
  ['legal_document_versions', 'legal_document_versions_pointer_guard', 'legal_document_versions_pointer_guard'],
  ['legal_document_versions', 'legal_document_versions_immutable', 'legal_document_versions_immutable'],
  ['legal_document_versions', 'legal_document_versions_reject_truncate', 'settings_history_reject_truncate'],
  ['request_sessions', 'request_sessions_guard', 'request_sessions_guard'],
  ['request_sessions', 'request_sessions_reject_truncate', 'settings_history_reject_truncate'],
  ['consent_records', 'consent_records_guard', 'consent_records_guard'],
  ['consent_records', 'consent_records_reject_truncate', 'settings_history_reject_truncate'],
];
// Exact runtime column privileges of 013 (plus the 010-012 columns on
// business_settings_versions). Anything more, anything less or any table-level
// privilege must fail closed.
const settingsGrants: Readonly<Record<string, { select: readonly string[]; insert: readonly string[]; update: readonly string[] }>> = {
  business_settings_versions: {
    select: ['id', 'version', 'launch_mode', 'primary_city_id', 'reviewed_by', 'published_at',
      'operator_name', 'operator_registration_id', 'operator_address', 'legal_review_ref',
      'security_policy_ref', 'retention_policy_ref', 'upload_policy_ref'],
    insert: ['id', 'version', 'launch_mode', 'primary_city_id', 'reviewed_by', 'operator_name',
      'operator_registration_id', 'operator_address', 'legal_review_ref', 'security_policy_ref',
      'retention_policy_ref', 'upload_policy_ref'],
    update: [] },
  reference_entries: {
    select: ['id', 'type', 'scope', 'city_id', 'code', 'row_version', 'current_version_id', 'archived_at'],
    insert: ['id', 'type', 'scope', 'city_id', 'code'], update: ['current_version_id', 'archived_at'] },
  reference_entry_versions: {
    select: ['id', 'entry_id', 'type', 'city_id', 'version', 'label', 'valid_from', 'valid_until', 'source_ref',
      'reviewed_by', 'published_at', 'city_version_id', 'start_minute', 'end_minute'],
    insert: ['id', 'entry_id', 'type', 'city_id', 'version', 'label', 'valid_from', 'valid_until', 'source_ref',
      'reviewed_by', 'city_version_id', 'start_minute', 'end_minute'],
    update: [] },
  content_blocks: {
    select: ['id', 'code', 'kind', 'scope', 'city_id', 'allow_company_fallback', 'row_version',
      'current_revision_id', 'archived_at'],
    insert: ['id', 'code', 'kind', 'scope', 'city_id', 'allow_company_fallback'],
    update: ['current_revision_id', 'archived_at'] },
  content_block_revisions: {
    select: ['id', 'block_id', 'version', 'title', 'body', 'source_ref', 'reviewed_by', 'published_at'],
    insert: ['id', 'block_id', 'version', 'title', 'body', 'source_ref', 'reviewed_by'], update: [] },
  legal_documents: {
    select: ['id', 'purpose', 'kind', 'row_version', 'current_version_id'],
    insert: ['id', 'purpose', 'kind'], update: ['current_version_id'] },
  legal_document_versions: {
    select: ['id', 'document_id', 'purpose', 'kind', 'version', 'title', 'body', 'checksum', 'legal_basis',
      'source_ref', 'reviewed_by', 'published_at'],
    insert: ['id', 'document_id', 'purpose', 'kind', 'version', 'title', 'body', 'checksum', 'legal_basis',
      'source_ref', 'reviewed_by'],
    update: [] },
  request_sessions: {
    select: ['id', 'secret_hash', 'intake_city_id', 'intake_city_version_id', 'created_at', 'expires_at', 'revoked_at'],
    insert: ['id', 'secret_hash', 'intake_city_id', 'intake_city_version_id', 'expires_at'],
    update: ['revoked_at'] },
  consent_records: {
    select: ['id', 'session_id', 'document_id', 'document_version_id', 'purpose', 'action', 'legal_basis',
      'source', 'evidence_ref', 'occurred_at', 'supersedes_id'],
    insert: ['id', 'session_id', 'document_id', 'document_version_id', 'purpose', 'action', 'legal_basis',
      'source', 'evidence_ref', 'supersedes_id'],
    update: [] },
};


const expectedConstraints = [
  ['audit_logs', 'audit_logs_pkey', 'p', 'PRIMARY KEY (id)'],  ['audit_logs', 'audit_logs_operation_check', 'c', 'CHECK ((length((operation)::text) > 0))'],
  ['outbox_events', 'outbox_events_pkey', 'p', 'PRIMARY KEY (id)'],
  ['outbox_events', 'outbox_events_status_check', 'c', "CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'EXPANDED'::character varying, 'FAILED'::character varying])::text[])))"],
  ['outbox_events', 'outbox_events_type_check', 'c', 'CHECK ((length((event_type)::text) > 0))'],
  ['outbox_events', 'outbox_events_attempt_count_check', 'c', 'CHECK ((attempt_count >= 0))'],
  ['outbox_events', 'outbox_events_lease_generation_check', 'c', 'CHECK ((lease_generation >= 0))'],
  ['outbox_events', 'outbox_events_lease_pair_check', 'c', 'CHECK (((lease_owner IS NULL) = (lease_expires_at IS NULL)))'],
  ['outbox_events', 'outbox_events_lease_pending_check', 'c', "CHECK (((lease_owner IS NULL) OR ((status)::text = 'PENDING'::text)))"],
  ['outbox_events', 'outbox_events_last_error_code_check', 'c', "CHECK (((last_error_code)::text = ANY ((ARRAY['HANDLER_FAILED'::character varying, 'ATTEMPTS_EXHAUSTED'::character varying])::text[])))"],
];

/** Readiness queries execute on the caller's pinned pg connection. */
export class LegacyReadinessProbes {
  constructor(private readonly client: Pick<Client, 'query'>, private readonly database: string,
    private readonly authEnabled: boolean, private readonly inspectorRole: 'fixlevelup_runtime' | 'fixlevelup_migrator' = 'fixlevelup_runtime') {}

  private async raw<Row extends QueryResultRow>(parts: TemplateStringsArray, ...values: unknown[]): Promise<Row[]> {
    // Only static template fragments become SQL; all interpolations are bindings.
    const sql = parts.reduce((result, part, index) => result + (index ? '$' + String(index) : '') + part, '');
    return (await this.client.query<Row>(sql, values)).rows;
  }

  async ready(raw: (parts: TemplateStringsArray) => Promise<ReadinessRow[]> =
    (parts) => this.raw<ReadinessRow>(parts)): Promise<boolean> {
    const rows = await raw`
      SELECT current_database() AS database, current_user AS role,
        (SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)
          AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid)
          FROM pg_roles r WHERE rolname='fixlevelup_runtime') AS safe_role,
        (EXISTS(SELECT 1 FROM pg_namespace n WHERE nspname='foundation' AND nspowner<>(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'))
          AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CREATE')
          AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'TEMP')
          AND has_schema_privilege('fixlevelup_runtime','foundation','USAGE')
          AND NOT has_schema_privilege('fixlevelup_runtime','foundation','CREATE')
          AND has_table_privilege('fixlevelup_runtime','foundation.audit_logs','SELECT')
          AND has_table_privilege('fixlevelup_runtime','foundation.audit_logs','INSERT')
          AND NOT has_table_privilege('fixlevelup_runtime','foundation.audit_logs','UPDATE,DELETE,TRUNCATE')
          AND NOT has_any_column_privilege('fixlevelup_runtime','foundation.audit_logs','UPDATE')
          AND has_table_privilege('fixlevelup_runtime','foundation.outbox_events','SELECT')
          AND has_table_privilege('fixlevelup_runtime','foundation.outbox_events','INSERT')
          AND NOT has_table_privilege('fixlevelup_runtime','foundation.outbox_events','UPDATE,DELETE,TRUNCATE')
          AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['status','attempt_count','lease_owner','lease_generation','lease_expires_at','next_attempt_at','last_error_code']) AS worker(column_name)
            WHERE NOT has_column_privilege('fixlevelup_runtime','foundation.outbox_events',worker.column_name,'UPDATE'))
          AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='foundation.outbox_events'::regclass
            AND a.attnum>0 AND NOT a.attisdropped
            AND a.attname NOT IN ('status','attempt_count','lease_owner','lease_generation','lease_expires_at','next_attempt_at','last_error_code')
            AND has_column_privilege('fixlevelup_runtime','foundation.outbox_events',a.attname,'UPDATE'))
          AND NOT has_table_privilege('fixlevelup_runtime','foundation._prisma_migrations','SELECT')
          AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='foundation' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'))) AS safe_schema,
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
      if (!row || row.database !== this.database || row.role !== this.inspectorRole
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
      return foundationReady && (!this.authEnabled || (await this.authReady() && await this.settingsReady()
        && await this.settingsManagementReady()));
  }

  // P03-03 (013) readiness: physical schema, named guards and exact column grants of the
  // settings/reference/content/legal slice. Mechanical only - it never claims legal
  // readiness, reviewed values, Q02/Q13 answers or a permitted production deployment.
  private async settingsReady(): Promise<boolean> {
    const tables = [...settingsTables, 'business_settings_versions'];
    const rows = await this.raw<{
      columns: { table: string; column: string; type: string; not_null: boolean; type_modifier: number }[];
      checks: { table: string; name: string; kind: string; validated: boolean; definition: string }[];
      indexes: { table: string; name: string; valid: boolean; definition: string }[];
      triggers: { table: string; name: string; enabled: boolean; fn: string; owner: string; secdef: boolean;
        config: string[] | null; runtime_execute: boolean; public_execute: boolean }[];
      grants: { table: string; column: string; readable: boolean; insertable: boolean; updatable: boolean;
        referencable: boolean; grantable: boolean; insert_grantable: boolean; update_grantable: boolean }[];
      broad: { table: string; elevated: boolean; deletable: boolean }[];
      public_acl: { table: string; column: string | null; privilege: string }[];
    }>`
      SELECT
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,'column',a.attname,'type',t.typname,
            'not_null',a.attnotnull,'type_modifier',a.atttypmod))
          FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          JOIN pg_type t ON t.oid=a.atttypid
          WHERE n.nspname='foundation' AND c.relname=ANY(${tables}::name[]) AND c.relkind='r'
            AND a.attnum>0 AND NOT a.attisdropped),'[]'::json) AS columns,
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,'name',k.conname,'kind',k.contype,
            'validated',k.convalidated,'definition',pg_get_constraintdef(k.oid)))
          FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='foundation' AND c.relname=ANY(${tables}::name[])),'[]'::json) AS checks,
        COALESCE((SELECT json_agg(json_build_object('table',t.relname,'name',i.relname,'valid',x.indisvalid,
            'definition',pg_get_indexdef(x.indexrelid)))
          FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid
          JOIN pg_namespace n ON n.oid=t.relnamespace
          WHERE n.nspname='foundation' AND t.relname=ANY(${tables}::name[])),'[]'::json) AS indexes,
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,'name',g.tgname,
            'enabled',g.tgenabled IN ('O','A'),'fn',p.proname,'owner',pg_get_userbyid(p.proowner),
            'secdef',p.prosecdef,'config',p.proconfig,
            'runtime_execute',has_function_privilege('fixlevelup_runtime',p.oid,'EXECUTE'),
            'public_execute',EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
              WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')))
          FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          JOIN pg_proc p ON p.oid=g.tgfoid
          WHERE n.nspname='foundation' AND c.relname=ANY(${tables}::name[]) AND NOT g.tgisinternal),'[]'::json) AS triggers,
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,'column',a.attname,
            'readable',has_column_privilege('fixlevelup_runtime',c.oid,a.attnum,'SELECT'),
            'insertable',has_column_privilege('fixlevelup_runtime',c.oid,a.attnum,'INSERT'),
            'updatable',has_column_privilege('fixlevelup_runtime',c.oid,a.attnum,'UPDATE'),
            'referencable',has_column_privilege('fixlevelup_runtime',c.oid,a.attnum,'REFERENCES'),
            'grantable',has_column_privilege('fixlevelup_runtime',c.oid,a.attnum,'SELECT WITH GRANT OPTION'),
            'insert_grantable',has_column_privilege('fixlevelup_runtime',c.oid,a.attnum,'INSERT WITH GRANT OPTION'),
            'update_grantable',has_column_privilege('fixlevelup_runtime',c.oid,a.attnum,'UPDATE WITH GRANT OPTION')))
          FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='foundation' AND c.relname=ANY(${tables}::name[]) AND a.attnum>0 AND NOT a.attisdropped),'[]'::json) AS grants,
        COALESCE((SELECT json_agg(json_build_object('table',c.relname,
            'elevated',has_table_privilege('fixlevelup_runtime',c.oid,'SELECT,INSERT,UPDATE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'),
            'deletable',has_table_privilege('fixlevelup_runtime',c.oid,'DELETE')))
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='foundation' AND c.relname=ANY(${tables}::name[])),'[]'::json) AS broad,
        -- PUBLIC is checked against the stored ACL, not against the effective privileges
        -- of the runtime: a duplicate PUBLIC grant would otherwise stay invisible. Both
        -- table-level and column-level PUBLIC entries of every privilege type count,
        -- including a PUBLIC table-level SELECT.
        COALESCE((SELECT json_agg(json_build_object('table',public_rows.table,'column',public_rows.column,
            'privilege',public_rows.privilege))
          FROM (
            SELECT c.relname AS table, NULL::text AS column, x.privilege_type AS privilege
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x
              WHERE n.nspname='foundation' AND c.relname=ANY(${tables}::name[]) AND x.grantee=0
            UNION ALL
            SELECT c.relname, a.attname, y.privilege_type
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
              CROSS JOIN LATERAL aclexplode(a.attacl) y
              WHERE n.nspname='foundation' AND c.relname=ANY(${tables}::name[]) AND y.grantee=0
          ) public_rows),'[]'::json) AS public_acl
    `;
    const row = rows[0];
    if (!row) { return false; }
    // 1. Exact physical columns, nullability and type modifiers.
    for (const [table, columns] of Object.entries(settingsColumns)) {
      for (const [column, [type, modifier, notNull]] of Object.entries(columns)) {
        if (!row.columns.some((entry) => entry.table === table && entry.column === column && entry.type === type
          && entry.type_modifier === modifier && entry.not_null === notNull)) { return false; }
      }
    }
    // 2. Every named guard exists, is validated, and its definition still enforces the rule.
    for (const [table, name, needles] of settingsChecks) {
      const found = row.checks.find((entry) => entry.table === table && entry.name === name);
      if (!found || found.kind !== 'c' || !found.validated
        || !needles.every((needle) => found.definition.includes(needle))) { return false; }
    }
    // 3. The composite FKs that make a pointer/target meaningful must exist and be validated;
    //    a dropped FK would otherwise leave a row naming a foreign version "ready".
    for (const [table, name, needles] of settingsForeignKeys) {
      const found = row.checks.find((entry) => entry.table === table && entry.name === name);
      if (!found || found.kind !== 'f' || !found.validated
        || !needles.every((needle) => found.definition.includes(needle))) { return false; }
    }
    // 4. Unique/partial-unique indexes and their exact definitions.
    for (const [table, name, definition] of settingsIndexes) {
      const found = row.indexes.find((entry) => entry.table === table && entry.name === name);
      if (!found || !found.valid || normalizeIndex(found.definition) !== normalizeIndex(definition)) { return false; }
    }
    // 5. Every guard trigger is enabled and its function is non-delegating and unreachable.
    for (const [table, trigger, fn] of settingsTriggers) {
      const found = row.triggers.find((entry) => entry.table === table && entry.name === trigger);
      if (!found || !found.enabled || found.fn !== fn || found.owner !== 'fixlevelup_migrator'
        || found.secdef || !found.config?.includes('search_path=pg_catalog')
        || found.runtime_execute || found.public_execute) { return false; }
    }
    // 6. Exact column grants: nothing extra, nothing missing, no table-level privilege,
    //    no REFERENCES/grant option and no DELETE/TRUNCATE on any of these tables.
    for (const [table, spec] of Object.entries(settingsGrants)) {
      const granted = row.grants.filter((entry) => entry.table === table);
      const pick = (flag: 'readable' | 'insertable' | 'updatable') =>
        granted.filter((entry) => entry[flag]).map((entry) => entry.column).sort();
      if (JSON.stringify(pick('readable')) !== JSON.stringify([...spec.select].sort())) { return false; }
      if (JSON.stringify(pick('insertable')) !== JSON.stringify([...spec.insert].sort())) { return false; }
      if (JSON.stringify(pick('updatable')) !== JSON.stringify([...spec.update].sort())) { return false; }
      if (granted.some((entry) => entry.referencable || entry.grantable
        || entry.insert_grantable || entry.update_grantable)) { return false; }
    }
    // 7. No PUBLIC privilege of any kind on these tables (checked against the stored ACL,
    //    so a duplicate PUBLIC grant cannot hide behind an existing runtime grant).
    if (row.public_acl.length > 0) { return false; }
    return row.broad.every((entry) => !entry.elevated && !entry.deletable);
  }

  // P03-05 (018), deliberately separate from the 013 and historical auth probes.
  // Also used by the management HTTP boundary; a failed probe never reaches a command.
  async settingsManagementReady(): Promise<boolean> {
    // Hash only the fixed physical contract, not business/configuration rows or personal
    // source state. `prosrc` is deliberately included: presence/name/ACL checks cannot
    // distinguish the real guards or issuer from same-signature no-op replacements.
    // PostgreSQL's deparsers below are pinned to the supported PostgreSQL 18 catalog.
    const rows = await this.raw<{ metadata: string; compatible: boolean }>`
      WITH tables AS (
        SELECT relname AS name,oid,relowner,relkind,relrowsecurity,relforcerowsecurity,relacl
        FROM pg_class WHERE relnamespace='foundation'::regnamespace
          AND relname IN ('p03_bootstrap_permissions','p03_command_receipts')
      ), columns AS (
        SELECT t.name,a.attname,t.oid,a.attnum,p.typname,a.atttypmod,a.attnotnull,a.attidentity,a.attgenerated,
          pg_get_expr(d.adbin,d.adrelid) AS default_expr,a.attacl,
          CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END AS collation_name
        FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid JOIN pg_type p ON p.oid=a.atttypid
        LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
        WHERE a.attnum>0 AND NOT a.attisdropped
      ), functions AS (
        SELECT p.* FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname IN
          ('issue_first_p03_permissions','p03_original_bootstrap_assignment','p03_bootstrap_guard',
           'p03_guard_role_grant','p03_history_immutable','rbac_lock_write')
      ), metadata(category,name,shape) AS (
        SELECT 'table',t.name,jsonb_build_array(pg_get_userbyid(t.relowner),t.relkind,t.relrowsecurity,t.relforcerowsecurity)
        FROM tables t
        UNION ALL
        SELECT 'column',name||'.'||attname,jsonb_build_array(attnum,typname,atttypmod,attnotnull,attidentity,attgenerated,default_expr,collation_name)
        FROM columns
        UNION ALL
        SELECT 'constraint',k.conname,jsonb_build_array(k.conrelid::regclass::text,k.contype,k.convalidated,k.condeferrable,k.condeferred,
          pg_get_constraintdef(k.oid),CASE WHEN k.conindid=0 THEN NULL ELSE EXISTS(SELECT FROM pg_index i WHERE i.indexrelid=k.conindid AND i.indisvalid AND i.indisready AND i.indisunique) END)
        FROM pg_constraint k WHERE k.conrelid IN (SELECT oid FROM tables)
          OR (k.conrelid='foundation.role_permissions'::regclass AND k.conname='role_permissions_scope_check')
        UNION ALL
        SELECT 'trigger',t.tgname,jsonb_build_array(t.tgrelid::regclass::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,
          t.tgnargs,t.tgqual::text,n.nspname,p.proname)
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE NOT t.tgisinternal AND (t.tgrelid IN (SELECT oid FROM tables) OR
          (t.tgrelid='foundation.role_permissions'::regclass AND t.tgname='p03_guard_role_grant'))
        UNION ALL
        SELECT 'function',p.proname,jsonb_build_array(pg_get_userbyid(p.proowner),p.proretset,p.prorettype::regtype::text,
          l.lanname,p.pronargs,p.pronargdefaults,p.proargtypes::text,p.prokind,p.prosecdef,p.proconfig,p.provolatile,p.proisstrict,
          p.proleakproof,p.proparallel,encode(sha256(convert_to(replace(p.prosrc,chr(13),''),'UTF8')),'hex'))
        FROM functions p JOIN pg_language l ON l.oid=p.prolang
      ), catalog AS (
        SELECT code,module,description,active,protected FROM foundation.permissions WHERE code=ANY(${[
          'settings.fullread', 'settings.manage', 'settings.readiness.read',
          'references.callbackinterval.read', 'references.callbackinterval.manage', 'references.paymentmethod.read', 'references.paymentmethod.manage',
          'references.cancelreason.read', 'references.cancelreason.manage', 'references.declinereason.read', 'references.declinereason.manage',
          'references.requestsource.read', 'references.requestsource.manage', 'content.read', 'content.manage', 'content.publish', 'legal.read', 'legal.manage',
        ]}::text[])
      ), checked AS (
        SELECT * FROM metadata
        UNION ALL
        SELECT 'catalog',code,jsonb_build_array(module,description,active,protected) FROM catalog
      )
      SELECT encode(sha256(convert_to((SELECT jsonb_agg(jsonb_build_array(category,name,shape)
          ORDER BY category COLLATE "C",name COLLATE "C",shape::text COLLATE "C")::text FROM checked),'UTF8')),'hex') AS metadata,
        current_user=${this.inspectorRole}
        AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'))
        AND NOT has_schema_privilege('fixlevelup_runtime','foundation','CREATE')
        AND NOT has_schema_privilege('fixlevelup_runtime','public','CREATE')
        AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CREATE,TEMP')
        AND NOT (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit FROM pg_roles WHERE rolname='fixlevelup_runtime')
        AND NOT EXISTS(SELECT FROM tables t WHERE has_table_privilege('fixlevelup_runtime',t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
          OR EXISTS(SELECT FROM aclexplode(t.relacl) acl WHERE acl.grantee<>t.relowner))
        AND NOT EXISTS(SELECT FROM columns a WHERE
          has_column_privilege('fixlevelup_runtime',a.oid,a.attnum,'SELECT') <> (a.attname NOT IN ('created_at','revoked_by'))
          OR has_column_privilege('fixlevelup_runtime',a.oid,a.attnum,'INSERT') <> (a.name='p03_command_receipts' AND a.attname<>'created_at')
          OR has_column_privilege('fixlevelup_runtime',a.oid,a.attnum,'UPDATE') <> (a.name='p03_bootstrap_permissions' AND a.attname IN ('revoked_at','revoked_by'))
          OR has_column_privilege('fixlevelup_runtime',a.oid,a.attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION')
          OR EXISTS(SELECT FROM aclexplode(a.attacl) acl WHERE acl.grantee<>(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime')))
        AND NOT EXISTS(SELECT FROM functions p WHERE has_function_privilege('fixlevelup_runtime',p.oid,'EXECUTE')
          OR NOT has_function_privilege('fixlevelup_migrator',p.oid,'EXECUTE')
          OR EXISTS(SELECT FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee<>p.proowner))
        AS compatible
    `;
    return rows[0]?.compatible === true && [
      '0495cf5140136b04298a8428bb99eb80b064c62b05863a247810b58c4019553a', // 018–020
      'c41a3d75fc824c5a967c242f45c3a05d02e28c3c27b9a20325b95a011e535183', // 021: exact extended role_permissions_scope_check
    ].includes(rows[0].metadata);
  }

  /** P04 has its own mechanical gate; legacy readiness never depends on this probe. */
  async catalogManagementReady(): Promise<boolean> {
    // Exact PostgreSQL 18 metadata for 019–021 and the upstream policy state they
    // trust. In particular, the RBAC writer fence must cover role, grant, assignment,
    // and geography changes. Fingerprint the trigger definitions/activation and their
    // functions' bodies and ACLs, not just the existence of the shared lock function.
    // No business, session, or grant rows enter the fingerprint.
    const { rows } = await this.client.query<{ metadata: string; compatible: boolean }>(`
      WITH tables AS (
        SELECT * FROM pg_class WHERE relnamespace='foundation'::regnamespace AND relname IN (
          'catalog_directory_entries','catalog_directory_versions','catalog_items','catalog_item_versions',
          'catalog_fault_service_mappings','catalog_price_series','catalog_price_versions','catalog_price_periods',
          'price_rules','price_rule_series','price_rule_versions','price_rule_scopes','price_rule_periods',
          'pricing_policy_series','pricing_policy_versions','price_rule_priorities','price_rule_compatibilities',
          'pricing_policy_periods','public_price_estimate_series','public_price_estimates','public_price_estimate_periods',
          'external_reviews','external_review_revisions','p04_bootstrap_permissions','p04_command_receipts',
          'role_permissions','permissions','roles','staff','staff_role_assignments','staff_admin_city_assignments',
          'staff_web_credentials','staff_bootstrap_marker','web_sessions')
      ), columns AS (
        SELECT t.relname,a.*,p.typname,pg_get_expr(d.adbin,d.adrelid) AS default_expr
        FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid JOIN pg_type p ON p.oid=a.atttypid
        LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
        WHERE a.attnum>0 AND NOT a.attisdropped
      ), triggers AS (
        SELECT g.* FROM pg_trigger g WHERE NOT g.tgisinternal AND g.tgrelid IN (SELECT oid FROM tables)
      ), functions AS (
        SELECT p.* FROM pg_proc p WHERE p.oid IN (SELECT tgfoid FROM triggers)
          OR (p.pronamespace='foundation'::regnamespace AND p.proname IN (
            'issue_p04_synthetic_permissions','p03_original_bootstrap_assignment','pricing_policy_units_valid'))
      ), metadata(category,name,shape) AS (
        SELECT 'table',t.relname,jsonb_build_array(pg_get_userbyid(t.relowner),t.relkind,t.relrowsecurity,t.relforcerowsecurity)
        FROM tables t
        UNION ALL
        SELECT 'column',a.relname||'.'||a.attname,jsonb_build_array(a.attnum,a.typname,a.atttypmod,a.attnotnull,
          a.attidentity,a.attgenerated,a.default_expr,CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END)
        FROM columns a
        UNION ALL
        SELECT 'constraint',k.conname,jsonb_build_array(k.conrelid::regclass::text,k.contype,k.convalidated,k.condeferrable,
          k.condeferred,pg_get_constraintdef(k.oid))
        FROM pg_constraint k WHERE k.conrelid IN (SELECT oid FROM tables)
        UNION ALL
        SELECT 'index',c.relname,jsonb_build_array(i.indisvalid,i.indisready,i.indisunique,i.indislive,pg_get_indexdef(c.oid))
        FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid IN (SELECT oid FROM tables)
        UNION ALL
        SELECT 'trigger',g.tgname,jsonb_build_array(g.tgrelid::regclass::text,g.tgenabled,pg_get_triggerdef(g.oid))
        FROM triggers g
        UNION ALL
        SELECT 'function',p.proname,jsonb_build_array(pg_get_userbyid(p.proowner),p.proretset,p.prorettype::regtype::text,
          l.lanname,pg_get_function_identity_arguments(p.oid),p.pronargs,p.pronargdefaults,p.prokind,p.prosecdef,p.proconfig,
          p.provolatile,p.proisstrict,p.proleakproof,p.proparallel,encode(sha256(convert_to(replace(p.prosrc,chr(13),''),'UTF8')),'hex'))
        FROM functions p JOIN pg_language l ON l.oid=p.prolang
        UNION ALL
        SELECT 'enum',t.typname,jsonb_build_array(pg_get_userbyid(t.typowner),
          (SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid=t.oid))
        FROM pg_type t WHERE t.typnamespace='foundation'::regnamespace AND t.typname='external_review_kind' AND t.typtype='e'
        UNION ALL
        SELECT 'catalog',code,jsonb_build_array(module,description,active,protected)
        FROM foundation.permissions WHERE code=ANY($1::text[])
      ), acl(category,name,entries) AS (
        SELECT 'table_acl',t.relname,COALESCE(t.relacl,acldefault('r',t.relowner)) FROM tables t
        UNION ALL
        SELECT 'column_acl',a.relname||'.'||a.attname,a.attacl FROM columns a
        UNION ALL
        SELECT 'function_acl',p.proname,COALESCE(p.proacl,acldefault('f',p.proowner)) FROM functions p
        UNION ALL
        SELECT 'enum_acl',t.typname,COALESCE(t.typacl,acldefault('T',t.typowner))
          FROM pg_type t WHERE t.typnamespace='foundation'::regnamespace AND t.typname='external_review_kind'
      ), checked AS (
        SELECT * FROM metadata
        UNION ALL
        SELECT a.category,a.name,jsonb_build_array(pg_get_userbyid(x.grantor),
          CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable)
        FROM acl a CROSS JOIN LATERAL aclexplode(a.entries) x
      )
      SELECT encode(sha256(convert_to((SELECT jsonb_agg(jsonb_build_array(category,name,shape)
          ORDER BY category COLLATE "C",name COLLATE "C",shape::text COLLATE "C")::text FROM checked),'UTF8')),'hex') AS metadata,
        current_database()=$2 AND current_user=$3
        AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'))
        AND has_schema_privilege('fixlevelup_runtime','foundation','USAGE')
        AND NOT has_schema_privilege('fixlevelup_runtime','foundation','CREATE')
        AND NOT has_schema_privilege('fixlevelup_runtime','public','CREATE')
        AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CREATE,TEMP')
        AND NOT (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit
          FROM pg_roles WHERE rolname='fixlevelup_runtime')
        AND NOT has_function_privilege('fixlevelup_runtime','foundation.issue_p04_synthetic_permissions()','EXECUTE') AS compatible
    `, [P04_CAPABILITIES, this.database, this.inspectorRole]);
    return rows[0]?.compatible === true && rows[0].metadata === '00a7323a31b502c1bb375aa3ca84cdc570da9bbffd4b87da5e4e0c463964725c';
  }

  private async authReady(): Promise<boolean> {
    // Catalog checks require no additional runtime table privileges. Missing objects, grants,
    // or incompatible schemas must fail closed without exposing driver errors.
    const rows = await this.raw<{ ready: boolean }>`
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
        ('role_permissions','enabled','UPDATE'), ('role_permissions','scope_type','UPDATE'),
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
        AND NOT EXISTS (SELECT 1 FROM required_privileges e WHERE NOT has_column_privilege('fixlevelup_runtime', format('foundation.%I',e.table_name), e.column_name,e.privilege))
        AND NOT EXISTS (SELECT 1 FROM (SELECT DISTINCT table_name FROM expected_columns) e
          WHERE has_table_privilege('fixlevelup_runtime',format('foundation.%I',e.table_name),'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'))
        AND NOT EXISTS (SELECT 1 FROM (SELECT DISTINCT table_name FROM expected_columns) e
          JOIN pg_namespace n ON n.nspname='foundation' JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=e.table_name
          JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
          CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
          WHERE has_column_privilege('fixlevelup_runtime',c.oid,a.attname,p.privilege || ' WITH GRANT OPTION') OR has_column_privilege('fixlevelup_runtime',c.oid,a.attname,p.privilege)
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
          ('role_permissions','geography_guard_role_grant','geography_guard_role_grant'),
          ('geography_bootstrap_permissions','geography_bootstrap_guard','geography_bootstrap_guard'),
          ('staff_admin_city_assignments','geography_admin_assignment_guard','geography_admin_assignment_guard'),
          ('staff_admin_city_assignments','geography_admin_assignment_write','rbac_lock_write'),
          ('technician_city_memberships','geography_membership_write','rbac_lock_write'),
          ('technician_service_areas','geography_zone_write','rbac_lock_write'),
          ('staff_role_assignments','rbac_assignment_write','rbac_lock_write'),('staff_role_assignments','rbac_guard_assignment','rbac_guard_assignment'),
          ('staff_role_assignments','rbac_assignment_current','rbac_check_staff'),('staff_web_credentials','rbac_credential_removal','rbac_lock_write'),
          ('staff_web_credentials','rbac_credential_current','rbac_check_staff')) required(tab,trig,fn)
          WHERE NOT EXISTS (SELECT FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid=to_regclass(format('foundation.%I', required.tab)) AND t.tgname=required.trig AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal
              AND p.pronamespace='foundation'::regnamespace AND p.proname=required.fn AND NOT p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']
              AND NOT has_function_privilege('fixlevelup_runtime',p.oid,'EXECUTE')
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
              AND p.proconfig @> ARRAY['search_path=pg_catalog'] AND p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime')
              AND has_function_privilege('fixlevelup_runtime',p.oid,'EXECUTE')
              AND NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')))
        AS ready
    `;
    return rows[0]?.ready === true;
  }

}
