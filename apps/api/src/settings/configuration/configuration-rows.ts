/**
 * Row shapes and database-error translation shared by the configuration ports.
 *
 * The database CHECK/trigger/unique/FK rules remain the authority on reviewed
 * text, callback windows, same-city references and pointer CAS. This module only
 * translates a driver error into a typed refusal, so the trusted caller never
 * sees a raw constraint name, a table name or driver text.
 */
import { ConfigurationError } from './configuration-errors.js';

/* ---------------------------- row shapes ---------------------------- */

export interface SettingsRow {
  id: string;
  version: number;
  launch_mode: string;
  primary_city_id: string;
  published_at: Date;
  operator_name: string | null;
  operator_registration_id: string | null;
  operator_address: string | null;
  legal_review_ref: string | null;
  security_policy_ref: string | null;
  retention_policy_ref: string | null;
  upload_policy_ref: string | null;
}

export interface ReferenceEntryRow {
  id: string;
  type: string;
  scope: string;
  city_id: string | null;
  code: string;
  row_version: number;
  current_version_id: string | null;
  archived_at: Date | null;
}

export interface ReferenceVersionRow {
  id: string;
  entry_id: string;
  type: string;
  city_id: string | null;
  version: number;
  label: string;
  valid_from: Date;
  valid_until: Date | null;
  source_ref: string;
  published_at: Date;
  city_version_id: string | null;
  start_minute: number | null;
  end_minute: number | null;
}

export interface ContentBlockRow {
  id: string;
  code: string;
  kind: string;
  scope: string;
  city_id: string | null;
  allow_company_fallback: boolean;
  row_version: number;
  current_revision_id: string | null;
  archived_at: Date | null;
}

export interface ContentRevisionRow {
  id: string;
  block_id: string;
  version: number;
  title: string;
  body: string;
  source_ref: string;
  published_at: Date;
}

export interface LegalDocumentRow {
  purpose: string;
  kind: string;
  current_version_id: string | null;
}

export const SETTINGS_COLUMNS = `id,version,launch_mode,primary_city_id,published_at,
  operator_name,operator_registration_id,operator_address,legal_review_ref,
  security_policy_ref,retention_policy_ref,upload_policy_ref`;
export const REFERENCE_ENTRY_COLUMNS = 'id,type,scope,city_id,code,row_version,current_version_id,archived_at';
export const REFERENCE_VERSION_COLUMNS = `id,entry_id,type,city_id,version,label,valid_from,valid_until,
  source_ref,published_at,city_version_id,start_minute,end_minute`;
export const CONTENT_BLOCK_COLUMNS = `id,code,kind,scope,city_id,allow_company_fallback,row_version,
  current_revision_id,archived_at`;
export const CONTENT_REVISION_COLUMNS = 'id,block_id,version,title,body,source_ref,published_at';

/* ------------------------- error translation ------------------------- */

interface DatabaseError {
  readonly code?: unknown;
  readonly constraint?: unknown;
}

function databaseError(error: unknown): DatabaseError | null {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return null;
  }
  const candidate = error as { code: unknown; constraint?: unknown };
  return typeof candidate.code === 'string'
    ? { code: candidate.code, constraint: candidate.constraint }
    : null;
}

/**
 * Maps a PostgreSQL SQLSTATE to a typed refusal.
 *
 * - unique violation: the stable identity (type+code, scope+city+code, entry+version) already exists;
 * - check/trigger refusal: a reviewed value violated a database rule;
 * - FK violation: the named city/version/staff does not exist (pre-checks make the
 *   city cases a NOT_FOUND before SQL, so this is the same-city/foreign-row guard);
 * - serialization/deadlock/lock timeout/cancel: the caller should retry the whole
 *   transaction, so it is a typed CONFLICT instead of an unhandled driver error;
 * - anything else (including 42501, a privilege regression) propagates unchanged,
 *   because that is an operational defect and not a client error.
 */
export function mapDatabaseError(error: unknown): never {
  if (error instanceof ConfigurationError) {
    throw error;
  }
  const mapped = databaseError(error);
  if (mapped === null) {
    throw error;
  }
  switch (mapped.code) {
    case '23505':
      throw new ConfigurationError('CONFLICT', 'identity');
    case '23503':
      throw new ConfigurationError('NOT_FOUND', 'reference');
    case '23514':
    case '22001':
    case '22007':
    case '22008':
    case '22P02':
      throw new ConfigurationError('INVALID_INPUT', 'value');
    case '40001':
    case '40P01':
    case '55P03':
    case '57014':
      throw new ConfigurationError('CONFLICT', 'concurrency');
    default:
      throw error;
  }
}
