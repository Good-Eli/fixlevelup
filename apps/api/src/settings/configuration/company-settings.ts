/**
 * Internal company-settings port (P03-03).
 *
 * Scope: the company-wide policy revision only — legal identity, security,
 * retention and upload policy *references*, plus the launch mode and primary city
 * pointer. City timezone, public contact and office hours live exclusively in
 * `service_city_versions` and are never read or written here, so there is exactly
 * one editable source for each value.
 *
 * A policy reference is reviewed provenance of a decision made elsewhere. This
 * module never interprets, executes or invents a policy: it stores the reference
 * the reviewer approved. No default operator, address, policy or retention value
 * is created by this code or by the migration.
 *
 * ## Read vs write shapes
 *
 * A historical revision may predate a policy column (the migration adds them as
 * nullable), so a *read* keeps an unknown field as `null` instead of mapping it to
 * an empty string: an empty string would be indistinguishable from a reviewed
 * empty value. A *write* accepts only non-empty strings, because the contract
 * refuses a partially configured revision.
 *
 * ## Caller transaction
 *
 * Every write function requires the caller's explicit transaction and takes the
 * shared company advisory lock (`acquireCompanySettingsLock`) as its first
 * statement, before any city read or FK check, so a settings publish and a
 * geography primary change cannot interleave their `max(version)+1` sequence or
 * invert the city/company lock order.
 *
 * ## What is deliberately absent
 *
 * No HTTP controller, NestJS provider, DI registration, capability check, session
 * proof or authorization decision: authentication and capability policy stay an
 * external mandatory port (P03-05/P05). `actorStaffId` is a server-trusted staff
 * identity supplied by that port, never a browser value.
 *
 * ## CAS, not idempotency
 *
 * The port is compare-and-swap on the published version, nothing more. It keeps no
 * idempotency key or write receipt: an HTTP retry/replay policy belongs to the
 * trusted command layer of P03-05, which can add a receipt table around these
 * calls without changing them.
 */
import { randomUUID } from 'node:crypto';
import { acquireCompanySettingsLock } from './company-lock.js';
import { writeConfigurationAudit } from './configuration-audit.js';
import { ConfigurationError, conflict, invalid, notFound, staleVersion } from './configuration-errors.js';
import {
  COMPANY_SETTINGS_COLUMNS, COMPANY_SETTINGS_FIELDS, companySettingsPublishInput, requireUuid,
} from './configuration-input.js';
import type { CompanySettingsField, CompanySettingsPublishInput } from './configuration-input.js';
import type { ConfigurationClient } from './configuration-port.js';
import { mapDatabaseError, SETTINGS_COLUMNS } from './configuration-rows.js';
import type { LegalDocumentRow, SettingsRow } from './configuration-rows.js';

/**
 * Default purposes whose consent document must be current before intake.
 *
 * Deliberately `REQUEST_PROCESSING` only: whether `ADDRESS_COVERAGE` needs its own
 * consent is an open product/legal question (Q02), so requiring it here would
 * silently answer it. A caller with an approved policy passes its own list.
 */
export const DEFAULT_REQUIRED_CONSENT_PURPOSES: readonly string[] = Object.freeze(['REQUEST_PROCESSING']);
/** Purposes the vocabulary recognises; a caller-supplied list must stay inside it. */
export const KNOWN_CONSENT_PURPOSES: readonly string[] = Object.freeze([
  'REQUEST_PROCESSING', 'ADDRESS_COVERAGE', 'MARKETING',
]);
/** Document kind readiness requires: a consent form, not a policy document. */
export const CONSENT_DOCUMENT_KIND = 'CONSENT_FORM';

/**
 * Stored policy values of one revision. `null` means the revision leaves the field
 * unknown (a revision published before the column existed, or before the field was
 * reviewed). It is never coerced to `''`.
 */
export type StoredCompanySettings = Readonly<Record<CompanySettingsField, string | null>>;

export interface CompanySettingsView {
  readonly id: string;
  readonly version: number;
  readonly launchMode: string;
  readonly primaryCityId: string;
  readonly publishedAt: string;
  /** Reviewer of *this* revision (publisher), not the author of a carried ref. */
  readonly reviewedBy: string;
  readonly settings: StoredCompanySettings;
}

export interface CompanySettingsPublishReceipt {
  readonly id: string;
  readonly version: number;
  readonly launchMode: string;
  readonly primaryCityId: string;
  readonly previousVersion: number;
  /**
   * Policy fields carried forward unchanged from the previous revision. They are
   * provenance of an earlier review, not a fresh review of this revision.
   */
  readonly carriedFields: readonly CompanySettingsField[];
}

export interface CompanySettingsHistory {
  readonly items: readonly CompanySettingsView[];
}

export interface ConsentDocumentStatus {
  readonly purpose: string;
  readonly kind: string | null;
  /** A current version exists for a consent-form document of this purpose. */
  readonly current: boolean;
}

/**
 * Readiness of this slice only. It is not an intake or production readiness
 * statement: geography/city resolution, prices, schedules and provider
 * connections are separate gates owned by their own modules.
 */
export interface CompanySettingsReadiness {
  readonly ready: boolean;
  readonly latestVersion: number | null;
  readonly launchMode: string | null;
  readonly primaryCityId: string | null;
  /** Concrete policy fields the latest revision leaves unknown. */
  readonly missingFields: readonly CompanySettingsField[];
  readonly documents: readonly ConsentDocumentStatus[];
  /** Purposes with no current consent-form document. */
  readonly missingDocuments: readonly string[];
}

function storedSettings(row: SettingsRow): StoredCompanySettings {
  const settings: Partial<Record<CompanySettingsField, string | null>> = {};
  for (const field of COMPANY_SETTINGS_FIELDS) {
    const value = row[COMPANY_SETTINGS_COLUMNS[field] as keyof SettingsRow];
    settings[field] = typeof value === 'string' && value.trim().length > 0 ? value : null;
  }
  return Object.freeze(settings as Record<CompanySettingsField, string | null>);
}

function view(row: SettingsRow & { reviewed_by?: string }): CompanySettingsView {
  return {
    id: row.id,
    version: row.version,
    launchMode: row.launch_mode,
    primaryCityId: row.primary_city_id,
    publishedAt: row.published_at.toISOString(),
    reviewedBy: row.reviewed_by ?? '',
    settings: storedSettings(row),
  };
}

async function latestSettings(client: ConfigurationClient): Promise<SettingsRow | null> {
  const result = await client.query<SettingsRow>(
    `SELECT ${SETTINGS_COLUMNS},reviewed_by FROM foundation.business_settings_versions ORDER BY version DESC LIMIT 1`);
  return result.rows[0] ?? null;
}

/** Fields the revision leaves NULL (or, defensively, blank). */
function missingFields(row: SettingsRow): readonly CompanySettingsField[] {
  return COMPANY_SETTINGS_FIELDS.filter((field) => {
    const value = row[COMPANY_SETTINGS_COLUMNS[field] as keyof SettingsRow];
    return typeof value !== 'string' || value.trim().length === 0;
  });
}

/**
 * Publishes one fully configured immutable company revision.
 *
 * The input is re-validated here even though the caller is trusted internal code:
 * a caller that skipped the parser must not be able to publish a whitespace-only
 * operator name or an unexpected key.
 *
 * `expectedLastVersion` is the version the caller last read (`0` when the company
 * has none). It must equal the current latest version, otherwise the write is
 * refused as stale: a publisher never silently overwrites a revision someone else
 * published, and two publishers cannot claim the same number because the shared
 * advisory lock serializes them.
 *
 * `launch_mode` and `primary_city_id` are carried forward from the latest
 * revision. A settings publish cannot switch the primary city or the launch mode:
 * that is a geography decision (`cityActivate` / `citySetPrimary`) with its own
 * reviewed snapshot, so company policy publishing stays company-scoped. A latest
 * revision in an unsupported launch mode is not carried forward silently either —
 * geography owns that transition.
 *
 * The first company revision is created by geography activation, because a
 * revision requires a primary city. Publishing policies before any city exists is
 * therefore refused instead of inventing a city.
 */
export async function publishCompanySettings(
  client: ConfigurationClient,
  actorStaffId: unknown,
  input: unknown,
): Promise<CompanySettingsPublishReceipt> {
  const actor = requireUuid(actorStaffId, 'actorStaffId');
  const parsed: CompanySettingsPublishInput = companySettingsPublishInput(input);
  await acquireCompanySettingsLock(client);
  const latest = await latestSettings(client);
  const currentVersion = latest?.version ?? 0;
  if (parsed.expectedLastVersion !== currentVersion) {
    staleVersion();
  }
  if (latest === null) {
    // No primary city exists yet: geography creates the first revision.
    conflict('primaryCityId');
  }
  const carriedFields = COMPANY_SETTINGS_FIELDS.filter((field) => {
    const stored = latest[COMPANY_SETTINGS_COLUMNS[field] as keyof SettingsRow];
    return typeof stored === 'string' && stored.trim().length > 0 && stored === parsed.settings[field];
  });
  const columns = COMPANY_SETTINGS_FIELDS.map((field) => COMPANY_SETTINGS_COLUMNS[field]);
  const parameters = COMPANY_SETTINGS_FIELDS.map((field) => parsed.settings[field]);
  const insert = await client.query<{ id: string; version: number; published_at: Date }>(
    `INSERT INTO foundation.business_settings_versions
       (id,version,launch_mode,primary_city_id,reviewed_by,${columns.join(',')})
     VALUES ($1,$2,$3,$4,$5,${columns.map((_, index) => `$${String(index + 6)}`).join(',')})
     RETURNING id,version,published_at`,
    [randomUUID(), latest.version + 1, latest.launch_mode, latest.primary_city_id, actor, ...parameters],
  ).catch(mapDatabaseError);
  const row = insert.rows[0];
  if (!row) {
    conflict('version');
  }
  await writeConfigurationAudit({
    client,
    operation: 'settings.publish',
    details: {
      actorStaffId: actor,
      entity: 'SETTINGS',
      entityId: row.id,
      version: row.version,
      previousVersion: latest.version,
    },
  });
  return {
    id: row.id,
    version: row.version,
    launchMode: latest.launch_mode,
    primaryCityId: latest.primary_city_id,
    previousVersion: latest.version,
    carriedFields,
  };
}

/** Latest published company revision, or `null` when the company has none. */
export async function readCompanySettings(client: ConfigurationClient): Promise<CompanySettingsView | null> {
  const row = await latestSettings(client);
  return row === null ? null : view(row);
}

/** Bounded newest-first history of company revisions (no secrets, no city values). */
export async function listCompanySettingsHistory(
  client: ConfigurationClient,
  limit: unknown = 50,
): Promise<CompanySettingsHistory> {
  const bounded = typeof limit === 'number' && Number.isSafeInteger(limit) && limit >= 1 && limit <= 200
    ? limit : invalid('limit');
  const result = await client.query<SettingsRow>(
    `SELECT ${SETTINGS_COLUMNS},reviewed_by FROM foundation.business_settings_versions ORDER BY version DESC LIMIT $1`,
    [bounded]);
  return { items: result.rows.map(view) };
}

/** Exact historical revision; a version number that does not exist is NOT_FOUND. */
export async function readCompanySettingsVersion(
  client: ConfigurationClient,
  version: unknown,
): Promise<CompanySettingsView> {
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) {
    invalid('version');
  }
  const result = await client.query<SettingsRow>(
    `SELECT ${SETTINGS_COLUMNS},reviewed_by FROM foundation.business_settings_versions WHERE version=$1`, [version]);
  const row = result.rows[0];
  if (!row) {
    notFound('version');
  }
  return view(row);
}

/**
 * Readiness of the company-settings slice.
 *
 * Reports the concrete missing policy fields and, per purpose in
 * `requiredPurposes`, whether a current *consent-form* document exists. The
 * default list is `REQUEST_PROCESSING` only; a caller with an approved policy may
 * pass `ADDRESS_COVERAGE`/`MARKETING` explicitly, which keeps the unresolved Q02
 * question out of this module's defaults.
 *
 * The document lookup filters by kind in SQL, so a policy/other document of the
 * same purpose can never be mistaken for a current consent form.
 *
 * It never claims that intake is open: a readiness report is a snapshot of
 * configuration, not an acceptance of requests.
 */
export async function readCompanySettingsReadiness(
  client: ConfigurationClient,
  requiredPurposes: unknown = DEFAULT_REQUIRED_CONSENT_PURPOSES,
): Promise<CompanySettingsReadiness> {
  const purposes = consentPurposes(requiredPurposes);
  const latest = await latestSettings(client);
  const documents = await client.query<LegalDocumentRow>(
    `SELECT purpose,kind,current_version_id FROM foundation.legal_documents
     WHERE purpose=ANY($1::text[]) AND kind=$2`,
    [purposes, CONSENT_DOCUMENT_KIND]);
  const byPurpose = new Map(documents.rows.map((row) => [row.purpose, row]));
  const statuses: ConsentDocumentStatus[] = purposes.map((purpose) => {
    const row = byPurpose.get(purpose);
    return {
      purpose,
      kind: row?.kind ?? null,
      current: row !== undefined && row.current_version_id !== null,
    };
  });
  const missingDocuments = statuses.filter((status) => !status.current).map((status) => status.purpose);
  const missing = latest === null ? COMPANY_SETTINGS_FIELDS : missingFields(latest);
  return {
    ready: latest !== null && missing.length === 0 && missingDocuments.length === 0,
    latestVersion: latest?.version ?? null,
    launchMode: latest?.launch_mode ?? null,
    primaryCityId: latest?.primary_city_id ?? null,
    missingFields: missing,
    documents: statuses,
    missingDocuments,
  };
}

function consentPurposes(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > KNOWN_CONSENT_PURPOSES.length) {
    invalid('requiredPurposes');
  }
  const purposes: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || !KNOWN_CONSENT_PURPOSES.includes(entry) || purposes.includes(entry)) {
      invalid('requiredPurposes');
    }
    purposes.push(entry);
  }
  return purposes;
}

/**
 * Guard for a caller that reads readiness first: publishing is refused while a
 * required field or consent document is missing. The typed publisher already
 * rejects blank values, so this exists for one explicit refusal code.
 */
export function requireCompleteSettings(readiness: CompanySettingsReadiness): void {
  if (!readiness.ready) {
    throw new ConfigurationError('INCOMPLETE',
      readiness.missingFields[0] ?? readiness.missingDocuments[0] ?? 'settings');
  }
}
