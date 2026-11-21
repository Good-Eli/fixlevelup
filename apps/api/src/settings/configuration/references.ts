/**
 * Internal typed reference-catalogue port (P03-03).
 *
 * One stable, typed reference catalogue:
 *
 * - `CALLBACK_INTERVAL` is CITY-scoped: it names a city, a reviewed local window
 *   (`startMinute`/`endMinute`, 0 <= start < end <= 1440) and the city version it
 *   was reviewed with. It has no company fallback at all: a callback window without
 *   a city is meaningless, so an interval is never inherited from the company.
 * - `PAYMENT_METHOD`, `CANCEL_REASON`, `DECLINE_REASON` and `REQUEST_SOURCE` are
 *   COMPANY-scoped: they carry no city and no interval.
 *
 * The type decides the scope. A caller cannot choose a scope that contradicts the
 * type, and a version cannot carry another type's fields.
 *
 * ## Creation provenance vs consumption timezone
 *
 * `reference_entry_versions.city_version_id` is *creation provenance*: the city
 * version reviewed together with the label. It is never used to compute a local
 * time at consumption. `resolveReferenceForUse` takes the trusted
 * `intakeCityVersionId` of the request that consumes the interval and resolves the
 * timezone from that same-city snapshot, so a later city-version change (or an
 * earlier request) keeps its own local window while the historical label stays
 * exactly as reviewed.
 *
 * ## Caller transaction
 *
 * Reads are plain bound-parameter SELECTs. Writes run on the caller's `PoolClient`
 * inside the caller's explicit transaction and add safe audit + outbox rows in the
 * same transaction, so a failed audit rolls the publish/archive back.
 */
import { randomUUID } from 'node:crypto';
import { writeConfigurationAudit } from './configuration-audit.js';
import { assertCallerTransaction } from './configuration-tx.js';
import { ConfigurationError, conflict, notFound, staleVersion } from './configuration-errors.js';
import { REFERENCE_TYPE_SCOPE } from './configuration-input.js';
import {
  referenceArchiveInput, referenceEntryCreateInput, referenceListInput, referenceResolutionInput,
  referenceSnapshotInput, referenceVersionInput, requireUuid,
} from './configuration-input.js';
import type {
  CallbackInterval, ReferenceArchiveInput, ReferenceEntryCreateInput, ReferenceListInput,
  ReferenceResolutionInput, ReferenceScope, ReferenceSnapshotInput, ReferenceType, ReferenceVersionInput,
} from './configuration-input.js';
import type { ConfigurationClient } from './configuration-port.js';
import {
  mapDatabaseError, REFERENCE_ENTRY_COLUMNS, REFERENCE_VERSION_COLUMNS,
} from './configuration-rows.js';
import type { ReferenceEntryRow, ReferenceVersionRow } from './configuration-rows.js';

export interface ReferenceEntryView {
  readonly id: string;
  readonly type: ReferenceType;
  readonly scope: ReferenceScope;
  readonly cityId: string | null;
  readonly code: string;
  readonly version: number;
  readonly currentVersionId: string | null;
  readonly archivedAt: string | null;
}

export interface ReferenceVersionView {
  readonly id: string;
  readonly entryId: string;
  readonly type: ReferenceType;
  readonly cityId: string | null;
  readonly version: number;
  readonly label: string;
  readonly sourceRef: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
  readonly publishedAt: string;
  /**
   * Creation provenance only. The consumption timezone is resolved from the
   * caller's intake city version, never from this column.
   */
  readonly provenanceCityVersionId: string | null;
  readonly interval: CallbackInterval | null;
}

export interface ReferenceEntryReceipt {
  readonly id: string;
  readonly version: number;
}

export interface ReferenceVersionReceipt {
  readonly id: string;
  readonly entryId: string;
  readonly version: number;
  readonly entryVersion: number;
}

export interface ReferenceList {
  readonly items: readonly ReferenceEntryView[];
}

export interface ReferenceSnapshot {
  readonly entry: ReferenceEntryView;
  readonly version: ReferenceVersionView;
}

export interface ReferenceResolution {
  readonly entryId: string;
  readonly type: ReferenceType;
  readonly scope: ReferenceScope;
  readonly cityId: string | null;
  readonly versionId: string;
  readonly version: number;
  readonly label: string;
  readonly sourceRef: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
  readonly interval: CallbackInterval | null;
  /**
   * Local zone of the consuming intake city version; `null` for a COMPANY-scoped
   * type. Never the reference's creation provenance and never a global default.
   */
  readonly timezone: string | null;
  /**
   * Exact `foundation.service_city_versions.id` row that supplied `timezone`:
   * `null` for a COMPANY-scoped type. This is the id of the row actually selected
   * by the same-city resolution query, not the reference's creation provenance and
   * not a value copied from the caller's input without a database read.
   */
  readonly timezoneCityVersionId: string | null;
  /** The instant the effective check was evaluated at (caller time or database time). */
  readonly effectiveAt: string;
}

function entryView(row: ReferenceEntryRow): ReferenceEntryView {
  return {
    id: row.id,
    type: row.type as ReferenceType,
    scope: row.scope as ReferenceScope,
    cityId: row.city_id,
    code: row.code,
    version: row.row_version,
    currentVersionId: row.current_version_id,
    archivedAt: row.archived_at === null ? null : row.archived_at.toISOString(),
  };
}

function versionView(row: ReferenceVersionRow): ReferenceVersionView {
  return {
    id: row.id,
    entryId: row.entry_id,
    type: row.type as ReferenceType,
    cityId: row.city_id,
    version: row.version,
    label: row.label,
    sourceRef: row.source_ref,
    validFrom: row.valid_from.toISOString(),
    validUntil: row.valid_until === null ? null : row.valid_until.toISOString(),
    publishedAt: row.published_at.toISOString(),
    provenanceCityVersionId: row.city_version_id,
    interval: row.start_minute === null || row.end_minute === null
      ? null : Object.freeze({ startMinute: row.start_minute, endMinute: row.end_minute }),
  };
}

async function entryRow(client: ConfigurationClient, entryId: string): Promise<ReferenceEntryRow | null> {
  const result = await client.query<ReferenceEntryRow>(
    `SELECT ${REFERENCE_ENTRY_COLUMNS} FROM foundation.reference_entries WHERE id=$1`, [entryId]);
  return result.rows[0] ?? null;
}

/**
 * Creates one stable entry identity. The row is not usable until a version is
 * published; `row_version` starts at 1 and the database owns the increments.
 */
export async function createReferenceEntry(
  client: ConfigurationClient,
  actorStaffId: unknown,
  raw: unknown,
): Promise<ReferenceEntryReceipt> {
  // Re-validated here so a caller that skipped the parser still cannot reach SQL.
  const actor = requireUuid(actorStaffId, 'actorStaffId');
  const input: ReferenceEntryCreateInput = referenceEntryCreateInput(raw);
  // The caller's explicit transaction is mandatory: the entry row, its audit row and
  // its outbox event must commit or roll back together.
  await assertCallerTransaction(client);
  const scope = REFERENCE_TYPE_SCOPE[input.type];
  if (input.cityId !== null) {
    const city = await client.query('SELECT 1 FROM foundation.service_cities WHERE id=$1', [input.cityId]);
    if (city.rows.length !== 1) {
      notFound('cityId');
    }
  }
  const insert = await client.query<{ id: string; row_version: number }>(
    `INSERT INTO foundation.reference_entries (id,type,scope,city_id,code) VALUES ($1,$2,$3,$4,$5)
     RETURNING id,row_version`,
    [randomUUID(), input.type, scope, input.cityId, input.code],
  ).catch(mapDatabaseError);
  const row = insert.rows[0];
  if (!row) {
    conflict('code');
  }
  await writeConfigurationAudit({
    client,
    operation: 'reference.entry.create',
    details: {
      actorStaffId: actor,
      entity: 'REFERENCE_ENTRY',
      entityId: row.id,
      type: input.type,
      scope,
      cityId: input.cityId,
    },
  });
  return { id: row.id, version: row.row_version };
}

/**
 * Publishes one immutable reviewed version and moves the current pointer.
 *
 * `expectedVersion` is the entry's `row_version` the caller last read (the same
 * token `createReferenceEntry` returned), so two publishers cannot both append to
 * one revision. `cityVersionId` is required for a callback interval and must be a
 * version of the entry's own city; other types must not carry it. The interval is
 * required for a callback interval and forbidden for every other type.
 */
export async function publishReferenceVersion(
  client: ConfigurationClient,
  actorStaffId: unknown,
  raw: unknown,
): Promise<ReferenceVersionReceipt> {
  const actor = requireUuid(actorStaffId, 'actorStaffId');
  const input: ReferenceVersionInput = referenceVersionInput(raw);
  // Guard before any row lock: an autocommit FOR UPDATE would release instantly.
  await assertCallerTransaction(client);
  const locked = await client.query<ReferenceEntryRow>(
    `SELECT ${REFERENCE_ENTRY_COLUMNS} FROM foundation.reference_entries WHERE id=$1 FOR UPDATE`, [input.entryId]);
  const entry = locked.rows[0];
  if (!entry) {
    notFound('entryId');
  }
  if (entry.type !== input.type) {
    // A version can never change the type of an entry: the composite FK and this
    // check both refuse it, so a wrong-type publish is a conflict, not a new entry.
    conflict('type');
  }
  if (entry.archived_at !== null) {
    throw new ConfigurationError('ARCHIVED', 'entryId');
  }
  if (entry.row_version !== input.expectedVersion) {
    staleVersion();
  }
  const scope = REFERENCE_TYPE_SCOPE[input.type];
  if (scope === 'CITY') {
    if (input.cityVersionId === null || input.interval === null) {
      conflict('interval');
    }
    const cityVersion = await client.query(
      'SELECT 1 FROM foundation.service_city_versions WHERE id=$1 AND city_id=$2',
      [input.cityVersionId, entry.city_id]);
    if (cityVersion.rows.length !== 1) {
      // Same-city rule: another city's version is not creation provenance for this entry.
      notFound('cityVersionId');
    }
  } else if (input.cityVersionId !== null || input.interval !== null) {
    conflict('scope');
  }
  const next = await client.query<{ version: number }>(
    'SELECT (COALESCE(max(version),0)+1)::int AS version FROM foundation.reference_entry_versions WHERE entry_id=$1',
    [entry.id]);
  const version = next.rows[0]?.version;
  if (version === undefined) {
    conflict('version');
  }
  const insert = await client.query<{ id: string; version: number }>(
    `INSERT INTO foundation.reference_entry_versions
       (id,entry_id,type,city_id,version,label,valid_from,valid_until,source_ref,reviewed_by,
        city_version_id,start_minute,end_minute)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id,version`,
    [randomUUID(), entry.id, entry.type, entry.city_id, version, input.label, input.validFrom,
      input.validUntil, input.sourceRef, actor, input.cityVersionId,
      input.interval?.startMinute ?? null, input.interval?.endMinute ?? null],
  ).catch(mapDatabaseError);
  const row = insert.rows[0];
  if (!row) {
    conflict('version');
  }
  const moved = await client.query<{ row_version: number }>(
    'UPDATE foundation.reference_entries SET current_version_id=$2 WHERE id=$1 AND row_version=$3 RETURNING row_version',
    [entry.id, row.id, input.expectedVersion]);
  const entryVersion = moved.rows[0]?.row_version;
  if (entryVersion === undefined) {
    staleVersion();
  }
  await writeConfigurationAudit({
    client,
    operation: 'reference.version.publish',
    details: {
      actorStaffId: actor,
      entity: 'REFERENCE_VERSION',
      entityId: row.id,
      entryId: entry.id,
      type: entry.type,
      scope,
      cityId: entry.city_id,
      version: row.version,
      previousVersion: input.expectedVersion,
    },
  });
  return { id: row.id, entryId: entry.id, version: row.version, entryVersion };
}

/**
 * Archives an entry. Historical versions and their reviewed labels are untouched,
 * and the entry is no longer selected for new use. The archive itself is a CAS on
 * the entry token, so a stale caller cannot archive a revision it never saw.
 */
export async function archiveReferenceEntry(
  client: ConfigurationClient,
  actorStaffId: unknown,
  raw: unknown,
): Promise<ReferenceEntryReceipt> {
  const actor = requireUuid(actorStaffId, 'actorStaffId');
  const input: ReferenceArchiveInput = referenceArchiveInput(raw);
  await assertCallerTransaction(client);
  const locked = await client.query<ReferenceEntryRow>(
    `SELECT ${REFERENCE_ENTRY_COLUMNS} FROM foundation.reference_entries WHERE id=$1 FOR UPDATE`, [input.entryId]);
  const entry = locked.rows[0];
  if (!entry) {
    notFound('entryId');
  }
  if (entry.archived_at !== null) {
    // Archive is strictly one-way: an archived entry is never re-archived or
    // un-archived, so the operation is refused instead of silently rewriting history.
    // Checked before the token so a write-only caller cannot learn the archive state
    // from an ETag comparison.
    throw new ConfigurationError('ARCHIVED', 'entryId');
  }
  if (entry.row_version !== input.expectedVersion) {
    staleVersion();
  }
  const archived = await client.query<{ row_version: number }>(
    `UPDATE foundation.reference_entries SET archived_at=clock_timestamp()
     WHERE id=$1 AND row_version=$2 AND archived_at IS NULL RETURNING row_version`,
    [entry.id, input.expectedVersion]).catch(mapDatabaseError);
  const row = archived.rows[0];
  if (!row) {
    staleVersion();
  }
  await writeConfigurationAudit({
    client,
    operation: 'reference.entry.archive',
    details: {
      actorStaffId: actor,
      entity: 'REFERENCE_ENTRY',
      entityId: entry.id,
      type: entry.type,
      scope: entry.scope,
      cityId: entry.city_id,
      version: row.row_version,
    },
  });
  return { id: entry.id, version: row.row_version };
}

/** Bounded list of one type; archived rows are excluded unless explicitly requested. */
export async function listReferenceEntries(
  client: ConfigurationClient,
  raw: unknown,
): Promise<ReferenceList> {
  const input: ReferenceListInput = referenceListInput(raw);
  const filters = ['type=$1'];
  const parameters: unknown[] = [input.type];
  if (input.cityId !== null) {
    parameters.push(input.cityId);
    filters.push(`city_id=$${String(parameters.length)}`);
  }
  if (!input.includeArchived) {
    filters.push('archived_at IS NULL');
  }
  parameters.push(input.limit);
  const result = await client.query<ReferenceEntryRow>(
    `SELECT ${REFERENCE_ENTRY_COLUMNS} FROM foundation.reference_entries
     WHERE ${filters.join(' AND ')} ORDER BY code LIMIT $${String(parameters.length)}`, parameters);
  return { items: result.rows.map(entryView) };
}

/**
 * Exact historical snapshot: the stable entry identity plus the exact version row.
 * An archived entry stays readable, because archiving must not rewrite history.
 */
export async function readReferenceSnapshot(
  client: ConfigurationClient,
  raw: unknown,
): Promise<ReferenceSnapshot> {
  const input: ReferenceSnapshotInput = referenceSnapshotInput(raw);
  const entry = await entryRow(client, input.entryId);
  if (entry === null || entry.type !== input.type) {
    notFound('entryId');
  }
  const versionRow = input.version === null
    ? await client.query<ReferenceVersionRow>(
      `SELECT ${REFERENCE_VERSION_COLUMNS} FROM foundation.reference_entry_versions
       WHERE entry_id=$1 AND id=$2`, [entry.id, entry.current_version_id])
    : await client.query<ReferenceVersionRow>(
      `SELECT ${REFERENCE_VERSION_COLUMNS} FROM foundation.reference_entry_versions
       WHERE entry_id=$1 AND version=$2`, [entry.id, input.version]);
  const version = versionRow.rows[0];
  if (!version) {
    notFound('version');
  }
  return { entry: entryView(entry), version: versionView(version) };
}

/**
 * Resolves a reference for use at one instant.
 *
 * - the entry must not be archived, must have a current version and must be of the
 *   requested type;
 * - effectiveness (`valid_from <= at < valid_until`) is evaluated in the database:
 *   the caller's explicit instant when supplied, otherwise `clock_timestamp()`;
 * - a CITY-scoped interval resolves its timezone from the explicit trusted
 *   `intakeCityVersionId`, which must belong to the entry's own city. A stale or
 *   foreign intake version is refused, never silently replaced by a company
 *   default or the reference's creation provenance. The resolution returns the
 *   exact `service_city_versions.id` row that supplied the zone, so a caller can
 *   audit the source instead of trusting an echo of its own input.
 */
export async function resolveReferenceForUse(
  client: ConfigurationClient,
  raw: unknown,
): Promise<ReferenceResolution> {
  const input: ReferenceResolutionInput = referenceResolutionInput(raw);
  const scope = REFERENCE_TYPE_SCOPE[input.type];
  const result = await client.query<{
    entry_id: string; type: string; scope: string; city_id: string | null; archived_at: Date | null;
    version_id: string; version: number; label: string; source_ref: string;
    valid_from: Date; valid_until: Date | null; city_version_id: string | null;
    start_minute: number | null; end_minute: number | null; effective: boolean;
    effective_at: Date;
  }>(
    `SELECT e.id AS entry_id, e.type, e.scope, e.city_id, e.archived_at,
            v.id AS version_id, v.version, v.label, v.source_ref, v.valid_from, v.valid_until,
            v.city_version_id, v.start_minute, v.end_minute,
            (v.valid_from <= COALESCE($3::timestamptz, clock_timestamp())
             AND (v.valid_until IS NULL OR v.valid_until > COALESCE($3::timestamptz, clock_timestamp()))) AS effective,
            COALESCE($3::timestamptz, clock_timestamp()) AS effective_at
     FROM foundation.reference_entries AS e
     JOIN foundation.reference_entry_versions AS v ON v.entry_id=e.id AND v.id=e.current_version_id
     WHERE e.id=$1 AND e.type=$2`,
    [input.entryId, input.type, input.at]);
  const row = result.rows[0];
  if (!row) {
    notFound('entryId');
  }
  if (row.archived_at !== null) {
    throw new ConfigurationError('ARCHIVED', 'entryId');
  }
  if (!row.effective) {
    // Not yet valid or already expired at the requested instant.
    conflict('validity');
  }
  let timezone: string | null = null;
  let timezoneCityVersionId: string | null = null;
  if (scope === 'CITY') {
    if (input.intakeCityVersionId === null) {
      conflict('intakeCityVersionId');
    }
    // Select the row (not only the zone) so the DTO names the exact version that
    // supplied the timezone: the id comes from the queried row, not the request.
    const cityVersion = await client.query<{ id: string; timezone: string }>(
      'SELECT id, timezone FROM foundation.service_city_versions WHERE id=$1 AND city_id=$2',
      [input.intakeCityVersionId, row.city_id]);
    const zone = cityVersion.rows[0];
    if (!zone) {
      notFound('intakeCityVersionId');
    }
    timezone = zone.timezone;
    timezoneCityVersionId = zone.id;
  }
  return {
    entryId: row.entry_id,
    type: row.type as ReferenceType,
    scope: row.scope as ReferenceScope,
    cityId: row.city_id,
    versionId: row.version_id,
    version: row.version,
    label: row.label,
    sourceRef: row.source_ref,
    validFrom: row.valid_from.toISOString(),
    validUntil: row.valid_until === null ? null : row.valid_until.toISOString(),
    interval: row.start_minute === null || row.end_minute === null
      ? null : Object.freeze({ startMinute: row.start_minute, endMinute: row.end_minute }),
    timezone,
    timezoneCityVersionId,
    effectiveAt: row.effective_at.toISOString(),
  };
}
