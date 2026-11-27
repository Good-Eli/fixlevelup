import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { SingleCityContext } from '../../settings/geography/city-context.js';
import type { StaffEvidence } from '../intake/basis.js';
import { REQUEST_RECEIPT_COMPLETE_SQL } from '../intake/effects.js';
import { deny } from '../intake/errors.js';
import { isRegistryInstant } from './filters.js';
import type { RegistryQuery } from './filters.js';

interface RegistryPosition {
  readonly createdAt: string;
  readonly publicNumber: string;
}

interface RegistryItem extends RegistryPosition {
  readonly id: string;
  readonly type: string;
  readonly status: string;
  readonly version: number;
}

interface RegistryRow extends RegistryItem {
  readonly evidenceId: string | null;
  readonly procedureRevision: string | null;
  readonly validUntil: Date | null;
}

const MIN_SCAN_SIZE = 30;

function cursorScope(city: SingleCityContext, query: RegistryQuery): string {
  return createHash('sha256').update(JSON.stringify([
    'p06-registry-v1', city.cityId, city.cityVersionId, query.from, query.to, query.status, query.urgency,
    query.categoryId, query.districtId, query.sourceId, query.contactMode, query.provider,
  ])).digest('hex');
}

function cursorPosition(cursor: string, scope: string): RegistryPosition {
  const [createdAt, publicNumber, digest, extra] = cursor.split('~', 4);
  if (extra !== undefined || digest !== scope || createdAt === undefined || !isRegistryInstant(createdAt)
    || publicNumber === undefined || !/^[1-9]\d{0,18}$/.test(publicNumber)
    || BigInt(publicNumber) > 9223372036854775807n) {
    return deny('INVALID_REQUEST');
  }
  return { createdAt, publicNumber };
}

async function scanRegistry(client: Pick<PoolClient, 'query'>, city: SingleCityContext, query: RegistryQuery,
  after: RegistryPosition | null, scanSize: number) {
  const values: (string | number)[] = [city.cityId];
  const predicates = ['request.city_id = $1'];
  const bind = (value: string | number): string => '$' + String(values.push(value));
  const filters = [
    ['request.created_at >=', query.from],
    ['request.created_at <', query.to],
    ['request.status =', query.status],
    ['appliance.category_id =', query.categoryId],
    ['address.district_id =', query.districtId],
    ['preference.urgency =', query.urgency],
    ['preference.contact_mode =', query.contactMode === 'CHANNEL' ? 'MESSENGER' : query.contactMode],
    ['source.source_entry_id =', query.sourceId],
    ['channel.provider =', query.provider],
  ] as const;
  for (const [expression, value] of filters) {
    if (value !== null) { predicates.push(expression + ' ' + bind(value)); }
  }
  if (after !== null) {
    predicates.push(`(request.created_at, request.public_number) < (${bind(after.createdAt)}::timestamptz, ${bind(after.publicNumber)}::bigint)`);
  }
  const { rows } = await client.query<RegistryRow>(`
    SELECT request.id, request.public_number::text AS "publicNumber",
      to_char(request.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt",
      request.type, request.status, request.row_version AS version,
      manual.id AS "evidenceId", manual.procedure_revision AS "procedureRevision", manual.valid_until AS "validUntil"
    FROM foundation.requests AS request
    LEFT JOIN foundation.request_appliance_revisions AS appliance
      ON appliance.request_id = request.id AND appliance.id = request.current_appliance_revision_id
    LEFT JOIN foundation.request_address_revisions AS address
      ON address.request_id = request.id AND address.id = request.current_address_revision_id
    LEFT JOIN foundation.request_preference_revisions AS preference
      ON preference.request_id = request.id AND preference.id = request.current_preference_revision_id
    LEFT JOIN foundation.request_intake_provenance AS source ON source.request_id = request.id
    LEFT JOIN foundation.request_channel_choices AS channel ON channel.request_id = request.id
    LEFT JOIN foundation.request_session_submits AS submit ON submit.request_id = request.id
    LEFT JOIN foundation.request_staff_evidence AS manual
      ON manual.request_id = request.id AND manual.purpose = 'MANUAL_INTAKE'
    WHERE ${predicates.join(' AND ')}
      AND (EXISTS (
        SELECT FROM foundation.consent_records AS consent
        JOIN foundation.legal_documents AS document ON document.id = consent.document_id
        JOIN foundation.request_events AS e ON e.id = submit.event_id AND e.request_id = submit.request_id
          AND e.command = submit.submit_command AND e.principal = 'F:' || submit.session_id::text AND e.resulting_version = 1
        JOIN foundation.request_command_receipts AS r ON r.event_id = e.id AND r.request_id = e.request_id
          AND r.version = e.resulting_version AND r.correlation_id = e.correlation_id AND r.command = e.command
          AND r.resulting_status = e.details->>'status' AND octet_length(r.fingerprint) = 32 AND r.version <= request.row_version
        LEFT JOIN foundation.audit_logs AS a ON a.id = r.audit_id
        LEFT JOIN foundation.outbox_events AS o ON o.id = r.outbox_id
        WHERE consent.session_id = submit.session_id AND consent.id = submit.consent_id
          AND consent.document_id = submit.document_id AND consent.document_version_id = submit.document_version_id
          AND consent.purpose = 'REQUEST_PROCESSING' AND consent.action = 'GIVEN' AND consent.source = 'FORM'
          AND document.purpose = 'REQUEST_PROCESSING' AND document.kind = 'CONSENT_FORM'
          AND NOT EXISTS (SELECT FROM foundation.consent_records AS revoked WHERE revoked.supersedes_id = consent.id)
          AND ${REQUEST_RECEIPT_COMPLETE_SQL}
      ) OR (submit.request_id IS NULL AND manual.valid_until > statement_timestamp()))
    ORDER BY request.created_at DESC, request.public_number DESC
    LIMIT ${bind(scanSize)}
  `, values);
  return rows;
}

/** The caller authorizes the city and holds the legal document lock through the final proof. */
export async function readVisibleRegistry(client: PoolClient, city: SingleCityContext, query: RegistryQuery,
  isCurrent: ((evidence: StaffEvidence) => boolean) | undefined) {
  const scope = cursorScope(city, query);
  let after = query.cursor === null ? null : cursorPosition(query.cursor, scope);
  const visible: RegistryItem[] = [];
  const scanSize = Math.max(MIN_SCAN_SIZE, query.limit + 1);
  const manualEvidence: StaffEvidence[] = [];
  while (visible.length <= query.limit) {
    const rows = await scanRegistry(client, city, query, after, scanSize);
    for (const row of rows) {
      if (row.evidenceId !== null) {
        if (row.procedureRevision === null || row.validUntil === null) { return deny('NOT_READY'); }
        const evidence = { id: row.evidenceId, procedureRevision: row.procedureRevision, validUntil: row.validUntil };
        if (!isCurrent?.(evidence)) { continue; }
        manualEvidence.push(evidence);
      }
      const { id, publicNumber, createdAt, type, status, version } = row;
      visible.push({ id, publicNumber, createdAt, type, status, version });
      if (visible.length > query.limit) { break; }
    }
    const lastScanned = rows.at(-1);
    if (rows.length < scanSize || lastScanned === undefined) { break; }
    after = lastScanned;
  }
  const items = visible.slice(0, query.limit);
  const last = items.at(-1);
  return {
    items, manualEvidence,
    nextCursor: visible.length > query.limit && last !== undefined
      ? `${last.createdAt}~${last.publicNumber}~${scope}` : null,
  };
}
