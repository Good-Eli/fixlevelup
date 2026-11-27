import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { SingleCityContext } from '../../settings/geography/city-context.js';
import type { StaffEvidence } from '../intake/basis.js';
import { REQUEST_RECEIPT_COMPLETE_SQL } from '../intake/effects.js';
import { deny } from '../intake/errors.js';
import { isRegistryInstant } from './filters.js';
import type { RegistryQuery } from './filters.js';
import { SEARCH_RESULT_LIMIT } from '../search/contract.js';

interface RegistryPosition {
  readonly createdAt: string;
  readonly publicNumber: string;
}

export interface RegistryItem extends RegistryPosition {
  readonly id: string;
  readonly type: string;
  readonly status: string;
  readonly version: number;
}

export interface RegistryRow extends RegistryItem {
  readonly evidenceId: string | null;
  readonly procedureRevision: string | null;
  readonly validUntil: Date | null;
}

export const registryVisibleFields = `request.id, request.public_number::text AS "publicNumber",
  to_char(request.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt",
  request.type, request.status, request.row_version AS version,
  manual.id AS "evidenceId", manual.procedure_revision AS "procedureRevision", manual.valid_until AS "validUntil"`;

export const registryBasisJoins = `
  LEFT JOIN foundation.request_session_submits AS submit ON submit.request_id = request.id
  LEFT JOIN foundation.request_staff_evidence AS manual
    ON manual.request_id = request.id AND manual.purpose = 'MANUAL_INTAKE'`;

export function registryVisibilitySql(requireCurrentDocument: boolean): string {
  return `(EXISTS (
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
      ${requireCurrentDocument ? 'AND document.current_version_id = consent.document_version_id' : ''}
      AND NOT EXISTS (SELECT FROM foundation.consent_records AS revoked WHERE revoked.supersedes_id = consent.id)
      AND ${REQUEST_RECEIPT_COMPLETE_SQL}
  ) OR (submit.request_id IS NULL AND manual.valid_until > statement_timestamp()))`;
}

export function readRegistryEvidence(row: Pick<RegistryRow,'evidenceId'|'procedureRevision'|'validUntil'>): StaffEvidence | null {
  if (row.evidenceId === null) { return null; }
  if (row.procedureRevision === null || row.validUntil === null) { return deny('NOT_READY'); }
  return { id:row.evidenceId,procedureRevision:row.procedureRevision,validUntil:row.validUntil };
}

const MIN_SCAN_SIZE = 30;

function cursorScope(city: SingleCityContext, query: RegistryQuery): string {
  return createHash('sha256').update(JSON.stringify([
    'p06-registry-v1', city.cityId, city.cityVersionId, query.from, query.to, query.status, query.urgency,
    query.categoryId, query.districtId, query.sourceId, query.contactMode, query.provider,
  ])).digest('hex');
}

const searchMatch = {
  number:'request.public_number = $2::bigint',
  name:'token.name_token = $2::bytea',
  phone:'token.phone_token = $2::bytea',
};

const searchJoin = `JOIN p06_crm.contact_search AS token ON token.request_id=request.id AND token.city_id=request.city_id
  AND token.contact_revision_id=request.current_contact_revision_id`;

/** A phone search may expose the association even without returning the phone itself. */
export const livePhonePermission = `EXISTS (
  SELECT FROM foundation.request_preference_revisions AS preference
  JOIN foundation.phone_permission_events AS permission ON permission.request_id=preference.request_id
  WHERE preference.request_id=request.id AND preference.id=request.current_preference_revision_id
    AND preference.contact_mode='PHONE' AND permission.contact_revision_id=request.current_contact_revision_id
    AND permission.purpose='REQUEST_SERVICE_CALL' AND permission.action='GIVEN'
    AND NOT EXISTS (SELECT FROM foundation.phone_permission_events AS revoked WHERE revoked.supersedes_given_id=permission.id)
)`;

export async function readRegistrySearch(client: PoolClient, cityId: string,
  query: { kind:'number'; key:string } | { kind:'name'|'phone'; key:Buffer },
  isCurrent: ((evidence: StaffEvidence) => boolean) | undefined) {
  const byContact = query.kind !== 'number';
  const from = `FROM foundation.requests AS request ${byContact ? searchJoin : ''}`;
  const selection = `SELECT ${registryVisibleFields} ${from} ${registryBasisJoins}
    WHERE request.city_id=$1 ${byContact ? 'AND token.city_id=$1' : ''} AND ${searchMatch[query.kind]}
      AND ${registryVisibilitySql(byContact)} ${query.kind === 'phone' ? `AND ${livePhonePermission}` : ''}`;
  const order = byContact ? 'token' : 'request';
  const wanted = await collectSearchMatches(client,selection,order,[cityId,query.key],isCurrent);
  if (!wanted.length) { return { items:[],manualEvidence:[],truncated:false }; }
  // Lock only the bounded final set in one globally ordered pass. RC then verifies
  // the live index and source again after any wait on those rows.
  const ids = wanted.map(row => row.id);
  await client.query('SELECT id FROM foundation.requests WHERE id=ANY($1::uuid[]) AND city_id=$2 ORDER BY id FOR SHARE', [ids,cityId]);
  const { rows } = await client.query<RegistryRow>(`${selection}
    AND request.id=ANY($3::uuid[]) ORDER BY request.created_at DESC, request.public_number DESC`,[cityId,query.key,ids]);
  if (rows.length !== ids.length) { return deny('NOT_READY'); }
  const manualEvidence: StaffEvidence[] = [];
  for (const row of rows) {
    const evidence = readRegistryEvidence(row);
    if (evidence) { manualEvidence.push(evidence); }
  }
  const items = rows.slice(0,SEARCH_RESULT_LIMIT).map(({id,publicNumber,createdAt,type,status,version}) =>
    ({id,publicNumber,createdAt,type,status,version}));
  return { items,manualEvidence,truncated:rows.length > SEARCH_RESULT_LIMIT };
}

async function collectSearchMatches(client: PoolClient, selection: string, order: 'token'|'request', bind: [string,string|Buffer],
  isCurrent: ((evidence: StaffEvidence) => boolean) | undefined) {
  const batchSize = 64;
  const visible: RegistryRow[] = [];
  let after: RegistryPosition | undefined;
  for (let batch = 0; batch < 8; batch++) {
    const cursor = after ? `AND (${order}.created_at,${order}.public_number) < ($3::timestamptz,$4::bigint)` : '';
    const { rows } = await client.query<RegistryRow>(`${selection} ${cursor}
      ORDER BY ${order}.created_at DESC,${order}.public_number DESC LIMIT ${String(batchSize)}`,
    after ? [...bind,after.createdAt,after.publicNumber] : bind);
    for (const row of rows) {
      const evidence = readRegistryEvidence(row);
      if (evidence && !isCurrent?.(evidence)) { continue; }
      visible.push(row);
      if (visible.length > SEARCH_RESULT_LIMIT) { return visible; }
    }
    if (rows.length < batchSize) { return visible; }
    after = rows.at(-1);
  }
  return deny('NOT_READY');
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
    SELECT ${registryVisibleFields}
    FROM foundation.requests AS request
    LEFT JOIN foundation.request_appliance_revisions AS appliance
      ON appliance.request_id = request.id AND appliance.id = request.current_appliance_revision_id
    LEFT JOIN foundation.request_address_revisions AS address
      ON address.request_id = request.id AND address.id = request.current_address_revision_id
    LEFT JOIN foundation.request_preference_revisions AS preference
      ON preference.request_id = request.id AND preference.id = request.current_preference_revision_id
    LEFT JOIN foundation.request_intake_provenance AS source ON source.request_id = request.id
    LEFT JOIN foundation.request_channel_choices AS channel ON channel.request_id = request.id
    ${registryBasisJoins}
    WHERE ${predicates.join(' AND ')} AND ${registryVisibilitySql(false)}
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
      const evidence = readRegistryEvidence(row);
      if (evidence) {
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
