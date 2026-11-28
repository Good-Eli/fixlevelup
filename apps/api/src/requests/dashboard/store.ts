import type { PoolClient } from 'pg';
import type { SingleCityContext } from '../../settings/geography/city-context.js';
import type { StaffEvidence } from '../intake/basis.js';
import { deny } from '../intake/errors.js';
import { livePhonePermission, readRegistryEvidence, registryBasisJoins, registryVisibilitySql, registryVisibleFields } from '../registry/store.js';
import type { RegistryItem, RegistryRow } from '../registry/store.js';
import { DASHBOARD_CAPACITY, QUEUE_STATUSES } from './contract.js';
import type { ReadyMetric } from './contract.js';

type EvidenceCheck = (evidence: StaffEvidence) => boolean;
type Queues = Record<ReadyMetric, RegistryItem[]>;
export interface DashboardMaterial {
  readonly asOf: string;
  readonly localDay: { readonly from: string; readonly to: string };
  readonly queues: Queues;
  readonly evidence: StaffEvidence[];
}

function firstMidnight(wall: string, timezone: string) {
  const standard = `(${wall} AT TIME ZONE ${timezone})`;
  const before = `(${standard} - interval '36 hours')`;
  const offset = `((${before} AT TIME ZONE ${timezone}) - (${before} AT TIME ZONE 'UTC'))`;
  const alternative = `((${wall} - ${offset}) AT TIME ZONE 'UTC')`;
  // PostgreSQL can choose the second occurrence of a repeated midnight.
  return `LEAST(${standard}, CASE WHEN ${alternative} AT TIME ZONE ${timezone} = ${wall} THEN ${alternative} END)`;
}

/** Date arithmetic is on the city's wall clock, so a day can be 23 or 25 hours. */
export function dashboardClockSql(instant: string, timezone: string) {
  return `SELECT wall.observed, wall.midnight::date AS city_date,
    ${firstMidnight('wall.midnight',timezone)} AS day_start,
    ${firstMidnight("(wall.midnight + interval '1 day')",timezone)} AS day_end
    FROM (SELECT ${instant} AS observed,date_trunc('day',${instant} AT TIME ZONE ${timezone}) AS midnight) AS wall`;
}

const activeCallback = `request.status='${QUEUE_STATUSES.callbackRequired[0]}' AND ${livePhonePermission} AND ${registryVisibilitySql(true)}`;
const queueStatuses = [...QUEUE_STATUSES.newRequests,...QUEUE_STATUSES.awaitingChannel,...QUEUE_STATUSES.readyForAssignment];

const timestamp = (sql: string) => `to_char(${sql} AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

export async function captureDashboard(client: PoolClient, city: SingleCityContext, isCurrent: EvidenceCheck | undefined): Promise<DashboardMaterial> {
  const { rows } = await client.query<RegistryRow & { asOf:string; dayStart:string; dayEnd:string; today:boolean; callback:boolean }>(`
    WITH clock AS (${dashboardClockSql('statement_timestamp()','$2::text')}), matched AS (
      SELECT ${registryVisibleFields}, day.today, call.callback
      FROM foundation.requests AS request CROSS JOIN clock
      ${registryBasisJoins}
      CROSS JOIN LATERAL (SELECT (request.created_at AT TIME ZONE $2::text)::date = clock.city_date AS today) AS day
      CROSS JOIN LATERAL (SELECT ${activeCallback} AS callback) AS call
      WHERE request.city_id=$1 AND request.created_at <= clock.observed AND ${registryVisibilitySql(false)}
        AND (day.today OR call.callback OR request.status=ANY($3::text[]))
      ORDER BY request.created_at DESC,request.public_number DESC LIMIT ${String(DASHBOARD_CAPACITY + 1)}
    )
    SELECT ${timestamp('clock.observed')} AS "asOf",${timestamp('clock.day_start')} AS "dayStart",${timestamp('clock.day_end')} AS "dayEnd",matched.*
    FROM clock LEFT JOIN matched ON true
    ORDER BY matched."createdAt" DESC,matched."publicNumber"::bigint DESC`,[city.cityId,city.timezone,queueStatuses]);
  const first = rows[0];
  if (!first || rows.length > DASHBOARD_CAPACITY) { return deny('NOT_READY'); }
  const queues: Queues = {newRequests:[],createdToday:[],callbackRequired:[],awaitingChannel:[],readyForAssignment:[]};
  const evidence: StaffEvidence[] = [];
  for (const row of rows) {
    if (!row.id) { continue; }
    const basis = readRegistryEvidence(row);
    if (basis && !isCurrent?.(basis)) { continue; }
    if (basis) { evidence.push(basis); }
    const {id,publicNumber,type,status,version,createdAt} = row;
    const item = {id,publicNumber,type,status,version,createdAt};
    if (status === QUEUE_STATUSES.newRequests[0]) { queues.newRequests.push(item); }
    if (row.today) { queues.createdToday.push(item); }
    if (row.callback) { queues.callbackRequired.push(item); }
    if (QUEUE_STATUSES.awaitingChannel.some(value => value === status)) { queues.awaitingChannel.push(item); }
    if (status === QUEUE_STATUSES.readyForAssignment[0]) { queues.readyForAssignment.push(item); }
  }
  return {asOf:first.asOf,localDay:{from:first.dayStart,to:first.dayEnd},queues,evidence};
}

/** Verify the whole retrieved queue before serving a page. New rows belong to a later snapshot. */
export async function dashboardRowsCurrent(client: PoolClient, cityId: string, material: DashboardMaterial) {
  const unique = new Map(Object.values(material.queues).flatMap(queue => queue.map(item => [item.id,item.version] as const)));
  if (!unique.size) { return true; }
  const { rows:[proof] } = await client.query<{ total:number }>(`
    SELECT count(*)::integer AS total FROM unnest($2::uuid[],$3::integer[]) AS wanted(id,version)
    JOIN foundation.requests AS request ON request.id=wanted.id AND request.row_version=wanted.version
    ${registryBasisJoins}
    WHERE request.city_id=$1 AND ${registryVisibilitySql(false)}
      AND (request.id <> ALL($4::uuid[]) OR (${activeCallback}))`,
  [cityId,[...unique.keys()],[...unique.values()],material.queues.callbackRequired.map(item => item.id)]);
  return proof?.total === unique.size;
}
