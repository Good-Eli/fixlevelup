import { randomUUID } from 'node:crypto';
import type { SingleCityContext } from '../../settings/geography/city-context.js';
import { CALLBACK_AUTHORITY, DASHBOARD_PAGE_SIZE, DASHBOARD_VERSION, QUEUE_STATUSES, READY_METRICS, UNAVAILABLE_METRICS } from './contract.js';
import type { DashboardLink, ReadyMetric } from './contract.js';
import type { DashboardMaterial } from './store.js';

export interface DashboardSubject extends SingleCityContext {
  readonly staffId: string;
  readonly sessionId: string;
}

export interface DashboardSnapshot {
  readonly id: string;
  readonly subject: DashboardSubject;
  readonly material: DashboardMaterial;
  readonly expiresAt: number;
}

const TTL_MS = 90_000;
const CAPACITY = 24;

/** Process-local ephemeral data for the isolated composition. No bearer authorization. */
export class DashboardSnapshots {
  private readonly snapshots = new Map<string,DashboardSnapshot>();

  constructor(private readonly monotonicNow: () => number = () => performance.now()) {}

  issue(subject: DashboardSubject, material: DashboardMaterial): DashboardSnapshot {
    return {id:randomUUID(),subject,material,expiresAt:this.monotonicNow()+TTL_MS};
  }

  remember(snapshot: DashboardSnapshot) {
    for (const [id,existing] of this.snapshots) {
      if (!this.live(existing)) { this.snapshots.delete(id); }
    }
    if (this.snapshots.size >= CAPACITY) {
      const oldest = this.snapshots.keys().next().value;
      if (oldest !== undefined) { this.snapshots.delete(oldest); }
    }
    this.snapshots.set(snapshot.id,snapshot);
  }

  live(snapshot: DashboardSnapshot) {
    return snapshot.expiresAt > this.monotonicNow();
  }

  find(id: string, subject: DashboardSubject) {
    const snapshot = this.snapshots.get(id);
    if (!snapshot) { return undefined; }
    const owner = snapshot.subject;
    if (owner.staffId !== subject.staffId || owner.sessionId !== subject.sessionId
      || owner.cityId !== subject.cityId || owner.cityVersionId !== subject.cityVersionId || owner.timezone !== subject.timezone
      || !this.live(snapshot)) { return undefined; }
    return snapshot;
  }
}

const keys = Object.keys(READY_METRICS) as ReadyMetric[];

function appliedFilters(metric: ReadyMetric, localDay: DashboardMaterial['localDay']) {
  if (metric === 'createdToday') { return localDay; }
  const statuses = QUEUE_STATUSES[metric];
  return metric === 'callbackRequired' ? {statuses,...CALLBACK_AUTHORITY} : {statuses};
}

export function dashboardDto({id,subject,material}: DashboardSnapshot) {
  const ready = keys.map(metric => [metric,{
    state:'ready',
    count:material.queues[metric].length,
    basis:READY_METRICS[metric],
    appliedFilters:appliedFilters(metric,material.localDay),
    href:`/crm/requests?snapshot=${id}&metric=${metric}`,
  }] as const);
  const unavailable = UNAVAILABLE_METRICS.map(metric => [metric,{state:'not_ready'}] as const);
  const metrics = Object.fromEntries<(typeof ready)[number][1] | (typeof unavailable)[number][1]>([...ready,...unavailable]);
  return {snapshotId:id,asOf:material.asOf,definitionsVersion:DASHBOARD_VERSION,cityId:subject.cityId,cityVersionId:subject.cityVersionId,
    timezone:subject.timezone,localDay:material.localDay,metrics};
}

export function dashboardPage(snapshot: DashboardSnapshot, link: DashboardLink, refreshed: boolean) {
  const queue = snapshot.material.queues[link.metric];
  const offset = refreshed ? 0 : link.offset;
  const next = offset + DASHBOARD_PAGE_SIZE;
  return {snapshot:dashboardDto(snapshot),metric:link.metric,items:queue.slice(offset,next),
    nextOffset:next < queue.length ? next : null,refreshed};
}
