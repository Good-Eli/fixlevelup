import { deny } from '../intake/errors.js';

export const DASHBOARD_VERSION = 'p06-v1';
export const DASHBOARD_CAPACITY = 2000;
export const DASHBOARD_PAGE_SIZE = 30;

export const READY_METRICS = {
  newRequests:'queue_status',
  createdToday:'city_creation_day',
  callbackRequired:'phone_authority',
  awaitingChannel:'queue_status',
  readyForAssignment:'queue_status',
} as const;
export type ReadyMetric = keyof typeof READY_METRICS;

export const QUEUE_STATUSES = {
  newRequests:['NEW'],
  callbackRequired:['CALLBACK_REQUIRED'],
  awaitingChannel:['WAITING_TELEGRAM_LINK','WAITING_CHANNEL_LINK'],
  readyForAssignment:['WAITING_ASSIGNMENT'],
} as const;

export const CALLBACK_AUTHORITY = {
  contactMode:'PHONE',phonePermission:'active_current_revision',processing:'current',
} as const;

export const UNAVAILABLE_METRICS = ['unassigned','unconfirmedAssignments','visitsToday','diagnosisOrApproval',
  'pendingReports','overdueOrProblem','freeTechnicians'] as const;

export interface DashboardLink {
  readonly snapshot: string;
  readonly metric: ReadyMetric;
  readonly offset: number;
}

function isReadyMetric(value: string): value is ReadyMetric {
  return Object.hasOwn(READY_METRICS,value);
}

export function parseDashboardLink(query: URLSearchParams): DashboardLink | null {
  if (!query.has('snapshot') && !query.has('metric') && !query.has('offset')) { return null; }
  const keys = [...query.keys()];
  const snapshot = query.get('snapshot') ?? '';
  const metric = query.get('metric') ?? '';
  const offset = query.get('offset') ?? '0';
  if (new Set(keys).size !== keys.length || keys.some(key => key !== 'snapshot' && key !== 'metric' && key !== 'offset')
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(snapshot)
    || !isReadyMetric(metric) || !/^(?:0|[1-9]\d{0,3})$/u.test(offset) || Number(offset) >= DASHBOARD_CAPACITY
    || Number(offset) % DASHBOARD_PAGE_SIZE !== 0) { return deny('INVALID_REQUEST'); }
  return { snapshot,metric,offset:Number(offset) };
}
