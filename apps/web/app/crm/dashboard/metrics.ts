export const readyMetrics = {
  newRequests: { label: 'Новые заявки', basis: 'queue_status' },
  createdToday: { label: 'Созданы сегодня', basis: 'city_creation_day' },
  callbackRequired: { label: 'Требуют звонка', basis: 'phone_authority' },
  awaitingChannel: { label: 'Ожидают привязки канала', basis: 'queue_status' },
  readyForAssignment: { label: 'Готовы к назначению', basis: 'queue_status' },
} as const;

export const unavailableMetrics = {
  unassigned: 'Заявки без назначенного мастера',
  unconfirmedAssignments: 'Назначения без подтверждения мастера',
  visitsToday: 'Визиты сегодня',
  diagnosisOrApproval: 'Заказы в диагностике или на согласовании',
  pendingReports: 'Отчёты мастера, ожидающие проверки',
  overdueOrProblem: 'Просроченные или проблемные заявки',
  freeTechnicians: 'Свободные мастера',
} as const;

export type ReadyMetric = keyof typeof readyMetrics;
export const readyKeys = Object.keys(readyMetrics) as ReadyMetric[];
export const snapshotPageSize = 30;
export const snapshotCapacity = 2000;

export const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const snapshotUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isSnapshotOffset(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value)
    && value >= 0 && value < snapshotCapacity && value % snapshotPageSize === 0;
}

export type SnapshotQuery = { snapshot: string; metric: ReadyMetric; offset: number };

export function readSnapshotQuery(params: Record<string, string | string[] | undefined>): SnapshotQuery | 'invalid' | null {
  const { snapshot, metric, offset } = params;
  if (snapshot === undefined && metric === undefined && offset === undefined) { return null; }
  if (Object.keys(params).some(key => key !== 'snapshot' && key !== 'metric' && key !== 'offset')
    || typeof snapshot !== 'string' || !snapshotUuid.test(snapshot)
    || typeof metric !== 'string' || !Object.hasOwn(readyMetrics, metric)) {
    return 'invalid';
  }
  const pageOffset = offset === undefined ? 0 : typeof offset === 'string' && /^(?:0|[1-9][0-9]{0,3})$/.test(offset)
    ? Number(offset) : NaN;
  return isSnapshotOffset(pageOffset) ? { snapshot, metric: metric as ReadyMetric, offset: pageOffset } : 'invalid';
}

export function snapshotHref(snapshot: string, metric: ReadyMetric) {
  return `/crm/requests?snapshot=${snapshot}&metric=${metric}`;
}
