export const P03_API_PREFIX = '/api/v1';
const company = '/settings/versions';
const references = '/settings/references/:type';
const content = '/content/blocks';
const legal = '/legal/documents';
const bootstrap = '/settings/management/bootstrap';
const geography = '/settings/service-cities';

/** Path templates relative to /api/v1; case-sensitive, no optional aliases. */
export const P03_ROUTES = Object.freeze({
  companyList: company, companyExact: `${company}/:version`, companyPublish: company,
  readiness: '/settings/readiness',
  referenceList: references, referenceCreate: references, referenceGet: `${references}/:id`,
  referenceVersions: `${references}/:id/versions`, referencePublish: `${references}/:id/versions`,
  referenceExact: `${references}/:id/versions/:versionId`, referenceArchive: `${references}/:id/archive`,
  contentList: content, contentCreate: content, contentGet: `${content}/:id`,
  contentRevisions: `${content}/:id/revisions`, contentExact: `${content}/:id/revisions/:revisionId`,
  contentPublish: `${content}/:id/publish`, contentArchive: `${content}/:id/archive`,
  legalList: legal, legalCreate: legal, legalGet: `${legal}/:id`,
  legalVersions: `${legal}/:id/versions`, legalExact: `${legal}/:id/versions/:versionId`, legalPublish: `${legal}/:id/publish`,
  bootstrapList: bootstrap, bootstrapRevoke: `${bootstrap}/:staffId/:code/revoke`,
  cityPicker: '/settings/management/cities', cityVersionPicker: '/settings/management/cities/:cityId/versions',
  technicianPicker: `${geography}/:cityId/technicians`,
  geographyCoverage: `${geography}/:cityId/service-areas/:areaId/versions/:versionId/district-coverage`,
} as const);

export const P03_BODY_BYTES = Object.freeze({ default: 4 * 1024, legalPublish: 1024 * 1024,
  contentPublish: 128 * 1024, geographyCoverage: 64 * 1024 });
export const P03_BODY_DEADLINE_MS = 10_000;
export const P03_RESPONSE_BYTES = Object.freeze({ list: 512 * 1024, legalExact: 2 * 1024 * 1024,
  contentExact: 256 * 1024, companyExact: 16 * 1024, referenceExact: 16 * 1024, detail: 4 * 1024 });
export const P03_DEFAULT_LIMIT = 50;
export const P03_MAX_LIMIT = 200;
export const P03_MAX_CURSOR_LENGTH = 1024;
export const P03_MAX_VERSION = 2_147_483_647;
export const P03_ETAG_PREFIX = 'p03-v';
export const P03_RECEIPT_ENVELOPE_VERSION = 1;
export const P03_PROBLEM_STATUS = Object.freeze({ badRequest: 400, unauthorized: 401, forbidden: 403, notFound: 404,
  bodyDeadline: 408, conflict: 409, staleVersion: 412, bodyTooLarge: 413,
  unsupportedEncoding: 415, versionRequired: 428, internalError: 500, notReady: 503 } as const);

function post<Route extends string, V extends boolean, R extends boolean, S extends 200 | 201>(
  route: Route, versioned: V, revisionReceipt: R, status: S,
) { return Object.freeze({ method: 'POST' as const, route, versioned, revisionReceipt, status }); }
export const P03_COMMANDS = Object.freeze({
  companyPublish: post(P03_ROUTES.companyPublish, true, false, 201),
  referenceCreate: post(P03_ROUTES.referenceCreate, false, false, 201),
  referencePublish: post(P03_ROUTES.referencePublish, true, true, 201),
  referenceArchive: post(P03_ROUTES.referenceArchive, true, false, 200),
  contentCreate: post(P03_ROUTES.contentCreate, false, false, 201),
  contentPublish: post(P03_ROUTES.contentPublish, true, true, 201),
  contentArchive: post(P03_ROUTES.contentArchive, true, false, 200),
  legalCreate: post(P03_ROUTES.legalCreate, false, false, 201),
  legalPublish: post(P03_ROUTES.legalPublish, true, true, 201),
  bootstrapRevoke: post(P03_ROUTES.bootstrapRevoke, true, false, 200),
});
export type P03Operation = keyof typeof P03_COMMANDS;
export const P03_OPERATIONS = Object.freeze(Object.keys(P03_COMMANDS) as P03Operation[]);
export function isP03Operation(value: unknown): value is P03Operation {
  return typeof value === 'string' && Object.hasOwn(P03_COMMANDS, value);
}

const UUID_PATTERN = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}';
const UUID = new RegExp(`^${UUID_PATTERN}$`);
export function isP03Uuid(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID.test(value);
}

export function isP03Version(value: unknown, allowZero = false): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= (allowZero ? 0 : 1) && value <= P03_MAX_VERSION;
}
export function formatP03Etag(version: number): string {
  if (!isP03Version(version, true)) { throw new RangeError('Invalid P03 version'); }
  return `"${P03_ETAG_PREFIX}${String(version)}"`;
}
export function parseP03Etag(value: unknown, allowZero = false): number | null {
  if (typeof value !== 'string') { return null; }
  const match = /^"p03-v(0|[1-9][0-9]{0,9})"$/.exec(value);
  if (!match || match[0] !== value) { return null; }
  const version = Number(match[1]);
  return isP03Version(version, allowZero) ? version : null;
}

const contentPublishPath = new RegExp(`^${P03_API_PREFIX}${P03_ROUTES.contentPublish.replace(':id', UUID_PATTERN)}$`);
const legalPublishPath = new RegExp(`^${P03_API_PREFIX}${P03_ROUTES.legalPublish.replace(':id', UUID_PATTERN)}$`);
const coveragePath = new RegExp(`^${P03_API_PREFIX}${P03_ROUTES.geographyCoverage.replace(/:\w+/g, UUID_PATTERN)}$`);

/** Input is the canonical pathname (without query); never match aliases, % encoding or trailing slash. */
export function p03BodyLimit(method: string, pathname: string): number {
  if (pathname.endsWith('\n') || pathname.endsWith('\r')) { return P03_BODY_BYTES.default; }
  if (method === 'POST' && legalPublishPath.test(pathname)) { return P03_BODY_BYTES.legalPublish; }
  if (method === 'POST' && contentPublishPath.test(pathname)) { return P03_BODY_BYTES.contentPublish; }
  if (method === 'PUT' && coveragePath.test(pathname)) { return P03_BODY_BYTES.geographyCoverage; }
  return P03_BODY_BYTES.default;
}
