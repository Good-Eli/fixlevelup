import { isP03Capability, P03_REFERENCE_DB_TYPES } from './policy.js';
import { isP03Uuid, isP03Version, P03_COMMANDS, P03_MAX_CURSOR_LENGTH, P03_MAX_LIMIT, P03_PROBLEM_STATUS } from './routes.js';
import type { P03Operation } from './routes.js';
import { P03_CITY_STATUSES, P03_COMPANY_FIELD_LENGTHS, P03_COMPANY_FIELDS, P03_CONTENT_KINDS, P03_LEGAL_KINDS,
  P03_LEGAL_PURPOSES, P03_READINESS_MISSING, P03_READINESS_SECTION_STATES, P03_TEXT_LENGTHS } from './wire.js';
import type { P03BootstrapGrant, P03CityPickerItem, P03CityVersionPickerItem, P03CommandReceipt, P03CompanySummary,
  P03CompanyVersion, P03ContentBlock, P03ContentRevision, P03ContentSummary, P03Envelope, P03LegalDocument, P03LegalSummary,
  P03LegalVersion, P03Page, P03PageInfo, P03Problem, P03Readiness, P03ReadinessCity, P03ReadinessSection, P03ReferenceEntry,
  P03ReferenceSummary, P03ReferenceVersion, P03TechnicianPickerItem, P03VersionedPage } from './wire.js';

/** Decoders take already byte-bounded JSON values, never a network stream. */
export type P03Decoder<T> = (value: unknown) => T | null;

function object(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) { return false; }
  const proto: unknown = Object.getPrototypeOf(value);
  return (proto === Object.prototype || proto === null) && Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key));
}
function text(value: unknown, limit: number): value is string {
  return typeof value === 'string' && value.length <= limit && /\S/.test(value);
}
function member<T extends string>(value: unknown, choices: readonly T[]): value is T {
  return typeof value === 'string' && (choices as readonly string[]).includes(value);
}
function nullable<T>(value: unknown, valid: (v: unknown) => v is T): value is T | null {
  return value === null || valid(value);
}
function instant(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 32 &&
    value.trim() === value && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/u.test(value) &&
    !Number.isNaN(Date.parse(value));
}
function code(value: unknown): value is string {
  return typeof value === 'string' && value.length <= P03_TEXT_LENGTHS.code && /^[A-Za-z]/u.test(value) && !/[^A-Za-z0-9_.-]/u.test(value);
}
function idAndVersion(v: Record<string, unknown>): boolean {
  return isP03Uuid(v['id']) && isP03Version(v['version']);
}
function exactSummary(v: Record<string, unknown>): boolean {
  return idAndVersion(v) && instant(v['publishedAt']);
}
function interval(value: unknown): boolean {
  if (!object(value, ['startMinute', 'endMinute'])) { return false; }
  const start = value['startMinute']; const end = value['endMinute'];
  return typeof start === 'number' && typeof end === 'number' && Number.isInteger(start) &&
    Number.isInteger(end) && start >= 0 && start < end && end <= 1440;
}

export function decodeP03Envelope<T>(value: unknown, decode: P03Decoder<T>): P03Envelope<T> | null {
  if (!object(value, ['data', 'meta'])) { return null; }
  const meta = value['meta'];
  if (!object(meta, ['requestId']) || !isP03Uuid(meta['requestId'])) { return null; }
  const data = decode(value['data']);
  return data === null ? null : { data, meta: { requestId: meta['requestId'] } };
}
export function decodeP03Problem(value: unknown): P03Problem | null {
  if (!object(value, ['type', 'title', 'status', 'code', 'requestId'])) { return null; }
  const status = value['status'];
  if (typeof status !== 'number' || !(Object.values(P03_PROBLEM_STATUS) as readonly number[]).includes(status)) { return null; }
  const expected = status === 503 ? 'NOT_READY' : status === 404 ? 'NOT_FOUND' : status === 500 ? 'INTERNAL_ERROR' : 'REQUEST_REJECTED';
  if (value['type'] !== 'about:blank' || value['title'] !== expected || value['code'] !== expected || !isP03Uuid(value['requestId'])) { return null; }
  return { type: 'about:blank', title: expected, status, code: expected, requestId: value['requestId'] };
}
export function isP03Cursor(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= P03_MAX_CURSOR_LENGTH && !/[^A-Za-z0-9_.-]/u.test(value);
}
export function decodeP03PageInfo(value: unknown): P03PageInfo | null {
  if (!object(value, ['hasMore', 'nextCursor'])) { return null; }
  if (value['hasMore'] === false && value['nextCursor'] === null) { return { hasMore: false, nextCursor: null }; }
  if (value['hasMore'] === true && isP03Cursor(value['nextCursor'])) { return { hasMore: true, nextCursor: value['nextCursor'] }; }
  return null;
}
function page<T>(rawItems: unknown, rawPageInfo: unknown, decode: P03Decoder<T>): P03Page<T> | null {
  if (!Array.isArray(rawItems) || rawItems.length > P03_MAX_LIMIT) { return null; }
  const pageInfo = decodeP03PageInfo(rawPageInfo);
  if (!pageInfo || (rawItems.length === 0 && pageInfo.hasMore)) { return null; }
  const items: T[] = [];
  for (const raw of rawItems) {
    const item = decode(raw);
    if (item === null) { return null; }
    items.push(item);
  }
  return { items, pageInfo };
}
export function decodeP03Page<T>(value: unknown, decode: P03Decoder<T>): P03Page<T> | null {
  return object(value, ['items', 'pageInfo']) ? page(value['items'], value['pageInfo'], decode) : null;
}
export function decodeP03VersionedPage<T>(value: unknown, decode: P03Decoder<T>, allowZero = false): P03VersionedPage<T> | null {
  if (!object(value, ['items', 'pageInfo', 'version']) || !isP03Version(value['version'], allowZero)) { return null; }
  const data = page(value['items'], value['pageInfo'], decode);
  return data && (value['version'] > 0 || data.items.length === 0) ? { ...data, version: value['version'] } : null;
}
export function decodeP03Receipt<O extends P03Operation>(value: unknown, operation: O): P03CommandReceipt<O> | null {
  const revision = P03_COMMANDS[operation].revisionReceipt;
  const keys = revision ? ['id', 'version', 'revisionId', 'revisionVersion'] : ['id', 'version'];
  return object(value, keys) && idAndVersion(value) && (!revision ||
    (isP03Uuid(value['revisionId']) && isP03Version(value['revisionVersion']))) ? value as unknown as P03CommandReceipt<O> : null;
}

const COMPANY_SUMMARY = ['id', 'version', 'publishedAt'] as const;
export function decodeP03CompanySummary(value: unknown): P03CompanySummary | null {
  return object(value, COMPANY_SUMMARY) && exactSummary(value) ? value as unknown as P03CompanySummary : null;
}
export function decodeP03CompanyVersion(value: unknown): P03CompanyVersion | null {
  if (!object(value, [...COMPANY_SUMMARY, 'launchMode', 'primaryCityId', 'reviewedBy', 'settings']) || !exactSummary(value) ||
    !member(value['launchMode'], ['SINGLE_CITY', 'MULTI_CITY']) || !isP03Uuid(value['primaryCityId']) || !isP03Uuid(value['reviewedBy'])) { return null; }
  const settings = value['settings'];
  return object(settings, P03_COMPANY_FIELDS) && P03_COMPANY_FIELDS.every(field => settings[field] === null ||
    text(settings[field], P03_COMPANY_FIELD_LENGTHS[field])) ? value as unknown as P03CompanyVersion : null;
}
export function decodeP03ReferenceEntry(value: unknown): P03ReferenceEntry | null {
  if (!object(value, ['id', 'version', 'type', 'scope', 'cityId', 'code', 'currentVersionId', 'archivedAt']) || !idAndVersion(value) ||
    !member(value['type'], P03_REFERENCE_DB_TYPES) || !code(value['code']) || !nullable(value['currentVersionId'], isP03Uuid) ||
    !nullable(value['archivedAt'], instant)) { return null; }
  const scoped = value['type'] === 'CALLBACK_INTERVAL' ? value['scope'] === 'CITY' && isP03Uuid(value['cityId'])
    : value['scope'] === 'COMPANY' && value['cityId'] === null;
  return scoped ? value as unknown as P03ReferenceEntry : null;
}
const REFERENCE_SUMMARY = ['id', 'entryId', 'version', 'label', 'publishedAt'] as const;
function referenceSummary(v: Record<string, unknown>): boolean {
  return exactSummary(v) && isP03Uuid(v['entryId']) && text(v['label'], P03_TEXT_LENGTHS.referenceLabel);
}
export function decodeP03ReferenceSummary(value: unknown): P03ReferenceSummary | null {
  return object(value, REFERENCE_SUMMARY) && referenceSummary(value) ? value as unknown as P03ReferenceSummary : null;
}
export function decodeP03ReferenceVersion(value: unknown): P03ReferenceVersion | null {
  if (!object(value, [...REFERENCE_SUMMARY, 'type', 'cityId', 'sourceRef', 'validFrom', 'validUntil', 'provenanceCityVersionId', 'interval']) ||
    !referenceSummary(value) || !member(value['type'], P03_REFERENCE_DB_TYPES) || !text(value['sourceRef'], P03_TEXT_LENGTHS.sourceRef) ||
    !instant(value['validFrom']) || !nullable(value['validUntil'], instant)) { return null; }
  const scoped = value['type'] === 'CALLBACK_INTERVAL' ? isP03Uuid(value['cityId']) &&
    isP03Uuid(value['provenanceCityVersionId']) && interval(value['interval'])
    : value['cityId'] === null && value['provenanceCityVersionId'] === null && value['interval'] === null;
  return scoped ? value as unknown as P03ReferenceVersion : null;
}
export function decodeP03ContentBlock(value: unknown): P03ContentBlock | null {
  if (!object(value, ['id', 'version', 'code', 'kind', 'scope', 'cityId', 'allowCompanyFallback', 'currentRevisionId', 'archivedAt']) ||
    !idAndVersion(value) || !code(value['code']) || !member(value['kind'], P03_CONTENT_KINDS) ||
    !nullable(value['currentRevisionId'], isP03Uuid) || !nullable(value['archivedAt'], instant)) { return null; }
  const scoped = value['scope'] === 'CITY' ? isP03Uuid(value['cityId']) && value['allowCompanyFallback'] === false
    : value['scope'] === 'COMPANY' && value['cityId'] === null && typeof value['allowCompanyFallback'] === 'boolean';
  return scoped ? value as unknown as P03ContentBlock : null;
}
const CONTENT_SUMMARY = ['id', 'blockId', 'version', 'title', 'publishedAt'] as const;
function contentSummary(v: Record<string, unknown>): boolean {
  return exactSummary(v) && isP03Uuid(v['blockId']) && text(v['title'], P03_TEXT_LENGTHS.title);
}
export function decodeP03ContentSummary(value: unknown): P03ContentSummary | null {
  return object(value, CONTENT_SUMMARY) && contentSummary(value) ? value as unknown as P03ContentSummary : null;
}
export function decodeP03ContentRevision(value: unknown): P03ContentRevision | null {
  return object(value, [...CONTENT_SUMMARY, 'body', 'sourceRef']) && contentSummary(value) &&
    text(value['body'], P03_TEXT_LENGTHS.contentBody) && text(value['sourceRef'], P03_TEXT_LENGTHS.sourceRef)
    ? value as unknown as P03ContentRevision : null;
}
function legalIdentity(v: Record<string, unknown>): boolean {
  return member(v['purpose'], P03_LEGAL_PURPOSES) && member(v['kind'], P03_LEGAL_KINDS);
}
export function decodeP03LegalDocument(value: unknown): P03LegalDocument | null {
  return object(value, ['id', 'version', 'purpose', 'kind', 'currentVersionId']) && idAndVersion(value) && legalIdentity(value) &&
    nullable(value['currentVersionId'], isP03Uuid) ? value as unknown as P03LegalDocument : null;
}
const LEGAL_SUMMARY = ['id', 'documentId', 'sequence', 'title', 'checksum', 'publishedAt'] as const;
function legalSummary(v: Record<string, unknown>): boolean {
  return isP03Uuid(v['id']) && isP03Uuid(v['documentId']) && isP03Version(v['sequence']) &&
    text(v['title'], P03_TEXT_LENGTHS.title) && instant(v['publishedAt']) &&
    typeof v['checksum'] === 'string' && v['checksum'].length === 64 && /^[a-f0-9]{64}$/u.test(v['checksum']);
}
export function decodeP03LegalSummary(value: unknown): P03LegalSummary | null {
  return object(value, LEGAL_SUMMARY) && legalSummary(value) ? value as unknown as P03LegalSummary : null;
}
export function decodeP03LegalVersion(value: unknown): P03LegalVersion | null {
  return object(value, [...LEGAL_SUMMARY, 'purpose', 'kind', 'body', 'legalBasis', 'sourceRef', 'reviewedBy']) &&
    legalSummary(value) && legalIdentity(value) && isP03Uuid(value['reviewedBy']) && text(value['body'], P03_TEXT_LENGTHS.legalBody) &&
    text(value['legalBasis'], P03_TEXT_LENGTHS.legalBasis) && text(value['sourceRef'], P03_TEXT_LENGTHS.legalSourceRef)
    ? value as unknown as P03LegalVersion : null;
}

export function decodeP03BootstrapGrant(value: unknown): P03BootstrapGrant | null {
  return object(value, ['assignmentId', 'staffId', 'code', 'version']) && isP03Uuid(value['assignmentId']) &&
    isP03Uuid(value['staffId']) && isP03Capability(value['code']) && isP03Version(value['version'])
    ? value as unknown as P03BootstrapGrant : null;
}
export function decodeP03CityPickerItem(value: unknown): P03CityPickerItem | null {
  return object(value, ['id', 'code', 'status', 'version', 'currentVersionId']) && idAndVersion(value) && code(value['code']) &&
    member(value['status'], P03_CITY_STATUSES) && nullable(value['currentVersionId'], isP03Uuid) ? value as unknown as P03CityPickerItem : null;
}
export function decodeP03CityVersionPickerItem(value: unknown): P03CityVersionPickerItem | null {
  return object(value, ['id', 'sequence', 'timezone', 'published']) && isP03Uuid(value['id']) && isP03Version(value['sequence']) &&
    text(value['timezone'], P03_TEXT_LENGTHS.timezone) && typeof value['published'] === 'boolean'
    ? value as unknown as P03CityVersionPickerItem : null;
}
export function decodeP03TechnicianPickerItem(value: unknown): P03TechnicianPickerItem | null {
  return object(value, ['id', 'displayName', 'version']) && isP03Uuid(value['id']) && isP03Version(value['version'], true) &&
    (value['displayName'] === null || text(value['displayName'], P03_TEXT_LENGTHS.staffName)) ? value as unknown as P03TechnicianPickerItem : null;
}
function closedList(value: unknown, choices: readonly string[]): boolean {
  return Array.isArray(value) && value.length <= choices.length && value.every(item => member(item, choices)) &&
    new Set(value).size === value.length;
}
function readinessSection(value: unknown): P03ReadinessSection | null {
  if (!object(value, ['section', 'status', 'missing'])) { return null; }
  const section = value['section']; const status = value['status']; const missing = value['missing'];
  if (!member(section, READINESS_SECTIONS) || !member(status, P03_READINESS_SECTION_STATES[section])) { return null; }
  const choices = section === 'COMPANY_SETTINGS' || section === 'REQUEST_PROCESSING' ? P03_READINESS_MISSING[section] : [];
  return closedList(missing, choices) && Array.isArray(missing) && (status === 'MISSING' ? missing.length > 0 : missing.length === 0)
    ? value as unknown as P03ReadinessSection : null;
}
const READINESS_SECTIONS = Object.freeze(Object.keys(P03_READINESS_SECTION_STATES) as P03ReadinessSection['section'][]);
function readinessCity(value: unknown): P03ReadinessCity | null {
  if (!object(value, ['id', 'name', 'status', 'missing']) || !isP03Uuid(value['id']) ||
    !(value['name'] === null || text(value['name'], P03_TEXT_LENGTHS.cityName)) || !member(value['status'], ['CONFIGURED', 'MISSING'])) { return null; }
  const missing = value['missing'];
  return closedList(missing, P03_READINESS_MISSING.CITY) && Array.isArray(missing) &&
    (value['status'] === 'MISSING' ? missing.length > 0 : missing.length === 0) ? value as unknown as P03ReadinessCity : null;
}
export function decodeP03Readiness(value: unknown): P03Readiness | null {
  if (!object(value, ['sections', 'items', 'pageInfo'])) { return null; }
  const raw = value['sections'];
  if (!Array.isArray(raw) || raw.length > READINESS_SECTIONS.length) { return null; }
  const sections: P03ReadinessSection[] = [];
  const seen = new Set<P03ReadinessSection['section']>();
  for (const x of raw) {
    const section = readinessSection(x);
    if (!section || seen.has(section.section)) { return null; }
    sections.push(section);
    seen.add(section.section);
  }
  const data = page(value['items'], value['pageInfo'], readinessCity);
  return data ? { sections, ...data } : null;
}

/** Exact UTF-8 bytes, including replacement of unmatched surrogate code units, without Node/DOM globals. */
export function p03Utf8ByteLength(value: string): number {
  let bytes = 0;
  for (const char of value) {
    const codepoint = char.codePointAt(0) ?? 0;
    bytes += codepoint < 0x80 ? 1 : codepoint < 0x800 ? 2 : codepoint < 0x10000 ? 3 : 4;
  }
  return bytes;
}
