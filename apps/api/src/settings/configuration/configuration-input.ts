/**
 * Strict typed inputs for the internal P03-03 configuration ports.
 *
 * These ports are called by trusted server code, never by a browser, but a
 * caller is still a boundary: every value is narrowed here so an unexpected key,
 * an unknown reference type, a foreign scope or an oversized text can never reach
 * SQL. A validation failure carries a field name and never echoes the submitted
 * value, so a refusal cannot leak settings text, labels or contact data.
 *
 * Database CHECK/trigger rules stay authoritative (non-empty reviewed text, the
 * callback interval bounds, the same-city FK, the pointer CAS). This module only
 * refuses what the schema cannot express: unknown keys, an unsupported reference
 * type, a scope that contradicts the type, and quantity/length limits.
 */
import { ConfigurationError, invalid } from './configuration-errors.js';

/* ----------------------------- limits ----------------------------- */

export const MAX_OPERATOR_NAME = 200;
export const MAX_OPERATOR_REGISTRATION_ID = 120;
export const MAX_OPERATOR_ADDRESS = 500;
export const MAX_POLICY_REF = 200;
export const MAX_REFERENCE_LABEL = 200;
export const MAX_SOURCE_REF = 200;
export const MAX_CONTENT_TITLE = 300;
export const MAX_CONTENT_BODY = 20_000;
export const MAX_CODE = 64;
export const MAX_LIST_ROWS = 200;
export const DEFAULT_LIST_ROWS = 50;
export const MAX_IDEMPOTENCY_KEY = 128;

/** Seven company policy fields of one immutable settings revision. */
export const COMPANY_SETTINGS_FIELDS = Object.freeze([
  'operatorName', 'operatorRegistrationId', 'operatorAddress', 'legalReviewRef',
  'securityPolicyRef', 'retentionPolicyRef', 'uploadPolicyRef',
] as const);
export type CompanySettingsField = typeof COMPANY_SETTINGS_FIELDS[number];

/** Database column of each policy field, used by readiness and the insert. */
export const COMPANY_SETTINGS_COLUMNS: Readonly<Record<CompanySettingsField, string>> = Object.freeze({
  operatorName: 'operator_name',
  operatorRegistrationId: 'operator_registration_id',
  operatorAddress: 'operator_address',
  legalReviewRef: 'legal_review_ref',
  securityPolicyRef: 'security_policy_ref',
  retentionPolicyRef: 'retention_policy_ref',
  uploadPolicyRef: 'upload_policy_ref',
});

/* --------------------------- primitives --------------------------- */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
/**
 * Mirrors the database CHECK `^[A-Za-z][A-Za-z0-9_.-]{0,63}$` of
 * `reference_entries_code_check` / `content_blocks_code_check` exactly, so this
 * boundary never rejects a stable code the schema accepts (nor accepts one it
 * refuses).
 */
const CODE = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
/** ISO-8601 instant with an explicit offset, so no wall-clock is guessed. */
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})$/;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}

export function requireUuid(value: unknown, field: string): string {
  if (!isUuid(value)) {
    invalid(field);
  }
  return value;
}

function record(value: unknown, allowed: readonly string[], field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    invalid(field);
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(field);
  }
  const entries = value as Record<string, unknown>;
  for (const key of Object.keys(entries)) {
    if (!allowed.includes(key)) {
      invalid(`${field}.${key}`);
    }
  }
  return entries;
}

function requiredText(value: unknown, max: number, field: string): string {
  if (typeof value !== 'string') {
    invalid(field);
  }
  const text = value.trim();
  if (text.length === 0 || text.length > max) {
    invalid(field);
  }
  return text;
}

function requiredCode(value: unknown, field: string): string {
  const code = requiredText(value, MAX_CODE, field);
  if (!CODE.test(code)) {
    invalid(field);
  }
  return code;
}

/** Non-negative safe integer; used for expected versions and row counts. */
function nonNegativeInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    invalid(field);
  }
  return value;
}

function optionalInstant(value: unknown, field: string): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'string' || !INSTANT.test(value) || Number.isNaN(Date.parse(value))) {
    invalid(field);
  }
  return value;
}

function requiredInstant(value: unknown, field: string): string {
  const instant = optionalInstant(value, field);
  if (instant === null) {
    invalid(field);
  }
  return instant;
}

function optionalBoolean(value: unknown, field: string): boolean {
  if (value === undefined || value === null) {
    return false;
  }
  if (typeof value !== 'boolean') {
    invalid(field);
  }
  return value;
}

/* ------------------------ company settings ------------------------ */

export type CompanySettings = Readonly<Record<CompanySettingsField, string>>;

export interface CompanySettingsPublishInput {
  readonly settings: CompanySettings;
  /** Latest published revision the caller read; 0 when the company has none. */
  readonly expectedLastVersion: number;
}

const SETTINGS_ALLOWED = COMPANY_SETTINGS_FIELDS;

function companySettings(value: unknown): CompanySettings {
  const input = record(value, SETTINGS_ALLOWED, 'settings');
  const result: Partial<Record<CompanySettingsField, string>> = {};
  for (const field of COMPANY_SETTINGS_FIELDS) {
    const max = field === 'operatorName' ? MAX_OPERATOR_NAME
      : field === 'operatorRegistrationId' ? MAX_OPERATOR_REGISTRATION_ID
        : field === 'operatorAddress' ? MAX_OPERATOR_ADDRESS : MAX_POLICY_REF;
    result[field] = requiredText(input[field], max, `settings.${field}`);
  }
  return Object.freeze(result as Record<CompanySettingsField, string>);
}

/**
 * The contract refuses a partially configured revision: every policy field is
 * required and a policy ref is provenance of a reviewed decision, never an
 * executable policy or a secret.
 */
export function companySettingsPublishInput(value: unknown): CompanySettingsPublishInput {
  const input = record(value, ['settings', 'expectedLastVersion'], 'input');
  return Object.freeze({
    settings: companySettings(input['settings']),
    expectedLastVersion: nonNegativeInteger(input['expectedLastVersion'], 'expectedLastVersion'),
  });
}

/* --------------------------- references --------------------------- */

export const REFERENCE_TYPES = Object.freeze([
  'CALLBACK_INTERVAL', 'PAYMENT_METHOD', 'CANCEL_REASON', 'DECLINE_REASON', 'REQUEST_SOURCE',
] as const);
export type ReferenceType = typeof REFERENCE_TYPES[number];
export type ReferenceScope = 'COMPANY' | 'CITY';

/**
 * Scope is a property of the type, not a caller choice: a callback interval is
 * meaningless without a city (its local time comes from that city's version) and
 * a payment method is company-wide. Anything else is refused before SQL.
 */
export const REFERENCE_TYPE_SCOPE: Readonly<Record<ReferenceType, ReferenceScope>> = Object.freeze({
  CALLBACK_INTERVAL: 'CITY',
  PAYMENT_METHOD: 'COMPANY',
  CANCEL_REASON: 'COMPANY',
  DECLINE_REASON: 'COMPANY',
  REQUEST_SOURCE: 'COMPANY',
});

export function referenceType(value: unknown, field = 'type'): ReferenceType {
  if (typeof value !== 'string' || !(REFERENCE_TYPES as readonly string[]).includes(value)) {
    invalid(field);
  }
  return value as ReferenceType;
}

/** 0 <= start < end <= 1440 minutes of the local day. */
export const MINUTES_PER_DAY = 1440;

export interface CallbackInterval {
  readonly startMinute: number;
  readonly endMinute: number;
}

export interface ReferenceEntryCreateInput {
  readonly type: ReferenceType;
  readonly cityId: string | null;
  readonly code: string;
}

export interface ReferenceVersionInput {
  readonly type: ReferenceType;
  readonly entryId: string;
  readonly expectedVersion: number;
  readonly label: string;
  readonly sourceRef: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
  /** Creation provenance only: the city version reviewed together with the label. */
  readonly cityVersionId: string | null;
  readonly interval: CallbackInterval | null;
}

export interface ReferenceArchiveInput {
  readonly entryId: string;
  readonly expectedVersion: number;
}

export interface ReferenceListInput {
  readonly type: ReferenceType;
  readonly cityId: string | null;
  readonly includeArchived: boolean;
  readonly limit: number;
}

export interface ReferenceSnapshotInput {
  readonly type: ReferenceType;
  readonly entryId: string;
  /** Omitted: the current pointer; present: that exact historical version. */
  readonly version: number | null;
}

export interface ReferenceResolutionInput {
  readonly type: ReferenceType;
  readonly entryId: string;
  /**
   * Trusted intake/request city version. The timezone of a callback interval is
   * resolved from this snapshot, not from the reference's creation provenance:
   * the local window follows the request that consumes it.
   */
  readonly intakeCityVersionId: string | null;
  readonly at: string | null;
}

export function referenceEntryCreateInput(value: unknown): ReferenceEntryCreateInput {
  const input = record(value, ['type', 'cityId', 'code'], 'input');
  const type = referenceType(input['type']);
  const scope = REFERENCE_TYPE_SCOPE[type];
  const cityId = input['cityId'] === undefined || input['cityId'] === null
    ? null : requireUuid(input['cityId'], 'cityId');
  if (scope === 'CITY' && cityId === null) {
    invalid('cityId');
  }
  if (scope === 'COMPANY' && cityId !== null) {
    invalid('cityId');
  }
  return Object.freeze({ type, cityId, code: requiredCode(input['code'], 'code') });
}

function callbackInterval(value: unknown, type: ReferenceType): CallbackInterval | null {
  if (type !== 'CALLBACK_INTERVAL') {
    if (value !== undefined && value !== null) {
      // Only a callback interval has a window; other types must not carry one.
      invalid('interval');
    }
    return null;
  }
  const input = record(value, ['startMinute', 'endMinute'], 'interval');
  const startMinute = nonNegativeInteger(input['startMinute'], 'interval.startMinute');
  const endMinute = nonNegativeInteger(input['endMinute'], 'interval.endMinute');
  if (startMinute >= endMinute || endMinute > MINUTES_PER_DAY) {
    invalid('interval');
  }
  return Object.freeze({ startMinute, endMinute });
}

export function referenceVersionInput(value: unknown): ReferenceVersionInput {
  const input = record(value,
    ['type', 'entryId', 'expectedVersion', 'label', 'sourceRef', 'validFrom', 'validUntil', 'cityVersionId', 'interval'],
    'input');
  const validFrom = requiredInstant(input['validFrom'], 'validFrom');
  const validUntil = optionalInstant(input['validUntil'], 'validUntil');
  if (validUntil !== null && Date.parse(validUntil) <= Date.parse(validFrom)) {
    invalid('validUntil');
  }
  const type = referenceType(input['type'], 'type');
  const cityVersionId = input['cityVersionId'] === undefined || input['cityVersionId'] === null
    ? null : requireUuid(input['cityVersionId'], 'cityVersionId');
  if (type !== 'CALLBACK_INTERVAL' && cityVersionId !== null) {
    // Mirrors the database type_fields CHECK: only a callback interval may name a
    // creation-provenance city version.
    invalid('cityVersionId');
  }
  return Object.freeze({
    type,
    entryId: requireUuid(input['entryId'], 'entryId'),
    expectedVersion: nonNegativeInteger(input['expectedVersion'], 'expectedVersion'),
    label: requiredText(input['label'], MAX_REFERENCE_LABEL, 'label'),
    sourceRef: requiredText(input['sourceRef'], MAX_SOURCE_REF, 'sourceRef'),
    validFrom,
    validUntil,
    cityVersionId,
    interval: callbackInterval(input['interval'], type),
  });
}

export function referenceArchiveInput(value: unknown): ReferenceArchiveInput {
  const input = record(value, ['entryId', 'expectedVersion'], 'input');
  return Object.freeze({
    entryId: requireUuid(input['entryId'], 'entryId'),
    expectedVersion: nonNegativeInteger(input['expectedVersion'], 'expectedVersion'),
  });
}

export function referenceListInput(value: unknown): ReferenceListInput {
  const input = record(value, ['type', 'cityId', 'includeArchived', 'limit'], 'input');
  const type = referenceType(input['type']);
  const cityId = input['cityId'] === undefined || input['cityId'] === null
    ? null : requireUuid(input['cityId'], 'cityId');
  if (REFERENCE_TYPE_SCOPE[type] === 'CITY' && cityId === null) {
    invalid('cityId');
  }
  if (REFERENCE_TYPE_SCOPE[type] === 'COMPANY' && cityId !== null) {
    invalid('cityId');
  }
  return Object.freeze({
    type,
    cityId,
    includeArchived: optionalBoolean(input['includeArchived'], 'includeArchived'),
    limit: listLimit(input['limit']),
  });
}

export function referenceSnapshotInput(value: unknown): ReferenceSnapshotInput {
  const input = record(value, ['type', 'entryId', 'version'], 'input');
  return Object.freeze({
    type: referenceType(input['type']),
    entryId: requireUuid(input['entryId'], 'entryId'),
    version: input['version'] === undefined || input['version'] === null
      ? null : nonNegativeInteger(input['version'], 'version'),
  });
}

export function referenceResolutionInput(value: unknown): ReferenceResolutionInput {
  const input = record(value, ['type', 'entryId', 'intakeCityVersionId', 'at'], 'input');
  const type = referenceType(input['type']);
  const intakeCityVersionId = input['intakeCityVersionId'] === undefined || input['intakeCityVersionId'] === null
    ? null : requireUuid(input['intakeCityVersionId'], 'intakeCityVersionId');
  if (REFERENCE_TYPE_SCOPE[type] === 'CITY' && intakeCityVersionId === null) {
    // A city-scoped interval has no meaning without the consuming city snapshot.
    invalid('intakeCityVersionId');
  }
  return Object.freeze({
    type,
    entryId: requireUuid(input['entryId'], 'entryId'),
    intakeCityVersionId,
    at: optionalInstant(input['at'], 'at'),
  });
}

function listLimit(value: unknown): number {
  if (value === undefined || value === null) {
    return DEFAULT_LIST_ROWS;
  }
  const limit = nonNegativeInteger(value, 'limit');
  if (limit < 1 || limit > MAX_LIST_ROWS) {
    invalid('limit');
  }
  return limit;
}

/* ---------------------------- content ---------------------------- */

export const CONTENT_KINDS = Object.freeze(['FAQ', 'FACT', 'SEO'] as const);
export type ContentKind = typeof CONTENT_KINDS[number];
export type ContentScope = 'COMPANY' | 'CITY';

/**
 * Codes a content block may not take.
 *
 * Company policy provenance lives in `business_settings_versions` and local
 * contacts/hours/timezone live only in `service_city_versions` (the contract's
 * "no copy" rule). A content block with one of these codes would be a second,
 * editable copy of a value with a different reviewed owner, so it is refused.
 */
export const RESERVED_CONTENT_CODES: readonly string[] = Object.freeze([
  'operator-name', 'operator-registration-id', 'operator-address',
  'legal-review-ref', 'security-policy-ref', 'retention-policy-ref', 'upload-policy-ref',
  'display-name', 'address-display', 'public-contact', 'office-hours', 'timezone',
]);

export interface ContentBlockCreateInput {
  readonly code: string;
  readonly kind: ContentKind;
  readonly scope: ContentScope;
  readonly cityId: string | null;
  readonly allowCompanyFallback: boolean;
}

export interface ContentRevisionInput {
  readonly blockId: string;
  readonly expectedVersion: number;
  readonly title: string;
  readonly body: string;
  readonly sourceRef: string;
}

export interface ContentArchiveInput {
  readonly blockId: string;
  readonly expectedVersion: number;
}

export interface ContentListInput {
  readonly scope: ContentScope | null;
  readonly cityId: string | null;
  readonly kind: ContentKind | null;
  readonly includeArchived: boolean;
  readonly limit: number;
}

export interface ContentSnapshotInput {
  readonly blockId: string;
  readonly version: number | null;
}

export interface ContentResolutionInput {
  /** Stable code; the CITY row wins when it exists, else an allowed COMPANY row. */
  readonly code: string;
  readonly cityId: string;
}

export function contentBlockCreateInput(value: unknown): ContentBlockCreateInput {
  const input = record(value, ['code', 'kind', 'scope', 'cityId', 'allowCompanyFallback'], 'input');
  const kind = input['kind'];
  if (typeof kind !== 'string' || !(CONTENT_KINDS as readonly string[]).includes(kind)) {
    invalid('kind');
  }
  const scope = input['scope'];
  if (scope !== 'COMPANY' && scope !== 'CITY') {
    invalid('scope');
  }
  const cityId = input['cityId'] === undefined || input['cityId'] === null
    ? null : requireUuid(input['cityId'], 'cityId');
  if (scope === 'CITY' && cityId === null) {
    invalid('cityId');
  }
  if (scope === 'COMPANY' && cityId !== null) {
    invalid('cityId');
  }
  const allowCompanyFallback = optionalBoolean(input['allowCompanyFallback'], 'allowCompanyFallback');
  if (scope === 'CITY' && allowCompanyFallback) {
    // The fallback permission belongs to the company row that grants it.
    invalid('allowCompanyFallback');
  }
  const code = requiredCode(input['code'], 'code');
  if (RESERVED_CONTENT_CODES.includes(code)) {
    throw new ConfigurationError('RESERVED_CODE', 'code');
  }
  return Object.freeze({ code, kind: kind as ContentKind, scope, cityId, allowCompanyFallback });
}

export function contentRevisionInput(value: unknown): ContentRevisionInput {
  const input = record(value, ['blockId', 'expectedVersion', 'title', 'body', 'sourceRef'], 'input');
  return Object.freeze({
    blockId: requireUuid(input['blockId'], 'blockId'),
    expectedVersion: nonNegativeInteger(input['expectedVersion'], 'expectedVersion'),
    title: requiredText(input['title'], MAX_CONTENT_TITLE, 'title'),
    body: requiredText(input['body'], MAX_CONTENT_BODY, 'body'),
    sourceRef: requiredText(input['sourceRef'], MAX_SOURCE_REF, 'sourceRef'),
  });
}

export function contentArchiveInput(value: unknown): ContentArchiveInput {
  const input = record(value, ['blockId', 'expectedVersion'], 'input');
  return Object.freeze({
    blockId: requireUuid(input['blockId'], 'blockId'),
    expectedVersion: nonNegativeInteger(input['expectedVersion'], 'expectedVersion'),
  });
}

export function contentListInput(value: unknown): ContentListInput {
  const input = record(value, ['scope', 'cityId', 'kind', 'includeArchived', 'limit'], 'input');
  const scope = input['scope'] === undefined || input['scope'] === null ? null : input['scope'];
  if (scope !== null && scope !== 'COMPANY' && scope !== 'CITY') {
    invalid('scope');
  }
  const kind = input['kind'] === undefined || input['kind'] === null ? null : input['kind'];
  if (kind !== null && (typeof kind !== 'string' || !(CONTENT_KINDS as readonly string[]).includes(kind))) {
    invalid('kind');
  }
  const cityId = input['cityId'] === undefined || input['cityId'] === null
    ? null : requireUuid(input['cityId'], 'cityId');
  if (scope === 'CITY' && cityId === null) {
    invalid('cityId');
  }
  return Object.freeze({
    scope,
    cityId,
    kind: kind as ContentKind | null,
    includeArchived: optionalBoolean(input['includeArchived'], 'includeArchived'),
    limit: listLimit(input['limit']),
  });
}

export function contentSnapshotInput(value: unknown): ContentSnapshotInput {
  const input = record(value, ['blockId', 'version'], 'input');
  return Object.freeze({
    blockId: requireUuid(input['blockId'], 'blockId'),
    version: input['version'] === undefined || input['version'] === null
      ? null : nonNegativeInteger(input['version'], 'version'),
  });
}

export function contentResolutionInput(value: unknown): ContentResolutionInput {
  const input = record(value, ['code', 'cityId'], 'input');
  return Object.freeze({
    code: requiredCode(input['code'], 'code'),
    cityId: requireUuid(input['cityId'], 'cityId'),
  });
}
