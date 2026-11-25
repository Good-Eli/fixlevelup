/**
 * P05-02 form-session protocol contract: fixed wire names, typed refusals and
 * pure request-body validators shared by the public form-session surface.
 *
 * This module is deliberately inert. It has no NestJS provider, no HTTP request
 * or response type, no SQL, no database client, no cookie jar and no clock: it
 * only names the protocol and re-narrows caller-supplied JSON before any route,
 * quota check or legal port is allowed to look at it. TTLs, quotas and crypto
 * keys are policy, so the constants below are protocol caps only (cookie count,
 * cookie/body bytes, live anchors per group) plus the CSRF domain separator; no
 * live TTL is invented here.
 *
 * A refusal is a `FormSessionError` whose message is exactly its machine code.
 * Submitted values, field contents and secrets are never echoed into a message,
 * a log or a response.
 */

/** Name prefix of one form-session proof cookie: `__Host-fixlevelup_f_<uuid>`. */
export const F_COOKIE_PREFIX = '__Host-fixlevelup_f_';

/** Separate browser-group cookie. It is not a form-session proof. */
export const F_GROUP_COOKIE = '__Host-fixlevelup_fgroup';

/** Header that carries the selector UUID of the presented proof. */
export const F_SELECTOR_HEADER = 'x-form-session-id';

/** Header that carries the stateless mutation proof. */
export const F_CSRF_HEADER = 'x-csrf-token';

/**
 * Header that carries the mandatory idempotency key of a consent mutation.
 *
 * The key is bound to the F-session and the operation: `consent_records` is
 * append-only with `unique(session_id,evidence_ref)`, so the key of a consent
 * command *is* the `evidenceRef` of its single legal evidence event. The same
 * key presented again replays that event; the same key with a different intent
 * is a refusal, never a second event.
 */
export const F_IDEMPOTENCY_HEADER = 'idempotency-key';

/** Protocol cap: live form-session anchors per browser group. */
export const F_MAX_LIVE_ANCHORS_PER_GROUP = 4;

/** Protocol cap: form proof cookies accepted in one request. */
export const F_MAX_F_COOKIES = 8;

/** Protocol cap: `Cookie` header bytes accepted before parsing. */
export const F_MAX_COOKIE_BYTES = 8192;

/** Domain separator for the stateless `P05_F_MUTATE` CSRF HMAC. */
export const F_CSRF_DOMAIN = 'p05-f-mutate\0';

/** Protocol cap: JSON request-body bytes accepted before parsing. */
export const F_JSON_BYTE_CAP = 16384;

/**
 * Closed refusal vocabulary of the P05-02 surface. The mapping to an HTTP status
 * belongs to the transport layer, not to this contract.
 */
export type FormSessionErrorCode =
  | 'MALFORMED'
  | 'ORIGIN'
  | 'CSRF'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'PAYLOAD_TOO_LARGE'
  | 'UNSUPPORTED_MEDIA'
  | 'UNPROCESSABLE'
  | 'QUOTA'
  | 'UNAVAILABLE'
  | 'PII_REJECTED';

/** Typed refusal. The message is the code itself and never contains input data. */
export class FormSessionError extends Error {
  readonly code: FormSessionErrorCode;

  constructor(code: FormSessionErrorCode) {
    super(code);
    this.name = 'FormSessionError';
    this.code = code;
  }
}

/** Canonical lowercase UUID text: 8-4-4-4-12 lowercase hex, no version rule. */
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Recursion bound of the pre-consent PII scan. */
const MAX_PERSONAL_DEPTH = 8;

/**
 * Personal/contact/address keys that must never reach the advisory coverage step.
 * The comparison is case-sensitive and follows the JSON member spelling exactly,
 * so the set covers the camelCase surface and the snake_case/address variants a
 * client may send by mistake. Anything here is refused before any processing.
 */
const PERSONAL_FIELDS: ReadonlySet<string> = new Set([
  'address',
  'street',
  'building',
  'apartment',
  'phone',
  'name',
  'fullName',
  'email',
  'comment',
  'description',
  'accessNotes',
  'intercom',
  'full_name',
  'firstName',
  'lastName',
  'patronymic',
  'house',
  'flat',
  'entrance',
  'floor',
  'access_notes',
  'addressText',
  'rawAddress',
  'coordinates',
  'lat',
  'lon',
  'lng',
  'postalCode',
  'zip',
]);

function malformed(): never {
  throw new FormSessionError('MALFORMED');
}

/** JSON-like object, including a null-prototype object from a strict parser. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Root body object or `MALFORMED`; arrays and non-objects are refused. */
function bodyRecord(body: unknown): Record<string, unknown> {
  if (!isPlainObject(body)) {
    malformed();
  }
  return body;
}

/** True when the object owns exactly the allowed string keys, no more and no less. */
function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Reflect.ownKeys(record);
  if (own.length !== keys.length) {
    return false;
  }
  return own.every((key) => typeof key === 'string' && keys.includes(key));
}

/**
 * True when every own key is allowed and every required key is present. A symbol
 * key or any key outside `allowed` fails the check.
 */
function hasAllowedKeys(
  record: Record<string, unknown>, required: readonly string[], allowed: readonly string[],
): boolean {
  const own = Reflect.ownKeys(record);
  if (!own.every((key) => typeof key === 'string' && allowed.includes(key))) {
    return false;
  }
  return required.every((key) => Object.hasOwn(record, key));
}

/** Canonical lowercase UUID string or `MALFORMED`. */
function canonicalUuid(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 36 || !CANONICAL_UUID.test(value)) {
    malformed();
  }
  return value;
}

/**
 * Mandatory `Idempotency-Key` of a consent mutation: a canonical lowercase UUID.
 * An absent or malformed key is `MALFORMED` (400); a command without a key is
 * never silently treated as "no idempotency".
 */
export function idempotencyKey(value: string | undefined): string {
  if (value === undefined) {
    malformed();
  }
  return canonicalUuid(value);
}

/**
 * Binds one idempotency key to exactly one submitted intent.
 *
 * The wire carries the same value twice on purpose: the `Idempotency-Key` header
 * is the protocol-level replay identity and the body `evidenceRef` is the legal
 * evidence identity. They must be equal, otherwise a stored key would name two
 * different intents. A mismatch is a reused key for a different intent, which is
 * `CONFLICT` (409), never a second event and never a replay of the first.
 */
export function bindIdempotencyKey(key: string, evidenceRef: string): string {
  if (key !== evidenceRef) {
    throw new FormSessionError('CONFLICT');
  }
  return key;
}

/**
 * Accepts only an empty plain object (`{}`). Personal fields are refused first,
 * so an address-bearing body is `PII_REJECTED` rather than merely malformed; any
 * other own key, including a symbol key, an array, `null` or a non-object
 * instance is `MALFORMED`.
 */
export function emptyObjectBody(body: unknown): void {
  rejectPersonalFields(body);
  if (!isPlainObject(body) || Reflect.ownKeys(body).length !== 0) {
    malformed();
  }
}

/**
 * Refuses any personal field anywhere in the body, before a coverage request is
 * interpreted. Objects and arrays are scanned recursively to a bounded depth;
 * a deeper body is `MALFORMED` rather than silently unscanned. Values are never
 * read for content, logged or echoed, and a non-object body is left to the shape
 * validator (`emptyObjectBody`/`districtCheckBody`).
 */
export function rejectPersonalFields(body: unknown): void {
  scanPersonalFields(body, 0);
}

function scanPersonalFields(value: unknown, depth: number): void {
  if (typeof value !== 'object' || value === null) {
    return;
  }
  if (depth > MAX_PERSONAL_DEPTH) {
    malformed();
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      scanPersonalFields(item, depth + 1);
    }
    return;
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (PERSONAL_FIELDS.has(key)) {
      throw new FormSessionError('PII_REJECTED');
    }
    scanPersonalFields(record[key], depth + 1);
  }
}

/** District-only advisory coverage body. It carries no address and no request. */
export interface DistrictCheckBody {
  readonly districtId: string;
}

/**
 * `{districtId: <canonical lowercase uuid>}` and nothing else. Personal fields
 * are refused first, so a body that carries an address is `PII_REJECTED` and is
 * never treated as an address check.
 */
export function districtCheckBody(body: unknown): DistrictCheckBody {
  rejectPersonalFields(body);
  const record = bodyRecord(body);
  if (!hasExactKeys(record, ['districtId'])) {
    malformed();
  }
  return { districtId: canonicalUuid(record['districtId']) };
}

export type ConsentAction = 'GIVEN' | 'REVOKED';

/**
 * GIVEN consent body. The purpose is not part of the body: the server fixes
 * REQUEST_PROCESSING for this surface, so a caller cannot widen or retarget it.
 */
export interface ConsentGivenBody {
  readonly action: 'GIVEN';
  readonly documentId: string;
  readonly documentVersionId: string;
  readonly evidenceRef: string;
}

/** REVOKED consent body. It names the exact GIVEN event it supersedes. */
export interface ConsentRevokedBody {
  readonly action: 'REVOKED';
  readonly supersedesEvidenceId: string;
  readonly evidenceRef: string;
  /**
   * Optional document revision. The legal port resolves both ids from
   * `supersedesEvidenceId`; when the client does send them they must be
   * canonical UUIDs and are checked against the stored GIVEN event.
   */
  readonly documentId?: string;
  readonly documentVersionId?: string;
}

export type ConsentBody = ConsentGivenBody | ConsentRevokedBody;

/** REVOKED body: required supersede reference plus optional exact document ids. */
function consentRevokedBody(record: Record<string, unknown>): ConsentRevokedBody {
  const allowed = [
    'action', 'supersedesEvidenceId', 'evidenceRef', 'documentId', 'documentVersionId',
  ];
  if (!hasAllowedKeys(record, ['action', 'supersedesEvidenceId', 'evidenceRef'], allowed)) {
    malformed();
  }
  const documentId = record['documentId'];
  const documentVersionId = record['documentVersionId'];
  return {
    action: 'REVOKED',
    supersedesEvidenceId: canonicalUuid(record['supersedesEvidenceId']),
    evidenceRef: canonicalUuid(record['evidenceRef']),
    ...(documentId === undefined ? {} : { documentId: canonicalUuid(documentId) }),
    ...(documentVersionId === undefined ? {} : { documentVersionId: canonicalUuid(documentVersionId) }),
  };
}

/**
 * Exact GIVEN/REVOKED body. Personal fields are refused first (`PII_REJECTED`),
 * the action discriminates the allowed key set, any extra key (including
 * `purpose`) is `MALFORMED`, and every present identifier must be a canonical
 * lowercase UUID.
 */
export function consentBody(body: unknown): ConsentBody {
  rejectPersonalFields(body);
  const record = bodyRecord(body);
  const action = record['action'];
  if (action === 'GIVEN') {
    if (!hasExactKeys(record, ['action', 'documentId', 'documentVersionId', 'evidenceRef'])) {
      malformed();
    }
    return {
      action: 'GIVEN',
      documentId: canonicalUuid(record['documentId']),
      documentVersionId: canonicalUuid(record['documentVersionId']),
      evidenceRef: canonicalUuid(record['evidenceRef']),
    };
  }
  if (action === 'REVOKED') {
    return consentRevokedBody(record);
  }
  malformed();
}

/** Public legal documents exposed by this surface. */
export type LegalKindParam = 'POLICY' | 'CONSENT_FORM';

/**
 * Path-parameter narrowing to the two public kinds. Every other value is
 * `NOT_FOUND` so the endpoint cannot be used as an oracle for internal kinds.
 */
export function legalKindParam(kind: string): LegalKindParam {
  if (kind === 'POLICY' || kind === 'CONSENT_FORM') {
    return kind;
  }
  throw new FormSessionError('NOT_FOUND');
}
