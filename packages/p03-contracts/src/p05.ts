/**
 * P05 shared wire contract (P05-03/P05-04 surface, docs/P05-PLAN.md §4.3, §6.1, §6.3).
 *
 * Platform-neutral and side-effect free: this module parses syntax, produces
 * closed normalized frozen DTOs, matches exact routes and drives a typed client
 * over an injected transport. It never performs network I/O, never reads
 * configuration, never computes authorization, never hashes an ETag and never
 * reads a coverage basis. Controllers must run the P05 authority chain
 * (live F/Origin/CSRF/anchor/legal or staff RBAC/scope) BEFORE they call any
 * body decoder: the DTO layer is not an admission gate and holds no authority.
 *
 * P03/P04 wire (index/p04 modules) is untouched; P05 lives behind its own
 * subpath export `@fixlevelup/p03-contracts/p05`.
 */
import { parseP04JsonText } from './p04-json.js';

export const P05_PREFIX = '/api/v1';

/** JSON body cap before parse (docs/P05-PLAN.md §6.3: 16 KiB, no compression). */
export const P05_BODY_BYTES = 16 * 1024;
/** Bounded response caps for the two canonical GETs and write receipts. */
export const P05_RESPONSE_BYTES = Object.freeze({ json: 16 * 1024, problem: 4 * 1024 });
/** Maximum number of fault IDs or attachment IDs in one request. */
export const P05_MAX_IDS = 32;
/**
 * Grammar bounds applied after the duplicate-aware JSON parse. Worst realistic
 * body is a manual REPAIR with 32 fault IDs and 32 attachments: ~100 nodes, so
 * the historical 256-node bound is kept instead of a looser one.
 */
export const P05_MAX_DEPTH = 8;
export const P05_MAX_NODES = 256;

/** Canonical request header names shared by the F and staff P05 surfaces. */
export const P05_HEADERS = Object.freeze({
  origin: 'origin',
  /** F proof selector; required on every F request including the canonical GET. */
  formSession: 'x-form-session-id',
  /** CSRF proof: F stateless mutate token or the staff session-bound token. */
  csrf: 'x-csrf-token',
  idempotency: 'idempotency-key',
  ifMatch: 'if-match',
  ifNoneMatch: 'if-none-match',
} as const);

/** Strong ETag prefix of the two canonical P05 GET representations (§4.3). */
export const P05_ETAG_PREFIX = 'p05-r1-';

export const P05_TYPES = Object.freeze(['CALLBACK', 'REPAIR'] as const);
export type P05Type = (typeof P05_TYPES)[number];

/** Closed persisted status vocabulary of the wf-r2-p05-v1 package (§6). */
export const P05_STATUSES = Object.freeze([
  'NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK', 'MANAGER_REVIEW',
  'WAITING_ASSIGNMENT', 'ASSIGNED', 'TECHNICIAN_ACCEPTED', 'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS',
  'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED', 'TECHNICIAN_COMPLETED',
  'REVISIT_REQUIRED', 'CLOSED', 'CANCELLED',
] as const);
export type P05Status = (typeof P05_STATUSES)[number];

export const P05_CHANNEL_PROVIDERS = Object.freeze(['TG', 'VK', 'MAX'] as const);
export type P05ChannelProvider = (typeof P05_CHANNEL_PROVIDERS)[number];

export const P05_COVERAGE_OUTCOMES = Object.freeze(['IN_ZONE', 'OUTSIDE', 'REVIEW', 'EXCEPTION'] as const);
export type P05CoverageOutcome = (typeof P05_COVERAGE_OUTCOMES)[number];

export const P05_COVERAGE_REASONS = Object.freeze(['OVERLAP_REVIEW', 'OUTSIDE_REVIEW', 'OPERATOR_REVIEW'] as const);
export type P05CoverageReason = (typeof P05_COVERAGE_REASONS)[number];

/**
 * Preference urgency, aligned one-to-one with the migration 022 source
 * vocabulary (`request_preference_revisions_urgency_check`): no local rename
 * and no lossy mapping is introduced here.
 */
export const P05_URGENCIES = Object.freeze(['FLEXIBLE', 'WITHIN_DAY', 'URGENT'] as const);
export type P05Urgency = (typeof P05_URGENCIES)[number];

export const P05_DETAIL_SECTIONS = Object.freeze(['ADDRESS', 'APPLIANCE', 'PREFERENCE'] as const);
export type P05DetailSection = (typeof P05_DETAIL_SECTIONS)[number];

export const P05_CONTACT_MODES = Object.freeze(['PHONE', 'CHANNEL'] as const);
export type P05ContactMode = (typeof P05_CONTACT_MODES)[number];

/** Closed refusal vocabulary of the shared problem envelope (§6.3 classification). */
export const P05_PROBLEM_STATUS = Object.freeze({
  REQUEST_REJECTED: 400,
  MALFORMED: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  REQUEST_TIMEOUT: 408,
  CONFLICT: 409,
  CITY_CONTEXT_STALE: 409,
  CONSENT_REQUIRED: 409,
  CHANNEL_OPTIONS_CHANGED: 409,
  CHANNEL_OFFER_DISABLED: 409,
  CHANNEL_NOT_READY: 409,
  FORM_ALREADY_SUBMITTED: 409,
  IDEMPOTENCY_KEY_REUSED: 409,
  COVERAGE_ASSESSMENT_STALE: 409,
  VERSION_MISMATCH: 412,
  BODY_TOO_LARGE: 413,
  UNSUPPORTED_MEDIA_TYPE: 415,
  SEMANTIC: 422,
  PRECONDITION_REQUIRED: 428,
  QUOTA: 429,
  INTERNAL_ERROR: 500,
  REQUEST_RULES_UNAVAILABLE: 503,
  NOT_READY: 503,
});
export type P05ProblemCode = keyof typeof P05_PROBLEM_STATUS;
export const P05_PROBLEM_CODES = Object.freeze(Object.keys(P05_PROBLEM_STATUS) as P05ProblemCode[]);

export interface P05Problem {
  readonly type: 'about:blank';
  readonly title: P05ProblemCode;
  readonly status: number;
  readonly code: P05ProblemCode;
  readonly requestId: string;
}

/** Two independent decode outcomes: shape/syntax (400) vs value semantics (422). */
export type P05DecodeKind = 'MALFORMED' | 'SEMANTIC';
export type P05DecodeCode =
  | 'BODY_TOO_LARGE' | 'BAD_UTF8' | 'BAD_JSON' | 'UNKNOWN_FIELD' | 'MISSING_FIELD' | 'BAD_TYPE'
  | 'BAD_FORMAT' | 'BAD_VALUE' | 'OUT_OF_RANGE' | 'TOO_MANY_ITEMS' | 'DUPLICATE_ITEM' | 'NO_BODY'
  | 'RESPONSE_TOO_LARGE' | 'BAD_RESPONSE'
  | 'CONSENT_NOT_ACCEPTED' | 'PHONE_PERMISSION_REQUIRED' | 'CHANNEL_NOT_ALLOWED'
  | 'AREA_REQUIRED' | 'AREA_NOT_ALLOWED' | 'REASON_REQUIRED' | 'REASON_NOT_ALLOWED'
  | 'PREFERENCE_EMPTY' | 'VISIT_WINDOW_INVALID' | 'VISIT_WINDOW_TOO_WIDE' | 'EMPTY_VALUE'
  | 'DUPLICATE_IDS' | 'FAULT_REQUIRED';

export class P05DecodeError extends Error {
  readonly kind: P05DecodeKind;
  readonly code: P05DecodeCode;
  readonly path: string;

  constructor(kind: P05DecodeKind, code: P05DecodeCode, path: string) {
    super(`P05 ${kind} ${code} at ${path}`);
    this.name = 'P05DecodeError';
    this.kind = kind;
    this.code = code;
    this.path = path;
  }
}

export class P05WireError extends Error {
  readonly status: number;
  readonly code: P05ProblemCode;
  readonly problem: P05Problem | null;

  constructor(status: number, code: P05ProblemCode, problem: P05Problem | null) {
    super(`P05 wire ${String(status)} ${code}`);
    this.name = 'P05WireError';
    this.status = status;
    this.code = code;
    this.problem = problem;
  }
}

/**
 * Closed mapping of a decode outcome to the exact problem status (§6.3):
 * a body over the 16 KiB cap is `413`, every other malformed shape is `400`,
 * a well-formed but semantically invalid value is `422`, and an unusable
 * response projection is the safe `503` rather than a `500`.
 */
export function p05DecodeStatus(error: P05DecodeError): { readonly status: number; readonly code: P05ProblemCode } {
  if (error.kind === 'SEMANTIC') { return { status: 422, code: 'SEMANTIC' }; }
  if (error.code === 'BODY_TOO_LARGE') { return { status: 413, code: 'BODY_TOO_LARGE' }; }
  if (error.code === 'RESPONSE_TOO_LARGE' || error.code === 'BAD_RESPONSE') {
    return { status: 503, code: 'NOT_READY' };
  }
  return { status: 400, code: 'MALFORMED' };
}

// ---------------------------------------------------------------------------
// Route surface: exact method + canonical pathname, no alias/trailing slash.
// ---------------------------------------------------------------------------

export type P05BodyKind =
  | 'callback' | 'repair' | 'contact-mode' | 'phone-withdrawal' | 'cancel' | 'manual'
  | 'empty' | 'convert-callback' | 'change-details' | 'coverage' | 'change-contact' | 'staff-withdraw-phone';
export type P05ResponseKind =
  | 'f-write-receipt' | 'staff-write-receipt' | 'effect-receipt' | 'request-session' | 'staff-request';

export interface P05RouteShape {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly scope: 'F' | 'STAFF';
  readonly body: P05BodyKind | null;
  readonly response: P05ResponseKind;
  readonly status: 200 | 201;
  readonly replayStatus: 200 | null;
  readonly ifMatch: boolean;
  readonly ifNoneMatch: boolean;
  readonly idempotencyKey: boolean;
  readonly origin: 'required' | 'optional' | 'none';
  readonly csrf: boolean;
}

export const P05_ROUTES = Object.freeze({
  createCallback: {
    method: 'POST', path: '/public/callback-requests', scope: 'F', body: 'callback', response: 'f-write-receipt',
    status: 201, replayStatus: 200, ifMatch: false, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  createRepair: {
    method: 'POST', path: '/public/repair-requests', scope: 'F', body: 'repair', response: 'f-write-receipt',
    status: 201, replayStatus: 200, ifMatch: false, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  readRequestSession: {
    method: 'GET', path: '/public/request-session', scope: 'F', body: null, response: 'request-session',
    status: 200, replayStatus: null, ifMatch: false, ifNoneMatch: true, idempotencyKey: false, origin: 'optional', csrf: false,
  },
  chooseCallback: {
    method: 'POST', path: '/public/request-session/contact-mode', scope: 'F', body: 'contact-mode', response: 'f-write-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  withdrawPhonePermission: {
    method: 'POST', path: '/public/request-session/phone-permissions', scope: 'F', body: 'phone-withdrawal', response: 'effect-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  cancelRequestF: {
    method: 'POST', path: '/public/request-session/cancel', scope: 'F', body: 'cancel', response: 'effect-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  createManualRequest: {
    method: 'POST', path: '/requests', scope: 'STAFF', body: 'manual', response: 'staff-write-receipt',
    status: 201, replayStatus: 200, ifMatch: false, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  readStaffRequest: {
    method: 'GET', path: '/requests/:id', scope: 'STAFF', body: null, response: 'staff-request',
    status: 200, replayStatus: null, ifMatch: false, ifNoneMatch: true, idempotencyKey: false, origin: 'none', csrf: false,
  },
  startReview: {
    method: 'POST', path: '/requests/:id/commands/start-review', scope: 'STAFF', body: 'empty', response: 'staff-write-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  convertCallback: {
    method: 'POST', path: '/requests/:id/commands/convert-callback', scope: 'STAFF', body: 'convert-callback', response: 'staff-write-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  changeDetails: {
    method: 'POST', path: '/requests/:id/commands/change-details', scope: 'STAFF', body: 'change-details', response: 'staff-write-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  recordCoverage: {
    method: 'POST', path: '/requests/:id/commands/record-coverage', scope: 'STAFF', body: 'coverage', response: 'staff-write-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  changeContact: {
    method: 'POST', path: '/requests/:id/commands/change-contact', scope: 'STAFF', body: 'change-contact', response: 'staff-write-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  readyForDispatch: {
    method: 'POST', path: '/requests/:id/commands/ready-for-dispatch', scope: 'STAFF', body: 'empty', response: 'staff-write-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  withdrawPhoneStaff: {
    method: 'POST', path: '/requests/:id/commands/withdraw-phone', scope: 'STAFF', body: 'staff-withdraw-phone', response: 'effect-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
  cancelRequestStaff: {
    method: 'POST', path: '/requests/:id/commands/cancel', scope: 'STAFF', body: 'cancel', response: 'effect-receipt',
    status: 200, replayStatus: null, ifMatch: true, ifNoneMatch: false, idempotencyKey: true, origin: 'required', csrf: true,
  },
} as const satisfies Record<string, P05RouteShape>);

export type P05Operation = keyof typeof P05_ROUTES;
export const P05_OPERATIONS = Object.freeze(Object.keys(P05_ROUTES) as P05Operation[]);

/** Runtime inventories; p05-verify.mjs asserts they match the route table. */
export const P05_ID_OPERATIONS = Object.freeze([
  'readStaffRequest', 'startReview', 'convertCallback', 'changeDetails', 'recordCoverage',
  'changeContact', 'readyForDispatch', 'withdrawPhoneStaff', 'cancelRequestStaff',
] as const);
export const P05_CSRF_OPERATIONS = Object.freeze([
  'createCallback', 'createRepair', 'chooseCallback', 'withdrawPhonePermission', 'cancelRequestF',
  'createManualRequest', 'startReview', 'convertCallback', 'changeDetails', 'recordCoverage',
  'changeContact', 'readyForDispatch', 'withdrawPhoneStaff', 'cancelRequestStaff',
] as const);
export const P05_IF_MATCH_OPERATIONS = Object.freeze([
  'chooseCallback', 'withdrawPhonePermission', 'cancelRequestF', 'startReview', 'convertCallback',
  'changeDetails', 'recordCoverage', 'changeContact', 'readyForDispatch', 'withdrawPhoneStaff', 'cancelRequestStaff',
] as const);
export const P05_GET_OPERATIONS = Object.freeze(['readRequestSession', 'readStaffRequest'] as const);
export const P05_BODY_OPERATIONS = Object.freeze([
  'createCallback', 'createRepair', 'chooseCallback', 'withdrawPhonePermission', 'cancelRequestF',
  'createManualRequest', 'startReview', 'convertCallback', 'changeDetails', 'recordCoverage',
  'changeContact', 'readyForDispatch', 'withdrawPhoneStaff', 'cancelRequestStaff',
] as const);

export type P05IdOperation = (typeof P05_ID_OPERATIONS)[number];
export type P05CsrfOperation = (typeof P05_CSRF_OPERATIONS)[number];
export type P05IfMatchOperation = (typeof P05_IF_MATCH_OPERATIONS)[number];
export type P05GetOperation = (typeof P05_GET_OPERATIONS)[number];
export type P05BodyOperation = (typeof P05_BODY_OPERATIONS)[number];

export function isP05Operation(value: unknown): value is P05Operation {
  return typeof value === 'string' && Object.hasOwn(P05_ROUTES, value);
}

export type P05ParamsByOperation = {
  readonly [K in P05Operation]: K extends P05IdOperation ? { readonly id: string } : Readonly<Record<string, never>>;
};

export type P05Match = {
  readonly [K in P05Operation]: { readonly operation: K; readonly scope: (typeof P05_ROUTES)[K]['scope']; readonly params: P05ParamsByOperation[K] };
}[P05Operation];

const UUID_PATTERN = '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const UUID = new RegExp(`^${UUID_PATTERN}$`);
const COMPILED_ROUTES = P05_OPERATIONS.map((operation) => {
  const route = P05_ROUTES[operation];
  // The UUID pattern is wrapped in a capture group: the only dynamic segment is
  // the request id, so `match[1]` is unambiguously that id.
  const pattern = new RegExp(`^${P05_PREFIX}${route.path.replace(':id', `(${UUID_PATTERN})`)}$`);
  return { operation, method: route.method, pattern, hasId: route.path.includes(':id') };
});

/**
 * Match the canonical pathname (never a query string, `%` encoding, trailing
 * slash, double slash, fragment or newline). Method must be the exact uppercase
 * literal of the route table.
 */
export function matchP05Route(method: string, pathname: string): P05Match | null {
  if (typeof method !== 'string' || typeof pathname !== 'string') { return null; }
  for (const entry of COMPILED_ROUTES) {
    if (entry.method !== method) { continue; }
    const match = entry.pattern.exec(pathname);
    if (match === null) { continue; }
    if (!entry.hasId) {
      return { operation: entry.operation, scope: P05_ROUTES[entry.operation].scope, params: {} } as P05Match;
    }
    const id = match[1];
    if (id === undefined) { continue; }
    return { operation: entry.operation, scope: P05_ROUTES[entry.operation].scope, params: { id } } as P05Match;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Normalized DTOs (closed, deep-frozen, no unknown/null/duplicate members).
// ---------------------------------------------------------------------------

export interface P05FContact { readonly name: string; readonly phone: string }
export interface P05Consent { readonly evidenceId: string; readonly documentVersionId: string; readonly accepted: true }
export interface P05ChannelSelection {
  readonly provider: P05ChannelProvider;
  readonly optionVersionId: string;
  readonly catalogVersionId: string;
  readonly purpose: 'REQUEST_CONFIRMATION';
}
export interface P05Address {
  readonly street: string;
  readonly building: string;
  readonly districtId?: string;
  readonly apartment?: string;
  readonly entrance?: string;
  readonly floor?: string;
  readonly intercom?: string;
  readonly accessNotes?: string;
}
export interface P05Appliance {
  readonly categoryId: string;
  readonly brandId?: string;
  readonly modelId?: string;
  readonly modelText?: string;
  readonly approximateAge?: number;
}
export interface P05Fault {
  /**
   * Selected published fault ids of the request's category. A repair is complete
   * with either at least one such id OR a non-empty `otherDescription`
   * (docs/P05-PLAN.md §1, Q12/Q16), so the wire may omit this member or send an
   * empty array; the normalized DTO always carries the array (`[]` when omitted).
   */
  readonly faultIds: readonly string[];
  readonly otherDescription?: string;
  readonly description?: string;
  readonly errorCode?: string;
}
export interface P05PreferredVisit { readonly from: string; readonly to: string }

export interface P05CallbackRequest {
  readonly contact: P05FContact;
  readonly consent: P05Consent;
  readonly phonePermission: true;
  readonly callbackIntervalId?: string;
  readonly comment?: string;
}

export interface P05RepairRequest {
  readonly contact: P05FContact;
  readonly consent: P05Consent;
  readonly channelSelection: P05ChannelSelection;
  readonly address: P05Address;
  readonly appliance: P05Appliance;
  readonly fault: P05Fault;
  readonly urgency?: P05Urgency;
  readonly preferredVisit?: P05PreferredVisit;
  readonly attachments?: readonly string[];
}

export interface P05ManualPhoneContact {
  readonly mode: 'PHONE';
  readonly name: string;
  readonly phone: string;
  readonly phonePermission: true;
  readonly phoneEvidenceId: string;
}
export interface P05ManualChannelContact {
  readonly mode: 'CHANNEL';
  readonly name: string;
  /**
   * The normalized phone is retained for manual no-call intake (§3/§4): staff
   * captured it, and it is needed to reach the client. It is explicitly NOT a
   * PHONE permission proof — that is a separate append-only evidence row.
   */
  readonly phone: string;
  readonly channelSelection: P05ChannelSelection;
}
export type P05ManualContact = P05ManualPhoneContact | P05ManualChannelContact;

export interface P05ManualCallbackRequest {
  readonly type: 'CALLBACK';
  readonly sourceEntryId: string;
  readonly evidenceId: string;
  readonly contact: P05ManualPhoneContact;
  readonly callbackIntervalId?: string;
  readonly comment?: string;
}
export interface P05ManualRepairRequest {
  readonly type: 'REPAIR';
  readonly sourceEntryId: string;
  readonly evidenceId: string;
  readonly contact: P05ManualContact;
  readonly address: P05Address;
  readonly appliance: P05Appliance;
  readonly fault: P05Fault;
  readonly urgency?: P05Urgency;
  readonly preferredVisit?: P05PreferredVisit;
}
export type P05ManualRequest = P05ManualCallbackRequest | P05ManualRepairRequest;

export interface P05ContactModeInput { readonly phonePermission: true }
export interface P05PhoneWithdrawalInput { readonly action: 'REVOKED' }
export interface P05CancelInput { readonly reasonEntryId: string }
export type P05EmptyInput = Readonly<Record<string, never>>;

export interface P05ConvertCallbackInput {
  readonly address: P05Address;
  readonly appliance: P05Appliance;
  readonly fault: P05Fault;
  readonly urgency?: P05Urgency;
  readonly preferredVisit?: P05PreferredVisit;
}

export interface P05ChangeDetailsAddress { readonly section: 'ADDRESS'; readonly address: P05Address }
/**
 * APPLIANCE is a named replacement of the appliance *and* its fault selection:
 * a new appliance invalidates the previous fault ids, so both travel together
 * and neither is silently dropped.
 */
export interface P05ChangeDetailsAppliance {
  readonly section: 'APPLIANCE';
  readonly appliance: P05Appliance;
  readonly fault: P05Fault;
}
export interface P05ChangeDetailsPreference {
  readonly section: 'PREFERENCE';
  readonly urgency?: P05Urgency;
  readonly preferredVisit?: P05PreferredVisit;
}
export type P05ChangeDetailsInput = P05ChangeDetailsAddress | P05ChangeDetailsAppliance | P05ChangeDetailsPreference;

export interface P05CoverageInput {
  readonly evidenceId: string;
  readonly areaId?: string;
  readonly outcome: P05CoverageOutcome;
  readonly reason?: P05CoverageReason;
}

/**
 * ChangeContact replaces only the contact values. The contact mode is persisted
 * server-side and is not switchable here: no `mode`, no `channelSelection` and no
 * `phonePermission` member exists, so a replacement can never grant PHONE rights
 * or move the request to another channel.
 */
export interface P05ChangeContactInput {
  readonly contact: P05FContact;
  readonly evidenceId: string;
}

export interface P05StaffWithdrawInput { readonly evidenceId: string }

export interface P05Bodies {
  createCallback: P05CallbackRequest;
  createRepair: P05RepairRequest;
  readRequestSession: never;
  chooseCallback: P05ContactModeInput;
  withdrawPhonePermission: P05PhoneWithdrawalInput;
  cancelRequestF: P05CancelInput;
  createManualRequest: P05ManualRequest;
  readStaffRequest: never;
  startReview: P05EmptyInput;
  convertCallback: P05ConvertCallbackInput;
  changeDetails: P05ChangeDetailsInput;
  recordCoverage: P05CoverageInput;
  changeContact: P05ChangeContactInput;
  readyForDispatch: P05EmptyInput;
  withdrawPhoneStaff: P05StaffWithdrawInput;
  cancelRequestStaff: P05CancelInput;
}

export interface P05FWriteReceipt { readonly publicNumber: string; readonly status: P05Status; readonly version: number }
export interface P05StaffWriteReceipt {
  readonly id: string;
  readonly publicNumber: string;
  readonly status: P05Status;
  readonly version: number;
}
export interface P05EffectReceipt { readonly applied: boolean; readonly version: number }
export type P05RequestSessionData =
  | { readonly publicNumber: string; readonly status: P05Status; readonly version: number }
  | { readonly version: number };
export type P05StaffRequestData =
  | { readonly id: string; readonly publicNumber: string; readonly type: P05Type; readonly status: P05Status; readonly version: number }
  | { readonly version: number };

export interface P05Data {
  createCallback: P05FWriteReceipt;
  createRepair: P05FWriteReceipt;
  readRequestSession: P05RequestSessionData;
  chooseCallback: P05FWriteReceipt;
  withdrawPhonePermission: P05EffectReceipt;
  cancelRequestF: P05EffectReceipt;
  createManualRequest: P05StaffWriteReceipt;
  readStaffRequest: P05StaffRequestData;
  startReview: P05StaffWriteReceipt;
  convertCallback: P05StaffWriteReceipt;
  changeDetails: P05StaffWriteReceipt;
  recordCoverage: P05StaffWriteReceipt;
  changeContact: P05StaffWriteReceipt;
  readyForDispatch: P05StaffWriteReceipt;
  withdrawPhoneStaff: P05EffectReceipt;
  cancelRequestStaff: P05EffectReceipt;
}

// ---------------------------------------------------------------------------
// Primitive helpers.
// ---------------------------------------------------------------------------

function fail(kind: P05DecodeKind, code: P05DecodeCode, path: string): never {
  throw new P05DecodeError(kind, code, path);
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) { return false; }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function object(value: unknown, path: string, allowed: readonly string[], required: readonly string[]): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) { return fail('MALFORMED', 'UNKNOWN_FIELD', `${path}.${key}`); }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) { return fail('MALFORMED', 'MISSING_FIELD', `${path}.${key}`); }
  }
  return value;
}

// Control characters are refused by code point instead of a regex class so the
// rule stays readable and lint-clean; `\n`/`\t` are allowed only in multiline text.
function hasForbiddenControl(value: string, multiline: boolean): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) { continue; }
    if (codePoint === 0x7f) { return true; }
    if (codePoint < 0x20 && !(multiline && (codePoint === 0x0a || codePoint === 0x09))) { return true; }
  }
  return false;
}

function text(value: unknown, path: string, min: number, max: number, multiline = false): string {
  if (typeof value !== 'string') { return fail('MALFORMED', 'BAD_TYPE', path); }
  if (value !== value.normalize('NFC')) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  if (value !== value.trim()) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  if (value.length < min || value.length > max) { return fail('MALFORMED', 'OUT_OF_RANGE', path); }
  if (hasForbiddenControl(value, multiline)) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  return value;
}

function optionalText(value: unknown, path: string, min: number, max: number, multiline = false): string | undefined {
  return value === undefined ? undefined : text(value, path, min, max, multiline);
}

function uuid(value: unknown, path: string): string {
  if (typeof value !== 'string') { return fail('MALFORMED', 'BAD_TYPE', path); }
  if (!UUID.test(value)) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  return value;
}

function optionalUuid(value: unknown, path: string): string | undefined {
  return value === undefined ? undefined : uuid(value, path);
}

function integer(value: unknown, path: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  if (value < min || value > max) { return fail('MALFORMED', 'OUT_OF_RANGE', path); }
  return value;
}

function version(value: unknown, path: string): number {
  return integer(value, path, 1, 2_147_483_647);
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') { return fail('MALFORMED', 'BAD_TYPE', path); }
  return value;
}

function oneOf<T extends string>(value: unknown, path: string, allowed: readonly T[]): T {
  if (typeof value !== 'string') { return fail('MALFORMED', 'BAD_TYPE', path); }
  const match = allowed.find((entry) => entry === value);
  if (match === undefined) { return fail('MALFORMED', 'BAD_VALUE', path); }
  return match;
}

function phone(value: unknown, path: string): string {
  const result = text(value, path, 12, 16);
  if (!/^\+[1-9][0-9]{9,14}$/u.test(result)) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  return result;
}

const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
function instant(value: unknown, path: string): string {
  if (typeof value !== 'string' || !INSTANT.test(value)) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  return value;
}

function uuidList(value: unknown, path: string, min: number, max: number): readonly string[] {
  if (!Array.isArray(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  if (value.length < min || value.length > max) { return fail('MALFORMED', 'OUT_OF_RANGE', path); }
  const seen = new Set<string>();
  const result: string[] = [];
  for (const [index, entry] of value.entries()) {
    const id = uuid(entry, `${path}[${String(index)}]`);
    if (seen.has(id)) { return fail('SEMANTIC', 'DUPLICATE_IDS', `${path}[${String(index)}]`); }
    seen.add(id);
    result.push(id);
  }
  return result;
}

function freeze<T>(value: T): T {
  if (Array.isArray(value)) {
    for (const entry of value) { freeze(entry); }
  } else if (isRecord(value)) {
    for (const key of Object.keys(value)) { freeze(value[key]); }
  }
  return Object.freeze(value);
}

// ---------------------------------------------------------------------------
// Body decoders (value level).
// ---------------------------------------------------------------------------

export function decodeP05FContact(value: unknown, path = '$.contact'): P05FContact {
  const record = object(value, path, ['name', 'phone'], ['name', 'phone']);
  return freeze({ name: text(record['name'], `${path}.name`, 1, 200), phone: phone(record['phone'], `${path}.phone`) });
}

export function decodeP05Consent(value: unknown, path = '$.consent'): P05Consent {
  const record = object(value, path, ['evidenceId', 'documentVersionId', 'accepted'], ['evidenceId', 'documentVersionId', 'accepted']);
  const accepted = boolean(record['accepted'], `${path}.accepted`);
  if (!accepted) { return fail('SEMANTIC', 'CONSENT_NOT_ACCEPTED', `${path}.accepted`); }
  return freeze({
    evidenceId: uuid(record['evidenceId'], `${path}.evidenceId`),
    documentVersionId: uuid(record['documentVersionId'], `${path}.documentVersionId`),
    accepted: true,
  });
}

export function decodeP05ChannelSelection(value: unknown, path = '$.channelSelection'): P05ChannelSelection {
  const record = object(value, path, ['provider', 'optionVersionId', 'catalogVersionId', 'purpose'],
    ['provider', 'optionVersionId', 'catalogVersionId', 'purpose']);
  return freeze({
    provider: oneOf(record['provider'], `${path}.provider`, P05_CHANNEL_PROVIDERS),
    optionVersionId: uuid(record['optionVersionId'], `${path}.optionVersionId`),
    catalogVersionId: uuid(record['catalogVersionId'], `${path}.catalogVersionId`),
    purpose: oneOf(record['purpose'], `${path}.purpose`, ['REQUEST_CONFIRMATION'] as const),
  });
}

export function decodeP05Address(value: unknown, path = '$.address'): P05Address {
  const record = object(value, path, ['street', 'building', 'districtId', 'apartment', 'entrance', 'floor', 'intercom', 'accessNotes'],
    ['street', 'building']);
  const districtId = optionalUuid(record['districtId'], `${path}.districtId`);
  const apartment = optionalText(record['apartment'], `${path}.apartment`, 1, 50);
  const entrance = optionalText(record['entrance'], `${path}.entrance`, 1, 50);
  const floor = optionalText(record['floor'], `${path}.floor`, 1, 50);
  const intercom = optionalText(record['intercom'], `${path}.intercom`, 1, 100);
  const accessNotes = optionalText(record['accessNotes'], `${path}.accessNotes`, 1, 1000, true);
  return freeze({
    street: text(record['street'], `${path}.street`, 1, 300),
    building: text(record['building'], `${path}.building`, 1, 50),
    ...(districtId === undefined ? {} : { districtId }),
    ...(apartment === undefined ? {} : { apartment }),
    ...(entrance === undefined ? {} : { entrance }),
    ...(floor === undefined ? {} : { floor }),
    ...(intercom === undefined ? {} : { intercom }),
    ...(accessNotes === undefined ? {} : { accessNotes }),
  });
}

export function decodeP05Appliance(value: unknown, path = '$.appliance'): P05Appliance {
  const record = object(value, path, ['categoryId', 'brandId', 'modelId', 'modelText', 'approximateAge'],
    ['categoryId']);
  const brandId = optionalUuid(record['brandId'], `${path}.brandId`);
  const modelId = optionalUuid(record['modelId'], `${path}.modelId`);
  const modelText = optionalText(record['modelText'], `${path}.modelText`, 1, 200);
  const approximateAge = record['approximateAge'] === undefined
    ? undefined
    : integer(record['approximateAge'], `${path}.approximateAge`, 0, 100);
  return freeze({
    categoryId: uuid(record['categoryId'], `${path}.categoryId`),
    ...(brandId === undefined ? {} : { brandId }),
    ...(modelId === undefined ? {} : { modelId }),
    ...(modelText === undefined ? {} : { modelText }),
    ...(approximateAge === undefined ? {} : { approximateAge }),
  });
}

/**
 * Fault snapshot source data. `faultIds` is OPTIONAL on the wire: a repair is
 * complete with at least one selected published fault of the request's category
 * OR an "other fault" with a non-empty description (docs/P05-PLAN.md §1,
 * Q12/Q16). Omitted `faultIds` (and an explicit `[]`) normalize to an empty
 * frozen array, so the canonical re-encoded bytes always carry `faultIds`; a
 * fault block with neither a selected id nor `otherDescription` is the semantic
 * `422 FAULT_REQUIRED`, never a malformed 400.
 */
export function decodeP05Fault(value: unknown, path = '$.fault'): P05Fault {
  const record = object(value, path, ['faultIds', 'otherDescription', 'description', 'errorCode'], []);
  const otherDescription = optionalText(record['otherDescription'], `${path}.otherDescription`, 1, 1000, true);
  const description = optionalText(record['description'], `${path}.description`, 1, 2000, true);
  const errorCode = optionalText(record['errorCode'], `${path}.errorCode`, 1, 100);
  const faultIds = record['faultIds'] === undefined
    ? []
    : uuidList(record['faultIds'], `${path}.faultIds`, 0, P05_MAX_IDS);
  if (faultIds.length === 0 && otherDescription === undefined) {
    return fail('SEMANTIC', 'FAULT_REQUIRED', path);
  }
  return freeze({
    faultIds,
    ...(otherDescription === undefined ? {} : { otherDescription }),
    ...(description === undefined ? {} : { description }),
    ...(errorCode === undefined ? {} : { errorCode }),
  });
}

export function decodeP05PreferredVisit(value: unknown, path = '$.preferredVisit'): P05PreferredVisit {
  const record = object(value, path, ['from', 'to'], ['from', 'to']);
  const from = instant(record['from'], `${path}.from`);
  const to = instant(record['to'], `${path}.to`);
  const span = Date.parse(to) - Date.parse(from);
  if (span <= 0) { return fail('SEMANTIC', 'VISIT_WINDOW_INVALID', path); }
  if (span > 14 * 24 * 60 * 60 * 1000) { return fail('SEMANTIC', 'VISIT_WINDOW_TOO_WIDE', path); }
  return freeze({ from, to });
}

function optionalPreferredVisit(value: unknown, path: string): P05PreferredVisit | undefined {
  return value === undefined ? undefined : decodeP05PreferredVisit(value, path);
}

function optionalUrgency(value: unknown, path: string): P05Urgency | undefined {
  return value === undefined ? undefined : oneOf(value, path, P05_URGENCIES);
}

function optionalComment(value: unknown, path: string): string | undefined {
  const result = optionalText(value, path, 1, 2000, true);
  if (result !== undefined && result.length === 0) { return fail('SEMANTIC', 'EMPTY_VALUE', path); }
  return result;
}

function phonePermission(value: unknown, path: string): true {
  const result = boolean(value, path);
  if (!result) { return fail('SEMANTIC', 'PHONE_PERMISSION_REQUIRED', path); }
  return true;
}

function decodeManualPhoneContact(value: unknown, path: string): P05ManualPhoneContact {
  const record = object(value, path, ['mode', 'name', 'phone', 'phonePermission', 'phoneEvidenceId'],
    ['mode', 'name', 'phone', 'phonePermission', 'phoneEvidenceId']);
  oneOf(record['mode'], `${path}.mode`, ['PHONE'] as const);
  return freeze({
    mode: 'PHONE',
    name: text(record['name'], `${path}.name`, 1, 200),
    phone: phone(record['phone'], `${path}.phone`),
    phonePermission: phonePermission(record['phonePermission'], `${path}.phonePermission`),
    phoneEvidenceId: uuid(record['phoneEvidenceId'], `${path}.phoneEvidenceId`),
  });
}

function decodeManualChannelContact(value: unknown, path: string): P05ManualChannelContact {
  const record = object(value, path, ['mode', 'name', 'phone', 'channelSelection'],
    ['mode', 'name', 'phone', 'channelSelection']);
  oneOf(record['mode'], `${path}.mode`, ['CHANNEL'] as const);
  return freeze({
    mode: 'CHANNEL',
    name: text(record['name'], `${path}.name`, 1, 200),
    // Stored for manual no-call intake; never a permission proof and never a
    // substitute for the append-only PHONE evidence row.
    phone: phone(record['phone'], `${path}.phone`),
    channelSelection: decodeP05ChannelSelection(record['channelSelection'], `${path}.channelSelection`),
  });
}

function decodeManualContact(value: unknown, path: string): P05ManualContact {
  if (!isRecord(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  const mode = oneOf(value['mode'], `${path}.mode`, P05_CONTACT_MODES);
  return mode === 'PHONE' ? decodeManualPhoneContact(value, path) : decodeManualChannelContact(value, path);
}

export function decodeP05CallbackRequest(value: unknown, path = '$'): P05CallbackRequest {
  const record = object(value, path, ['contact', 'consent', 'phonePermission', 'callbackIntervalId', 'comment'],
    ['contact', 'consent', 'phonePermission']);
  const callbackIntervalId = optionalUuid(record['callbackIntervalId'], `${path}.callbackIntervalId`);
  const comment = optionalComment(record['comment'], `${path}.comment`);
  return freeze({
    contact: decodeP05FContact(record['contact'], `${path}.contact`),
    consent: decodeP05Consent(record['consent'], `${path}.consent`),
    phonePermission: phonePermission(record['phonePermission'], `${path}.phonePermission`),
    ...(callbackIntervalId === undefined ? {} : { callbackIntervalId }),
    ...(comment === undefined ? {} : { comment }),
  });
}

export function decodeP05RepairRequest(value: unknown, path = '$'): P05RepairRequest {
  const record = object(value, path,
    ['contact', 'consent', 'channelSelection', 'address', 'appliance', 'fault', 'urgency', 'preferredVisit', 'attachments'],
    ['contact', 'consent', 'channelSelection', 'address', 'appliance', 'fault']);
  const urgency = optionalUrgency(record['urgency'], `${path}.urgency`);
  const preferredVisit = optionalPreferredVisit(record['preferredVisit'], `${path}.preferredVisit`);
  const attachments = record['attachments'] === undefined
    ? undefined
    : uuidList(record['attachments'], `${path}.attachments`, 0, P05_MAX_IDS);
  return freeze({
    contact: decodeP05FContact(record['contact'], `${path}.contact`),
    consent: decodeP05Consent(record['consent'], `${path}.consent`),
    channelSelection: decodeP05ChannelSelection(record['channelSelection'], `${path}.channelSelection`),
    address: decodeP05Address(record['address'], `${path}.address`),
    appliance: decodeP05Appliance(record['appliance'], `${path}.appliance`),
    fault: decodeP05Fault(record['fault'], `${path}.fault`),
    ...(urgency === undefined ? {} : { urgency }),
    ...(preferredVisit === undefined ? {} : { preferredVisit }),
    ...(attachments === undefined ? {} : { attachments }),
  });
}

function decodeManualCallback(value: Readonly<Record<string, unknown>>, path: string): P05ManualCallbackRequest {
  const record = object(value, path,
    ['type', 'sourceEntryId', 'evidenceId', 'contact', 'callbackIntervalId', 'comment'],
    ['type', 'sourceEntryId', 'evidenceId', 'contact']);
  const contactValue = record['contact'];
  if (!isRecord(contactValue)) { return fail('MALFORMED', 'BAD_TYPE', `${path}.contact`); }
  const mode = oneOf(contactValue['mode'], `${path}.contact.mode`, P05_CONTACT_MODES);
  if (mode !== 'PHONE') { return fail('SEMANTIC', 'CHANNEL_NOT_ALLOWED', `${path}.contact.mode`); }
  const callbackIntervalId = optionalUuid(record['callbackIntervalId'], `${path}.callbackIntervalId`);
  const comment = optionalComment(record['comment'], `${path}.comment`);
  return freeze({
    type: 'CALLBACK',
    sourceEntryId: uuid(record['sourceEntryId'], `${path}.sourceEntryId`),
    evidenceId: uuid(record['evidenceId'], `${path}.evidenceId`),
    contact: decodeManualPhoneContact(contactValue, `${path}.contact`),
    ...(callbackIntervalId === undefined ? {} : { callbackIntervalId }),
    ...(comment === undefined ? {} : { comment }),
  });
}

function decodeManualRepair(value: Readonly<Record<string, unknown>>, path: string): P05ManualRepairRequest {
  const record = object(value, path,
    ['type', 'sourceEntryId', 'evidenceId', 'contact', 'address', 'appliance', 'fault', 'urgency', 'preferredVisit'],
    ['type', 'sourceEntryId', 'evidenceId', 'contact', 'address', 'appliance', 'fault']);
  const urgency = optionalUrgency(record['urgency'], `${path}.urgency`);
  const preferredVisit = optionalPreferredVisit(record['preferredVisit'], `${path}.preferredVisit`);
  return freeze({
    type: 'REPAIR',
    sourceEntryId: uuid(record['sourceEntryId'], `${path}.sourceEntryId`),
    evidenceId: uuid(record['evidenceId'], `${path}.evidenceId`),
    contact: decodeManualContact(record['contact'], `${path}.contact`),
    address: decodeP05Address(record['address'], `${path}.address`),
    appliance: decodeP05Appliance(record['appliance'], `${path}.appliance`),
    fault: decodeP05Fault(record['fault'], `${path}.fault`),
    ...(urgency === undefined ? {} : { urgency }),
    ...(preferredVisit === undefined ? {} : { preferredVisit }),
  });
}

export function decodeP05ManualRequest(value: unknown, path = '$'): P05ManualRequest {
  if (!isRecord(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  const type = oneOf(value['type'], `${path}.type`, P05_TYPES);
  return type === 'CALLBACK' ? decodeManualCallback(value, path) : decodeManualRepair(value, path);
}

export function decodeP05ContactMode(value: unknown, path = '$'): P05ContactModeInput {
  const record = object(value, path, ['phonePermission'], ['phonePermission']);
  return freeze({ phonePermission: phonePermission(record['phonePermission'], `${path}.phonePermission`) });
}

export function decodeP05PhoneWithdrawal(value: unknown, path = '$'): P05PhoneWithdrawalInput {
  const record = object(value, path, ['action'], ['action']);
  oneOf(record['action'], `${path}.action`, ['REVOKED'] as const);
  return freeze({ action: 'REVOKED' });
}

export function decodeP05Cancel(value: unknown, path = '$'): P05CancelInput {
  const record = object(value, path, ['reasonEntryId'], ['reasonEntryId']);
  return freeze({ reasonEntryId: uuid(record['reasonEntryId'], `${path}.reasonEntryId`) });
}

export function decodeP05Empty(value: unknown, path = '$'): P05EmptyInput {
  object(value, path, [], []);
  return freeze({});
}

export function decodeP05ConvertCallback(value: unknown, path = '$'): P05ConvertCallbackInput {
  const record = object(value, path, ['address', 'appliance', 'fault', 'urgency', 'preferredVisit'],
    ['address', 'appliance', 'fault']);
  const urgency = optionalUrgency(record['urgency'], `${path}.urgency`);
  const preferredVisit = optionalPreferredVisit(record['preferredVisit'], `${path}.preferredVisit`);
  return freeze({
    address: decodeP05Address(record['address'], `${path}.address`),
    appliance: decodeP05Appliance(record['appliance'], `${path}.appliance`),
    fault: decodeP05Fault(record['fault'], `${path}.fault`),
    ...(urgency === undefined ? {} : { urgency }),
    ...(preferredVisit === undefined ? {} : { preferredVisit }),
  });
}

export function decodeP05ChangeDetails(value: unknown, path = '$'): P05ChangeDetailsInput {
  if (!isRecord(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  const section = oneOf(value['section'], `${path}.section`, P05_DETAIL_SECTIONS);
  if (section === 'ADDRESS') {
    const record = object(value, path, ['section', 'address'], ['section', 'address']);
    return freeze({ section: 'ADDRESS', address: decodeP05Address(record['address'], `${path}.address`) });
  }
  if (section === 'APPLIANCE') {
    const record = object(value, path, ['section', 'appliance', 'fault'], ['section', 'appliance', 'fault']);
    return freeze({
      section: 'APPLIANCE',
      appliance: decodeP05Appliance(record['appliance'], `${path}.appliance`),
      fault: decodeP05Fault(record['fault'], `${path}.fault`),
    });
  }
  const record = object(value, path, ['section', 'urgency', 'preferredVisit'], ['section']);
  const urgency = optionalUrgency(record['urgency'], `${path}.urgency`);
  const preferredVisit = optionalPreferredVisit(record['preferredVisit'], `${path}.preferredVisit`);
  if (urgency === undefined && preferredVisit === undefined) {
    return fail('SEMANTIC', 'PREFERENCE_EMPTY', path);
  }
  return freeze({
    section: 'PREFERENCE',
    ...(urgency === undefined ? {} : { urgency }),
    ...(preferredVisit === undefined ? {} : { preferredVisit }),
  });
}

/**
 * Coverage assessment rules, aligned with migration 024
 * (`request_coverage_assessments`):
 *   CHECK (outcome NOT IN ('IN_ZONE','EXCEPTION') OR area_id IS NOT NULL)
 *   CHECK (outcome NOT IN ('OUTSIDE','EXCEPTION') OR reason IS NOT NULL)
 * plus the plan's "no automatic exception" rule:
 *   - IN_ZONE:   areaId required; an optional reason may only be OVERLAP_REVIEW
 *                (a positive overlap decision);
 *   - EXCEPTION: areaId required AND an explicit rationale is required, one of
 *                OUTSIDE_REVIEW | OPERATOR_REVIEW; EXCEPTION is never automatic;
 *   - OUTSIDE:   reason required (OUTSIDE_REVIEW | OPERATOR_REVIEW); an areaId
 *                would imply positive authority, so it is refused;
 *   - REVIEW:    reason required (OVERLAP_REVIEW | OPERATOR_REVIEW); areaId refused.
 * The candidate basis is never taken from the body: the server reads it via its
 * own coverage port under the GEO fence.
 */
export function decodeP05Coverage(value: unknown, path = '$'): P05CoverageInput {
  const record = object(value, path, ['evidenceId', 'areaId', 'outcome', 'reason'], ['evidenceId', 'outcome']);
  const outcome = oneOf(record['outcome'], `${path}.outcome`, P05_COVERAGE_OUTCOMES);
  const areaId = optionalUuid(record['areaId'], `${path}.areaId`);
  const reason = record['reason'] === undefined ? undefined : oneOf(record['reason'], `${path}.reason`, P05_COVERAGE_REASONS);
  if (outcome === 'IN_ZONE') {
    if (areaId === undefined) { return fail('SEMANTIC', 'AREA_REQUIRED', `${path}.areaId`); }
    if (reason !== undefined && reason !== 'OVERLAP_REVIEW') {
      return fail('SEMANTIC', 'REASON_NOT_ALLOWED', `${path}.reason`);
    }
  } else if (outcome === 'EXCEPTION') {
    if (areaId === undefined) { return fail('SEMANTIC', 'AREA_REQUIRED', `${path}.areaId`); }
    if (reason !== 'OUTSIDE_REVIEW' && reason !== 'OPERATOR_REVIEW') {
      return fail('SEMANTIC', 'REASON_REQUIRED', `${path}.reason`);
    }
  } else if (outcome === 'OUTSIDE') {
    if (reason !== 'OUTSIDE_REVIEW' && reason !== 'OPERATOR_REVIEW') {
      return fail('SEMANTIC', 'REASON_REQUIRED', `${path}.reason`);
    }
    if (areaId !== undefined) { return fail('SEMANTIC', 'AREA_NOT_ALLOWED', `${path}.areaId`); }
  } else {
    if (reason !== 'OVERLAP_REVIEW' && reason !== 'OPERATOR_REVIEW') {
      return fail('SEMANTIC', 'REASON_REQUIRED', `${path}.reason`);
    }
    if (areaId !== undefined) { return fail('SEMANTIC', 'AREA_NOT_ALLOWED', `${path}.areaId`); }
  }
  return freeze({
    evidenceId: uuid(record['evidenceId'], `${path}.evidenceId`),
    ...(areaId === undefined ? {} : { areaId }),
    outcome,
    ...(reason === undefined ? {} : { reason }),
  });
}

export function decodeP05ChangeContact(value: unknown, path = '$'): P05ChangeContactInput {
  const record = object(value, path, ['contact', 'evidenceId'], ['contact', 'evidenceId']);
  // Only the contact values are replaceable. A supplied `mode`, `channelSelection`
  // or `phonePermission` is an unknown member and therefore a malformed 400: the
  // contact mode and the PHONE permission are server-persisted facts.
  return freeze({
    contact: decodeP05FContact(record['contact'], `${path}.contact`),
    evidenceId: uuid(record['evidenceId'], `${path}.evidenceId`),
  });
}

export function decodeP05StaffWithdraw(value: unknown, path = '$'): P05StaffWithdrawInput {
  const record = object(value, path, ['evidenceId'], ['evidenceId']);
  return freeze({ evidenceId: uuid(record['evidenceId'], `${path}.evidenceId`) });
}

// ---------------------------------------------------------------------------
// Byte-level body decoding: cap -> strict UTF-8 -> duplicate-aware JSON -> DTO.
// ---------------------------------------------------------------------------

const OPERATION_BODY_DECODER: { readonly [K in P05BodyOperation]: (value: unknown) => P05Bodies[K] } = {
  createCallback: (value) => decodeP05CallbackRequest(value),
  createRepair: (value) => decodeP05RepairRequest(value),
  chooseCallback: (value) => decodeP05ContactMode(value),
  withdrawPhonePermission: (value) => decodeP05PhoneWithdrawal(value),
  cancelRequestF: (value) => decodeP05Cancel(value),
  createManualRequest: (value) => decodeP05ManualRequest(value),
  startReview: (value) => decodeP05Empty(value),
  convertCallback: (value) => decodeP05ConvertCallback(value),
  changeDetails: (value) => decodeP05ChangeDetails(value),
  recordCoverage: (value) => decodeP05Coverage(value),
  changeContact: (value) => decodeP05ChangeContact(value),
  readyForDispatch: (value) => decodeP05Empty(value),
  withdrawPhoneStaff: (value) => decodeP05StaffWithdraw(value),
  cancelRequestStaff: (value) => decodeP05Cancel(value),
};

function utf8(bytes: Uint8Array): string {
  let output = '';
  let index = 0;
  while (index < bytes.length) {
    const first = bytes[index];
    if (first === undefined) { break; }
    if (first < 0x80) {
      output += String.fromCharCode(first);
      index += 1;
      continue;
    }
    let codePoint: number;
    let extra: number;
    if (first >= 0xc2 && first <= 0xdf) { codePoint = first & 0x1f; extra = 1; }
    else if (first >= 0xe0 && first <= 0xef) { codePoint = first & 0x0f; extra = 2; }
    else if (first >= 0xf0 && first <= 0xf4) { codePoint = first & 0x07; extra = 3; }
    else { return fail('MALFORMED', 'BAD_UTF8', '$'); }
    if (index + extra >= bytes.length) { return fail('MALFORMED', 'BAD_UTF8', '$'); }
    for (let offset = 1; offset <= extra; offset += 1) {
      const next = bytes[index + offset];
      if (next === undefined || (next & 0xc0) !== 0x80) { return fail('MALFORMED', 'BAD_UTF8', '$'); }
      codePoint = (codePoint << 6) | (next & 0x3f);
    }
    const minimum = extra === 1 ? 0x80 : extra === 2 ? 0x800 : 0x10000;
    if (codePoint < minimum || codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
      return fail('MALFORMED', 'BAD_UTF8', '$');
    }
    output += String.fromCodePoint(codePoint);
    index += extra + 1;
  }
  return output;
}

function boundedShape(value: unknown): void {
  let nodes = 0;
  const walk = (node: unknown, depth: number): void => {
    nodes += 1;
    if (nodes > P05_MAX_NODES || depth > P05_MAX_DEPTH) { return fail('MALFORMED', 'BODY_TOO_LARGE', '$'); }
    if (Array.isArray(node)) {
      for (const entry of node) { walk(entry, depth + 1); }
    } else if (isRecord(node)) {
      for (const key of Object.keys(node)) { walk(node[key], depth + 1); }
    }
  };
  walk(value, 1);
}

function parseBodyValue(bytes: Uint8Array): unknown {
  if (bytes.length > P05_BODY_BYTES) { return fail('MALFORMED', 'BODY_TOO_LARGE', '$'); }
  const text = utf8(bytes);
  let parsed: unknown;
  try {
    parsed = parseP04JsonText(text);
  } catch {
    return fail('MALFORMED', 'BAD_JSON', '$');
  }
  boundedShape(parsed);
  return parsed;
}

/** Decode a raw JSON body of a body-bearing P05 operation. Authority is the caller's job. */
export function decodeP05Body<Op extends P05BodyOperation>(operation: Op, bytes: Uint8Array): P05Bodies[Op] {
  return OPERATION_BODY_DECODER[operation](parseBodyValue(bytes));
}

function encodeUtf8(text: string): Uint8Array {
  const bytes: number[] = [];
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) { continue; }
    if (codePoint < 0x80) {
      bytes.push(codePoint);
    } else if (codePoint < 0x800) {
      bytes.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint < 0x10000) {
      bytes.push(0xe0 | (codePoint >> 12), 0x80 | ((codePoint >> 6) & 0x3f), 0x80 | (codePoint & 0x3f));
    } else {
      bytes.push(0xf0 | (codePoint >> 18), 0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f), 0x80 | (codePoint & 0x3f));
    }
  }
  return Uint8Array.from(bytes);
}

/** Canonical normalized body bytes (fixed key order, identity encoding) for HMAC/receipt evidence. */
export function encodeP05Body<Op extends P05BodyOperation>(operation: Op, body: P05Bodies[Op]): Uint8Array {
  return encodeUtf8(JSON.stringify(OPERATION_BODY_DECODER[operation](body)));
}

// ---------------------------------------------------------------------------
// ETag: strong representation tag `"p05-r1-<sha256 hex>"`; hash is server-side.
// ---------------------------------------------------------------------------

export function formatP05Etag(hash: string): string {
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/u.test(hash)) { throw new RangeError('Invalid P05 ETag hash'); }
  return `"${P05_ETAG_PREFIX}${hash}"`;
}

export function parseP05Etag(value: unknown): string | null {
  if (typeof value !== 'string') { return null; }
  const match = /^"p05-r1-([0-9a-f]{64})"$/u.exec(value);
  if (match === null || match[0] !== value) { return null; }
  const hash = match[1];
  return hash === undefined ? null : hash;
}

// ---------------------------------------------------------------------------
// Safe response projections (only the closed keys of the allowed shape).
// ---------------------------------------------------------------------------

/**
 * Public request number is a decimal bigint string (migration 022 uses
 * `bigint`/`nextval`): canonical digits, no sign, no leading zero, bounded by
 * the signed 64-bit maximum. It is never a JS number here.
 */
const PUBLIC_NUMBER = /^(?:0|[1-9][0-9]{0,18})$/u;
const PUBLIC_NUMBER_MAX = 9223372036854775807n;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;

function publicNumber(value: unknown, path: string): string {
  if (typeof value !== 'string') { return fail('MALFORMED', 'BAD_TYPE', path); }
  if (!PUBLIC_NUMBER.test(value)) { return fail('MALFORMED', 'BAD_FORMAT', path); }
  if (BigInt(value) > PUBLIC_NUMBER_MAX) { return fail('MALFORMED', 'OUT_OF_RANGE', path); }
  return value;
}

function status(value: unknown, path: string): P05Status {
  return oneOf(value, path, P05_STATUSES);
}

export function decodeP05FWriteReceipt(value: unknown, path = '$'): P05FWriteReceipt {
  const record = object(value, path, ['publicNumber', 'status', 'version'], ['publicNumber', 'status', 'version']);
  return freeze({
    publicNumber: publicNumber(record['publicNumber'], `${path}.publicNumber`),
    status: status(record['status'], `${path}.status`),
    version: version(record['version'], `${path}.version`),
  });
}

export function decodeP05StaffWriteReceipt(value: unknown, path = '$'): P05StaffWriteReceipt {
  const record = object(value, path, ['id', 'publicNumber', 'status', 'version'], ['id', 'publicNumber', 'status', 'version']);
  return freeze({
    id: uuid(record['id'], `${path}.id`),
    publicNumber: publicNumber(record['publicNumber'], `${path}.publicNumber`),
    status: status(record['status'], `${path}.status`),
    version: version(record['version'], `${path}.version`),
  });
}

export function decodeP05EffectReceipt(value: unknown, path = '$'): P05EffectReceipt {
  const record = object(value, path, ['applied', 'version'], ['applied', 'version']);
  return freeze({
    applied: boolean(record['applied'], `${path}.applied`),
    version: version(record['version'], `${path}.version`),
  });
}

function envelopeData(value: unknown, path: string): Readonly<Record<string, unknown>> {
  const record = object(value, path, ['data'], ['data']);
  const data = record['data'];
  if (!isRecord(data)) { return fail('MALFORMED', 'BAD_TYPE', `${path}.data`); }
  return data;
}

export function decodeP05RequestSessionData(value: unknown, path = '$.data'): P05RequestSessionData {
  if (!isRecord(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === 'version') {
    return freeze({ version: version(value['version'], `${path}.version`) });
  }
  const full = object(value, path, ['publicNumber', 'status', 'version'], ['publicNumber', 'status', 'version']);
  return freeze({
    publicNumber: publicNumber(full['publicNumber'], `${path}.publicNumber`),
    status: status(full['status'], `${path}.status`),
    version: version(full['version'], `${path}.version`),
  });
}

export function decodeP05StaffRequestData(value: unknown, path = '$.data'): P05StaffRequestData {
  if (!isRecord(value)) { return fail('MALFORMED', 'BAD_TYPE', path); }
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === 'version') {
    return freeze({ version: version(value['version'], `${path}.version`) });
  }
  const full = object(value, path, ['id', 'publicNumber', 'type', 'status', 'version'],
    ['id', 'publicNumber', 'type', 'status', 'version']);
  return freeze({
    id: uuid(full['id'], `${path}.id`),
    publicNumber: publicNumber(full['publicNumber'], `${path}.publicNumber`),
    type: oneOf(full['type'], `${path}.type`, P05_TYPES),
    status: status(full['status'], `${path}.status`),
    version: version(full['version'], `${path}.version`),
  });
}

export function decodeP05Problem(value: unknown, path = '$'): P05Problem | null {
  if (!isRecord(value)) { return null; }
  try {
    const record = object(value, path, ['type', 'title', 'status', 'code', 'requestId'],
      ['type', 'title', 'status', 'code', 'requestId']);
    oneOf(record['type'], `${path}.type`, ['about:blank'] as const);
    const code = oneOf(record['code'], `${path}.code`, P05_PROBLEM_CODES);
    const problemStatus = integer(record['status'], `${path}.status`, 400, 599);
    if (P05_PROBLEM_STATUS[code] !== problemStatus) { return null; }
    if (typeof record['title'] !== 'string' || record['title'] !== code) { return null; }
    if (typeof record['requestId'] !== 'string' || !REQUEST_ID.test(record['requestId'])) { return null; }
    return freeze({ type: 'about:blank', title: code, status: problemStatus, code, requestId: record['requestId'] });
  } catch {
    return null;
  }
}

const OPERATION_RESPONSE_DECODER: { readonly [K in P05Operation]: (value: unknown) => P05Data[K] } = {
  createCallback: (value) => decodeP05FWriteReceipt(value),
  createRepair: (value) => decodeP05FWriteReceipt(value),
  readRequestSession: (value) => decodeP05RequestSessionData(value),
  chooseCallback: (value) => decodeP05FWriteReceipt(value),
  withdrawPhonePermission: (value) => decodeP05EffectReceipt(value),
  cancelRequestF: (value) => decodeP05EffectReceipt(value),
  createManualRequest: (value) => decodeP05StaffWriteReceipt(value),
  readStaffRequest: (value) => decodeP05StaffRequestData(value),
  startReview: (value) => decodeP05StaffWriteReceipt(value),
  convertCallback: (value) => decodeP05StaffWriteReceipt(value),
  changeDetails: (value) => decodeP05StaffWriteReceipt(value),
  recordCoverage: (value) => decodeP05StaffWriteReceipt(value),
  changeContact: (value) => decodeP05StaffWriteReceipt(value),
  readyForDispatch: (value) => decodeP05StaffWriteReceipt(value),
  withdrawPhoneStaff: (value) => decodeP05EffectReceipt(value),
  cancelRequestStaff: (value) => decodeP05EffectReceipt(value),
};

/** Decode the successful response of an operation. Non-success statuses raise P05WireError. */
export function decodeP05Response<Op extends P05Operation>(operation: Op, responseStatus: number, bytes: Uint8Array): P05Data[Op] {
  const route: P05RouteShape = P05_ROUTES[operation];
  const success = responseStatus === route.status
    || (route.replayStatus !== null && responseStatus === route.replayStatus);
  if (!success) {
    const problem = decodeP05ProblemBytes(bytes);
    throw new P05WireError(responseStatus, problem?.code ?? 'INTERNAL_ERROR', problem);
  }
  if (bytes.length > P05_RESPONSE_BYTES.json) { return fail('MALFORMED', 'RESPONSE_TOO_LARGE', '$'); }
  let parsed: unknown;
  try {
    parsed = parseP04JsonText(utf8(bytes));
  } catch {
    return fail('MALFORMED', 'BAD_JSON', '$');
  }
  boundedShape(parsed);
  return OPERATION_RESPONSE_DECODER[operation](envelopeData(parsed, '$'));
}

function decodeP05ProblemBytes(bytes: Uint8Array): P05Problem | null {
  if (bytes.length > P05_RESPONSE_BYTES.problem) { return null; }
  let parsed: unknown;
  try {
    parsed = parseP04JsonText(utf8(bytes));
  } catch {
    return null;
  }
  return decodeP05Problem(parsed);
}

// ---------------------------------------------------------------------------
// Typed client over an injected transport (no network, retries or credentials).
// ---------------------------------------------------------------------------

export interface P05TransportRequest {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string | null;
}

export interface P05TransportResponse {
  readonly status: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

export type P05Transport = (request: P05TransportRequest) => Promise<P05TransportResponse>;

export interface P05ClientOptions { readonly origin: string }

export type P05RequestInput<Op extends P05Operation> =
  & (Op extends P05IdOperation ? { readonly id: string } : { readonly id?: never })
  & (Op extends P05BodyOperation
    ? { readonly body: P05Bodies[Op]; readonly idempotencyKey: string }
    : { readonly body?: never; readonly idempotencyKey?: never })
  & (Op extends P05CsrfOperation ? { readonly csrfToken: string } : { readonly csrfToken?: never })
  & (Op extends P05IfMatchOperation ? { readonly expectedVersion: string } : { readonly expectedVersion?: never })
  & (Op extends P05GetOperation ? { readonly ifNoneMatch?: string } : { readonly ifNoneMatch?: never })
  & ((typeof P05_ROUTES)[Op]['scope'] extends 'F'
    ? { readonly formSessionId: string }
    : { readonly formSessionId?: never });

export type P05ClientResult<Op extends P05Operation> =
  | { readonly kind: 'data'; readonly status: number; readonly data: P05Data[Op]; readonly etag: string | null }
  | (Op extends P05GetOperation ? { readonly kind: 'not-modified'; readonly status: 304; readonly etag: string } : never);

export interface P05Client {
  request<Op extends P05Operation>(operation: Op, input: P05RequestInput<NoInfer<Op>>): Promise<P05ClientResult<Op>>;
}

function headerValue(headers: Readonly<Record<string, string>> | undefined, name: string): string | null {
  if (headers === undefined) { return null; }
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      const value = headers[key];
      return value === undefined ? null : value;
    }
  }
  return null;
}

function readField(input: unknown, key: string): unknown {
  return isRecord(input) ? input[key] : undefined;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string') { throw new TypeError(`P05 client requires ${name}`); }
  return value;
}

export function createP05Client(transport: P05Transport, options: P05ClientOptions): P05Client {
  return {
    async request<Op extends P05Operation>(operation: Op, input: P05RequestInput<NoInfer<Op>>): Promise<P05ClientResult<Op>> {
      const route: P05RouteShape = P05_ROUTES[operation];
      const rawId = readField(input, 'id');
      const hasId = route.path.includes(':id');
      if (hasId !== (rawId !== undefined)) { throw new TypeError('P05 client params mismatch'); }
      const path = hasId ? `${P05_PREFIX}${route.path.replace(':id', requireString(rawId, 'id'))}` : `${P05_PREFIX}${route.path}`;
      if (hasId && !UUID.test(requireString(rawId, 'id'))) { throw new TypeError('P05 client id is not canonical'); }

      const headers: Record<string, string> = { accept: 'application/json' };
      if (route.origin !== 'none') { headers[P05_HEADERS.origin] = requireString(options.origin, 'origin'); }
      if (route.scope === 'F') {
        // The selector is the public F anchor id; it is required on every F
        // request (mutations and the canonical GET alike) and never a secret.
        const selector = requireString(readField(input, 'formSessionId'), 'formSessionId');
        if (!UUID.test(selector)) { throw new TypeError('P05 client formSessionId is not canonical'); }
        headers[P05_HEADERS.formSession] = selector;
      }

      let body: string | null = null;
      if (route.body !== null) {
        const rawBody = readField(input, 'body');
        const normalized = OPERATION_BODY_DECODER[operation as P05BodyOperation](rawBody);
        body = JSON.stringify(normalized);
        headers['content-type'] = 'application/json';
      }
      if (route.idempotencyKey) {
        const key = requireString(readField(input, 'idempotencyKey'), 'idempotencyKey');
        if (!UUID.test(key)) { throw new TypeError('P05 client idempotency key is not canonical'); }
        headers[P05_HEADERS.idempotency] = key;
      }
      if (route.csrf) { headers[P05_HEADERS.csrf] = requireString(readField(input, 'csrfToken'), 'csrfToken'); }
      if (route.ifMatch) {
        const expected = requireString(readField(input, 'expectedVersion'), 'expectedVersion');
        if (parseP05Etag(expected) === null) { throw new TypeError('P05 client expectedVersion is not a strong P05 ETag'); }
        headers[P05_HEADERS.ifMatch] = expected;
      }
      if (route.ifNoneMatch) {
        const noneMatch = readField(input, 'ifNoneMatch');
        if (noneMatch !== undefined) {
          if (typeof noneMatch !== 'string' || parseP05Etag(noneMatch) === null) {
            throw new TypeError('P05 client ifNoneMatch is not a strong P05 ETag');
          }
          headers[P05_HEADERS.ifNoneMatch] = noneMatch;
        }
      }

      const response = await transport({ method: route.method, path, headers: Object.freeze({ ...headers }), body });
      if (response.status === 304) {
        if (!route.ifNoneMatch) { throw new P05WireError(304, 'INTERNAL_ERROR', null); }
        const etag = headerValue(response.headers, 'etag');
        if (etag === null || parseP05Etag(etag) === null) { throw new P05WireError(304, 'INTERNAL_ERROR', null); }
        return { kind: 'not-modified', status: 304, etag } as P05ClientResult<Op>;
      }
      const data = decodeP05Response(operation, response.status, response.body);
      const etagHeader = headerValue(response.headers, 'etag');
      const etag = etagHeader !== null && parseP05Etag(etagHeader) !== null ? etagHeader : null;
      return { kind: 'data', status: response.status, data, etag };
    },
  };
}
