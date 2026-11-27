// Declarative OpenAPI 3.1 description of the P05 wire surface.
// This module is build-time only (Node ESM); the runtime entry `src/p05.ts`
// never imports it. `generate-p05.mjs` writes `dist/p05-openapi.json`, and
// `p05-verify.mjs` asserts the artifact, the route table and the decoders agree.
//
// Keep the shape vocabulary in sync with docs/P05-PLAN.md §6.3 and with the
// hand-written DTO decoders in src/p05.ts; the verifier probes the decoders so
// an accidental drift fails the build instead of shipping a lying artifact.

export const P05_PREFIX = '/api/v1';

const MAX_IDS = 32;
const STATUSES = ['NEW', 'CALLBACK_REQUIRED', 'WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK', 'MANAGER_REVIEW',
  'WAITING_ASSIGNMENT', 'ASSIGNED', 'TECHNICIAN_ACCEPTED', 'ON_THE_WAY', 'ARRIVED', 'DIAGNOSTICS',
  'WAITING_ESTIMATE_APPROVAL', 'IN_PROGRESS', 'WAITING_PARTS', 'PAUSED', 'TECHNICIAN_COMPLETED',
  'REVISIT_REQUIRED', 'CLOSED', 'CANCELLED'];
const TYPES = ['CALLBACK', 'REPAIR'];
const PROVIDERS = ['TG', 'VK', 'MAX'];
const URGENCIES = ['FLEXIBLE', 'WITHIN_DAY', 'URGENT'];
const OUTCOMES = ['IN_ZONE', 'OUTSIDE', 'REVIEW', 'EXCEPTION'];
const REASONS = ['OVERLAP_REVIEW', 'OUTSIDE_REVIEW', 'OPERATOR_REVIEW'];

const UUID_PATTERN = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const PUBLIC_NUMBER_PATTERN = '^(?:0|[1-9][0-9]{0,18})$';
const INSTANT_PATTERN = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$';
const PHONE_PATTERN = '^\\+[1-9][0-9]{9,14}$';

export const PROBLEM_STATUS = {
  REQUEST_REJECTED: 400, MALFORMED: 400, UNAUTHORIZED: 401, FORBIDDEN: 403, NOT_FOUND: 404, REQUEST_TIMEOUT: 408,
  CONFLICT: 409, FORM_ALREADY_SUBMITTED: 409, IDEMPOTENCY_KEY_REUSED: 409, COVERAGE_ASSESSMENT_STALE: 409,
  CITY_CONTEXT_STALE: 409, CONSENT_REQUIRED: 409, CHANNEL_OPTIONS_CHANGED: 409, CHANNEL_OFFER_DISABLED: 409, CHANNEL_NOT_READY: 409,
  VERSION_MISMATCH: 412, BODY_TOO_LARGE: 413, UNSUPPORTED_MEDIA_TYPE: 415, SEMANTIC: 422,
  PRECONDITION_REQUIRED: 428, QUOTA: 429, INTERNAL_ERROR: 500, REQUEST_RULES_UNAVAILABLE: 503, NOT_READY: 503,
};

const uuid = (description) => ({ type: 'string', format: 'uuid', pattern: UUID_PATTERN, description });
const text = (minLength, maxLength, description) => ({ type: 'string', minLength, maxLength, description });
const enumOf = (values, description) => ({ type: 'string', enum: values, description });
const bool = (description) => ({ type: 'boolean', description });
const int = (minimum, maximum, description) => ({ type: 'integer', minimum, maximum, description });
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const arr = (items, maxItems, description) => ({ type: 'array', maxItems, items, description });

/** Closed object: `additionalProperties: false` is the wire-level "no unknown fields" rule. */
function closed(properties, required, description) {
  return { type: 'object', additionalProperties: false, properties, required, description };
}

const SCHEMAS = {
  FContact: closed({
    name: text(1, 200, 'Client display name; trimmed, NFC, no control characters.'),
    phone: { type: 'string', pattern: PHONE_PATTERN, minLength: 12, maxLength: 16, description: 'E.164-ish: + and 10..15 digits.' },
  }, ['name', 'phone'], 'Explicit contact of an F-origin request.'),

  Consent: closed({
    evidenceId: uuid('Append-only P03 consent evidence id bound to this F anchor.'),
    documentVersionId: uuid('Exact displayed REQUEST_PROCESSING document version.'),
    accepted: { type: 'boolean', enum: [true], description: 'Must be literal true; false is a semantic 422.' },
  }, ['evidenceId', 'documentVersionId', 'accepted'], 'Consent reference; the server re-validates it, this is not authority.'),

  ChannelSelection: closed({
    provider: enumOf(PROVIDERS, 'No-call channel provider.'),
    optionVersionId: uuid('Exact published channel option version.'),
    catalogVersionId: uuid('Exact catalog version the option was read from.'),
    purpose: enumOf(['REQUEST_CONFIRMATION'], 'Only request confirmation is allowed in P05.'),
  }, ['provider', 'optionVersionId', 'catalogVersionId', 'purpose'], 'One admitted no-call channel choice.'),

  Address: closed({
    street: text(1, 300, 'Street and house part as typed by the client.'),
    building: text(1, 50, 'Building / block marker.'),
    districtId: uuid('Optional same-city district id; coverage is never inferred from it.'),
    apartment: text(1, 50, 'Apartment.'),
    entrance: text(1, 50, 'Entrance.'),
    floor: text(1, 50, 'Floor.'),
    intercom: text(1, 100, 'Intercom code.'),
    accessNotes: text(1, 1000, 'Free-form access notes; stored as PII in the request payload.'),
  }, ['street', 'building'], 'Address of a REPAIR request; no city or coverage override is accepted.'),

  Appliance: closed({
    categoryId: uuid('Catalog appliance category.'),
    brandId: uuid('Optional catalog brand.'),
    modelId: uuid('Optional catalog model.'),
    modelText: text(1, 200, 'Free-text model when the catalog has no match.'),
    approximateAge: int(0, 100, 'Approximate age in years.'),
  }, ['categoryId'], 'Appliance snapshot source data.'),

  /**
   * A repair is complete with at least one selected published fault of its
   * category OR an "other fault" with a non-empty description (P05-PLAN §1,
   * Q12/Q16). `faultIds` is therefore optional and may be omitted or empty; the
   * decoder normalizes an omitted member to `[]`. Neither branch -> 422
   * FAULT_REQUIRED (semantic, never a malformed 400).
   */
  Fault: {
    type: 'object',
    additionalProperties: false,
    properties: {
      faultIds: { type: 'array', maxItems: MAX_IDS, items: uuid('Catalog fault id.'),
        description: 'Optional selected fault ids of the request category; omit or [] when only otherDescription is given. Duplicates are a semantic 422.' },
      otherDescription: text(1, 1000, 'Other fault description; completes a repair without selected fault ids.'),
      description: text(1, 2000, 'Free-form fault description.'),
      errorCode: text(1, 100, 'Device error code.'),
    },
    anyOf: [
      { required: ['faultIds'], properties: { faultIds: { type: 'array', minItems: 1 } } },
      { required: ['otherDescription'] },
    ],
    description: 'Fault snapshot source data: at least one selected fault id or a non-empty otherDescription is required. '
      + 'Omitted faultIds normalize to [].',
  },

  PreferredVisit: closed({
    from: { type: 'string', format: 'date-time', pattern: INSTANT_PATTERN, description: 'Window start (UTC instant, ms precision).' },
    to: { type: 'string', format: 'date-time', pattern: INSTANT_PATTERN, description: 'Window end; must be later and at most 14 days away.' },
  }, ['from', 'to'], 'Bounded time preference. This is not an appointment and books nothing.'),

  CallbackRequest: closed({
    contact: ref('FContact'),
    consent: ref('Consent'),
    phonePermission: { type: 'boolean', enum: [true], description: 'Explicit PHONE permission for this contact; false is 422.' },
    callbackIntervalId: uuid('Optional city-scoped callback interval reference.'),
    comment: text(1, 2000, 'Optional free-form comment.'),
  }, ['contact', 'consent', 'phonePermission'], 'F callback request: no address, appliance or slot.'),

  RepairRequest: closed({
    contact: ref('FContact'),
    consent: ref('Consent'),
    channelSelection: ref('ChannelSelection'),
    address: ref('Address'),
    appliance: ref('Appliance'),
    fault: ref('Fault'),
    urgency: enumOf(URGENCIES, 'Preference urgency, same vocabulary as migration 022.'),
    preferredVisit: ref('PreferredVisit'),
    attachments: arr(uuid('P03 file publication id.'), MAX_IDS, 'Optional already-READY attachments; admission happens in the server transaction.'),
  }, ['contact', 'consent', 'channelSelection', 'address', 'appliance', 'fault'], 'F repair request: messenger channel only, no PHONE mode.'),

  ManualPhoneContact: closed({
    mode: enumOf(['PHONE'], 'Discriminator.'),
    name: text(1, 200, 'Contact name captured by staff.'),
    phone: { type: 'string', pattern: PHONE_PATTERN, minLength: 12, maxLength: 16, description: 'Phone captured by staff.' },
    phonePermission: { type: 'boolean', enum: [true], description: 'Explicit permission evidence; false is 422.' },
    phoneEvidenceId: uuid('Separate staff phone-permission evidence id.'),
  }, ['mode', 'name', 'phone', 'phonePermission', 'phoneEvidenceId'], 'Full manual PHONE contact with its own evidence.'),

  ManualChannelContact: closed({
    mode: enumOf(['CHANNEL'], 'Discriminator.'),
    name: text(1, 200, 'Contact name captured by staff.'),
    phone: { type: 'string', pattern: PHONE_PATTERN, minLength: 12, maxLength: 16,
      description: 'Normalized phone captured by staff for manual no-call intake. Retained, but explicitly NOT a PHONE permission proof.' },
    channelSelection: ref('ChannelSelection'),
  }, ['mode', 'name', 'phone', 'channelSelection'], 'Manual messenger contact; keeps the phone but grants no phone permission.'),

  ManualCallbackRequest: closed({
    type: enumOf(['CALLBACK'], 'Discriminator.'),
    sourceEntryId: uuid('Exact active source entry (procedure/reference) for manual intake.'),
    evidenceId: uuid('Staff intake evidence id for this source.'),
    contact: ref('ManualPhoneContact'),
    callbackIntervalId: uuid('Optional city-scoped callback interval reference.'),
    comment: text(1, 2000, 'Optional free-form comment.'),
  }, ['type', 'sourceEntryId', 'evidenceId', 'contact'], 'Manual CALLBACK intake; PHONE contact only.'),

  ManualRepairRequest: closed({
    type: enumOf(['REPAIR'], 'Discriminator.'),
    sourceEntryId: uuid('Exact active source entry (procedure/reference) for manual intake.'),
    evidenceId: uuid('Staff intake evidence id for this source.'),
    contact: { oneOf: [ref('ManualPhoneContact'), ref('ManualChannelContact')], description: 'PHONE or CHANNEL contact.' },
    address: ref('Address'),
    appliance: ref('Appliance'),
    fault: ref('Fault'),
    urgency: enumOf(URGENCIES, 'Preference urgency.'),
    preferredVisit: ref('PreferredVisit'),
  }, ['type', 'sourceEntryId', 'evidenceId', 'contact', 'address', 'appliance', 'fault'], 'Manual REPAIR intake; no F, no attachments.'),

  ManualRequest: { oneOf: [ref('ManualCallbackRequest'), ref('ManualRepairRequest')], discriminator: { propertyName: 'type' },
    description: 'Staff manual intake, discriminated by `type`.' },

  ContactModeInput: closed({
    phonePermission: { type: 'boolean', enum: [true], description: 'ChooseCallback always grants PHONE for the current contact.' },
  }, ['phonePermission'], 'ChooseCallback body.'),

  PhoneWithdrawalInput: closed({
    action: enumOf(['REVOKED'], 'The only action this route accepts.'),
  }, ['action'], 'F phone-permission withdrawal.'),

  CancelInput: closed({
    reasonEntryId: uuid('Published cancellation reason reference.'),
  }, ['reasonEntryId'], 'Cancellation reason reference.'),

  EmptyInput: closed({}, [], 'Exact empty object; any member is a malformed 400.'),

  ConvertCallbackInput: closed({
    address: ref('Address'),
    appliance: ref('Appliance'),
    fault: ref('Fault'),
    urgency: enumOf(URGENCIES, 'Preference urgency.'),
    preferredVisit: ref('PreferredVisit'),
  }, ['address', 'appliance', 'fault'], 'ConvertCallback replacement details; contact and channel are not replaceable here.'),

  ChangeDetailsAddress: closed({ section: enumOf(['ADDRESS'], 'Discriminator.'), address: ref('Address') },
    ['section', 'address'], 'Named ADDRESS section replacement.'),
  ChangeDetailsAppliance: closed({
    section: enumOf(['APPLIANCE'], 'Discriminator.'),
    appliance: ref('Appliance'),
    fault: ref('Fault'),
  }, ['section', 'appliance', 'fault'],
  'Named APPLIANCE replacement. A new appliance invalidates the old fault selection, so the fault block is replaced with it, never dropped.'),
  ChangeDetailsPreference: closed({
    section: enumOf(['PREFERENCE'], 'Discriminator.'),
    urgency: enumOf(URGENCIES, 'Preference urgency.'),
    preferredVisit: ref('PreferredVisit'),
  }, ['section'], 'Named PREFERENCE replacement; at least one field is required (422 when empty).'),
  ChangeDetailsInput: { oneOf: [ref('ChangeDetailsAddress'), ref('ChangeDetailsAppliance'), ref('ChangeDetailsPreference')],
    discriminator: { propertyName: 'section' }, description: 'ChangeDetails body: exactly one named section.' },

  CoverageInput: closed({
    evidenceId: uuid('Independent coverage evidence id.'),
    areaId: uuid('Selected same-city area. Required for IN_ZONE and EXCEPTION; refused for OUTSIDE/REVIEW (no positive authority).'),
    outcome: enumOf(OUTCOMES, 'Assessment outcome. EXCEPTION is never automatic.'),
    reason: enumOf(REASONS, 'OVERLAP_REVIEW only with IN_ZONE; OUTSIDE_REVIEW or OPERATOR_REVIEW required for OUTSIDE and EXCEPTION; OVERLAP_REVIEW or OPERATOR_REVIEW required for REVIEW.'),
  }, ['evidenceId', 'outcome'],
  'RecordCoverage body, aligned with migration 024 request_coverage_assessments: '
    + 'IN_ZONE requires areaId (optional OVERLAP_REVIEW reason); EXCEPTION requires areaId and an explicit OUTSIDE_REVIEW/OPERATOR_REVIEW rationale; '
    + 'OUTSIDE requires OUTSIDE_REVIEW/OPERATOR_REVIEW; REVIEW requires OVERLAP_REVIEW/OPERATOR_REVIEW. '
    + 'The server derives the candidate basis itself; nothing here is authority.'),

  ChangeContactInput: closed({
    contact: ref('FContact'),
    evidenceId: uuid('Current versioned contact-change evidence id.'),
  }, ['contact', 'evidenceId'],
  'ChangeContact body. Only the contact values are replaceable: the contact mode is persisted server-side, '
    + 'and no mode/channelSelection/phonePermission member exists, so a replacement cannot switch channel or grant PHONE.'),

  StaffWithdrawInput: closed({
    evidenceId: uuid('Scoped staff declaration evidence id.'),
  }, ['evidenceId'], 'Staff phone-permission withdrawal body.'),

  FWriteReceipt: closed({
    publicNumber: { type: 'string', pattern: PUBLIC_NUMBER_PATTERN, description: 'Decimal bigint string, never a JSON number.' },
    status: enumOf(STATUSES, 'Persisted status.'),
    version: int(1, 2147483647, 'Domain row_version; not an HTTP validator.'),
  }, ['publicNumber', 'status', 'version'], 'F submit receipt. No ETag is returned for write receipts.'),

  StaffWriteReceipt: closed({
    id: uuid('Request id.'),
    publicNumber: { type: 'string', pattern: PUBLIC_NUMBER_PATTERN, description: 'Decimal bigint string.' },
    status: enumOf(STATUSES, 'Persisted status.'),
    version: int(1, 2147483647, 'Domain row_version.'),
  }, ['id', 'publicNumber', 'status', 'version'], 'Staff write receipt. No ETag is returned for write receipts.'),

  EffectReceipt: closed({
    applied: bool('Whether this call applied the effect (false for an idempotent replay).'),
    version: int(1, 2147483647, 'Domain row_version.'),
  }, ['applied', 'version'], 'Minimal effect receipt for cancel/withdraw.'),

  RequestSessionFull: closed({
    publicNumber: { type: 'string', pattern: PUBLIC_NUMBER_PATTERN, description: 'Decimal bigint string.' },
    status: enumOf(STATUSES, 'Persisted status.'),
    version: int(1, 2147483647, 'Domain row_version.'),
  }, ['publicNumber', 'status', 'version'], 'Authorized projection while the basis is live.'),
  RequestSessionRestricted: closed({
    version: int(1, 2147483647, 'Domain row_version.'),
  }, ['version'], 'Restricted projection after withdrawal: version only.'),
  RequestSessionData: { oneOf: [ref('RequestSessionFull'), ref('RequestSessionRestricted')],
    description: 'The exact authorized projection chosen by the server; both shapes carry their own strong ETag.' },

  StaffRequestFull: closed({
    id: uuid('Request id.'),
    publicNumber: { type: 'string', pattern: PUBLIC_NUMBER_PATTERN, description: 'Decimal bigint string.' },
    type: enumOf(TYPES, 'Request type.'),
    status: enumOf(STATUSES, 'Persisted status.'),
    version: int(1, 2147483647, 'Domain row_version.'),
  }, ['id', 'publicNumber', 'type', 'status', 'version'], 'Authorized staff projection while the basis is live.'),
  StaffRequestRestricted: closed({
    version: int(1, 2147483647, 'Domain row_version.'),
  }, ['version'], 'Restricted staff projection: version only.'),
  StaffRequestData: { oneOf: [ref('StaffRequestFull'), ref('StaffRequestRestricted')],
    description: 'Exact authorized staff projection; no phone, name, address, customer or attachment ids.' },

  Problem: closed({
    type: { type: 'string', enum: ['about:blank'] },
    title: { type: 'string', enum: Object.keys(PROBLEM_STATUS) },
    status: { type: 'integer', minimum: 400, maximum: 599 },
    code: { type: 'string', enum: Object.keys(PROBLEM_STATUS) },
    requestId: { type: 'string', minLength: 1, maxLength: 64 },
  }, ['type', 'title', 'status', 'code', 'requestId'], 'Closed five-key problem envelope, application/problem+json.'),
};

/**
 * One row per operation. `body`, `data`, `status`, `scope`, `ifMatch` and
 * `ifNoneMatch` are asserted against the runtime route table by p05-verify.
 */
export const P05_OPERATIONS = [
  { operationId: 'createCallback', method: 'post', path: '/public/callback-requests', scope: 'F', body: 'CallbackRequest',
    data: 'FWriteReceipt', status: 201, replay: 200, ifMatch: false, ifNoneMatch: false,
    summary: 'F callback request creation (consume scope).' },
  { operationId: 'createRepair', method: 'post', path: '/public/repair-requests', scope: 'F', body: 'RepairRequest',
    data: 'FWriteReceipt', status: 201, replay: 200, ifMatch: false, ifNoneMatch: false,
    summary: 'F repair request creation (consume scope).' },
  { operationId: 'readRequestSession', method: 'get', path: '/public/request-session', scope: 'F', body: null,
    data: 'RequestSessionData', status: 200, replay: null, ifMatch: false, ifNoneMatch: true,
    summary: 'Authorized F request-session projection with a strong ETag.' },
  { operationId: 'chooseCallback', method: 'post', path: '/public/request-session/contact-mode', scope: 'F', body: 'ContactModeInput',
    data: 'FWriteReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'ChooseCallback: atomic PHONE permission plus CALLBACK_REQUIRED.' },
  { operationId: 'withdrawPhonePermission', method: 'post', path: '/public/request-session/phone-permissions', scope: 'F', body: 'PhoneWithdrawalInput',
    data: 'EffectReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'F phone-permission withdrawal (REVOKED only).' },
  { operationId: 'cancelRequestF', method: 'post', path: '/public/request-session/cancel', scope: 'F', body: 'CancelInput',
    data: 'EffectReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'Early F cancellation.' },
  { operationId: 'createManualRequest', method: 'post', path: '/requests', scope: 'STAFF', body: 'ManualRequest',
    data: 'StaffWriteReceipt', status: 201, replay: 200, ifMatch: false, ifNoneMatch: false,
    summary: 'Staff manual intake, discriminated by type.' },
  { operationId: 'readStaffRequest', method: 'get', path: '/requests/{id}', scope: 'STAFF', body: null,
    data: 'StaffRequestData', status: 200, replay: null, ifMatch: false, ifNoneMatch: true,
    summary: 'Authorized staff request projection with a strong ETag.' },
  { operationId: 'startReview', method: 'post', path: '/requests/{id}/commands/start-review', scope: 'STAFF', body: 'EmptyInput',
    data: 'StaffWriteReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'StartReview: NEW/CALLBACK_REQUIRED to MANAGER_REVIEW.' },
  { operationId: 'convertCallback', method: 'post', path: '/requests/{id}/commands/convert-callback', scope: 'STAFF', body: 'ConvertCallbackInput',
    data: 'StaffWriteReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'ConvertCallback: CALLBACK to REPAIR with fresh replacement details.' },
  { operationId: 'changeDetails', method: 'post', path: '/requests/{id}/commands/change-details', scope: 'STAFF', body: 'ChangeDetailsInput',
    data: 'StaffWriteReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'ChangeDetails: one named section replacement.' },
  { operationId: 'recordCoverage', method: 'post', path: '/requests/{id}/commands/record-coverage', scope: 'STAFF', body: 'CoverageInput',
    data: 'StaffWriteReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'RecordCoverage: append-only assessment on server-derived basis.' },
  { operationId: 'changeContact', method: 'post', path: '/requests/{id}/commands/change-contact', scope: 'STAFF', body: 'ChangeContactInput',
    data: 'StaffWriteReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'ChangeContact: replacement contact with its own evidence.' },
  { operationId: 'readyForDispatch', method: 'post', path: '/requests/{id}/commands/ready-for-dispatch', scope: 'STAFF', body: 'EmptyInput',
    data: 'StaffWriteReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'ReadyForDispatch: MANAGER_REVIEW to WAITING_ASSIGNMENT.' },
  { operationId: 'withdrawPhoneStaff', method: 'post', path: '/requests/{id}/commands/withdraw-phone', scope: 'STAFF', body: 'StaffWithdrawInput',
    data: 'EffectReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'Staff phone-permission withdrawal.' },
  { operationId: 'cancelRequestStaff', method: 'post', path: '/requests/{id}/commands/cancel', scope: 'STAFF', body: 'CancelInput',
    data: 'EffectReceipt', status: 200, replay: null, ifMatch: true, ifNoneMatch: false,
    summary: 'Staff cancellation.' },
];

const headersFor = (op) => {
  const headers = { accept: { schema: { type: 'string', enum: ['application/json'] } } };
  if (op.scope === 'F') {
    headers['x-form-session-id'] = { required: true, schema: { type: 'string', format: 'uuid' },
      description: 'F proof selector; required on every F request, including the canonical GET.' };
  }
  if (op.body !== null) { headers['content-type'] = { required: true, schema: { type: 'string', enum: ['application/json'] } }; }
  if (op.scope === 'F' && op.method === 'post') {
    headers['x-csrf-token'] = { required: true, schema: { type: 'string', minLength: 1, maxLength: 512 },
      description: 'Stateless P05_F_MUTATE proof.' };
    headers.origin = { required: true, schema: { type: 'string' }, description: 'Exact configured Origin.' };
  }
  if (op.scope === 'STAFF' && op.method === 'post') {
    headers['x-csrf-token'] = { required: true, schema: { type: 'string', minLength: 1, maxLength: 512 },
      description: 'Session-bound staff CSRF token (same contract as P02-03).' };
    headers.origin = { required: true, schema: { type: 'string' }, description: 'Exact configured Origin.' };
  }
  if (op.body !== null) {
    headers['idempotency-key'] = { required: true, schema: { type: 'string', format: 'uuid' },
      description: 'Canonical lowercase UUID idempotency key.' };
  }
  if (op.ifMatch) {
    headers['if-match'] = { required: true, schema: { type: 'string', pattern: '^"p05-r1-[0-9a-f]{64}"$' },
      description: 'Strong ETag from the same surface canonical GET; 428 when absent.' };
  }
  if (op.ifNoneMatch) {
    headers['if-none-match'] = { required: false, schema: { type: 'string', pattern: '^"p05-r1-[0-9a-f]{64}"$' },
      description: 'Single strong ETag; 304 only on exact match of the selected projection.' };
  }
  return headers;
};

const parameters = (op) => op.path.includes('{id}')
  ? [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Request id.' }]
  : [];

const responses = (op) => {
  const success = {
    [String(op.status)]: {
      description: op.status === 201 ? 'Created.' : 'Success.',
      headers: op.ifNoneMatch
        ? { etag: { schema: { type: 'string', pattern: '^"p05-r1-[0-9a-f]{64}"$' }, description: 'Strong representation tag.' } }
        : {},
      content: { 'application/json': { schema: closed({ data: ref(op.data) }, ['data'], 'Exact data envelope; no random meta on P05 GETs.') } },
    },
  };
  if (op.replay !== null && op.replay !== op.status) {
    success[String(op.replay)] = {
      description: 'Exact idempotent replay of the stored receipt.',
      content: { 'application/json': { schema: closed({ data: ref(op.data) }, ['data'], 'Stored receipt replay.') } },
    };
  }
  if (op.ifNoneMatch) {
    success['304'] = { description: 'Not modified: exact selected projection matches the supplied If-None-Match.',
      headers: { etag: { schema: { type: 'string' } } } };
  }
  const problems = {};
  for (const status of [...new Set(Object.values(PROBLEM_STATUS))].sort((a, b) => a - b)) {
    problems[String(status)] = {
      description: 'Closed problem envelope.',
      content: { 'application/problem+json': { schema: ref('Problem') } },
    };
  }
  return { ...success, ...problems };
};

export const P05_OPENAPI = {
  openapi: '3.1.0',
  info: {
    title: 'FixLevelUp P05 wire contract',
    version: '1.0.0',
    description: 'Test-only P05-03/P05-04 surface (docs/P05-PLAN.md §6.3). '
      + 'Every P05 body is closed (additionalProperties=false), every response and error is no-store, '
      + 'and authorization is enforced by the server before any decoder runs. '
      + 'Canonical GETs use strong `p05-r1-<sha256>` ETags computed by the server over the exact representation bytes.',
  },
  servers: [{ url: P05_PREFIX }],
  components: { schemas: SCHEMAS },
  paths: Object.fromEntries(P05_OPERATIONS.map((op) => [op.path, {
    ...(Object.fromEntries([[
      op.method,
      {
        operationId: op.operationId,
        summary: op.summary,
        tags: [op.scope === 'F' ? 'public-form' : 'staff-requests'],
        parameters: parameters(op),
        ...(op.body === null ? {} : {
          requestBody: {
            required: true,
            content: { 'application/json': { schema: ref(op.body) } },
          },
        }),
        responses: responses(op),
        'x-p05-scope': op.scope,
        'x-p05-status': op.status,
        'x-p05-replay': op.replay,
        'x-p05-headers': headersFor(op),
      },
    ]])),
  }])),
};
