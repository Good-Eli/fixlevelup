// P05 contract verification: artifact <-> runtime route table <-> decoders <-> client.
// Build-time only (Node ESM); the runtime entry `dist/p05.js` uses no Node APIs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { p05Dist, renderP05 } from './generate-p05.mjs';
import { P05_OPENAPI, P05_OPERATIONS as OPENAPI_OPERATIONS, PROBLEM_STATUS } from './p05-openapi.mjs';
import {
  P05_BODY_BYTES, P05_HEADERS, P05_MAX_IDS, P05_MAX_NODES, P05_OPERATIONS, P05_PREFIX, P05_PROBLEM_STATUS,
  P05_ROUTES, P05_STATUSES, P05_TYPES, P05_URGENCIES, P05DecodeError, P05WireError, createP05Client,
  decodeP05Body, decodeP05Problem, decodeP05Response, encodeP05Body, formatP05Etag, matchP05Route,
  p05DecodeStatus, parseP05Etag,
} from './dist/p05.js';

const id = 'a1234567-1234-4321-8123-123456789012';
const id2 = 'b1234567-1234-4321-8123-123456789012';
const id3 = 'c1234567-1234-4321-8123-123456789012';
const id4 = 'd1234567-1234-4321-8123-123456789012';
const id5 = 'e1234567-1234-4321-8123-123456789012';
const hash = 'f'.repeat(64);
const etag = formatP05Etag(hash);
const encoder = new TextEncoder();
const json = (value) => encoder.encode(JSON.stringify(value));
const only = (fn) => assert.throws(fn);

// 1. Artifact is reproducible and every operation is described exactly once.
for (const [file, content] of Object.entries(renderP05())) {
  assert.equal(readFileSync(new URL(file, p05Dist), 'utf8'), content, `${file} is reproducible`);
}
const artifact = JSON.parse(readFileSync(new URL('p05-openapi.json', p05Dist), 'utf8'));
assert.deepEqual(artifact, P05_OPENAPI);
assert.deepEqual(P05_PROBLEM_STATUS, PROBLEM_STATUS, 'exact runtime/OpenAPI problem code and status parity');
assert.equal(artifact.openapi, '3.1.0');
assert.equal(artifact.servers[0].url, P05_PREFIX);
assert.equal(P05_PREFIX, '/api/v1');

const described = Object.entries(artifact.paths).flatMap(([path, methods]) =>
  Object.entries(methods).map(([method, op]) => ({ path, method, op })));
assert.equal(described.length, OPENAPI_OPERATIONS.length);
assert.equal(described.length, P05_OPERATIONS.length);
assert.deepEqual(described.map(({ op }) => op.operationId).sort(), [...P05_OPERATIONS].sort());
const rows = new Map(OPENAPI_OPERATIONS.map((row) => [row.operationId, row]));

// 2. Artifact and runtime route table agree on method/path/status/scope/validators.
// Artifact paths are relative to the single `servers[0].url` (= P05_PREFIX).
for (const { path, method, op } of described) {
  const route = P05_ROUTES[op.operationId];
  assert.equal(route.method, method.toUpperCase(), op.operationId);
  assert.equal(route.path.replace(':id', '{id}'), path, op.operationId);
  assert.equal(route.scope, op['x-p05-scope']);
  assert.equal(route.status, op['x-p05-status']);
  assert.equal(route.ifMatch, 'if-match' in op['x-p05-headers']);
  assert.equal(route.ifNoneMatch, 'if-none-match' in op['x-p05-headers']);
  assert.equal(route.idempotencyKey, 'idempotency-key' in op['x-p05-headers']);
  // F CSRF is a stateless P05_F_MUTATE proof; staff CSRF is the session-bound
  // P02-03 token. Both travel in `x-csrf-token`, so the flag and the header are
  // asserted per surface instead of being conflated.
  assert.equal(route.csrf, 'x-csrf-token' in op['x-p05-headers']);
  assert.equal(route.origin === 'required', op['x-p05-headers'].origin?.required === true);
  assert.equal(route.body === null, op.requestBody === undefined);
  const success = op.responses[String(op['x-p05-status'])];
  assert(success, `${op.operationId} success response`);
  const dataSchema = success.content['application/json'].schema.properties.data;
  assert.equal(dataSchema.$ref, `#/components/schemas/${rows.get(op.operationId).data}`);
  if (op['x-p05-replay'] !== null && op['x-p05-replay'] !== op['x-p05-status']) { assert(op.responses[String(op['x-p05-replay'])]); }
  // Problem envelope is present for every closed refusal status.
  for (const status of new Set(Object.values(P05_PROBLEM_STATUS))) {
    assert.equal(op.responses[String(status)].content['application/problem+json'].schema.$ref,
      '#/components/schemas/Problem', `${op.operationId} ${String(status)}`);
  }
}

// 3. Closed schema rule: every component object refuses unknown members.
for (const [name, schema] of Object.entries(artifact.components.schemas)) {
  if (schema.type === 'object') { assert.equal(schema.additionalProperties, false, name); }
  if (schema.oneOf) { assert(Array.isArray(schema.oneOf), name); }
}
// 3b. Fault completeness is ">=1 selected published fault OR non-empty
// otherDescription" (P05-PLAN §1, Q12/Q16). The schema must not require
// faultIds, must admit an empty array, and must still bound it to 32 ids.
const faultSchema = artifact.components.schemas.Fault;
assert.equal(faultSchema.required?.includes('faultIds') ?? false, false, 'Fault must not require faultIds');
assert.equal(faultSchema.required?.includes('otherDescription') ?? false, false, 'Fault must not require otherDescription');
assert.equal(faultSchema.properties.faultIds.maxItems, P05_MAX_IDS);
assert.equal(faultSchema.properties.faultIds.minItems, undefined, 'the property itself admits []');
assert.deepEqual(faultSchema.anyOf, [
  { required: ['faultIds'], properties: { faultIds: { type: 'array', minItems: 1 } } },
  { required: ['otherDescription'] },
]);

// 4. Route matcher: exact only. Canonical uppercase method; aliases all refuse.
for (const { path, op } of described) {
  const canonicalMethod = P05_ROUTES[op.operationId].method;
  const params = Object.fromEntries([...path.matchAll(/\{([a-zA-Z]+)\}/gu)].map((match) => [match[1], id]));
  const actual = `${P05_PREFIX}${path.replace(/\{([a-zA-Z]+)\}/gu, (_, name) => params[name])}`;
  assert.deepEqual(matchP05Route(canonicalMethod, actual), {
    operation: op.operationId,
    scope: P05_ROUTES[op.operationId].scope,
    params,
  });
  const aliases = [`${actual}/`, `${actual}?`, `${actual}#`, `${actual}\n`, `${actual} `,
    actual.replace('/api/', '/API/'), actual.replace('/v1/', '/v1//'), actual.replace('/v1/', '/v1/%2e/'),
    actual.replace('/public/', '/%70ublic/'), actual.replace('/requests', '/%72equests')];
  if (Object.keys(params).length > 0) {
    aliases.push(actual.replace(id, id.toUpperCase()), actual.replace(id, '%61' + id.slice(1)));
  }
  for (const alias of aliases.filter((entry) => entry !== actual)) {
    assert.equal(matchP05Route(canonicalMethod, alias), null, alias);
  }
  assert.equal(matchP05Route(canonicalMethod.toLowerCase(), actual), null, `${op.operationId} lowercase method`);
  assert.equal(matchP05Route('HEAD', actual), null);
  assert.equal(matchP05Route('PUT', actual), null);
}

// 5. Canonical bodies accepted; decoder output is frozen and closed.
const contact = { name: 'Synthetic Client', phone: '+79990000001' };
const consent = { evidenceId: id, documentVersionId: id2, accepted: true };
const channel = { provider: 'TG', optionVersionId: id3, catalogVersionId: id4, purpose: 'REQUEST_CONFIRMATION' };
const address = { street: 'Synthetic street 1', building: '2', districtId: id5, accessNotes: 'call on arrival' };
const appliance = { categoryId: id, brandId: id2, modelText: 'Model X', approximateAge: 5 };
const fault = { faultIds: [id3, id4], errorCode: 'E01' };
const preferredVisit = { from: '2030-01-02T09:00:00.000Z', to: '2030-01-02T12:00:00.000Z' };

const bodies = {
  createCallback: { contact, consent, phonePermission: true, callbackIntervalId: id5, comment: 'synthetic' },
  createRepair: { contact, consent, channelSelection: channel, address, appliance, fault,
    urgency: 'WITHIN_DAY', preferredVisit, attachments: [id2, id3] },
  chooseCallback: { phonePermission: true },
  withdrawPhonePermission: { action: 'REVOKED' },
  cancelRequestF: { reasonEntryId: id },
  createManualRequest: { type: 'CALLBACK', sourceEntryId: id, evidenceId: id2,
    contact: { mode: 'PHONE', name: 'Manual Client', phone: '+79990000002', phonePermission: true, phoneEvidenceId: id3 } },
  startReview: {},
  convertCallback: { address, appliance, fault, urgency: 'URGENT' },
  changeDetails: { section: 'PREFERENCE', urgency: 'FLEXIBLE' },
  recordCoverage: { evidenceId: id, areaId: id2, outcome: 'IN_ZONE' },
  changeContact: { contact: { name: 'New Client', phone: '+79990000003' }, evidenceId: id2 },
  readyForDispatch: {},
  withdrawPhoneStaff: { evidenceId: id },
  cancelRequestStaff: { reasonEntryId: id2 },
};
assert.deepEqual(Object.keys(bodies).sort(), P05_OPERATIONS.filter((op) => P05_ROUTES[op].body !== null).sort());
for (const [operation, body] of Object.entries(bodies)) {
  const decoded = decodeP05Body(operation, json(body));
  assert(Object.isFrozen(decoded), `${operation} frozen`);
  assert.deepEqual(decodeP05Body(operation, encodeP05Body(operation, decoded)), decoded);
  // Unknown member is malformed 400, and the status mapping is exact.
  const withUnknown = { ...body, unexpected: true };
  try {
    decodeP05Body(operation, json(withUnknown));
    assert.fail(`${operation} accepted an unknown field`);
  } catch (error) {
    assert(error instanceof P05DecodeError);
    assert.equal(error.kind, 'MALFORMED');
    assert.equal(error.code, 'UNKNOWN_FIELD');
    assert.deepEqual(p05DecodeStatus(error), { status: 400, code: 'MALFORMED' });
  }
}

// 6. Manual intake is discriminated, and normalized as documented.
assert.equal(decodeP05Body('createManualRequest', json(bodies.createManualRequest)).type, 'CALLBACK');
assert.equal(decodeP05Body('createManualRequest', json(bodies.createManualRequest)).contact.mode, 'PHONE');
const manualRepair = { type: 'REPAIR', sourceEntryId: id, evidenceId: id2, contact: { mode: 'CHANNEL', name: 'C', phone: '+79990000004', channelSelection: channel },
  address, appliance, fault, urgency: 'FLEXIBLE', preferredVisit };
const decodedManualRepair = decodeP05Body('createManualRequest', json(manualRepair));
assert.equal(decodedManualRepair.type, 'REPAIR');
assert.equal(decodedManualRepair.contact.mode, 'CHANNEL');
// A manual no-call contact keeps the normalized phone, but grants no permission.
assert.equal(decodedManualRepair.contact.phone, '+79990000004');
assert.equal('phonePermission' in decodedManualRepair.contact, false);
assert.equal(decodedManualRepair.contact.channelSelection.provider, 'TG');
assert.equal('attachments' in decodedManualRepair, false, 'manual intake has no attachments');
only(() => decodeP05Body('createManualRequest', json({ ...manualRepair, attachments: [id] })));
only(() => decodeP05Body('createManualRequest', json({ ...manualRepair, type: 'PHONE' })));
only(() => decodeP05Body('createManualRequest', json({ ...bodies.createManualRequest,
  contact: { mode: 'CHANNEL', name: 'C', phone: '+79990000004', channelSelection: channel } })));
// The phone of a channel contact is required, not optional.
only(() => decodeP05Body('createManualRequest', json({ ...manualRepair,
  contact: { mode: 'CHANNEL', name: 'C', channelSelection: channel } })));

// 6b. ChangeContact replaces contact values only: no mode, channel switch or permission.
assert.deepEqual(decodeP05Body('changeContact', json(bodies.changeContact)),
  { contact: { name: 'New Client', phone: '+79990000003' }, evidenceId: id2 });
for (const forbidden of [
  { contact: { mode: 'PHONE', name: 'N', phone: '+79990000003' }, evidenceId: id2 },
  { contact: { name: 'N', phone: '+79990000003', phonePermission: true }, evidenceId: id2 },
  { contact: { name: 'N', phone: '+79990000003', channelSelection: channel }, evidenceId: id2 },
  { contact: { mode: 'CHANNEL', name: 'N', phone: '+79990000003', channelSelection: channel }, evidenceId: id2 },
]) {
  only(() => decodeP05Body('changeContact', json(forbidden)));
}
// 6c. ChangeDetails APPLIANCE replaces the appliance together with its fault block.
const detailsAppliance = { section: 'APPLIANCE', appliance, fault };
assert.deepEqual(decodeP05Body('changeDetails', json(detailsAppliance)), detailsAppliance);
only(() => decodeP05Body('changeDetails', json({ section: 'APPLIANCE', appliance })));

// 7. Cap boundary: 16 KiB is admitted to parsing, one byte over is 413, UTF-8 is strict.
// Every DTO field is individually capped, so the boundary is proven on the byte
// gate itself: at the cap the JSON parser runs (BAD_JSON), above it the cap wins.
const atCap = encoder.encode('x'.repeat(P05_BODY_BYTES));
const overCap = encoder.encode('x'.repeat(P05_BODY_BYTES + 1));
try { decodeP05Body('createCallback', atCap); assert.fail('non-JSON at cap accepted'); }
catch (error) {
  assert.equal(error.code, 'BAD_JSON');
  assert.deepEqual(p05DecodeStatus(error), { status: 400, code: 'MALFORMED' });
}
try { decodeP05Body('createCallback', overCap); assert.fail('over-cap body accepted'); }
catch (error) {
  assert.equal(error.code, 'BODY_TOO_LARGE');
  assert.deepEqual(p05DecodeStatus(error), { status: 413, code: 'BODY_TOO_LARGE' });
}
for (const bytes of [Uint8Array.from([0x7b, 0x22, 0xff, 0x22, 0x7d]), Uint8Array.from([0xc3, 0x28])]) {
  try { decodeP05Body('createCallback', bytes); assert.fail('bad UTF-8 accepted'); }
  catch (error) { assert.equal(error.code, 'BAD_UTF8'); }
}
try { decodeP05Body('createCallback', encoder.encode('{"contact":{},"contact":{}}')); assert.fail('duplicate key accepted'); }
catch (error) { assert.equal(error.code, 'BAD_JSON'); }

// 8. Semantic 422 cases are separated from malformed 400 cases.
const semantic = [
  ['createCallback', { ...bodies.createCallback, consent: { ...consent, accepted: false } }, 'CONSENT_NOT_ACCEPTED'],
  ['createCallback', { ...bodies.createCallback, phonePermission: false }, 'PHONE_PERMISSION_REQUIRED'],
  ['createRepair', { ...bodies.createRepair, fault: { faultIds: [id, id] } }, 'DUPLICATE_IDS'],
  // Neither a selected published fault nor an other-description is an
  // incomplete repair: semantic 422, never a malformed 400.
  ['createRepair', { ...bodies.createRepair, fault: {} }, 'FAULT_REQUIRED'],
  ['createRepair', { ...bodies.createRepair, fault: { faultIds: [] } }, 'FAULT_REQUIRED'],
  ['createRepair', { ...bodies.createRepair, fault: { faultIds: [], description: 'noise only' } }, 'FAULT_REQUIRED'],
  ['createRepair', { ...bodies.createRepair, fault: { faultIds: [], errorCode: 'E01' } }, 'FAULT_REQUIRED'],
  ['createRepair', { ...bodies.createRepair, preferredVisit: { from: preferredVisit.to, to: preferredVisit.from } }, 'VISIT_WINDOW_INVALID'],
  ['recordCoverage', { evidenceId: id, outcome: 'IN_ZONE' }, 'AREA_REQUIRED'],
  ['recordCoverage', { evidenceId: id, outcome: 'IN_ZONE', areaId: id2, reason: 'OUTSIDE_REVIEW' }, 'REASON_NOT_ALLOWED'],
  ['recordCoverage', { evidenceId: id, outcome: 'EXCEPTION', reason: 'OPERATOR_REVIEW' }, 'AREA_REQUIRED'],
  ['recordCoverage', { evidenceId: id, outcome: 'EXCEPTION', areaId: id2 }, 'REASON_REQUIRED'],
  ['recordCoverage', { evidenceId: id, outcome: 'EXCEPTION', areaId: id2, reason: 'OVERLAP_REVIEW' }, 'REASON_REQUIRED'],
  ['recordCoverage', { evidenceId: id, outcome: 'OUTSIDE' }, 'REASON_REQUIRED'],
  ['recordCoverage', { evidenceId: id, outcome: 'OUTSIDE', areaId: id2, reason: 'OUTSIDE_REVIEW' }, 'AREA_NOT_ALLOWED'],
  ['recordCoverage', { evidenceId: id, outcome: 'REVIEW' }, 'REASON_REQUIRED'],
  ['recordCoverage', { evidenceId: id, outcome: 'REVIEW', areaId: id2, reason: 'OVERLAP_REVIEW' }, 'AREA_NOT_ALLOWED'],
  ['changeDetails', { section: 'PREFERENCE' }, 'PREFERENCE_EMPTY'],
];
for (const [operation, body, code] of semantic) {
  try { decodeP05Body(operation, json(body)); assert.fail(`${operation} accepted ${code}`); }
  catch (error) {
    assert(error instanceof P05DecodeError, code);
    assert.equal(error.kind, 'SEMANTIC', code);
    assert.equal(error.code, code);
    assert.deepEqual(p05DecodeStatus(error), { status: 422, code: 'SEMANTIC' });
  }
}
// 8b. Fault completeness: an "other fault" description alone (or with an empty
// id list) is a complete repair and normalizes the omitted list to [].
const otherOnlyRepair = { ...bodies.createRepair, fault: { otherDescription: 'Synthetic unknown noise' } };
const otherOnly = decodeP05Body('createRepair', json(otherOnlyRepair));
assert(Object.isFrozen(otherOnly.fault), 'fault frozen');
assert(Object.isFrozen(otherOnly.fault.faultIds), 'faultIds frozen');
assert.deepEqual(otherOnly.fault, { faultIds: [], otherDescription: 'Synthetic unknown noise' });
// The canonical bytes always carry the normalized array, and re-decoding is stable.
assert.deepEqual(JSON.parse(new TextDecoder().decode(encodeP05Body('createRepair', otherOnly))).fault,
  { faultIds: [], otherDescription: 'Synthetic unknown noise' });
assert.deepEqual(decodeP05Body('createRepair', encodeP05Body('createRepair', otherOnly)), otherOnly);
for (const complete of [
  { faultIds: [], otherDescription: 'Synthetic unknown noise', description: 'free text', errorCode: 'E9' },
  { faultIds: [id3], otherDescription: 'Synthetic unknown noise' },
  { faultIds: [id3] },
]) {
  const decoded = decodeP05Body('createRepair', json({ ...bodies.createRepair, fault: complete }));
  assert.deepEqual(decoded.fault, complete);
  assert.deepEqual(decodeP05Body('createRepair', encodeP05Body('createRepair', decoded)), decoded);
}
// The other-fault branch is not a backdoor for unknown members or a non-list.
only(() => decodeP05Body('createRepair', json({ ...bodies.createRepair, fault: { otherDescription: 'x', extra: 1 } })));
only(() => decodeP05Body('createRepair', json({ ...bodies.createRepair, fault: { faultIds: 'not-a-list', otherDescription: 'x' } })));
only(() => decodeP05Body('createRepair', json({ ...bodies.createRepair, fault: { otherDescription: '   ' } })));
only(() => decodeP05Body('createRepair', json({ ...bodies.createRepair, fault: { otherDescription: '' } })));
// The same rule applies to every operation that carries a fault block.
for (const operation of ['convertCallback', 'changeDetails']) {
  const body = operation === 'convertCallback'
    ? { address, appliance, fault: { otherDescription: 'Synthetic unknown noise' } }
    : { section: 'APPLIANCE', appliance, fault: { otherDescription: 'Synthetic unknown noise' } };
  assert.deepEqual(decodeP05Body(operation, json(body)).fault, { faultIds: [], otherDescription: 'Synthetic unknown noise' });
  only(() => decodeP05Body(operation, json({ ...body, fault: {} })));
}
const manualOtherOnly = { ...manualRepair, fault: { otherDescription: 'Synthetic unknown noise' } };
assert.deepEqual(decodeP05Body('createManualRequest', json(manualOtherOnly)).fault,
  { faultIds: [], otherDescription: 'Synthetic unknown noise' });

// 8c. Positive coverage combinations accepted by the same rules.
for (const coverage of [
  { evidenceId: id, outcome: 'IN_ZONE', areaId: id2 },
  { evidenceId: id, outcome: 'IN_ZONE', areaId: id2, reason: 'OVERLAP_REVIEW' },
  { evidenceId: id, outcome: 'EXCEPTION', areaId: id2, reason: 'OUTSIDE_REVIEW' },
  { evidenceId: id, outcome: 'EXCEPTION', areaId: id2, reason: 'OPERATOR_REVIEW' },
  { evidenceId: id, outcome: 'OUTSIDE', reason: 'OUTSIDE_REVIEW' },
  { evidenceId: id, outcome: 'OUTSIDE', reason: 'OPERATOR_REVIEW' },
  { evidenceId: id, outcome: 'REVIEW', reason: 'OVERLAP_REVIEW' },
  { evidenceId: id, outcome: 'REVIEW', reason: 'OPERATOR_REVIEW' },
]) {
  assert.deepEqual(decodeP05Body('recordCoverage', json(coverage)), coverage);
}
// The body never carries a coverage candidate: only areaId/outcome/reason/evidence.
only(() => decodeP05Body('recordCoverage', json({ evidenceId: id, outcome: 'IN_ZONE', areaId: id2, candidate: { zone: id } })));
// Grammar bound: 33 IDs exceed the 32-id cap; 256 nodes still admits the worst body.
only(() => decodeP05Body('createRepair', json({ ...bodies.createRepair,
  fault: { faultIds: Array.from({ length: P05_MAX_IDS + 1 }, () => id) } })));
assert(P05_MAX_NODES >= 100 && P05_MAX_NODES <= 256);

// 9. Urgency vocabulary is exactly the migration 022 source vocabulary.
assert.deepEqual([...P05_URGENCIES], ['FLEXIBLE', 'WITHIN_DAY', 'URGENT']);
for (const value of P05_URGENCIES) {
  assert.deepEqual(decodeP05Body('createRepair', json({ ...bodies.createRepair, urgency: value })).urgency, value);
}
only(() => decodeP05Body('createRepair', json({ ...bodies.createRepair, urgency: 'NORMAL' })));
assert.deepEqual([...P05_TYPES], ['CALLBACK', 'REPAIR']);
assert.deepEqual([...P05_STATUSES].length, 19);

// 10. ETag grammar is exact and the hash is never computed here.
assert.equal(parseP05Etag(etag), hash);
for (const invalid of [`W/${etag}`, `"p05-r1-${'F'.repeat(64)}"`, `"p05-r1-${'f'.repeat(63)}"`, etag.replace('p05-r1', 'p05-r2'),
  `${etag}, ${etag}`, '*', etag.replace('"', ''), `${etag}\n`]) {
  assert.equal(parseP05Etag(invalid), null, invalid);
}
only(() => formatP05Etag('F'.repeat(64)));
only(() => formatP05Etag('f'.repeat(63)));

// 11. Response projections: closed keys, both authorized shapes, no leaked extras.
const fReceipt = { publicNumber: '100042', status: 'CALLBACK_REQUIRED', version: 1 };
assert.deepEqual(decodeP05Response('createCallback', 201, json({ data: fReceipt })), fReceipt);
assert.deepEqual(decodeP05Response('createCallback', 200, json({ data: fReceipt })), fReceipt);
const staffReceipt = { id, publicNumber: '100042', status: 'NEW', version: 1 };
assert.deepEqual(decodeP05Response('createManualRequest', 201, json({ data: staffReceipt })), staffReceipt);
assert.deepEqual(decodeP05Response('withdrawPhoneStaff', 200, json({ data: { applied: true, version: 3 } })),
  { applied: true, version: 3 });
assert.deepEqual(decodeP05Response('readRequestSession', 200, json({ data: { version: 4 } })), { version: 4 });
assert.deepEqual(decodeP05Response('readRequestSession', 200,
  json({ data: { publicNumber: '100042', status: 'MANAGER_REVIEW', version: 4 } })),
{ publicNumber: '100042', status: 'MANAGER_REVIEW', version: 4 });
assert.deepEqual(decodeP05Response('readStaffRequest', 200,
  json({ data: { id, publicNumber: '100042', type: 'REPAIR', status: 'NEW', version: 1 } })),
{ id, publicNumber: '100042', type: 'REPAIR', status: 'NEW', version: 1 });
// No random `meta` on the two canonical GETs, and no extra member anywhere.
only(() => decodeP05Response('readRequestSession', 200, json({ data: { version: 4 }, meta: { requestId: id } })));
only(() => decodeP05Response('createCallback', 201, json({ data: { ...fReceipt, etag: etag } })));
only(() => decodeP05Response('createCallback', 201, json({ data: { ...fReceipt, publicNumber: 100042 } })));
only(() => decodeP05Response('createCallback', 201, json({ data: { ...fReceipt, status: 'WAITING' } })));
only(() => decodeP05Response('readRequestSession', 200,
  json({ data: { publicNumber: '100042', status: 'NEW' } })));
// Decimal bigint strings: canonical digits only, never a number, bounded by int64.
only(() => decodeP05Response('createCallback', 201, json({ data: { ...fReceipt, publicNumber: '0100042' } })));
only(() => decodeP05Response('createCallback', 201, json({ data: { ...fReceipt, publicNumber: '9223372036854775808' } })));
assert.equal(decodeP05Response('createCallback', 201, json({ data: { ...fReceipt, publicNumber: '9223372036854775807' } })).publicNumber,
  '9223372036854775807');

// 12. Problem envelope: closed five keys, code/status pair must agree.
const problem = { type: 'about:blank', title: 'CONFLICT', status: 409, code: 'CONFLICT', requestId: id };
assert.deepEqual(decodeP05Problem(problem), problem);
assert.equal(decodeP05Problem({ ...problem, status: 400 }), null);
assert.equal(decodeP05Problem({ ...problem, extra: 1 }), null);
assert.equal(decodeP05Problem({ ...problem, title: 'MALFORMED' }), null);
try { decodeP05Response('startReview', 409, json(problem)); assert.fail('problem accepted as success'); }
catch (error) {
  assert(error instanceof P05WireError);
  assert.equal(error.status, 409);
  assert.equal(error.code, 'CONFLICT');
  assert.deepEqual(error.problem, problem);
}
// A non-problem error body degrades to a typed error without inventing a code.
try { decodeP05Response('startReview', 500, encoder.encode('{}')); assert.fail('500 accepted'); }
catch (error) { assert.equal(error.code, 'INTERNAL_ERROR'); assert.equal(error.problem, null); }

// 13. Typed client: canonical uppercase method, exact headers, no hidden authority.
const requests = [];
const queued = [
  { status: 201, headers: {}, body: json({ data: fReceipt }) },
  { status: 200, headers: { etag }, body: json({ data: { version: 4 } }) },
  { status: 200, headers: {}, body: json({ data: staffReceipt }) },
];
const client = createP05Client(async (request) => {
  requests.push(request);
  const response = queued.shift();
  if (response === undefined) { throw new Error(`unexpected transport call ${request.path}`); }
  return response;
}, { origin: 'https://app.test' });

const created = await client.request('createCallback', {
  body: bodies.createCallback, idempotencyKey: id2, csrfToken: 'csrf-token', formSessionId: id,
});
assert.equal(created.kind, 'data');
assert.deepEqual(created.data, fReceipt);
assert.equal(created.etag, null, 'write receipt carries no ETag');
const first = requests[0];
assert.equal(first.method, 'POST');
assert.equal(first.path, '/api/v1/public/callback-requests');
assert.equal(first.headers[P05_HEADERS.formSession], id);
assert.equal(first.headers[P05_HEADERS.csrf], 'csrf-token');
assert.equal(first.headers[P05_HEADERS.idempotency], id2);
assert.equal(first.headers[P05_HEADERS.origin], 'https://app.test');
assert.equal(first.headers['content-type'], 'application/json');
assert.deepEqual(Object.keys(first.headers).filter((key) => key.startsWith('x-')).sort(),
  [P05_HEADERS.csrf, P05_HEADERS.formSession]);
assert.deepEqual(JSON.parse(first.body), bodies.createCallback);

const read = await client.request('readRequestSession', { formSessionId: id, ifNoneMatch: etag });
assert.equal(read.kind, 'data');
assert.equal(read.etag, etag);
const readRequest = requests[1];
assert.equal(readRequest.method, 'GET');
assert.equal(readRequest.body, null);
assert.equal(readRequest.headers[P05_HEADERS.ifNoneMatch], etag);
assert.equal(readRequest.headers[P05_HEADERS.formSession], id);
assert.equal(readRequest.headers[P05_HEADERS.csrf], undefined);

const staff = await client.request('startReview', {
  id, body: {}, idempotencyKey: id3, expectedVersion: etag, csrfToken: 'staff-csrf',
});
assert.equal(staff.kind, 'data');
const staffRequest = requests[2];
assert.equal(staffRequest.method, 'POST');
assert.equal(staffRequest.path, `/api/v1/requests/${id}/commands/start-review`);
assert.equal(staffRequest.headers[P05_HEADERS.ifMatch], etag);
assert.equal(staffRequest.headers[P05_HEADERS.formSession], undefined, 'staff routes carry no F selector');
assert.equal(staffRequest.headers[P05_HEADERS.csrf], 'staff-csrf');
assert.equal(staffRequest.headers[P05_HEADERS.origin], 'https://app.test');

// Client-side argument validation: no silent defaults, no cross-surface leakage.
await assert.rejects(async () => client.request('createCallback', { body: bodies.createCallback,
  idempotencyKey: 'NOT-A-UUID', csrfToken: 't', formSessionId: id }));
await assert.rejects(async () => client.request('createCallback', { body: bodies.createCallback,
  idempotencyKey: id2, csrfToken: 't', formSessionId: 'not-a-uuid' }));
await assert.rejects(async () => client.request('startReview', { id, body: {}, idempotencyKey: id3,
  expectedVersion: `W/${etag}` }));
await assert.rejects(async () => client.request('readRequestSession', { formSessionId: id, ifNoneMatch: '*' }));

// 14. 304 is a first-class result only for the two canonical GETs.
const notModified = createP05Client(async () => ({ status: 304, headers: { etag }, body: new Uint8Array() }),
  { origin: 'https://app.test' });
assert.deepEqual(await notModified.request('readStaffRequest', { id, ifNoneMatch: etag }),
  { kind: 'not-modified', status: 304, etag });
await assert.rejects(async () => notModified.request('startReview', { id, body: {}, idempotencyKey: id3,
  expectedVersion: etag, csrfToken: 'staff-csrf' }));

// 15. Server-authority split: the module exposes no hashing, no DB and no auth helpers.
for (const forbidden of ['hashP05', 'computeP05Etag', 'authorizeP05', 'readP05Coverage']) {
  const module = await import('./dist/p05.js');
  assert.equal(Object.hasOwn(module, forbidden), false, forbidden);
}
console.log(`P05 contracts verified: ${String(P05_OPERATIONS.length)} exact routes, `
  + `${String(Object.keys(artifact.components.schemas).length)} closed schemas, strict DTO/ETag/client parity`);
