/**
 * P05 shared wire contract tests (packages/p03-contracts/src/p05.ts).
 *
 * Self-contained: no PostgreSQL, no HTTP server, no working database, no
 * network. The contract is pure syntax/DTO/route/client logic, so these tests
 * assert exactly that layer and never re-run a P05 runtime review.
 */
import { describe, expect, it } from 'vitest';
import {
  P05_BODY_BYTES, P05_HEADERS, P05_MAX_IDS, P05_MAX_NODES, P05_OPERATIONS, P05_PREFIX, P05_PROBLEM_STATUS,
  P05_ROUTES, P05_TYPES, P05_URGENCIES, P05DecodeError, P05WireError, createP05Client, decodeP05Body,
  decodeP05Problem, decodeP05Response, encodeP05Body, formatP05Etag, matchP05Route, p05DecodeStatus,
  parseP05Etag,
} from '@fixlevelup/p03-contracts/p05';

const id = 'a1234567-1234-4321-8123-123456789012';
const id2 = 'b1234567-1234-4321-8123-123456789012';
const id3 = 'c1234567-1234-4321-8123-123456789012';
const id4 = 'd1234567-1234-4321-8123-123456789012';
const id5 = 'e1234567-1234-4321-8123-123456789012';
const hash = 'f'.repeat(64);
const etag = formatP05Etag(hash);
const encoder = new TextEncoder();
const json = (value: unknown): Uint8Array => encoder.encode(JSON.stringify(value));

const contact = { name: 'Synthetic Client', phone: '+79990000001' };
const consent = { evidenceId: id, documentVersionId: id2, accepted: true };
const channel = { provider: 'TG', optionVersionId: id3, catalogVersionId: id4, purpose: 'REQUEST_CONFIRMATION' };
const address = { street: 'Synthetic street 1', building: '2', districtId: id5, accessNotes: 'call on arrival' };
const appliance = { categoryId: id, brandId: id2, modelText: 'Model X', approximateAge: 5 };
const fault = { faultIds: [id3, id4], errorCode: 'E01' };
const preferredVisit = { from: '2030-01-02T09:00:00.000Z', to: '2030-01-02T12:00:00.000Z' };

const bodies: Readonly<Record<string, Record<string, unknown>>> = {
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

function decodeError(run: () => unknown): P05DecodeError {
  try {
    run();
  } catch (error) {
    if (error instanceof P05DecodeError) { return error; }
    throw error;
  }
  throw new Error('expected a P05DecodeError');
}

describe('P05 exact route surface', () => {
  it('matches every canonical route and nothing else', () => {
    expect(P05_OPERATIONS).toHaveLength(16);
    for (const operation of P05_OPERATIONS) {
      const route = P05_ROUTES[operation];
      const path = route.path.includes(':id')
        ? `${P05_PREFIX}${route.path.replace(':id', id)}`
        : `${P05_PREFIX}${route.path}`;
      expect(matchP05Route(route.method, path)).toEqual({
        operation,
        scope: route.scope,
        params: route.path.includes(':id') ? { id } : {},
      });
      // Case-sensitive method, no aliases, no query/fragment/trailing slash/% encoding.
      expect(matchP05Route(route.method.toLowerCase(), path)).toBeNull();
      expect(matchP05Route(route.method, `${path}/`)).toBeNull();
      expect(matchP05Route(route.method, `${path}?x=1`)).toBeNull();
      expect(matchP05Route(route.method, `${path}#f`)).toBeNull();
      expect(matchP05Route('HEAD', path)).toBeNull();
    }
  });

  it('keeps F and staff surfaces disjoint and the staff ids canonical', () => {
    const f = P05_OPERATIONS.filter((operation) => P05_ROUTES[operation].scope === 'F');
    const staff = P05_OPERATIONS.filter((operation) => P05_ROUTES[operation].scope === 'STAFF');
    expect(f).toHaveLength(6);
    expect(staff).toHaveLength(10);
    expect(f.every((operation) => P05_ROUTES[operation].path.startsWith('/public/'))).toBe(true);
    expect(staff.every((operation) => P05_ROUTES[operation].path.startsWith('/requests'))).toBe(true);
    // A non-canonical UUID (wrong version nibble or uppercase) never matches.
    expect(matchP05Route('GET', `${P05_PREFIX}/requests/${id.replace('-4', '-0')}`)).toBeNull();
    expect(matchP05Route('GET', `${P05_PREFIX}/requests/${id.toUpperCase()}`)).toBeNull();
  });
});

describe('P05 closed normalized DTOs', () => {
  it('accepts each canonical body, freezes it and round-trips its canonical bytes', () => {
    expect(Object.keys(bodies).sort()).toEqual(
      P05_OPERATIONS.filter((operation) => P05_ROUTES[operation].body !== null).sort(),
    );
    for (const [operation, body] of Object.entries(bodies)) {
      const decoded = decodeP05Body(operation as never, json(body)) as unknown;
      expect(Object.isFrozen(decoded)).toBe(true);
      expect(decodeP05Body(operation as never, encodeP05Body(operation as never, decoded as never))).toEqual(decoded);
    }
  });

  it('refuses unknown members as malformed 400 instead of dropping them', () => {
    for (const [operation, body] of Object.entries(bodies)) {
      const error = decodeError(() => decodeP05Body(operation as never, json({ ...body, unexpected: true })));
      expect(error.kind).toBe('MALFORMED');
      expect(error.code).toBe('UNKNOWN_FIELD');
      expect(p05DecodeStatus(error)).toEqual({ status: 400, code: 'MALFORMED' });
    }
  });

  it('keeps the manual intake discriminated by type and by contact mode', () => {
    const manual = decodeP05Body('createManualRequest', json(bodies['createManualRequest']));
    expect(manual.type).toBe('CALLBACK');
    expect(manual.contact.mode).toBe('PHONE');
    const repair = { type: 'REPAIR', sourceEntryId: id, evidenceId: id2,
      contact: { mode: 'CHANNEL', name: 'C', phone: '+79990000004', channelSelection: channel },
      address, appliance, fault, urgency: 'FLEXIBLE', preferredVisit };
    const decoded = decodeP05Body('createManualRequest', json(repair));
    expect(decoded.type).toBe('REPAIR');
    expect(decoded.contact.mode).toBe('CHANNEL');
    // A manual no-call contact keeps the normalized phone for the intake, but the
    // phone is not a permission proof: no phonePermission member exists here.
    expect(decoded.contact.phone).toBe('+79990000004');
    expect('phonePermission' in decoded.contact).toBe(false);
    // The channel phone is required, not optional.
    expect(decodeError(() => decodeP05Body('createManualRequest', json({ ...repair,
      contact: { mode: 'CHANNEL', name: 'C', channelSelection: channel } }))).code).toBe('MISSING_FIELD');
    // Manual intake never carries F attachments, and CALLBACK requires PHONE.
    expect('attachments' in decoded).toBe(false);
    expect(decodeError(() => decodeP05Body('createManualRequest', json({ ...repair, attachments: [id] }))).code)
      .toBe('UNKNOWN_FIELD');
    expect(decodeError(() => decodeP05Body('createManualRequest', json({ ...bodies['createManualRequest'],
      contact: { mode: 'CHANNEL', name: 'C', phone: '+79990000004', channelSelection: channel } }))).code).toBe('CHANNEL_NOT_ALLOWED');
  });

  it('replaces only contact values on ChangeContact and never switches mode or grants PHONE', () => {
    expect(decodeP05Body('changeContact', json(bodies['changeContact'])))
      .toEqual({ contact: { name: 'New Client', phone: '+79990000003' }, evidenceId: id2 });
    for (const forbidden of [
      { contact: { mode: 'PHONE', name: 'N', phone: '+79990000003' }, evidenceId: id2 },
      { contact: { name: 'N', phone: '+79990000003', phonePermission: true }, evidenceId: id2 },
      { contact: { name: 'N', phone: '+79990000003', channelSelection: channel }, evidenceId: id2 },
      { contact: { mode: 'CHANNEL', name: 'N', phone: '+79990000003', channelSelection: channel }, evidenceId: id2 },
    ]) {
      expect(decodeError(() => decodeP05Body('changeContact', json(forbidden))).code).toBe('UNKNOWN_FIELD');
    }
  });

  it('replaces appliance and fault together on the APPLIANCE ChangeDetails section', () => {
    const section = { section: 'APPLIANCE', appliance, fault };
    expect(decodeP05Body('changeDetails', json(section))).toEqual(section);
    expect(decodeError(() => decodeP05Body('changeDetails', json({ section: 'APPLIANCE', appliance }))).code)
      .toBe('MISSING_FIELD');
    expect(decodeError(() => decodeP05Body('changeDetails', json({ section: 'APPLIANCE', fault }))).code)
      .toBe('MISSING_FIELD');
  });

  it('accepts exactly the migration 024 coverage combinations', () => {
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
      expect(decodeP05Body('recordCoverage', json(coverage))).toEqual(coverage);
    }
    // The body never carries the coverage candidate: that comes from the server port.
    expect(decodeError(() => decodeP05Body('recordCoverage',
      json({ evidenceId: id, outcome: 'IN_ZONE', areaId: id2, candidate: { zone: id } }))).code)
      .toBe('UNKNOWN_FIELD');
  });

  it('accepts an other-description-only fault and normalizes omitted faultIds to []', () => {
    // P05-PLAN §1 (Q12/Q16): a repair is complete with >=1 selected published
    // fault of the category OR an "other fault" with a non-empty description.
    const otherOnly = { ...bodies['createRepair'], fault: { otherDescription: 'Synthetic unknown noise' } };
    const decoded = decodeP05Body('createRepair', json(otherOnly));
    expect(decoded.fault).toEqual({ faultIds: [], otherDescription: 'Synthetic unknown noise' });
    expect(Object.isFrozen(decoded.fault)).toBe(true);
    expect(Object.isFrozen(decoded.fault.faultIds)).toBe(true);
    // The documented normalization is visible in the canonical bytes: the
    // omitted list becomes an explicit [] and re-decoding is stable.
    const canonical = JSON.parse(new TextDecoder().decode(encodeP05Body('createRepair', decoded))) as {
      fault: Record<string, unknown>;
    };
    expect(canonical.fault).toEqual({ faultIds: [], otherDescription: 'Synthetic unknown noise' });
    expect(decodeP05Body('createRepair', encodeP05Body('createRepair', decoded))).toEqual(decoded);
    // Every complete combination is accepted, including both branches together.
    for (const faultBlock of [
      { faultIds: [], otherDescription: 'Synthetic unknown noise', description: 'free text', errorCode: 'E9' },
      { faultIds: [id3], otherDescription: 'Synthetic unknown noise' },
      { faultIds: [id3] },
    ]) {
      const repair = decodeP05Body('createRepair', json({ ...bodies['createRepair'], fault: faultBlock }));
      expect(repair.fault).toEqual(faultBlock);
      expect(decodeP05Body('createRepair', encodeP05Body('createRepair', repair))).toEqual(repair);
    }
    // The rule holds for every operation that carries a fault block.
    expect(decodeP05Body('convertCallback', json({ address, appliance,
      fault: { otherDescription: 'Synthetic unknown noise' } }))).toMatchObject({
      fault: { faultIds: [], otherDescription: 'Synthetic unknown noise' } });
    expect(decodeP05Body('changeDetails', json({ section: 'APPLIANCE', appliance,
      fault: { otherDescription: 'Synthetic unknown noise' } }))).toMatchObject({
      section: 'APPLIANCE', fault: { faultIds: [], otherDescription: 'Synthetic unknown noise' } });
    expect(decodeP05Body('createManualRequest', json({ type: 'REPAIR', sourceEntryId: id, evidenceId: id2,
      contact: { mode: 'CHANNEL', name: 'C', phone: '+79990000004', channelSelection: channel },
      address, appliance, fault: { otherDescription: 'Synthetic unknown noise' } }))).toMatchObject({
      type: 'REPAIR', fault: { faultIds: [], otherDescription: 'Synthetic unknown noise' } });
    // An empty fault block is the same 422 for those operations too.
    for (const body of [
      { address, appliance, fault: {} },
      { section: 'APPLIANCE', appliance, fault: {} },
    ]) {
      const operation = 'section' in body ? 'changeDetails' : 'convertCallback';
      expect(decodeError(() => decodeP05Body(operation, json(body))).code).toBe('FAULT_REQUIRED');
    }
  });

  it('classifies an incomplete fault block as semantic 422 FAULT_REQUIRED, not a malformed 400', () => {
    for (const faultBlock of [{}, { faultIds: [] }, { faultIds: [], description: 'noise only' },
      { faultIds: [], errorCode: 'E01' }]) {
      const error = decodeError(() => decodeP05Body('createRepair', json({ ...bodies['createRepair'], fault: faultBlock })));
      expect(error.kind).toBe('SEMANTIC');
      expect(error.code).toBe('FAULT_REQUIRED');
      expect(p05DecodeStatus(error)).toEqual({ status: 422, code: 'SEMANTIC' });
    }
    // The other-fault branch never becomes a backdoor for unknown members,
    // a non-list value or a blank description.
    expect(decodeError(() => decodeP05Body('createRepair',
      json({ ...bodies['createRepair'], fault: { otherDescription: 'x', extra: 1 } }))).code).toBe('UNKNOWN_FIELD');
    expect(decodeError(() => decodeP05Body('createRepair',
      json({ ...bodies['createRepair'], fault: { faultIds: 'not-a-list', otherDescription: 'x' } }))).code).toBe('BAD_TYPE');
    expect(decodeError(() => decodeP05Body('createRepair',
      json({ ...bodies['createRepair'], fault: { otherDescription: '   ' } }))).code).toBe('BAD_FORMAT');
  });

  it('aligns preference urgency with the migration 022 vocabulary', () => {
    expect([...P05_URGENCIES]).toEqual(['FLEXIBLE', 'WITHIN_DAY', 'URGENT']);
    for (const urgency of P05_URGENCIES) {
      expect(decodeP05Body('createRepair', json({ ...bodies['createRepair'], urgency })).urgency).toBe(urgency);
    }
    expect(decodeError(() => decodeP05Body('createRepair', json({ ...bodies['createRepair'], urgency: 'NORMAL' }))).code)
      .toBe('BAD_VALUE');
    expect([...P05_TYPES]).toEqual(['CALLBACK', 'REPAIR']);
  });
});

describe('P05 byte caps, UTF-8 and grammar bounds', () => {
  it('admits exactly 16 KiB to parsing and answers 413 one byte over', () => {
    const atCap = encoder.encode('x'.repeat(P05_BODY_BYTES));
    const overCap = encoder.encode('x'.repeat(P05_BODY_BYTES + 1));
    expect(decodeError(() => decodeP05Body('createCallback', atCap)).code).toBe('BAD_JSON');
    const over = decodeError(() => decodeP05Body('createCallback', overCap));
    expect(over.code).toBe('BODY_TOO_LARGE');
    expect(p05DecodeStatus(over)).toEqual({ status: 413, code: 'BODY_TOO_LARGE' });
  });

  it('refuses invalid UTF-8, duplicate members and over-wide shapes', () => {
    expect(decodeError(() => decodeP05Body('createCallback', Uint8Array.from([0x7b, 0x22, 0xff, 0x22, 0x7d]))).code)
      .toBe('BAD_UTF8');
    expect(decodeError(() => decodeP05Body('createCallback', encoder.encode('{"contact":{},"contact":{}}'))).code)
      .toBe('BAD_JSON');
    expect(P05_MAX_NODES).toBeLessThanOrEqual(256);
    expect(P05_MAX_IDS).toBe(32);
  });

  it('caps id lists at 32 and refuses duplicates as semantic 422', () => {
    const tooMany = Array.from({ length: P05_MAX_IDS + 1 }, () => id);
    expect(decodeError(() => decodeP05Body('createRepair',
      json({ ...bodies['createRepair'], fault: { faultIds: tooMany } }))).code).toBe('OUT_OF_RANGE');
    const duplicate = decodeError(() => decodeP05Body('createRepair',
      json({ ...bodies['createRepair'], fault: { faultIds: [id, id] } })));
    expect(duplicate.kind).toBe('SEMANTIC');
    expect(duplicate.code).toBe('DUPLICATE_IDS');
  });
});

describe('P05 semantic 422 versus malformed 400', () => {
  it('classifies each closed semantic rule and its status', () => {
    const cases: readonly (readonly [string, Record<string, unknown>, string])[] = [
      ['createCallback', { ...bodies['createCallback'], consent: { ...consent, accepted: false } }, 'CONSENT_NOT_ACCEPTED'],
      ['createCallback', { ...bodies['createCallback'], phonePermission: false }, 'PHONE_PERMISSION_REQUIRED'],
      ['createRepair', { ...bodies['createRepair'],
        preferredVisit: { from: preferredVisit.to, to: preferredVisit.from } }, 'VISIT_WINDOW_INVALID'],
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
    for (const [operation, body, code] of cases) {
      const error = decodeError(() => decodeP05Body(operation as never, json(body)));
      expect(error.kind, code).toBe('SEMANTIC');
      expect(error.code, code).toBe(code);
      expect(p05DecodeStatus(error)).toEqual({ status: 422, code: 'SEMANTIC' });
    }
  });
});

describe('P05 ETag and safe response projections', () => {
  it('accepts only the exact strong p05-r1 tag syntax', () => {
    expect(parseP05Etag(etag)).toBe(hash);
    for (const invalid of [`W/${etag}`, `"p05-r1-${'F'.repeat(64)}"`, `"p05-r1-${'f'.repeat(63)}"`,
      etag.replace('p05-r1', 'p05-r2'), `${etag}, ${etag}`, '*', etag.replaceAll('"', '')]) {
      expect(parseP05Etag(invalid)).toBeNull();
    }
    expect(() => formatP05Etag('F'.repeat(64))).toThrow(RangeError);
  });

  it('decodes only the authorized projection shapes with closed keys', () => {
    const receipt = { publicNumber: '100042', status: 'CALLBACK_REQUIRED', version: 1 };
    expect(decodeP05Response('createCallback', 201, json({ data: receipt }))).toEqual(receipt);
    expect(decodeP05Response('createCallback', 200, json({ data: receipt }))).toEqual(receipt);
    expect(decodeP05Response('readRequestSession', 200, json({ data: { version: 4 } }))).toEqual({ version: 4 });
    expect(decodeP05Response('readRequestSession', 200,
      json({ data: { publicNumber: '100042', status: 'MANAGER_REVIEW', version: 4 } })))
      .toEqual({ publicNumber: '100042', status: 'MANAGER_REVIEW', version: 4 });
    expect(decodeP05Response('readStaffRequest', 200,
      json({ data: { id, publicNumber: '100042', type: 'REPAIR', status: 'NEW', version: 1 } })))
      .toEqual({ id, publicNumber: '100042', type: 'REPAIR', status: 'NEW', version: 1 });
    // No random `meta` on the two canonical GETs and no extra member anywhere.
    expect(decodeError(() => decodeP05Response('readRequestSession', 200,
      json({ data: { version: 4 }, meta: { requestId: id } }))).code).toBe('UNKNOWN_FIELD');
    expect(decodeError(() => decodeP05Response('createCallback', 201,
      json({ data: { ...receipt, etag } }))).code).toBe('UNKNOWN_FIELD');
  });

  it('treats the public number as a decimal bigint string, never a JSON number', () => {
    const receipt = { publicNumber: '100042', status: 'NEW', version: 1 };
    expect(decodeP05Response('createCallback', 201, json({ data: { ...receipt, publicNumber: '9223372036854775807' } }))
      .publicNumber).toBe('9223372036854775807');
    for (const invalid of ['0100042', '9223372036854775808', '1e3', '+100042', ' 100042', '-1']) {
      expect(decodeError(() => decodeP05Response('createCallback', 201,
        json({ data: { ...receipt, publicNumber: invalid } }))).code, invalid).toBeTruthy();
    }
    expect(decodeError(() => decodeP05Response('createCallback', 201,
      json({ data: { ...receipt, publicNumber: 100042 } }))).code).toBe('BAD_TYPE');
  });

  it('keeps the problem envelope closed and consistent with the status', () => {
    const problem = { type: 'about:blank', title: 'CONFLICT', status: 409, code: 'CONFLICT', requestId: id };
    expect(decodeP05Problem(problem)).toEqual(problem);
    expect(decodeP05Problem({ ...problem, status: 400 })).toBeNull();
    expect(decodeP05Problem({ ...problem, extra: 1 })).toBeNull();
    try {
      decodeP05Response('startReview', 409, json(problem));
      throw new Error('problem accepted as success');
    } catch (error) {
      expect(error).toBeInstanceOf(P05WireError);
      const wire = error as P05WireError;
      expect(wire.status).toBe(409);
      expect(wire.code).toBe('CONFLICT');
      expect(wire.problem).toEqual(problem);
    }
    expect(P05_PROBLEM_STATUS.CONFLICT).toBe(409);
    expect(P05_PROBLEM_STATUS.SEMANTIC).toBe(422);
    const rules = { ...problem, title: 'REQUEST_RULES_UNAVAILABLE', code: 'REQUEST_RULES_UNAVAILABLE', status: 503 };
    expect(decodeP05Problem(rules)).toEqual(rules);
    expect(decodeP05Problem({ ...rules, status: 409 })).toBeNull();
  });
});

describe('P05 typed client', () => {
  it('sends canonical method, path and headers for F and staff calls', async () => {
    const requests: { method: string; path: string; headers: Record<string, string>; body: string | null }[] = [];
    const queued = [
      { status: 201, headers: {}, body: json({ data: { publicNumber: '100042', status: 'CALLBACK_REQUIRED', version: 1 } }) },
      { status: 200, headers: { etag }, body: json({ data: { version: 4 } }) },
      { status: 200, headers: {}, body: json({ data: { id, publicNumber: '100042', status: 'NEW', version: 1 } }) },
    ];
    const client = createP05Client((request) => {
      requests.push({ method: request.method, path: request.path,
        headers: { ...request.headers }, body: request.body });
      const response = queued.shift();
      if (response === undefined) { throw new Error(`unexpected transport call ${request.path}`); }
      return Promise.resolve(response);
    }, { origin: 'https://app.test' });

    const created = await client.request('createCallback', {
      body: bodies['createCallback'] as never, idempotencyKey: id2, csrfToken: 'csrf-token', formSessionId: id,
    });
    expect(created.kind).toBe('data');
    expect(created.etag).toBeNull();
    expect(requests[0]).toMatchObject({
      method: 'POST',
      path: '/api/v1/public/callback-requests',
      headers: {
        [P05_HEADERS.formSession]: id,
        [P05_HEADERS.csrf]: 'csrf-token',
        [P05_HEADERS.idempotency]: id2,
        [P05_HEADERS.origin]: 'https://app.test',
        'content-type': 'application/json',
      },
    });

    const read = await client.request('readRequestSession', { formSessionId: id, ifNoneMatch: etag });
    expect(read).toMatchObject({ kind: 'data', etag });
    expect(requests[1]).toMatchObject({
      method: 'GET',
      path: '/api/v1/public/request-session',
      body: null,
      headers: { [P05_HEADERS.ifNoneMatch]: etag, [P05_HEADERS.formSession]: id },
    });
    expect(requests[1]?.headers[P05_HEADERS.csrf]).toBeUndefined();

    const staff = await client.request('startReview', { id, body: {}, idempotencyKey: id3, expectedVersion: etag, csrfToken: 'staff-csrf' });
    expect(staff.kind).toBe('data');
    expect(requests[2]).toMatchObject({
      method: 'POST',
      path: `/api/v1/requests/${id}/commands/start-review`,
      headers: { [P05_HEADERS.ifMatch]: etag, [P05_HEADERS.csrf]: 'staff-csrf', [P05_HEADERS.origin]: 'https://app.test' },
    });
    // The staff surface never receives the F selector.
    expect(requests[2]?.headers[P05_HEADERS.formSession]).toBeUndefined();
  });

  it('sends the normalized fault block through the typed client (otherDescription only)', async () => {
    const sent: { body: string | null }[] = [];
    const client = createP05Client((request) => {
      sent.push({ body: request.body });
      return Promise.resolve({ status: 201, headers: {},
        body: json({ data: { publicNumber: '100042', status: 'WAITING_CHANNEL_LINK', version: 1 } }) });
    }, { origin: 'https://app.test' });
    const created = await client.request('createRepair', {
      body: { ...bodies['createRepair'], fault: { otherDescription: 'Synthetic unknown noise' } } as never,
      idempotencyKey: id2, csrfToken: 'csrf-token', formSessionId: id,
    });
    expect(created.kind).toBe('data');
    // Client parity: the request body is the canonical normalized form, so the
    // omitted list is explicit `[]` on the wire and never a missing member.
    const parsed = JSON.parse(sent[0]?.body ?? 'null') as { fault: Record<string, unknown> };
    expect(parsed.fault).toEqual({ faultIds: [], otherDescription: 'Synthetic unknown noise' });
    // The client refuses an incomplete fault block before any transport call.
    await expect(client.request('createRepair', {
      body: { ...bodies['createRepair'], fault: { faultIds: [] } } as never,
      idempotencyKey: id3, csrfToken: 'csrf-token', formSessionId: id,
    })).rejects.toThrow(P05DecodeError);
  });

  it('refuses non-canonical client arguments instead of silently defaulting', async () => {
    const client = createP05Client(() => Promise.resolve({ status: 200, headers: {}, body: json({ data: {} }) }),
      { origin: 'https://app.test' });
    await expect(client.request('createCallback', { body: bodies['createCallback'] as never,
      idempotencyKey: 'NOT-A-UUID', csrfToken: 't', formSessionId: id })).rejects.toThrow(TypeError);
    await expect(client.request('createCallback', { body: bodies['createCallback'] as never,
      idempotencyKey: id2, csrfToken: 't', formSessionId: 'not-a-uuid' })).rejects.toThrow(TypeError);
    await expect(client.request('startReview', { id, body: {}, idempotencyKey: id3,
      expectedVersion: `W/${etag}`, csrfToken: 'staff-csrf' })).rejects.toThrow(TypeError);
    await expect(client.request('readRequestSession', { formSessionId: id, ifNoneMatch: '*' }))
      .rejects.toThrow(TypeError);
  });

  it('returns 304 only as an explicit not-modified result for the canonical GETs', async () => {
    const notModified = createP05Client(() => Promise.resolve({ status: 304, headers: { etag }, body: new Uint8Array() }),
      { origin: 'https://app.test' });
    await expect(notModified.request('readStaffRequest', { id, ifNoneMatch: etag }))
      .resolves.toEqual({ kind: 'not-modified', status: 304, etag });
    await expect(notModified.request('startReview', { id, body: {}, idempotencyKey: id3, expectedVersion: etag, csrfToken: 'staff-csrf' }))
      .rejects.toBeInstanceOf(P05WireError);
  });
});
